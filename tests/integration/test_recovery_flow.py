# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import asyncio

import pytest

from termrecall.bridge import Bridge
from termrecall.model import OutcomeKind
from termrecall.processes import ProcessStatus
from termrecall.protocol import ErrorResponse


@pytest.mark.asyncio
async def test_real_service_bridge_capture_approval_retry_and_discard(system_harness) -> None:
    shell_a = await system_harness.register_shell(system_harness.root / "srv" / "a")
    shell_b = await system_harness.register_shell(system_harness.root / "srv" / "b")
    assert await shell_a.command_started(1, "python3 -m http.server 8000")
    assert await shell_b.command_started(1, "sleep 100")
    await system_harness.snapshot()
    system_harness.mark_process(shell_a.identity, ProcessStatus.DEAD)
    system_harness.mark_process(shell_b.identity, ProcessStatus.DEAD)

    workspace = await system_harness.list_recovery()
    assert {item.shell_id for item in workspace.items} == {shell_a.id, shell_b.id}
    item_by_shell = {item.shell_id: item.item_id for item in workspace.items}
    system_harness.adapter.failures.add(item_by_shell[shell_b.id])
    first = await system_harness.restore(
        workspace.workspace_id,
        selected=(item_by_shell[shell_a.id], item_by_shell[shell_b.id]),
        approved=(item_by_shell[shell_a.id],),
    )
    argv = {action.item_ids[0]: action.argv for action in system_harness.adapter.actions}
    assert argv[item_by_shell[shell_a.id]].count("python3 -m http.server 8000") == 1
    assert "sleep 100" not in argv[item_by_shell[shell_b.id]]

    assert {outcome.item_id: outcome.kind for outcome in first.outcomes} == {
        item_by_shell[shell_a.id]: OutcomeKind.SUCCESS,
        item_by_shell[shell_b.id]: OutcomeKind.FAILURE,
    }
    system_harness.adapter.failures.clear()
    retry = await system_harness.retry(workspace.workspace_id, first.attempt_id)
    assert [outcome.item_id for outcome in retry.outcomes] == [item_by_shell[shell_b.id]]
    assert retry.remaining_item_ids == ()
    assert system_harness.store.load_recovery() is None


@pytest.mark.asyncio
async def test_same_and_prior_boot_recovery_filters_liveness_exit_unknown_and_pid_reuse(
    system_harness,
) -> None:
    live = await system_harness.register_shell(system_harness.root / "live")
    exited = await system_harness.register_shell(system_harness.root / "exited")
    gui_closed = await system_harness.register_shell(system_harness.root / "gui")
    unknown = await system_harness.register_shell(system_harness.root / "unknown")
    reused = await system_harness.register_shell(system_harness.root / "reused")
    prior = await system_harness.register_shell(
        system_harness.root / "prior",
        boot_id="22222222-2222-2222-2222-222222222222",
    )
    assert await exited.explicit_exit()
    await system_harness.snapshot()
    system_harness.mark_process(live.identity, ProcessStatus.ALIVE)
    system_harness.mark_process(gui_closed.identity, ProcessStatus.DEAD)
    system_harness.mark_process(unknown.identity, ProcessStatus.UNKNOWN)
    system_harness.mark_process(reused.identity, ProcessStatus.DEAD)

    response = await system_harness.list_recovery()
    recovered = {item.shell_id: item.reason.value for item in response.items}
    assert recovered == {
        gui_closed.id: "same_boot_dead",
        reused.id: "same_boot_dead",
        prior.id: "previous_boot",
    }
    assert live.id not in recovered
    assert exited.id not in recovered
    assert unknown.id not in recovered
    assert response.diagnostics


@pytest.mark.asyncio
async def test_real_server_rejects_post_exit_events_until_reregistration(system_harness) -> None:
    shell = await system_harness.register_shell(system_harness.root / "terminal-exit")
    assert await shell.explicit_exit()
    exited = system_harness.server.state
    assert not await shell.command_started(1, "sleep 10")
    assert system_harness.server.state is exited
    assert system_harness.server.state.dirty_generation == exited.dirty_generation
    assert system_harness.socket_path.is_socket()

    shell.bridge.close()
    from termrecall.bridge import Bridge
    replacement = Bridge(system_harness.socket_path, shell.id, shell.identity)
    payload = __import__("json").dumps({
        "schema_version": 1,
        "type": "prompt_ready",
        "shell_id": shell.id,
        "cwd": str(system_harness.root / "terminal-exit"),
    }).encode() + b"\n"
    assert await asyncio.to_thread(replacement.process_frame, payload)
    assert system_harness.server.state.snapshot.shells[0].termination is None
    replacement.close()


@pytest.mark.asyncio
async def test_production_checkpoint_scheduler_coalesces_flushes_and_shuts_down_cleanly(
    system_harness,
) -> None:
    first = await system_harness.register_shell(system_harness.root / "coalesce-a")
    second = await system_harness.register_shell(system_harness.root / "coalesce-b")
    assert system_harness.store.list_valid() == ()
    await system_harness.clock.advance(0.249)
    assert system_harness.store.list_valid() == ()
    await system_harness.clock.advance(0.001)
    for _ in range(100):
        if system_harness.checkpoints.status.durable_generation == 4:
            break
        await asyncio.sleep(0.001)
    assert [item.generation for item in system_harness.store.list_valid()] == [4]
    assert system_harness.checkpoints.status.durable_generation == 4

    assert await first.command_started(1, "sleep 10")
    await system_harness.snapshot()
    assert system_harness.checkpoints.status.durable_generation == 5
    assert system_harness.store.load_latest().generation == 5

    system_harness.checkpoint_stop.set()
    system_harness.checkpoints._changed.set()
    assert system_harness.checkpoint_task is not None
    await system_harness.checkpoint_task
    assert system_harness.checkpoint_task.done()
    system_harness.checkpoint_task = None


@pytest.mark.asyncio
async def test_production_checkpoint_degrades_then_retries_at_backoff(
    system_harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_write = system_harness.store.write
    failures = 1

    def flaky_write(snapshot):
        nonlocal failures
        if failures:
            failures -= 1
            raise OSError("injected disk failure")
        return real_write(snapshot)

    monkeypatch.setattr(system_harness.store, "write", flaky_write)
    await system_harness.register_shell(system_harness.root / "retry")
    await system_harness.clock.advance(0.250)
    for _ in range(100):
        if system_harness.checkpoints.status.last_error is not None:
            break
        await asyncio.sleep(0.001)
    degraded = system_harness.checkpoints.status
    assert degraded.durable_generation == 0
    assert degraded.last_error == "OSError: checkpoint write failed"
    assert degraded.next_retry_at == pytest.approx(0.5)
    await system_harness.clock.advance(0.250)
    for _ in range(100):
        if system_harness.checkpoints.status.durable_generation == 2:
            break
        await asyncio.sleep(0.001)
    assert system_harness.checkpoints.status.durable_generation == 2
    assert system_harness.checkpoints.status.last_error is None


@pytest.mark.asyncio
async def test_authenticated_bridge_survives_idle_read_timeout(system_harness) -> None:
    shell = await system_harness.register_shell(system_harness.root / "idle")
    await asyncio.sleep(1.1)
    assert await shell.command_started(1, "sleep 10")
    assert system_harness.server.state.snapshot.shells[0].command is not None


@pytest.mark.asyncio
async def test_service_restart_forces_bridge_reregistration_with_new_capability(
    system_harness,
) -> None:
    shell = await system_harness.register_shell(system_harness.root / "restart")
    first_capability = shell.bridge.capability
    shell.bridge.close()
    await system_harness.snapshot()
    system_harness.checkpoint_stop.set()
    system_harness.checkpoints._changed.set()
    assert system_harness.checkpoint_task is not None
    await system_harness.checkpoint_task
    system_harness.checkpoint_task = None
    await system_harness.server.close()

    # Reopen the persisted snapshot in a fresh service instance without touching real XDG paths.
    from tests.conftest import DeterministicClock, RecordingAdapter
    from termrecall.checkpoint import CheckpointManager
    from termrecall.server import TermRecallServer
    from termrecall.state import EngineState
    from termrecall.store import SnapshotStore

    store = SnapshotStore(system_harness.state)
    snapshot = store.load_latest()
    assert snapshot is not None
    clock = DeterministicClock()
    checkpoints = CheckpointManager(
        store, lambda: server.state.snapshot, clock.now, clock.sleep
    )
    server = TermRecallServer(
        system_harness.socket_path,
        system_harness.server.service_uid,
        EngineState(snapshot, {}, snapshot.generation),
        checkpoints,
        store,
        adapter=RecordingAdapter(),
        current_boot_id=system_harness.server.current_boot_id,
        home=system_harness.home,
        process_probe=lambda _: __import__("termrecall.processes", fromlist=["ProcessProbe"]).ProcessProbe(ProcessStatus.ALIVE),
    )
    await server.start()
    try:
        replacement = Bridge(system_harness.socket_path, shell.id, shell.identity)
        assert await asyncio.to_thread(
            replacement.process_frame,
            __import__("json").dumps({
                "schema_version": 1,
                "type": "prompt_ready",
                "shell_id": shell.id,
                "cwd": str(system_harness.root / "restart"),
            }).encode() + b"\n",
        )
        assert replacement.capability != first_capability
        generation = server.state.dirty_generation
        from termrecall.protocol import EventRequest, Operation

        rejected = await server._dispatch(
            EventRequest(
                Operation.CWD_CHANGED,
                shell.id,
                first_capability,
                shell.identity,
                2,
                cwd=str(system_harness.root / "restart"),
            )
        )
        assert isinstance(rejected, ErrorResponse)
        assert rejected.error.code.value == "unauthorized"
        assert server.state.dirty_generation == generation
        assert await asyncio.to_thread(
            replacement.process_frame,
            __import__("json").dumps({
                "schema_version": 1,
                "type": "cwd_changed",
                "shell_id": shell.id,
                "cwd": str(system_harness.root),
            }).encode() + b"\n",
        )
        assert server.state.dirty_generation == generation + 1
        replacement.close()
    finally:
        await server.close()
        system_harness.server = server
