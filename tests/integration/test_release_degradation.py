# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest

import termrecall.cli as cli
from termrecall.adapters.gnome import GnomeTerminalAdapter
from termrecall.checkpoint import CheckpointManager
from termrecall.client import ServiceClient
from termrecall.model import Snapshot, snapshot_from_dict, snapshot_to_dict
from termrecall.paths import XDGPaths
from termrecall.processes import ProcessStatus
from termrecall.protocol import ErrorCode, ErrorResponse
from termrecall.server import TermRecallServer
from termrecall.state import EngineState
from termrecall.store import SnapshotStore, UnsupportedSchemaVersion


def test_future_recovery_schema_is_preserved_for_newer_version(tmp_path: Path) -> None:
    state = tmp_path / "state"
    store = SnapshotStore(state)
    store.close()
    future = state / "recovery.json"
    payload = b'{"schema_version":99,"workspace_id":"future"}'
    future.write_bytes(payload)
    future.chmod(0o600)
    with pytest.raises(UnsupportedSchemaVersion, match="unsupported schema version 99"):
        SnapshotStore(state)
    assert future.read_bytes() == payload


@pytest.mark.asyncio
async def test_manually_persisted_unsupported_adapter_skips_without_gnome_launch(
    system_harness,
) -> None:
    shell = await system_harness.register_shell(system_harness.root / "legacy-adapter")
    assert await shell.command_started(1, "sleep 10")
    await system_harness.snapshot()
    checkpoint = system_harness.store.load_latest()
    raw = snapshot_to_dict(checkpoint)
    raw["shells"][0]["adapter"] = "wezterm"
    legacy = snapshot_from_dict(raw)
    system_harness.server.state = EngineState(
        legacy,
        {},
        legacy.generation,
    )
    system_harness.mark_process(shell.identity, ProcessStatus.DEAD)
    system_harness.server.adapter = GnomeTerminalAdapter(
        lambda _: "/usr/bin/gnome-terminal",
        runner=lambda argv, **kwargs: (_ for _ in ()).throw(
            AssertionError("unsupported persisted adapter must not launch GNOME")
        ),
    )

    workspace = await system_harness.list_recovery()
    item = workspace.items[0]
    assert item.level.value == "unavailable"
    result = await system_harness.restore(
        workspace.workspace_id,
        (item.item_id,),
        (item.item_id,),
    )
    assert result.outcomes[0].kind.value == "skip"


@pytest.mark.asyncio
async def test_duplicate_restore_is_idempotent_and_completed_item_is_suppressed(
    system_harness,
) -> None:
    shell = await system_harness.register_shell(system_harness.root / "duplicate")
    system_harness.mark_process(shell.identity, ProcessStatus.DEAD)
    await system_harness.snapshot()
    workspace = await system_harness.list_recovery()
    item = workspace.items[0]
    first = await system_harness.restore(workspace.workspace_id, (item.item_id,), ())
    second = await system_harness.restore(workspace.workspace_id, (item.item_id,), ())
    assert isinstance(second, ErrorResponse)
    assert second.error.code is ErrorCode.WORKSPACE_MISMATCH
    assert first.remaining_item_ids == ()
    assert len(system_harness.adapter.actions) == 1
    assert system_harness.store.load_recovery() is None


@pytest.mark.asyncio
async def test_simultaneous_real_coordinators_start_one_service_and_one_chooser(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CURRENT_DESKTOP", "X-Cinnamon")
    paths = XDGPaths(
        tmp_path / "run" / "termrecall",
        tmp_path / "state" / "termrecall",
        tmp_path / "config" / "termrecall",
    )
    paths.state_dir.parent.mkdir(mode=0o700)
    seed = SnapshotStore(paths.state_dir)
    from tests.integration.test_release_durability import recovery
    seed.write_recovery(recovery())
    seed.close()

    servers: list[TermRecallServer] = []
    chooser_calls: list[str] = []
    chooser_started = asyncio.Event()

    def server_factory() -> TermRecallServer:
        store = SnapshotStore(paths.state_dir)
        server: TermRecallServer
        manager = CheckpointManager(
            store, lambda: server.state.snapshot, asyncio.get_running_loop().time, asyncio.sleep
        )
        server = TermRecallServer(
            paths.runtime_dir / "service.sock",
            os.getuid(),
            EngineState(Snapshot(1, 0, 0.0, ()), {}, 0),
            manager,
            store,
            adapter=GnomeTerminalAdapter(lambda _: None),
            current_boot_id="11111111-1111-1111-1111-111111111111",
            home=tmp_path,
        )
        servers.append(server)
        return server

    async def chooser(response) -> None:
        chooser_calls.append(response.workspace_id)
        chooser_started.set()

    stop = asyncio.Event()
    first = asyncio.create_task(
        cli.run_login_coordinator(
            paths,
            stop,
            server_factory,
            lambda: ServiceClient(paths.runtime_dir / "service.sock"),
            chooser,
        )
    )
    await asyncio.wait_for(chooser_started.wait(), 2)
    second = await cli.run_login_coordinator(
        paths,
        asyncio.Event(),
        server_factory,
        lambda: ServiceClient(paths.runtime_dir / "service.sock"),
        chooser,
    )
    assert second == 0
    assert len(servers) == 1
    assert chooser_calls == ["workspace-release"]
    stop.set()
    assert await asyncio.wait_for(first, 2) == 0


@pytest.mark.asyncio
async def test_missing_terminal_and_directory_degrade_without_execution(system_harness) -> None:
    shell = await system_harness.register_shell(system_harness.root / "parent" / "gone")
    assert await shell.command_started(1, "sleep 10")
    await system_harness.snapshot()
    (system_harness.root / "parent" / "gone").rmdir()
    system_harness.mark_process(shell.identity, ProcessStatus.DEAD)
    system_harness.server.adapter = GnomeTerminalAdapter(lambda _: None)
    workspace = await system_harness.list_recovery()
    assert workspace.items[0].directory == str(system_harness.root / "parent")
    result = await system_harness.restore(
        workspace.workspace_id,
        (workspace.items[0].item_id,),
        (workspace.items[0].item_id,),
    )
    assert isinstance(result, ErrorResponse)
    assert result.error.code is ErrorCode.ADAPTER_UNAVAILABLE
    assert system_harness.store.load_recovery() is not None
