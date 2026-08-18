# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import asyncio
import json
import os
import stat
import threading
from dataclasses import replace
from pathlib import Path

import pytest

from termrecall.model import (
    CommandDisposition,
    CommandRecord,
    Outcome,
    OutcomeKind,
    ProcessIdentity,
    RecoveryItemRecord,
    RecoveryRecord,
    RestoreAttempt,
    ShellRecord,
    Snapshot,
)
from termrecall.processes import ProcessStatus
from termrecall.store import SnapshotStore


def snapshot(generation: int) -> Snapshot:
    return Snapshot(1, generation, float(generation), ())


def recovery(workspace: str = "workspace-release") -> RecoveryRecord:
    shell = ShellRecord(
        "shell-release-item",
        ProcessIdentity("22222222-2222-2222-2222-222222222222", 42, 900),
        "gnome-terminal",
        "/tmp",
        2,
        CommandRecord(1, "sleep 10", "sleep 10", CommandDisposition.REPLAYABLE, True),
        None,
    )
    return RecoveryRecord(
        1,
        workspace,
        1,
        1.0,
        (RecoveryItemRecord("item-release", shell, "previous_boot"),),
        (),
        (),
    )


def inject_atomic_failure(monkeypatch: pytest.MonkeyPatch, store: SnapshotStore, point: str) -> None:
    real_open, real_write, real_fsync, real_replace = os.open, os.write, os.fsync, os.replace
    state_fd = store._state_fd
    temporary_fds: set[int] = set()
    writes = 0

    def attacked_open(path, flags, *args, **kwargs):
        if point == "temporary_create" and isinstance(path, str) and path.startswith(".tmp-"):
            raise OSError("injected temporary create failure")
        fd = real_open(path, flags, *args, **kwargs)
        if isinstance(path, str) and path.startswith(".tmp-"):
            temporary_fds.add(fd)
        return fd

    def attacked_write(fd, data):
        nonlocal writes
        if point == "partial_write" and fd in temporary_fds:
            writes += 1
            if writes == 1:
                return real_write(fd, data[: max(1, len(data) // 2)])
            raise OSError("injected partial write failure")
        return real_write(fd, data)

    def attacked_fsync(fd):
        if point == "file_fsync" and fd in temporary_fds:
            raise OSError("injected file fsync failure")
        result = real_fsync(fd)
        if point == "directory_fsync" and fd == state_fd:
            raise OSError("injected directory fsync failure")
        return result

    def attacked_replace(src, dst, **kwargs):
        if point == "replace":
            raise OSError("injected replace failure")
        return real_replace(src, dst, **kwargs)

    monkeypatch.setattr(os, "open", attacked_open)
    monkeypatch.setattr(os, "write", attacked_write)
    monkeypatch.setattr(os, "fsync", attacked_fsync)
    monkeypatch.setattr(os, "replace", attacked_replace)
    if point == "validation":
        real_decode = store._decode
        calls = 0

        def attacked_decode(payload, decoder):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise ValueError("injected validation failure")
            return real_decode(payload, decoder)

        monkeypatch.setattr(store, "_decode", attacked_decode)


@pytest.mark.parametrize(
    "point",
    ("temporary_create", "partial_write", "file_fsync", "validation", "replace", "directory_fsync"),
)
def test_real_checkpoint_crash_matrix_reopens_prior_or_complete_new_schema_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, point: str
) -> None:
    state = tmp_path / "state"
    store = SnapshotStore(state)
    store.write(snapshot(1))
    inject_atomic_failure(monkeypatch, store, point)
    with pytest.raises((OSError, ValueError), match="injected"):
        store.write(snapshot(2))
    monkeypatch.undo()
    store.close()

    reopened = SnapshotStore(state)
    valid = reopened.list_valid()
    assert valid
    assert {item.generation for item in valid} <= {1, 2}
    assert all(item.schema_version == 1 for item in valid)
    for path in state.glob("checkpoint-*.json"):
        assert json.loads(path.read_bytes())["schema_version"] == 1
    assert not tuple(state.glob(".tmp-*"))
    reopened.close()


@pytest.mark.parametrize(
    "point",
    ("temporary_create", "partial_write", "file_fsync", "validation", "replace", "directory_fsync"),
)
def test_real_recovery_crash_matrix_reopens_prior_or_complete_new_schema_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, point: str
) -> None:
    state = tmp_path / "state"
    store = SnapshotStore(state)
    prior = recovery()
    store.write_recovery(prior)
    newer = replace(prior, created_at=2.0)
    inject_atomic_failure(monkeypatch, store, point)
    with pytest.raises((OSError, ValueError), match="injected"):
        store._update_recovery(
            newer,
            expected_workspace_id=prior.workspace_id,
            expected_generation=prior.source_generation,
        )
    monkeypatch.undo()
    store.close()

    reopened = SnapshotStore(state)
    loaded = reopened.load_recovery()
    assert loaded in (prior, newer)
    raw = json.loads((state / "recovery.json").read_bytes())
    assert raw["schema_version"] == 1
    assert not tuple(state.glob(".tmp-*"))
    reopened.close()


@pytest.mark.asyncio
async def test_real_service_ack_waits_for_recovery_outcome_and_tombstone_directory_fsync(
    system_harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    shell = await system_harness.register_shell(system_harness.root / "durability")
    assert await shell.command_started(1, "sleep 10")
    await system_harness.snapshot()
    system_harness.mark_process(shell.identity, ProcessStatus.DEAD)

    real_fsync = os.fsync
    entered = threading.Event()
    release = threading.Event()
    armed = threading.Event()

    def blocking_fsync(fd: int) -> None:
        real_fsync(fd)
        if armed.is_set() and stat.S_ISDIR(os.fstat(fd).st_mode):
            armed.clear()
            entered.set()
            assert release.wait(timeout=2)

    monkeypatch.setattr(os, "fsync", blocking_fsync)

    armed.set()
    listing = asyncio.create_task(system_harness.list_recovery())
    assert await asyncio.to_thread(entered.wait, 1)
    assert not listing.done()
    release.set()
    workspace = await listing
    assert system_harness.store.load_recovery() is not None

    entered.clear(); release.clear(); armed.set()
    item = workspace.items[0]
    system_harness.adapter.failures.add(item.item_id)
    restoring = asyncio.create_task(
        system_harness.restore(workspace.workspace_id, (item.item_id,), ())
    )
    assert await asyncio.to_thread(entered.wait, 1)
    assert not restoring.done()
    release.set()
    result = await restoring
    persisted = system_harness.store.load_recovery()
    assert persisted is not None and persisted.attempts[-1].attempt_id == result.attempt_id

    entered.clear(); release.clear(); armed.set()
    discarding = asyncio.create_task(system_harness.discard(workspace.workspace_id))
    assert await asyncio.to_thread(entered.wait, 1)
    assert not discarding.done()
    release.set()
    await discarding
    assert system_harness.store.load_recovery() is None
    assert (system_harness.state / "recovery-discard.json").is_file()
