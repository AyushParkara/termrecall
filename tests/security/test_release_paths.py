# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import asyncio
import json
import os
import socket
from pathlib import Path

import pytest

from termrecall.cli import _write_chooser_setting
from termrecall.doctor import cleanup_stale_socket
from termrecall.model import Snapshot
from termrecall.paths import XDGPaths
from termrecall.server import UnsafeRuntimePath
from termrecall.store import SnapshotStore, UnsafeStatePath


@pytest.mark.parametrize("kind", ("runtime", "state", "config"))
def test_real_xdg_operations_reject_symlink_ancestors(tmp_path: Path, kind: str) -> None:
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)
    paths = XDGPaths(
        linked / "runtime" if kind == "runtime" else tmp_path / "runtime",
        linked / "state" if kind == "state" else tmp_path / "state",
        linked / "config" if kind == "config" else tmp_path / "config",
    )
    if kind == "runtime":
        from termrecall.server import TermRecallServer
        with pytest.raises(UnsafeRuntimePath):
            TermRecallServer._open_runtime_directory(paths.runtime_dir)
    elif kind == "state":
        with pytest.raises(UnsafeStatePath):
            SnapshotStore(paths.state_dir)
    else:
        with pytest.raises(OSError):
            _write_chooser_setting(paths, True)
    assert tuple(real.iterdir()) == ()


@pytest.mark.parametrize("entry", ("checkpoint", "recovery", "temporary"))
def test_real_store_rejects_symlink_destination_and_temporary_collision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, entry: str
) -> None:
    state = tmp_path / "state"
    store = SnapshotStore(state)
    attacker = tmp_path / "attacker"
    attacker.write_text("unchanged")
    if entry == "checkpoint":
        (state / "checkpoint-00000000000000000001.json").symlink_to(attacker)
        operation = lambda: store.write(Snapshot(1, 1, 1.0, ()))
    elif entry == "recovery":
        (state / "recovery.json").symlink_to(attacker)
        operation = store.load_recovery
    else:
        monkeypatch.setattr("termrecall.store.secrets.token_hex", lambda _: "fixed")
        (state / ".tmp-fixed").symlink_to(attacker)
        operation = lambda: store.write(Snapshot(1, 1, 1.0, ()))
    with pytest.raises((UnsafeStatePath, OSError)):
        operation()
    assert attacker.read_text() == "unchanged"
    store.close()


@pytest.mark.asyncio
async def test_concurrent_real_server_start_has_one_lock_owner_and_preserves_live_socket(
    system_harness,
) -> None:
    from tests.conftest import DeterministicClock, RecordingAdapter
    from termrecall.checkpoint import CheckpointManager
    from termrecall.server import TermRecallServer
    from termrecall.state import EngineState

    second_store = SnapshotStore(system_harness.root / "second-state")
    clock = DeterministicClock()
    second_server: TermRecallServer
    manager = CheckpointManager(
        second_store, lambda: second_server.state.snapshot, clock.now, clock.sleep
    )
    second_server = TermRecallServer(
        system_harness.socket_path,
        os.getuid(),
        EngineState(Snapshot(1, 0, 0.0, ()), {}, 0),
        manager,
        second_store,
        adapter=RecordingAdapter(),
        current_boot_id=system_harness.server.current_boot_id,
        home=system_harness.home,
    )
    identity = system_harness.socket_path.stat().st_ino
    with pytest.raises(UnsafeRuntimePath, match="another service"):
        await second_server.start()
    assert system_harness.socket_path.stat().st_ino == identity
    second_store.close()


def test_real_stale_cleanup_removes_only_verified_exact_inode(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    lock = runtime / "service.lock"
    lock.touch(mode=0o600)
    socket_path = runtime / "service.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    socket_path.chmod(0o600)
    identity = (socket_path.stat().st_dev, socket_path.stat().st_ino)
    listener.close()
    paths = XDGPaths(runtime, tmp_path / "state", tmp_path / "config")
    assert cleanup_stale_socket(paths) == identity
    assert not socket_path.exists()
    assert lock.is_file()
