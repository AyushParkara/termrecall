# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import asyncio
import errno
import fcntl
import json
import os
import socket
import stat
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest

import termrecall.server as server_module
from termrecall.adapters.base import AdapterCapabilities, LaunchAction
from termrecall.adapters.gnome import GnomeTerminalAdapter
from termrecall.model import (
    CommandDisposition,
    CommandRecord,
    Outcome,
    OutcomeKind,
    ProcessIdentity,
    RecoveryItemRecord,
    RecoveryRecord,
    RestorationLevel,
    RestoreAttempt,
    ShellRecord,
    Snapshot,
)
from termrecall.processes import ProcessProbe, ProcessStatus
from termrecall.recovery import RecoveryReason, derive_attempt_id, safe_recovery_reason
from termrecall.protocol import MAX_MESSAGE_BYTES, decode_response
from termrecall.server import (
    PeerCredentials,
    TermRecallServer,
    UnsafeRuntimePath,
    get_peer_credentials,
)
from termrecall.state import EngineState

IDENTITY = ProcessIdentity("123e4567-e89b-12d3-a456-426614174000", 1234, 5678)
SHELL_ID = "shell-identifier-1"
COMMAND_SENTINEL = "printf TASK9_SECRET_COMMAND"
SECOND_SHELL_ID = "123e4567-e89b-12d3-a456-426614174001"


def line(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode() + b"\n"


def register_wire(*, cwd: str = "/home/user") -> bytes:
    return line(
        {
            "schema_version": 1,
            "operation": "register",
            "shell_id": SHELL_ID,
            "identity": {
                "boot_id": IDENTITY.boot_id,
                "pid": IDENTITY.pid,
                "start_time": IDENTITY.start_time,
            },
            "adapter": "gnome-terminal",
            "cwd": cwd,
            "sequence": 0,
        }
    )


def event_wire(operation: str, capability: str, sequence: int, **extra: object) -> bytes:
    value: dict[str, object] = {
        "schema_version": 1,
        "operation": operation,
        "shell_id": SHELL_ID,
        "capability": capability,
        "identity": {
            "boot_id": IDENTITY.boot_id,
            "pid": IDENTITY.pid,
            "start_time": IDENTITY.start_time,
        },
        "sequence": sequence,
    }
    value.update(extra)
    return line(value)


@dataclass
class FakeStatus:
    dirty_generation: int = 0
    durable_generation: int = 0
    write_active: bool = False
    last_error: str | None = None
    next_retry_at: float | None = None


class FakeCheckpoints:
    def __init__(self) -> None:
        self.status = FakeStatus()
        self.marked: list[int] = []
        self.flush_result: FakeStatus | None = None
        self.mark_error: Exception | None = None

    async def mark_dirty(self, generation: int) -> None:
        if self.mark_error is not None:
            raise self.mark_error
        self.marked.append(generation)
        self.status.dirty_generation = generation

    async def flush(self) -> FakeStatus:
        return self.flush_result or self.status


class FakeStore:
    diagnostics: list[str]

    def __init__(self) -> None:
        self.diagnostics = []
        self.recovery = None
        self.written = []
        self.commits = []
        self.completed = []
        self.commit_error = None
        self.complete_error = None
        self.commit_started = None
        self.commit_release = None

    def load_recovery(self):
        return self.recovery

    def write_recovery(self, record):
        if self.recovery is None:
            self.recovery = record
            self.written.append(record)

    def commit_outcomes(self, workspace_id, attempt, outcomes):
        if self.commit_started is not None:
            self.commit_started.set()
        if self.commit_release is not None:
            self.commit_release.wait(timeout=5)
        if self.commit_error is not None:
            raise self.commit_error
        completed = list(self.recovery.completed_item_ids)
        for outcome in outcomes:
            if outcome.kind in (OutcomeKind.SUCCESS, OutcomeKind.WARNING) and outcome.item_id not in completed:
                completed.append(outcome.item_id)
        committed = RestoreAttempt(attempt.attempt_id, attempt.workspace_id, attempt.selected_item_ids, attempt.approved_item_ids, tuple(outcomes))
        self.recovery = __import__("dataclasses").replace(self.recovery, attempts=(*self.recovery.attempts, committed), completed_item_ids=tuple(completed))
        self.commits.append((workspace_id, committed, tuple(outcomes)))
        return self.recovery

    def complete_or_discard(self, workspace_id, *, discard):
        self.completed.append((workspace_id, discard))
        if self.complete_error is not None:
            error = self.complete_error
            self.complete_error = None
            raise error
        self.recovery = None


class MemoryReader:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.calls: list[int] = []

    async def readline(self, limit: int = -1) -> bytes:
        self.calls.append(limit)
        return self.payload[:limit] if limit >= 0 else self.payload


class MemoryWriter:
    def __init__(self, peer_uid: int, *, peer_pid: int = IDENTITY.pid) -> None:
        self.socket = SimpleNamespace(peer_uid=peer_uid, peer_pid=peer_pid)
        self.data = bytearray()
        self.closed = False

    def get_extra_info(self, name: str):
        return self.socket if name == "socket" else None

    def write(self, raw: bytes) -> None:
        self.data.extend(raw)

    async def drain(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        pass


@pytest.fixture
def initial_state() -> EngineState:
    return EngineState(Snapshot(1, 0, 100.0, ()), {}, 0)


@pytest.fixture
def server_factory(tmp_path: Path, initial_state: EngineState, monkeypatch):
    monkeypatch.setattr(
        "termrecall.server.get_peer_credentials",
        lambda sock: PeerCredentials(
            getattr(sock, "peer_pid", IDENTITY.pid),
            getattr(sock, "peer_uid", os.getuid()),
            99,
        ),
    )

    def make(
        runtime: Path | None = None,
        *,
        peer_uid: int = 1000,
        peer_pid: int = IDENTITY.pid,
        service_uid: int = 1000,
        checkpoints: FakeCheckpoints | None = None,
        store: FakeStore | None = None,
        adapter=None,
        current_boot_id: str = IDENTITY.boot_id,
        home: Path | None = None,
        process_probe=None,
    ):
        server = TermRecallServer(
            (runtime or tmp_path / "run" / "termrecall") / "service.sock",
            service_uid,
            initial_state,
            checkpoints or FakeCheckpoints(),
            store or FakeStore(),
            adapter=adapter,
            current_boot_id=current_boot_id,
            home=home or tmp_path,
            process_probe=process_probe or (lambda _: ProcessProbe(ProcessStatus.DEAD)),
        )
        server.peer_uid = peer_uid
        server.peer_pid = peer_pid
        return server

    return make


async def dispatch(
    server: TermRecallServer,
    raw: bytes,
    *,
    uid: int | None = None,
    pid: int | None = None,
):
    reader = MemoryReader(raw)
    writer = MemoryWriter(
        server.peer_uid if uid is None else uid,
        peer_pid=server.peer_pid if pid is None else pid,
    )
    await server.handle_connection(reader, writer)
    assert writer.closed
    return json.loads(writer.data), bytes(writer.data), reader


def test_get_peer_credentials_uses_linux_socket_credentials() -> None:
    left, right = socket.socketpair(socket.AF_UNIX)
    try:
        credentials = get_peer_credentials(left)
    finally:
        left.close()
        right.close()
    assert credentials.uid == os.getuid()
    assert credentials.gid == os.getgid()
    assert credentials.pid == os.getpid()


@pytest.mark.asyncio
async def test_start_unix_server_disables_supported_automatic_cleanup(monkeypatch) -> None:
    received: dict[str, object] = {}
    sentinel = object()

    async def supports_cleanup_socket(
        callback, path=None, *, cleanup_socket=True, **kwargs
    ):
        received.update(callback=callback, path=path, cleanup_socket=cleanup_socket, **kwargs)
        return sentinel

    monkeypatch.setattr(server_module.asyncio, "start_unix_server", supports_cleanup_socket)
    callback = object()
    bound_socket = object()

    result = await server_module._start_unix_server(callback, bound_socket)

    assert result is sentinel
    assert received == {
        "callback": callback,
        "path": None,
        "cleanup_socket": False,
        "sock": bound_socket,
        "limit": MAX_MESSAGE_BYTES + 1,
    }


@pytest.mark.asyncio
async def test_start_unix_server_omits_unsupported_automatic_cleanup(monkeypatch) -> None:
    received: dict[str, object] = {}
    sentinel = object()

    async def lacks_cleanup_socket(callback, path=None, *, limit=65536, sock=None):
        received.update(callback=callback, path=path, limit=limit, sock=sock)
        return sentinel

    monkeypatch.setattr(server_module.asyncio, "start_unix_server", lacks_cleanup_socket)
    callback = object()
    bound_socket = object()

    result = await server_module._start_unix_server(callback, bound_socket)

    assert result is sentinel
    assert received == {
        "callback": callback,
        "path": None,
        "limit": MAX_MESSAGE_BYTES + 1,
        "sock": bound_socket,
    }


@pytest.mark.asyncio
async def test_start_creates_private_runtime_lock_and_socket(tmp_path: Path, server_factory) -> None:
    runtime = tmp_path / "run" / "termrecall"
    server = server_factory(runtime)
    await server.start()
    try:
        assert stat.S_IMODE(runtime.stat().st_mode) == 0o700
        assert server.socket_path.is_socket()
        assert stat.S_IMODE(server.socket_path.stat().st_mode) == 0o600
        assert stat.S_IMODE((runtime / "service.lock").stat().st_mode) == 0o600
    finally:
        await server.close()
    assert not server.socket_path.exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", [0o750, 0o707])
async def test_start_rejects_group_or_world_accessible_runtime(
    tmp_path: Path, server_factory, mode: int
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=mode)
    runtime.chmod(mode)
    server = server_factory(runtime)
    with pytest.raises(UnsafeRuntimePath, match="mode"):
        await server.start()


@pytest.mark.asyncio
async def test_start_rejects_foreign_owned_runtime(tmp_path: Path, server_factory, monkeypatch) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    real_fstat = os.fstat

    def foreign_runtime(fd: int):
        result = real_fstat(fd)
        if stat.S_ISDIR(result.st_mode) and Path(f"/proc/self/fd/{fd}").resolve() == runtime:
            values = list(result)
            values[4] = os.getuid() + 1
            return os.stat_result(values)
        return result

    monkeypatch.setattr("termrecall.server.os.fstat", foreign_runtime)
    with pytest.raises(UnsafeRuntimePath, match="owner"):
        await server_factory(runtime).start()


@pytest.mark.asyncio
@pytest.mark.parametrize("entry_kind", ["symlink", "directory", "wrong_mode"])
async def test_start_rejects_unsafe_preexisting_lock(
    tmp_path: Path, server_factory, entry_kind: str
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    lock_path = runtime / "service.lock"
    if entry_kind == "symlink":
        lock_path.symlink_to(runtime / "missing")
    elif entry_kind == "directory":
        lock_path.mkdir(mode=0o700)
    else:
        lock_path.write_bytes(b"")
        lock_path.chmod(0o644)
    before = lock_path.lstat()

    with pytest.raises(UnsafeRuntimePath, match="service.lock"):
        await server_factory(runtime).start()

    after = lock_path.lstat()
    assert (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino)
    assert not (runtime / "service.sock").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("entry_kind", ["symlink", "regular", "dead_socket"])
async def test_start_never_replaces_preexisting_socket_entry(
    tmp_path: Path, server_factory, entry_kind: str
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    path = runtime / "service.sock"
    held_socket = None
    if entry_kind == "symlink":
        path.symlink_to(runtime / "missing")
    elif entry_kind == "regular":
        path.write_bytes(b"operator-owned")
    else:
        held_socket = socket.socket(socket.AF_UNIX)
        held_socket.bind(str(path))
        held_socket.close()
    before = path.lstat()
    with pytest.raises(UnsafeRuntimePath, match="already exists"):
        await server_factory(runtime).start()
    after = path.lstat()
    assert (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino)


@pytest.mark.asyncio
async def test_socket_created_after_absence_check_is_not_unlinked_or_replaced(
    tmp_path: Path, server_factory, monkeypatch
) -> None:
    runtime = tmp_path / "runtime"
    server = server_factory(runtime)
    raced_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    real_socket = socket.socket
    injected = False
    raced_identity: tuple[int, int] | None = None

    def inject_before_server_socket(family=socket.AF_INET, type=socket.SOCK_STREAM, *args, **kwargs):
        nonlocal injected, raced_identity
        if family == socket.AF_UNIX and type == socket.SOCK_STREAM and not injected:
            injected = True
            raced_socket.bind(str(runtime / "service.sock"))
            metadata = server.socket_path.lstat()
            raced_identity = (metadata.st_dev, metadata.st_ino)
        return real_socket(family, type, *args, **kwargs)

    monkeypatch.setattr("termrecall.server.socket.socket", inject_before_server_socket)
    try:
        with pytest.raises(OSError) as raised:
            await server.start()
        assert raised.value.errno == errno.EADDRINUSE
        raced = server.socket_path.lstat()
        assert stat.S_ISSOCK(raced.st_mode)
        assert (raced.st_dev, raced.st_ino) == raced_identity
    finally:
        raced_socket.close()
        server.socket_path.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_failed_start_removes_unchanged_owned_socket_and_allows_fresh_start(
    tmp_path: Path, server_factory, monkeypatch
) -> None:
    runtime = tmp_path / "runtime"
    server = server_factory(runtime)
    real_chmod = os.chmod
    bound_socket = None
    real_socket = socket.socket

    def capture_bound_socket(*args, **kwargs):
        nonlocal bound_socket
        bound_socket = real_socket(*args, **kwargs)
        return bound_socket

    def fail_socket_chmod(path, mode, *, dir_fd=None, follow_symlinks=True):
        if path == "service.sock":
            raise OSError("injected chmod failure")
        return real_chmod(path, mode, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

    monkeypatch.setattr("termrecall.server.socket.socket", capture_bound_socket)
    monkeypatch.setattr("termrecall.server.os.chmod", fail_socket_chmod)
    with pytest.raises(OSError, match="injected"):
        await server.start()
    assert bound_socket is not None
    assert bound_socket.fileno() == -1
    assert not (runtime / "service.sock").exists()
    monkeypatch.undo()
    fresh = server_factory(runtime)
    await fresh.start()
    await fresh.close()


@pytest.mark.asyncio
async def test_start_unix_failure_removes_unchanged_owned_socket(
    tmp_path: Path, server_factory, monkeypatch
) -> None:
    runtime = tmp_path / "runtime"
    server = server_factory(runtime)

    async def fail_start_unix(callback, bound_socket):
        raise OSError("injected start_unix failure")

    monkeypatch.setattr(server_module, "_start_unix_server", fail_start_unix)
    with pytest.raises(OSError, match="start_unix"):
        await server.start()
    assert not (runtime / "service.sock").exists()
    fresh = server_factory(runtime)
    monkeypatch.undo()
    await fresh.start()
    await fresh.close()


@pytest.mark.asyncio
async def test_start_unix_failure_preserves_replacement_socket(
    tmp_path: Path, server_factory, monkeypatch
) -> None:
    runtime = tmp_path / "runtime"
    server = server_factory(runtime)
    replacement = socket.socket(socket.AF_UNIX)

    async def replace_then_fail(callback, bound_socket):
        (runtime / "service.sock").unlink()
        replacement.bind(str(runtime / "service.sock"))
        raise OSError("injected start_unix failure")

    monkeypatch.setattr(server_module, "_start_unix_server", replace_then_fail)
    try:
        with pytest.raises(OSError, match="start_unix"):
            await server.start()
        assert (runtime / "service.sock").is_socket()
    finally:
        replacement.close()
        (runtime / "service.sock").unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_start_rejects_socket_replaced_during_creation_without_unlinking_replacement(
    tmp_path: Path, server_factory, monkeypatch
) -> None:
    runtime = tmp_path / "runtime"
    server = server_factory(runtime)
    replacement = socket.socket(socket.AF_UNIX)
    real_chmod = os.chmod

    def replace_before_chmod(path, mode, *, dir_fd=None, follow_symlinks=True):
        if path == "service.sock":
            os.unlink(path, dir_fd=dir_fd)
            replacement.bind(str(runtime / "service.sock"))
        return real_chmod(path, mode, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

    monkeypatch.setattr("termrecall.server.os.chmod", replace_before_chmod)
    try:
        with pytest.raises(UnsafeRuntimePath, match="changed during creation"):
            await server.start()
        assert server.socket_path.is_socket()
    finally:
        replacement.close()
        server.socket_path.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_singleton_lock_allows_exactly_one_server(tmp_path: Path, server_factory) -> None:
    runtime = tmp_path / "runtime"
    first = server_factory(runtime)
    second = server_factory(runtime)
    results = await asyncio.gather(first.start(), second.start(), return_exceptions=True)
    try:
        assert sum(result is None for result in results) == 1
        failure = next(result for result in results if result is not None)
        assert isinstance(failure, UnsafeRuntimePath)
        assert first.socket_path.is_socket()
    finally:
        await first.close()
        await second.close()


@pytest.mark.asyncio
async def test_close_closes_blocked_connection_before_socket_and_lock_cleanup(
    tmp_path: Path, server_factory
) -> None:
    runtime = tmp_path / "runtime"
    server = server_factory(runtime, peer_uid=os.getuid(), service_uid=os.getuid())
    await server.start()
    reader, writer = await asyncio.open_unix_connection(server.socket_path)
    for _ in range(20):
        if server._connection_tasks:
            break
        await asyncio.sleep(0)
    assert len(server._connection_tasks) == 1
    assert len(server._connection_writers) == 1

    await asyncio.wait_for(server.close(), timeout=0.5)

    assert not server.socket_path.exists()
    assert not server._connection_tasks
    assert not server._connection_writers
    assert await reader.read() == b""
    writer.close()
    await writer.wait_closed()
    lock_fd = os.open(runtime / "service.lock", os.O_RDWR | os.O_NOFOLLOW)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(lock_fd)


@pytest.mark.asyncio
async def test_orderly_close_removes_exact_owned_socket(
    tmp_path: Path, server_factory
) -> None:
    server = server_factory(tmp_path / "runtime")
    await server.start()

    await server.close()

    assert not server.socket_path.exists()


@pytest.mark.asyncio
async def test_close_does_not_unlink_replacement_inode(tmp_path: Path, server_factory) -> None:
    server = server_factory(tmp_path / "runtime")
    await server.start()
    server.socket_path.unlink()
    server.socket_path.write_bytes(b"replacement")
    replacement = server.socket_path.stat()
    await server.close()
    assert server.socket_path.read_bytes() == b"replacement"
    assert server.socket_path.stat().st_ino == replacement.st_ino
    assert server.diagnostics == ["service.sock changed before shutdown cleanup"]


@pytest.mark.asyncio
async def test_close_is_anchored_if_runtime_path_is_swapped_for_symlink(
    tmp_path: Path, server_factory
) -> None:
    runtime = tmp_path / "runtime"
    moved = tmp_path / "verified-runtime"
    attacker = tmp_path / "attacker"
    server = server_factory(runtime)
    await server.start()
    runtime.rename(moved)
    attacker.mkdir()
    (attacker / "service.sock").write_bytes(b"untouched")
    runtime.symlink_to(attacker, target_is_directory=True)
    await server.close()
    assert not (moved / "service.sock").exists()
    assert (attacker / "service.sock").read_bytes() == b"untouched"


@pytest.mark.asyncio
async def test_wrong_uid_peer_is_rejected_before_decode(server_factory) -> None:
    server = server_factory(peer_uid=2000, service_uid=1000)
    response, raw, reader = await dispatch(server, b"not json\n")
    assert response == {
        "schema_version": 1,
        "ok": False,
        "response": "error",
        "error": {"code": "peer_rejected", "message": "peer uid rejected"},
    }
    assert reader.calls == []
    assert server.state == server.initial_state
    assert COMMAND_SENTINEL.encode() not in raw


@pytest.mark.asyncio
async def test_unavailable_peer_credentials_are_rejected_before_decode(
    server_factory, monkeypatch
) -> None:
    server = server_factory()

    def fail_credentials(sock):
        raise OSError("credentials unavailable")

    monkeypatch.setattr("termrecall.server.get_peer_credentials", fail_credentials)
    response, raw, reader = await dispatch(server, b"not json\n")
    assert response == {
        "schema_version": 1,
        "ok": False,
        "response": "error",
        "error": {"code": "peer_rejected", "message": "peer uid rejected"},
    }
    assert reader.calls == []
    assert server.state == server.initial_state
    assert COMMAND_SENTINEL.encode() not in raw


@pytest.mark.asyncio
@pytest.mark.parametrize("raw", [b"{broken\n", b"", b"[]\n"])
async def test_malformed_request_maps_to_fixed_invalid_request(server_factory, raw: bytes) -> None:
    response, encoded, _ = await dispatch(server_factory(), raw)
    assert response["error"] == {"code": "invalid_request", "message": "request rejected"}
    assert COMMAND_SENTINEL.encode() not in encoded


@pytest.mark.asyncio
async def test_request_read_is_bounded_to_16_kib_plus_one(server_factory) -> None:
    response, _, reader = await dispatch(server_factory(), b"x" * (MAX_MESSAGE_BYTES + 100))
    assert reader.calls == [MAX_MESSAGE_BYTES + 1]
    assert response["error"]["code"] == "invalid_request"


@pytest.mark.asyncio
async def test_register_and_every_lifecycle_event_return_exact_typed_responses(server_factory) -> None:
    server = server_factory()
    response, raw, _ = await dispatch(server, register_wire())
    capability = response.pop("capability")
    assert len(capability) >= 32
    assert response == {"schema_version": 1, "ok": True, "response": "register", "resume_sequence": 0}
    assert server.checkpoints.marked == [1]

    events = [
        ("command_started", {"command_sequence": 1, "command": COMMAND_SENTINEL}),
        ("command_finished", {"command_sequence": 1, "exit_status": 0}),
        ("prompt_ready", {"cwd": "/srv/app"}),
        ("cwd_changed", {"cwd": "/srv/next"}),
        ("explicit_exit", {}),
    ]
    for sequence, (operation, extra) in enumerate(events, 1):
        response, raw, _ = await dispatch(server, event_wire(operation, capability, sequence, **extra))
        assert response == {
            "schema_version": 1,
            "ok": True,
            "response": "event",
            "sequence": sequence,
        }
        assert COMMAND_SENTINEL.encode() not in raw
    assert server.checkpoints.marked == [1, 2, 3, 4, 5, 6]


@pytest.mark.asyncio
async def test_register_rejects_identity_pid_mismatch_with_peer_pid(server_factory) -> None:
    server = server_factory()
    # The wire identity claims pid 1234, but the connecting peer's real pid is
    # 9999, so registration must be rejected as an impersonation attempt.
    response, _, _ = await dispatch(server, register_wire(), pid=9999)
    assert response == {
        "schema_version": 1,
        "ok": False,
        "response": "error",
        "error": {"code": "invalid_request", "message": "request rejected"},
    }
    assert server.state.registrations == {}


@pytest.mark.asyncio
async def test_register_accepts_matching_peer_pid(server_factory) -> None:
    server = server_factory()
    response, _, _ = await dispatch(server, register_wire(), pid=IDENTITY.pid)
    assert response["ok"] is True
    assert response["response"] == "register"
    assert set(server.state.registrations) == {SHELL_ID}


@pytest.mark.asyncio
async def test_reconnect_returns_resume_sequence_and_rejects_stale_events(
    server_factory,
) -> None:
    # Findings #10/#11: a reconnect must report the persisted sequence watermark
    # via resume_sequence and must reject stale duplicate events.
    server = server_factory()
    response, _, _ = await dispatch(server, register_wire())
    capability = response["capability"]
    assert response["resume_sequence"] == 0
    # Accept one event (sequence 1).
    response, _, _ = await dispatch(
        server, event_wire("prompt_ready", capability, 1, cwd="/srv/app")
    )
    assert response["sequence"] == 1
    # Reconnect the same shell id; the server must report resume_sequence=1.
    response, _, _ = await dispatch(server, register_wire())
    new_capability = response["capability"]
    assert response["resume_sequence"] == 1
    # A stale duplicate of event 1 must be rejected.
    stale, _, _ = await dispatch(
        server, event_wire("prompt_ready", new_capability, 1, cwd="/srv/app")
    )
    assert stale["ok"] is False


@pytest.mark.asyncio
async def test_concurrent_registrations_are_serialized(server_factory) -> None:
    class YieldingCheckpoints(FakeCheckpoints):
        async def mark_dirty(self, generation: int) -> None:
            await asyncio.sleep(0)
            await super().mark_dirty(generation)

    server = server_factory(checkpoints=YieldingCheckpoints())
    first = json.loads(register_wire())
    second = dict(first)
    second["shell_id"] = "shell-identifier-2"
    second["identity"] = dict(first["identity"], pid=4321)

    responses = await asyncio.gather(
        dispatch(server, line(first)),
        dispatch(server, line(second), pid=4321),
    )

    assert all(response[0]["ok"] for response in responses)
    assert set(server.state.registrations) == {SHELL_ID, "shell-identifier-2"}
    assert server.state.dirty_generation == 2
    assert server.checkpoints.marked == [1, 2]


@pytest.mark.asyncio
async def test_connection_cancellation_propagates(server_factory) -> None:
    checkpoints = FakeCheckpoints()
    checkpoints.mark_error = asyncio.CancelledError()
    server = server_factory(checkpoints=checkpoints)
    reader = MemoryReader(register_wire())
    writer = MemoryWriter(server.peer_uid)

    with pytest.raises(asyncio.CancelledError):
        await server.handle_connection(reader, writer)

    assert server.state == server.initial_state
    assert writer.data == b""
    assert writer.closed


@pytest.mark.asyncio
async def test_checkpoint_failure_does_not_publish_mutated_state(server_factory) -> None:
    checkpoints = FakeCheckpoints()
    checkpoints.mark_error = RuntimeError(COMMAND_SENTINEL)
    server = server_factory(checkpoints=checkpoints)
    original = server.state

    response, raw, _ = await dispatch(server, register_wire())

    assert response["error"] == {
        "code": "internal_error",
        "message": "request could not be completed",
    }
    assert server.state is original
    assert COMMAND_SENTINEL.encode() not in raw


@pytest.mark.asyncio
async def test_authority_and_sequence_failures_are_distinct_and_do_not_mutate(server_factory) -> None:
    server = server_factory()
    registered, _, _ = await dispatch(server, register_wire())
    capability = registered["capability"]
    accepted = event_wire("cwd_changed", capability, 1, cwd="/one")
    await dispatch(server, accepted)
    original = server.state

    unauthorized, unauthorized_raw, _ = await dispatch(
        server, event_wire("cwd_changed", "x" * 43, 2, cwd="/unauthorized")
    )
    sequence, sequence_raw, _ = await dispatch(
        server, event_wire("cwd_changed", capability, 1, cwd="/duplicate")
    )
    assert unauthorized["error"] == {"code": "unauthorized", "message": "event authority rejected"}
    assert sequence["error"] == {"code": "sequence_rejected", "message": "event sequence rejected"}
    assert server.state is original
    assert COMMAND_SENTINEL.encode() not in unauthorized_raw + sequence_raw


@pytest.mark.asyncio
async def test_status_reports_registry_checkpoint_and_store_without_command_data(server_factory) -> None:
    checkpoints = FakeCheckpoints()
    checkpoints.status = FakeStatus(4, 3, True, f"RuntimeError: {COMMAND_SENTINEL}", 10.0)
    store = FakeStore()
    store.diagnostics = [COMMAND_SENTINEL]
    store.recovery = SimpleNamespace(items=(1, 2), completed_item_ids=(1,))
    server = server_factory(checkpoints=checkpoints, store=store)
    await dispatch(server, register_wire(cwd="/status-shell"))
    checkpoints.status = FakeStatus(4, 3, True, f"RuntimeError: {COMMAND_SENTINEL}", 10.0)

    response, raw, _ = await dispatch(
        server, line({"schema_version": 1, "operation": "status"})
    )
    assert response == {
        "schema_version": 1,
        "ok": True,
        "response": "status",
        "ready": True,
        "registered_shells": 1,
        "dirty_generation": 4,
        "durable_generation": 3,
        "write_active": True,
        "durability_degraded": True,
        "last_error": "details unavailable",
        "recovery_item_count": 1,
        "diagnostics": ["details unavailable"],
    }
    assert COMMAND_SENTINEL.encode() not in raw


@pytest.mark.asyncio
async def test_snapshot_requires_entry_generation_to_be_durable(server_factory) -> None:
    checkpoints = FakeCheckpoints()
    checkpoints.status = FakeStatus(3, 1)
    checkpoints.flush_result = FakeStatus(4, 3)
    server = server_factory(checkpoints=checkpoints)
    server.state = EngineState(Snapshot(1, 3, 100.0, ()), {}, 3)
    success, _, _ = await dispatch(
        server, line({"schema_version": 1, "operation": "snapshot"})
    )
    assert success == {
        "schema_version": 1,
        "ok": True,
        "response": "snapshot",
        "durable_generation": 3,
    }

    checkpoints.flush_result = FakeStatus(4, 2, last_error=COMMAND_SENTINEL)
    failure, raw, _ = await dispatch(
        server, line({"schema_version": 1, "operation": "snapshot"})
    )
    assert failure["error"] == {
        "code": "persistence_failed",
        "message": "recovery state was not saved",
    }
    assert COMMAND_SENTINEL.encode() not in raw


@pytest.mark.asyncio
async def test_restore_list_without_recovery_has_exact_empty_schema(server_factory) -> None:
    response, _, _ = await dispatch(
        server_factory(), line({"schema_version": 1, "operation": "restore_list"})
    )
    assert response == {"schema_version": 1, "ok": True, "response": "restore_list", "workspace_id": None, "items": [], "diagnostics": []}


@pytest.mark.asyncio
async def test_encoding_failure_uses_preencoded_bounded_internal_error(server_factory, monkeypatch) -> None:
    def fail_encoding(response):
        raise RuntimeError(COMMAND_SENTINEL)

    monkeypatch.setattr("termrecall.server.encode_response", fail_encoding)
    response, raw, _ = await dispatch(
        server_factory(), line({"schema_version": 1, "operation": "status"})
    )
    assert response["error"] == {
        "code": "internal_error",
        "message": "request could not be completed",
    }
    assert len(raw) <= MAX_MESSAGE_BYTES
    assert COMMAND_SENTINEL.encode() not in raw


@pytest.mark.asyncio
async def test_real_socket_serves_and_restart_restores_without_old_capabilities(
    tmp_path: Path, server_factory
) -> None:
    runtime = tmp_path / "runtime"
    first = server_factory(runtime, peer_uid=os.getuid(), service_uid=os.getuid())
    await first.start()
    reader, writer = await asyncio.open_unix_connection(first.socket_path)
    writer.write(register_wire())
    await writer.drain()
    registered = decode_response(await reader.readline())
    old_capability = registered.capability
    writer.close()
    await writer.wait_closed()
    persisted = first.state.snapshot
    await first.close()

    fresh = EngineState(persisted, {}, persisted.generation)
    second = TermRecallServer(
        runtime / "service.sock", os.getuid(), fresh, FakeCheckpoints(), FakeStore()
    )
    second.peer_uid = os.getuid()
    await second.start()
    try:
        reader, writer = await asyncio.open_unix_connection(second.socket_path)
        writer.write(register_wire(cwd="/current"))
        await writer.drain()
        current = decode_response(await reader.readline())
        writer.close()
        await writer.wait_closed()
        assert current.capability != old_capability
        assert len(second.state.snapshot.shells) == 1
        assert second.state.snapshot.shells[0].cwd == "/current"
        assert old_capability not in {item.capability for item in second.state.registrations.values()}
    finally:
        await second.close()


class RecordingRecoveryAdapter:
    name = "recording"

    def __init__(self, outcomes=None) -> None:
        self.planned = []
        self.executed = []
        self.outcomes = outcomes

    def detect(self):
        return True

    def capabilities(self):
        return AdapterCapabilities(True, True, False, False, False, True, False)

    def plan(self, items):
        self.planned.append(tuple(items))
        return tuple(LaunchAction((item.item_id,), ("terminal",), RestorationLevel.PARTIAL, ()) for item in items)

    def execute(self, actions, attempt_id):
        self.executed.append((tuple(actions), attempt_id))
        if self.outcomes is not None:
            return tuple(self.outcomes)
        return tuple(Outcome(item_id, OutcomeKind.SUCCESS, "restored") for action in actions for item_id in action.item_ids)


def recovery_record(tmp_path: Path, *, attempts=(), completed=()) -> RecoveryRecord:
    command = CommandRecord(1, "python3 -m http.server", "python3 -m http.server", CommandDisposition.REPLAYABLE, True)
    base = ShellRecord(SHELL_ID, IDENTITY, "gnome-terminal", str(tmp_path), 1, command, None)
    return RecoveryRecord(
        1,
        "workspace-a",
        4,
        13.5,
        (
            RecoveryItemRecord("item-a", base, "same_boot_dead"),
            RecoveryItemRecord("item-b", __import__("dataclasses").replace(base, shell_id=SECOND_SHELL_ID, command=None), "same_boot_dead"),
        ),
        attempts,
        completed,
    )


@pytest.mark.asyncio
async def test_restore_list_derives_and_durably_installs_workspace(server_factory, tmp_path: Path) -> None:
    store = FakeStore()
    state = EngineState(Snapshot(1, 1, 10.0, (ShellRecord(SHELL_ID, IDENTITY, "gnome-terminal", str(tmp_path), 0, None, None),)), {}, 1)
    server = server_factory(store=store, home=tmp_path)
    server.state = state
    response, raw, _ = await dispatch(server, line({"schema_version": 1, "operation": "restore_list"}))
    assert response["response"] == "restore_list"
    assert len(store.written) == 1
    assert response["items"][0] == {"item_id": SHELL_ID, "shell_id": SHELL_ID, "reason": "same_boot_dead", "level": "partial", "directory": str(tmp_path), "directory_warning": None, "replay_display": None, "replay_eligible": False}
    assert b"command" not in raw and b"argv" not in raw


@pytest.mark.asyncio
async def test_restore_list_prefers_unresolved_durable_workspace(server_factory, tmp_path: Path) -> None:
    store = FakeStore()
    store.recovery = recovery_record(tmp_path)
    server = server_factory(store=store, current_boot_id="other", home=tmp_path)
    response, _, _ = await dispatch(server, line({"schema_version": 1, "operation": "restore_list"}))
    assert response["workspace_id"] == "workspace-a"
    assert store.written == []


@pytest.mark.asyncio
async def test_restore_retry_list_contains_only_failed_uncompleted_attempt_items(server_factory, tmp_path: Path) -> None:
    previous = RestoreAttempt(
        "attempt-old",
        "workspace-a",
        ("item-a", "item-b"),
        ("item-a",),
        (
            Outcome("item-a", OutcomeKind.FAILURE, COMMAND_SENTINEL),
            Outcome("item-b", OutcomeKind.SUCCESS, "restored"),
        ),
    )
    store = FakeStore()
    store.recovery = recovery_record(tmp_path, attempts=(previous,))
    response, raw, _ = await dispatch(
        server_factory(store=store, home=tmp_path),
        line(
            {
                "schema_version": 1,
                "operation": "restore_list",
                "workspace_id": "workspace-a",
                "attempt_id": "attempt-old",
            }
        ),
    )
    assert [item["item_id"] for item in response["items"]] == ["item-a"]
    assert b"item-b" not in raw
    assert COMMAND_SENTINEL.encode() not in raw
    assert b"command" not in raw and b"argv" not in raw


@pytest.mark.asyncio
async def test_restore_retry_list_rejects_attempt_without_retryable_items(server_factory, tmp_path: Path) -> None:
    previous = RestoreAttempt(
        "attempt-old",
        "workspace-a",
        ("item-a",),
        (),
        (Outcome("item-a", OutcomeKind.SUCCESS, "restored"),),
    )
    store = FakeStore()
    store.recovery = recovery_record(tmp_path, attempts=(previous,))
    response, _, _ = await dispatch(
        server_factory(store=store, home=tmp_path),
        line(
            {
                "schema_version": 1,
                "operation": "restore_list",
                "workspace_id": "workspace-a",
                "attempt_id": "attempt-old",
            }
        ),
    )
    assert response["error"]["code"] == "attempt_mismatch"


@pytest.mark.asyncio
async def test_restore_retry_list_rejects_unknown_attempt(server_factory, tmp_path: Path) -> None:
    store = FakeStore()
    store.recovery = recovery_record(tmp_path)
    response, _, _ = await dispatch(
        server_factory(store=store, home=tmp_path),
        line(
            {
                "schema_version": 1,
                "operation": "restore_list",
                "workspace_id": "workspace-a",
                "attempt_id": "missing-attempt",
            }
        ),
    )
    assert response["error"]["code"] == "attempt_mismatch"


@pytest.mark.asyncio
async def test_restore_execute_uses_stored_command_and_commits_before_ack(server_factory, tmp_path: Path) -> None:
    store = FakeStore()
    store.recovery = recovery_record(tmp_path)
    adapter = RecordingRecoveryAdapter()
    server = server_factory(store=store, adapter=adapter, home=tmp_path)
    response, raw, _ = await dispatch(server, line({"schema_version": 1, "operation": "restore_execute", "workspace_id": "workspace-a", "selected_item_ids": ["item-a", "item-b"], "approved_item_ids": ["item-a"]}))
    assert adapter.planned[0][0].approved_command == "python3 -m http.server"
    assert adapter.planned[0][1].approved_command is None
    assert store.commits
    assert response["outcomes"] == [{"item_id": "item-a", "kind": "success", "message": "restored"}, {"item_id": "item-b", "kind": "success", "message": "restored"}]
    assert store.completed == [("workspace-a", False)]
    assert b"python" not in raw and b"argv" not in raw


@pytest.mark.asyncio
async def test_restore_execute_rejects_client_command_and_unknown_ids(server_factory, tmp_path: Path) -> None:
    store = FakeStore(); store.recovery = recovery_record(tmp_path)
    server = server_factory(store=store, adapter=RecordingRecoveryAdapter(), home=tmp_path)
    malformed, _, _ = await dispatch(server, line({"schema_version": 1, "operation": "restore_execute", "workspace_id": "workspace-a", "selected_item_ids": ["item-a"], "approved_item_ids": [], "command": "evil"}))
    unknown, _, _ = await dispatch(server, line({"schema_version": 1, "operation": "restore_execute", "workspace_id": "workspace-a", "selected_item_ids": ["missing"], "approved_item_ids": []}))
    assert malformed["error"]["code"] == "invalid_request"
    assert unknown == {"schema_version": 1, "ok": False, "response": "error", "error": {"code": "unknown_item", "message": "recovery item rejected"}}


@pytest.mark.asyncio
async def test_restore_retry_only_retries_failed_with_fresh_approval(server_factory, tmp_path: Path) -> None:
    previous = RestoreAttempt("attempt-old", "workspace-a", ("item-a", "item-b"), ("item-a",), (Outcome("item-a", OutcomeKind.FAILURE, "failed"), Outcome("item-b", OutcomeKind.SUCCESS, "restored")))
    store = FakeStore(); store.recovery = recovery_record(tmp_path, attempts=(previous,), completed=("item-b",))
    adapter = RecordingRecoveryAdapter()
    server = server_factory(store=store, adapter=adapter, home=tmp_path)
    response, _, _ = await dispatch(server, line({"schema_version": 1, "operation": "restore_retry", "workspace_id": "workspace-a", "attempt_id": "attempt-old", "approved_item_ids": []}))
    assert [item.item_id for item in adapter.planned[0]] == ["item-a"]
    assert adapter.planned[0][0].approved_command is None
    assert response["remaining_item_ids"] == []


@pytest.mark.asyncio
async def test_restore_retry_rejects_nonretryable_approval(server_factory, tmp_path: Path) -> None:
    previous = RestoreAttempt("attempt-old", "workspace-a", ("item-a", "item-b"), (), (Outcome("item-a", OutcomeKind.FAILURE, "failed"), Outcome("item-b", OutcomeKind.SUCCESS, "restored")))
    store = FakeStore(); store.recovery = recovery_record(tmp_path, attempts=(previous,), completed=("item-b",))
    server = server_factory(store=store, adapter=RecordingRecoveryAdapter(), home=tmp_path)
    response, _, _ = await dispatch(server, line({"schema_version": 1, "operation": "restore_retry", "workspace_id": "workspace-a", "attempt_id": "attempt-old", "approved_item_ids": ["item-b"]}))
    assert response["error"]["code"] == "unknown_item"


@pytest.mark.asyncio
async def test_persistence_failure_never_acknowledges_restore(server_factory, tmp_path: Path) -> None:
    store = FakeStore(); store.recovery = recovery_record(tmp_path); store.commit_error = OSError("crash")
    server = server_factory(store=store, adapter=RecordingRecoveryAdapter(), home=tmp_path)
    response, _, _ = await dispatch(server, line({"schema_version": 1, "operation": "restore_execute", "workspace_id": "workspace-a", "selected_item_ids": ["item-a"], "approved_item_ids": []}))
    assert response["error"]["code"] == "persistence_failed"
    assert store.recovery.workspace_id == "workspace-a"


@pytest.mark.asyncio
async def test_discard_requires_confirm_and_tombstones_before_ack(server_factory, tmp_path: Path) -> None:
    store = FakeStore(); store.recovery = recovery_record(tmp_path)
    server = server_factory(store=store, adapter=RecordingRecoveryAdapter(), home=tmp_path)
    refused, _, _ = await dispatch(server, line({"schema_version": 1, "operation": "discard", "workspace_id": "workspace-a", "confirm": False}))
    accepted, _, _ = await dispatch(server, line({"schema_version": 1, "operation": "discard", "workspace_id": "workspace-a", "confirm": True}))
    assert refused["error"]["code"] == "invalid_request"
    assert accepted == {"schema_version": 1, "ok": True, "response": "discard", "workspace_id": "workspace-a", "discarded": True}
    assert store.completed == [("workspace-a", True)]


@pytest.mark.asyncio
async def test_mixed_completed_approval_does_not_approve_unresolved_item(server_factory, tmp_path: Path) -> None:
    prior = RestoreAttempt("old", "workspace-a", ("item-a",), ("item-a",), (Outcome("item-a", OutcomeKind.SUCCESS, "restored"),))
    store = FakeStore(); store.recovery = recovery_record(tmp_path, attempts=(prior,), completed=("item-a",))
    adapter = RecordingRecoveryAdapter()
    server = server_factory(store=store, adapter=adapter, home=tmp_path)
    await dispatch(server, line({"schema_version": 1, "operation": "restore_execute", "workspace_id": "workspace-a", "selected_item_ids": ["item-a", "item-b"], "approved_item_ids": ["item-a"]}))
    assert [item.item_id for item in adapter.planned[0]] == ["item-b"]
    assert adapter.planned[0][0].approved_command is None


@pytest.mark.asyncio
async def test_exact_completed_repeat_reuses_without_adapter_and_filters_requested_outcomes(server_factory, tmp_path: Path) -> None:
    adapter = RecordingRecoveryAdapter()
    attempt_id = derive_attempt_id("workspace-a", ("item-a", "item-b"), {"item-a"}, adapter)
    prior = RestoreAttempt(attempt_id, "workspace-a", ("item-a", "item-b"), ("item-a",), (Outcome("item-a", OutcomeKind.SUCCESS, "restored"), Outcome("item-b", OutcomeKind.SUCCESS, "restored")))
    store = FakeStore(); store.recovery = recovery_record(tmp_path, attempts=(prior,), completed=("item-a", "item-b"))
    server = server_factory(store=store, adapter=adapter, home=tmp_path)
    response, _, _ = await dispatch(server, line({"schema_version": 1, "operation": "restore_execute", "workspace_id": "workspace-a", "selected_item_ids": ["item-a", "item-b"], "approved_item_ids": ["item-a"]}))
    assert response["attempt_id"] == attempt_id
    assert [outcome["item_id"] for outcome in response["outcomes"]] == ["item-a", "item-b"]
    assert adapter.planned == [] and adapter.executed == []


@pytest.mark.asyncio
async def test_completed_subset_does_not_disclose_unrequested_outcomes(server_factory, tmp_path: Path) -> None:
    adapter = RecordingRecoveryAdapter()
    attempt_id = derive_attempt_id("workspace-a", ("item-a", "item-b"), set(), adapter)
    prior = RestoreAttempt(attempt_id, "workspace-a", ("item-a", "item-b"), (), (Outcome("item-a", OutcomeKind.SUCCESS, "restored"), Outcome("item-b", OutcomeKind.SUCCESS, "restored")))
    store = FakeStore(); store.recovery = recovery_record(tmp_path, attempts=(prior,), completed=("item-a", "item-b"))
    server = server_factory(store=store, adapter=adapter, home=tmp_path)
    response, _, _ = await dispatch(server, line({"schema_version": 1, "operation": "restore_execute", "workspace_id": "workspace-a", "selected_item_ids": ["item-a"], "approved_item_ids": []}))
    assert response["error"]["code"] == "unknown_item"
    assert "outcomes" not in response


@pytest.mark.asyncio
async def test_completed_repeat_with_changed_approvals_does_not_reuse(server_factory, tmp_path: Path) -> None:
    adapter = RecordingRecoveryAdapter()
    attempt_id = derive_attempt_id("workspace-a", ("item-a",), {"item-a"}, adapter)
    prior = RestoreAttempt(attempt_id, "workspace-a", ("item-a",), ("item-a",), (Outcome("item-a", OutcomeKind.SUCCESS, "restored"),))
    store = FakeStore(); store.recovery = recovery_record(tmp_path, attempts=(prior,), completed=("item-a",))
    server = server_factory(store=store, adapter=adapter, home=tmp_path)
    response, _, _ = await dispatch(server, line({"schema_version": 1, "operation": "restore_execute", "workspace_id": "workspace-a", "selected_item_ids": ["item-a"], "approved_item_ids": []}))
    assert response["error"]["code"] == "unknown_item"


@pytest.mark.asyncio
async def test_completion_tombstone_failure_is_retried_before_repeat_ack(server_factory, tmp_path: Path) -> None:
    store = FakeStore(); store.recovery = recovery_record(tmp_path); store.complete_error = OSError("tombstone crash")
    adapter = RecordingRecoveryAdapter()
    server = server_factory(store=store, adapter=adapter, home=tmp_path)
    first, _, _ = await dispatch(server, line({"schema_version": 1, "operation": "restore_execute", "workspace_id": "workspace-a", "selected_item_ids": ["item-a", "item-b"], "approved_item_ids": []}))
    second, _, _ = await dispatch(server, line({"schema_version": 1, "operation": "restore_execute", "workspace_id": "workspace-a", "selected_item_ids": ["item-a", "item-b"], "approved_item_ids": []}))
    assert first["error"]["code"] == "persistence_failed"
    assert second["response"] == "restore_result"
    assert len(adapter.executed) == 1
    assert store.completed == [("workspace-a", False), ("workspace-a", False)]


@pytest.mark.asyncio
async def test_response_is_held_until_outcomes_commit_finishes(server_factory, tmp_path: Path) -> None:
    store = FakeStore(); store.recovery = recovery_record(tmp_path)
    store.commit_started = threading.Event(); store.commit_release = threading.Event()
    server = server_factory(store=store, adapter=RecordingRecoveryAdapter(), home=tmp_path)
    task = asyncio.create_task(dispatch(server, line({"schema_version": 1, "operation": "restore_execute", "workspace_id": "workspace-a", "selected_item_ids": ["item-a"], "approved_item_ids": []})))
    assert await asyncio.to_thread(store.commit_started.wait, 1)
    await asyncio.sleep(0)
    assert not task.done()
    store.commit_release.set()
    response, _, _ = await task
    assert response["response"] == "restore_result"


@pytest.mark.asyncio
async def test_empty_retry_does_not_call_adapter(server_factory, tmp_path: Path) -> None:
    prior = RestoreAttempt("old", "workspace-a", ("item-a",), (), (Outcome("item-a", OutcomeKind.SUCCESS, "restored"),))
    store = FakeStore(); store.recovery = recovery_record(tmp_path, attempts=(prior,), completed=("item-a",))
    adapter = RecordingRecoveryAdapter(); server = server_factory(store=store, adapter=adapter, home=tmp_path)
    response, _, _ = await dispatch(server, line({"schema_version": 1, "operation": "restore_retry", "workspace_id": "workspace-a", "attempt_id": "old", "approved_item_ids": []}))
    assert response["error"]["code"] == "attempt_mismatch"
    assert adapter.planned == [] and adapter.executed == []


@pytest.mark.asyncio
async def test_blocked_restore_does_not_block_unrelated_status_or_register(
    server_factory, tmp_path: Path
) -> None:
    started = threading.Event()
    release = threading.Event()

    class BlockingAdapter(RecordingRecoveryAdapter):
        def execute(self, actions, attempt_id):
            started.set()
            release.wait(timeout=5)
            return super().execute(actions, attempt_id)

    store = FakeStore()
    store.recovery = recovery_record(tmp_path)
    server = server_factory(store=store, adapter=BlockingAdapter(), home=tmp_path)
    restore = asyncio.create_task(
        dispatch(
            server,
            line(
                {
                    "schema_version": 1,
                    "operation": "restore_execute",
                    "workspace_id": "workspace-a",
                    "selected_item_ids": ["item-a"],
                    "approved_item_ids": [],
                }
            ),
        )
    )
    assert await asyncio.to_thread(started.wait, 1)

    status, registered = await asyncio.wait_for(
        asyncio.gather(
            dispatch(server, line({"schema_version": 1, "operation": "status"})),
            dispatch(server, register_wire(cwd=str(tmp_path))),
        ),
        timeout=0.5,
    )

    assert status[0]["response"] == "status"
    assert registered[0]["response"] == "register"
    release.set()
    assert (await restore)[0]["response"] == "restore_result"


@pytest.mark.asyncio
async def test_same_workspace_discard_waits_for_restore_outcome_commit(
    server_factory, tmp_path: Path
) -> None:
    execute_started = threading.Event()
    release_execute = threading.Event()

    class BlockingAdapter(RecordingRecoveryAdapter):
        def execute(self, actions, attempt_id):
            execute_started.set()
            release_execute.wait(timeout=5)
            return super().execute(actions, attempt_id)

    store = FakeStore()
    store.recovery = recovery_record(tmp_path)
    server = server_factory(store=store, adapter=BlockingAdapter(), home=tmp_path)
    restore = asyncio.create_task(
        dispatch(
            server,
            line(
                {
                    "schema_version": 1,
                    "operation": "restore_execute",
                    "workspace_id": "workspace-a",
                    "selected_item_ids": ["item-a"],
                    "approved_item_ids": [],
                }
            ),
        )
    )
    assert await asyncio.to_thread(execute_started.wait, 1)

    discard = asyncio.create_task(
        dispatch(
            server,
            line(
                {
                    "schema_version": 1,
                    "operation": "discard",
                    "workspace_id": "workspace-a",
                    "confirm": True,
                }
            ),
        )
    )
    await asyncio.sleep(0.05)

    assert not discard.done()
    assert store.commits == []
    assert store.completed == []

    release_execute.set()
    restore_response, discard_response = await asyncio.gather(restore, discard)

    assert restore_response[0]["response"] == "restore_result"
    assert discard_response[0]["response"] == "discard"
    assert len(store.commits) == 1
    assert store.completed == [("workspace-a", True)]


@pytest.mark.asyncio
async def test_different_workspace_discard_is_not_blocked_by_restore(
    server_factory, tmp_path: Path
) -> None:
    execute_started = threading.Event()
    release_execute = threading.Event()

    class BlockingAdapter(RecordingRecoveryAdapter):
        def execute(self, actions, attempt_id):
            execute_started.set()
            release_execute.wait(timeout=5)
            return super().execute(actions, attempt_id)

    store = FakeStore()
    store.recovery = recovery_record(tmp_path)
    server = server_factory(store=store, adapter=BlockingAdapter(), home=tmp_path)
    restore = asyncio.create_task(
        dispatch(
            server,
            line(
                {
                    "schema_version": 1,
                    "operation": "restore_execute",
                    "workspace_id": "workspace-a",
                    "selected_item_ids": ["item-a"],
                    "approved_item_ids": [],
                }
            ),
        )
    )
    assert await asyncio.to_thread(execute_started.wait, 1)

    different, _, _ = await asyncio.wait_for(
        dispatch(
            server,
            line(
                {
                    "schema_version": 1,
                    "operation": "discard",
                    "workspace_id": "workspace-b",
                    "confirm": True,
                }
            ),
        ),
        timeout=0.5,
    )

    assert different["error"]["code"] == "workspace_mismatch"
    assert store.completed == []
    release_execute.set()
    assert (await restore)[0]["response"] == "restore_result"


@pytest.mark.asyncio
async def test_gnome_timeout_is_retryable_and_persisted_without_waiting_ten_seconds(
    server_factory, tmp_path: Path
) -> None:
    received: list[float] = []

    def timeout_runner(argv, **kwargs):
        received.append(kwargs["timeout"])
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    store = FakeStore()
    store.recovery = recovery_record(tmp_path)
    adapter = GnomeTerminalAdapter(
        lambda _: "/usr/bin/gnome-terminal",
        runner=timeout_runner,
        launch_timeout=0.01,
    )
    server = server_factory(store=store, adapter=adapter, home=tmp_path)

    response, _, _ = await asyncio.wait_for(
        dispatch(
            server,
            line(
                {
                    "schema_version": 1,
                    "operation": "restore_execute",
                    "workspace_id": "workspace-a",
                    "selected_item_ids": ["item-a"],
                    "approved_item_ids": [],
                }
            ),
        ),
        timeout=0.5,
    )

    assert received == [0.01]
    assert response["outcomes"][0]["kind"] == "failure"
    assert store.commits[0][2][0].kind is OutcomeKind.FAILURE
    assert "retryable" in store.commits[0][2][0].message


@pytest.mark.asyncio
async def test_concurrent_restores_for_same_workspace_are_serialized(
    server_factory, tmp_path: Path
) -> None:
    first_started = threading.Event()
    release_first = threading.Event()

    class SerialAdapter(RecordingRecoveryAdapter):
        def __init__(self):
            super().__init__()
            self.active = 0
            self.maximum_active = 0
            self.calls = 0
            self.guard = threading.Lock()

        def execute(self, actions, attempt_id):
            with self.guard:
                self.calls += 1
                call = self.calls
                self.active += 1
                self.maximum_active = max(self.maximum_active, self.active)
            if call == 1:
                first_started.set()
                release_first.wait(timeout=5)
            try:
                return super().execute(actions, attempt_id)
            finally:
                with self.guard:
                    self.active -= 1

    store = FakeStore()
    store.recovery = recovery_record(tmp_path)
    adapter = SerialAdapter()
    server = server_factory(store=store, adapter=adapter, home=tmp_path)
    request = line(
        {
            "schema_version": 1,
            "operation": "restore_execute",
            "workspace_id": "workspace-a",
            "selected_item_ids": ["item-a"],
            "approved_item_ids": [],
        }
    )
    first = asyncio.create_task(dispatch(server, request))
    assert await asyncio.to_thread(first_started.wait, 1)
    second = asyncio.create_task(dispatch(server, request))
    await asyncio.sleep(0.05)

    assert adapter.calls == 1
    release_first.set()
    first_response, second_response = await asyncio.gather(first, second)

    assert first_response[0]["response"] == "restore_result"
    assert second_response[0]["response"] == "restore_result"
    assert adapter.maximum_active == 1
    assert adapter.calls == 1


@pytest.mark.asyncio
async def test_adapter_work_runs_off_event_loop_thread(server_factory, tmp_path: Path) -> None:
    loop_thread = threading.get_ident()
    class ThreadAdapter(RecordingRecoveryAdapter):
        def __init__(self):
            super().__init__(); self.threads = []
        def detect(self): self.threads.append(threading.get_ident()); return True
        def plan(self, items): self.threads.append(threading.get_ident()); return super().plan(items)
        def execute(self, actions, attempt_id): self.threads.append(threading.get_ident()); return super().execute(actions, attempt_id)
    store = FakeStore(); store.recovery = recovery_record(tmp_path)
    adapter = ThreadAdapter(); server = server_factory(store=store, adapter=adapter, home=tmp_path)
    await dispatch(server, line({"schema_version": 1, "operation": "restore_execute", "workspace_id": "workspace-a", "selected_item_ids": ["item-a"], "approved_item_ids": []}))
    assert len(adapter.threads) == 3
    assert all(thread != loop_thread for thread in adapter.threads)


@pytest.mark.parametrize("reason", tuple(RecoveryReason))
def test_safe_recovery_reason_exhaustively_projects_exact_enum(reason) -> None:
    assert safe_recovery_reason(reason).value == reason.value


def test_recovery_reason_enum_has_exact_safe_catalog_members() -> None:
    assert {reason.value for reason in RecoveryReason} == {
        "previous_boot", "same_boot_dead", "process_unknown", "explicit_exit", "still_alive"
    }


@pytest.mark.asyncio
async def test_restore_list_projects_malformed_durable_reason_as_process_unknown(server_factory, tmp_path: Path) -> None:
    record = recovery_record(tmp_path)
    record = __import__("dataclasses").replace(record, items=(__import__("dataclasses").replace(record.items[0], reason="malformed"),))
    store = FakeStore(); store.recovery = record
    response, _, _ = await dispatch(server_factory(store=store, home=tmp_path), line({"schema_version": 1, "operation": "restore_list"}))
    assert response["items"][0]["reason"] == "process_unknown"


@pytest.mark.asyncio
async def test_restore_list_preserves_previous_and_same_boot_reasons(server_factory, tmp_path: Path) -> None:
    previous = recovery_record(tmp_path)
    previous = __import__("dataclasses").replace(previous, items=(__import__("dataclasses").replace(previous.items[0], reason="previous_boot"), __import__("dataclasses").replace(previous.items[1], reason="same_boot_dead")))
    store = FakeStore(); store.recovery = previous
    response, _, _ = await dispatch(server_factory(store=store, home=tmp_path), line({"schema_version": 1, "operation": "restore_list"}))
    assert [item["reason"] for item in response["items"]] == ["previous_boot", "same_boot_dead"]


@pytest.mark.asyncio
async def test_restore_list_probes_only_same_boot_non_explicit_candidates(server_factory, tmp_path: Path) -> None:
    same_alive = ProcessIdentity(IDENTITY.boot_id, 2001, 11)
    same_unknown = ProcessIdentity(IDENTITY.boot_id, 2002, 22)
    same_dead = ProcessIdentity(IDENTITY.boot_id, 2003, 33)
    previous = ProcessIdentity("22222222-2222-2222-2222-222222222222", 2004, 44)
    explicit = ProcessIdentity(IDENTITY.boot_id, 2005, 55)
    shells = (
        ShellRecord("123e4567-e89b-12d3-a456-426614174010", same_alive, "gnome-terminal", str(tmp_path), 1, None, None),
        ShellRecord("123e4567-e89b-12d3-a456-426614174011", same_unknown, "gnome-terminal", str(tmp_path), 1, None, None),
        ShellRecord("123e4567-e89b-12d3-a456-426614174012", same_dead, "gnome-terminal", str(tmp_path), 1, None, None),
        ShellRecord("123e4567-e89b-12d3-a456-426614174013", previous, "gnome-terminal", str(tmp_path), 1, None, None),
        ShellRecord("123e4567-e89b-12d3-a456-426614174014", explicit, "gnome-terminal", str(tmp_path), 1, None, __import__("termrecall.model", fromlist=["TerminationKind"]).TerminationKind.EXPLICIT_EXIT),
    )
    calls = []
    statuses = {same_alive: ProcessStatus.ALIVE, same_unknown: ProcessStatus.UNKNOWN, same_dead: ProcessStatus.DEAD}
    def probe(identity):
        calls.append(identity)
        assert identity in statuses
        return ProcessProbe(statuses[identity])
    store = FakeStore()
    server = server_factory(store=store, home=tmp_path, process_probe=probe)
    server.state = EngineState(Snapshot(1, 4, 10.0, shells), {}, 4)
    response, _, _ = await dispatch(server, line({"schema_version": 1, "operation": "restore_list"}))
    assert calls == [same_alive, same_unknown, same_dead]
    assert [item["reason"] for item in response["items"]] == ["same_boot_dead", "previous_boot"]


@pytest.mark.asyncio
async def test_restore_list_previous_boot_and_explicit_exit_bypass_failing_probe(server_factory, tmp_path: Path) -> None:
    previous = ProcessIdentity("22222222-2222-2222-2222-222222222222", 3001, 66)
    explicit = ProcessIdentity(IDENTITY.boot_id, 3002, 77)
    shells = (
        ShellRecord("123e4567-e89b-12d3-a456-426614174020", previous, "gnome-terminal", str(tmp_path), 1, None, None),
        ShellRecord("123e4567-e89b-12d3-a456-426614174021", explicit, "gnome-terminal", str(tmp_path), 1, None, __import__("termrecall.model", fromlist=["TerminationKind"]).TerminationKind.EXPLICIT_EXIT),
    )
    def fail_probe(identity):
        raise AssertionError(f"unexpected probe {identity}")
    store = FakeStore(); server = server_factory(store=store, home=tmp_path, process_probe=fail_probe)
    server.state = EngineState(Snapshot(1, 5, 10.0, shells), {}, 5)
    response, _, _ = await dispatch(server, line({"schema_version": 1, "operation": "restore_list"}))
    assert [item["reason"] for item in response["items"]] == ["previous_boot"]


@pytest.mark.asyncio
async def test_discard_rejects_workspace_mismatch(server_factory, tmp_path: Path) -> None:
    store = FakeStore(); store.recovery = recovery_record(tmp_path)
    server = server_factory(store=store, adapter=RecordingRecoveryAdapter(), home=tmp_path)
    response, _, _ = await dispatch(server, line({"schema_version": 1, "operation": "discard", "workspace_id": "other", "confirm": True}))
    assert response["error"]["code"] == "workspace_mismatch"
    assert store.completed == []


@pytest.mark.asyncio
async def test_recovery_view_populates_server_authoritative_resume_fields(server_factory) -> None:
    """_recovery_view resolves the resume plan server-side so the client UI
    displays what build_attempt will actually run (single source of truth)."""
    from termrecall.model import CommandRecord, CommandDisposition, ShellRecord, ProcessIdentity, Snapshot
    from termrecall.state import EngineState, register_shell
    from termrecall.protocol import RegisterRequest
    server = server_factory()
    # A codex shell that died in a previous boot.
    ident = ProcessIdentity("boot-dead", 4242, 123456)
    cmd = CommandRecord(1, "codex", "codex", CommandDisposition.REPLAYABLE, True)
    # Build a snapshot with the dead shell and reconcile.
    # (Use the server's reconcile path indirectly via restore_list is heavy;
    # test _recovery_view directly instead.)
    from termrecall.recovery import RecoveryItem, RecoveryReason, RestorationLevel
    from pathlib import Path
    item = RecoveryItem(
        item_id="item-x",
        shell=ShellRecord("shell-aaaaaaaaaaaa", ident, "gnome-terminal", "/srv/codex", 1, cmd, None),
        reason=RecoveryReason.PREVIOUS_BOOT,
        level=RestorationLevel.RECONSTRUCTED,
        directory=Path("/srv/codex"),
        directory_warning=None,
        replay_display=cmd.executable,
        replay_eligible=True,
    )
    view = server.__class__._recovery_view(item)
    # resume_command is populated by the server (may be empty if codex isn't
    # installed in the test env, but the field must exist and be a string).
    assert isinstance(view.resume_command, str)
    assert isinstance(view.resume_summary, str)
    assert isinstance(view.resume_session_count, int)
    assert view.resume_session_count >= 0
