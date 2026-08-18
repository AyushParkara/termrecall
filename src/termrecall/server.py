# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import asyncio
import fcntl
import inspect
import os
import socket
import stat
import struct
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from termrecall.adapters.base import TerminalAdapter
from termrecall.model import MAX_OUTCOME_MESSAGE_CHARS, Outcome, OutcomeKind, RestorationLevel
from termrecall.paths import read_boot_id
from termrecall.processes import ProcessProbe, identity_status
from termrecall.protocol import (
    ERROR_MESSAGES,
    FALLBACK_ERROR_BYTES,
    MAX_MESSAGE_BYTES,
    ErrorCode,
    DiscardRequest,
    DiscardResponse,
    ErrorResponse,
    EventRequest,
    EventResponse,
    ProtocolError,
    RegisterRequest,
    RecoveryItemView,
    RedactedDisplay,
    RegisterResponse,
    RestoreExecuteRequest,
    RestoreListRequest,
    RestoreListResponse,
    RestoreResultResponse,
    RestoreRetryRequest,
    OutcomeView,
    SafeExternalText,
    SnapshotRequest,
    SnapshotResponse,
    StatusRequest,
    StatusResponse,
    decode_request,
    encode_response,
)
from termrecall.recovery import (
    build_attempt,
    derive_attempt_id,
    reconcile,
    record_from_workspace,
    safe_recovery_reason,
    workspace_from_record,
)
from termrecall.state import EngineState, apply_event, register_shell
from termrecall.store import SnapshotStore

_SOCKET_NAME = "service.sock"
_LOCK_NAME = "service.lock"
_READ_TIMEOUT = 1.0
_STALE_MESSAGE = (
    "service.sock already exists; run termrecall doctor and explicitly clean "
    "a verified stale socket"
)


class UnsafeRuntimePath(RuntimeError):
    """The runtime directory, singleton lock, or socket path is unsafe."""


@dataclass(frozen=True, slots=True)
class PeerCredentials:
    pid: int
    uid: int
    gid: int


def get_peer_credentials(sock: socket.socket) -> PeerCredentials:
    raw_credentials = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return PeerCredentials(*struct.unpack("3i", raw_credentials))


def _error(code: ErrorCode) -> ErrorResponse:
    return ErrorResponse(ProtocolError(code, ERROR_MESSAGES[code]))


def _unix_server_kwargs() -> dict[str, bool]:
    parameters = inspect.signature(asyncio.start_unix_server).parameters
    if "cleanup_socket" in parameters or (
        sys.version_info >= (3, 13)
        and any(
            parameter.kind is inspect.Parameter.VAR_KEYWORD
            for parameter in parameters.values()
        )
    ):
        return {"cleanup_socket": False}
    return {}


async def _start_unix_server(
    callback: Any, bound_socket: Any
) -> asyncio.AbstractServer:
    return await asyncio.start_unix_server(
        callback,
        sock=bound_socket,
        limit=MAX_MESSAGE_BYTES + 1,
        **_unix_server_kwargs(),
    )


class TermRecallServer:
    def __init__(
        self,
        socket_path: Path,
        service_uid: int,
        initial_state: EngineState,
        checkpoints: Any,
        store: SnapshotStore,
        *,
        adapter: TerminalAdapter | None = None,
        current_boot_id: str | None = None,
        home: Path | None = None,
        process_probe: Callable[[object], ProcessProbe] | None = None,
    ) -> None:
        self.socket_path = Path(socket_path)
        self.service_uid = service_uid
        self.initial_state = initial_state
        self.state = initial_state
        self.checkpoints = checkpoints
        self.store = store
        self.adapter = adapter
        self.current_boot_id = read_boot_id() if current_boot_id is None else current_boot_id
        self.home = Path.home() if home is None else Path(home)
        self.process_probe = process_probe or (
            lambda identity: identity_status(identity, self.current_boot_id)
        )
        self.diagnostics: list[str] = []
        self._runtime_fd: int | None = None
        self._lock_fd: int | None = None
        self._socket_fd: int | None = None
        self._server: asyncio.AbstractServer | None = None
        self._dispatch_lock = asyncio.Lock()
        self._workspace_locks: dict[str, asyncio.Lock] = {}
        self._connection_tasks: set[asyncio.Task[object]] = set()
        self._connection_writers: set[asyncio.StreamWriter] = set()
        self._created_socket_identity: tuple[int, int] | None = None
        self._closing = False
        self._closed = False

    async def start(self) -> None:
        if self._server is not None or self._runtime_fd is not None:
            raise RuntimeError("server already started")
        runtime_fd: int | None = None
        lock_fd: int | None = None
        socket_fd: int | None = None
        bound_socket: socket.socket | None = None
        created_identity: tuple[int, int] | None = None
        server: asyncio.AbstractServer | None = None
        try:
            runtime_fd = self._open_runtime_directory(self.socket_path.parent)
            lock_fd = self._open_lock(runtime_fd)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise UnsafeRuntimePath("another service instance holds service.lock") from exc

            try:
                os.stat(_SOCKET_NAME, dir_fd=runtime_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise UnsafeRuntimePath(_STALE_MESSAGE)

            anchored_path = f"/proc/self/fd/{runtime_fd}/{_SOCKET_NAME}"
            bound_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            bound_socket.setblocking(False)
            bound_socket.bind(anchored_path)
            created = os.stat(_SOCKET_NAME, dir_fd=runtime_fd, follow_symlinks=False)
            created_identity = (created.st_dev, created.st_ino)
            os.chmod(_SOCKET_NAME, 0o600, dir_fd=runtime_fd, follow_symlinks=False)
            socket_fd = os.open(
                _SOCKET_NAME,
                getattr(os, "O_PATH", os.O_RDONLY) | os.O_NOFOLLOW,
                dir_fd=runtime_fd,
            )
            metadata = os.fstat(socket_fd)
            if (metadata.st_dev, metadata.st_ino) != created_identity:
                raise UnsafeRuntimePath("service.sock changed during creation")
            if (
                not stat.S_ISSOCK(metadata.st_mode)
                or metadata.st_uid != self.service_uid
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise UnsafeRuntimePath("created service.sock failed safety checks")

            bound_socket.listen(socket.SOMAXCONN)
            server = await _start_unix_server(self.handle_connection, bound_socket)
            bound_socket = None

            self._runtime_fd = runtime_fd
            self._lock_fd = lock_fd
            self._socket_fd = socket_fd
            self._created_socket_identity = created_identity
            self._server = server
            self._closed = False
            runtime_fd = lock_fd = socket_fd = None
            server = None
        except BaseException:
            if server is not None:
                server.close()
                await server.wait_closed()
            if bound_socket is not None:
                bound_socket.close()
            if runtime_fd is not None and created_identity is not None:
                try:
                    metadata = os.stat(
                        _SOCKET_NAME, dir_fd=runtime_fd, follow_symlinks=False
                    )
                    if (
                        stat.S_ISSOCK(metadata.st_mode)
                        and (metadata.st_dev, metadata.st_ino) == created_identity
                    ):
                        os.unlink(_SOCKET_NAME, dir_fd=runtime_fd)
                except FileNotFoundError:
                    pass
            if socket_fd is not None:
                os.close(socket_fd)
            if lock_fd is not None:
                os.close(lock_fd)
            if runtime_fd is not None:
                os.close(runtime_fd)
            raise

    async def serve(self, stop: asyncio.Event) -> None:
        if self._server is None:
            await self.start()
        checkpoint_task: asyncio.Task[object] | None = None
        if hasattr(self.checkpoints, "run"):
            checkpoint_task = asyncio.create_task(self.checkpoints.run(stop))
        try:
            await stop.wait()
        finally:
            if checkpoint_task is not None:
                await checkpoint_task

    async def close(self) -> None:
        if self._closed or self._closing:
            return
        self._closing = True
        try:
            serving = self._server
            if serving is not None:
                serving.close()
                self._server = None
            for writer in tuple(self._connection_writers):
                writer.close()
            writers = tuple(self._connection_writers)
            if writers:
                await asyncio.gather(
                    *(writer.wait_closed() for writer in writers),
                    return_exceptions=True,
                )
            connection_tasks = tuple(
                task for task in self._connection_tasks if task is not asyncio.current_task()
            )
            if connection_tasks:
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*connection_tasks, return_exceptions=True),
                        timeout=1.0,
                    )
                except asyncio.TimeoutError:
                    for task in connection_tasks:
                        task.cancel()
                    await asyncio.gather(*connection_tasks, return_exceptions=True)
            if serving is not None:
                await serving.wait_closed()
            try:
                status = self.checkpoints.status
                if status.dirty_generation > status.durable_generation:
                    snapshot = self.state.snapshot
                    await asyncio.wait_for(
                        asyncio.to_thread(self.store.write, snapshot), timeout=2.0
                    )
            except (Exception, asyncio.CancelledError) as exc:
                self.diagnostics.append(f"shutdown snapshot flush failed: {type(exc).__name__}")
            if self._runtime_fd is not None and self._created_socket_identity is not None:
                try:
                    metadata = os.stat(_SOCKET_NAME, dir_fd=self._runtime_fd, follow_symlinks=False)
                    identity = (metadata.st_dev, metadata.st_ino)
                    if stat.S_ISSOCK(metadata.st_mode) and identity == self._created_socket_identity:
                        os.unlink(_SOCKET_NAME, dir_fd=self._runtime_fd)
                    else:
                        self.diagnostics.append("service.sock changed before shutdown cleanup")
                except FileNotFoundError:
                    pass
                except OSError as exc:
                    self.diagnostics.append(f"service.sock cleanup failed: {type(exc).__name__}")
        finally:
            if self._socket_fd is not None:
                os.close(self._socket_fd)
                self._socket_fd = None
            if self._lock_fd is not None:
                os.close(self._lock_fd)
                self._lock_fd = None
            if self._runtime_fd is not None:
                os.close(self._runtime_fd)
                self._runtime_fd = None
            self._created_socket_identity = None
            try:
                close_store = getattr(self.store, "close", None)
                if close_store is not None:
                    close_store()
            except (OSError, RuntimeError):
                pass
            self._closed = True
            self._closing = False

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        current = asyncio.current_task()
        if current is not None:
            self._connection_tasks.add(current)
        self._connection_writers.add(writer)
        try:
            peer_socket = writer.get_extra_info("socket")
            try:
                peer = None if peer_socket is None else get_peer_credentials(peer_socket)
            except OSError:
                peer = None
            if peer is None or peer.uid != self.service_uid:
                await self._write_response(writer, _error(ErrorCode.PEER_REJECTED))
                return

            persistent = isinstance(reader, asyncio.StreamReader)
            authenticated_stream = False
            while True:
                try:
                    read = (
                        reader.readline()
                        if persistent
                        else reader.readline(MAX_MESSAGE_BYTES + 1)
                    )
                    raw = (
                        await read
                        if authenticated_stream
                        else await asyncio.wait_for(read, timeout=_READ_TIMEOUT)
                    )
                    if not raw:
                        if persistent:
                            return
                        raise ValueError("request ended before newline")
                    request = decode_request(raw)
                except (asyncio.TimeoutError, ValueError):
                    await self._write_response(writer, _error(ErrorCode.INVALID_REQUEST))
                    return
                if isinstance(
                    request,
                    (RestoreExecuteRequest, RestoreRetryRequest, DiscardRequest),
                ):
                    response = await self._dispatch_workspace_operation(request)
                else:
                    async with self._dispatch_lock:
                        response = await self._dispatch(
                            request, peer_pid=peer.pid if peer is not None else None
                        )
                await self._write_response(writer, response)
                if not persistent or not isinstance(request, (RegisterRequest, EventRequest)):
                    return
                if isinstance(request, RegisterRequest) and isinstance(
                    response, RegisterResponse
                ):
                    authenticated_stream = True
        except asyncio.CancelledError:
            raise
        except Exception:
            try:
                await self._write_response(writer, _error(ErrorCode.INTERNAL_ERROR))
            except (ConnectionError, OSError):
                pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
            self._connection_writers.discard(writer)
            if current is not None:
                self._connection_tasks.discard(current)

    @staticmethod
    async def _write_response(writer: asyncio.StreamWriter, response: object) -> None:
        try:
            encoded = encode_response(response)  # type: ignore[arg-type]
            if len(encoded) > MAX_MESSAGE_BYTES:
                encoded = FALLBACK_ERROR_BYTES
        except BaseException:
            encoded = FALLBACK_ERROR_BYTES
        writer.write(encoded)
        await writer.drain()

    async def _dispatch_workspace_operation(
        self,
        request: RestoreExecuteRequest | RestoreRetryRequest | DiscardRequest,
    ) -> object:
        async with self._dispatch_lock:
            workspace_lock = self._workspace_locks.setdefault(
                request.workspace_id,
                asyncio.Lock(),
            )
        async with workspace_lock:
            if isinstance(request, RestoreExecuteRequest):
                return await self._restore_execute(request)
            if isinstance(request, RestoreRetryRequest):
                return await self._restore_retry(request)
            return await self._discard(request)

    async def _dispatch(
        self, request: object, *, peer_pid: int | None = None
    ) -> object:
        if isinstance(request, RegisterRequest):
            try:
                updated, capability = register_shell(
                    self.state, request, peer_pid=peer_pid
                )
            except ValueError:
                return _error(ErrorCode.INVALID_REQUEST)
            await self.checkpoints.mark_dirty(updated.dirty_generation)
            self.state = updated
            # Tell the bridge where to resume from so a reconnect cannot replay
            # already-accepted events (finding #11).
            resume_sequence = updated.registrations[request.shell_id].last_sequence
            return RegisterResponse(capability, resume_sequence)

        if isinstance(request, EventRequest):
            try:
                updated = apply_event(self.state, request)
            except ValueError as exc:
                message = str(exc)
                if "sequence" in message:
                    return _error(ErrorCode.SEQUENCE_REJECTED)
                if "registration" in message or "authority" in message or "identity" in message:
                    return _error(ErrorCode.UNAUTHORIZED)
                return _error(ErrorCode.INVALID_REQUEST)
            await self.checkpoints.mark_dirty(updated.dirty_generation)
            self.state = updated
            return EventResponse(request.sequence)

        if isinstance(request, StatusRequest):
            status = self.checkpoints.status
            recovery_count = 0
            try:
                recovery = self.store.load_recovery()
                if recovery is not None:
                    recovery_count = max(
                        0,
                        len(recovery.items) - len(recovery.completed_item_ids),
                    )
            except BaseException:
                recovery_count = 0
            diagnostics = tuple(
                SafeExternalText.sanitize(item)
                for item in getattr(self.store, "diagnostics", ())
            )
            last_error = (
                None
                if status.last_error is None
                else SafeExternalText.sanitize(status.last_error)
            )
            return StatusResponse(
                True,
                len(self.state.registrations),
                status.dirty_generation,
                status.durable_generation,
                status.write_active,
                status.last_error is not None,
                last_error,
                recovery_count,
                diagnostics,
            )

        if isinstance(request, SnapshotRequest):
            required_generation = self.state.dirty_generation
            status = await self.checkpoints.flush()
            if status.durable_generation < required_generation:
                return _error(ErrorCode.PERSISTENCE_FAILED)
            return SnapshotResponse(status.durable_generation)

        if isinstance(request, RestoreListRequest):
            return await self._restore_list(request)

        if isinstance(request, RestoreExecuteRequest):
            return await self._restore_execute(request)

        if isinstance(request, RestoreRetryRequest):
            return await self._restore_retry(request)

        if isinstance(request, DiscardRequest):
            return await self._discard(request)

        return _error(ErrorCode.INVALID_REQUEST)

    async def _restore_list(self, request: RestoreListRequest) -> object:
        try:
            record = await asyncio.to_thread(self.store.load_recovery)
            diagnostics: tuple[str, ...] = ()
            if record is None:
                workspace = reconcile(
                    self.state.snapshot,
                    self.current_boot_id,
                    self.process_probe,
                    self.home,
                )
                if workspace is None:
                    return RestoreListResponse(None, (), ())
                diagnostics = workspace.diagnostics
                if workspace.items:
                    candidate = record_from_workspace(workspace, self.state.snapshot)
                    await asyncio.to_thread(self.store.write_recovery, candidate)
                    record = await asyncio.to_thread(self.store.load_recovery)
                else:
                    return RestoreListResponse(None, (), tuple(SafeExternalText.sanitize(item) for item in diagnostics))
            if record is None:
                return RestoreListResponse(None, (), ())
            if request.workspace_id is not None:
                mismatch = self._validate_workspace(record, request.workspace_id)
                if mismatch is not None:
                    return mismatch
                source = next(
                    (
                        attempt
                        for attempt in record.attempts
                        if attempt.attempt_id == request.attempt_id
                    ),
                    None,
                )
                if source is None:
                    return _error(ErrorCode.ATTEMPT_MISMATCH)
                included_ids = {
                    outcome.item_id
                    for outcome in source.outcomes
                    if outcome.kind in (OutcomeKind.SKIP, OutcomeKind.FAILURE)
                    and outcome.item_id not in record.completed_item_ids
                }
                if not included_ids:
                    return _error(ErrorCode.ATTEMPT_MISMATCH)
            else:
                included_ids = {
                    item.item_id
                    for item in record.items
                    if item.item_id not in record.completed_item_ids
                }
            workspace = workspace_from_record(record, self.home)
            views = tuple(
                self._recovery_view(item)
                for item in workspace.items
                if item.item_id in included_ids
            )
            return RestoreListResponse(record.workspace_id, views, tuple(SafeExternalText.sanitize(item) for item in diagnostics))
        except (OSError, ValueError):
            return _error(ErrorCode.PERSISTENCE_FAILED)

    async def _restore_execute(self, request: RestoreExecuteRequest) -> object:
        async with self._dispatch_lock:
            try:
                record = await asyncio.to_thread(self.store.load_recovery)
            except (OSError, ValueError):
                return _error(ErrorCode.PERSISTENCE_FAILED)
            mismatch = self._validate_workspace(record, request.workspace_id)
            if mismatch is not None:
                return mismatch
            assert record is not None
            selected = tuple(request.selected_item_ids)
            known = {item.item_id for item in record.items}
            if len(selected) != len(set(selected)) or not set(selected) <= known:
                return _error(ErrorCode.UNKNOWN_ITEM)
            if not set(request.approved_item_ids) <= set(selected):
                return _error(ErrorCode.UNKNOWN_ITEM)
            effective = tuple(
                item_id
                for item_id in selected
                if item_id not in record.completed_item_ids
            )
            effective_approved = frozenset(request.approved_item_ids) & frozenset(
                effective
            )
            if not effective:
                prior = self._matching_attempt(
                    record,
                    selected,
                    tuple(request.approved_item_ids),
                )
                if prior is None:
                    return _error(ErrorCode.UNKNOWN_ITEM)
                if set(record.completed_item_ids) == known:
                    try:
                        await asyncio.to_thread(
                            self.store.complete_or_discard,
                            record.workspace_id,
                            discard=False,
                        )
                    except (OSError, ValueError):
                        return _error(ErrorCode.PERSISTENCE_FAILED)
                outcomes = tuple(
                    outcome
                    for outcome in prior.outcomes
                    if outcome.item_id in set(selected)
                )
                return self._result(record, prior.attempt_id, outcomes)
        return await self._run_attempt(record, effective, effective_approved)

    async def _restore_retry(self, request: RestoreRetryRequest) -> object:
        async with self._dispatch_lock:
            try:
                record = await asyncio.to_thread(self.store.load_recovery)
            except (OSError, ValueError):
                return _error(ErrorCode.PERSISTENCE_FAILED)
            mismatch = self._validate_workspace(record, request.workspace_id)
            if mismatch is not None:
                return mismatch
            assert record is not None
            source = next(
                (
                    attempt
                    for attempt in record.attempts
                    if attempt.attempt_id == request.attempt_id
                ),
                None,
            )
            if source is None:
                return _error(ErrorCode.ATTEMPT_MISMATCH)
            retryable = tuple(
                outcome.item_id
                for outcome in source.outcomes
                if outcome.kind in (OutcomeKind.SKIP, OutcomeKind.FAILURE)
                and outcome.item_id not in record.completed_item_ids
            )
            if not set(request.approved_item_ids) <= set(retryable):
                return _error(ErrorCode.UNKNOWN_ITEM)
            if not retryable:
                return _error(ErrorCode.ATTEMPT_MISMATCH)
        return await self._run_attempt(
            record,
            retryable,
            frozenset(request.approved_item_ids),
            source_attempt_id=request.attempt_id,
        )

    def _matching_attempt(self, record, selected, approved):
        if self.adapter is None:
            return None
        expected_id = derive_attempt_id(
            record.workspace_id,
            selected,
            frozenset(approved),
            self.adapter,
        )
        return next(
            (
                attempt
                for attempt in reversed(record.attempts)
                if attempt.attempt_id == expected_id
                and tuple(sorted(attempt.selected_item_ids)) == tuple(sorted(selected))
                and tuple(sorted(attempt.approved_item_ids)) == tuple(sorted(approved))
            ),
            None,
        )

    async def _run_attempt(self, record, selected, approved, *, source_attempt_id=None) -> object:
        if self.adapter is None:
            return _error(ErrorCode.ADAPTER_UNAVAILABLE)
        try:
            available = await asyncio.to_thread(self.adapter.detect)
        except Exception:
            return _error(ErrorCode.ADAPTER_UNAVAILABLE)
        if not available:
            return _error(ErrorCode.ADAPTER_UNAVAILABLE)
        try:
            attempt, actions = await asyncio.to_thread(
                build_attempt,
                record,
                selected,
                approved,
                self.adapter,
                source_attempt_id=source_attempt_id,
                home=self.home,
            )
            raw_outcomes = tuple(await asyncio.to_thread(self.adapter.execute, actions, attempt.attempt_id))
            expected = set(selected)
            outcome_ids = [outcome.item_id for outcome in raw_outcomes]
            if len(outcome_ids) != len(set(outcome_ids)) or set(outcome_ids) != expected:
                return _error(ErrorCode.INTERNAL_ERROR)
            outcomes = tuple(
                Outcome(outcome.item_id, outcome.kind, outcome.message[:MAX_OUTCOME_MESSAGE_CHARS])
                for outcome in raw_outcomes
            )
            async with self._dispatch_lock:
                updated = await asyncio.to_thread(
                    self.store.commit_outcomes,
                    record.workspace_id,
                    attempt,
                    outcomes,
                )
                if set(updated.completed_item_ids) == {
                    item.item_id for item in updated.items
                }:
                    await asyncio.to_thread(
                        self.store.complete_or_discard,
                        record.workspace_id,
                        discard=False,
                    )
                return self._result(updated, attempt.attempt_id, outcomes)
        except (OSError, ValueError):
            return _error(ErrorCode.PERSISTENCE_FAILED)
        except Exception:
            return _error(ErrorCode.INTERNAL_ERROR)

    async def _discard(self, request: DiscardRequest) -> object:
        async with self._dispatch_lock:
            try:
                record = await asyncio.to_thread(self.store.load_recovery)
            except (OSError, ValueError):
                return _error(ErrorCode.PERSISTENCE_FAILED)
            mismatch = self._validate_workspace(record, request.workspace_id)
            if mismatch is not None:
                return mismatch
            try:
                await asyncio.to_thread(
                    self.store.complete_or_discard,
                    request.workspace_id,
                    discard=True,
                )
            except (OSError, ValueError):
                return _error(ErrorCode.PERSISTENCE_FAILED)
            return DiscardResponse(request.workspace_id, True)

    @staticmethod
    def _validate_workspace(record, workspace_id: str) -> object | None:
        if record is None or record.workspace_id != workspace_id:
            return _error(ErrorCode.WORKSPACE_MISMATCH)
        return None

    @staticmethod
    def _recovery_view(item) -> RecoveryItemView:
        command = item.shell.command
        display = None
        if command is not None and item.replay_eligible:
            display = RedactedDisplay.from_command_record(command)
        return RecoveryItemView(
            item.item_id,
            item.shell.shell_id,
            safe_recovery_reason(item.reason),
            item.level,
            str(item.directory),
            None if item.directory_warning is None else SafeExternalText.sanitize(item.directory_warning),
            display,
            item.replay_eligible,
        )

    @staticmethod
    def _result(record, attempt_id: str, outcomes) -> RestoreResultResponse:
        views = tuple(
            OutcomeView(
                outcome.item_id,
                outcome.kind,
                SafeExternalText.catalog(outcome.message) if outcome.message in {"restored"} else SafeExternalText.sanitize(outcome.message),
            )
            for outcome in outcomes
        )
        remaining = tuple(item.item_id for item in record.items if item.item_id not in record.completed_item_ids)
        return RestoreResultResponse(record.workspace_id, attempt_id, views, remaining)

    @staticmethod
    def _open_runtime_directory(path: Path) -> int:
        absolute = path.absolute()
        name = absolute.name
        if not name or name in (".", ".."):
            raise UnsafeRuntimePath("runtime directory must have a final component")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        try:
            parent_fd = os.open(absolute.anchor, flags)
        except OSError as exc:
            raise UnsafeRuntimePath("unsafe runtime directory root") from exc
        try:
            parent_parts = absolute.parent.parts[1:]
            for index, component in enumerate(parent_parts):
                try:
                    next_fd = os.open(component, flags, dir_fd=parent_fd)
                except FileNotFoundError as exc:
                    if index != len(parent_parts) - 1:
                        raise UnsafeRuntimePath(
                            f"unsafe runtime directory ancestor {component}"
                        ) from exc
                    try:
                        os.mkdir(component, mode=0o700, dir_fd=parent_fd)
                        next_fd = os.open(component, flags, dir_fd=parent_fd)
                    except OSError as create_exc:
                        raise UnsafeRuntimePath(
                            f"unsafe runtime directory ancestor {component}"
                        ) from create_exc
                except OSError as exc:
                    raise UnsafeRuntimePath(
                        f"unsafe runtime directory ancestor {component}"
                    ) from exc
                os.close(parent_fd)
                parent_fd = next_fd
            try:
                os.mkdir(name, mode=0o700, dir_fd=parent_fd)
                os.chmod(name, 0o700, dir_fd=parent_fd, follow_symlinks=False)
            except FileExistsError:
                pass
            try:
                runtime_fd = os.open(name, flags, dir_fd=parent_fd)
            except OSError as exc:
                raise UnsafeRuntimePath("runtime path is not a safe directory") from exc
        finally:
            os.close(parent_fd)

        metadata = os.fstat(runtime_fd)
        problem: str | None = None
        if not stat.S_ISDIR(metadata.st_mode):
            problem = "type"
        elif metadata.st_uid != os.getuid():
            problem = "owner"
        elif stat.S_IMODE(metadata.st_mode) != 0o700:
            problem = "mode must be 0700"
        if problem is not None:
            os.close(runtime_fd)
            raise UnsafeRuntimePath(f"unsafe runtime directory {problem}")
        return runtime_fd

    def _open_lock(self, runtime_fd: int) -> int:
        try:
            fd = os.open(
                _LOCK_NAME,
                os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW,
                0o600,
                dir_fd=runtime_fd,
            )
        except OSError as exc:
            raise UnsafeRuntimePath("unsafe service.lock") from exc
        try:
            metadata = os.fstat(fd)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != self.service_uid
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise UnsafeRuntimePath("unsafe service.lock type, owner, or mode")
            return fd
        except BaseException:
            os.close(fd)
            raise
