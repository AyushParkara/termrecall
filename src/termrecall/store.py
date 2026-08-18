# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import fcntl
import json
import os
import secrets
import stat
import threading
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import Any

from termrecall.model import (
    SCHEMA_VERSION,
    Outcome,
    OutcomeKind,
    RecoveryRecord,
    RestoreAttempt,
    Snapshot,
    recovery_from_dict,
    recovery_to_dict,
    snapshot_from_dict,
    snapshot_to_dict,
)

MIGRATIONS: dict[int, Callable[[Mapping[str, object]], Mapping[str, object]]] = {}
MAX_SNAPSHOT_BYTES = 2 * 1024 * 1024
MAX_RECOVERY_BYTES = 2 * 1024 * 1024
MAX_TOMBSTONE_BYTES = 4 * 1024
_CHECKPOINT_PREFIX = "checkpoint-"
_CHECKPOINT_SUFFIX = ".json"
_CHECKPOINT_DIGITS = 20
_MAX_CHECKPOINTS = 10


class UnsafeStatePath(RuntimeError):
    """A state path failed ownership, mode, type, or symlink checks."""


class UnsupportedSchemaVersion(ValueError):
    """Persisted state cannot be decoded by this version."""


class SnapshotStore:
    def __init__(
        self,
        state_dir: Path,
        *,
        create_parents: bool = False,
        root_boundary: Path | None = None,
    ) -> None:
        self.state_dir = Path(state_dir)
        self.diagnostics: list[str] = []
        self._thread_lock = threading.RLock()
        self._transaction_depth = 0
        self._state_fd = self._open_state_directory(
            self.state_dir,
            create_parents=create_parents,
            root_boundary=root_boundary,
        )
        self._lock_fd = self._open_lock_file()
        self._closed = False
        with self._transaction():
            self._cleanup_stale_recovery_unlocked()

    def __enter__(self) -> SnapshotStore:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def close(self) -> None:
        with self._thread_lock:
            if self._closed:
                return
            if self._transaction_depth != 0:
                raise RuntimeError("cannot close SnapshotStore during a transaction")
            self._closed = True
            try:
                os.close(self._lock_fd)
            finally:
                os.close(self._state_fd)

    def write(self, snapshot: Snapshot) -> Path:
        with self._transaction():
            return self._write_unlocked(snapshot)

    def _write_unlocked(self, snapshot: Snapshot) -> Path:
        name = f"{_CHECKPOINT_PREFIX}{snapshot.generation:0{_CHECKPOINT_DIGITS}d}{_CHECKPOINT_SUFFIX}"
        payload = snapshot_to_dict(snapshot)
        self._atomic_json_write(
            name,
            payload,
            snapshot_from_dict,
            maximum=MAX_SNAPSHOT_BYTES,
            kind="snapshot",
        )
        self._prune_checkpoints_unlocked()
        return self.state_dir / name

    def load_latest(self) -> Snapshot | None:
        with self._transaction():
            valid = self._load_valid_checkpoints_unlocked(newest_first=True)
            return valid[0] if valid else None

    def list_valid(self) -> Sequence[Snapshot]:
        with self._transaction():
            return tuple(reversed(self._load_valid_checkpoints_unlocked(newest_first=True)))

    def load_recovery(self) -> RecoveryRecord | None:
        with self._transaction():
            return self._load_recovery_unlocked()

    def _load_recovery_unlocked(self) -> RecoveryRecord | None:
        try:
            payload = self._read_json("recovery.json", maximum=MAX_RECOVERY_BYTES, kind="recovery")
        except FileNotFoundError:
            return None
        try:
            record = self._decode(payload, recovery_from_dict)
            if self._has_terminal_tombstone(record.workspace_id):
                os.unlink("recovery.json", dir_fd=self._state_fd)
                os.fsync(self._state_fd)
                return None
            return record
        except (TypeError, ValueError) as exc:
            if isinstance(exc, UnsupportedSchemaVersion):
                raise
            raise ValueError(f"invalid recovery record: {exc}") from exc

    def write_recovery(self, record: RecoveryRecord) -> None:
        with self._transaction():
            self._write_recovery_if_absent_unlocked(record)

    def _write_recovery_if_absent_unlocked(self, record: RecoveryRecord) -> None:
        try:
            self._read_json("recovery.json", maximum=MAX_RECOVERY_BYTES, kind="recovery")
        except FileNotFoundError:
            self._atomic_json_write(
                "recovery.json",
                recovery_to_dict(record),
                recovery_from_dict,
                maximum=MAX_RECOVERY_BYTES,
                kind="recovery",
            )

    def _update_recovery(
        self,
        record: RecoveryRecord,
        *,
        expected_workspace_id: str,
        expected_generation: int,
    ) -> None:
        with self._transaction():
            self._update_recovery_unlocked(
                record,
                expected_workspace_id=expected_workspace_id,
                expected_generation=expected_generation,
            )

    def _update_recovery_unlocked(
        self,
        record: RecoveryRecord,
        *,
        expected_workspace_id: str,
        expected_generation: int,
    ) -> None:
        current = self._load_recovery_unlocked()
        if current is None:
            raise ValueError("no unresolved recovery workspace")
        if current.workspace_id != expected_workspace_id or record.workspace_id != expected_workspace_id:
            raise ValueError("recovery workspace changed")
        if current.source_generation != expected_generation:
            raise ValueError("recovery source generation changed")
        if record.source_generation != expected_generation:
            raise ValueError("replacement recovery source generation changed")
        self._atomic_json_write(
            "recovery.json",
            recovery_to_dict(record),
            recovery_from_dict,
            maximum=MAX_RECOVERY_BYTES,
            kind="recovery",
        )

    def commit_outcomes(
        self,
        workspace_id: str,
        attempt: RestoreAttempt,
        outcomes: Sequence[Outcome],
    ) -> RecoveryRecord:
        with self._transaction():
            return self._commit_outcomes_unlocked(workspace_id, attempt, outcomes)

    def _commit_outcomes_unlocked(
        self,
        workspace_id: str,
        attempt: RestoreAttempt,
        outcomes: Sequence[Outcome],
    ) -> RecoveryRecord:
        record = self._load_recovery_unlocked()
        if record is None:
            raise ValueError("no unresolved recovery workspace")
        if workspace_id != record.workspace_id or attempt.workspace_id != workspace_id:
            raise ValueError("restore attempt workspace does not match recovery workspace")
        if any(existing.attempt_id == attempt.attempt_id for existing in record.attempts):
            raise ValueError("restore attempt ID already exists")

        item_ids = {item.item_id for item in record.items}
        selected = set(attempt.selected_item_ids)
        if not selected <= item_ids:
            raise ValueError("selected item must exist in recovery items")
        materialized = tuple(outcomes)
        outcome_ids = [outcome.item_id for outcome in materialized]
        if len(outcome_ids) != len(set(outcome_ids)):
            raise ValueError("duplicate outcome item ID")
        if not set(outcome_ids) <= selected:
            raise ValueError("outcome item must be selected")
        if attempt.outcomes and tuple(attempt.outcomes) != materialized:
            raise ValueError("attempt outcomes do not match committed outcomes")

        committed_attempt = replace(attempt, outcomes=materialized)
        completed = list(record.completed_item_ids)
        for outcome in materialized:
            if outcome.kind in (OutcomeKind.SUCCESS, OutcomeKind.WARNING) and outcome.item_id not in completed:
                completed.append(outcome.item_id)
        updated = replace(
            record,
            attempts=(*record.attempts, committed_attempt),
            completed_item_ids=tuple(completed),
        )
        self._update_recovery_unlocked(
            updated,
            expected_workspace_id=workspace_id,
            expected_generation=record.source_generation,
        )
        return updated

    def complete_or_discard(self, workspace_id: str, *, discard: bool) -> None:
        with self._transaction():
            self._complete_or_discard_unlocked(workspace_id, discard=discard)

    def _complete_or_discard_unlocked(self, workspace_id: str, *, discard: bool) -> None:
        record = self._load_recovery_unlocked()
        if record is None:
            raise ValueError("no unresolved recovery workspace")
        if record.workspace_id != workspace_id:
            raise ValueError("recovery workspace does not match")
        if not discard:
            item_ids = {item.item_id for item in record.items}
            if set(record.completed_item_ids) != item_ids:
                raise ValueError("all recovery items must be terminally successful")

        disposition = "discarded" if discard else "completed"
        tombstone_name = "recovery-discard.json" if discard else "recovery-completion.json"
        tombstone: dict[str, object] = {
            "schema_version": SCHEMA_VERSION,
            "workspace_id": workspace_id,
            "disposition": disposition,
            "timestamp": time.time(),
        }
        self._atomic_json_write(
            tombstone_name,
            tombstone,
            self._validate_tombstone,
            maximum=MAX_TOMBSTONE_BYTES,
            kind="tombstone",
        )
        os.unlink("recovery.json", dir_fd=self._state_fd)
        os.fsync(self._state_fd)

    def _open_lock_file(self) -> int:
        fd = os.open(
            ".store.lock",
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
            0o600,
            dir_fd=self._state_fd,
        )
        os.fchmod(fd, 0o600)
        metadata = os.fstat(fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            os.close(fd)
            raise UnsafeStatePath("unsafe state lock file")
        return fd

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        with self._thread_lock:
            if self._closed:
                raise RuntimeError("SnapshotStore is closed")
            outermost = self._transaction_depth == 0
            if outermost:
                fcntl.flock(self._lock_fd, fcntl.LOCK_EX)
            self._transaction_depth += 1
            try:
                yield
            finally:
                self._transaction_depth -= 1
                if outermost:
                    fcntl.flock(self._lock_fd, fcntl.LOCK_UN)

    @staticmethod
    def _open_state_directory(
        path: Path,
        *,
        create_parents: bool,
        root_boundary: Path | None,
    ) -> int:
        absolute = path.absolute()
        name = absolute.name
        if not name or name in (".", ".."):
            raise UnsafeStatePath("state directory must have a final component")
        if create_parents and root_boundary is None:
            raise UnsafeStatePath("state parent creation requires a root boundary")

        boundary = (root_boundary or Path(absolute.anchor)).absolute()
        try:
            relative = absolute.relative_to(boundary)
        except ValueError as exc:
            raise UnsafeStatePath("state directory is outside root boundary") from exc
        if not relative.parts:
            raise UnsafeStatePath("state directory must be below root boundary")

        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        try:
            parent_fd = os.open(boundary, flags)
        except OSError as exc:
            raise UnsafeStatePath(f"unsafe state directory root: {exc}") from exc
        try:
            if create_parents:
                SnapshotStore._validate_state_directory_fd(
                    parent_fd,
                    "root boundary",
                    private=False,
                )
            for index, component in enumerate(relative.parts):
                final = index == len(relative.parts) - 1
                try:
                    next_fd = os.open(component, flags, dir_fd=parent_fd)
                except FileNotFoundError as exc:
                    if not final and not create_parents:
                        raise UnsafeStatePath(
                            f"unsafe state directory ancestor {component}: {exc}"
                        ) from exc
                    try:
                        os.mkdir(component, mode=0o700, dir_fd=parent_fd)
                        os.chmod(
                            component,
                            0o700,
                            dir_fd=parent_fd,
                            follow_symlinks=False,
                        )
                        next_fd = os.open(component, flags, dir_fd=parent_fd)
                    except OSError as create_exc:
                        label = "state directory" if final else f"ancestor {component}"
                        raise UnsafeStatePath(
                            f"unsafe state directory {label}: {create_exc}"
                        ) from create_exc
                except OSError as exc:
                    raise UnsafeStatePath(
                        f"unsafe state directory ancestor {component}: {exc}"
                    ) from exc
                try:
                    if create_parents or final:
                        SnapshotStore._validate_state_directory_fd(
                            next_fd,
                            "state directory" if final else "ancestor",
                            private=final,
                        )
                except BaseException:
                    os.close(next_fd)
                    raise
                os.close(parent_fd)
                parent_fd = next_fd
            state_fd = parent_fd
            parent_fd = -1
            return state_fd
        finally:
            if parent_fd >= 0:
                os.close(parent_fd)

    @staticmethod
    def _validate_state_directory_fd(
        fd: int,
        label: str,
        *,
        private: bool = True,
    ) -> None:
        metadata = os.fstat(fd)
        problem: str | None = None
        mode = stat.S_IMODE(metadata.st_mode)
        if not stat.S_ISDIR(metadata.st_mode):
            problem = "type"
        elif metadata.st_uid != os.getuid():
            problem = "owner"
        elif private and mode != 0o700:
            problem = "mode must be 0700"
        elif not private and mode & 0o022:
            problem = "mode must not be group or world writable"
        if problem is not None:
            raise UnsafeStatePath(f"unsafe state directory {label} {problem}")

    def _atomic_json_write(
        self,
        destination: str,
        value: Mapping[str, object],
        decoder: Callable[[Mapping[str, object]], Any],
        *,
        maximum: int,
        kind: str,
    ) -> None:
        self._verify_existing_destination(destination)
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if len(encoded) > maximum:
            raise ValueError(f"serialized {kind} exceeds size limit {maximum}")
        decoded = json.loads(encoded)
        if not isinstance(decoded, Mapping):
            raise ValueError("encoded state must be an object")
        self._decode(decoded, decoder)

        temporary = f".tmp-{secrets.token_hex(16)}"
        fd: int | None = None
        try:
            fd = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=self._state_fd,
            )
            os.fchmod(fd, 0o600)
            metadata = os.fstat(fd)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise UnsafeStatePath("unsafe temporary state file")
            view = memoryview(encoded)
            while view:
                written = os.write(fd, view)
                if written == 0:
                    raise OSError("short write while persisting state")
                view = view[written:]
            os.fsync(fd)
            os.close(fd)
            fd = None
            os.replace(
                temporary,
                destination,
                src_dir_fd=self._state_fd,
                dst_dir_fd=self._state_fd,
            )
            os.fsync(self._state_fd)
        except BaseException:
            if fd is not None:
                os.close(fd)
            self._remove_known_temporary(temporary)
            raise

    def _verify_existing_destination(self, name: str) -> None:
        try:
            metadata = os.stat(name, dir_fd=self._state_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        if not stat.S_ISREG(metadata.st_mode):
            raise UnsafeStatePath(f"unsafe state file type: {name}")
        if metadata.st_uid != os.getuid():
            raise UnsafeStatePath(f"unsafe state file owner: {name}")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise UnsafeStatePath(f"unsafe state file mode: {name}")

    def _remove_known_temporary(self, name: str) -> None:
        try:
            metadata = os.stat(name, dir_fd=self._state_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        if stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.getuid():
            os.unlink(name, dir_fd=self._state_fd)

    def _cleanup_stale_recovery_unlocked(self) -> None:
        try:
            payload = self._read_json("recovery.json", maximum=MAX_RECOVERY_BYTES, kind="recovery")
        except FileNotFoundError:
            return
        record = self._decode(payload, recovery_from_dict)
        if self._has_terminal_tombstone(record.workspace_id):
            os.unlink("recovery.json", dir_fd=self._state_fd)
            os.fsync(self._state_fd)

    def _has_terminal_tombstone(self, workspace_id: str) -> bool:
        for name in ("recovery-completion.json", "recovery-discard.json"):
            try:
                payload = self._read_json(name, maximum=MAX_TOMBSTONE_BYTES, kind="tombstone")
            except FileNotFoundError:
                continue
            validated = self._validate_tombstone(payload)
            if validated["workspace_id"] == workspace_id:
                return True
        return False

    def _read_json(self, name: str, *, maximum: int, kind: str) -> Mapping[str, object]:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self._state_fd)
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise UnsafeStatePath(f"unsafe state file type: {name}")
            if metadata.st_uid != os.getuid():
                raise UnsafeStatePath(f"unsafe state file owner: {name}")
            if stat.S_IMODE(metadata.st_mode) != 0o600:
                raise UnsafeStatePath(f"unsafe state file mode: {name}")
            if metadata.st_size > maximum:
                raise ValueError(f"serialized {kind} exceeds size limit {maximum}")
            chunks: list[bytes] = []
            remaining = maximum + 1
            while remaining:
                chunk = os.read(fd, min(65_536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            if sum(map(len, chunks)) > maximum:
                raise ValueError(f"serialized {kind} exceeds size limit {maximum}")
        finally:
            os.close(fd)
        value = json.loads(b"".join(chunks))
        if not isinstance(value, Mapping):
            raise ValueError("persisted state must be an object")
        return value

    def _decode(
        self,
        payload: Mapping[str, object],
        decoder: Callable[[Mapping[str, object]], Any],
    ) -> Any:
        version = payload.get("schema_version")
        if isinstance(version, bool) or not isinstance(version, int):
            raise ValueError("schema_version must be an integer")
        if version != SCHEMA_VERSION:
            migration = MIGRATIONS.get(version)
            if migration is None:
                detail = f"no migration for schema version {version}" if version < SCHEMA_VERSION else f"unsupported schema version {version}"
                raise UnsupportedSchemaVersion(detail)
            payload = migration(payload)
        return decoder(payload)

    def _checkpoint_names(self) -> list[str]:
        names: list[str] = []
        for name in os.listdir(self._state_fd):
            if not name.startswith(_CHECKPOINT_PREFIX) or not name.endswith(_CHECKPOINT_SUFFIX):
                continue
            generation = name[len(_CHECKPOINT_PREFIX) : -len(_CHECKPOINT_SUFFIX)]
            if len(generation) == _CHECKPOINT_DIGITS and generation.isascii() and generation.isdigit():
                names.append(name)
        names.sort(reverse=True)
        return names

    def _load_valid_checkpoints_unlocked(self, *, newest_first: bool) -> list[Snapshot]:
        valid: list[Snapshot] = []
        for name in self._checkpoint_names():
            try:
                payload = self._read_json(name, maximum=MAX_SNAPSHOT_BYTES, kind="snapshot")
                item = self._decode(payload, snapshot_from_dict)
            except UnsupportedSchemaVersion as exc:
                if not valid:
                    raise
                self.diagnostics.append(f"ignored older unsupported checkpoint {name}: {exc}")
                continue
            except (UnsafeStatePath, OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
                self.diagnostics.append(f"ignored invalid checkpoint {name}: {exc}")
                continue
            valid.append(item)
        if newest_first:
            return valid
        return list(reversed(valid))

    def _prune_checkpoints_unlocked(self) -> None:
        valid_names: list[str] = []
        for name in self._checkpoint_names():
            try:
                payload = self._read_json(name, maximum=MAX_SNAPSHOT_BYTES, kind="snapshot")
                self._decode(payload, snapshot_from_dict)
            except (UnsafeStatePath, OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
                continue
            valid_names.append(name)
        removed = False
        for name in valid_names[_MAX_CHECKPOINTS:]:
            try:
                os.unlink(name, dir_fd=self._state_fd)
            except FileNotFoundError:
                continue
            removed = True
        if removed:
            os.fsync(self._state_fd)

    @staticmethod
    def _validate_tombstone(value: Mapping[str, object]) -> Mapping[str, object]:
        required = {"schema_version", "workspace_id", "disposition", "timestamp"}
        if set(value) != required or value["schema_version"] != SCHEMA_VERSION:
            raise ValueError("invalid recovery tombstone")
        if not isinstance(value["workspace_id"], str) or not value["workspace_id"]:
            raise ValueError("invalid recovery tombstone workspace")
        if value["disposition"] not in ("completed", "discarded"):
            raise ValueError("invalid recovery tombstone disposition")
        if isinstance(value["timestamp"], bool) or not isinstance(value["timestamp"], (int, float)):
            raise ValueError("invalid recovery tombstone timestamp")
        return value
