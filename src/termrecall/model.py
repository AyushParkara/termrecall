# SPDX-License-Identifier: GPL-3.0-or-later

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from math import isfinite
from typing import Any

SCHEMA_VERSION = 1
MAX_COMMAND_CHARS = 3_072
MAX_PATH_CHARS = 768
MAX_ID_CHARS = 128
MAX_ERROR_MESSAGE_CHARS = 96
MAX_OUTCOME_MESSAGE_CHARS = 160
MAX_DIAGNOSTIC_CHARS = 160
MAX_ITEMS = 256


class RestorationLevel(StrEnum):
    EXACT = "exact"
    RECONSTRUCTED = "reconstructed"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"


class TerminationKind(StrEnum):
    EXPLICIT_EXIT = "explicit_exit"
    AMBIGUOUS = "ambiguous"


class CommandDisposition(StrEnum):
    REPLAYABLE = "replayable"
    REDACTED = "redacted"
    UNSAFE = "unsafe"
    UNREPRESENTABLE = "unrepresentable"


class OutcomeKind(StrEnum):
    SUCCESS = "success"
    WARNING = "warning"
    SKIP = "skip"
    FAILURE = "failure"


@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    boot_id: str
    pid: int
    start_time: int

    def __post_init__(self) -> None:
        _require_bounded_string(self.boot_id, "boot_id", MAX_ID_CHARS)
        _require_integer(self.pid, "pid")
        _require_integer(self.start_time, "start_time")
        if self.pid <= 0:
            raise ValueError("pid must be positive")
        if self.start_time < 0:
            raise ValueError("start_time must be non-negative")


@dataclass(frozen=True, slots=True)
class CommandRecord:
    sequence: int
    display: str
    executable: str | None
    disposition: CommandDisposition
    active: bool

    def __post_init__(self) -> None:
        _require_non_negative_integer(self.sequence, "command sequence")
        display_limit = (
            MAX_DIAGNOSTIC_CHARS
            if self.disposition is CommandDisposition.REDACTED
            else MAX_COMMAND_CHARS
        )
        _require_bounded_string(self.display, "display", display_limit)
        if self.executable is not None:
            _require_bounded_string(self.executable, "executable", MAX_COMMAND_CHARS)
        if self.disposition is CommandDisposition.REPLAYABLE:
            if not self.active:
                raise ValueError("completed command cannot be replayable")
            if self.executable is None:
                raise ValueError("active replayable command requires executable body")


@dataclass(frozen=True, slots=True)
class ShellRecord:
    shell_id: str
    identity: ProcessIdentity
    adapter: str
    cwd: str
    last_sequence: int
    command: CommandRecord | None
    termination: TerminationKind | None

    def __post_init__(self) -> None:
        _require_bounded_string(self.shell_id, "shell_id", MAX_ID_CHARS)
        _require_bounded_string(self.adapter, "adapter", MAX_ID_CHARS)
        _require_bounded_string(self.cwd, "cwd", MAX_PATH_CHARS)
        _require_non_negative_integer(self.last_sequence, "last_sequence")


@dataclass(frozen=True, slots=True)
class Outcome:
    item_id: str
    kind: OutcomeKind
    message: str

    def __post_init__(self) -> None:
        _require_bounded_string(self.item_id, "item_id", MAX_ID_CHARS)
        _require_bounded_string(self.message, "message", MAX_OUTCOME_MESSAGE_CHARS)


@dataclass(frozen=True, slots=True)
class RestoreAttempt:
    attempt_id: str
    workspace_id: str
    selected_item_ids: Sequence[str]
    approved_item_ids: Sequence[str]
    outcomes: Sequence[Outcome]

    def __post_init__(self) -> None:
        _require_bounded_string(self.attempt_id, "attempt_id", MAX_ID_CHARS)
        _require_bounded_string(self.workspace_id, "workspace_id", MAX_ID_CHARS)
        _require_bounded_sequence(self.selected_item_ids, "selected_item_ids")
        _require_bounded_sequence(self.approved_item_ids, "approved_item_ids")
        _require_bounded_sequence(self.outcomes, "outcomes")
        for item_id in self.selected_item_ids:
            _require_bounded_string(item_id, "selected item ID", MAX_ID_CHARS)
        for item_id in self.approved_item_ids:
            _require_bounded_string(item_id, "approved item ID", MAX_ID_CHARS)
        selected = tuple(self.selected_item_ids)
        approved = tuple(self.approved_item_ids)
        outcomes = tuple(self.outcomes)
        object.__setattr__(self, "selected_item_ids", selected)
        object.__setattr__(self, "approved_item_ids", approved)
        object.__setattr__(self, "outcomes", outcomes)

        _require_unique(selected, "selected item ID")
        _require_unique(approved, "approved item ID")
        selected_set = set(selected)
        if not set(approved) <= selected_set:
            raise ValueError("approved item must be selected")
        if any(outcome.item_id not in selected_set for outcome in outcomes):
            raise ValueError("outcome item must be selected")
        _require_unique((outcome.item_id for outcome in outcomes), "outcome item ID")


@dataclass(frozen=True, slots=True)
class Snapshot:
    schema_version: int
    generation: int
    captured_at: float
    shells: Sequence[ShellRecord]

    def __post_init__(self) -> None:
        _require_schema_one(self.schema_version)
        _require_non_negative_integer(self.generation, "generation")
        _require_finite_number(self.captured_at, "captured_at")
        _require_bounded_sequence(self.shells, "shells")
        object.__setattr__(self, "shells", tuple(self.shells))


@dataclass(frozen=True, slots=True)
class RecoveryItemRecord:
    item_id: str
    shell: ShellRecord
    reason: str

    def __post_init__(self) -> None:
        _require_bounded_string(self.item_id, "item_id", MAX_ID_CHARS)
        _require_bounded_string(self.reason, "reason", MAX_DIAGNOSTIC_CHARS)


@dataclass(frozen=True, slots=True)
class RecoveryRecord:
    schema_version: int
    workspace_id: str
    source_generation: int
    created_at: float
    items: Sequence[RecoveryItemRecord]
    attempts: Sequence[RestoreAttempt]
    completed_item_ids: Sequence[str]

    def __post_init__(self) -> None:
        _require_schema_one(self.schema_version)
        _require_bounded_string(self.workspace_id, "workspace_id", MAX_ID_CHARS)
        _require_non_negative_integer(self.source_generation, "source_generation")
        _require_finite_number(self.created_at, "created_at")
        _require_bounded_sequence(self.items, "items")
        _require_bounded_sequence(self.attempts, "attempts")
        _require_bounded_sequence(self.completed_item_ids, "completed_item_ids")
        for item_id in self.completed_item_ids:
            _require_bounded_string(item_id, "completed item ID", MAX_ID_CHARS)
        items = tuple(self.items)
        attempts = tuple(self.attempts)
        completed = tuple(self.completed_item_ids)
        object.__setattr__(self, "items", items)
        object.__setattr__(self, "attempts", attempts)
        object.__setattr__(self, "completed_item_ids", completed)

        _require_unique((item.item_id for item in items), "recovery item ID")
        _require_unique((attempt.attempt_id for attempt in attempts), "restore attempt ID")
        _require_unique(completed, "completed item ID")
        item_ids = {item.item_id for item in items}
        if not set(completed) <= item_ids:
            raise ValueError("completed item must exist in recovery items")
        for attempt in attempts:
            if attempt.workspace_id != self.workspace_id:
                raise ValueError("restore attempt workspace does not match recovery workspace")
            if not set(attempt.selected_item_ids) <= item_ids:
                raise ValueError("selected item must exist in recovery items")

        terminal_item_ids = {
            outcome.item_id
            for attempt in attempts
            for outcome in attempt.outcomes
            if outcome.kind in (OutcomeKind.SUCCESS, OutcomeKind.WARNING)
        }
        if not set(completed) <= terminal_item_ids:
            raise ValueError("completed item lacks terminal outcome")


def snapshot_to_dict(snapshot: Snapshot) -> dict[str, object]:
    _require_schema_one(snapshot.schema_version)
    return {
        "schema_version": snapshot.schema_version,
        "generation": snapshot.generation,
        "captured_at": snapshot.captured_at,
        "shells": [_shell_to_dict(shell) for shell in snapshot.shells],
    }


def snapshot_from_dict(value: Mapping[str, object]) -> Snapshot:
    payload = _mapping(value, "snapshot")
    schema_version = _read_schema_version(payload)
    _require_exact_keys(payload, {"schema_version", "generation", "captured_at", "shells"}, "snapshot")
    return Snapshot(
        schema_version,
        _integer(payload["generation"], "generation"),
        _number(payload["captured_at"], "captured_at"),
        tuple(_shell_from_dict(item) for item in _sequence(payload["shells"], "shells")),
    )


def recovery_to_dict(record: RecoveryRecord) -> dict[str, object]:
    _require_schema_one(record.schema_version)
    return {
        "schema_version": record.schema_version,
        "workspace_id": record.workspace_id,
        "source_generation": record.source_generation,
        "created_at": record.created_at,
        "items": [_recovery_item_to_dict(item) for item in record.items],
        "attempts": [_attempt_to_dict(attempt) for attempt in record.attempts],
        "completed_item_ids": list(record.completed_item_ids),
    }


def recovery_from_dict(value: Mapping[str, object]) -> RecoveryRecord:
    payload = _mapping(value, "recovery")
    schema_version = _read_schema_version(payload)
    _require_exact_keys(
        payload,
        {
            "schema_version",
            "workspace_id",
            "source_generation",
            "created_at",
            "items",
            "attempts",
            "completed_item_ids",
        },
        "recovery",
    )
    workspace_id = _bounded_string(payload["workspace_id"], "workspace_id", MAX_ID_CHARS)
    items_value = _sequence(payload["items"], "items")
    attempts_value = _sequence(payload["attempts"], "attempts")
    completed_values = _sequence(payload["completed_item_ids"], "completed_item_ids")
    completed_item_ids = tuple(
        _bounded_string(item, "completed item ID", MAX_ID_CHARS) for item in completed_values
    )
    return RecoveryRecord(
        schema_version,
        workspace_id,
        _integer(payload["source_generation"], "source_generation"),
        _number(payload["created_at"], "created_at"),
        tuple(_recovery_item_from_dict(item) for item in items_value),
        tuple(_attempt_from_dict(item) for item in attempts_value),
        completed_item_ids,
    )


def _identity_to_dict(identity: ProcessIdentity) -> dict[str, object]:
    return {
        "boot_id": identity.boot_id,
        "pid": identity.pid,
        "start_time": identity.start_time,
    }


def _identity_from_dict(value: object) -> ProcessIdentity:
    payload = _mapping(value, "identity")
    _require_exact_keys(payload, {"boot_id", "pid", "start_time"}, "identity")
    boot_id = _bounded_string(payload["boot_id"], "boot_id", MAX_ID_CHARS)
    return ProcessIdentity(
        boot_id,
        _integer(payload["pid"], "pid"),
        _integer(payload["start_time"], "start_time"),
    )


def _command_to_dict(command: CommandRecord) -> dict[str, object]:
    return {
        "sequence": command.sequence,
        "display": command.display,
        "executable": command.executable,
        "disposition": command.disposition.value,
        "active": command.active,
    }


def _command_from_dict(value: object) -> CommandRecord:
    payload = _mapping(value, "command")
    _require_exact_keys(
        payload,
        {"sequence", "display", "executable", "disposition", "active"},
        "command",
    )
    display = _bounded_string(payload["display"], "display", MAX_COMMAND_CHARS)
    executable_value = payload["executable"]
    executable = (
        None
        if executable_value is None
        else _bounded_string(executable_value, "executable", MAX_COMMAND_CHARS)
    )
    disposition_text = _bounded_string(
        payload["disposition"], "command disposition", MAX_ID_CHARS
    )
    disposition = _enum(disposition_text, CommandDisposition, "command disposition")
    if disposition is CommandDisposition.REDACTED:
        _require_bounded_string(display, "display", MAX_DIAGNOSTIC_CHARS)
    return CommandRecord(
        _integer(payload["sequence"], "command sequence"),
        display,
        executable,
        disposition,
        _boolean(payload["active"], "active"),
    )


def _shell_to_dict(shell: ShellRecord) -> dict[str, object]:
    return {
        "shell_id": shell.shell_id,
        "identity": _identity_to_dict(shell.identity),
        "adapter": shell.adapter,
        "cwd": shell.cwd,
        "last_sequence": shell.last_sequence,
        "command": None if shell.command is None else _command_to_dict(shell.command),
        "termination": None if shell.termination is None else shell.termination.value,
    }


def _shell_from_dict(value: object) -> ShellRecord:
    payload = _mapping(value, "shell")
    _require_exact_keys(
        payload,
        {"shell_id", "identity", "adapter", "cwd", "last_sequence", "command", "termination"},
        "shell",
    )
    shell_id = _bounded_string(payload["shell_id"], "shell_id", MAX_ID_CHARS)
    adapter = _bounded_string(payload["adapter"], "adapter", MAX_ID_CHARS)
    cwd = _bounded_string(payload["cwd"], "cwd", MAX_PATH_CHARS)
    termination_value = payload["termination"]
    termination = (
        None
        if termination_value is None
        else _enum(termination_value, TerminationKind, "termination")
    )
    command_value = payload["command"]
    return ShellRecord(
        shell_id,
        _identity_from_dict(payload["identity"]),
        adapter,
        cwd,
        _integer(payload["last_sequence"], "last_sequence"),
        None if command_value is None else _command_from_dict(command_value),
        termination,
    )


def _outcome_to_dict(outcome: Outcome) -> dict[str, object]:
    return {"item_id": outcome.item_id, "kind": outcome.kind.value, "message": outcome.message}


def _outcome_from_dict(value: object) -> Outcome:
    payload = _mapping(value, "outcome")
    _require_exact_keys(payload, {"item_id", "kind", "message"}, "outcome")
    item_id = _bounded_string(payload["item_id"], "item_id", MAX_ID_CHARS)
    message = _bounded_string(payload["message"], "message", MAX_OUTCOME_MESSAGE_CHARS)
    return Outcome(
        item_id,
        _enum(payload["kind"], OutcomeKind, "outcome kind"),
        message,
    )


def _attempt_to_dict(attempt: RestoreAttempt) -> dict[str, object]:
    return {
        "attempt_id": attempt.attempt_id,
        "workspace_id": attempt.workspace_id,
        "selected_item_ids": list(attempt.selected_item_ids),
        "approved_item_ids": list(attempt.approved_item_ids),
        "outcomes": [_outcome_to_dict(outcome) for outcome in attempt.outcomes],
    }


def _attempt_from_dict(value: object) -> RestoreAttempt:
    payload = _mapping(value, "restore attempt")
    _require_exact_keys(
        payload,
        {"attempt_id", "workspace_id", "selected_item_ids", "approved_item_ids", "outcomes"},
        "restore attempt",
    )
    attempt_id = _bounded_string(payload["attempt_id"], "attempt_id", MAX_ID_CHARS)
    workspace_id = _bounded_string(payload["workspace_id"], "workspace_id", MAX_ID_CHARS)
    selected_values = _sequence(payload["selected_item_ids"], "selected_item_ids")
    approved_values = _sequence(payload["approved_item_ids"], "approved_item_ids")
    outcome_values = _sequence(payload["outcomes"], "outcomes")
    selected_item_ids = tuple(
        _bounded_string(item, "selected item ID", MAX_ID_CHARS) for item in selected_values
    )
    approved_item_ids = tuple(
        _bounded_string(item, "approved item ID", MAX_ID_CHARS) for item in approved_values
    )
    return RestoreAttempt(
        attempt_id,
        workspace_id,
        selected_item_ids,
        approved_item_ids,
        tuple(_outcome_from_dict(item) for item in outcome_values),
    )


def _recovery_item_to_dict(item: RecoveryItemRecord) -> dict[str, object]:
    return {"item_id": item.item_id, "shell": _shell_to_dict(item.shell), "reason": item.reason}


def _recovery_item_from_dict(value: object) -> RecoveryItemRecord:
    payload = _mapping(value, "recovery item")
    _require_exact_keys(payload, {"item_id", "shell", "reason"}, "recovery item")
    item_id = _bounded_string(payload["item_id"], "item_id", MAX_ID_CHARS)
    reason = _bounded_string(payload["reason"], "reason", MAX_DIAGNOSTIC_CHARS)
    return RecoveryItemRecord(
        item_id,
        _shell_from_dict(payload["shell"]),
        reason,
    )


def _read_schema_version(payload: Mapping[str, object]) -> int:
    if "schema_version" not in payload:
        raise ValueError("missing keys in schema: schema_version")
    version = _integer(payload["schema_version"], "schema_version")
    _require_schema_one(version)
    return version


def _require_schema_one(version: int) -> None:
    _require_integer(version, "schema_version")
    if version != SCHEMA_VERSION:
        raise ValueError(f"unsupported schema version {version}; reader supports 1")


def _require_exact_keys(payload: Mapping[str, object], expected: set[str], context: str) -> None:
    actual = set(payload)
    unknown = actual - expected
    missing = expected - actual
    if unknown:
        raise ValueError(f"unknown keys in {context}: {', '.join(sorted(unknown))}")
    if missing:
        raise ValueError(f"missing keys in {context}: {', '.join(sorted(missing))}")


def _mapping(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ValueError(f"{context} must be an object")
    return value


def _sequence(value: object, context: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError(f"{context} must be an array")
    _require_bounded_sequence(value, context)
    return value


def _string(value: object, context: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{context} must be a string")
    return value


def _bounded_string(value: object, context: str, maximum: int) -> str:
    text = _string(value, context)
    _require_bounded_string(text, context, maximum)
    return text


def _integer(value: object, context: str) -> int:
    _require_integer(value, context)
    return value


def _number(value: object, context: str) -> float:
    _require_finite_number(value, context)
    return float(value)


def _boolean(value: object, context: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{context} must be a boolean")
    return value


def _enum(value: object, enum_type: type[Any], context: str) -> Any:
    text = _bounded_string(value, context, MAX_ID_CHARS)
    try:
        return enum_type(text)
    except ValueError as exc:
        raise ValueError(f"invalid {context}: {text}") from exc


def _require_integer(value: object, context: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{context} must be an integer")


def _require_non_negative_integer(value: object, context: str) -> None:
    _require_integer(value, context)
    if value < 0:
        raise ValueError(f"{context} must be non-negative")


def _require_finite_number(value: object, context: str) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{context} must be a number")
    if not isfinite(value):
        raise ValueError(f"{context} must be finite")


def _require_bounded_string(value: object, context: str, maximum: int) -> None:
    if not isinstance(value, str):
        raise ValueError(f"{context} must be a string")
    if len(value) > maximum:
        raise ValueError(f"{context} exceeds maximum length {maximum}")


def _require_bounded_sequence(value: object, context: str) -> None:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError(f"{context} must be an array")
    if len(value) > MAX_ITEMS:
        raise ValueError(f"{context} exceeds maximum items {MAX_ITEMS}")


def _require_unique(values: Sequence[str] | Any, context: str) -> None:
    materialized = tuple(values)
    if len(materialized) != len(set(materialized)):
        raise ValueError(f"duplicate {context}")
