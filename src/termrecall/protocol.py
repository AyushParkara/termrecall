# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any, Literal, TypeAlias
from uuid import UUID

from termrecall.adapters.registry import SUPPORTED_ADAPTERS
from termrecall.model import (
    CommandDisposition,
    CommandRecord,
    OutcomeKind,
    ProcessIdentity,
    RestorationLevel,
)

SCHEMA_VERSION = 1
MAX_MESSAGE_BYTES = 16_384
MAX_RESPONSE_BYTES = 16_384
MAX_LOCAL_FRAME_BYTES = 4_096
MAX_COMMAND_CHARS = 3_072
MAX_PATH_CHARS = 768
MAX_ID_CHARS = 128
MAX_ERROR_MESSAGE_CHARS = 96
MAX_OUTCOME_MESSAGE_CHARS = 160
MAX_DIAGNOSTIC_CHARS = 160
MAX_ITEMS = 256
MAX_JSON_NESTING = 16

_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_CAPABILITY_RE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_MAX_INTEGER = 2**63 - 1


class EventType(StrEnum):
    COMMAND_STARTED = "command_started"
    COMMAND_FINISHED = "command_finished"
    PROMPT_READY = "prompt_ready"
    CWD_CHANGED = "cwd_changed"
    EXPLICIT_EXIT = "explicit_exit"


class Operation(StrEnum):
    REGISTER = "register"
    COMMAND_STARTED = "command_started"
    COMMAND_FINISHED = "command_finished"
    PROMPT_READY = "prompt_ready"
    CWD_CHANGED = "cwd_changed"
    EXPLICIT_EXIT = "explicit_exit"
    STATUS = "status"
    SNAPSHOT = "snapshot"
    RESTORE_LIST = "restore_list"
    RESTORE_EXECUTE = "restore_execute"
    RESTORE_RETRY = "restore_retry"
    DISCARD = "discard"


class ErrorCode(StrEnum):
    INVALID_REQUEST = "invalid_request"
    PEER_REJECTED = "peer_rejected"
    UNAUTHORIZED = "unauthorized"
    SEQUENCE_REJECTED = "sequence_rejected"
    WORKSPACE_MISMATCH = "workspace_mismatch"
    UNKNOWN_ITEM = "unknown_item"
    ATTEMPT_MISMATCH = "attempt_mismatch"
    ADAPTER_UNAVAILABLE = "adapter_unavailable"
    PERSISTENCE_FAILED = "persistence_failed"
    SERVICE_UNAVAILABLE = "service_unavailable"
    INTERNAL_ERROR = "internal_error"


_SAFE_EXTERNAL_TEXT_CATALOG = frozenset({
    "healthy",
    "partial",
    "prior_boot",
    "previous_boot",
    "same_boot_dead",
    "process_unknown",
    "explicit_exit",
    "still_alive",
    "restored",
    "details unavailable",
})
_SAFE_REPLAY_DISPLAY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ./_+-]*$")


@dataclass(frozen=True, slots=True, init=False)
class SafeExternalText:
    value: str

    @classmethod
    def catalog(cls, value: str) -> SafeExternalText:
        if value not in _SAFE_EXTERNAL_TEXT_CATALOG:
            raise ValueError("external text is not in the fixed catalog")
        instance = object.__new__(cls)
        object.__setattr__(instance, "value", value)
        return instance

    @classmethod
    def sanitize(cls, untrusted: object) -> SafeExternalText:
        del untrusted
        return cls.catalog("details unavailable")


@dataclass(frozen=True, slots=True, init=False)
class RedactedDisplay:
    value: str

    @classmethod
    def from_command_record(cls, record: CommandRecord) -> RedactedDisplay:
        if not isinstance(record, CommandRecord):
            raise TypeError("display provenance requires CommandRecord")
        from termrecall.classifier import classify_command

        source = record.executable or record.display
        classified = classify_command(source, record.sequence).record
        if (
            classified.disposition is not CommandDisposition.REPLAYABLE
            or not classified.active
            or classified.executable != record.executable
            or classified.display != record.display
            or not record.active
        ):
            raise ValueError("command record does not match classifier policy")
        value = classified.display
        if len(value) > MAX_DIAGNOSTIC_CHARS or not _SAFE_REPLAY_DISPLAY_RE.fullmatch(value):
            raise ValueError("classified display violates bounded display policy")
        if value.startswith(("cat ", "rm ")) or any(marker in value for marker in ("/etc/", "/private", "..", "=", ";")):
            raise ValueError("classified display violates bounded display policy")
        instance = object.__new__(cls)
        object.__setattr__(instance, "value", value)
        return instance


@dataclass(frozen=True, slots=True, init=False)
class DecodedReplayDisplay:
    value: str

    @classmethod
    def _from_wire(cls, value: str) -> DecodedReplayDisplay:
        instance = object.__new__(cls)
        object.__setattr__(instance, "value", value)
        return instance


ERROR_MESSAGES: Mapping[ErrorCode, str] = {
    ErrorCode.INVALID_REQUEST: "request rejected",
    ErrorCode.PEER_REJECTED: "peer uid rejected",
    ErrorCode.UNAUTHORIZED: "event authority rejected",
    ErrorCode.SEQUENCE_REJECTED: "event sequence rejected",
    ErrorCode.WORKSPACE_MISMATCH: "recovery workspace rejected",
    ErrorCode.UNKNOWN_ITEM: "recovery item rejected",
    ErrorCode.ATTEMPT_MISMATCH: "recovery attempt rejected",
    ErrorCode.ADAPTER_UNAVAILABLE: "terminal adapter unavailable",
    ErrorCode.PERSISTENCE_FAILED: "recovery state was not saved",
    ErrorCode.SERVICE_UNAVAILABLE: "service unavailable",
    ErrorCode.INTERNAL_ERROR: "request could not be completed",
}


@dataclass(frozen=True, slots=True)
class LocalEvent:
    event_type: EventType
    shell_id: str
    cwd: str | None = None
    command_sequence: int | None = None
    command: str | None = None
    exit_status: int | None = None


@dataclass(frozen=True, slots=True)
class RegisterRequest:
    shell_id: str
    identity: ProcessIdentity
    adapter: str
    cwd: str
    sequence: int


@dataclass(frozen=True, slots=True)
class EventRequest:
    operation: Operation
    shell_id: str
    capability: str
    identity: ProcessIdentity
    sequence: int
    cwd: str | None = None
    command_sequence: int | None = None
    command: str | None = None
    exit_status: int | None = None


@dataclass(frozen=True, slots=True)
class StatusRequest:
    pass


@dataclass(frozen=True, slots=True)
class SnapshotRequest:
    pass


@dataclass(frozen=True, slots=True)
class RestoreListRequest:
    workspace_id: str | None = None
    attempt_id: str | None = None


@dataclass(frozen=True, slots=True)
class RestoreExecuteRequest:
    workspace_id: str
    selected_item_ids: Sequence[str]
    approved_item_ids: Sequence[str]


@dataclass(frozen=True, slots=True)
class RestoreRetryRequest:
    workspace_id: str
    attempt_id: str
    approved_item_ids: Sequence[str]


@dataclass(frozen=True, slots=True)
class DiscardRequest:
    workspace_id: str
    confirm: Literal[True]


ServiceRequest: TypeAlias = (
    RegisterRequest | EventRequest | StatusRequest | SnapshotRequest | RestoreListRequest
    | RestoreExecuteRequest | RestoreRetryRequest | DiscardRequest
)


@dataclass(frozen=True, slots=True)
class RegisterResponse:
    capability: str
    resume_sequence: int = 0


@dataclass(frozen=True, slots=True)
class EventResponse:
    sequence: int


@dataclass(frozen=True, slots=True)
class StatusResponse:
    ready: Literal[True]
    registered_shells: int
    dirty_generation: int
    durable_generation: int
    write_active: bool
    durability_degraded: bool
    last_error: SafeExternalText | None
    recovery_item_count: int
    diagnostics: Sequence[SafeExternalText]


@dataclass(frozen=True, slots=True)
class SnapshotResponse:
    durable_generation: int


@dataclass(frozen=True, slots=True)
class RecoveryItemView:
    item_id: str
    shell_id: str
    reason: SafeExternalText
    level: RestorationLevel
    directory: str
    directory_warning: SafeExternalText | None
    replay_display: RedactedDisplay | DecodedReplayDisplay | None
    replay_eligible: bool


@dataclass(frozen=True, slots=True)
class OutcomeView:
    item_id: str
    kind: OutcomeKind
    message: SafeExternalText


@dataclass(frozen=True, slots=True)
class ProtocolError:
    code: ErrorCode
    message: str


@dataclass(frozen=True, slots=True)
class RestoreListResponse:
    workspace_id: str | None
    items: Sequence[RecoveryItemView]
    diagnostics: Sequence[str]


@dataclass(frozen=True, slots=True)
class RestoreResultResponse:
    workspace_id: str
    attempt_id: str
    outcomes: Sequence[OutcomeView]
    remaining_item_ids: Sequence[str]


@dataclass(frozen=True, slots=True)
class DiscardResponse:
    workspace_id: str
    discarded: Literal[True]


@dataclass(frozen=True, slots=True)
class ErrorResponse:
    error: ProtocolError


ServiceResponse: TypeAlias = (
    RegisterResponse | EventResponse | StatusResponse | SnapshotResponse | RestoreListResponse
    | RestoreResultResponse | DiscardResponse | ErrorResponse
)


class ResponseEncodingError(ValueError):
    pass


def _duplicate_rejector(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _require_json_depth(value: object) -> None:
    stack = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > MAX_JSON_NESTING:
            raise ValueError("JSON nesting exceeds limit")
        if isinstance(current, dict):
            stack.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)


def _decode_json_line(raw: bytes, limit: int, context: str) -> dict[str, object]:
    if not isinstance(raw, bytes):
        raise ValueError(f"{context} must be bytes")
    if len(raw) > limit:
        raise ValueError(f"{context} message exceeds byte limit")
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise ValueError(f"{context} must end in exactly one newline")
    try:
        text = raw[:-1].decode("utf-8")
        value = json.loads(text, object_pairs_hook=_duplicate_rejector)
    except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise ValueError(f"invalid {context} JSON") from exc
    _require_json_depth(value)
    if not isinstance(value, dict):
        raise ValueError(f"{context} must be a JSON object")
    return value


def _encode_json_line(payload: Mapping[str, object], limit: int, context: str) -> bytes:
    try:
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8") + b"\n"
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ValueError(f"invalid {context} value") from exc
    if len(raw) > limit:
        raise ValueError(f"{context} message exceeds byte limit")
    return raw


def _exact(payload: Mapping[str, object], keys: set[str], context: str) -> None:
    actual = set(payload)
    if actual != keys:
        unknown, missing = actual - keys, keys - actual
        detail = "unknown" if unknown else "missing"
        values = unknown if unknown else missing
        raise ValueError(f"{detail} keys in {context}: {', '.join(sorted(values))}")


def _schema(payload: Mapping[str, object]) -> None:
    value = payload.get("schema_version")
    if type(value) is not int or value != SCHEMA_VERSION:
        raise ValueError("unsupported schema version")


def _string(value: object, name: str, limit: int, *, empty: bool = True) -> str:
    if not isinstance(value, str) or (not empty and not value):
        raise ValueError(f"{name} must be a string")
    if len(value) > limit:
        raise ValueError(f"{name} exceeds character limit")
    if any(ord(char) < 32 or ord(char) == 127 or 0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise ValueError(f"{name} contains forbidden characters")
    return value


def _id(value: object, name: str = "ID", *, shell: bool = False) -> str:
    result = _string(value, name, MAX_ID_CHARS, empty=False)
    if not _ID_RE.fullmatch(result) or (shell and len(result) < 16):
        raise ValueError(f"invalid {name}")
    return result


def _capability(value: object) -> str:
    result = _string(value, "capability", MAX_ID_CHARS, empty=False)
    if not _CAPABILITY_RE.fullmatch(result):
        raise ValueError("invalid capability")
    return result


def _integer(value: object, name: str, low: int = 0, high: int = _MAX_INTEGER) -> int:
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"invalid {name}")
    return value


def _boolean(value: object, name: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"{name} must be boolean")
    return value


def _absolute(value: object, name: str = "path") -> str:
    result = _string(value, name, MAX_PATH_CHARS, empty=False)
    if not PurePosixPath(result).is_absolute():
        raise ValueError(f"{name} must be absolute")
    return result


def _enum(value: object, enum_type: type[StrEnum], name: str) -> Any:
    bounded = _string(value, name, MAX_ID_CHARS, empty=False)
    try:
        return enum_type(bounded)
    except ValueError as exc:
        raise ValueError(f"invalid {name}") from exc


def _identity(value: object) -> ProcessIdentity:
    if not isinstance(value, dict):
        raise ValueError("identity must be an object")
    _exact(value, {"boot_id", "pid", "start_time"}, "identity")
    boot_id = _string(value["boot_id"], "boot_id", MAX_ID_CHARS, empty=False)
    try:
        canonical = str(UUID(boot_id))
    except ValueError as exc:
        raise ValueError("invalid boot_id") from exc
    if canonical != boot_id:
        raise ValueError("boot_id must be canonical UUID text")
    return ProcessIdentity(canonical, _integer(value["pid"], "pid", 1, 2**31 - 1), _integer(value["start_time"], "start_time"))


def _identity_dict(value: ProcessIdentity) -> dict[str, object]:
    return {"boot_id": value.boot_id, "pid": value.pid, "start_time": value.start_time}


def _bounded_typed_sequence(value: object, name: str, *, nonempty: bool = False) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError(f"invalid {name}")
    length = len(value)
    if length > MAX_ITEMS or (nonempty and length == 0):
        raise ValueError(f"invalid {name}")
    return value


def _id_list(value: object, name: str, *, nonempty: bool = False) -> tuple[str, ...]:
    sequence = _bounded_typed_sequence(value, name, nonempty=nonempty)
    result = tuple(_id(item, name) for item in sequence)
    if len(set(result)) != len(result):
        raise ValueError(f"duplicate {name}")
    return result


def _safe_external_text_from_wire(value: object, name: str) -> SafeExternalText:
    text = _string(value, name, MAX_DIAGNOSTIC_CHARS)
    return SafeExternalText.catalog(text)


def _safe_external_text_list(value: object, name: str) -> tuple[SafeExternalText, ...]:
    if not isinstance(value, list) or len(value) > MAX_ITEMS:
        raise ValueError(f"invalid {name}")
    return tuple(_safe_external_text_from_wire(item, name) for item in value)


def _local_decoder(payload: dict[str, object]) -> LocalEvent:
    _schema(payload)
    event_type = _enum(payload.get("type"), EventType, "type")
    base = {"schema_version", "type", "shell_id"}
    extra = {
        EventType.COMMAND_STARTED: {"command_sequence", "command"},
        EventType.COMMAND_FINISHED: {"command_sequence", "exit_status"},
        EventType.PROMPT_READY: {"cwd"}, EventType.CWD_CHANGED: {"cwd"},
        EventType.EXPLICIT_EXIT: set(),
    }[event_type]
    _exact(payload, base | extra, "local event")
    return LocalEvent(
        event_type, _id(payload["shell_id"], "shell_id", shell=True),
        _absolute(payload["cwd"], "cwd") if "cwd" in extra else None,
        _integer(payload["command_sequence"], "command_sequence", 1) if "command_sequence" in extra else None,
        _string(payload["command"], "command", MAX_COMMAND_CHARS, empty=False) if "command" in extra else None,
        _integer(payload["exit_status"], "exit_status", 0, 255) if "exit_status" in extra else None,
    )


def decode_local_frame(raw: bytes) -> LocalEvent:
    return _local_decoder(_decode_json_line(raw, MAX_LOCAL_FRAME_BYTES, "local frame"))


def encode_local_frame(event: LocalEvent) -> bytes:
    if not isinstance(event, LocalEvent):
        raise ValueError("unsupported local event")
    payload: dict[str, object] = {"schema_version": 1, "type": event.event_type.value, "shell_id": event.shell_id}
    if event.event_type in (EventType.PROMPT_READY, EventType.CWD_CHANGED): payload["cwd"] = event.cwd
    elif event.event_type is EventType.COMMAND_STARTED: payload.update(command_sequence=event.command_sequence, command=event.command)
    elif event.event_type is EventType.COMMAND_FINISHED: payload.update(command_sequence=event.command_sequence, exit_status=event.exit_status)
    raw = _encode_json_line(payload, MAX_LOCAL_FRAME_BYTES, "local frame")
    _local_decoder(_decode_json_line(raw, MAX_LOCAL_FRAME_BYTES, "local frame"))
    return raw


def _register(payload: dict[str, object]) -> ServiceRequest:
    _exact(payload, {"schema_version", "operation", "shell_id", "identity", "adapter", "cwd", "sequence"}, "register request")
    adapter = _string(payload["adapter"], "adapter", MAX_ID_CHARS, empty=False)
    if adapter not in SUPPORTED_ADAPTERS: raise ValueError("invalid adapter")
    return RegisterRequest(_id(payload["shell_id"], "shell_id", shell=True), _identity(payload["identity"]), adapter, _absolute(payload["cwd"], "cwd"), _integer(payload["sequence"], "sequence", 0, 0))


def _event(payload: dict[str, object], operation: Operation) -> ServiceRequest:
    common = {"schema_version", "operation", "shell_id", "capability", "identity", "sequence"}
    extra = {Operation.COMMAND_STARTED: {"command_sequence", "command"}, Operation.COMMAND_FINISHED: {"command_sequence", "exit_status"}, Operation.PROMPT_READY: {"cwd"}, Operation.CWD_CHANGED: {"cwd"}, Operation.EXPLICIT_EXIT: set()}[operation]
    _exact(payload, common | extra, "event request")
    return EventRequest(operation, _id(payload["shell_id"], "shell_id", shell=True), _capability(payload["capability"]), _identity(payload["identity"]), _integer(payload["sequence"], "sequence", 1), _absolute(payload["cwd"], "cwd") if "cwd" in extra else None, _integer(payload["command_sequence"], "command_sequence", 1) if "command_sequence" in extra else None, _string(payload["command"], "command", MAX_COMMAND_CHARS, empty=False) if "command" in extra else None, _integer(payload["exit_status"], "exit_status", 0, 255) if "exit_status" in extra else None)


def _control(payload: dict[str, object], cls: type[StatusRequest] | type[SnapshotRequest] | type[RestoreListRequest]) -> ServiceRequest:
    _exact(payload, {"schema_version", "operation"}, "control request")
    return cls()


def _restore_list(payload: dict[str, object]) -> ServiceRequest:
    base = {"schema_version", "operation"}
    if set(payload) == base:
        return RestoreListRequest()
    _exact(payload, base | {"workspace_id", "attempt_id"}, "restore list request")
    return RestoreListRequest(
        _id(payload["workspace_id"], "workspace_id"),
        _id(payload["attempt_id"], "attempt_id"),
    )


def _execute(payload: dict[str, object]) -> ServiceRequest:
    _exact(payload, {"schema_version", "operation", "workspace_id", "selected_item_ids", "approved_item_ids"}, "restore execute request")
    selected = _id_list(payload["selected_item_ids"], "selected_item_ids", nonempty=True)
    approved = _id_list(payload["approved_item_ids"], "approved_item_ids")
    if not set(approved) <= set(selected): raise ValueError("approved IDs must be selected")
    return RestoreExecuteRequest(_id(payload["workspace_id"], "workspace_id"), selected, approved)


def _retry(payload: dict[str, object]) -> ServiceRequest:
    _exact(payload, {"schema_version", "operation", "workspace_id", "attempt_id", "approved_item_ids"}, "restore retry request")
    return RestoreRetryRequest(_id(payload["workspace_id"], "workspace_id"), _id(payload["attempt_id"], "attempt_id"), _id_list(payload["approved_item_ids"], "approved_item_ids"))


def _discard(payload: dict[str, object]) -> ServiceRequest:
    _exact(payload, {"schema_version", "operation", "workspace_id", "confirm"}, "discard request")
    if payload["confirm"] is not True: raise ValueError("confirm must be true")
    return DiscardRequest(_id(payload["workspace_id"], "workspace_id"), True)


REQUEST_DECODERS: dict[Operation, Callable[[dict[str, object]], ServiceRequest]] = {
    Operation.REGISTER: _register,
    Operation.COMMAND_STARTED: lambda p: _event(p, Operation.COMMAND_STARTED),
    Operation.COMMAND_FINISHED: lambda p: _event(p, Operation.COMMAND_FINISHED),
    Operation.PROMPT_READY: lambda p: _event(p, Operation.PROMPT_READY),
    Operation.CWD_CHANGED: lambda p: _event(p, Operation.CWD_CHANGED),
    Operation.EXPLICIT_EXIT: lambda p: _event(p, Operation.EXPLICIT_EXIT),
    Operation.STATUS: lambda p: _control(p, StatusRequest),
    Operation.SNAPSHOT: lambda p: _control(p, SnapshotRequest),
    Operation.RESTORE_LIST: _restore_list,
    Operation.RESTORE_EXECUTE: _execute, Operation.RESTORE_RETRY: _retry, Operation.DISCARD: _discard,
}


def decode_request(raw: bytes) -> ServiceRequest:
    payload = _decode_json_line(raw, MAX_MESSAGE_BYTES, "request")
    _schema(payload)
    operation = _enum(payload.get("operation"), Operation, "operation")
    return REQUEST_DECODERS[operation](payload)


def _request_to_dict(request: ServiceRequest) -> dict[str, object]:
    base: dict[str, object] = {"schema_version": 1}
    if isinstance(request, RegisterRequest): base.update(operation="register", shell_id=request.shell_id, identity=_identity_dict(request.identity), adapter=request.adapter, cwd=request.cwd, sequence=request.sequence)
    elif isinstance(request, EventRequest):
        base.update(operation=request.operation.value, shell_id=request.shell_id, capability=request.capability, identity=_identity_dict(request.identity), sequence=request.sequence)
        if request.operation in (Operation.PROMPT_READY, Operation.CWD_CHANGED): base["cwd"] = request.cwd
        elif request.operation is Operation.COMMAND_STARTED: base.update(command_sequence=request.command_sequence, command=request.command)
        elif request.operation is Operation.COMMAND_FINISHED: base.update(command_sequence=request.command_sequence, exit_status=request.exit_status)
    elif isinstance(request, StatusRequest): base["operation"] = "status"
    elif isinstance(request, SnapshotRequest): base["operation"] = "snapshot"
    elif isinstance(request, RestoreListRequest):
        base["operation"] = "restore_list"
        if (request.workspace_id is None) != (request.attempt_id is None):
            raise ValueError("workspace_id and attempt_id must be provided together")
        if request.workspace_id is not None:
            base.update(
                workspace_id=_id(request.workspace_id, "workspace_id"),
                attempt_id=_id(request.attempt_id, "attempt_id"),
            )
    elif isinstance(request, RestoreExecuteRequest): base.update(operation="restore_execute", workspace_id=request.workspace_id, selected_item_ids=list(_id_list(request.selected_item_ids, "selected_item_ids", nonempty=True)), approved_item_ids=list(_id_list(request.approved_item_ids, "approved_item_ids")))
    elif isinstance(request, RestoreRetryRequest): base.update(operation="restore_retry", workspace_id=request.workspace_id, attempt_id=request.attempt_id, approved_item_ids=list(_id_list(request.approved_item_ids, "approved_item_ids")))
    elif isinstance(request, DiscardRequest): base.update(operation="discard", workspace_id=request.workspace_id, confirm=request.confirm)
    else: raise ValueError("unsupported request type")
    return base


def encode_request(request: ServiceRequest) -> bytes:
    raw = _encode_json_line(_request_to_dict(request), MAX_MESSAGE_BYTES, "request")
    decode_request(raw)
    return raw


def _item(value: object) -> RecoveryItemView:
    if not isinstance(value, dict): raise ValueError("item must be object")
    keys = {"item_id", "shell_id", "reason", "level", "directory", "directory_warning", "replay_display", "replay_eligible"}; _exact(value, keys, "item")
    warning = value["directory_warning"]; display = value["replay_display"]
    return RecoveryItemView(_id(value["item_id"], "item_id"), _id(value["shell_id"], "shell_id", shell=True), _safe_external_text_from_wire(value["reason"], "reason"), _enum(value["level"], RestorationLevel, "level"), _absolute(value["directory"], "directory"), None if warning is None else _safe_external_text_from_wire(warning, "directory_warning"), None if display is None else DecodedReplayDisplay._from_wire(_string(display, "replay_display", MAX_COMMAND_CHARS)), _boolean(value["replay_eligible"], "replay_eligible"))


def _outcome(value: object) -> OutcomeView:
    if not isinstance(value, dict): raise ValueError("outcome must be object")
    _exact(value, {"item_id", "kind", "message"}, "outcome")
    return OutcomeView(_id(value["item_id"], "item_id"), _enum(value["kind"], OutcomeKind, "kind"), _safe_external_text_from_wire(value["message"], "message"))


def _object_list(value: object, name: str, reader: Callable[[object], Any]) -> tuple[Any, ...]:
    if not isinstance(value, list) or len(value) > MAX_ITEMS: raise ValueError(f"invalid {name}")
    result = tuple(reader(item) for item in value)
    ids = [item.item_id for item in result]
    if len(ids) != len(set(ids)): raise ValueError(f"duplicate {name} IDs")
    return result


def _decode_response_payload(p: dict[str, object]) -> ServiceResponse:
    _schema(p); ok = _boolean(p.get("ok"), "ok"); response = _string(p.get("response"), "response", MAX_ID_CHARS, empty=False)
    common = {"schema_version", "ok", "response"}
    if response == "register" and ok: _exact(p, common | {"capability", "resume_sequence"}, response); return RegisterResponse(_capability(p["capability"]), _integer(p["resume_sequence"], "resume_sequence", 0))
    if response == "event" and ok: _exact(p, common | {"sequence"}, response); return EventResponse(_integer(p["sequence"], "sequence", 1))
    if response == "status" and ok:
        keys = {"ready", "registered_shells", "dirty_generation", "durable_generation", "write_active", "durability_degraded", "last_error", "recovery_item_count", "diagnostics"}; _exact(p, common | keys, response)
        if p["ready"] is not True: raise ValueError("ready must be true")
        error = p["last_error"]
        return StatusResponse(True, _integer(p["registered_shells"], "registered_shells"), _integer(p["dirty_generation"], "dirty_generation"), _integer(p["durable_generation"], "durable_generation"), _boolean(p["write_active"], "write_active"), _boolean(p["durability_degraded"], "durability_degraded"), None if error is None else _safe_external_text_from_wire(error, "last_error"), _integer(p["recovery_item_count"], "recovery_item_count"), _safe_external_text_list(p["diagnostics"], "diagnostics"))
    if response == "snapshot" and ok: _exact(p, common | {"durable_generation"}, response); return SnapshotResponse(_integer(p["durable_generation"], "durable_generation"))
    if response == "restore_list" and ok:
        _exact(p, common | {"workspace_id", "items", "diagnostics"}, response); items = _object_list(p["items"], "items", _item); workspace = p["workspace_id"]
        if (workspace is None) != (not items): raise ValueError("workspace_id must be null iff items empty")
        return RestoreListResponse(None if workspace is None else _id(workspace, "workspace_id"), items, _safe_external_text_list(p["diagnostics"], "diagnostics"))
    if response == "restore_result" and ok:
        _exact(p, common | {"workspace_id", "attempt_id", "outcomes", "remaining_item_ids"}, response)
        return RestoreResultResponse(_id(p["workspace_id"], "workspace_id"), _id(p["attempt_id"], "attempt_id"), _object_list(p["outcomes"], "outcomes", _outcome), _id_list(p["remaining_item_ids"], "remaining_item_ids"))
    if response == "discard" and ok:
        _exact(p, common | {"workspace_id", "discarded"}, response)
        if p["discarded"] is not True: raise ValueError("discarded must be true")
        return DiscardResponse(_id(p["workspace_id"], "workspace_id"), True)
    if response == "error" and not ok:
        _exact(p, common | {"error"}, response); value = p["error"]
        if not isinstance(value, dict): raise ValueError("error must be object")
        _exact(value, {"code", "message"}, "error"); code = _enum(value["code"], ErrorCode, "error code"); message = _string(value["message"], "error message", MAX_ERROR_MESSAGE_CHARS)
        if message != ERROR_MESSAGES[code]: raise ValueError("invalid fixed error message")
        return ErrorResponse(ProtocolError(code, message))
    raise ValueError("invalid response discriminator")


def decode_response(raw: bytes) -> ServiceResponse:
    return _decode_response_payload(_decode_json_line(raw, MAX_RESPONSE_BYTES, "response"))


def _typed_values(value: object, name: str, expected: type) -> tuple[object, ...]:
    sequence = _bounded_typed_sequence(value, name)
    values = tuple(sequence)
    if any(not isinstance(item, expected) for item in values):
        raise ValueError(f"invalid {name} element")
    return values


def _typed_safe_text_values(value: object, name: str) -> tuple[str, ...]:
    return tuple(item.value for item in _typed_values(value, name, SafeExternalText))


def _item_dict(item: RecoveryItemView) -> dict[str, object]:
    if not isinstance(item.reason, SafeExternalText):
        raise ValueError("reason lacks safe external provenance")
    if item.directory_warning is not None and not isinstance(item.directory_warning, SafeExternalText):
        raise ValueError("directory_warning lacks safe external provenance")
    if item.replay_display is not None and not isinstance(item.replay_display, RedactedDisplay):
        raise ValueError("replay_display lacks classifier provenance")
    return {"item_id": item.item_id, "shell_id": item.shell_id, "reason": item.reason.value, "level": item.level.value, "directory": item.directory, "directory_warning": None if item.directory_warning is None else item.directory_warning.value, "replay_display": None if item.replay_display is None else item.replay_display.value, "replay_eligible": item.replay_eligible}


def _outcome_dict(item: OutcomeView) -> dict[str, object]:
    if not isinstance(item.message, SafeExternalText):
        raise ValueError("outcome message lacks safe external provenance")
    return {"item_id": item.item_id, "kind": item.kind.value, "message": item.message.value}


def _response_to_dict(response: ServiceResponse) -> dict[str, object]:
    p: dict[str, object] = {"schema_version": 1, "ok": True}
    if isinstance(response, RegisterResponse): p.update(response="register", capability=response.capability, resume_sequence=response.resume_sequence)
    elif isinstance(response, EventResponse): p.update(response="event", sequence=response.sequence)
    elif isinstance(response, StatusResponse):
        if response.last_error is not None and not isinstance(response.last_error, SafeExternalText): raise ValueError("last_error lacks safe external provenance")
        p.update(response="status", ready=response.ready, registered_shells=response.registered_shells, dirty_generation=response.dirty_generation, durable_generation=response.durable_generation, write_active=response.write_active, durability_degraded=response.durability_degraded, last_error=None if response.last_error is None else response.last_error.value, recovery_item_count=response.recovery_item_count, diagnostics=list(_typed_safe_text_values(response.diagnostics, "diagnostics")))
    elif isinstance(response, SnapshotResponse): p.update(response="snapshot", durable_generation=response.durable_generation)
    elif isinstance(response, RestoreListResponse): p.update(response="restore_list", workspace_id=response.workspace_id, items=[_item_dict(i) for i in _typed_values(response.items, "items", RecoveryItemView)], diagnostics=list(_typed_safe_text_values(response.diagnostics, "diagnostics")))
    elif isinstance(response, RestoreResultResponse): p.update(response="restore_result", workspace_id=response.workspace_id, attempt_id=response.attempt_id, outcomes=[_outcome_dict(i) for i in _typed_values(response.outcomes, "outcomes", OutcomeView)], remaining_item_ids=list(_id_list(response.remaining_item_ids, "remaining_item_ids")))
    elif isinstance(response, DiscardResponse): p.update(response="discard", workspace_id=response.workspace_id, discarded=response.discarded)
    elif isinstance(response, ErrorResponse): p.update(ok=False, response="error", error={"code": response.error.code.value, "message": response.error.message})
    else: raise ResponseEncodingError("unsupported response type")
    return p


def _safe_response_tree(value: object, *, register: bool = False) -> None:
    if isinstance(value, BaseException): raise ResponseEncodingError("exception objects forbidden")
    if isinstance(value, dict):
        for key, child in value.items():
            if key in {"command", "approved_command", "argv", "executable"} or (key == "capability" and not register): raise ResponseEncodingError("sensitive response key forbidden")
            _safe_response_tree(child, register=register)
    elif isinstance(value, (list, tuple)):
        for child in value: _safe_response_tree(child, register=register)


def encode_response(response: ServiceResponse) -> bytes:
    try:
        payload = _response_to_dict(response); _safe_response_tree(payload, register=isinstance(response, RegisterResponse))
        raw = _encode_json_line(payload, MAX_RESPONSE_BYTES, "response"); decode_response(raw); return raw
    except ResponseEncodingError: raise
    except (ValueError, TypeError, AttributeError) as exc: raise ResponseEncodingError("response encoding failed") from exc


INTERNAL_ERROR = ErrorResponse(ProtocolError(ErrorCode.INTERNAL_ERROR, ERROR_MESSAGES[ErrorCode.INTERNAL_ERROR]))
FALLBACK_ERROR_BYTES = encode_response(INTERNAL_ERROR)
assert len(FALLBACK_ERROR_BYTES) <= MAX_RESPONSE_BYTES
