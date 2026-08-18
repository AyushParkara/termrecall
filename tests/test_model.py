from dataclasses import replace

import pytest

from termrecall.model import (
    MAX_COMMAND_CHARS,
    MAX_DIAGNOSTIC_CHARS,
    MAX_ID_CHARS,
    MAX_ITEMS,
    MAX_OUTCOME_MESSAGE_CHARS,
    MAX_PATH_CHARS,
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
    TerminationKind,
    recovery_from_dict,
    recovery_to_dict,
    snapshot_from_dict,
    snapshot_to_dict,
)


def sample_shell(*, command: CommandRecord | None = None) -> ShellRecord:
    identity = ProcessIdentity("11111111-1111-1111-1111-111111111111", 42, 900)
    return ShellRecord(
        "shell-aaaaaaaaaaa",
        identity,
        "gnome-terminal",
        "/srv/app",
        7,
        command,
        None,
    )


def sample_recovery() -> RecoveryRecord:
    command = CommandRecord(
        3,
        "python -m http.server",
        "python -m http.server",
        CommandDisposition.REPLAYABLE,
        True,
    )
    item = RecoveryItemRecord("item-a", sample_shell(command=command), "prior_boot")
    outcome = Outcome("item-a", OutcomeKind.SUCCESS, "restored")
    attempt = RestoreAttempt(
        "attempt-a",
        "workspace-a",
        ("item-a",),
        ("item-a",),
        (outcome,),
    )
    return RecoveryRecord(
        1,
        "workspace-a",
        4,
        13.5,
        (item,),
        (attempt,),
        ("item-a",),
    )


def test_enum_values_are_lowercase_schema_values() -> None:
    assert [member.value for member in RestorationLevel] == [
        "exact",
        "reconstructed",
        "partial",
        "unavailable",
    ]
    assert [member.value for member in TerminationKind] == [
        "explicit_exit",
        "ambiguous",
    ]
    assert [member.value for member in CommandDisposition] == [
        "replayable",
        "redacted",
        "unsafe",
        "unrepresentable",
    ]
    assert [member.value for member in OutcomeKind] == [
        "success",
        "warning",
        "skip",
        "failure",
    ]


def test_snapshot_schema_one_round_trip() -> None:
    command = CommandRecord(
        3,
        "python -m http.server",
        "python -m http.server",
        CommandDisposition.REPLAYABLE,
        True,
    )
    original = Snapshot(1, 4, 12.5, (sample_shell(command=command),))
    assert snapshot_from_dict(snapshot_to_dict(original)) == original


def test_snapshot_serialization_has_exact_schema_one_shape() -> None:
    original = Snapshot(1, 4, 12.5, (sample_shell(),))
    assert snapshot_to_dict(original) == {
        "schema_version": 1,
        "generation": 4,
        "captured_at": 12.5,
        "shells": [
            {
                "shell_id": "shell-aaaaaaaaaaa",
                "identity": {
                    "boot_id": "11111111-1111-1111-1111-111111111111",
                    "pid": 42,
                    "start_time": 900,
                },
                "adapter": "gnome-terminal",
                "cwd": "/srv/app",
                "last_sequence": 7,
                "command": None,
                "termination": None,
            }
        ],
    }


def test_future_snapshot_schema_is_rejected_without_interpretation() -> None:
    with pytest.raises(ValueError, match="unsupported schema version 2; reader supports 1"):
        snapshot_from_dict({"schema_version": 2})


def test_schema_version_must_be_an_integer() -> None:
    with pytest.raises(ValueError, match="schema_version must be an integer"):
        Snapshot(True, 0, 0.0, ())


def test_snapshot_unknown_keys_are_rejected() -> None:
    value = snapshot_to_dict(Snapshot(1, 4, 12.5, (sample_shell(),)))
    value["unknown"] = True
    with pytest.raises(ValueError, match="unknown keys"):
        snapshot_from_dict(value)


def test_nested_snapshot_unknown_keys_are_rejected() -> None:
    value = snapshot_to_dict(Snapshot(1, 4, 12.5, (sample_shell(),)))
    shell = value["shells"][0]
    assert isinstance(shell, dict)
    shell["unknown"] = True
    with pytest.raises(ValueError, match="unknown keys"):
        snapshot_from_dict(value)


@pytest.mark.parametrize(
    ("factory", "match"),
    [
        (lambda: ProcessIdentity("boot", 0, 0), "pid"),
        (lambda: ProcessIdentity("boot", 1, -1), "start_time"),
        (
            lambda: CommandRecord(1, "redacted", None, CommandDisposition.REPLAYABLE, True),
            "active replayable command",
        ),
        (
            lambda: CommandRecord(1, "done", "done", CommandDisposition.REPLAYABLE, False),
            "completed command cannot be replayable",
        ),
        (lambda: CommandRecord(-1, "bad", None, CommandDisposition.UNSAFE, False), "sequence"),
        (
            lambda: ShellRecord("shell", ProcessIdentity("boot", 1, 0), "adapter", "/", -1, None, None),
            "last_sequence",
        ),
        (lambda: Snapshot(1, -1, 0.0, ()), "generation"),
    ],
)
def test_model_bounds_and_command_replay_invariants(factory, match: str) -> None:
    with pytest.raises(ValueError, match=match):
        factory()


def test_shared_model_limits_match_protocol_plan() -> None:
    assert MAX_COMMAND_CHARS == 3_072
    assert MAX_PATH_CHARS == 768
    assert MAX_ID_CHARS == 128
    assert MAX_OUTCOME_MESSAGE_CHARS == 160
    assert MAX_DIAGNOSTIC_CHARS == 160
    assert MAX_ITEMS == 256


@pytest.mark.parametrize(
    ("factory", "match"),
    [
        (lambda: ProcessIdentity("b" * (MAX_ID_CHARS + 1), 1, 0), "boot_id exceeds"),
        (
            lambda: CommandRecord(
                1,
                "d" * (MAX_DIAGNOSTIC_CHARS + 1),
                None,
                CommandDisposition.REDACTED,
                False,
            ),
            "display exceeds",
        ),
        (
            lambda: CommandRecord(
                1,
                "display",
                "x" * (MAX_COMMAND_CHARS + 1),
                CommandDisposition.REPLAYABLE,
                True,
            ),
            "executable exceeds",
        ),
        (
            lambda: replace(sample_shell(), shell_id="s" * (MAX_ID_CHARS + 1)),
            "shell_id exceeds",
        ),
        (
            lambda: replace(sample_shell(), adapter="a" * (MAX_ID_CHARS + 1)),
            "adapter exceeds",
        ),
        (
            lambda: replace(sample_shell(), cwd="/" + "p" * MAX_PATH_CHARS),
            "cwd exceeds",
        ),
        (
            lambda: Outcome(
                "item-a", OutcomeKind.SUCCESS, "m" * (MAX_OUTCOME_MESSAGE_CHARS + 1)
            ),
            "message exceeds",
        ),
        (
            lambda: RecoveryItemRecord(
                "item-a", sample_shell(), "r" * (MAX_DIAGNOSTIC_CHARS + 1)
            ),
            "reason exceeds",
        ),
    ],
)
def test_direct_construction_rejects_oversized_strings(factory, match: str) -> None:
    with pytest.raises(ValueError, match=match):
        factory()


def test_non_redacted_command_display_uses_command_limit() -> None:
    command = CommandRecord(
        1,
        "d" * MAX_COMMAND_CHARS,
        None,
        CommandDisposition.UNSAFE,
        False,
    )
    assert len(command.display) == MAX_COMMAND_CHARS
    with pytest.raises(ValueError, match="display exceeds"):
        replace(command, display="d" * (MAX_COMMAND_CHARS + 1))


@pytest.mark.parametrize(
    "factory",
    [
        lambda: Snapshot(1, 0, 0.0, [sample_shell()] * (MAX_ITEMS + 1)),
        lambda: RecoveryRecord(
            1,
            "workspace-a",
            0,
            0.0,
            [RecoveryItemRecord(f"item-{index}", sample_shell(), "reason") for index in range(MAX_ITEMS + 1)],
            (),
            (),
        ),
        lambda: RestoreAttempt(
            "attempt-a", "workspace-a", [f"item-{index}" for index in range(MAX_ITEMS + 1)], (), ()
        ),
        lambda: RestoreAttempt(
            "attempt-a",
            "workspace-a",
            ("item-a",),
            (),
            [Outcome("item-a", OutcomeKind.FAILURE, "failed")] * (MAX_ITEMS + 1),
        ),
    ],
)
def test_direct_construction_rejects_oversized_lists_before_tuple_conversion(factory) -> None:
    with pytest.raises(ValueError, match="exceeds maximum items"):
        factory()


def test_snapshot_decoder_rejects_oversized_top_level_array() -> None:
    value = snapshot_to_dict(Snapshot(1, 0, 0.0, ()))
    value["shells"] = [None] * (MAX_ITEMS + 1)
    with pytest.raises(ValueError, match="shells exceeds maximum items"):
        snapshot_from_dict(value)


def test_recovery_decoder_rejects_oversized_nested_array() -> None:
    value = recovery_to_dict(sample_recovery())
    attempt = value["attempts"][0]
    assert isinstance(attempt, dict)
    attempt["approved_item_ids"] = ["item-a"] * (MAX_ITEMS + 1)
    with pytest.raises(ValueError, match="approved_item_ids exceeds maximum items"):
        recovery_from_dict(value)


def test_recovery_decoder_bounds_top_level_string_before_nested_content() -> None:
    value = recovery_to_dict(sample_recovery())
    value["workspace_id"] = "w" * (MAX_ID_CHARS + 1)
    value["items"] = [None]
    with pytest.raises(ValueError, match="workspace_id exceeds"):
        recovery_from_dict(value)


def test_recovery_decoder_rejects_oversized_nested_string() -> None:
    value = recovery_to_dict(sample_recovery())
    item = value["items"][0]
    assert isinstance(item, dict)
    shell = item["shell"]
    assert isinstance(shell, dict)
    shell["cwd"] = "/" + "p" * MAX_PATH_CHARS
    with pytest.raises(ValueError, match="cwd exceeds"):
        recovery_from_dict(value)


@pytest.mark.parametrize(
    ("field", "oversized", "match"),
    [
        ("shell_id", "s" * (MAX_ID_CHARS + 1), "shell_id exceeds"),
        ("adapter", "a" * (MAX_ID_CHARS + 1), "adapter exceeds"),
        ("cwd", "/" + "p" * MAX_PATH_CHARS, "cwd exceeds"),
    ],
)
def test_shell_decoder_rejects_parent_strings_before_malformed_identity(
    field: str, oversized: str, match: str
) -> None:
    value = snapshot_to_dict(Snapshot(1, 0, 0.0, (sample_shell(),)))
    shell = value["shells"][0]
    assert isinstance(shell, dict)
    shell[field] = oversized
    shell["identity"] = None
    with pytest.raises(ValueError, match=match):
        snapshot_from_dict(value)


def test_process_identity_decoder_rejects_boot_id_before_malformed_pid() -> None:
    value = snapshot_to_dict(Snapshot(1, 0, 0.0, (sample_shell(),)))
    shell = value["shells"][0]
    assert isinstance(shell, dict)
    identity = shell["identity"]
    assert isinstance(identity, dict)
    identity["boot_id"] = "b" * (MAX_ID_CHARS + 1)
    identity["pid"] = "malformed"
    with pytest.raises(ValueError, match="boot_id exceeds"):
        snapshot_from_dict(value)


@pytest.mark.parametrize(
    ("field", "oversized", "match"),
    [
        ("display", "d" * (MAX_COMMAND_CHARS + 1), "display exceeds"),
        ("executable", "x" * (MAX_COMMAND_CHARS + 1), "executable exceeds"),
        ("disposition", "u" * (MAX_ID_CHARS + 1), "command disposition exceeds"),
    ],
)
def test_command_decoder_rejects_strings_before_malformed_sequence(
    field: str, oversized: str, match: str
) -> None:
    command = CommandRecord(1, "unsafe", None, CommandDisposition.UNSAFE, False)
    value = snapshot_to_dict(Snapshot(1, 0, 0.0, (sample_shell(command=command),)))
    shell = value["shells"][0]
    assert isinstance(shell, dict)
    command_value = shell["command"]
    assert isinstance(command_value, dict)
    command_value[field] = oversized
    command_value["sequence"] = "malformed"
    with pytest.raises(ValueError, match=match):
        snapshot_from_dict(value)


@pytest.mark.parametrize(
    ("field", "match"),
    [("attempt_id", "attempt_id exceeds"), ("workspace_id", "workspace_id exceeds")],
)
def test_attempt_decoder_rejects_parent_strings_before_malformed_outcomes(
    field: str, match: str
) -> None:
    value = recovery_to_dict(sample_recovery())
    attempt = value["attempts"][0]
    assert isinstance(attempt, dict)
    attempt[field] = "a" * (MAX_ID_CHARS + 1)
    attempt["outcomes"] = [None]
    with pytest.raises(ValueError, match=match):
        recovery_from_dict(value)


@pytest.mark.parametrize(
    ("field", "oversized", "match"),
    [
        ("item_id", "i" * (MAX_ID_CHARS + 1), "item_id exceeds"),
        ("reason", "r" * (MAX_DIAGNOSTIC_CHARS + 1), "reason exceeds"),
    ],
)
def test_recovery_item_decoder_rejects_parent_strings_before_malformed_shell(
    field: str, oversized: str, match: str
) -> None:
    value = recovery_to_dict(sample_recovery())
    item = value["items"][0]
    assert isinstance(item, dict)
    item[field] = oversized
    item["shell"] = None
    with pytest.raises(ValueError, match=match):
        recovery_from_dict(value)


@pytest.mark.parametrize(
    ("field", "oversized", "match"),
    [
        ("item_id", "i" * (MAX_ID_CHARS + 1), "item_id exceeds"),
        ("message", "m" * (MAX_OUTCOME_MESSAGE_CHARS + 1), "message exceeds"),
    ],
)
def test_outcome_decoder_rejects_parent_strings_before_malformed_kind(
    field: str, oversized: str, match: str
) -> None:
    value = recovery_to_dict(sample_recovery())
    attempt = value["attempts"][0]
    assert isinstance(attempt, dict)
    outcome = attempt["outcomes"][0]
    assert isinstance(outcome, dict)
    outcome[field] = oversized
    outcome["kind"] = None
    with pytest.raises(ValueError, match=match):
        recovery_from_dict(value)


def test_attempt_decoder_rejects_list_item_string_before_nested_outcomes() -> None:
    value = recovery_to_dict(sample_recovery())
    attempt = value["attempts"][0]
    assert isinstance(attempt, dict)
    attempt["selected_item_ids"] = ["i" * (MAX_ID_CHARS + 1)]
    attempt["outcomes"] = [None]
    with pytest.raises(ValueError, match="selected item ID exceeds"):
        recovery_from_dict(value)


def test_snapshot_decoder_bounds_enum_strings_before_interpretation() -> None:
    command = CommandRecord(1, "unsafe", None, CommandDisposition.UNSAFE, False)
    value = snapshot_to_dict(Snapshot(1, 0, 0.0, (sample_shell(command=command),)))
    shell = value["shells"][0]
    assert isinstance(shell, dict)
    command_value = shell["command"]
    assert isinstance(command_value, dict)
    command_value["disposition"] = "x" * (MAX_ID_CHARS + 1)
    with pytest.raises(ValueError, match="command disposition exceeds"):
        snapshot_from_dict(value)


@pytest.mark.parametrize("timestamp", [float("nan"), float("inf"), float("-inf")])
def test_snapshot_rejects_non_finite_timestamp_in_construction_and_decoding(
    timestamp: float,
) -> None:
    with pytest.raises(ValueError, match="captured_at must be finite"):
        Snapshot(1, 0, timestamp, ())
    value = snapshot_to_dict(Snapshot(1, 0, 0.0, ()))
    value["captured_at"] = timestamp
    with pytest.raises(ValueError, match="captured_at must be finite"):
        snapshot_from_dict(value)


@pytest.mark.parametrize("timestamp", [float("nan"), float("inf"), float("-inf")])
def test_recovery_rejects_non_finite_timestamp_in_construction_and_decoding(
    timestamp: float,
) -> None:
    original = sample_recovery()
    with pytest.raises(ValueError, match="created_at must be finite"):
        replace(original, created_at=timestamp)
    value = recovery_to_dict(original)
    value["created_at"] = timestamp
    with pytest.raises(ValueError, match="created_at must be finite"):
        recovery_from_dict(value)


def test_recovery_schema_one_round_trip_and_exact_shape() -> None:
    original = sample_recovery()
    value = recovery_to_dict(original)
    assert value == {
        "schema_version": 1,
        "workspace_id": "workspace-a",
        "source_generation": 4,
        "created_at": 13.5,
        "items": [
            {
                "item_id": "item-a",
                "shell": {
                    "shell_id": "shell-aaaaaaaaaaa",
                    "identity": {
                        "boot_id": "11111111-1111-1111-1111-111111111111",
                        "pid": 42,
                        "start_time": 900,
                    },
                    "adapter": "gnome-terminal",
                    "cwd": "/srv/app",
                    "last_sequence": 7,
                    "command": {
                        "sequence": 3,
                        "display": "python -m http.server",
                        "executable": "python -m http.server",
                        "disposition": "replayable",
                        "active": True,
                    },
                    "termination": None,
                },
                "reason": "prior_boot",
            }
        ],
        "attempts": [
            {
                "attempt_id": "attempt-a",
                "workspace_id": "workspace-a",
                "selected_item_ids": ["item-a"],
                "approved_item_ids": ["item-a"],
                "outcomes": [
                    {"item_id": "item-a", "kind": "success", "message": "restored"}
                ],
            }
        ],
        "completed_item_ids": ["item-a"],
    }
    assert recovery_from_dict(value) == original


@pytest.mark.parametrize("version", [0, 2])
def test_non_schema_one_recovery_is_rejected_without_interpretation(version: int) -> None:
    with pytest.raises(
        ValueError,
        match=rf"unsupported schema version {version}; reader supports 1",
    ):
        recovery_from_dict({"schema_version": version})


def test_recovery_unknown_keys_are_rejected() -> None:
    value = recovery_to_dict(sample_recovery())
    value["unknown"] = True
    with pytest.raises(ValueError, match="unknown keys"):
        recovery_from_dict(value)


def test_recovery_rejects_duplicate_item_ids() -> None:
    original = sample_recovery()
    with pytest.raises(ValueError, match="duplicate recovery item ID"):
        RecoveryRecord(
            1,
            original.workspace_id,
            original.source_generation,
            original.created_at,
            (original.items[0], original.items[0]),
            original.attempts,
            original.completed_item_ids,
        )


def test_recovery_rejects_duplicate_attempt_ids_in_direct_construction() -> None:
    original = sample_recovery()
    with pytest.raises(ValueError, match="duplicate restore attempt ID"):
        replace(original, attempts=(original.attempts[0], original.attempts[0]))


def test_recovery_decoder_rejects_duplicate_attempt_ids() -> None:
    value = recovery_to_dict(sample_recovery())
    value["attempts"] = [value["attempts"][0], value["attempts"][0]]
    with pytest.raises(ValueError, match="duplicate restore attempt ID"):
        recovery_from_dict(value)


def test_recovery_rejects_duplicate_completed_ids() -> None:
    original = sample_recovery()
    with pytest.raises(ValueError, match="duplicate completed item ID"):
        RecoveryRecord(
            1,
            original.workspace_id,
            original.source_generation,
            original.created_at,
            original.items,
            original.attempts,
            ("item-a", "item-a"),
        )


def test_attempt_rejects_outcome_for_unselected_item() -> None:
    with pytest.raises(ValueError, match="outcome item must be selected"):
        RestoreAttempt(
            "attempt-a",
            "workspace-a",
            ("item-a",),
            (),
            (Outcome("item-b", OutcomeKind.FAILURE, "failed"),),
        )


def test_attempt_rejects_approval_outside_selection() -> None:
    with pytest.raises(ValueError, match="approved item must be selected"):
        RestoreAttempt(
            "attempt-a",
            "workspace-a",
            ("item-a",),
            ("item-b",),
            (),
        )


def test_completed_item_requires_terminal_success_or_warning_outcome() -> None:
    original = sample_recovery()
    failed_attempt = RestoreAttempt(
        "attempt-a",
        "workspace-a",
        ("item-a",),
        (),
        (Outcome("item-a", OutcomeKind.FAILURE, "failed"),),
    )
    with pytest.raises(ValueError, match="completed item lacks terminal outcome"):
        RecoveryRecord(
            1,
            original.workspace_id,
            original.source_generation,
            original.created_at,
            original.items,
            (failed_attempt,),
            ("item-a",),
        )
