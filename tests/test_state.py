# SPDX-License-Identifier: GPL-3.0-or-later

from dataclasses import replace

import pytest

from termrecall.model import (
    CommandDisposition,
    ProcessIdentity,
    Snapshot,
    TerminationKind,
)
from termrecall.protocol import EventRequest, Operation, RegisterRequest
from termrecall.state import EngineState, Registration, apply_event, register_shell


IDENTITY = ProcessIdentity("123e4567-e89b-12d3-a456-426614174000", 1234, 5678)
CAPABILITY = "c" * 43


@pytest.fixture
def empty_state() -> EngineState:
    return EngineState(Snapshot(1, 0, 100.0, ()), {}, 0)


@pytest.fixture
def register_request() -> RegisterRequest:
    return RegisterRequest("shell-identifier-1", IDENTITY, "gnome-terminal", "/home/user", 0)


def event(
    operation: Operation,
    *,
    capability: str = CAPABILITY,
    identity: ProcessIdentity = IDENTITY,
    sequence: int = 1,
    cwd: str | None = None,
    command_sequence: int | None = None,
    command: str | None = None,
    exit_status: int | None = None,
) -> EventRequest:
    return EventRequest(
        operation,
        "shell-identifier-1",
        capability,
        identity,
        sequence,
        cwd,
        command_sequence,
        command,
        exit_status,
    )


def registered(empty_state: EngineState, register_request: RegisterRequest) -> EngineState:
    state, capability = register_shell(empty_state, register_request, lambda: CAPABILITY)
    assert capability == CAPABILITY
    return state


def test_three_argument_registration_defaults_command_watermark_to_zero() -> None:
    registration = Registration(CAPABILITY, IDENTITY, 7)

    assert registration.last_command_sequence == 0


def test_registration_creates_shell_and_capability_registry(
    empty_state: EngineState, register_request: RegisterRequest
) -> None:
    state, capability = register_shell(empty_state, register_request, lambda: CAPABILITY)

    assert capability == CAPABILITY
    assert state.dirty_generation == 1
    assert state.snapshot.generation == 1
    assert state.snapshot.shells[0].shell_id == register_request.shell_id
    assert state.snapshot.shells[0].cwd == register_request.cwd
    assert state.snapshot.shells[0].command is None
    assert state.snapshot.shells[0].termination is None
    assert state.registrations[register_request.shell_id].capability == CAPABILITY
    assert state.registrations[register_request.shell_id].last_sequence == 0
    assert state.registrations[register_request.shell_id].last_command_sequence == 0
    assert empty_state.snapshot.shells == ()
    assert empty_state.registrations == {}


def test_unsupported_adapter_registration_is_rejected_before_capability_or_mutation(
    empty_state: EngineState, register_request: RegisterRequest
) -> None:
    called = False

    def capability_factory() -> str:
        nonlocal called
        called = True
        return CAPABILITY

    with pytest.raises(ValueError, match="unsupported adapter"):
        register_shell(
            empty_state,
            replace(register_request, adapter="wezterm"),
            capability_factory,
        )

    assert not called
    assert empty_state.snapshot.shells == ()
    assert empty_state.registrations == {}
    assert empty_state.dirty_generation == 0


@pytest.mark.parametrize(
    "adapter", ["gnome-terminal", "kitty", "xfce4-terminal", "konsole"]
)
def test_each_supported_adapter_can_register(
    empty_state: EngineState, register_request: RegisterRequest, adapter: str
) -> None:
    state, capability = register_shell(
        empty_state,
        replace(register_request, adapter=adapter),
        lambda: CAPABILITY,
    )

    assert capability == CAPABILITY
    assert state.snapshot.shells[0].adapter == adapter
    assert state.registrations[register_request.shell_id].capability == CAPABILITY


def test_invalid_registration_is_rejected_before_capability_generation(
    empty_state: EngineState, register_request: RegisterRequest
) -> None:
    called = False

    def capability_factory() -> str:
        nonlocal called
        called = True
        return CAPABILITY

    with pytest.raises(ValueError, match="cwd"):
        register_shell(
            empty_state,
            replace(register_request, cwd="x" * 769),
            capability_factory,
        )

    assert not called
    assert empty_state.snapshot.shells == ()
    assert empty_state.registrations == {}
    assert empty_state.dirty_generation == 0


def test_register_shell_rejects_identity_pid_mismatch_with_peer_pid(
    empty_state: EngineState, register_request: RegisterRequest
) -> None:
    called = False

    def capability_factory() -> str:
        nonlocal called
        called = True
        return CAPABILITY

    with pytest.raises(ValueError, match="identity does not match peer"):
        register_shell(
            empty_state,
            register_request,
            capability_factory,
            peer_pid=9999,
        )

    assert not called
    assert empty_state.snapshot.shells == ()
    assert empty_state.registrations == {}
    assert empty_state.dirty_generation == 0


def test_register_shell_accepts_matching_peer_pid(
    empty_state: EngineState, register_request: RegisterRequest
) -> None:
    state, capability = register_shell(
        empty_state,
        register_request,
        lambda: CAPABILITY,
        peer_pid=IDENTITY.pid,
    )
    assert capability == CAPABILITY
    assert state.registrations[register_request.shell_id].identity == IDENTITY


def test_reregistration_is_complete_authoritative_current_state(
    empty_state: EngineState, register_request: RegisterRequest
) -> None:
    state = registered(empty_state, register_request)
    state = apply_event(
        state,
        event(
            Operation.COMMAND_STARTED,
            sequence=1,
            command_sequence=4,
            command="sleep 10",
        ),
    )
    new_identity = ProcessIdentity(IDENTITY.boot_id, 4321, 8765)
    replacement = replace(register_request, identity=new_identity, cwd="/tmp")

    state, capability = register_shell(state, replacement, lambda: "d" * 43)

    assert capability == "d" * 43
    assert len(state.snapshot.shells) == 1
    shell = state.snapshot.shells[0]
    assert shell.identity == new_identity
    assert shell.cwd == "/tmp"
    assert shell.last_sequence == 0
    assert shell.command is None
    assert shell.termination is None
    registration = state.registrations[shell.shell_id]
    assert registration.identity == new_identity
    assert registration.last_command_sequence == 0
    assert state.dirty_generation == 3

    state = apply_event(
        state,
        event(
            Operation.COMMAND_STARTED,
            capability="d" * 43,
            identity=new_identity,
            sequence=1,
            command_sequence=4,
            command="sleep 10",
        ),
    )
    assert state.snapshot.shells[0].command is not None
    assert state.snapshot.shells[0].command.sequence == 4
    assert state.registrations[shell.shell_id].last_command_sequence == 4


def test_command_finish_atomically_clears_replay_before_status(
    empty_state: EngineState, register_request: RegisterRequest
) -> None:
    state = registered(empty_state, register_request)
    state = apply_event(
        state,
        event(
            Operation.COMMAND_STARTED,
            sequence=1,
            command_sequence=8,
            command="python3 -m http.server",
        ),
    )
    assert state.snapshot.shells[0].command is not None
    assert state.snapshot.shells[0].command.disposition is CommandDisposition.REPLAYABLE
    assert state.snapshot.shells[0].command.active

    state = apply_event(
        state,
        event(
            Operation.COMMAND_FINISHED,
            sequence=2,
            command_sequence=8,
            exit_status=0,
        ),
    )

    assert state.snapshot.shells[0].command is None
    assert state.snapshot.shells[0].last_sequence == 2
    assert state.registrations["shell-identifier-1"].last_sequence == 2
    assert state.dirty_generation == 3


def test_finished_command_sequence_cannot_start_again_and_rejection_is_immutable(
    empty_state: EngineState, register_request: RegisterRequest
) -> None:
    state = registered(empty_state, register_request)
    state = apply_event(
        state,
        event(
            Operation.COMMAND_STARTED,
            sequence=1,
            command_sequence=8,
            command="sleep 10",
        ),
    )
    state = apply_event(
        state,
        event(
            Operation.COMMAND_FINISHED,
            sequence=2,
            command_sequence=8,
            exit_status=0,
        ),
    )
    snapshot = state.snapshot
    registration = state.registrations["shell-identifier-1"]
    dirty_generation = state.dirty_generation

    with pytest.raises(ValueError, match="command sequence"):
        apply_event(
            state,
            event(
                Operation.COMMAND_STARTED,
                sequence=3,
                command_sequence=8,
                command="python3 -m http.server",
            ),
        )

    assert state.snapshot is snapshot
    assert state.registrations["shell-identifier-1"] is registration
    assert registration.last_command_sequence == 8
    assert state.dirty_generation == dirty_generation


def test_prompt_cleared_command_rejects_older_sequence_without_mutation(
    empty_state: EngineState, register_request: RegisterRequest
) -> None:
    state = registered(empty_state, register_request)
    state = apply_event(
        state,
        event(
            Operation.COMMAND_STARTED,
            sequence=1,
            command_sequence=8,
            command="sleep 10",
        ),
    )
    state = apply_event(
        state,
        event(Operation.PROMPT_READY, sequence=2, cwd="/home/user/project"),
    )
    snapshot = state.snapshot
    registration = state.registrations["shell-identifier-1"]
    dirty_generation = state.dirty_generation

    with pytest.raises(ValueError, match="command sequence"):
        apply_event(
            state,
            event(
                Operation.COMMAND_STARTED,
                sequence=3,
                command_sequence=7,
                command="python3 -m http.server",
            ),
        )

    assert state.snapshot is snapshot
    assert state.snapshot.shells[0].command is None
    assert state.registrations["shell-identifier-1"] is registration
    assert registration.last_command_sequence == 8
    assert state.dirty_generation == dirty_generation


def test_prompt_ready_updates_cwd_and_defensively_clears_stale_command(
    empty_state: EngineState, register_request: RegisterRequest
) -> None:
    state = registered(empty_state, register_request)
    state = apply_event(
        state,
        event(
            Operation.COMMAND_STARTED,
            sequence=1,
            command_sequence=1,
            command="sleep 10",
        ),
    )

    state = apply_event(
        state,
        event(Operation.PROMPT_READY, sequence=2, cwd="/home/user/project"),
    )

    assert state.snapshot.shells[0].cwd == "/home/user/project"
    assert state.snapshot.shells[0].command is None


def test_cwd_changed_updates_directory_without_clearing_active_command(
    empty_state: EngineState, register_request: RegisterRequest
) -> None:
    state = registered(empty_state, register_request)
    state = apply_event(
        state,
        event(
            Operation.COMMAND_STARTED,
            sequence=1,
            command_sequence=1,
            command="sleep 10",
        ),
    )

    state = apply_event(
        state, event(Operation.CWD_CHANGED, sequence=2, cwd="/home/user/project")
    )

    assert state.snapshot.shells[0].cwd == "/home/user/project"
    assert state.snapshot.shells[0].command is not None


def test_explicit_exit_marks_shell_termination(
    empty_state: EngineState, register_request: RegisterRequest
) -> None:
    state = registered(empty_state, register_request)

    state = apply_event(state, event(Operation.EXPLICIT_EXIT, sequence=1))

    assert state.snapshot.shells[0].termination is TerminationKind.EXPLICIT_EXIT


def test_absence_of_explicit_exit_remains_ambiguous_for_later_reconciliation(
    empty_state: EngineState, register_request: RegisterRequest
) -> None:
    state = registered(empty_state, register_request)
    state = apply_event(
        state, event(Operation.CWD_CHANGED, sequence=1, cwd="/home/user/project")
    )

    assert state.snapshot.shells[0].termination is None


def test_new_active_command_sequence_replaces_older_candidate(
    empty_state: EngineState, register_request: RegisterRequest
) -> None:
    state = registered(empty_state, register_request)
    state = apply_event(
        state,
        event(
            Operation.COMMAND_STARTED,
            sequence=1,
            command_sequence=7,
            command="sleep 10",
        ),
    )

    state = apply_event(
        state,
        event(
            Operation.COMMAND_STARTED,
            sequence=2,
            command_sequence=8,
            command="python3 -m http.server",
        ),
    )

    assert state.snapshot.shells[0].command is not None
    assert state.snapshot.shells[0].command.sequence == 8
    assert state.snapshot.shells[0].command.executable == "python3 -m http.server"


def test_finish_for_another_command_sequence_is_rejected_without_mutation(
    empty_state: EngineState, register_request: RegisterRequest
) -> None:
    state = registered(empty_state, register_request)
    state = apply_event(
        state,
        event(
            Operation.COMMAND_STARTED,
            sequence=1,
            command_sequence=7,
            command="sleep 10",
        ),
    )
    original = state

    with pytest.raises(ValueError, match="command sequence"):
        apply_event(
            state,
            event(
                Operation.COMMAND_FINISHED,
                sequence=2,
                command_sequence=8,
                exit_status=0,
            ),
        )

    assert state is original
    assert state.snapshot.shells[0].command is not None
    assert state.snapshot.shells[0].command.sequence == 7
    assert state.registrations["shell-identifier-1"].last_sequence == 1


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"capability": "x" * 43}, "authority"),
        ({"identity": ProcessIdentity(IDENTITY.boot_id, 9999, 5678)}, "identity"),
        ({"sequence": 1}, "sequence"),
        ({"sequence": 0}, "sequence"),
    ],
    ids=["wrong-capability", "wrong-identity", "duplicate-sequence", "older-sequence"],
)
def test_invalid_authority_or_order_is_rejected_without_mutation(
    empty_state: EngineState,
    register_request: RegisterRequest,
    change: dict[str, object],
    message: str,
) -> None:
    state = registered(empty_state, register_request)
    state = apply_event(
        state, event(Operation.CWD_CHANGED, sequence=1, cwd="/home/user/project")
    )
    invalid = replace(
        event(Operation.CWD_CHANGED, sequence=2, cwd="/tmp"), **change
    )
    original = state

    with pytest.raises(ValueError, match=message):
        apply_event(state, invalid)

    assert state is original
    assert state.snapshot.shells[0].cwd == "/home/user/project"
    assert state.registrations["shell-identifier-1"].last_sequence == 1
    assert state.dirty_generation == 2


@pytest.mark.parametrize(
    "subsequent",
    [
        event(Operation.COMMAND_STARTED, sequence=2, command_sequence=1, command="sleep 10"),
        event(Operation.PROMPT_READY, sequence=2, cwd="/tmp"),
        event(Operation.CWD_CHANGED, sequence=2, cwd="/tmp"),
        event(Operation.COMMAND_FINISHED, sequence=2, command_sequence=1, exit_status=0),
        event(Operation.EXPLICIT_EXIT, sequence=2),
    ],
    ids=("command-started", "prompt-ready", "cwd-changed", "command-finished", "explicit-exit"),
)
def test_explicit_exit_is_terminal_for_registration_without_mutation(
    empty_state: EngineState,
    register_request: RegisterRequest,
    subsequent: EventRequest,
) -> None:
    exited = apply_event(
        registered(empty_state, register_request),
        event(Operation.EXPLICIT_EXIT, sequence=1),
    )
    original = exited

    with pytest.raises(ValueError, match="registration terminated"):
        apply_event(exited, subsequent)

    assert exited is original
    assert exited.snapshot.shells[0].termination is TerminationKind.EXPLICIT_EXIT
    assert exited.registrations[register_request.shell_id].last_sequence == 1
    assert exited.dirty_generation == 2


def test_reregistration_resets_explicit_exit_finality(
    empty_state: EngineState, register_request: RegisterRequest
) -> None:
    exited = apply_event(
        registered(empty_state, register_request),
        event(Operation.EXPLICIT_EXIT, sequence=1),
    )
    current, new_capability = register_shell(
        exited,
        replace(register_request, cwd="/new"),
        lambda: "n" * 43,
    )

    assert new_capability == "n" * 43
    assert current.snapshot.shells[0].termination is None
    assert current.snapshot.shells[0].cwd == "/new"
    assert current.registrations[register_request.shell_id].last_sequence == 0


def test_unknown_shell_is_rejected_without_mutation(empty_state: EngineState) -> None:
    with pytest.raises(ValueError, match="registration"):
        apply_event(empty_state, event(Operation.EXPLICIT_EXIT))

    assert empty_state.snapshot.shells == ()
    assert empty_state.dirty_generation == 0


def test_completed_command_cannot_become_replayable(
    empty_state: EngineState, register_request: RegisterRequest
) -> None:
    state = registered(empty_state, register_request)
    state = apply_event(
        state,
        event(
            Operation.COMMAND_STARTED,
            sequence=1,
            command_sequence=1,
            command="python3 -m http.server",
        ),
    )
    state = apply_event(
        state,
        event(
            Operation.COMMAND_FINISHED,
            sequence=2,
            command_sequence=1,
            exit_status=0,
        ),
    )

    assert state.snapshot.shells[0].command is None
