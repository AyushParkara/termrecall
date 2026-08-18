# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import re
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from types import MappingProxyType

from termrecall.adapters.registry import SUPPORTED_ADAPTERS
from termrecall.classifier import classify_command
from termrecall.model import ProcessIdentity, ShellRecord, Snapshot, TerminationKind
from termrecall.protocol import EventRequest, Operation, RegisterRequest

_CAPABILITY_RE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")


@dataclass(frozen=True, slots=True)
class Registration:
    capability: str
    identity: ProcessIdentity
    last_sequence: int
    last_command_sequence: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.capability, str) or _CAPABILITY_RE.fullmatch(self.capability) is None:
            raise ValueError("invalid capability")
        if not isinstance(self.identity, ProcessIdentity):
            raise ValueError("invalid process identity")
        if isinstance(self.last_sequence, bool) or not isinstance(self.last_sequence, int):
            raise ValueError("last_sequence must be an integer")
        if self.last_sequence < 0:
            raise ValueError("last_sequence must be non-negative")
        if isinstance(self.last_command_sequence, bool) or not isinstance(
            self.last_command_sequence, int
        ):
            raise ValueError("last_command_sequence must be an integer")
        if self.last_command_sequence < 0:
            raise ValueError("last_command_sequence must be non-negative")


@dataclass(frozen=True, slots=True)
class EngineState:
    snapshot: Snapshot
    registrations: Mapping[str, Registration]
    dirty_generation: int

    def __post_init__(self) -> None:
        if not isinstance(self.snapshot, Snapshot):
            raise ValueError("invalid snapshot")
        if not isinstance(self.registrations, Mapping):
            raise ValueError("registrations must be a mapping")
        if isinstance(self.dirty_generation, bool) or not isinstance(self.dirty_generation, int):
            raise ValueError("dirty_generation must be an integer")
        if self.dirty_generation < 0:
            raise ValueError("dirty_generation must be non-negative")
        registrations = dict(self.registrations)
        if any(not isinstance(key, str) or not isinstance(value, Registration) for key, value in registrations.items()):
            raise ValueError("invalid registration")
        object.__setattr__(self, "registrations", MappingProxyType(registrations))


def register_shell(
    state: EngineState,
    request: RegisterRequest,
    capability_factory: Callable[[], str] = lambda: secrets.token_urlsafe(32),
    *,
    peer_pid: int | None = None,
) -> tuple[EngineState, str]:
    """Create an authoritative current shell registration."""
    if not isinstance(state, EngineState):
        raise ValueError("invalid engine state")
    if not isinstance(request, RegisterRequest):
        raise ValueError("invalid registration request")
    if request.sequence != 0:
        raise ValueError("registration sequence must be zero")
    if not isinstance(request.identity, ProcessIdentity):
        raise ValueError("invalid registration identity")
    if request.adapter not in SUPPORTED_ADAPTERS:
        raise ValueError("unsupported adapter")
    if peer_pid is not None and request.identity.pid != peer_pid:
        raise ValueError("identity does not match peer")

    # A re-registration of an existing shell_id is a reconnect (the peer_pid
    # check above already verifies the submitting process's real PID, so a
    # process cannot lie about its identity).  Rather than replacing the
    # registration wholesale, RECONCILE it: preserve the event/command
    # sequence watermarks so duplicate events replayed after the reconnect are
    # still rejected (finding #11).  A fresh capability is issued and any prior
    # explicit-exit termination is cleared so a recovered shell can resume.
    existing_registration = state.registrations.get(request.shell_id)
    existing_shell = None
    for candidate in state.snapshot.shells:
        if candidate.shell_id == request.shell_id:
            existing_shell = candidate
            break
    if existing_registration is not None:
        preserved_sequence = existing_shell.last_sequence if existing_shell else existing_registration.last_sequence
    else:
        preserved_sequence = request.sequence
    # Construct the ShellRecord (which validates shell_id/cwd) BEFORE minting a
    # capability so an invalid request is rejected without side effects.
    shell = ShellRecord(
        request.shell_id,
        request.identity,
        request.adapter,
        request.cwd,
        preserved_sequence,
        None,
        None,
    )
    capability = capability_factory()
    if any(
        existing.capability == capability
        for shell_id, existing in state.registrations.items()
        if shell_id != request.shell_id
    ):
        raise ValueError("capability collision")
    if existing_registration is not None:
        registration = Registration(
            capability,
            request.identity,
            existing_registration.last_sequence,
            existing_registration.last_command_sequence,
        )
    else:
        registration = Registration(capability, request.identity, request.sequence, 0)
    shells = _replace_or_append_shell(state.snapshot.shells, shell)
    registrations = dict(state.registrations)
    registrations[request.shell_id] = registration
    generation = state.dirty_generation + 1
    snapshot = replace(state.snapshot, generation=generation, shells=shells)
    return EngineState(snapshot, registrations, generation), capability


def apply_event(state: EngineState, request: EventRequest) -> EngineState:
    """Validate event authority and immutably reduce one lifecycle event."""
    if not isinstance(state, EngineState):
        raise ValueError("invalid engine state")
    if not isinstance(request, EventRequest):
        raise ValueError("invalid event request")

    registration = state.registrations.get(request.shell_id)
    if registration is None:
        raise ValueError("shell registration not found")
    if not secrets.compare_digest(registration.capability, request.capability):
        raise ValueError("event authority rejected")
    if registration.identity != request.identity:
        raise ValueError("event identity rejected")
    if request.sequence <= registration.last_sequence:
        raise ValueError("event sequence rejected")

    shell_index, shell = _find_shell(state.snapshot.shells, request.shell_id)
    if shell.termination is TerminationKind.EXPLICIT_EXIT:
        raise ValueError("shell registration terminated")
    updated_shell = _reduce_shell(shell, registration, request)
    updated_shell = replace(updated_shell, last_sequence=request.sequence)

    shells = list(state.snapshot.shells)
    shells[shell_index] = updated_shell
    registrations = dict(state.registrations)
    last_command_sequence = registration.last_command_sequence
    if request.operation is Operation.COMMAND_STARTED:
        assert request.command_sequence is not None
        last_command_sequence = request.command_sequence
    registrations[request.shell_id] = replace(
        registration,
        last_sequence=request.sequence,
        last_command_sequence=last_command_sequence,
    )
    generation = state.dirty_generation + 1
    snapshot = replace(state.snapshot, generation=generation, shells=tuple(shells))
    return EngineState(snapshot, registrations, generation)


def _reduce_shell(
    shell: ShellRecord, registration: Registration, request: EventRequest
) -> ShellRecord:
    if request.operation is Operation.COMMAND_STARTED:
        if request.command_sequence is None or request.command is None:
            raise ValueError("command start data missing")
        if request.command_sequence <= registration.last_command_sequence:
            raise ValueError("command sequence rejected")
        command = classify_command(request.command, request.command_sequence).record
        return replace(shell, command=command)

    if request.operation is Operation.COMMAND_FINISHED:
        if request.command_sequence is None:
            raise ValueError("command finish sequence missing")
        if shell.command is None or shell.command.sequence != request.command_sequence:
            raise ValueError("command sequence rejected")
        return replace(shell, command=None)

    if request.operation is Operation.PROMPT_READY:
        if request.cwd is None:
            raise ValueError("prompt directory missing")
        return replace(shell, cwd=request.cwd, command=None)

    if request.operation is Operation.CWD_CHANGED:
        if request.cwd is None:
            raise ValueError("working directory missing")
        return replace(shell, cwd=request.cwd)

    if request.operation is Operation.EXPLICIT_EXIT:
        return replace(shell, termination=TerminationKind.EXPLICIT_EXIT)

    raise ValueError("unsupported lifecycle operation")


def _find_shell(shells: object, shell_id: str) -> tuple[int, ShellRecord]:
    for index, shell in enumerate(shells):
        if shell.shell_id == shell_id:
            return index, shell
    raise ValueError("registered shell state not found")


def _replace_or_append_shell(
    shells: object, replacement: ShellRecord
) -> tuple[ShellRecord, ...]:
    updated = list(shells)
    for index, shell in enumerate(updated):
        if shell.shell_id == replacement.shell_id:
            updated[index] = replacement
            break
    else:
        updated.append(replacement)
    return tuple(updated)
