# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
from collections.abc import Callable, Set as AbstractSet, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path

from termrecall.adapters.base import LaunchAction, LaunchItem, TerminalAdapter
from termrecall.adapters.registry import SUPPORTED_ADAPTERS
from termrecall.adapters.resume import build_resume_argv, find_resume_adapter
from termrecall.classifier import _parse_one_simple_command
from termrecall.model import (
    CommandDisposition,
    RecoveryItemRecord,
    RecoveryRecord,
    RestorationLevel,
    RestoreAttempt,
    SCHEMA_VERSION,
    ShellRecord,
    Snapshot,
)
from termrecall.processes import ProcessProbe, ProcessStatus
from termrecall.protocol import SafeExternalText


class RecoveryReason(StrEnum):
    PREVIOUS_BOOT = "previous_boot"
    SAME_BOOT_DEAD = "same_boot_dead"
    EXPLICIT_EXIT = "explicit_exit"
    STILL_ALIVE = "still_alive"
    PROCESS_UNKNOWN = "process_unknown"


_SAFE_RECOVERY_REASONS = {
    RecoveryReason.PREVIOUS_BOOT: "previous_boot",
    RecoveryReason.SAME_BOOT_DEAD: "same_boot_dead",
    RecoveryReason.EXPLICIT_EXIT: "explicit_exit",
    RecoveryReason.STILL_ALIVE: "still_alive",
    RecoveryReason.PROCESS_UNKNOWN: "process_unknown",
}
assert set(_SAFE_RECOVERY_REASONS) == set(RecoveryReason)
assert {value for value in _SAFE_RECOVERY_REASONS.values()} == {
    reason.value for reason in RecoveryReason
}


def safe_recovery_reason(reason: RecoveryReason) -> SafeExternalText:
    if not isinstance(reason, RecoveryReason):
        raise TypeError("recovery reason provenance requires RecoveryReason")
    return SafeExternalText.catalog(_SAFE_RECOVERY_REASONS[reason])


@dataclass(frozen=True, slots=True)
class RecoveryItem:
    item_id: str
    shell: ShellRecord
    reason: RecoveryReason
    level: RestorationLevel
    directory: Path
    directory_warning: str | None
    replay_display: str | None
    replay_eligible: bool


@dataclass(frozen=True, slots=True)
class RecoveryWorkspace:
    workspace_id: str
    items: Sequence[RecoveryItem]
    diagnostics: Sequence[str]

    def __post_init__(self) -> None:
        object.__setattr__(self, "items", tuple(self.items))
        object.__setattr__(self, "diagnostics", tuple(self.diagnostics))


def reconcile(
    snapshot: Snapshot,
    current_boot_id: str,
    probe: Callable[[object], ProcessProbe],
    home: Path,
    *,
    directory_resolver: Callable[[Path, Path], tuple[Path, str | None]] | None = None,
) -> RecoveryWorkspace | None:
    candidates: list[tuple[ShellRecord, RecoveryReason]] = []
    diagnostics: list[str] = []
    for shell in sorted(snapshot.shells, key=lambda item: item.shell_id):
        if shell.termination is not None and shell.termination.value == RecoveryReason.EXPLICIT_EXIT.value:
            continue
        if shell.identity.boot_id != current_boot_id:
            candidates.append((shell, RecoveryReason.PREVIOUS_BOOT))
            continue
        result = probe(shell.identity)
        if result.status is ProcessStatus.DEAD:
            candidates.append((shell, RecoveryReason.SAME_BOOT_DEAD))
        elif result.status is ProcessStatus.UNKNOWN:
            diagnostics.append(
                f"process status unknown for shell {shell.shell_id}; not recoverable"
            )

    if not candidates and not diagnostics:
        return None

    identity = {
        "generation": snapshot.generation,
        "items": [
            {
                "shell_id": shell.shell_id,
                "boot_id": shell.identity.boot_id,
                "pid": shell.identity.pid,
                "start_time": shell.identity.start_time,
                "reason": reason.value,
            }
            for shell, reason in candidates
        ],
    }
    workspace_id = hashlib.sha256(_canonical_json(identity)).hexdigest()[:24]
    items: list[RecoveryItem] = []
    resolve = directory_resolver or resolve_directory
    for shell, reason in candidates:
        directory, warning = resolve(Path(shell.cwd), home)
        command = shell.command
        supported = shell.adapter in SUPPORTED_ADAPTERS
        eligible = bool(
            supported
            and command is not None
            and command.active
            and command.disposition is CommandDisposition.REPLAYABLE
            and command.executable is not None
        )
        items.append(
            RecoveryItem(
                item_id=shell.shell_id,
                shell=shell,
                reason=reason,
                level=(
                    RestorationLevel.UNAVAILABLE
                    if not supported
                    else RestorationLevel.RECONSTRUCTED
                    if eligible
                    else RestorationLevel.PARTIAL
                ),
                directory=directory,
                directory_warning=warning,
                replay_display=command.display if command is not None else None,
                replay_eligible=eligible,
            )
        )
    return RecoveryWorkspace(workspace_id, tuple(items), tuple(diagnostics))


def resolve_directory(recorded: Path, home: Path) -> tuple[Path, str | None]:
    recorded = Path(recorded)
    home = Path(home)
    candidate = recorded
    while True:
        if _usable_directory(candidate):
            if candidate == recorded:
                return candidate, None
            return candidate, f"{recorded} missing; using {candidate}"
        parent = candidate.parent
        if parent == candidate:
            break
        candidate = parent
    if not _usable_directory(home):
        raise ValueError("home directory is not usable")
    return home, f"{recorded} missing; using {home}"


def _usable_directory(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode) and os.access(
        path, os.R_OK | os.X_OK
    )


def record_from_workspace(workspace: RecoveryWorkspace, snapshot: Snapshot) -> RecoveryRecord:
    return RecoveryRecord(
        SCHEMA_VERSION,
        workspace.workspace_id,
        snapshot.generation,
        snapshot.captured_at,
        tuple(
            RecoveryItemRecord(item.item_id, item.shell, item.reason.value)
            for item in workspace.items
        ),
        (),
        (),
    )


def workspace_from_record(record: RecoveryRecord, home: Path) -> RecoveryWorkspace:
    items: list[RecoveryItem] = []
    for stored in sorted(record.items, key=lambda item: item.item_id):
        directory, warning = resolve_directory(Path(stored.shell.cwd), home)
        command = stored.shell.command
        supported = stored.shell.adapter in SUPPORTED_ADAPTERS
        eligible = bool(
            supported
            and command is not None
            and command.active
            and command.disposition is CommandDisposition.REPLAYABLE
            and command.executable is not None
        )
        try:
            reason = RecoveryReason(stored.reason)
        except ValueError:
            reason = RecoveryReason.PREVIOUS_BOOT if stored.reason == "prior_boot" else RecoveryReason.PROCESS_UNKNOWN
        level = (
            RestorationLevel.UNAVAILABLE
            if not supported
            else RestorationLevel.RECONSTRUCTED
            if eligible
            else RestorationLevel.PARTIAL
        )
        items.append(
            RecoveryItem(
                stored.item_id,
                stored.shell,
                reason,
                level,
                directory,
                warning,
                command.display if command else None,
                eligible,
            )
        )
    return RecoveryWorkspace(record.workspace_id, tuple(items), ())


def derive_attempt_id(
    workspace_id: str,
    selected_item_ids: Sequence[str],
    approved_item_ids: AbstractSet[str],
    adapter: TerminalAdapter,
    *,
    source_attempt_id: str | None = None,
) -> str:
    identity: dict[str, object] = {
        "workspace_id": workspace_id,
        "selected_item_ids": sorted(selected_item_ids),
        "approved_item_ids": sorted(approved_item_ids),
        "adapter": getattr(adapter, "name", adapter.__class__.__name__),
    }
    if source_attempt_id is not None:
        identity["source_attempt_id"] = source_attempt_id
    return hashlib.sha256(_canonical_json(identity)).hexdigest()[:24]


def build_attempt(
    record: RecoveryRecord,
    selected_item_ids: Sequence[str],
    approved_item_ids: AbstractSet[str],
    adapter: TerminalAdapter,
    executable_resolver: Callable[[str], str | None] = shutil.which,
    *,
    source_attempt_id: str | None = None,
    home: Path | None = None,
) -> tuple[RestoreAttempt, Sequence[LaunchAction]]:
    selected = tuple(selected_item_ids)
    approved = frozenset(approved_item_ids)
    item_by_id = {item.item_id: item for item in record.items}
    launches: list[LaunchItem] = []
    missing_executable: set[str] = set()
    unsupported_adapter: set[str] = set()
    for item_id in selected:
        stored = item_by_id[item_id]
        if stored.shell.adapter not in SUPPORTED_ADAPTERS:
            unsupported_adapter.add(item_id)
            continue
        command = stored.shell.command
        approved_command: str | None = None
        if item_id in approved and command is not None and command.active:
            # First, try the session-resume path: if the captured launch
            # command is a recognized session-persistent tool (codex, opencode,
            # pi, hermes, ...), substitute the tool's native resume argv.  The
            # resume argv is a fixed, hand-verified argv (never reconstructed
            # from user input) so it bypasses the replay-classifier expansion
            # surface; resume relies on the tool's own cwd-keyed session lookup.
            executable_name: str | None = None
            captured_text = command.executable if command.executable else command.display
            if captured_text:
                try:
                    parsed_for_resume = _parse_one_simple_command(captured_text)
                    executable_name = parsed_for_resume.executable
                except ValueError:
                    executable_name = None
            resume_adapter = find_resume_adapter(executable_name) if executable_name else None
            if resume_adapter is not None:
                # Resolve the exact session id for deterministic resume: prefer
                # a live env var (e.g. CODEX_SESSION_ID for the current process),
                # then fall back to the most-recent session the tool recorded in
                # this cwd (handles the multi-session case deterministically).
                session_id: str | None = None
                try:
                    from termrecall.sessions import find_active_session_id, find_sessions_for_cwd
                    session_id = find_active_session_id(resume_adapter.executable)
                    if session_id is None:
                        matches = find_sessions_for_cwd(str(directory) if directory else str(Path(stored.shell.cwd)))
                        session_id = matches[0].session_id if matches else None
                except Exception:
                    session_id = None
                resume_argv = build_resume_argv(resume_adapter, session_id)
                resume_executable = resume_argv[0] if resume_argv else None
                if resume_executable and executable_resolver(resume_executable) is None:
                    missing_executable.add(item_id)
                else:
                    approved_command = " ".join(resume_argv)
            elif (
                command.disposition is CommandDisposition.REPLAYABLE
                and command.executable is not None
            ):
                # Plain replayable command: use the same canonical ParsedCommand
                # representation the classifier produces so classification and
                # replay agree on what the executable is.
                try:
                    parsed = _parse_one_simple_command(command.executable)
                except ValueError:
                    parsed = None
                if (
                    parsed is None
                    or not parsed.executable
                    or executable_resolver(parsed.executable) is None
                ):
                    missing_executable.add(item_id)
                else:
                    approved_command = command.executable
        directory, _ = resolve_directory(Path(stored.shell.cwd), home or Path.home())
        launches.append(LaunchItem(item_id, directory, approved_command))

    attempt_id = derive_attempt_id(
        record.workspace_id,
        selected,
        approved,
        adapter,
        source_attempt_id=source_attempt_id,
    )
    attempt = RestoreAttempt(attempt_id, record.workspace_id, selected, tuple(sorted(approved)), ())
    actions = tuple(adapter.plan(tuple(launches)))
    actions = (
        *actions,
        *(
            LaunchAction(
                (item_id,),
                (),
                RestorationLevel.UNAVAILABLE,
                ("unsupported adapter",),
            )
            for item_id in selected
            if item_id in unsupported_adapter
        ),
    )
    if missing_executable:
        actions = tuple(
            replace(
                action,
                warnings=(*action.warnings, "executable unavailable"),
            )
            if set(action.item_ids) & missing_executable
            else action
            for action in actions
        )
    return attempt, actions


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
