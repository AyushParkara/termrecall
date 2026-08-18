# SPDX-License-Identifier: GPL-3.0-or-later
"""Resume adapters for session-persistent agent tools.

Many long-running developer tools (codex, opencode, pi, hermes) keep their
conversation/state on disk and expose a native ``resume``/``continue`` command.
TermRecall captures the *launch* command of such a tool, but re-running the
launch argv on restore would start a fresh session with no memory of the prior
work.  Resume adapters solve this: for a recognized tool, the restore path
substitutes the tool's *resume* command (a fixed, safe argv that reconnects to
the persisted session) instead of replaying the original launch.

Each resume command is an explicit, hand-verified argv (never reconstructed
from user input), so it does not re-enter the classifier's expansion/glob/env
attack surface.  Resume relies on the tool's own cwd-keyed session lookup: the
adapter launches the resume command in the recorded working directory, and the
tool resolves the matching session itself.  An optional ``session_id`` may be
attached when TermRecall captured it, but cwd disambiguation is the primary
mechanism so resume still works for sessions begun before installation.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ResumeAdapter:
    """Maps a captured tool launch to its native resume argv."""

    # The executable name(s) this adapter recognizes (last path component,
    # lower-cased), matching the classifier's ``ParsedCommand.executable``.
    executables: frozenset[str]
    # A human-readable tool name for diagnostics.
    name: str
    # The resume argv template.  ``{session_id}`` is substituted when a session
    # id was captured; otherwise the command is used as-is and relies on the
    # tool's cwd-filtered "most recent" selection.
    resume_argv: tuple[str, ...]
    # ``True`` when the resume_argv contains a ``{session_id}`` placeholder that
    # must be substituted (and is required) before replay.
    requires_session_id: bool = False
    # A fallback resume argv used when no session id was captured.  When this is
    # ``None`` and no session id is available, resume falls back to cwd-only
    # selection using ``resume_argv`` directly.
    fallback_argv: tuple[str, ...] | None = None


# Each resume argv below was verified against the tool's own ``--help`` output
# on 2026-08-18.  The tools cwd-filter by default, so launching the resume
# command in the recorded working directory selects the right session.
_RESUME_ADAPTERS: tuple[ResumeAdapter, ...] = (
    ResumeAdapter(
        executables=frozenset({"codex"}),
        name="codex",
        # ``codex resume --last`` continues the most recent session for the
        # current cwd.  ``codex resume <id>`` is used when a session id is known.
        resume_argv=("codex", "resume", "{session_id}"),
        requires_session_id=False,
        fallback_argv=("codex", "resume", "--last"),
    ),
    ResumeAdapter(
        executables=frozenset({"opencode"}),
        name="opencode",
        # opencode stores sessions per-project and restores the most recent for
        # the cwd when launched with no subcommand (its default TUI).  An
        # explicit session id is not exposed via a stable resume flag, so we
        # rely on cwd-keyed restoration.
        resume_argv=("opencode",),
        requires_session_id=False,
        fallback_argv=("opencode",),
    ),
    ResumeAdapter(
        executables=frozenset({"pi"}),
        name="pi",
        # ``pi --continue`` continues the previous session for the cwd.
        # ``pi --session <id>`` resumes a specific session when captured.
        resume_argv=("pi", "--session", "{session_id}"),
        requires_session_id=False,
        fallback_argv=("pi", "--continue"),
    ),
    ResumeAdapter(
        executables=frozenset({"hermes"}),
        name="hermes",
        # ``hermes --resume <session>`` resumes a named/recorded session.
        # Without a session id, ``hermes --continue`` resumes the last session.
        resume_argv=("hermes", "--resume", "{session_id}"),
        requires_session_id=False,
        fallback_argv=("hermes", "--continue"),
    ),
)

_RESUME_BY_EXECUTABLE: Mapping[str, ResumeAdapter] = {
    exe: adapter for adapter in _RESUME_ADAPTERS for exe in adapter.executables
}


def find_resume_adapter(executable: str) -> ResumeAdapter | None:
    """Return the resume adapter for ``executable`` (lower-cased name), or None."""
    if not executable:
        return None
    return _RESUME_BY_EXECUTABLE.get(executable)


def build_resume_argv(adapter: ResumeAdapter, session_id: str | None) -> tuple[str, ...]:
    """Resolve the concrete resume argv for ``adapter``.

    When ``session_id`` is available and the adapter's template carries a
    ``{session_id}`` placeholder, substitute it.  Otherwise fall back to the
    adapter's cwd-only selection argv.  Raises ``ValueError`` if a session id is
    required but unavailable (no adapter currently sets ``requires_session_id``).
    """
    if adapter.requires_session_id and not session_id:
        raise ValueError(f"{adapter.name} resume requires a session id")
    if "{session_id}" in adapter.resume_argv:
        if session_id:
            return tuple(part.replace("{session_id}", session_id) for part in adapter.resume_argv)
        return adapter.fallback_argv or adapter.resume_argv
    if session_id and adapter.fallback_argv is not None:
        return adapter.fallback_argv
    return adapter.resume_argv
