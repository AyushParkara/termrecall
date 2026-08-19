# SPDX-License-Identifier: GPL-3.0-or-later
"""Universal session-resume engine.

TermRecall captures the *launch* command of a long-running tool, but re-running
the launch argv on restore would start a fresh session with no memory.  Many
developer tools (codex, opencode, pi, hermes, and any tool following the same
conventions) keep their conversation/state on disk and expose a native
``resume``/``continue`` command that reconnects to the persisted session.

This engine is deliberately universal rather than a hard-coded per-tool list:

1. A *declarative convention registry* maps resume conventions (subcommand
   forms, flag forms) to safe resume-argv builders.  Adding a tool that follows
   a known convention is a one-line data entry, not new code.
2. A *convention probe* introspects an unrecognized tool's own ``--help`` output
   to discover its resume capability, so tools TermRecall has never heard of
   (and future tools) resume correctly without registration.

All resume argv are built from an explicit allowlist of literal tokens, so they
never re-enter the classifier's expansion/glob/env attack surface.  Resume relies
on the tool's own cwd-keyed session lookup: the adapter launches the resume
command in the recorded working directory, and the tool resolves the matching
session itself.  An optional captured ``session_id`` may be substituted when the
tool supports a ``{session_id}`` placeholder, but cwd disambiguation is the
primary mechanism so resume still works for sessions begun before installation.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol


# ---------------------------------------------------------------------------
# Safe-token guard
# ---------------------------------------------------------------------------

# A resume argv is built entirely from these literal tokens.  Any token that is
# not an allowlisted literal, a known long/short flag, or the executable name is
# rejected so user-controlled text can never reach the replay layer.
_SAFE_RESUME_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+:=-]*$")


def _is_safe_token(token: str) -> bool:
    """A resume token must be a safe literal (no shell metacharacters)."""
    if not token:
        return False
    if token in _RESERVED_FLAG_LITERALS:
        return True
    if token.startswith("--") and _SAFE_RESUME_TOKEN_RE.match(token):
        return True
    return bool(_SAFE_RESUME_TOKEN_RE.match(token))


# ---------------------------------------------------------------------------
# Convention contracts
# ---------------------------------------------------------------------------


class ExecutableResolver(Protocol):
    def __call__(self, name: str) -> str | None: ...


@dataclass(frozen=True, slots=True)
class ResumeContract:
    """A declarative resume convention shared by many tools.

    Each contract describes how to detect a tool that follows it and how to
    build the resume argv.  Detection is by executable name (for registered
    tools) or by probing the tool's ``--help`` for the convention's signature
    tokens (for unknown tools).
    """

    # Short human-readable id, e.g. ``resume-subcommand``.
    name: str
    # Tokens whose presence in ``<exe> --help`` output indicates the tool
    # follows this convention.  Matched case-insensitively as whole words.
    help_signature: tuple[str, ...]
    # Resume argv with cwd-only selection (no session id).  ``{exe}`` is
    # substituted with the executable name; ``{session_id}`` is substituted
    # when a session id is available and the tool supports it.
    resume_argv: tuple[str, ...]
    # Same shape with an explicit session id, when the tool supports one.
    # ``None`` means the tool has no session-id form (cwd-only resume).
    with_session_id: tuple[str, ...] | None = None

    def supports_session_id(self) -> bool:
        return self.with_session_id is not None

    def build(self, executable: str, session_id: str | None) -> tuple[str, ...]:
        template = self.resume_argv
        if session_id and self.with_session_id is not None:
            template = self.with_session_id
        argv = tuple(part.replace("{exe}", executable) for part in template)
        if "{session_id}" in " ".join(argv):
            if session_id is None:
                # No session id captured: keep the cwd-only template (which must
                # not itself contain the placeholder).
                argv = tuple(part.replace("{exe}", executable) for part in self.resume_argv)
                if "{session_id}" in " ".join(argv):
                    raise ValueError(f"{self.name} requires a session id but none was captured")
            else:
                argv = tuple(part.replace("{session_id}", session_id) for part in argv)
        # Safety: every token must pass the literal guard.
        bad = [t for t in argv if not _is_safe_token(t)]
        if bad:
            raise ValueError(f"{self.name} resume argv has unsafe tokens: {bad}")
        return argv


# Reserved flag literals that appear in resume argv.  Kept explicit so the safe-
# token guard recognises them even if they contain characters outside the bare
# literal pattern.
_RESERVED_FLAG_LITERALS = frozenset({
    "resume", "--last", "--continue", "--resume", "--session",
    "--attach", "--all", "-c", "-r",
})


# The convention registry.  Adding a new convention (or a tool that follows an
# existing one) is a data entry here, not new code.  Order matters only for the
# probe: more-specific conventions should come first.
_CONTRACTS: tuple[ResumeContract, ...] = (
    # ``<exe> --continue`` — the most widely supported "resume last session"
    # form (pi, hermes, opencode).  Preferred because it is a flag, not a
    # subcommand, and tools that expose it resume the most-recent session for
    # the current cwd without an interactive picker.
    ResumeContract(
        name="continue-flag",
        help_signature=("--continue",),
        resume_argv=("{exe}", "--continue"),
        # pi/hermes/opencode expose ``--session``/``-s`` for a specific id.
        with_session_id=("{exe}", "--session", "{session_id}"),
    ),
    # ``<exe> resume [--last|<id>]`` — codex and any tool with a resume
    # SUBCOMMAND.  Detected as the token ``resume`` starting an indented help
    # line (a listed command), not a prose mention.
    ResumeContract(
        name="resume-subcommand",
        help_signature=("resume",),
        resume_argv=("{exe}", "resume", "--last"),
        with_session_id=("{exe}", "resume", "{session_id}"),
    ),
    # ``<exe> --resume [<id>]`` — flag form (hermes -r, pi -r as a picker).
    ResumeContract(
        name="resume-flag",
        help_signature=("--resume",),
        resume_argv=("{exe}", "--resume"),
        with_session_id=("{exe}", "--resume", "{session_id}"),
    ),
)


# Executable-name overrides: when a tool's help matches multiple conventions or
# uses a non-obvious form, pin it to one contract by name.  Empty by default;
# the probe resolves everything else.
_EXECUTABLE_OVERRIDES: Mapping[str, str] = {}


# Executables that must never get a resume probe (shells, editors, coreutils).
# These are not session-persistent agent tools; probing their --help is wasted
# work and could misclassify (e.g. ``bash --help`` mentions no resume).
_NON_RESUME_EXECUTABLES = frozenset({
    "bash", "sh", "dash", "zsh", "fish", "ksh",
    "vim", "vi", "nvim", "nano", "emacs",
    "less", "more", "cat", "tail", "head",
    "ssh", "mosh", "telnet", "sftp", "scp",
    "python", "python3", "ruby", "perl", "node", "php", "lua",
})


# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ResumeMatch:
    """The resolved resume plan for a captured tool launch."""

    executable: str
    contract: ResumeContract
    source: str  # "registry" (name override) | "probe" (help introspection)


def _find_contract_by_name(contract_name: str) -> ResumeContract | None:
    for contract in _CONTRACTS:
        if contract.name == contract_name:
            return contract
    return None


def _probe_help_output(executable: str, resolver: ExecutableResolver) -> str:
    """Return the lower-cased ``<exe> --help`` text, or "" on failure."""
    path = resolver(executable)
    if path is None:
        return ""
    try:
        completed = subprocess.run(
            (path, "--help"),
            capture_output=True,
            text=True,
            timeout=3.0,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return (completed.stdout + "\n" + completed.stderr).lower()


_WORD_RE = re.compile(r"[a-z0-9_-]+")
# A "listed command" line in --help: leading whitespace then a bare token,
# e.g. "  resume          Resume a previous...".  This distinguishes a real
# subcommand from a prose mention like "...on resume and after resize".
_LISTED_COMMAND_RE = re.compile(r"(?m)^\s{2,}([a-z][a-z0-9_-]*)\b")


def _listed_commands(text: str) -> set[str]:
    return set(_LISTED_COMMAND_RE.findall(text))


_SESSION_CONTEXT_WORDS = frozenset({
    "session", "sessions", "previous", "last", "conversation", "history",
})


def _help_mentions(text: str, signature: tuple[str, ...]) -> bool:
    """True if ``text`` presents ``signature`` as a resume capability.

    A flag signature (``--continue``, ``--resume``) matches only when the help
    text also mentions session-oriented context (``session``/``last``/
    ``previous``/``conversation``/``history``) near the flag, so a tool that
    uses ``--continue`` to mean "continue a download" is not mistaken for a
    session-resume tool.

    A bare-word subcommand signature (``resume``) must appear as a *listed
    command* (start of an indented help line), not a prose mention, to avoid
    matching descriptive text like "...on resume and after resize".
    """
    words = set(_WORD_RE.findall(text))
    listed = _listed_commands(text)
    for sig in signature:
        sig_l = sig.lower()
        if sig_l.startswith("--"):
            if sig_l not in words:
                return False
            if not (words & _SESSION_CONTEXT_WORDS):
                # No session context anywhere: this --continue/--resume is not
                # about resuming a session.
                return False
        elif sig_l in listed:
            continue
        elif sig_l in words:
            # Bare-word subcommand signature must be a listed command, not prose.
            return False
        else:
            return False
    return True


def find_resume_adapter(
    executable: str,
    *,
    resolver: ExecutableResolver = shutil.which,
    probe: bool = True,
) -> ResumeMatch | None:
    """Resolve a resume plan for ``executable`` (lower-cased name).

    Returns ``None`` for shells/editors/interpreters and for executables that
    expose no resume convention.  When ``probe`` is true (default), unrecognized
    executables are introspected via ``--help`` so new tools work without
    registration.
    """
    if not executable:
        return None
    if executable in _NON_RESUME_EXECUTABLES:
        return None

    # 1. Explicit name override (rare; only for tools that need pinning).
    override = _EXECUTABLE_OVERRIDES.get(executable)
    if override is not None:
        contract = _find_contract_by_name(override)
        if contract is not None:
            return ResumeMatch(executable, contract, "registry")

    # 2. Convention probe: introspect the tool's own help.
    if probe:
        help_text = _probe_help_output(executable, resolver)
        if help_text:
            for contract in _CONTRACTS:
                if _help_mentions(help_text, contract.help_signature):
                    # Confirm the executable actually resolves so we don't
                    # return a plan for a tool that isn't installed.
                    if resolver(executable) is not None:
                        return ResumeMatch(executable, contract, "probe")
    return None


def build_resume_argv(match: ResumeMatch, session_id: str | None) -> tuple[str, ...]:
    """Build the concrete resume argv for a resolved ``ResumeMatch``."""
    return match.contract.build(match.executable, session_id)


# Backwards-compatible aliases retained for callers that imported the old names.
ResumeAdapter = ResumeMatch
