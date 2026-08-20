# SPDX-License-Identifier: GPL-3.0-or-later
"""Universal resume-engine tests.

Verifies the convention-probe resolves each tool's best resume form WITHOUT any
hard-coded per-tool entry, that session-id forms work, that non-session tools
are rejected, and that resume argv is free of shell expansions/globs/env
assignments so it can safely bypass the replay classifier.
"""

from __future__ import annotations

import pytest

import termrecall.sessions
from termrecall.adapters.resume import (
    ResumeContract,
    ResumeMatch,
    build_resume_argv,
    find_resume_adapter,
)
from termrecall.classifier import _parse_one_simple_command
from termrecall.model import CommandDisposition, CommandRecord, RecoveryItemRecord, RecoveryRecord, ShellRecord
from termrecall.recovery import build_attempt


class RecordingAdapter:
    def __init__(self) -> None:
        self.items: list = []
    def detect(self) -> bool: return True
    def capabilities(self): ...
    def plan(self, items): self.items = list(items); return ()
    def execute(self, actions, attempt_id): return ()


def _shell(cwd: str, command: CommandRecord) -> ShellRecord:
    return ShellRecord("a", None, "gnome-terminal", cwd, 0, command, None)


# Hermetic --help texts modelled on each tool's real output (verified
# 2026-08-18).  The probe must resolve the BEST form per tool without a
# registry entry.
HELP = {
    "codex": """
  resume          Resume a previous interactive session (picker by default; use --last to continue
  archive         Archive a saved session by id or session name
""",
    "pi": """
  --continue, -c                 Continue previous session
  --resume, -r                   Select a session to resume
  --session <path|id>            Use specific session file or partial UUID
""",
    "hermes": """
  --resume SESSION, -r SESSION   Resume a previous session by ID or title
  --continue [SESSION_NAME]      Resume a session by name, or the most recent if no
""",
    "opencode": """
  -c, --continue      continue the last session
  -s, --session       session id to continue
  opencode session                manage sessions
""",
    # Non-session tools that must NOT match:
    "wget": "GNU Wget: download files\n  --continue      continue a partial download\n",
    "curl": "curl [options] url\n  -C, --continue-at  resume transfer\n",
    "bash": "GNU bash, version 5\n  --posix\n  --restricted\n",
}


def _resolver(name: str) -> str | None:
    return f"/usr/bin/{name}" if name in HELP else None


def _probe(exe: str, resolver) -> str:
    return HELP.get(exe, "")


@pytest.mark.parametrize("exe,expected_cwd,expected_with_id", [
    ("codex", ("codex", "resume", "--last"), ("codex", "resume", "SID")),
    ("pi", ("pi", "--continue"), ("pi", "--session", "SID")),
    ("hermes", ("hermes", "--continue"), ("hermes", "--session", "SID")),
    ("opencode", ("opencode", "--continue"), ("opencode", "--session", "SID")),
])
def test_probe_resolves_best_resume_form(exe, expected_cwd, expected_with_id, monkeypatch):
    monkeypatch.setattr("termrecall.adapters.resume._probe_help_output", _probe)
    monkeypatch.setattr("termrecall.adapters.resume.shutil.which", _resolver)
    match = find_resume_adapter(exe, resolver=_resolver)
    assert match is not None
    assert match.source == "probe"
    assert build_resume_argv(match, None) == expected_cwd
    assert build_resume_argv(match, "SID") == expected_with_id


@pytest.mark.parametrize("exe", ["wget", "curl", "bash"])
def test_non_session_tools_are_rejected(exe, monkeypatch):
    monkeypatch.setattr("termrecall.adapters.resume._probe_help_output", _probe)
    match = find_resume_adapter(exe, resolver=_resolver)
    assert match is None


def test_resume_works_even_when_launch_was_unsafe(monkeypatch):
    monkeypatch.setattr("termrecall.adapters.resume._probe_help_output", _probe)
    monkeypatch.setattr("termrecall.adapters.resume.shutil.which", _resolver)
    # Isolate the session-store lookup so no real session id is resolved and
    # the resume falls back to the cwd-only form.
    monkeypatch.setattr("termrecall.sessions.find_active_session_id", lambda tool: None)
    monkeypatch.setattr("termrecall.sessions.find_sessions_for_cwd", lambda *a, **k: [])
    command = CommandRecord(1, "codex --yolo", None, CommandDisposition.UNSAFE, True)
    record = RecoveryRecord(1, "ws", 7, 13.5,
        (RecoveryItemRecord("item", _shell("/srv", command), "previous_boot"),), (), ())
    adapter = RecordingAdapter()
    build_attempt(record, ("item",), {"item"}, adapter, _resolver)
    assert adapter.items[0].approved_command == "codex resume --last"


def test_non_resume_command_replays_original_argv(monkeypatch):
    monkeypatch.setattr("termrecall.adapters.resume._probe_help_output", _probe)
    monkeypatch.setattr("termrecall.adapters.resume.shutil.which", _resolver)
    command = CommandRecord(1, "sleep 10", "sleep 10", CommandDisposition.REPLAYABLE, True)
    record = RecoveryRecord(1, "ws", 7, 13.5,
        (RecoveryItemRecord("item", _shell("/srv", command), "previous_boot"),), (), ())
    adapter = RecordingAdapter()
    build_attempt(record, ("item",), {"item"}, adapter,
        lambda name: "/bin/sleep" if name == "sleep" else None)
    assert adapter.items[0].approved_command == "sleep 10"


def test_resume_argv_is_free_of_expansions_globs_env(monkeypatch):
    monkeypatch.setattr("termrecall.adapters.resume._probe_help_output", _probe)
    monkeypatch.setattr("termrecall.adapters.resume.shutil.which", _resolver)
    for exe in ("codex", "pi", "hermes", "opencode"):
        match = find_resume_adapter(exe, resolver=_resolver)
        assert match is not None
        for argv in (build_resume_argv(match, None), build_resume_argv(match, "SID")):
            text = " ".join(argv)
            assert "$" not in text, f"{exe}: expansion in resume argv"
            assert "*" not in text and "?" not in text and "[" not in text, f"{exe}: glob in resume argv"
            parsed = _parse_one_simple_command(text)
            assert parsed.executable == exe


def test_prose_mention_does_not_trigger_false_resume(monkeypatch):
    # A tool whose --help mentions "resume"/"continue" only in prose, with no
    # session context, must NOT be matched.
    monkeypatch.setattr("termrecall.adapters.resume._probe_help_output",
        lambda exe, res: "usage: foo\n  --verbose   print more\n  note: this tool cannot resume a session.\n" if exe == "foo" else "")
    match = find_resume_adapter("foo", resolver=lambda n: "/bin/foo" if n == "foo" else None)
    assert match is None


def test_unknown_executable_with_no_resume_returns_none(monkeypatch):
    monkeypatch.setattr("termrecall.adapters.resume._probe_help_output",
        lambda exe, res: "usage: idff\n  --serve   run server\n" if exe == "idff" else "")
    match = find_resume_adapter("idff", resolver=lambda n: "/usr/bin/idff" if n == "idff" else None)
    assert match is None
