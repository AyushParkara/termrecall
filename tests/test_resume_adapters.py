# SPDX-License-Identifier: GPL-3.0-or-later
"""Resume-adapter tests.

Verifies that session-persistent tools (codex, opencode, pi, hermes) are
restored via their native resume command rather than replaying the launch
argv, while ordinary replayable commands are unaffected.
"""

from __future__ import annotations

import pytest

from termrecall.adapters.resume import ResumeAdapter, build_resume_argv, find_resume_adapter
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


@pytest.mark.parametrize("tool,expected", [
    ("codex", "codex resume --last"),
    ("opencode", "opencode"),
    ("pi", "pi --continue"),
    ("hermes", "hermes --continue"),
])
def test_resume_adapter_substitutes_native_resume_command(tool: str, expected: str) -> None:
    command = CommandRecord(1, tool, tool, CommandDisposition.REPLAYABLE, True)
    record = RecoveryRecord(1, "ws", 7, 13.5,
        (RecoveryItemRecord("item", _shell("/srv/app", command), "previous_boot"),), (), ())
    adapter = RecordingAdapter()
    build_attempt(record, ("item",), {"item"}, adapter,
        lambda name: f"/usr/bin/{name}" if name == tool else None)
    assert adapter.items[0].approved_command == expected


def test_resume_works_even_when_launch_was_unsafe() -> None:
    # An UNSAFE launch (executable is None) must still resume via display text.
    command = CommandRecord(1, "codex --yolo", None, CommandDisposition.UNSAFE, True)
    record = RecoveryRecord(1, "ws", 7, 13.5,
        (RecoveryItemRecord("item", _shell("/srv", command), "previous_boot"),), (), ())
    adapter = RecordingAdapter()
    build_attempt(record, ("item",), {"item"}, adapter,
        lambda name: "/usr/bin/codex" if name == "codex" else None)
    assert adapter.items[0].approved_command == "codex resume --last"


def test_resume_uses_session_id_when_provided() -> None:
    adapter = find_resume_adapter("codex")
    assert adapter is not None
    assert build_resume_argv(adapter, "abc-123") == ("codex", "resume", "abc-123")


def test_non_resume_command_replays_original_argv() -> None:
    command = CommandRecord(1, "sleep 10", "sleep 10", CommandDisposition.REPLAYABLE, True)
    record = RecoveryRecord(1, "ws", 7, 13.5,
        (RecoveryItemRecord("item", _shell("/srv", command), "previous_boot"),), (), ())
    adapter = RecordingAdapter()
    build_attempt(record, ("item",), {"item"}, adapter,
        lambda name: "/bin/sleep" if name == "sleep" else None)
    assert adapter.items[0].approved_command == "sleep 10"


def test_resume_argv_is_free_of_expansions_and_globs() -> None:
    # The resume argv bypasses the classifier, so it must be a literal argv
    # with no shell expansions, globs, or env assignments.
    for adapter_name in ("codex", "opencode", "pi", "hermes"):
        adapter = find_resume_adapter(adapter_name)
        assert adapter is not None
        for argv in (adapter.resume_argv, adapter.fallback_argv):
            if argv is None:
                continue
            text = " ".join(argv)
            assert "$" not in text, f"{adapter_name}: expansion in resume argv"
            assert "*" not in text and "?" not in text and "[" not in text, f"{adapter_name}: glob in resume argv"
            # Must parse as one simple command with a known executable.
            parsed = _parse_one_simple_command(text)
            assert parsed.executable == adapter_name


def test_unknown_executable_has_no_resume_adapter() -> None:
    assert find_resume_adapter("vim") is None
    assert find_resume_adapter("") is None
