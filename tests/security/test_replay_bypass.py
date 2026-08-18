# SPDX-License-Identifier: GPL-3.0-or-later
"""Adversarial replay-bypass regression suite.

Every command below was identified by the security audit as a replay bypass:
the classifier accepted it as REPLAYABLE even though it can execute arbitrary
code when re-evaluated or invoked with code-executing flags.  These tests pin
the fixed behaviour so the bypasses can never silently return.
"""

from __future__ import annotations

import shlex

import pytest

from termrecall.adapters.base import _COMMAND_WRAPPER
from termrecall.classifier import CommandDisposition, classify_command

# awk/sed/find/make/xargs/tar/git code execution + shell keywords + interpreter -e flags.
MALICIOUS_COMMANDS = [
    "awk 'BEGIN { system(\"touch /tmp/pwn\") }'",
    "gawk 'BEGIN { system(\"touch /tmp/pwn\") }'",
    "sed '1e touch /tmp/pwn' /dev/null",
    "find . -exec sh -c 'touch /tmp/pwn' '{}' +",
    "make -f /tmp/Makefile",
    "xargs sh -c 'touch /tmp/pwn'",
    "git -c core.pager='!/bin/sh -c \"touch /tmp/pwn\"' log",
    "tar -cf /tmp/a.tar --checkpoint=1 --checkpoint-action=exec='touch /tmp/pwn' /etc/hosts",
    # shell keywords
    "time rm -rf /",
    "! rm -rf /",
    "coproc rm -rf /",
    # interpreter -e flags
    "perl -e 'system(\"touch /tmp/pwn\")'",
    "lua -e 'os.execute(\"touch /tmp/pwn\")'",
    "tclsh -c 'exec touch /tmp/pwn'",
    "php -r 'system(\"touch /tmp/pwn\")'",
]


@pytest.mark.parametrize("command", MALICIOUS_COMMANDS)
def test_malicious_command_not_replayable(command: str) -> None:
    record = classify_command(command, sequence=1).record
    assert record.disposition is not CommandDisposition.REPLAYABLE, (
        f"{command!r} was classified as REPLAYABLE!"
    )


def test_replayable_command_tokens_run_directly_under_exec_dollar_at() -> None:
    """shlex.split of a REPLAYABLE command yields argv tokens that ``exec "$@"``
    runs directly; the centralized wrapper never re-evaluates the command
    through a login shell (which would allow command substitution or
    metacharacter re-evaluation)."""
    # The centralized wrapper must exec the positional argv directly and must
    # not route the command back through a login shell.
    assert _COMMAND_WRAPPER == 'exec "$@"; status=$?; exec bash -i'
    assert "bash -lc" not in _COMMAND_WRAPPER
    assert "$command" not in _COMMAND_WRAPPER

    command = "printf '%s' hello world"
    record = classify_command(command, sequence=1).record
    assert record.disposition is CommandDisposition.REPLAYABLE

    tokens = shlex.split(command)
    # Under ``bash -c _COMMAND_WRAPPER bash *tokens``: $0=bash, "$@"=tokens,
    # so ``exec "$@"`` runs tokens[0] as a program with the remaining tokens as
    # literal argv elements (bash never re-parses them as shell syntax).
    assert tokens == ["printf", "%s", "hello", "world"]
