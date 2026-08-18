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


# --- Audit findings #2-#8: additional classifier bypasses ---------------------

# Bash parameter expansion ($VAR / ${VAR}) and glob metacharacters can change
# the executed program after classification (findings #2, #3).  Environment
# assignment prefixes can load attacker libraries (finding #5).  Interpreter
# script-file forms execute attacker code (finding #4).  State-changing
# commands mutate filesystem/package/remote state (finding #8).
EXPANSION_AND_GLOB_COMMANDS = [
    r"bash${IFS}-c${IFS}'touch /tmp/pwn'",
    "./*",
    "ls *",
    "echo ${HOME}",
    "cat $HOME/file",
]
ENV_ASSIGNMENT_COMMANDS = [
    "LD_PRELOAD=/tmp/x.so /bin/true",
    "LD_LIBRARY_PATH=/tmp /bin/true",
    "PYTHONPATH=/tmp python3 /tmp/payload.py",
    "GIT_SSH_COMMAND=/tmp/payload git push",
    "PATH=/tmp /bin/ls",
    "FOO=bar python -m http.server",
]
INTERPRETER_SCRIPT_COMMANDS = [
    "python3 /tmp/payload.py",
    "python3 app.py",
    "python worker.py --port 8000",
    "ruby /tmp/payload.rb",
    "ruby worker.rb",
    "node /tmp/payload.js",
    "node server.js",
    "perl /tmp/payload.pl",
    "php /tmp/payload.php",
    "lua /tmp/payload.lua",
    "groovy /tmp/payload.groovy",
    "python3 -c 'touch /tmp/pwn'",
]
STATE_CHANGING_COMMANDS = [
    "touch /tmp/x",
    "mkdir /tmp/x",
    "cp a b",
    "mv a b",
    "install a b",
    "chmod 755 x",
    "chown root x",
    "ln -s a b",
    "ln a b",
    "pip install x",
    "npm install x",
    "npm run build",
    "cargo install x",
    "go install x",
    "crontab file",
    "curl -X POST http://example.test",
    "wget http://example.test",
]


@pytest.mark.parametrize("command", EXPANSION_AND_GLOB_COMMANDS)
def test_expansion_and_glob_commands_are_not_replayable(command: str) -> None:
    record = classify_command(command, sequence=1).record
    assert record.disposition is not CommandDisposition.REPLAYABLE, (
        f"{command!r} was classified as REPLAYABLE!"
    )


@pytest.mark.parametrize("command", ENV_ASSIGNMENT_COMMANDS)
def test_environment_assignment_prefixes_are_not_replayable(command: str) -> None:
    record = classify_command(command, sequence=1).record
    assert record.disposition is not CommandDisposition.REPLAYABLE, (
        f"{command!r} was classified as REPLAYABLE!"
    )


@pytest.mark.parametrize("command", INTERPRETER_SCRIPT_COMMANDS)
def test_interpreter_script_file_commands_are_not_replayable(command: str) -> None:
    record = classify_command(command, sequence=1).record
    assert record.disposition is not CommandDisposition.REPLAYABLE, (
        f"{command!r} was classified as REPLAYABLE!"
    )


@pytest.mark.parametrize("command", STATE_CHANGING_COMMANDS)
def test_state_changing_commands_are_not_replayable(command: str) -> None:
    record = classify_command(command, sequence=1).record
    assert record.disposition is not CommandDisposition.REPLAYABLE, (
        f"{command!r} was classified as REPLAYABLE!"
    )


# The safe module-form interpreter command must remain replayable so the fix
# does not over-reach and break legitimate long-running services.
SAFE_REPLAYABLE_COMMANDS = [
    "python3 -m http.server 8000",
    "python -m http.server",
    "printf '%s' hello world",
    "sleep 10",
    "echo '(date)'",
]


@pytest.mark.parametrize("command", SAFE_REPLAYABLE_COMMANDS)
def test_safe_commands_remain_replayable(command: str) -> None:
    record = classify_command(command, sequence=1).record
    assert record.disposition is CommandDisposition.REPLAYABLE, (
        f"{command!r} was incorrectly rejected!"
    )


# --- Edge-case regression: special-parameter expansions ------------------------
# Bash special parameters ($@ $@ $# $0..$9 $$ $! $? $- $* and their ${...}
# braces) splice shell state at replay time and must be rejected even though
# they don't start with a letter.
SPECIAL_EXPANSION_COMMANDS = [
    "echo $@",
    "echo $#",
    "echo $0",
    "echo $1",
    "echo $9",
    "echo $$",
    "echo $!",
    "echo $?",
    "echo $-",
    "echo $*",
    "echo ${@}",
    "echo ${0}",
    "echo ${#}",
    "echo ${HOME}",
    "echo ${HOME:-/tmp}",
    "echo $VAR",
    "echo $HOME",
]


@pytest.mark.parametrize("command", SPECIAL_EXPANSION_COMMANDS)
def test_special_parameter_expansions_are_not_replayable(command: str) -> None:
    record = classify_command(command, sequence=1).record
    assert record.disposition is not CommandDisposition.REPLAYABLE, (
        f"{command!r} was classified as REPLAYABLE!"
    )


# --- Edge-case regression: interpreter option-then-file bypass -----------------
# ``groovy -X file`` (and similar) must be rejected: a non-option argument
# anywhere in the list is a script file that executes attacker code, even when
# it is not the first argument.
INTERPRETER_OPTION_FILE_COMMANDS = [
    "groovy -X /tmp/payload.groovy",
    "groovy --some-flag /tmp/payload.groovy",
    "node --print 'touch /tmp/pwn'",
    "node --inspect /tmp/payload.js",
    'ruby -e \'system("touch /tmp/pwn")\'',
    "perl -w /tmp/payload.pl",
    "php -f /tmp/payload.php",
    'lua -e \'os.execute("touch /tmp/pwn")\'',
]


@pytest.mark.parametrize("command", INTERPRETER_OPTION_FILE_COMMANDS)
def test_interpreter_option_then_file_is_not_replayable(command: str) -> None:
    record = classify_command(command, sequence=1).record
    assert record.disposition is not CommandDisposition.REPLAYABLE, (
        f"{command!r} was classified as REPLAYABLE!"
    )
