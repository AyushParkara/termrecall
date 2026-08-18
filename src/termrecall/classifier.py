# SPDX-License-Identifier: GPL-3.0-or-later

import re
import shlex
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import NamedTuple

from termrecall.model import MAX_COMMAND_CHARS, CommandDisposition, CommandRecord

_REDACTED_DISPLAY = "[sensitive command redacted]"

_SECRET_VALUE_PATTERN = r"(?:'[^']+'|\"[^\"]+\"|[^\s'\";]+)"
_CREDENTIAL_NAME_PATTERN = (
    r"(?:aws_)?(?:secret(?:_access)?_key|access_key|api[_-]?(?:key|token)|"
    r"auth[_-]?token|password|passwd|pwd|token)"
)
_QUOTE_NORMALIZED_CREDENTIAL_NAME_PATTERN = (
    rf"(?:'{_CREDENTIAL_NAME_PATTERN}'|\"{_CREDENTIAL_NAME_PATTERN}\"|"
    rf"(?:--?)?{_CREDENTIAL_NAME_PATTERN})"
)
_CREDENTIAL_RE = re.compile(
    rf"(?ix){_QUOTE_NORMALIZED_CREDENTIAL_NAME_PATTERN}"
    rf"\s*(?:(?:=|:)\s*|\s+){_SECRET_VALUE_PATTERN}"
)
_AUTHORIZATION_RE = re.compile(r"(?ix)authorization\s*:\s*[^\s'\"]+")
_CREDENTIAL_FRAGMENT_RE = re.compile(
    rf"(?ix)(?:^|[^A-Z0-9_])(?:--?)?{_CREDENTIAL_NAME_PATTERN}(?:$|[^A-Z0-9_])"
)
_PRIVATE_KEY_RE = re.compile(
    r"(?i)(?:-----\s*BEGIN[\s_-]+(?:[A-Z0-9]+[\s_-]+)?PRIVATE[\s_-]+KEY\s*-----|"
    r"BEGIN_PRIVATE_KEY)"
)
_AWS_ACCESS_KEY_RE = re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])")
_CREDENTIAL_URL_RE = re.compile(
    r"(?i)\b[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@"
)

_PRIVILEGED_OR_DESTRUCTIVE = {
    "busybox",
    "sudo",
    "su",
    "doas",
    "pkexec",
    "shutdown",
    "reboot",
    "halt",
    "kill",
    "killall",
    "pkill",
    "poweroff",
    "systemctl",
    "toybox",
    "rm",
    "dd",
    "mkfs",
    "fdisk",
    "sfdisk",
    "parted",
    "wipefs",
    "shred",
    "truncate",
}
_SHELL_STATEFUL = {
    ".",
    "bash",
    "dash",
    "alias",
    "builtin",
    "cd",
    "command",
    "declare",
    "enable",
    "env",
    "eval",
    "exec",
    "export",
    "fish",
    "ksh",
    "nohup",
    "nice",
    "readonly",
    "set",
    "setsid",
    "sh",
    "source",
    "timeout",
    "trap",
    "typeset",
    "ulimit",
    "umask",
    "unalias",
    "unset",
    "zsh",
}
_INTERACTIVE_STATEFUL = {
    "ssh",
    "mosh",
    "telnet",
    "ftp",
    "sftp",
    "vim",
    "vi",
    "nvim",
    "nano",
    "emacs",
    "less",
    "more",
    "mysql",
    "psql",
    "redis-cli",
    "top",
    "htop",
    "tmux",
    "screen",
}
# Commands that can execute arbitrary code through embedded interpreters,
# exec actions, or config-driven hooks and therefore cannot be safely
# replayed as a single simple argv.
_CODE_EXECUTING = {
    "awk", "gawk", "mawk", "nawk",
    "sed",
    "find",
    "make", "cmake", "gmake",
    "xargs",
    "tar",
    "git",
    "perl",
    "lua",
    "tclsh", "wish", "tcl",
    "php",
    "dd",
}
# Shell reserved words/keywords that change control flow or syntax and so
# cannot be replayed as a single simple command.
_SHELL_RESERVED_WORDS = {
    "time", "coproc", "!",
    "function", "let", "select",
    "for", "while", "until", "case", "if", "then", "else",
    "do", "done", "fi", "esac", "in",
    "local",
}

# Commands that mutate filesystem, package, cron, or remote state and so
# cannot be safely auto-replayed even when no embedded interpreter is present.
_STATE_CHANGING = {
    "touch", "mkdir", "rmdir", "cp", "mv", "install", "chmod", "chown",
    "chgrp", "ln", "link", "rename", "unlink", "truncate", "tee", "dd",
    "mkfifo", "mknod", "mount", "umount", "swapoff", "swapon",
    "pip", "pip3", "pipx", "poetry", "uv", "conda", "mamba",
    "npm", "npx", "yarn", "pnpm", "bun", "deno",
    "cargo", "rustup", "go", "gem", "bundle", "composer",
    "crontab", "at", "batch",
    "curl", "wget", "ftp", "scp", "rsync", "s3cmd", "aws", "gcloud", "kubectl",
    "systemctl", "service", "initctl", "update-rc.d", "chkconfig",
    "useradd", "usermod", "userdel", "groupadd", "groupmod", "groupdel",
    "passwd", "chpasswd", "chage",
    "docker", "podman", "nerdctl",
}
# Interpreters that execute an attacker-supplied script file or inline code
# and therefore cannot be auto-replayed as a single safe argv unless they take
# the module form ``name -m module`` (no local file execution).
_SCRIPT_INTERPRETERS = {
    "python", "python3",
    "ruby", "rb",
    "node",
    "perl",
    "php",
    "lua",
    "tclsh", "wish", "tcl",
    "groovy", "gosh", "jrunscript",
    "rscript", "R",
    "julia",
    "awk", "gawk", "mawk", "nawk",
}


@dataclass(frozen=True, slots=True)
class Classification:
    record: CommandRecord
    reason: str


class _PolicyRejection(ValueError):
    pass


class ParsedCommand(NamedTuple):
    """Canonical representation of a single, validated simple command.

    ``executable`` is the program name (last path component, lower-cased) after
    skipping any ``VAR=value`` prefix assignments.  ``argv`` is the literal
    token list (including any prefix assignments) and ``prefix`` is the number
    of leading environment-assignment tokens.  Both the classifier and the
    recovery layer consume this single representation so they cannot disagree
    about what the executable is.
    """

    executable: str
    argv: tuple[str, ...]
    prefix: int


# A leading ``VAR=value`` token is an environment assignment to Bash, not an
# executable argument.  Replay must not honour captured environment mutations,
# so any such prefix causes rejection.
_ENV_ASSIGNMENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=.*")
# Bash parameter / variable expansions are expanded by the shell at replay
# time and can splice arbitrary arguments or state (positional params ``$@``,
# PID ``$$``, exit status ``$?``, ``${@}``, ``${0}``, named ``$VAR``, etc.),
# so any such construct is rejected even when quoted.
_PARAM_EXPANSION_RE = re.compile(r"\$\{[^}]*\}|\$[@#0-9!?$*\-]|\$[A-Za-z_][A-Za-z0-9_]*")
# Glob / pathname-expansion metacharacters let directory contents change the
# executed program after classification, so they are rejected.
_GLOB_CHARS = ("*", "?", "[")


def classify_command(command: str, sequence: int) -> Classification:
    if (
        _contains_dollar_quote(command)
        or _contains_obfuscated_authorization_skeleton(command)
        or _contains_raw_secret_marker(command)
        or _AWS_ACCESS_KEY_RE.search(command) is not None
        or _CREDENTIAL_URL_RE.search(command) is not None
    ):
        return _redacted(sequence)

    try:
        normalized_tokens = shlex.split(command, posix=True)
    except ValueError:
        if _contains_authorization_skeleton(command) or _contains_fragmented_credential(command):
            return _redacted(sequence)
        normalized_tokens = None
    else:
        if _contains_normalized_credential(normalized_tokens):
            return _redacted(sequence)

    try:
        parsed = _parse_one_simple_command(command, normalized_tokens)
    except _PolicyRejection:
        return Classification(
            CommandRecord(
                sequence,
                _bounded_display(command),
                None,
                CommandDisposition.UNREPRESENTABLE,
                True,
            ),
            "command cannot be represented as one simple command",
        )

    executable = parsed.executable
    tokens = list(parsed.argv)
    if _is_unsafe(executable) or executable in _SHELL_STATEFUL:
        return Classification(
            CommandRecord(
                sequence,
                _bounded_display(command),
                None,
                CommandDisposition.UNSAFE,
                True,
            ),
            "privileged or destructive command",
        )
    if executable in _CODE_EXECUTING:
        return Classification(
            CommandRecord(
                sequence,
                _bounded_display(command),
                None,
                CommandDisposition.UNSAFE,
                True,
            ),
            "code-executing command",
        )
    if executable in _SHELL_RESERVED_WORDS:
        return Classification(
            CommandRecord(
                sequence,
                _bounded_display(command),
                None,
                CommandDisposition.UNSAFE,
                True,
            ),
            "shell reserved word",
        )
    if executable in _STATE_CHANGING:
        return Classification(
            CommandRecord(
                sequence,
                _bounded_display(command),
                None,
                CommandDisposition.UNSAFE,
                True,
            ),
            "state-changing command",
        )
    if executable in _SCRIPT_INTERPRETERS and _interpreter_runs_script(executable, parsed):
        return Classification(
            CommandRecord(
                sequence,
                _bounded_display(command),
                None,
                CommandDisposition.UNSAFE,
                True,
            ),
            "interpreter executes a script file",
        )
    if _requires_unavailable_interactive_state(executable, tokens):
        return Classification(
            CommandRecord(
                sequence,
                _bounded_display(command),
                None,
                CommandDisposition.UNSAFE,
                True,
            ),
            "interactive command requires unavailable state",
        )
    if len(command) > MAX_COMMAND_CHARS:
        return Classification(
            CommandRecord(
                sequence,
                _bounded_display(command),
                None,
                CommandDisposition.UNREPRESENTABLE,
                True,
            ),
            "command exceeds replay length limit",
        )

    return Classification(
        CommandRecord(
            sequence,
            command,
            command,
            CommandDisposition.REPLAYABLE,
            True,
        ),
        "single simple command accepted",
    )


def _redacted(sequence: int) -> Classification:
    return Classification(
        CommandRecord(
            sequence,
            _REDACTED_DISPLAY,
            None,
            CommandDisposition.REDACTED,
            True,
        ),
        "likely credential or private-key material",
    )


def _contains_dollar_quote(command: str) -> bool:
    return "$'" in command or '$"' in command


def _authorization_skeleton(command: str) -> str:
    return re.sub(r"['\"$\\\s]", "", command).lower()


def _contains_authorization_skeleton(command: str) -> bool:
    return "authorization:" in _authorization_skeleton(command)


def _contains_obfuscated_authorization_skeleton(command: str) -> bool:
    return _contains_authorization_skeleton(command) and not bool(
        re.search(r"(?i)authorization\s*:", command)
    )


def _contains_raw_secret_marker(command: str) -> bool:
    return bool(_AUTHORIZATION_RE.search(command) or _PRIVATE_KEY_RE.search(command))


def _contains_normalized_credential(tokens: list[str]) -> bool:
    normalized = " ".join(tokens)
    if _CREDENTIAL_RE.search(normalized):
        return True
    for index, token in enumerate(tokens):
        match = re.fullmatch(r"(?i)authorization\s*:(.*)", token)
        if match and match.group(1).strip():
            return True
        if token.lower() == "authorization" and index + 1 < len(tokens) and tokens[index + 1] == ":":
            return _authorization_has_separate_value(tokens, index + 1)
    return False


def _authorization_has_separate_value(tokens: list[str], separator_index: int) -> bool:
    return separator_index + 1 < len(tokens)


def _contains_fragmented_credential(command: str) -> bool:
    fragments = re.sub(r"['\"]", "", command)
    return bool(
        _CREDENTIAL_RE.search(fragments) or _CREDENTIAL_FRAGMENT_RE.search(fragments)
    )


def _parse_one_simple_command(
    command: str, normalized_tokens: list[str] | None = None
) -> ParsedCommand:
    if not command.strip() or "\x00" in command or command.endswith("\\"):
        raise _PolicyRejection

    # Reject glob metacharacters and parameter expansions anywhere in the
    # command text.  Quoting does not make these safe: a quoted ``$VAR`` is
    # still expanded by Bash at replay time, and a quoted ``*`` is still a
    # literal token but ``shlex`` cannot distinguish it from an unquoted glob
    # reliably, so we refuse both forms for replayable commands.
    if any(ch in command for ch in _GLOB_CHARS):
        raise _PolicyRejection
    if _PARAM_EXPANSION_RE.search(command):
        raise _PolicyRejection

    quote: str | None = None
    escaped = False
    index = 0
    while index < len(command):
        character = command[index]
        if quote == "'":
            if character == "'":
                quote = None
            index += 1
            continue
        if escaped:
            if quote is None and character in ";&|<>()\n":
                raise _PolicyRejection
            escaped = False
            index += 1
            continue
        if character == "\\":
            escaped = True
            index += 1
            continue
        if quote == '"':
            if character == '"':
                quote = None
            elif character == "`" or command.startswith("$(", index):
                raise _PolicyRejection
            index += 1
            continue
        if character == "'":
            quote = character
            index += 1
            continue
        if character == '"':
            quote = character
            index += 1
            continue
        if character == "`" or command.startswith("$(", index):
            raise _PolicyRejection
        if character in ";&|<>()\n":
            raise _PolicyRejection
        index += 1

    if quote is not None or escaped:
        raise _PolicyRejection
    if normalized_tokens is None:
        try:
            tokens = shlex.split(command, posix=True)
        except ValueError as exc:
            raise _PolicyRejection from exc
    else:
        tokens = normalized_tokens
    if not tokens:
        raise _PolicyRejection

    # Leading ``VAR=value`` tokens are environment-assignment prefixes in
    # Bash.  Replay must not honour captured environment mutations (they can
    # load attacker libraries via LD_PRELOAD, alter interpreter search paths
    # via PYTHONPATH, etc.), so any such prefix makes the command
    # unrepresentable rather than replayable.
    prefix = 0
    while prefix < len(tokens) and _ENV_ASSIGNMENT_RE.fullmatch(tokens[prefix]):
        prefix += 1
    if prefix >= len(tokens):
        raise _PolicyRejection
    if prefix > 0:
        # One or more environment assignments precede the executable.  Replay
        # would reconstruct those mutations, which is unsafe, so refuse.
        raise _PolicyRejection

    executable_name = PurePosixPath(tokens[prefix]).name.lower()
    return ParsedCommand(executable_name, tuple(tokens), prefix)


def _command_name(tokens: list[str]) -> str:
    """Backward-compatible executable name from raw token list.

    Used by the recovery layer to resolve the executable past ``VAR=value``
    prefixes.  Prefer ``ParsedCommand`` for new code.
    """
    index = 0
    while index < len(tokens) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[index]):
        index += 1
    if index == len(tokens):
        return "export"
    return PurePosixPath(tokens[index]).name.lower()


def _is_unsafe(executable: str) -> bool:
    return executable in _PRIVILEGED_OR_DESTRUCTIVE or executable.startswith("mkfs.")


def _requires_unavailable_interactive_state(executable: str, tokens: list[str]) -> bool:
    if executable in _INTERACTIVE_STATEFUL:
        return True
    interpreters = {"node", "perl", "python", "python3", "ruby"}
    if executable not in interpreters:
        return False
    arguments = tokens[1:]
    if not arguments:
        return True
    if executable in {"python", "python3"}:
        if "-i" in arguments:
            return True
        if arguments[0] == "-m":
            return len(arguments) < 2
    return arguments[0].startswith("-")


# Inline-code / interactive flags for script interpreters.  When the first
# argument is one of these the interpreter runs attacker-supplied code.
_INTERPRETER_CODE_FLAGS = {
    "-c", "-e", "-r", "-p", "-y", "--eval", "-i", "-Q",
}
# Module-form flags that do NOT execute a local script file.  ``python -m
# http.server`` imports a stdlib module by name and is safe to replay.
_INTERPRETER_MODULE_FLAGS = {"-m", "--module"}


def _interpreter_runs_script(executable: str, parsed: ParsedCommand) -> bool:
    """Return True when an interpreter invocation runs a script file or inline code.

    ``python -m http.server`` and ``python --version`` are safe; everything
    else (``python file.py``, ``python -c '...'``, ``ruby file.rb``) executes
    attacker-controlled code and is rejected.
    """
    arguments = parsed.argv[parsed.prefix + 1:]
    if not arguments:
        # A bare interpreter with no arguments starts a REPL/interactive shell,
        # which cannot be replayed.
        return True
    first = arguments[0]
    if executable in {"python", "python3"}:
        if first in _INTERPRETER_MODULE_FLAGS:
            # ``-m module`` form: no local file execution; allow it.
            return len(arguments) < 2
        if first in _INTERPRETER_CODE_FLAGS:
            return True
        # A non-option first argument is a script filename -> reject.
        return not first.startswith("-")
    # For all other script interpreters (ruby/node/perl/php/lua/groovy/...)
    # any non-option argument is a script file and any -c/-e style flag is
    # inline code.  Scan the WHOLE argument list (not just the first token) so
    # that ``groovy -X /tmp/payload.groovy`` or ``node --print code`` is still
    # rejected: a script/code argument anywhere means attacker code runs.
    if any(arg in _INTERPRETER_CODE_FLAGS for arg in arguments):
        return True
    # Any non-option (positional) argument is treated as a script file.
    if any(not arg.startswith("-") for arg in arguments):
        return True
    # Only purely-option invocations (e.g. ``--version``) are allowed.
    return False


def _bounded_display(command: str) -> str:
    return command[:MAX_COMMAND_CHARS]
