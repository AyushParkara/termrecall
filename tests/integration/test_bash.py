# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import fcntl
import json
import os
import subprocess
from pathlib import Path

import pytest


def run_bash(script: str, env: dict[str, str], *, timeout: float = 3) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "--noprofile", "--norc", "-i", "-c", script],
        env={**os.environ, **env},
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


@pytest.fixture
def bash_hook() -> Path:
    return Path(__file__).parents[2] / "src/termrecall/data/bash/termrecall.bash"


@pytest.fixture
def hook_env(tmp_path: Path, bash_hook: Path) -> tuple[dict[str, str], Path]:
    capture = tmp_path / "frames.jsonl"
    bridge = tmp_path / "bridge"
    bridge.write_text("#!/bin/bash\nwhile IFS= read -r line; do printf '%s\\n' \"$line\" >>\"$CAPTURE\"; done\n")
    bridge.chmod(0o755)
    helper = tmp_path / "nonblock"
    source = Path(__file__).parents[2] / "native/termrecall-nonblock.c"
    subprocess.run(["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", str(source), "-o", str(helper)], check=True)
    return {
        "GNOME_TERMINAL_SCREEN": "/org/gnome/Terminal/screen/1",
        "TERMRECALL_BRIDGE_PROGRAM": str(bridge),
        "TERMRECALL_NONBLOCK_PROGRAM": str(helper),
        "TERMRECALL_SOCKET": str(tmp_path / "service.sock"),
        "CAPTURE": str(capture),
    }, capture


def test_repeated_sourcing_installs_one_hook_and_bridge(bash_hook: Path, hook_env: tuple[dict[str, str], Path]) -> None:
    env, capture = hook_env
    result = run_bash(
        f"source {bash_hook}; first=$TERMRECALL_BRIDGE_PID; source {bash_hook}; "
        "printf 'hooks=%s first=%s second=%s fd=%s\\n' \"${PROMPT_COMMAND[*]}\" \"$first\" \"$TERMRECALL_BRIDGE_PID\" \"$TERMRECALL_BRIDGE_FD\"; "
        "termrecall_uninstall",
        env,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.count("__termrecall_prompt") == 1
    fields = dict(item.split("=", 1) for item in result.stdout.strip().split())
    assert fields["first"] == fields["second"]
    assert int(fields["fd"]) >= 0


@pytest.mark.parametrize(
    "env_var,adapter",
    [
        ("GNOME_TERMINAL_SCREEN", "gnome-terminal"),
        ("KITTY_WINDOW_ID", "kitty"),
        ("GHOSTTY_RESOURCES_DIR", "ghostty"),
        ("XFCE4_TERMINAL", "xfce4-terminal"),
        ("KONSOLE_DBUS_SERVICE", "konsole"),
    ],
)
def test_hook_detects_terminal_and_passes_adapter_flag(
    bash_hook: Path, tmp_path: Path, env_var: str, adapter: str
) -> None:
    argv_file = tmp_path / "argv"
    bridge = tmp_path / "bridge"
    bridge.write_text(
        f'#!/bin/bash\nprintf \'%s\\n\' "$@" >>"{argv_file}"\nwhile IFS= read -r _; do :; done\n'
    )
    bridge.chmod(0o755)
    helper = tmp_path / "nonblock"
    source = Path(__file__).parents[2] / "native/termrecall-nonblock.c"
    subprocess.run(
        ["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", str(source), "-o", str(helper)],
        check=True,
    )
    terminal_vars = [
        "GNOME_TERMINAL_SCREEN",
        "KITTY_WINDOW_ID",
        "GHOSTTY_RESOURCES_DIR",
        "XFCE4_TERMINAL",
        "KONSOLE_DBUS_SERVICE",
    ]
    env = {var: ("1" if var == env_var else "") for var in terminal_vars}
    env.update(
        {
            "TERMRECALL_BRIDGE_PROGRAM": str(bridge),
            "TERMRECALL_NONBLOCK_PROGRAM": str(helper),
            "TERMRECALL_SOCKET": str(tmp_path / "service.sock"),
        }
    )
    result = run_bash(
        f"source {bash_hook}; sleep 0.1; termrecall_uninstall; "
        f"cat \"{argv_file}\" 2>/dev/null || true",
        env,
    )
    assert result.returncode == 0, result.stderr
    args = result.stdout.splitlines()
    assert "--adapter" in args, (args, result.stderr)
    index = args.index("--adapter")
    assert args[index + 1] == adapter


def test_hook_does_not_install_when_no_terminal_env_is_set(bash_hook: Path, tmp_path: Path) -> None:
    helper = tmp_path / "nonblock"
    source = Path(__file__).parents[2] / "native/termrecall-nonblock.c"
    subprocess.run(
        ["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", str(source), "-o", str(helper)],
        check=True,
    )
    env = {
        "GNOME_TERMINAL_SCREEN": "",
        "KITTY_WINDOW_ID": "",
        "GHOSTTY_RESOURCES_DIR": "",
        "XFCE4_TERMINAL": "",
        "KONSOLE_DBUS_SERVICE": "",
        "TERMRECALL_BRIDGE_PROGRAM": "echo-should-not-run",
        "TERMRECALL_NONBLOCK_PROGRAM": str(helper),
        "TERMRECALL_SOCKET": str(tmp_path / "service.sock"),
    }
    result = run_bash(
        f"source {bash_hook}; printf 'pid=%s' \"${{TERMRECALL_BRIDGE_PID-unset}}\"",
        env,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "pid=unset"


@pytest.mark.parametrize(
    "environment,script",
    [
        ({"SSH_CONNECTION": "host-pair"}, "source HOOK; printf '%s' \"${TERMRECALL_BRIDGE_PID-unset}\""),
        ({"GNOME_TERMINAL_SCREEN": ""}, "source HOOK; printf '%s' \"${TERMRECALL_BRIDGE_PID-unset}\""),
        ({}, "bash -c 'source HOOK; printf %s \"${TERMRECALL_BRIDGE_PID-unset}\"'"),
        ({}, "( source HOOK; printf '%s' \"${TERMRECALL_BRIDGE_PID-unset}\" )"),
        ({}, "value=$(source HOOK; printf '%s' \"${TERMRECALL_BRIDGE_PID-unset}\"); printf '%s' \"$value\""),
        ({}, "bash --noprofile --norc -i -c 'source HOOK; printf %s \"${TERMRECALL_BRIDGE_PID-unset}\"'; :"),
    ],
)
def test_ineligible_shells_do_not_start_bridge(
    bash_hook: Path,
    hook_env: tuple[dict[str, str], Path],
    environment: dict[str, str],
    script: str,
) -> None:
    env, _ = hook_env
    env.update(environment)
    result = run_bash(script.replace("HOOK", str(bash_hook)), env)
    assert result.stdout.strip() == "unset", (result.stdout, result.stderr)


def test_hooks_emit_capability_free_frames_preserve_status_and_existing_hooks(
    bash_hook: Path, hook_env: tuple[dict[str, str], Path]
) -> None:
    env, capture = hook_env
    script = f"""
PROMPT_COMMAND='printf old-prompt\\n'
trap 'printf old-exit\\n' EXIT
source {bash_hook}
printf 'exit-trap=%s\\n' "$(trap -p EXIT)"
__termrecall_exit_trap
false
__termrecall_prompt
status=$?
printf 'status=%s\\n' "$status"
__termrecall_prompt
__termrecall_preexec 'printf hello'
__termrecall_prompt
sleep 0.1
termrecall_uninstall
printf 'restored=%s\\n' "$PROMPT_COMMAND"
trap - EXIT
"""
    result = run_bash(script, env)
    assert result.returncode == 0, result.stderr
    assert "restored=printf old-prompt" in result.stdout
    assert "old-exit" in result.stdout
    assert "status=1" in result.stdout
    frames = [json.loads(line) for line in capture.read_text().splitlines()]
    assert frames
    assert all(not ({"capability", "identity", "sequence"} & set(frame)) for frame in frames)
    assert any(frame["type"] == "command_started" and frame["command"] == "printf hello" for frame in frames)
    assert any(frame["type"] == "command_finished" for frame in frames)
    assert any(frame["type"] == "prompt_ready" for frame in frames)


def test_hook_path_spawns_no_processes_after_setup(
    bash_hook: Path, hook_env: tuple[dict[str, str], Path]
) -> None:
    env, capture = hook_env
    result = run_bash(
        f"source {bash_hook}; before=$(ps --ppid $$ -o pid= | wc -l); "
        "__termrecall_preexec 'printf hello'; __termrecall_prompt; "
        "after=$(ps --ppid $$ -o pid= | wc -l); sleep 0.05; termrecall_uninstall; "
        "printf 'before=%s after=%s\\n' \"$before\" \"$after\"",
        env,
    )
    assert result.returncode == 0, result.stderr
    fields = dict(item.split("=", 1) for item in result.stdout.strip().split())
    assert fields["before"] == fields["after"]
    assert capture.exists()


def test_nonblocking_full_pipe_fails_open_under_ten_milliseconds(
    bash_hook: Path, hook_env: tuple[dict[str, str], Path]
) -> None:
    env, _ = hook_env
    result = run_bash(
        f"source {bash_hook}; kill -STOP $TERMRECALL_BRIDGE_PID; "
        "frame='{\"schema_version\":1,\"type\":\"prompt_ready\",\"shell_id\":\"'$TERMRECALL_SHELL_ID'\",\"cwd\":\"/tmp\"}'; "
        "while __termrecall_queue \"$frame\" && [[ -n ${TERMRECALL_BRIDGE_FD-} ]]; do :; done; "
        "start=${EPOCHREALTIME/./}; __termrecall_prompt; status=$?; end=${EPOCHREALTIME/./}; elapsed=$((end-start)); "
        "printf 'status=%s elapsed_us=%s fd=%s\\n' \"$status\" \"$elapsed\" \"${TERMRECALL_BRIDGE_FD-unset}\"; "
        "kill -CONT $TERMRECALL_BRIDGE_PID 2>/dev/null || :; termrecall_uninstall",
        env,
    )
    assert result.returncode == 0, result.stderr
    fields = dict(item.split("=", 1) for item in result.stdout.strip().split())
    assert fields["status"] == "0"
    assert fields["fd"] == "unset"
    assert int(fields["elapsed_us"]) <= 10_000


def _captured_frames(capture: Path) -> list[dict[str, object]]:
    if not capture.exists():
        return []
    return [json.loads(line) for line in capture.read_text().splitlines()]


def test_exit_wrapper_preserves_old_trap_status_without_explicit_exit(
    bash_hook: Path, hook_env: tuple[dict[str, str], Path]
) -> None:
    env, capture = hook_env
    result = run_bash(
        f"trap 'printf old-exit-status=%s\\n \"$?\"' EXIT; source {bash_hook}; "
        "trap - DEBUG; false; __termrecall_exit_trap; wrapper=$?; "
        "sleep 0.05; termrecall_uninstall; trap - EXIT; printf 'wrapper=%s\\n' \"$wrapper\"",
        env,
    )
    assert result.returncode == 0, result.stderr
    assert "old-exit-status=1" in result.stdout
    assert "wrapper=1" in result.stdout
    assert not [frame for frame in _captured_frames(capture) if frame["type"] == "explicit_exit"]


def test_literal_exit_is_emitted_exactly_once_but_eof_and_wrapper_are_not(
    bash_hook: Path, hook_env: tuple[dict[str, str], Path]
) -> None:
    env, capture = hook_env
    result = run_bash(
        f"source {bash_hook}; __termrecall_busy=1; trap - DEBUG; __termrecall_busy=0; __termrecall_preexec exit; "
        "__termrecall_preexec exit; __termrecall_exit_trap; "
        "sleep 0.05; termrecall_uninstall",
        env,
    )
    assert result.returncode == 0, result.stderr
    frames = _captured_frames(capture)
    assert [frame["type"] for frame in frames].count("explicit_exit") == 1
    assert not [frame for frame in frames if frame["type"] == "command_started"]


def test_queue_uses_builtin_printf_despite_hostile_shell_function(
    bash_hook: Path, hook_env: tuple[dict[str, str], Path]
) -> None:
    env, capture = hook_env
    result = run_bash(
        f"source {bash_hook}; __termrecall_busy=1; trap - DEBUG; __termrecall_busy=0; "
        "printf_calls=0; printf() { ((printf_calls++)); return 99; }; "
        "__termrecall_busy=1; unset __termrecall_active_sequence; __termrecall_busy=0; "
        "__termrecall_preexec 'hostile-proof'; __termrecall_prompt; sleep 0.05; "
        "termrecall_uninstall; builtin printf 'calls=%s\\n' \"$printf_calls\"",
        env,
    )
    assert result.returncode == 0, result.stderr
    assert "calls=0" in result.stdout
    frames = _captured_frames(capture)
    assert any(frame.get("command") == "hostile-proof" for frame in frames)
    assert all(len(json.dumps(frame, separators=(",", ":")).encode()) + 1 <= 4096 for frame in frames)


@pytest.mark.parametrize("literal", ["exit", "logout"])
def test_natural_literal_exit_wins_over_active_command_and_emits_once(
    bash_hook: Path,
    hook_env: tuple[dict[str, str], Path],
    literal: str,
) -> None:
    env, capture = hook_env
    result = run_bash(
        f"shopt -s extdebug; source {bash_hook}; "
        "__termrecall_busy=1; unset __termrecall_active_sequence; __termrecall_busy=0; "
        f"true; {literal}; :; sleep 0.05; termrecall_uninstall",
        env,
    )
    assert result.returncode in {0, 1}, result.stderr
    frames = _captured_frames(capture)
    assert [frame["type"] for frame in frames].count("explicit_exit") == 1
    assert not [
        frame for frame in frames
        if frame["type"] == "command_started" and frame.get("command") in {"exit", "logout"}
    ]


def test_prior_debug_zero_naturally_allows_pending_command_after_failure(
    bash_hook: Path, hook_env: tuple[dict[str, str], Path]
) -> None:
    env, capture = hook_env
    result = run_bash(
        "shopt -s extdebug; marker=absent; seen=unset; "
        "prior_debug() { local incoming=$?; if [[ $BASH_COMMAND == *marker=executed* ]]; then seen=$incoming; return 0; fi; return 0; }; "
        f"trap prior_debug DEBUG; source {bash_hook}; "
        "__termrecall_busy=1; unset __termrecall_active_sequence; __termrecall_busy=0; false; marker=executed; "
        "active=$__termrecall_active_sequence; started=$TERMRECALL_COMMAND_SEQUENCE; __termrecall_prompt; "
        "sleep 0.05; termrecall_uninstall; printf 'marker=%s seen=%s active=%s started=%s\\n' \"$marker\" \"$seen\" \"$active\" \"$started\"",
        env,
    )
    assert result.returncode == 0, result.stderr
    assert "marker=executed seen=1" in result.stdout
    active = int(result.stdout.split("active=")[1].split()[0])
    started = int(result.stdout.split("started=")[1].split()[0])
    assert active == started and started > 0
    assert any(
        frame["type"] == "command_started" and frame["command_sequence"] == active
        for frame in _captured_frames(capture)
    )


def test_prior_debug_nonzero_naturally_suppresses_pending_command_and_lifecycle(
    bash_hook: Path, hook_env: tuple[dict[str, str], Path]
) -> None:
    env, capture = hook_env
    result = run_bash(
        "shopt -s extdebug; marker=absent; seen=unset; "
        "prior_debug() { local incoming=$?; if [[ $BASH_COMMAND == *marker=executed* ]]; then seen=$incoming; return 7; fi; return 0; }; "
        f"trap prior_debug DEBUG; source {bash_hook}; "
        "__termrecall_busy=1; unset __termrecall_active_sequence; __termrecall_busy=0; false; marker=executed; "
        "active=$__termrecall_active_sequence; started=$TERMRECALL_COMMAND_SEQUENCE; __termrecall_prompt; "
        "sleep 0.05; termrecall_uninstall; printf 'marker=%s seen=%s active=%s started=%s\\n' \"$marker\" \"$seen\" \"$active\" \"$started\"",
        env,
    )
    assert result.returncode == 0, result.stderr
    assert "marker=absent seen=1" in result.stdout
    assert not [frame for frame in _captured_frames(capture) if (frame.get("command") or "").endswith("marker=executed")]


def test_no_prior_debug_naturally_allows_pending_command_after_failure(
    bash_hook: Path, hook_env: tuple[dict[str, str], Path]
) -> None:
    env, capture = hook_env
    result = run_bash(
        f"shopt -s extdebug; marker=absent; source {bash_hook}; "
        "__termrecall_busy=1; unset __termrecall_active_sequence; __termrecall_busy=0; false; marker=executed; "
        "active=$__termrecall_active_sequence; started=$TERMRECALL_COMMAND_SEQUENCE; __termrecall_prompt; "
        "sleep 0.05; termrecall_uninstall; printf 'marker=%s active=%s started=%s\\n' \"$marker\" \"$active\" \"$started\"",
        env,
    )
    assert result.returncode == 0, result.stderr
    assert "marker=executed" in result.stdout
    active = int(result.stdout.split("active=")[1].split()[0])
    started = int(result.stdout.split("started=")[1].split()[0])
    assert active == started and started > 0
    assert any(
        frame["type"] == "command_started" and frame["command_sequence"] == active
        for frame in _captured_frames(capture)
    )


@pytest.mark.parametrize(
    "callbacks",
    [
        "PROMPT_COMMAND='printf external-looking-scalar >/dev/null'",
        "PROMPT_COMMAND=('printf external-looking-array >/dev/null' 'true')",
    ],
)
def test_prior_prompt_callbacks_run_under_guard_and_first_user_command_is_sequence_one(
    bash_hook: Path,
    hook_env: tuple[dict[str, str], Path],
    callbacks: str,
) -> None:
    env, capture = hook_env
    result = run_bash(
        f"{callbacks}; source {bash_hook}; __termrecall_busy=1; trap - DEBUG; __termrecall_busy=0; __termrecall_prompt; "
        "__termrecall_preexec 'printf actual-user'; __termrecall_prompt; "
        "sleep 0.05; termrecall_uninstall",
        env,
    )
    assert result.returncode == 0, result.stderr
    started = [frame for frame in _captured_frames(capture) if frame["type"] == "command_started"]
    assert [(frame["command_sequence"], frame["command"]) for frame in started] == [(1, "printf actual-user")]


@pytest.mark.parametrize(
    "callbacks",
    [
        ["printf pipeline-left", "printf pipeline-right"],
        ["true && printf and-right", "printf and-right"],
        ["false || printf or-right", "printf or-right"],
        ["printf one; printf two", "printf two"],
        ["function outer", "printf nested", "true"],
    ],
)
def test_active_command_ignores_nested_debug_callbacks_until_prompt(
    bash_hook: Path,
    hook_env: tuple[dict[str, str], Path],
    callbacks: list[str],
) -> None:
    env, capture = hook_env
    calls = "; ".join(f"__termrecall_preexec {subprocess.list2cmdline([command])}" for command in callbacks)
    result = run_bash(
        f"source {bash_hook}; __termrecall_busy=1; trap - DEBUG; __termrecall_busy=0; {calls}; false; __termrecall_prompt; "
        "sleep 0.05; termrecall_uninstall",
        env,
    )
    assert result.returncode == 0, result.stderr
    lifecycle = [frame for frame in _captured_frames(capture) if frame["type"] in {"command_started", "command_finished"}]
    assert [frame["type"] for frame in lifecycle] == ["command_started", "command_finished"]
    assert lifecycle[0]["command_sequence"] == lifecycle[1]["command_sequence"] == 1
    assert lifecycle[0]["command"] == callbacks[0]


def test_installed_bridge_fd_is_nonblocking_and_linux_pipe_buf_is_sufficient(
    bash_hook: Path, hook_env: tuple[dict[str, str], Path]
) -> None:
    env, _ = hook_env
    result = run_bash(
        f"source {bash_hook}; trap - DEBUG; "
        "flags=$(while read -r key value; do [[ $key == flags: ]] && printf '%s' \"$value\"; done <\"/proc/$$/fdinfo/$TERMRECALL_BRIDGE_FD\"); "
        "pipe_buf=$(getconf PIPE_BUF /proc/$$/fd/$TERMRECALL_BRIDGE_FD); "
        "printf 'flags=%s pipe_buf=%s\\n' \"$flags\" \"$pipe_buf\"; termrecall_uninstall",
        env,
    )
    assert result.returncode == 0, result.stderr
    fields = dict(item.split("=", 1) for item in result.stdout.strip().split())
    assert int(fields["flags"], 8) & os.O_NONBLOCK
    assert int(fields["pipe_buf"]) >= 4096


def test_pipe_contention_delivers_only_complete_frames(
    bash_hook: Path, hook_env: tuple[dict[str, str], Path]
) -> None:
    env, capture = hook_env
    result = run_bash(
        f"source {bash_hook}; trap - DEBUG; "
        "for ((i=1; i<=200; i++)); do __termrecall_preexec \"printf command-$i\"; __termrecall_prompt; done; "
        "sleep 0.1; termrecall_uninstall",
        env,
        timeout=5,
    )
    assert result.returncode == 0, result.stderr
    lines = capture.read_bytes().splitlines(keepends=True)
    assert lines and all(line.endswith(b"\n") and len(line) <= 4096 for line in lines)
    assert all(isinstance(json.loads(line), dict) for line in lines)


def test_hook_path_uses_no_external_command_or_filesystem_write(
    bash_hook: Path, hook_env: tuple[dict[str, str], Path]
) -> None:
    env, capture = hook_env
    result = run_bash(
        f"source {bash_hook}; trap - DEBUG; "
        "printf() { builtin printf \"$@\"; }; "
        "command_not_found_handle() { builtin printf 'spawned=%s\\n' \"$1\"; return 127; }; "
        "before=$(find \"${TMPDIR:-/tmp}\" -maxdepth 1 -type f -newer \"$CAPTURE\" 2>/dev/null | wc -l); "
        "__termrecall_preexec 'printf controlled'; __termrecall_prompt; "
        "after=$(find \"${TMPDIR:-/tmp}\" -maxdepth 1 -type f -newer \"$CAPTURE\" 2>/dev/null | wc -l); "
        "sleep 0.05; termrecall_uninstall; builtin printf 'delta=%s\\n' \"$((after-before))\"",
        env,
    )
    assert result.returncode == 0, result.stderr
    assert "spawned=" not in result.stdout
    assert "delta=0" in result.stdout


def test_dead_bridge_hook_timing_is_bounded_repeatedly(
    bash_hook: Path, hook_env: tuple[dict[str, str], Path]
) -> None:
    env, _ = hook_env
    result = run_bash(
        f"source {bash_hook}; trap - DEBUG; kill $TERMRECALL_BRIDGE_PID; sleep 0.02; "
        "max=0; for ((i=0; i<100; i++)); do start=${EPOCHREALTIME/./}; __termrecall_prompt; end=${EPOCHREALTIME/./}; elapsed=$((end-start)); ((elapsed>max)) && max=$elapsed; done; "
        "printf 'max_us=%s\\n' \"$max\"; termrecall_uninstall",
        env,
    )
    assert result.returncode == 0, result.stderr
    assert int(result.stdout.strip().split("=")[-1]) <= 10_000
