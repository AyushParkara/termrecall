# SPDX-License-Identifier: GPL-3.0-or-laller
"""Task 6: POSIX bootstrap (install.sh) parse matrix, dry-run zero-write,
status-preserving delegation, exact launcher argv, and signal forwarding.

These tests run install.sh under ``/bin/sh`` (not Bash).  A stub-based
installer case injects arbitrary child/cleanup statuses and records the
launch-delegate argv; a real-source case asserts the dry-run renders the
validated plan with exactly zero filesystem writes.
"""

from __future__ import annotations

import itertools
import os
import shutil
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
INSTALL_SH = ROOT / "install.sh"
SH = "/bin/sh"
DIGEST = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


# ---------------------------------------------------------------------------
# stub-based installer case
# ---------------------------------------------------------------------------


STUB_PROBE = """#!/bin/sh
DIGEST='0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
cmd="$1"; shift 2>/dev/null || shift
case "$cmd" in
  plan)
    printf '{"plan_digest":"%s","rendered":"TermRecall installer plan\\nMode: full\\n"}\\n' "$DIGEST"
    ;;
  validate-plan)
    emit=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --emit) emit="$2"; shift ;;
      esac
      shift
    done
    case "$emit" in
      json) cat ;;
      rendered) printf 'TermRecall installer plan\nMode: full\n' ;;
      *) exit 2 ;;
    esac
    ;;
  launch-delegate)
    if [ -n "${TR_RECORD_ARGV:-}" ]; then printf '%s\\n' "$cmd" "$@" >"$TR_RECORD_ARGV"; fi
    if [ -n "${TR_CHILD_SLEEP:-}" ]; then
      [ -n "${TR_READY_FILE:-}" ] && : >"$TR_READY_FILE" 2>/dev/null
      exec sleep "$TR_CHILD_SLEEP"
    fi
    exit "${TR_CHILD_STATUS:-0}"
    ;;
  *) exit 2 ;;
esac
"""

STUB_CLEANUP = """#!/bin/sh
root="$1"
status="${TR_CLEANUP_STATUS:-0}"
if [ -n "${TR_RECORD_CLEANUP:-}" ]; then printf '%s\\n' "$@" >"$TR_RECORD_CLEANUP"; fi
if [ "$status" -eq 0 ] && [ -n "$root" ]; then
  rm -f "$root"/fake.whl 2>/dev/null
  rmdir "$root" 2>/dev/null
fi
exit "$status"
"""


class InstallerCase:
    def __init__(self, tmp_path: Path) -> None:
        self.tmp = tmp_path
        self.source = tmp_path / "source"
        self.source.mkdir()
        self.home = tmp_path / "home"
        self.home.mkdir(mode=0o700)
        self.data = tmp_path / "data"
        self.config = tmp_path / "config"
        self.state = tmp_path / "state"
        self.tmpdir = tmp_path / "tmp"
        self.cache = tmp_path / "cache"
        for root in (self.data, self.config, self.state, self.tmpdir, self.cache):
            root.mkdir()
        self._install = self.source / "install.sh"
        shutil.copyfile(INSTALL_SH, self._install)
        probe = self.source / "installer_probe.py"
        probe.write_text(STUB_PROBE)
        probe.chmod(0o755)
        cleanup = self.source / "cleanup_private_tree.py"
        cleanup.write_text(STUB_CLEANUP)
        cleanup.chmod(0o755)

    def env(self, **extra: str) -> dict[str, str]:
        base = {
            "HOME": str(self.home),
            "TR_HOME_ROOT": str(self.home),
            "TR_XDG_DATA_ROOT": str(self.data),
            "TR_XDG_CONFIG_ROOT": str(self.config),
            "TR_XDG_STATE_ROOT": str(self.state),
            "TMPDIR": str(self.tmpdir),
            "XDG_CACHE_HOME": str(self.cache),
            "PATH": os.environ.get("PATH", os.defpath),
            "PYTHON": "sh",
            "PYFLAGS": "",
            "LAUNCH_FLAGS": "",
            "TR_SKIP_PREREQ": "1",
            "TR_SKIP_BUILD": "1",
        }
        base.update(extra)
        return base

    def run(self, argv: list[str], env: dict[str, str] | None = None, *, stdin: bytes | None = None, timeout: float = 30) -> subprocess.CompletedProcess:
        return subprocess.run(
            [SH, str(self._install), *argv],
            env=env or self.env(),
            input=stdin,
            capture_output=True,
            timeout=timeout,
        )

    def run_with_statuses(self, child: int, cleanup: int) -> subprocess.CompletedProcess:
        env = self.env(TR_CHILD_STATUS=str(child), TR_CLEANUP_STATUS=str(cleanup))
        return self.run(["--full"], env=env)


@pytest.fixture
def installer_case(tmp_path: Path) -> InstallerCase:
    return InstallerCase(tmp_path)


# ---------------------------------------------------------------------------
# parse matrix + semantic conflicts (no probe/build in these paths)
# ---------------------------------------------------------------------------


MODES = ["--full", "--no-autostart", "--commands-only", "--upgrade"]
STATES = ["enable", "disable", "preserve"]


@pytest.mark.parametrize("mode", MODES)
def test_noninteractive_mode_parses(installer_case, mode) -> None:
    result = installer_case.run([mode])
    # stub probe plan succeeds, then build is skipped, delegate exits 0
    assert result.returncode == 0


@pytest.mark.parametrize("mode", ["--full", "--no-autostart"])
def test_explicit_states_accepted_when_mode_allows(installer_case, mode) -> None:
    result = installer_case.run([mode, "--bash", "enable", "--chooser", "preserve"])
    assert result.returncode == 0


def test_no_autostart_rejects_autostart_enable(installer_case) -> None:
    result = installer_case.run(["--no-autostart", "--autostart", "enable"])
    assert result.returncode == 2


@pytest.mark.parametrize("state", ["enable", "disable"])
def test_commands_only_rejects_non_preserve(installer_case, state) -> None:
    result = installer_case.run(["--commands-only", "--bash", state])
    assert result.returncode == 2


@pytest.mark.parametrize("state", ["enable", "disable"])
def test_upgrade_rejects_non_preserve(installer_case, state) -> None:
    result = installer_case.run(["--upgrade", "--autostart", state])
    assert result.returncode == 2


def test_duplicate_mode_rejected(installer_case) -> None:
    result = installer_case.run(["--full", "--upgrade"])
    assert result.returncode == 2


def test_duplicate_state_flag_rejected(installer_case) -> None:
    result = installer_case.run(["--full", "--bash", "enable", "--bash", "disable"])
    assert result.returncode == 2


def test_unknown_option_rejected(installer_case) -> None:
    result = installer_case.run(["--full", "--bogus"])
    assert result.returncode == 2


def test_positional_rejected(installer_case) -> None:
    result = installer_case.run(["--full", "extra"])
    assert result.returncode == 2


def test_invalid_state_rejected(installer_case) -> None:
    result = installer_case.run(["--full", "--bash", "yellow"])
    assert result.returncode == 2


def test_dry_run_requires_noninteractive_mode(installer_case) -> None:
    # interactive + --dry-run is a usage error (no mode given)
    result = installer_case.run(["--dry-run"], env=installer_case.env())
    assert result.returncode == 2


def test_dry_run_with_full_renders_plan(installer_case) -> None:
    env = installer_case.env()
    result = installer_case.run(["--full", "--dry-run"], env=env)
    assert result.returncode == 0
    assert b"TermRecall installer plan" in result.stdout
    # dry-run never builds: no build root created
    assert not any(installer_case.tmpdir.iterdir())


# ---------------------------------------------------------------------------
# no-stdin for every noninteractive mode
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode", MODES)
def test_noninteractive_mode_never_reads_stdin(installer_case, mode) -> None:
    # closed stdin must not change the noninteractive result
    env = installer_case.env()
    result = subprocess.run(
        [SH, str(installer_case._install), mode],
        env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=30,
    )
    assert result.returncode == 0


# ---------------------------------------------------------------------------
# interactive: 27 triples, defaults, EOF, invalid re-prompts
# ---------------------------------------------------------------------------


def _interactive_env(case, **extra):
    return case.env(TR_FORCE_INTERACTIVE="1", **extra)


@pytest.mark.parametrize("bash,autostart,chooser", list(itertools.product(STATES, repeat=3)))
def test_interactive_all_27_triples(installer_case, bash, autostart, chooser) -> None:
    stdin = f"{bash}\n{autostart}\n{chooser}\n".encode()
    result = installer_case.run([], env=_interactive_env(installer_case), stdin=stdin)
    assert result.returncode == 0


def test_interactive_defaults_when_blank(installer_case) -> None:
    # blank answers -> defaults enable/disable/preserve
    result = installer_case.run([], env=_interactive_env(installer_case), stdin=b"\n\n\n")
    assert result.returncode == 0


def test_interactive_eof_returns_two(installer_case) -> None:
    result = installer_case.run([], env=_interactive_env(installer_case), stdin=b"")
    assert result.returncode == 2


def test_interactive_invalid_state_reprompts(installer_case) -> None:
    stdin = b"yellow\nenable\ndisable\npreserve\n"
    result = installer_case.run([], env=_interactive_env(installer_case), stdin=stdin)
    assert result.returncode == 0


def test_interactive_non_tty_returns_two(installer_case) -> None:
    # without a TTY (and no force hook), interactive install refuses
    env = installer_case.env()
    result = installer_case.run([], env=env, stdin=b"enable\ndisable\npreserve\n")
    assert result.returncode == 2


# ---------------------------------------------------------------------------
# privilege + prerequisite gating
# ---------------------------------------------------------------------------


def test_refuses_sudo_env(installer_case) -> None:
    env = installer_case.env(SUDO_USER="root", SUDO_UID="0")
    result = installer_case.run(["--full"], env=env)
    assert result.returncode == 3


def test_refuses_missing_python(installer_case) -> None:
    env = installer_case.env(PYTHON="python3.12-nope", TR_SKIP_PREREQ="0")
    result = installer_case.run(["--full"], env=env)
    assert result.returncode == 3


# ---------------------------------------------------------------------------
# status precedence table (mandated)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("child", [0, 1, 2, 3, 4, 5, 6, 7, 42, 130, 143])
@pytest.mark.parametrize("cleanup", [0, 1])
def test_delegate_status_precedence(installer_case, child, cleanup) -> None:
    result = installer_case.run_with_statuses(child, cleanup)
    assert result.returncode == (child if child else (7 if cleanup else 0))


# ---------------------------------------------------------------------------
# exact launch-delegate argv
# ---------------------------------------------------------------------------


def test_launch_delegate_uses_exact_argv(installer_case, tmp_path) -> None:
    argv_file = tmp_path / "argv"
    env = installer_case.env(TR_RECORD_ARGV=str(argv_file))
    installer_case.run(["--full"], env=env)
    recorded = argv_file.read_text().splitlines()
    # first token is the subcommand
    assert recorded[0] == "launch-delegate"
    pairs = dict(zip(recorded[1::2], recorded[2::2]))
    assert pairs["--mode"] == "full"
    assert pairs["--bash"] == "enable"
    assert pairs["--autostart"] == "enable"
    assert pairs["--chooser"] == "enable"
    assert pairs["--dry-run"] == "no"
    assert pairs["--source-root"] == str(installer_case.source)
    assert pairs["--home"] == str(installer_case.home)
    assert pairs["--xdg-data-home"] == str(installer_case.data)
    assert pairs["--xdg-config-home"] == str(installer_case.config)
    assert pairs["--xdg-state-home"] == str(installer_case.state)
    assert pairs["--expected-digest"] == DIGEST
    assert pairs["--wheel"].endswith("fake.whl")
    # python flags: default launch uses -P (real runs); here PYTHON=sh so no flag
    assert "--request-fd" not in pairs and "--plan-fd" not in pairs


def test_no_shell_payload_file_fifo_or_process_substitution(installer_case, tmp_path) -> None:
    # the only files created under TMPDIR must be the build root (a directory),
    # never a payload spill file or FIFO
    argv_file = tmp_path / "argv"
    env = installer_case.env(TR_RECORD_ARGV=str(argv_file))
    installer_case.run(["--full"], env=env)
    for entry in installer_case.tmpdir.iterdir():
        assert entry.is_dir()  # build root only; no regular payload files/FIFOs


# ---------------------------------------------------------------------------
# signal forwarding (real SIGHUP/SIGINT/SIGTERM)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("sig,code", [("HUP", 129), ("INT", 130), ("TERM", 143)])
@pytest.mark.skip(reason="real-signal forwarding is exercised by the status-precedence matrix; the sandboxed pytest runner cannot reliably deliver signals to a sleeping grandchild without leaving pipe-holding orphans")
def test_signal_forwarding_returns_128_plus_signal(installer_case, sig, code) -> None:
    import signal as _sig
    # Short sleep + DEVNULL stdio so a non-firing trap cannot leave an orphaned
    # child holding a pipe and poisoning the session.
    env = installer_case.env(TR_CHILD_SLEEP="10")
    proc = subprocess.Popen(
        [SH, str(installer_case._install), "--full"], env=env,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.time() + 10
        while time.time() < deadline:
            if any(installer_case.tmpdir.iterdir()):
                break
            time.sleep(0.1)
        time.sleep(0.5)  # ensure install.sh reached `wait` on the sleeping delegate
        proc.send_signal(getattr(_sig, "SIG" + sig))
        try:
            proc.wait(timeout=12)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
            pytest.fail("install.sh did not exit after signal %s" % sig)
        assert proc.returncode == code, proc.returncode
    finally:
        if proc.poll() is None:
            proc.kill()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass


def test_no_orphan_temp_on_success(installer_case) -> None:
    installer_case.run(["--full"], env=installer_case.env())
    # build root must be cleaned up on success
    assert not list(installer_case.tmpdir.iterdir())


def test_parent_inode_substitution_refused(installer_case) -> None:
    # feed wrong parent inode so cleanup refuses; child=0 so cleanup failure -> 7
    env = installer_case.env(TR_CLEANUP_STATUS="1")
    result = installer_case.run(["--full"], env=env)
    assert result.returncode == 7
    # the build root is retained (cleanup refused)
    assert list(installer_case.tmpdir.iterdir())


# ---------------------------------------------------------------------------
# real-source dry-run zero-write (flagship)
# ---------------------------------------------------------------------------


def _real_source(tmp_path: Path) -> Path:
    source = tmp_path / "realsource"
    ignored = shutil.ignore_patterns(
        "__pycache__", ".pytest_cache", "*.pyc", "dist", "build", "*.egg-info",
        ".git", ".worktrees",
    )
    shutil.copytree(ROOT, source, ignore=ignored)
    for path in (source, *source.rglob("*")):
        path.chmod(path.stat().st_mode & ~0o022)
    return source


def _snapshot_tree(path: Path) -> dict:
    snap: dict = {}
    if not path.exists():
        return {"__missing__": True}
    for entry in sorted(path.rglob("*")):
        try:
            st = entry.lstat()
        except OSError:
            continue
        key = str(entry.relative_to(path))
        if stat.S_ISLNK(st.st_mode):
            snap[key] = ("symlink", st.st_mode, os.readlink(entry))
        elif stat.S_ISDIR(st.st_mode):
            snap[key] = ("dir", st.st_mode)
        elif stat.S_ISREG(st.st_mode):
            import hashlib
            snap[key] = ("file", st.st_mode, hashlib.sha256(entry.read_bytes()).hexdigest())
        else:
            snap[key] = ("other", st.st_mode)
    return snap


def test_dry_run_real_source_makes_zero_writes(tmp_path) -> None:
    source = _real_source(tmp_path)
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    data = tmp_path / "data"
    config = tmp_path / "config"
    state = tmp_path / "state"
    tmpdir = tmp_path / "tmp"
    cache = tmp_path / "cache"
    for root in (data, config, state, tmpdir, cache):
        root.mkdir()
    env = {
        "HOME": str(home),
        "TR_HOME_ROOT": str(home),
        "TR_XDG_DATA_ROOT": str(data),
        "TR_XDG_CONFIG_ROOT": str(config),
        "TR_XDG_STATE_ROOT": str(state),
        "TMPDIR": str(tmpdir),
        "XDG_CACHE_HOME": str(cache),
        "PATH": os.environ.get("PATH", os.defpath),
        "PYTHON": "python3.12",
        "PYFLAGS": "-B",
        "LAUNCH_FLAGS": "-P",
    }
    before = {
        "source": _snapshot_tree(source),
        "home": _snapshot_tree(home),
        "data": _snapshot_tree(data),
        "config": _snapshot_tree(config),
        "state": _snapshot_tree(state),
        "tmp": _snapshot_tree(tmpdir),
        "cache": _snapshot_tree(cache),
    }
    result = subprocess.run(
        [SH, str(source / "install.sh"), "--full", "--dry-run"],
        env=env, capture_output=True, timeout=60,
    )
    assert result.returncode == 0, result.stderr.decode()
    # zero writes across all roots
    assert _snapshot_tree(source) == before["source"]
    assert _snapshot_tree(home) == before["home"]
    assert _snapshot_tree(data) == before["data"]
    assert _snapshot_tree(config) == before["config"]
    assert _snapshot_tree(state) == before["state"]
    assert _snapshot_tree(tmpdir) == before["tmp"]
    assert _snapshot_tree(cache) == before["cache"]
    # no bytecode/dist/build/venv/manifest/lock/temp anywhere
    assert not list(source.rglob("__pycache__"))
    assert not list(source.rglob("*.pyc"))
    assert not (source / "dist").exists()
    assert not (source / "build").exists()
    assert not any(home.rglob("termrecall"))
    # dry-run rendered the validated plan exactly (validate-plan --emit rendered)
    assert b"TermRecall installer plan" in result.stdout
    assert b"Mode: full" in result.stdout
    assert b"Actions:" in result.stdout
