# SPDX-License-Identifier: GPL-3.0-or-later
"""Task 5: local installer lifecycle CLI adapters.

These tests pin the public installed ``setup``/``autostart``/``uninstall``
commands, the hidden ``installer-bootstrap`` delegate entry, and the
service-independent dispatch boundary.  Exit codes follow
:class:`~termrecall.installer_contract.LifecycleExit` exactly for the
lifecycle commands; the service client constructor is never reached.
"""

from __future__ import annotations

import io
import itertools
import os
import shutil
import stat
import subprocess
import sys
import threading
from pathlib import Path
from typing import TextIO

import pytest

from termrecall import cli, installer
from termrecall.installer_contract import (
    DesiredState,
    IntegrationSetupRequest,
    LifecycleExit,
    LifecyclePaths,
    SetupMode,
    SetupRequest,
    resolve_lifecycle_paths,
)
from termrecall.installer_probe import (
    compute_plan_digest,
    plan_to_bytes,
    plan_from_bytes,
)

ROOT = Path(__file__).parents[2]
UID = os.getuid()
MARKER_NAME = ".termrecall-generation.json"


# ---------------------------------------------------------------------------
# environment + installed-state fixtures (mirror test_transactions helpers)
# ---------------------------------------------------------------------------


def _make_roots(tmp_path: Path) -> tuple[LifecyclePaths, dict[str, Path]]:
    home = tmp_path / "home"
    home.mkdir(parents=True, mode=0o700)
    paths = resolve_lifecycle_paths({}, home)
    roots = {
        "home": home, "data": paths.xdg_data_home, "config": paths.xdg_config_home,
        "state": paths.xdg_state_home, "bin": paths.bin_root,
        "temp": tmp_path / "tmp", "cache": tmp_path / "cache",
    }
    for root in roots.values():
        root.mkdir(parents=True, exist_ok=True)
        root.chmod(0o755)
    home.chmod(0o700)
    return paths, roots


def _source_tree(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    ignored = shutil.ignore_patterns(
        "__pycache__", ".pytest_cache", "*.pyc", "dist", "build", "*.egg-info",
        ".git", ".worktrees",
    )
    shutil.copytree(ROOT, source, ignore=ignored)
    for path in (source, *source.rglob("*")):
        path.chmod(path.stat().st_mode & ~0o022)
    return source


def _write_chooser(paths: LifecyclePaths, enabled: bool) -> None:
    from termrecall.lifecycle_integrations import render_chooser
    paths.config_root.mkdir(parents=True, exist_ok=True)
    paths.config_root.chmod(0o700)
    paths.chooser.write_bytes(render_chooser(enabled))
    paths.chooser.chmod(0o600)


def _write_bash_block(paths: LifecyclePaths) -> None:
    from termrecall.lifecycle_integrations import _v1_block  # type: ignore[attr-defined]
    paths.bashrc.parent.mkdir(parents=True, exist_ok=True)
    block = _v1_block(paths.bash_integration)
    paths.bashrc.write_bytes(b"alias ll='ls -l'\n\n" + block)
    paths.bashrc.chmod(0o644)
    paths.bash_integration.parent.mkdir(parents=True, exist_ok=True)
    paths.bash_integration.parent.chmod(0o700)
    paths.bash_integration.write_bytes(b"# integration\n")
    paths.bash_integration.chmod(0o600)


def _write_autostart(paths: LifecyclePaths) -> None:
    from termrecall.lifecycle_integrations import render_desktop
    paths.autostart.parent.mkdir(parents=True, exist_ok=True)
    paths.autostart.parent.chmod(0o700)
    paths.autostart.write_bytes(render_desktop(paths.current / "venv/bin/termrecall"))
    paths.autostart.chmod(0o600)


def _make_generation(paths: LifecyclePaths, gen_id: str) -> Path:
    import json
    gen = paths.generations / gen_id
    gen.parent.mkdir(parents=True, exist_ok=True)
    gen.parent.chmod(0o700)
    gen.mkdir(mode=0o700)
    venv_bin = gen / "venv/bin"
    venv_bin.mkdir(parents=True, mode=0o700)
    for name in ("termrecall", "termrecall-bridge", "termrecall-nonblock"):
        exe = venv_bin / name
        exe.write_bytes(b"#!/bin/sh\necho ok\n")
        exe.chmod(0o755)
    marker = gen / MARKER_NAME
    raw = json.dumps(
        {"schema": 2, "install_id": "install-1", "generation_id": gen_id, "path": str(gen), "nonce": "nonce-1"},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8") + b"\n"
    marker.write_bytes(raw)
    marker.chmod(0o600)
    return gen


def _install_prior(paths: LifecyclePaths, gen_id: str = "gen-1", *, bash=True, autostart=True, chooser_enabled=True) -> None:
    import hashlib
    from termrecall.installer_contract import (
        BeforeImage, ChooserOwnership, InstallManifest, MarkerIdentity,
        OwnedObject, ObjectKind, manifest_to_bytes,
    )
    gen = _make_generation(paths, gen_id)
    paths.current.parent.mkdir(parents=True, exist_ok=True)
    paths.current.parent.chmod(0o700)
    os.symlink(str(gen), str(paths.current))
    paths.bin_root.mkdir(parents=True, exist_ok=True)
    for link in paths.command_links:
        os.symlink(str(paths.current / f"venv/bin/{link.name}"), str(link))
    paths.config_root.mkdir(parents=True, exist_ok=True)
    paths.config_root.chmod(0o700)
    if bash:
        _write_bash_block(paths)
    if autostart:
        _write_autostart(paths)
    _write_chooser(paths, chooser_enabled)
    marker_path = paths.generations / gen_id / MARKER_NAME
    raw_marker = marker_path.read_bytes()
    owned = [
        OwnedObject(str(paths.current), ObjectKind.SYMLINK, 0o777, None, str(gen)),
        *(OwnedObject(str(link), ObjectKind.SYMLINK, 0o777, None, str(paths.current / f"venv/bin/{link.name}")) for link in paths.command_links),
    ]
    if paths.autostart.exists():
        content = paths.autostart.read_bytes()
        owned.append(OwnedObject(str(paths.autostart), ObjectKind.FILE, 0o600, hashlib.sha256(content).hexdigest(), None))
    if paths.chooser.exists():
        content = paths.chooser.read_bytes()
        owned.append(OwnedObject(str(paths.chooser), ObjectKind.FILE, 0o600, hashlib.sha256(content).hexdigest(), None))
    absent = BeforeImage(str(paths.chooser), ObjectKind.ABSENT, None, None, None, None)
    chooser_img = BeforeImage(str(paths.chooser), ObjectKind.FILE, 0o600, None, paths.chooser.read_bytes(), hashlib.sha256(paths.chooser.read_bytes()).hexdigest())
    chooser = ChooserOwnership(absent, chooser_img, True) if paths.chooser.exists() else ChooserOwnership(absent, None, False)
    manifest = InstallManifest(
        schema_version=2, installer_version="1.0", application_version="0.1.0",
        install_id="install-1", generation_id=gen_id,
        roots={"uid": UID, "data": str(paths.data_root), "config": str(paths.config_root), "state": str(paths.state_root), "bin": str(paths.bin_root)},
        marker=MarkerIdentity(str(marker_path), hashlib.sha256(raw_marker).hexdigest(), 0o600),
        owned=tuple(owned), created_parents=(), bash_enabled=bash, autostart_enabled=autostart,
        chooser=chooser, rollback_images=(), bash_backup=None,
    )
    paths.manifest.parent.mkdir(parents=True, exist_ok=True)
    paths.manifest.parent.chmod(0o700)
    paths.manifest.write_bytes(manifest_to_bytes(manifest))
    paths.manifest.chmod(0o600)


def _env_for(paths: LifecyclePaths) -> dict[str, str]:
    return {
        "HOME": str(paths.home),
        "XDG_DATA_HOME": str(paths.xdg_data_home),
        "XDG_CONFIG_HOME": str(paths.xdg_config_home),
        "XDG_STATE_HOME": str(paths.xdg_state_home),
        "PATH": os.environ.get("PATH", os.defpath),
    }


def _snapshot(paths: LifecyclePaths) -> dict:
    import hashlib
    snap: dict = {}
    for path in (paths.manifest, paths.current, *paths.command_links, paths.bashrc, paths.bash_integration, paths.autostart, paths.chooser, paths.state_root):
        try:
            st = path.lstat()
            if stat.S_ISLNK(st.st_mode):
                snap[str(path)] = ("symlink", stat.S_IMODE(st.st_mode), os.readlink(path))
            elif stat.S_ISREG(st.st_mode):
                snap[str(path)] = ("file", stat.S_IMODE(st.st_mode), hashlib.sha256(path.read_bytes()).hexdigest())
            elif stat.S_ISDIR(st.st_mode):
                snap[str(path)] = ("dir", stat.S_IMODE(st.st_mode))
            else:
                snap[str(path)] = ("other", stat.S_IMODE(st.st_mode))
        except FileNotFoundError:
            snap[str(path)] = None
    return snap


class TTY(io.StringIO):
    def isatty(self) -> bool:
        return True


# ---------------------------------------------------------------------------
# parser: public setup accepts only the three integration states
# ---------------------------------------------------------------------------


SETUP_TRIPLES = list(itertools.product(("enable", "disable", "preserve"), repeat=3))


@pytest.mark.parametrize("bash,autostart,chooser", SETUP_TRIPLES)
def test_setup_parses_every_integration_triple(bash, autostart, chooser) -> None:
    args = cli.build_parser().parse_args(["setup", "--bash", bash, "--autostart", autostart, "--chooser", chooser])
    assert (args.bash, args.autostart, args.chooser) == (bash, autostart, chooser)


def test_setup_defaults_every_state_to_preserve() -> None:
    args = cli.build_parser().parse_args(["setup"])
    assert (args.bash, args.autostart, args.chooser) == ("preserve", "preserve", "preserve")
    assert args.dry_run is False


def test_setup_accepts_dry_run() -> None:
    args = cli.build_parser().parse_args(["setup", "--dry-run"])
    assert args.dry_run is True


@pytest.mark.parametrize("argv", [
    ["setup", "--full"],
    ["setup", "--no-autostart"],
    ["setup", "--commands-only"],
    ["setup", "--upgrade"],
    ["setup", "--mode", "full"],
    ["setup", "--source-root", "/x"],
    ["setup", "--wheel", "/x.whl"],
    ["setup", "--expected-digest", "0" * 64],
    ["setup", "--request-fd", "3"],
    ["setup", "--plan-fd", "4"],
    ["setup", "--delegate-python", "/x"],
    ["setup", "positional"],
    ["setup", "--bash", "enable", "--bash", "disable"],
    ["setup", "--bash", "yellow"],
])
def test_setup_rejects_application_modes_source_probe_and_positionals(argv) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.build_parser().parse_args(argv)
    assert exc.value.code == 2


def test_autostart_parses_enable_or_disable() -> None:
    for setting in ("enable", "disable"):
        args = cli.build_parser().parse_args(["autostart", setting])
        assert args.setting == setting


def test_autostart_rejects_other_values() -> None:
    with pytest.raises(SystemExit) as exc:
        cli.build_parser().parse_args(["autostart", "always"])
    assert exc.value.code == 2


def test_uninstall_parses_yes_and_purge_flags() -> None:
    args = cli.build_parser().parse_args(["uninstall", "--yes", "--purge-state"])
    assert args.yes is True and args.purge_state is True


def test_hidden_installer_bootstrap_absent_from_public_help() -> None:
    parser = cli.build_parser()
    help_text = parser.format_help()
    assert "installer-bootstrap" not in help_text
    assert "setup" in help_text and "autostart" in help_text and "uninstall" in help_text


# ---------------------------------------------------------------------------
# run_integration_setup
# ---------------------------------------------------------------------------


def _run_setup(env, request: IntegrationSetupRequest, stdin: TextIO | None = None) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = installer.run_integration_setup(request, out, err)
    return code, out.getvalue(), err.getvalue()


def test_run_integration_setup_dry_run_renders_dispositions_and_writes_zero(tmp_path, monkeypatch) -> None:
    paths, _ = _make_roots(tmp_path)
    _install_prior(paths)
    monkeypatch.setattr(installer, "_lifecycle_paths", lambda: paths)
    before = _snapshot(paths)
    request = IntegrationSetupRequest(dry_run=True, bash=DesiredState.DISABLE, autostart=DesiredState.DISABLE, chooser=DesiredState.PRESERVE)
    code, out, _ = _run_setup(_env_for(paths), request)
    assert code == int(LifecycleExit.OK)
    assert _snapshot(paths) == before
    assert "bash" in out and "autostart" in out and "disable" in out


def test_run_integration_setup_applies_bash_disable_and_rewrites_manifest(tmp_path, monkeypatch) -> None:
    from termrecall.installer_contract import manifest_from_bytes
    paths, _ = _make_roots(tmp_path)
    _install_prior(paths, bash=True)
    monkeypatch.setattr(installer, "_lifecycle_paths", lambda: paths)
    request = IntegrationSetupRequest(dry_run=False, bash=DesiredState.DISABLE, autostart=DesiredState.PRESERVE, chooser=DesiredState.PRESERVE)
    code, _, _ = _run_setup(_env_for(paths), request)
    assert code == int(LifecycleExit.OK)
    manifest = manifest_from_bytes(paths.manifest.read_bytes(), paths, UID)
    assert manifest.bash_enabled is False


def test_run_integration_setup_preserve_only_is_idempotent(tmp_path, monkeypatch) -> None:
    paths, _ = _make_roots(tmp_path)
    _install_prior(paths)
    monkeypatch.setattr(installer, "_lifecycle_paths", lambda: paths)
    before = _snapshot(paths)
    request = IntegrationSetupRequest(dry_run=False, bash=DesiredState.PRESERVE, autostart=DesiredState.PRESERVE, chooser=DesiredState.PRESERVE)
    code, _, _ = _run_setup(_env_for(paths), request)
    assert code == int(LifecycleExit.OK)
    assert _snapshot(paths) == before


def test_run_integration_setup_refused_without_manifest(tmp_path, monkeypatch) -> None:
    paths, _ = _make_roots(tmp_path)
    monkeypatch.setattr(installer, "_lifecycle_paths", lambda: paths)
    request = IntegrationSetupRequest(dry_run=False, bash=DesiredState.PRESERVE, autostart=DesiredState.ENABLE, chooser=DesiredState.PRESERVE)
    code, _, err = _run_setup(_env_for(paths), request)
    assert code == int(LifecycleExit.REFUSED)
    assert "manifest" in err


def test_setup_never_requires_runtime_dir_or_service(tmp_path, monkeypatch) -> None:
    paths, _ = _make_roots(tmp_path)
    _install_prior(paths)
    env = _env_for(paths)
    env.pop("XDG_RUNTIME_DIR", None)
    monkeypatch.setattr(installer, "_lifecycle_paths", lambda: paths)
    monkeypatch.setattr(cli, "_service_client", lambda: pytest.fail("service client must not be constructed for setup"))
    stdin, out, err = TTY(), io.StringIO(), io.StringIO()
    code = cli.run(["setup", "--bash", "disable"], stdin, out, err)
    assert code == int(LifecycleExit.OK)


# ---------------------------------------------------------------------------
# run_autostart
# ---------------------------------------------------------------------------


def test_run_autostart_disable_removes_desktop(tmp_path, monkeypatch) -> None:
    from termrecall.installer_contract import manifest_from_bytes
    paths, _ = _make_roots(tmp_path)
    _install_prior(paths, autostart=True)
    monkeypatch.setattr(installer, "_lifecycle_paths", lambda: paths)
    out, err = io.StringIO(), io.StringIO()
    code = installer.run_autostart("disable", out, err)
    assert code == int(LifecycleExit.OK)
    assert not paths.autostart.exists()
    manifest = manifest_from_bytes(paths.manifest.read_bytes(), paths, UID)
    assert manifest.autostart_enabled is False


def test_run_autostart_enable_recreates_desktop(tmp_path, monkeypatch) -> None:
    paths, _ = _make_roots(tmp_path)
    _install_prior(paths, autostart=True)
    paths.autostart.unlink()
    monkeypatch.setattr(installer, "_lifecycle_paths", lambda: paths)
    out, err = io.StringIO(), io.StringIO()
    code = installer.run_autostart("enable", out, err)
    assert code == int(LifecycleExit.OK)
    assert paths.autostart.exists()


def test_run_autostart_dispatches_before_service_client(tmp_path, monkeypatch) -> None:
    paths, _ = _make_roots(tmp_path)
    _install_prior(paths, autostart=True)
    monkeypatch.setattr(installer, "_lifecycle_paths", lambda: paths)
    monkeypatch.setattr(cli, "_service_client", lambda: pytest.fail("service client must not be constructed for autostart"))
    stdin, out, err = TTY(), io.StringIO(), io.StringIO()
    assert cli.run(["autostart", "disable"], stdin, out, err) == int(LifecycleExit.OK)


# ---------------------------------------------------------------------------
# run_uninstall
# ---------------------------------------------------------------------------


def _uninstall_args(**kwargs):
    return cli.build_parser().parse_args(["uninstall", *(["--yes"] if kwargs.get("yes") else []), *(["--purge-state"] if kwargs.get("purge_state") else [])])


def test_run_uninstall_yes_removes_app_bash_autostart_preserves_chooser_state(tmp_path, monkeypatch) -> None:
    paths, _ = _make_roots(tmp_path)
    _install_prior(paths, bash=True, autostart=True, chooser_enabled=True)
    paths.state_root.mkdir(parents=True, exist_ok=True)
    (paths.state_root / "recovery.db").write_bytes(b"data")
    monkeypatch.setattr(installer, "_lifecycle_paths", lambda: paths)
    stdin, out, err = io.StringIO(), io.StringIO(), io.StringIO()
    code = installer.run_uninstall(_uninstall_args(yes=True), stdin, out, err)
    assert code == int(LifecycleExit.OK)
    assert not paths.current.exists()
    assert not paths.manifest.exists()
    assert not paths.autostart.exists()
    for link in paths.command_links:
        assert not link.exists()
    # bash block removed
    assert b"termrecall v1" not in paths.bashrc.read_bytes()
    # chooser retained, state retained (no purge)
    assert paths.chooser.exists()
    assert paths.state_root.exists()
    assert (paths.state_root / "recovery.db").exists()


def test_run_uninstall_purge_state_requires_yes(tmp_path, monkeypatch) -> None:
    paths, _ = _make_roots(tmp_path)
    _install_prior(paths)
    monkeypatch.setattr(installer, "_lifecycle_paths", lambda: paths)
    stdin, out, err = io.StringIO(), io.StringIO(), io.StringIO()
    code = installer.run_uninstall(_uninstall_args(purge_state=True), stdin, out, err)
    assert code == 2
    assert paths.manifest.exists()  # nothing mutated


def test_run_uninstall_yes_purge_state_deletes_state(tmp_path, monkeypatch) -> None:
    paths, _ = _make_roots(tmp_path)
    _install_prior(paths, bash=True, autostart=True)
    paths.state_root.mkdir(parents=True, exist_ok=True)
    paths.state_root.chmod(0o700)
    (paths.state_root / "secret").write_bytes(b"x")
    monkeypatch.setattr(installer, "_lifecycle_paths", lambda: paths)
    stdin, out, err = io.StringIO(), io.StringIO(), io.StringIO()
    code = installer.run_uninstall(_uninstall_args(yes=True, purge_state=True), stdin, out, err)
    assert code == int(LifecycleExit.OK)
    assert not paths.state_root.exists()


def test_run_uninstall_interactive_invariant_reprompt_then_keep_app(tmp_path, monkeypatch) -> None:
    """app=yes with bash/autostart no re-prompts; declining app keeps it."""
    paths, _ = _make_roots(tmp_path)
    _install_prior(paths, bash=True, autostart=True)
    monkeypatch.setattr(installer, "_lifecycle_paths", lambda: paths)
    # app=y, bash=n, autostart=n, chooser=n, purge=n -> invariant loop
    # re-prompt bash=n autostart=n -> either stays no -> re-prompt app (keep? y) -> app kept
    answers = "y\nn\nn\nn\nn\nn\nn\ny\n"
    stdin, out, err = TTY(answers), io.StringIO(), io.StringIO()
    code = installer.run_uninstall(_uninstall_args(), stdin, out, err)
    assert code == int(LifecycleExit.OK)
    # application kept, nothing removed
    assert paths.current.exists() and paths.manifest.exists()
    assert paths.autostart.exists()


def test_run_uninstall_interactive_keeps_app_partial_autostart_removal(tmp_path, monkeypatch) -> None:
    from termrecall.installer_contract import manifest_from_bytes
    paths, _ = _make_roots(tmp_path)
    _install_prior(paths, bash=True, autostart=True)
    monkeypatch.setattr(installer, "_lifecycle_paths", lambda: paths)
    # keep application (n), remove autostart (y), keep bash (n), chooser no, purge no
    answers = "n\nn\ny\nn\nn\n"
    stdin, out, err = TTY(answers), io.StringIO(), io.StringIO()
    code = installer.run_uninstall(_uninstall_args(), stdin, out, err)
    assert code == int(LifecycleExit.OK)
    assert paths.current.exists() and paths.manifest.exists()  # app kept
    assert not paths.autostart.exists()  # autostart removed
    manifest = manifest_from_bytes(paths.manifest.read_bytes(), paths, UID)
    assert manifest.autostart_enabled is False


def test_run_uninstall_eof_at_initial_prompt_returns_two(tmp_path, monkeypatch) -> None:
    paths, _ = _make_roots(tmp_path)
    _install_prior(paths)
    monkeypatch.setattr(installer, "_lifecycle_paths", lambda: paths)
    stdin, out, err = TTY(""), io.StringIO(), io.StringIO()
    code = installer.run_uninstall(_uninstall_args(), stdin, out, err)
    assert code == 2


def test_run_uninstall_non_tty_interactive_returns_two(tmp_path, monkeypatch) -> None:
    paths, _ = _make_roots(tmp_path)
    _install_prior(paths)
    monkeypatch.setattr(installer, "_lifecycle_paths", lambda: paths)
    stdin, out, err = io.StringIO("y\n"), io.StringIO(), io.StringIO()
    code = installer.run_uninstall(_uninstall_args(), stdin, out, err)
    assert code == 2


def test_run_uninstall_final_decline_keeps_everything(tmp_path, monkeypatch) -> None:
    paths, _ = _make_roots(tmp_path)
    _install_prior(paths)
    monkeypatch.setattr(installer, "_lifecycle_paths", lambda: paths)
    before = _snapshot(paths)
    # decline application removal
    answers = "n\nn\nn\nn\nn\n"
    stdin, out, err = TTY(answers), io.StringIO(), io.StringIO()
    code = installer.run_uninstall(_uninstall_args(), stdin, out, err)
    assert code == int(LifecycleExit.OK)
    assert _snapshot(paths) == before


def test_run_uninstall_inconsistent_request_returns_usage(tmp_path, monkeypatch) -> None:
    paths, _ = _make_roots(tmp_path)
    _install_prior(paths)
    monkeypatch.setattr(installer, "_lifecycle_paths", lambda: paths)
    # Programmatic inconsistent request: remove_application without bash/autostart.
    args = _uninstall_args()
    # bypass interactive collection by forcing yes but inconsistent flags via direct namespace
    args.yes = True
    args.purge_state = False
    # craft an inconsistent request by monkeypatching the builder
    from termrecall.installer_contract import UninstallRequest
    monkeypatch.setattr(installer, "_yes_uninstall_request", lambda purge: UninstallRequest(True, False, False, False, purge, True))
    stdin, out, err = io.StringIO(), io.StringIO(), io.StringIO()
    code = installer.run_uninstall(args, stdin, out, err)
    assert code == int(LifecycleExit.USAGE)


def test_run_uninstall_dispatches_before_service_client(tmp_path, monkeypatch) -> None:
    paths, _ = _make_roots(tmp_path)
    _install_prior(paths)
    monkeypatch.setattr(installer, "_lifecycle_paths", lambda: paths)
    monkeypatch.setattr(cli, "_service_client", lambda: pytest.fail("service client must not be constructed for uninstall"))
    stdin, out, err = TTY(""), io.StringIO(), io.StringIO()
    assert cli.run(["uninstall", "--yes"], stdin, out, err) == int(LifecycleExit.OK)


# ---------------------------------------------------------------------------
# hidden installer-bootstrap
# ---------------------------------------------------------------------------


def _canonical_request(source: Path, paths: LifecyclePaths, *, mode="full", bash="enable", autostart="enable", chooser="enable", dry_run=False) -> dict:
    return {
        "request_schema": 1, "source_root": str(source), "home": str(paths.home),
        "xdg_data_home": str(paths.xdg_data_home), "xdg_config_home": str(paths.xdg_config_home),
        "xdg_state_home": str(paths.xdg_state_home), "mode": mode, "bash": bash,
        "autostart": autostart, "chooser": chooser, "dry_run": dry_run,
    }


def _run_source_plan(source: Path, paths: LifecyclePaths, *, mode="full") -> bytes:
    argv = [
        sys.executable, "-I", "-B", str(source / "installer_probe.py"), "plan",
        "--source-root", str(source), "--home", str(paths.home),
        "--xdg-data-home", str(paths.xdg_data_home), "--xdg-config-home", str(paths.xdg_config_home),
        "--xdg-state-home", str(paths.xdg_state_home), "--mode", mode, "--bash", "enable",
        "--autostart", "enable", "--chooser", "enable", "--dry-run", "no",
    ]
    completed = subprocess.run(argv, env={"PATH": os.environ["PATH"], "PYTHONDONTWRITEBYTECODE": "1"}, capture_output=True, check=False)
    assert completed.returncode == 0, completed.stderr.decode()
    return completed.stdout


def _write_payload_in_thread(fd: int, payload: bytes) -> threading.Thread:
    def deliver():
        try:
            os.write(fd, payload)
        except OSError:
            pass
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
    thread = threading.Thread(target=deliver)
    thread.start()
    return thread


def test_installer_bootstrap_incomplete_invocation_refused(tmp_path) -> None:
    code = installer.installer_bootstrap(["--request-fd", "3"])
    assert code == 2


def test_installer_bootstrap_rejects_public_setup_fields(tmp_path) -> None:
    code = installer.installer_bootstrap(["--request-fd", "3", "--plan-fd", "4", "--expected-digest", "0" * 64, "--wheel", "/x", "--bash", "enable"])
    assert code == 2


def test_installer_bootstrap_digest_mismatch_refused(tmp_path) -> None:
    paths, _ = _make_roots(tmp_path)
    source = _source_tree(tmp_path)
    plan_raw = _run_source_plan(source, paths)
    request = _canonical_request(source, paths)
    request_raw = plan_to_bytes(request)  # canonical request bytes
    digest = "0" * 64  # wrong digest
    request_r, request_w = os.pipe()
    plan_r, plan_w = os.pipe()
    t1 = _write_payload_in_thread(request_w, request_raw)
    t2 = _write_payload_in_thread(plan_w, plan_raw)
    try:
        code = installer.installer_bootstrap([
            "--request-fd", str(request_r), "--plan-fd", str(plan_r),
            "--expected-digest", digest, "--wheel", str(source / "dummy.whl"),
        ])
    finally:
        for fd in (request_r, plan_r):
            try:
                os.close(fd)
            except OSError:
                pass
        t1.join(); t2.join()
    assert code == int(LifecycleExit.REFUSED)


def test_installer_bootstrap_payload_overflow_refused_and_descriptors_closed(tmp_path) -> None:
    paths, _ = _make_roots(tmp_path)
    source = _source_tree(tmp_path)
    plan_raw = _run_source_plan(source, paths)
    request = _canonical_request(source, paths)
    # Build an oversized request payload (65,537 bytes) by appending valid JSON padding? 
    # Instead, pass an oversized plan payload (>65,536 bytes).
    oversized = b"{" + b",".join(b'"k%d":"%s"' % (i, b"x" * 10) for i in range(9000)) + b"}\n"
    assert len(oversized) > 65536
    digest = compute_plan_digest(plan_from_bytes(plan_raw, request))
    request_r, request_w = os.pipe()
    plan_r, plan_w = os.pipe()
    t1 = _write_payload_in_thread(request_w, plan_to_bytes(request))
    t2 = _write_payload_in_thread(plan_w, oversized)
    fds_closed: list[bool] = []
    try:
        code = installer.installer_bootstrap([
            "--request-fd", str(request_r), "--plan-fd", str(plan_r),
            "--expected-digest", digest, "--wheel", str(source / "dummy.whl"),
        ])
        # after return, read fds must be closed by bootstrap
        for fd in (request_r, plan_r):
            try:
                os.fstat(fd)
                fds_closed.append(False)
            except OSError:
                fds_closed.append(True)
    finally:
        for fd in (request_r, plan_r):
            try:
                os.close(fd)
            except OSError:
                pass
        t1.join(); t2.join()
    assert code == int(LifecycleExit.REFUSED)
    assert all(fds_closed)


def test_installer_bootstrap_fresh_install_succeeds(tmp_path) -> None:
    paths, _ = _make_roots(tmp_path)
    source = _source_tree(tmp_path)
    plan_raw = _run_source_plan(source, paths)
    request = _canonical_request(source, paths)
    plan = plan_from_bytes(plan_raw, request)
    digest = compute_plan_digest(plan)
    request_raw = plan_to_bytes(request)
    request_r, request_w = os.pipe()
    plan_r, plan_w = os.pipe()
    t1 = _write_payload_in_thread(request_w, request_raw)
    t2 = _write_payload_in_thread(plan_w, plan_raw)
    try:
        code = installer.installer_bootstrap([
            "--request-fd", str(request_r), "--plan-fd", str(plan_r),
            "--expected-digest", digest, "--wheel", str(source / "dummy.whl"),
        ])
    finally:
        for fd in (request_r, plan_r):
            try:
                os.close(fd)
            except OSError:
                pass
        t1.join(); t2.join()
    assert code == int(LifecycleExit.OK)
    assert paths.current.exists()
    assert paths.manifest.exists()
    for link in paths.command_links:
        assert link.exists()


def test_installer_bootstrap_not_exposed_via_public_cli_help(tmp_path) -> None:
    # the public termrecall CLI must not accept installer-bootstrap
    parser = cli.build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["installer-bootstrap", "--request-fd", "3"])
    assert exc.value.code == 2
