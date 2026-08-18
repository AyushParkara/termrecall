# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import fcntl
import json
import os
import socket
from pathlib import Path

import pytest

from termrecall.adapters.base import AdapterCapabilities
from termrecall.doctor import Diagnostic, cleanup_stale_socket, run_doctor
from termrecall.paths import XDGPaths


class Adapter:
    def __init__(self, detected: bool = True) -> None:
        self.detected = detected

    def detect(self) -> bool:
        return self.detected

    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(True, True, False, False, False, True, False)

    def plan(self, items: object) -> tuple[()]:
        return ()

    def execute(self, actions: object, attempt_id: str) -> tuple[()]:
        return ()


def paths(tmp_path: Path) -> XDGPaths:
    runtime = tmp_path / "run" / "termrecall"
    state = tmp_path / "state" / "termrecall"
    config = tmp_path / "config" / "termrecall"
    runtime.mkdir(parents=True, mode=0o700)
    runtime.chmod(0o700)
    state.mkdir(parents=True, mode=0o700)
    state.chmod(0o700)
    config.mkdir(parents=True, mode=0o700)
    return XDGPaths(runtime, state, config)


def install_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    hook = tmp_path / "termrecall.bash"
    hook.write_text("# hook\n")
    helper = tmp_path / "termrecall-nonblock"
    helper.write_text("helper\n")
    helper.chmod(0o755)
    chooser = tmp_path / "termrecall.desktop"
    chooser.write_text("[Desktop Entry]\n")
    monkeypatch.setattr("termrecall.doctor.BASH_HOOK_PATH", hook)
    monkeypatch.setattr("termrecall.doctor.NATIVE_HELPER_PATH", helper)
    monkeypatch.setattr("termrecall.doctor.CHOOSER_PATH", chooser)
    monkeypatch.setattr("termrecall.doctor.read_boot_id", lambda: "00000000-0000-0000-0000-000000000000")
    monkeypatch.setattr("termrecall.doctor.shutil.which", lambda name: "/usr/bin/gnome-terminal")
    monkeypatch.setenv("XDG_CURRENT_DESKTOP", "X-Cinnamon")
    monkeypatch.setenv("GNOME_TERMINAL_SCREEN", "/org/gnome/Terminal/screen/1")


def test_doctor_returns_structured_checks_and_capability_warnings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    configured = paths(tmp_path)
    install_files(tmp_path, monkeypatch)
    diagnostics = run_doctor(configured, Adapter())
    assert all(isinstance(item, Diagnostic) for item in diagnostics)
    names = {item.name for item in diagnostics}
    assert {"bash hook", "native helper", "runtime directory", "socket", "state store", "boot ID", "desktop session", "GNOME Terminal shell context", "terminal adapter", "adapter capabilities", "login chooser", "chooser config", "durability"} <= names
    capability = next(item for item in diagnostics if item.name == "adapter capabilities")
    assert capability.status == "warning"
    assert "windows" in capability.message and "scrollback" in capability.message


def test_missing_integrations_have_actionable_remedies(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    configured = paths(tmp_path)
    monkeypatch.setattr("termrecall.doctor.BASH_HOOK_PATH", tmp_path / "missing-hook")
    monkeypatch.setattr("termrecall.doctor.NATIVE_HELPER_PATH", tmp_path / "missing-helper")
    monkeypatch.setattr("termrecall.doctor.CHOOSER_PATH", tmp_path / "missing-chooser")
    monkeypatch.setattr("termrecall.doctor.read_boot_id", lambda: "boot")
    monkeypatch.setattr("termrecall.doctor.shutil.which", lambda name: None)
    monkeypatch.delenv("XDG_CURRENT_DESKTOP", raising=False)
    diagnostics = run_doctor(configured, Adapter(False))
    assert any(item.status == "error" and item.remedy for item in diagnostics)
    assert any(item.name == "desktop session" and item.status == "warning" for item in diagnostics)
    assert any(item.name == "GNOME Terminal shell context" and item.status == "ok" for item in diagnostics)


@pytest.mark.parametrize(
    "desktop", ["X-Cinnamon", "Cinnamon", "GNOME", "ubuntu:GNOME", "XFCE", "KDE"]
)
def test_doctor_accepts_each_supported_desktop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, desktop: str
) -> None:
    from termrecall.adapters.registry import SUPPORTED_DESKTOPS

    assert desktop in SUPPORTED_DESKTOPS
    configured = paths(tmp_path)
    install_files(tmp_path, monkeypatch)
    monkeypatch.setenv("XDG_CURRENT_DESKTOP", desktop)
    diagnostics = run_doctor(configured, Adapter())
    session = next(item for item in diagnostics if item.name == "desktop session")
    assert session.status == "ok"


def test_doctor_reports_warning_for_unsupported_desktop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configured = paths(tmp_path)
    install_files(tmp_path, monkeypatch)
    monkeypatch.setenv("XDG_CURRENT_DESKTOP", "MATE")
    diagnostics = run_doctor(configured, Adapter())
    session = next(item for item in diagnostics if item.name == "desktop session")
    assert session.status == "warning"


@pytest.mark.parametrize(
    "executable,name",
    [
        ("/usr/bin/gnome-terminal", "gnome-terminal"),
        ("/usr/bin/kitty", "kitty"),
        ("/usr/bin/xfce4-terminal", "xfce4-terminal"),
        ("/usr/bin/konsole", "konsole"),
    ],
)
def test_doctor_reports_detected_terminal_adapter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, executable: str, name: str
) -> None:
    configured = paths(tmp_path)
    install_files(tmp_path, monkeypatch)
    monkeypatch.setattr(
        "termrecall.doctor.shutil.which",
        lambda resolved: executable if resolved == name else None,
    )
    diagnostics = run_doctor(configured, Adapter(True))
    adapter = next(item for item in diagnostics if item.name == "terminal adapter")
    assert adapter.status == "ok"
    assert name in adapter.message


def bind_stale_socket(runtime: Path) -> tuple[int, int]:
    lock = runtime / "service.lock"
    lock.touch(mode=0o600)
    lock.chmod(0o600)
    stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stale.bind(str(runtime / "service.sock"))
    runtime.joinpath("service.sock").chmod(0o600)
    identity = (runtime.joinpath("service.sock").stat().st_dev, runtime.joinpath("service.sock").stat().st_ino)
    stale.close()
    return identity


def test_ordinary_doctor_only_reports_verified_stale_candidate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    configured = paths(tmp_path)
    install_files(tmp_path, monkeypatch)
    identity = bind_stale_socket(configured.runtime_dir)
    diagnostics = run_doctor(configured, Adapter())
    socket_check = next(item for item in diagnostics if item.name == "socket")
    assert socket_check.status == "warning"
    assert "verified stale socket candidate" in socket_check.message
    assert str(identity[1]) in socket_check.message
    assert socket_check.remedy == "termrecall doctor --cleanup-stale-socket"
    assert (configured.runtime_dir / "service.sock").exists()


def test_cleanup_removes_only_verified_same_socket_inode(tmp_path: Path) -> None:
    configured = paths(tmp_path)
    identity = bind_stale_socket(configured.runtime_dir)
    assert cleanup_stale_socket(configured) == identity
    assert not (configured.runtime_dir / "service.sock").exists()


@pytest.mark.parametrize("entry", ["regular", "symlink"])
def test_cleanup_refuses_non_socket_and_symlink(tmp_path: Path, entry: str) -> None:
    configured = paths(tmp_path)
    lock = configured.runtime_dir / "service.lock"
    lock.touch(mode=0o600)
    target = configured.runtime_dir / "service.sock"
    if entry == "regular":
        target.write_text("do not delete")
    else:
        target.symlink_to(tmp_path / "elsewhere")
    with pytest.raises(RuntimeError, match="refused"):
        cleanup_stale_socket(configured)
    assert target.exists() or target.is_symlink()


def test_cleanup_refuses_live_socket(tmp_path: Path) -> None:
    configured = paths(tmp_path)
    lock = configured.runtime_dir / "service.lock"
    lock.touch(mode=0o600)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(configured.runtime_dir / "service.sock"))
    (configured.runtime_dir / "service.sock").chmod(0o600)
    listener.listen(1)
    try:
        with pytest.raises(RuntimeError, match="live"):
            cleanup_stale_socket(configured)
    finally:
        listener.close()
    assert (configured.runtime_dir / "service.sock").exists()


def test_cleanup_refuses_when_singleton_lock_is_held(tmp_path: Path) -> None:
    configured = paths(tmp_path)
    bind_stale_socket(configured.runtime_dir)
    fd = os.open(configured.runtime_dir / "service.lock", os.O_RDWR | os.O_NOFOLLOW)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        with pytest.raises(RuntimeError, match="lock"):
            cleanup_stale_socket(configured)
    finally:
        os.close(fd)
    assert (configured.runtime_dir / "service.sock").exists()


def test_socket_with_unsafe_mode_is_not_treated_as_reachable_or_stale(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    configured = paths(tmp_path)
    install_files(tmp_path, monkeypatch)
    bind_stale_socket(configured.runtime_dir)
    (configured.runtime_dir / "service.sock").chmod(0o666)
    diagnostic = next(item for item in run_doctor(configured, Adapter()) if item.name == "socket")
    assert diagnostic.status == "error"
    assert "mode" in diagnostic.message
    assert (configured.runtime_dir / "service.sock").exists()


def test_recovery_schema_failure_is_reported_without_modifying_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    configured = paths(tmp_path)
    install_files(tmp_path, monkeypatch)
    recovery = configured.state_dir / "recovery.json"
    recovery.write_text(json.dumps({"schema_version": 999}))
    before = recovery.read_bytes()
    diagnostics = run_doctor(configured, Adapter())
    assert next(item for item in diagnostics if item.name == "state store").status == "error"
    assert recovery.read_bytes() == before


def test_checkpoint_schema_failure_is_reported_without_modifying_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    configured = paths(tmp_path)
    install_files(tmp_path, monkeypatch)
    checkpoint = configured.state_dir / "checkpoint-00000000000000000001.json"
    checkpoint.write_text(json.dumps({"schema_version": 999}))
    before = checkpoint.read_bytes()
    diagnostics = run_doctor(configured, Adapter())
    assert next(item for item in diagnostics if item.name == "state store").status == "error"
    assert checkpoint.read_bytes() == before


# ---------------------------------------------------------------------------
# installed lifecycle integration diagnostics (Task 7)
# ---------------------------------------------------------------------------


def _lifecycle_paths(tmp_path: Path):
    from termrecall.installer_contract import resolve_lifecycle_paths

    home = tmp_path / "home"
    home.mkdir(parents=True, mode=0o700)
    paths = resolve_lifecycle_paths({}, home)
    for root in (paths.xdg_data_home, paths.xdg_config_home, paths.xdg_state_home, paths.bin_root):
        root.mkdir(parents=True, exist_ok=True)
    paths.state_root.mkdir(parents=True, exist_ok=True)
    paths.state_root.chmod(0o700)
    return paths


def _install_prior(paths, *, bash=True, autostart=True, chooser_enabled=True):
    import hashlib
    from termrecall.installer_contract import (
        BeforeImage, ChooserOwnership, InstallManifest, MarkerIdentity,
        OwnedObject, ObjectKind, manifest_to_bytes,
    )
    from termrecall.lifecycle_integrations import render_chooser, render_desktop, _v1_block  # type: ignore[attr-defined]

    gen = paths.generations / "gen-1"
    gen.parent.mkdir(parents=True, exist_ok=True)
    gen.parent.chmod(0o700)
    gen.mkdir(mode=0o700)
    venv_bin = gen / "venv/bin"
    venv_bin.mkdir(parents=True, mode=0o700)
    for name in ("termrecall", "termrecall-bridge", "termrecall-nonblock"):
        exe = venv_bin / name
        exe.write_bytes(b"#!/bin/sh\necho ok\n")
        exe.chmod(0o755)
    import json
    marker = gen / ".termrecall-generation.json"
    raw = json.dumps({"schema": 2, "install_id": "install-1", "generation_id": "gen-1", "path": str(gen), "nonce": "n"}, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    marker.write_bytes(raw)
    marker.chmod(0o600)
    paths.current.parent.mkdir(parents=True, exist_ok=True)
    paths.current.parent.chmod(0o700)
    os.symlink(str(gen), str(paths.current))
    paths.bin_root.mkdir(parents=True, exist_ok=True)
    for link in paths.command_links:
        os.symlink(str(paths.current / f"venv/bin/{link.name}"), str(link))
    paths.config_root.mkdir(parents=True, exist_ok=True)
    paths.config_root.chmod(0o700)
    paths.bashrc.parent.mkdir(parents=True, exist_ok=True)
    if bash:
        paths.bashrc.write_bytes(b"alias ll='ls -l'\n\n" + _v1_block(paths.bash_integration))
        paths.bashrc.chmod(0o644)
    if autostart:
        paths.autostart.parent.mkdir(parents=True, exist_ok=True)
        paths.autostart.parent.chmod(0o700)
        paths.autostart.write_bytes(render_desktop(paths.current / "venv/bin/termrecall"))
        paths.autostart.chmod(0o600)
    paths.chooser.write_bytes(render_chooser(chooser_enabled))
    paths.chooser.chmod(0o600)
    owned = [
        OwnedObject(str(paths.current), ObjectKind.SYMLINK, 0o777, None, str(gen)),
        *(OwnedObject(str(link), ObjectKind.SYMLINK, 0o777, None, str(paths.current / f"venv/bin/{link.name}")) for link in paths.command_links),
    ]
    absent = BeforeImage(str(paths.chooser), ObjectKind.ABSENT, None, None, None, None)
    chooser = ChooserOwnership(absent, BeforeImage(str(paths.chooser), ObjectKind.FILE, 0o600, None, paths.chooser.read_bytes(), hashlib.sha256(paths.chooser.read_bytes()).hexdigest()), True)
    manifest = InstallManifest(
        schema_version=2, installer_version="1.0", application_version="0.1.0",
        install_id="install-1", generation_id="gen-1",
        roots={"uid": os.getuid(), "data": str(paths.data_root), "config": str(paths.config_root), "state": str(paths.state_root), "bin": str(paths.bin_root)},
        marker=MarkerIdentity(str(marker), hashlib.sha256(raw).hexdigest(), 0o600),
        owned=tuple(owned), created_parents=(), bash_enabled=bash, autostart_enabled=autostart,
        chooser=chooser, rollback_images=(), bash_backup=None,
    )
    paths.manifest.parent.mkdir(parents=True, exist_ok=True)
    paths.manifest.parent.chmod(0o700)
    paths.manifest.write_bytes(manifest_to_bytes(manifest))
    paths.manifest.chmod(0o600)


def test_doctor_lifecycle_reports_missing_install_as_informational(tmp_path: Path) -> None:
    from termrecall.doctor import _lifecycle_diagnostics

    paths = _lifecycle_paths(tmp_path)
    diagnostics = _lifecycle_diagnostics(paths, os.getuid())
    manifest = next(item for item in diagnostics if item.name == "install manifest")
    assert manifest.status == "warning"
    assert any("install" in item.remedy for item in diagnostics if item.remedy)


def test_doctor_lifecycle_validates_installed_manifest_links_and_integrations(tmp_path: Path) -> None:
    from termrecall.doctor import _lifecycle_diagnostics

    paths = _lifecycle_paths(tmp_path)
    _install_prior(paths, bash=True, autostart=True, chooser_enabled=True)
    diagnostics = _lifecycle_diagnostics(paths, os.getuid())
    by_name = {item.name: item for item in diagnostics}
    assert by_name["install manifest"].status == "ok"
    assert by_name["current link"].status == "ok"
    assert all(by_name[f"command link {link.name}"].status == "ok" for link in paths.command_links)
    assert by_name["bash integration"].status == "ok"
    assert by_name["autostart entry"].status == "ok"
    assert by_name["state safety"].status == "ok"


def test_doctor_lifecycle_flags_drifted_current_link(tmp_path: Path) -> None:
    from termrecall.doctor import _lifecycle_diagnostics

    paths = _lifecycle_paths(tmp_path)
    _install_prior(paths)
    os.unlink(paths.current)
    os.symlink("/nonexistent", str(paths.current))
    diagnostics = _lifecycle_diagnostics(paths, os.getuid())
    by_name = {item.name: item for item in diagnostics}
    assert by_name["current link"].status == "error"
    # no lock/write/service call occurred
    assert not (paths.config_root / "lifecycle.lock").exists()


def test_doctor_lifecycle_flags_absent_bash_block(tmp_path: Path) -> None:
    from termrecall.doctor import _lifecycle_diagnostics

    paths = _lifecycle_paths(tmp_path)
    _install_prior(paths, bash=False, autostart=True)
    diagnostics = _lifecycle_diagnostics(paths, os.getuid())
    by_name = {item.name: item for item in diagnostics}
    assert by_name["bash integration"].status == "warning"
