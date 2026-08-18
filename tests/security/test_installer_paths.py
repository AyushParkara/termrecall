# SPDX-License-Identifier: GPL-3.0-or-later
"""Security invariants: no-follow path handling, sentinel preservation,
and the standalone cleanup_private_tree.py helper."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from termrecall.installer_contract import MarkerIdentity
from termrecall.lifecycle_fs import (
    UnsafeLifecyclePath,
    atomic_write,
    delete_tree_structural,
    open_lock_infrastructure,
    verified_delete_generation,
    _open_dir_chain,  # type: ignore[attr-defined]
)

ROOT = Path(__file__).parents[2]
CLEANUP = ROOT / "cleanup_private_tree.py"
MARKER_NAME = ".termrecall-generation.json"
UID = os.getuid()


def _canonical(obj: object) -> bytes:
    return (
        json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        .encode("utf-8")
        + b"\n"
    )


def _ident(path: Path):
    st = os.lstat(path)
    return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode), st.st_nlink)


# ---------------------------------------------------------------------------
# No-follow path opening
# ---------------------------------------------------------------------------


def test_open_dir_chain_refuses_symlinked_root(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    link = tmp_path / "link"
    os.symlink(real, link)
    with pytest.raises(UnsafeLifecyclePath):
        _open_dir_chain(link)


def test_open_dir_chain_refuses_symlinked_ancestor(tmp_path: Path) -> None:
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir(mode=0o700)
    target = real_parent / "gen"
    target.mkdir(mode=0o700)
    link_parent = tmp_path / "link-parent"
    os.symlink(real_parent, link_parent)
    with pytest.raises(UnsafeLifecyclePath):
        _open_dir_chain(link_parent / "gen")


def test_open_dir_chain_opens_real_directory(tmp_path: Path) -> None:
    fd, ident = _open_dir_chain(tmp_path)
    try:
        st = os.fstat(fd)
        assert stat.S_ISDIR(st.st_mode)
        assert ident.inode == st.st_ino
        assert ident.device == st.st_dev
        assert ident.uid == UID
    finally:
        os.close(fd)


def test_verified_delete_generation_refuses_symlink_root(tmp_path: Path) -> None:
    real = tmp_path / "real-gen"
    real.mkdir(mode=0o700)
    marker = real / MARKER_NAME
    raw = _canonical({"schema": 2, "install_id": "i", "generation_id": "g", "path": str(real), "nonce": "n"})
    marker.write_bytes(raw)
    marker.chmod(0o600)
    (real / "venv").mkdir(mode=0o700)
    link = tmp_path / "link-gen"
    os.symlink(real, link)
    marker_identity = MarkerIdentity(str(link / MARKER_NAME), hashlib.sha256(raw).hexdigest(), 0o600)
    # the symlink path must be refused; the real generation must survive
    with pytest.raises(UnsafeLifecyclePath):
        verified_delete_generation(link, marker_identity, UID)
    assert real.exists()
    assert marker.exists()


# ---------------------------------------------------------------------------
# Sentinel preservation across operations
# ---------------------------------------------------------------------------


def test_atomic_write_into_symlinked_directory_refused(tmp_path: Path) -> None:
    real_dir = tmp_path / "real"
    real_dir.mkdir(mode=0o700)
    link_dir = tmp_path / "link"
    os.symlink(real_dir, link_dir)
    sentinel = real_dir / "inside"
    sentinel.write_bytes(b"precious")
    with pytest.raises(UnsafeLifecyclePath):
        atomic_write(link_dir / "target", b"x", 0o600, UID)
    assert sentinel.read_bytes() == b"precious"


def test_lock_refuses_symlinked_config_directory(tmp_path: Path) -> None:
    from termrecall.installer_contract import LockInfrastructurePlan

    real_dir = tmp_path / "real-config"
    real_dir.mkdir(mode=0o700)
    link_dir = tmp_path / "link-config"
    os.symlink(real_dir, link_dir)
    plan = LockInfrastructurePlan(
        directory_path=str(link_dir),
        lock_path=str(link_dir / "lifecycle.lock"),
        directory_absent=False,
        lock_absent=True,
        may_create_directory=False,
        may_create_lock=True,
        directory_mode=0o700,
        lock_mode=0o600,
    )
    with pytest.raises(UnsafeLifecyclePath):
        open_lock_infrastructure(plan, UID)


# ---------------------------------------------------------------------------
# cleanup_private_tree.py CLI
# ---------------------------------------------------------------------------


def _build_tree(tmp_path: Path, *, with_venv: bool = False, root_mode: int = 0o700) -> Path:
    parent = tmp_path / "bp"
    parent.mkdir(mode=0o700)
    root = parent / "b"
    root.mkdir(mode=root_mode)
    (root / "inside").mkdir(mode=0o700)
    (root / "inside" / "file").write_bytes(b"payload")
    (root / "inside" / "file").chmod(0o600)
    os.symlink("/usr/bin/true", root / "inside" / "leaf")
    if with_venv:
        subprocess.run([sys.executable, "-m", "venv", str(root / "venv")], check=True)
    return root


def _run_cleanup(
    root: Path,
    *,
    parent_device=None,
    parent_inode=None,
    root_device=None,
    root_inode=None,
    uid=None,
    parent_path=None,
):
    parent = parent_path or root.parent
    pst = os.lstat(parent)
    rst = os.lstat(root)
    args = [
        sys.executable,
        str(CLEANUP),
        str(root),
        str(parent),
        str(parent_device if parent_device is not None else pst.st_dev),
        str(parent_inode if parent_inode is not None else pst.st_ino),
        str(root_device if root_device is not None else rst.st_dev),
        str(root_inode if root_inode is not None else rst.st_ino),
        str(uid if uid is not None else os.getuid()),
    ]
    return subprocess.run(args, capture_output=True)


def test_cleanup_helper_deletes_real_venv_tree(tmp_path: Path) -> None:
    root = _build_tree(tmp_path, with_venv=True)
    result = _run_cleanup(root)
    assert result.returncode == 0, result.stderr
    assert not root.exists()


def test_cleanup_helper_deletes_structural_tree(tmp_path: Path) -> None:
    root = _build_tree(tmp_path)
    result = _run_cleanup(root)
    assert result.returncode == 0, result.stderr
    assert not root.exists()


def test_cleanup_helper_refuses_parent_device_forgery(tmp_path: Path) -> None:
    root = _build_tree(tmp_path)
    pst = os.lstat(root.parent)
    result = _run_cleanup(root, parent_device=pst.st_dev + 1)
    assert result.returncode != 0
    assert root.exists()


def test_cleanup_helper_refuses_parent_inode_forgery(tmp_path: Path) -> None:
    root = _build_tree(tmp_path)
    pst = os.lstat(root.parent)
    result = _run_cleanup(root, parent_inode=pst.st_ino + 1)
    assert result.returncode != 0
    assert root.exists()


def test_cleanup_helper_refuses_root_device_forgery(tmp_path: Path) -> None:
    root = _build_tree(tmp_path)
    rst = os.lstat(root)
    result = _run_cleanup(root, root_device=rst.st_dev + 1)
    assert result.returncode != 0
    assert root.exists()


def test_cleanup_helper_refuses_root_inode_forgery(tmp_path: Path) -> None:
    root = _build_tree(tmp_path)
    rst = os.lstat(root)
    result = _run_cleanup(root, root_inode=rst.st_ino + 1)
    assert result.returncode != 0
    assert root.exists()


def test_cleanup_helper_refuses_uid_mismatch(tmp_path: Path) -> None:
    root = _build_tree(tmp_path)
    result = _run_cleanup(root, uid=UID + 1)
    assert result.returncode != 0
    assert root.exists()


def test_cleanup_helper_refuses_non_numeric_args(tmp_path: Path) -> None:
    root = _build_tree(tmp_path)
    parent = root.parent
    pst = os.lstat(parent)
    rst = os.lstat(root)
    args = [
        sys.executable,
        str(CLEANUP),
        str(root),
        str(parent),
        "not-a-number",
        str(pst.st_ino),
        str(rst.st_dev),
        str(rst.st_ino),
        str(UID),
    ]
    result = subprocess.run(args, capture_output=True)
    assert result.returncode != 0
    assert root.exists()


def test_cleanup_helper_refuses_wrong_root_mode(tmp_path: Path) -> None:
    root = _build_tree(tmp_path, root_mode=0o755)
    result = _run_cleanup(root)
    assert result.returncode != 0
    assert root.exists()


def test_cleanup_helper_preserves_sentinel_through_symlink(tmp_path: Path) -> None:
    sentinel_home = tmp_path / "sentinel-home"
    sentinel_home.mkdir(mode=0o700)
    sentinel = sentinel_home / "secret"
    sentinel.write_bytes(b"operator-owned")
    root = _build_tree(tmp_path)
    os.symlink(sentinel, root / "inside" / "escape")
    result = _run_cleanup(root)
    assert result.returncode == 0, result.stderr
    assert not root.exists()
    assert sentinel.read_bytes() == b"operator-owned"


def test_cleanup_helper_refuses_hardlink_to_sentinel(tmp_path: Path) -> None:
    sentinel_home = tmp_path / "sentinel-home"
    sentinel_home.mkdir(mode=0o700)
    sentinel = sentinel_home / "secret"
    sentinel.write_bytes(b"operator-owned")
    root = _build_tree(tmp_path)
    os.link(sentinel, root / "inside" / "evil")
    result = _run_cleanup(root)
    assert result.returncode != 0
    assert root.exists()
    assert sentinel.read_bytes() == b"operator-owned"


def test_cleanup_helper_refuses_fifo(tmp_path: Path) -> None:
    root = _build_tree(tmp_path)
    os.mkfifo(root / "inside" / "pipe", 0o600)
    result = _run_cleanup(root)
    assert result.returncode != 0
    assert root.exists()


def test_cleanup_helper_refuses_socket(tmp_path: Path) -> None:
    root = _build_tree(tmp_path)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.bind(str(root / "inside" / "sock"))
    finally:
        s.close()
    result = _run_cleanup(root)
    assert result.returncode != 0
    assert root.exists()


def test_cleanup_helper_refuses_root_not_direct_child(tmp_path: Path) -> None:
    # claim a parent that is not the real parent -> refusal
    root = _build_tree(tmp_path)
    bogus_parent = tmp_path / "bogus-parent"
    bogus_parent.mkdir(mode=0o700)
    pst = os.lstat(bogus_parent)
    rst = os.lstat(root)
    result = _run_cleanup(
        root,
        parent_path=bogus_parent,
        parent_device=pst.st_dev,
        parent_inode=pst.st_ino,
        root_device=rst.st_dev,
        root_inode=rst.st_ino,
    )
    assert result.returncode != 0
    assert root.exists()


# ---------------------------------------------------------------------------
# lifecycle orchestrator path-safety (Task 4)
# ---------------------------------------------------------------------------


def _lifecycle_roots(tmp_path: Path):
    from termrecall.installer_contract import resolve_lifecycle_paths

    home = tmp_path / "home"
    home.mkdir(parents=True, mode=0o700)
    paths = resolve_lifecycle_paths({}, home)
    for root in (paths.xdg_data_home, paths.xdg_config_home, paths.xdg_state_home, paths.bin_root):
        root.mkdir(parents=True, exist_ok=True)
        root.chmod(0o755)
    home.chmod(0o700)
    return paths


def _make_source(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    ignored = shutil.ignore_patterns(
        "__pycache__", ".pytest_cache", "*.pyc", "dist", "build", "*.egg-info", ".git", ".worktrees"
    )
    shutil.copytree(ROOT, source, ignore=ignored)
    for path in (source, *source.rglob("*")):
        path.chmod(path.stat().st_mode & ~0o022)
    return source


def _prior_install(paths: Path, gen_id: str = "gen-1") -> None:
    from termrecall.installer_contract import (
        BeforeImage, ChooserOwnership, InstallManifest, MarkerIdentity,
        OwnedObject, ObjectKind, manifest_to_bytes,
    )
    from termrecall.lifecycle_integrations import render_desktop

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
    raw = _canonical(
        {"schema": 2, "install_id": "install-1", "generation_id": gen_id, "path": str(gen), "nonce": "n"}
    )
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
    paths.autostart.parent.mkdir(parents=True, exist_ok=True)
    paths.autostart.parent.chmod(0o700)
    paths.autostart.write_bytes(render_desktop(paths.current / "venv/bin/termrecall"))
    paths.autostart.chmod(0o600)
    owned = [OwnedObject(str(paths.current), ObjectKind.SYMLINK, 0o777, None, str(gen))]
    for link in paths.command_links:
        owned.append(OwnedObject(str(link), ObjectKind.SYMLINK, 0o777, None, str(paths.current / f"venv/bin/{link.name}")))
    owned.append(OwnedObject(str(paths.autostart), ObjectKind.FILE, 0o600, hashlib.sha256(paths.autostart.read_bytes()).hexdigest(), None))
    absent = BeforeImage(str(paths.chooser), ObjectKind.ABSENT, None, None, None, None)
    manifest = InstallManifest(
        schema_version=2, installer_version="1.0", application_version="0.1.0",
        install_id="install-1", generation_id=gen_id,
        roots={"uid": UID, "data": str(paths.data_root), "config": str(paths.config_root), "state": str(paths.state_root), "bin": str(paths.bin_root)},
        marker=MarkerIdentity(str(marker), hashlib.sha256(raw).hexdigest(), 0o600),
        owned=tuple(owned), created_parents=(), bash_enabled=False, autostart_enabled=True,
        chooser=ChooserOwnership(absent, None, False), rollback_images=(), bash_backup=None,
    )
    paths.manifest.parent.mkdir(parents=True, exist_ok=True)
    paths.manifest.parent.chmod(0o700)
    paths.manifest.write_bytes(manifest_to_bytes(manifest))
    paths.manifest.chmod(0o600)


def test_execute_setup_refuses_symlinked_config_root_and_preserves_sentinel(tmp_path: Path) -> None:
    from termrecall.installer_contract import (
        DesiredState, SetupMode, SetupRequest, probe_plan_from_bytes,
    )
    from termrecall.lifecycle import execute_setup, NO_FAILURE
    import subprocess

    paths = _lifecycle_roots(tmp_path)
    source = _make_source(tmp_path)
    argv = [
        sys.executable, "-I", "-B", str(source / "installer_probe.py"), "plan",
        "--source-root", str(source), "--home", str(paths.home),
        "--xdg-data-home", str(paths.xdg_data_home), "--xdg-config-home", str(paths.xdg_config_home),
        "--xdg-state-home", str(paths.xdg_state_home), "--mode", "full", "--bash", "enable",
        "--autostart", "enable", "--chooser", "enable", "--dry-run", "no",
    ]
    completed = subprocess.run(argv, env={"PATH": os.environ["PATH"], "PYTHONDONTWRITEBYTECODE": "1"}, capture_output=True, check=False)
    assert completed.returncode == 0, completed.stderr.decode()
    request_obj = {
        "request_schema": 1, "source_root": str(source), "home": str(paths.home),
        "xdg_data_home": str(paths.xdg_data_home), "xdg_config_home": str(paths.xdg_config_home),
        "xdg_state_home": str(paths.xdg_state_home), "mode": "full", "bash": "enable",
        "autostart": "enable", "chooser": "enable", "dry_run": False,
    }
    plan = probe_plan_from_bytes(completed.stdout, request_obj)
    request = SetupRequest(
        mode=SetupMode.FULL, dry_run=False, bash=DesiredState.ENABLE,
        autostart=DesiredState.ENABLE, chooser=DesiredState.ENABLE,
        source_root=source, wheel=None, probe_request=None, probe_plan=None, probe_plan_digest=None,
    )
    # plant a symlink where the config directory should be created
    real_config = tmp_path / "real-config"
    real_config.mkdir(mode=0o700)
    os.symlink(real_config, str(paths.config_root))
    sentinel = real_config / "operator-secret"
    sentinel.write_bytes(b"operator-owned")
    assert execute_setup(plan, request, paths, UID, NO_FAILURE) is not None
    # the sentinel under the symlinked config must be untouched and no install committed
    assert sentinel.read_bytes() == b"operator-owned"
    assert not paths.current.exists()
    assert not paths.manifest.exists()


def test_execute_uninstall_quarantine_preserves_external_sentinel(tmp_path: Path) -> None:
    from termrecall.installer_contract import UninstallRequest
    from termrecall.lifecycle import execute_uninstall, plan_uninstall, NO_FAILURE

    paths = _lifecycle_roots(tmp_path)
    _prior_install(paths)
    # seed state with a sentinel the quarantine must not traverse
    paths.state_root.mkdir(parents=True, exist_ok=True)
    paths.state_root.chmod(0o700)
    sentinel_home = tmp_path / "sentinel-home"
    sentinel_home.mkdir(mode=0o700)
    sentinel = sentinel_home / "secret"
    sentinel.write_bytes(b"operator-owned")
    os.symlink(sentinel, str(paths.state_root / "escape"))
    request = UninstallRequest(
        remove_application=True, remove_bash=True, remove_autostart=True,
        restore_chooser=True, purge_state=True, assume_yes=True,
    )
    plan = plan_uninstall(request, paths, UID)
    result = execute_uninstall(plan, UID, NO_FAILURE)
    assert result == 0  # LifecycleExit.OK
    # the external sentinel is untouched and the live state root is gone
    assert sentinel.read_bytes() == b"operator-owned"
    assert not paths.state_root.exists()
