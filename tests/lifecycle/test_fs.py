# SPDX-License-Identifier: GPL-3.0-or-later
"""Strict TDD tests for descriptor-relative lifecycle filesystem operations."""

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

from termrecall.installer_contract import (
    BeforeImage,
    LockInfrastructurePlan,
    MarkerIdentity,
    ObjectKind,
)
from termrecall.lifecycle_fs import (
    CleanupFailure,
    ConcurrentLifecycleChange,
    NodeIdentity,
    QuarantinedTree,
    SafeSnapshot,
    TreePolicy,
    UnsafeLifecyclePath,
    acquire_lifecycle_lock,
    atomic_rename,
    atomic_symlink,
    atomic_write,
    capture_before,
    delete_quarantine,
    delete_tree_structural,
    inspect_paths,
    open_lock_infrastructure,
    quarantine_state,
    remove_created_parents,
    restore_before,
    restore_quarantine,
    revalidate,
    validate_lock_infrastructure,
    verified_delete_generation,
)

MARKER_NAME = ".termrecall-generation.json"
UID = os.getuid()


def _rmtree(path: Path) -> None:
    """Test-only recursive cleanup of a tree we created, without relying on
    any unchecked recursive-deletion helper from the standard library."""
    if not os.path.lexists(path):
        return
    if os.path.islink(path) or not os.path.isdir(path):
        try:
            os.unlink(path)
        except OSError:
            pass
        return
    for root, dirs, files in os.walk(path, topdown=False, followlinks=False):
        for name in files:
            try:
                os.unlink(os.path.join(root, name))
            except OSError:
                pass
        for name in dirs:
            full = os.path.join(root, name)
            if os.path.islink(full):
                try:
                    os.unlink(full)
                except OSError:
                    pass
            else:
                try:
                    os.rmdir(full)
                except OSError:
                    pass
    try:
        os.rmdir(path)
    except OSError:
        pass


def _canonical(obj: object) -> bytes:
    return (
        json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        .encode("utf-8")
        + b"\n"
    )


def _ident(path: Path) -> NodeIdentity:
    st = os.lstat(path)
    return NodeIdentity(st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode), st.st_nlink)


def _lock_plan(
    tmp_path: Path,
    *,
    may_create_directory: bool,
    may_create_lock: bool,
    dir_path: str | None = None,
    lock_path: str | None = None,
    dir_mode: int = 0o700,
    lock_mode: int = 0o600,
) -> LockInfrastructurePlan:
    dir_path = dir_path or str(tmp_path / "tr-config")
    lock_path = lock_path or str(Path(dir_path) / "lifecycle.lock")
    return LockInfrastructurePlan(
        directory_path=dir_path,
        lock_path=lock_path,
        directory_absent=may_create_directory,
        lock_absent=may_create_lock,
        may_create_directory=may_create_directory,
        may_create_lock=may_create_lock,
        directory_mode=dir_mode,
        lock_mode=lock_mode,
    )


def _patch_stat(
    monkeypatch,
    target_ino: int,
    *,
    device: int | None = None,
    uid: int | None = None,
    nlink: int | None = None,
    mode: int | None = None,
) -> None:
    """Targeted no-follow lstat/fstat tamper for one inode (race/forge simulation).

    Patches both os.lstat and os.fstat so the forge is observed regardless of
    whether the implementation stats an entry by pathname or by open descriptor.
    """
    real_lstat = os.lstat
    real_fstat = os.fstat

    def _tamper(st):
        if st.st_ino == target_ino:
            seq = list(st)
            if device is not None:
                seq[2] = device
            if uid is not None:
                seq[4] = uid
            if nlink is not None:
                seq[3] = nlink
            if mode is not None:
                seq[0] = mode
            return os.stat_result(seq)
        return st

    def patched_lstat(path, *args, **kwargs):
        return _tamper(real_lstat(path, *args, **kwargs))

    def patched_fstat(fd, *args, **kwargs):
        return _tamper(real_fstat(fd, *args, **kwargs))

    monkeypatch.setattr(os, "lstat", patched_lstat)
    monkeypatch.setattr(os, "fstat", patched_fstat)


class SecureTree:
    """A marked generation root with an external operator-owned sentinel."""

    def __init__(self, tmp_path: Path) -> None:
        self.tmp = tmp_path
        self.gen_id = "gen-one"
        # keep the root path short so AF_UNIX socket binds stay under the limit
        self.root = tmp_path / "trgen" / self.gen_id
        self.root.parent.mkdir(parents=True, exist_ok=True)
        self.root.mkdir(mode=0o700)
        self.sentinel_home = tmp_path / "sentinel-home"
        self.sentinel_home.mkdir(mode=0o700)
        self.sentinel = self.sentinel_home / "operator-secret"
        self.sentinel.write_bytes(b"operator-owned")
        self.sentinel.chmod(0o600)
        self._venv_made = False
        self.make_marker()

    def make_marker(
        self,
        *,
        canonical: bool = True,
        content_override: bytes | None = None,
        mode: int = 0o600,
        extra_fields: dict | None = None,
    ) -> MarkerIdentity:
        marker_path = self.root / MARKER_NAME
        obj = {
            "schema": 2,
            "install_id": "inst-1",
            "generation_id": self.gen_id,
            "path": str(self.root),
            "nonce": "nonce-one",
        }
        if extra_fields:
            obj.update(extra_fields)
        if content_override is not None:
            raw = content_override
        elif canonical:
            raw = _canonical(obj)
        else:
            raw = json.dumps(obj).encode("utf-8")
        marker_path.write_bytes(raw)
        marker_path.chmod(mode)
        return MarkerIdentity(str(marker_path), hashlib.sha256(raw).hexdigest(), mode)

    def marker_identity(self) -> MarkerIdentity:
        p = self.root / MARKER_NAME
        return MarkerIdentity(
            str(p),
            hashlib.sha256(p.read_bytes()).hexdigest(),
            stat.S_IMODE(os.lstat(p).st_mode),
        )

    def ensure_venv_dir(self) -> None:
        if not self._venv_made:
            (self.root / "venv").mkdir(mode=0o700)
            self._venv_made = True

    def make_venv(self) -> None:
        subprocess.run(
            [sys.executable, "-m", "venv", str(self.root / "venv")],
            check=True,
        )
        self._venv_made = True

    def add_leaf_symlink(self, name: str, target: str) -> None:
        self.ensure_venv_dir()
        os.symlink(target, self.root / "venv" / name)

    def add_hardlink_to_sentinel(self, name: str) -> None:
        self.ensure_venv_dir()
        os.link(self.sentinel, self.root / "venv" / name)

    def add_fifo(self, name: str) -> None:
        self.ensure_venv_dir()
        os.mkfifo(self.root / "venv" / name, 0o600)

    def add_socket(self, name: str) -> None:
        self.ensure_venv_dir()
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(str(self.root / "venv" / name))
        s.close()

    def add_regular(self, name: str, content: bytes = b"x", mode: int = 0o600) -> None:
        self.ensure_venv_dir()
        p = self.root / "venv" / name
        p.write_bytes(content)
        p.chmod(mode)

    def add_top_level(self, name: str) -> None:
        (self.root / name).mkdir(mode=0o700)

    def delete_generation(self, uid: int = UID) -> None:
        verified_delete_generation(self.root, self.marker_identity(), uid)

    @property
    def sentinel_bytes(self) -> bytes:
        return self.sentinel.read_bytes()


@pytest.fixture
def secure_tree(tmp_path: Path) -> SecureTree:
    return SecureTree(tmp_path)


# ---------------------------------------------------------------------------
# capture_before / inspect_paths / revalidate
# ---------------------------------------------------------------------------


def test_capture_before_absent(tmp_path: Path) -> None:
    img = capture_before(tmp_path / "missing", UID)
    assert img.kind is ObjectKind.ABSENT
    assert img.mode is None and img.literal_target is None
    assert img.content is None and img.content_sha256 is None


def test_capture_before_file_records_content_and_mode(tmp_path: Path) -> None:
    p = tmp_path / "f"
    p.write_bytes(b"hello")
    p.chmod(0o600)
    img = capture_before(p, UID)
    assert img.kind is ObjectKind.FILE
    assert img.content == b"hello"
    assert img.content_sha256 == hashlib.sha256(b"hello").hexdigest()
    assert img.mode == 0o600
    assert img.literal_target is None


def test_capture_before_symlink_does_not_follow(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_bytes(b"secret")
    link = tmp_path / "link"
    os.symlink(target, link)
    img = capture_before(link, UID)
    assert img.kind is ObjectKind.SYMLINK
    assert img.literal_target == str(target)
    assert img.content is None and img.content_sha256 is None


def test_capture_before_refuses_directory(tmp_path: Path) -> None:
    with pytest.raises(UnsafeLifecyclePath):
        capture_before(tmp_path, UID)


def test_capture_before_rejects_oversized(tmp_path: Path) -> None:
    p = tmp_path / "big"
    p.write_bytes(b"x" * 16)
    with pytest.raises(UnsafeLifecyclePath):
        capture_before(p, UID, max_bytes=8)


def test_revalidate_stable_passes(tmp_path: Path) -> None:
    p = tmp_path / "f"
    p.write_bytes(b"ok")
    snap = inspect_paths([p], UID)
    revalidate(snap, UID)


def test_revalidate_detects_ancestor_swap(tmp_path: Path) -> None:
    parent = tmp_path / "d"
    parent.mkdir()
    p = parent / "f"
    p.write_bytes(b"ok")
    snap = inspect_paths([p], UID)
    # swap the parent directory inode (delete + recreate) without checked-rmtree helpers
    os.unlink(p)
    os.rmdir(parent)
    parent.mkdir()
    with pytest.raises(ConcurrentLifecycleChange):
        revalidate(snap, UID)


def test_revalidate_detects_mode_change(tmp_path: Path) -> None:
    p = tmp_path / "f"
    p.write_bytes(b"ok")
    p.chmod(0o600)
    snap = inspect_paths([p], UID)
    p.chmod(0o644)
    with pytest.raises(ConcurrentLifecycleChange):
        revalidate(snap, UID)


# ---------------------------------------------------------------------------
# atomic_write / atomic_symlink / atomic_rename / restore_before
# ---------------------------------------------------------------------------


def test_atomic_write_creates_file_exact_mode(tmp_path: Path) -> None:
    target = tmp_path / "f"
    atomic_write(target, b"data", 0o600, UID)
    st = os.lstat(target)
    assert stat.S_ISREG(st.st_mode)
    assert stat.S_IMODE(st.st_mode) == 0o600
    assert target.read_bytes() == b"data"
    assert st.st_uid == UID


def test_atomic_write_replaces_existing(tmp_path: Path) -> None:
    target = tmp_path / "f"
    target.write_bytes(b"old")
    target.chmod(0o600)
    atomic_write(target, b"new", 0o600, UID)
    assert target.read_bytes() == b"new"


def test_atomic_write_replaces_symlink_without_following(tmp_path: Path) -> None:
    sentinel = tmp_path / "sentinel"
    sentinel.write_bytes(b"precious")
    link = tmp_path / "f"
    os.symlink(sentinel, link)
    atomic_write(link, b"real", 0o600, UID)
    assert os.lstat(link).st_mode & stat.S_IFMT(stat.S_IFREG) == stat.S_IFREG
    assert link.read_bytes() == b"real"
    assert sentinel.read_bytes() == b"precious"


def test_atomic_write_fsyncs_file_before_parent(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "f"
    order: list[int] = []
    real_fsync = os.fsync

    def rec(fd: int) -> None:
        order.append(os.fstat(fd).st_ino)
        return real_fsync(fd)

    monkeypatch.setattr(os, "fsync", rec)
    atomic_write(target, b"hello", 0o600, UID)
    file_ino = os.lstat(target).st_ino
    parent_ino = os.lstat(tmp_path).st_ino
    assert file_ino in order and parent_ino in order
    assert order.index(file_ino) < order.index(parent_ino)


def test_atomic_write_leaves_no_temp(tmp_path: Path) -> None:
    target = tmp_path / "f"
    atomic_write(target, b"x", 0o600, UID)
    temps = [n for n in os.listdir(tmp_path) if n.startswith(".tr-")]
    assert temps == []


def test_atomic_write_refuses_foreign_owned_parent(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "f"
    parent_ino = os.lstat(tmp_path).st_ino
    _patch_stat(monkeypatch, parent_ino, uid=UID + 1)
    with pytest.raises(UnsafeLifecyclePath):
        atomic_write(target, b"x", 0o600, UID)


def test_atomic_symlink_creates_literal_target(tmp_path: Path) -> None:
    link = tmp_path / "lnk"
    atomic_symlink(link, "/some/abs/target", UID)
    st = os.lstat(link)
    assert stat.S_ISLNK(st.st_mode)
    assert os.readlink(link) == "/some/abs/target"


def test_atomic_symlink_replaces_existing_symlink(tmp_path: Path) -> None:
    link = tmp_path / "lnk"
    os.symlink("/old", link)
    atomic_symlink(link, "/new", UID)
    assert os.readlink(link) == "/new"


def test_atomic_symlink_rejects_target_tamper(tmp_path: Path, monkeypatch) -> None:
    link = tmp_path / "lnk"
    # sabotage readlink so the verification sees a different target
    real_readlink = os.readlink

    def patched(path, *args, **kwargs):
        return "/tampered"

    monkeypatch.setattr(os, "readlink", patched)
    with pytest.raises(ConcurrentLifecycleChange):
        atomic_symlink(link, "/intended", UID)


def test_atomic_symlink_fsyncs_parent(tmp_path: Path, monkeypatch) -> None:
    link = tmp_path / "lnk"
    calls: list[int] = []
    real_fsync = os.fsync

    def rec(fd: int) -> None:
        calls.append(os.fstat(fd).st_ino)
        return real_fsync(fd)

    monkeypatch.setattr(os, "fsync", rec)
    atomic_symlink(link, "/t", UID)
    assert os.lstat(tmp_path).st_ino in calls


def test_atomic_rename_replaces_destination(tmp_path: Path) -> None:
    dest = tmp_path / "dest"
    dest.write_bytes(b"old")
    dest.chmod(0o600)
    expected = _ident(dest)
    src = tmp_path / "src"
    src.write_bytes(b"new")
    src.chmod(0o600)
    new = atomic_rename(src, dest, expected, UID)
    assert not src.exists()
    assert dest.read_bytes() == b"new"
    assert new.inode == os.lstat(dest).st_ino


def test_atomic_rename_refuses_swapped_destination(tmp_path: Path) -> None:
    dest = tmp_path / "dest"
    os.symlink("/old", dest)
    expected = _ident(dest)
    # swap the destination by renaming a different object (regular file) over
    # it so the inode/type definitely changes (inode reuse would defeat an
    # unlink-then-recreate swap on tmpfs).
    impostor = tmp_path / "impostor"
    impostor.write_bytes(b"x")
    os.rename(impostor, dest)
    src = tmp_path / "src"
    os.symlink("/new", src)
    with pytest.raises(ConcurrentLifecycleChange):
        atomic_rename(src, dest, expected, UID)
    # the swapped destination survives untouched (no promotion of our source)
    assert dest.read_bytes() == b"x"
    assert os.path.lexists(src)


def test_atomic_rename_refuses_missing_destination(tmp_path: Path) -> None:
    dest = tmp_path / "missing"
    expected = NodeIdentity(0, 0, 0, 0, 0)
    src = tmp_path / "src"
    src.write_bytes(b"x")
    with pytest.raises(ConcurrentLifecycleChange):
        atomic_rename(src, dest, expected, UID)


def test_restore_before_absent_unlinks_existing(tmp_path: Path) -> None:
    p = tmp_path / "f"
    p.write_bytes(b"present")
    p.chmod(0o600)
    img = BeforeImage(str(p), ObjectKind.ABSENT, None, None, None, None)
    restore_before(img, UID)
    assert not p.exists()


def test_restore_before_file_writes_content_and_mode(tmp_path: Path) -> None:
    p = tmp_path / "f"
    img = BeforeImage(str(p), ObjectKind.FILE, 0o600, None, b"restored", hashlib.sha256(b"restored").hexdigest())
    restore_before(img, UID)
    assert p.read_bytes() == b"restored"
    assert stat.S_IMODE(os.lstat(p).st_mode) == 0o600


def test_restore_before_symlink_recreates_target(tmp_path: Path) -> None:
    p = tmp_path / "lnk"
    img = BeforeImage(str(p), ObjectKind.SYMLINK, 0o777, "/orig", None, None)
    restore_before(img, UID)
    assert stat.S_ISLNK(os.lstat(p).st_mode)
    assert os.readlink(p) == "/orig"


def test_restore_before_absent_when_already_absent(tmp_path: Path) -> None:
    p = tmp_path / "missing"
    img = BeforeImage(str(p), ObjectKind.ABSENT, None, None, None, None)
    restore_before(img, UID)
    assert not p.exists()


# ---------------------------------------------------------------------------
# Lock infrastructure
# ---------------------------------------------------------------------------


def test_open_lock_infrastructure_creates_fresh(tmp_path: Path) -> None:
    plan = _lock_plan(tmp_path, may_create_directory=True, may_create_lock=True)
    dir_fd, lock_fd = open_lock_infrastructure(plan, UID)
    try:
        validate_lock_infrastructure(plan, dir_fd, lock_fd, UID)
        dst = os.fstat(dir_fd)
        lst = os.fstat(lock_fd)
        assert stat.S_ISDIR(dst.st_mode) and stat.S_IMODE(dst.st_mode) == 0o700
        assert stat.S_ISREG(lst.st_mode) and stat.S_IMODE(lst.st_mode) == 0o600
        assert dst.st_uid == UID and lst.st_uid == UID
        assert lst.st_nlink == 1
    finally:
        os.close(lock_fd)
        os.close(dir_fd)


def test_open_lock_infrastructure_opens_preexisting_safe(tmp_path: Path) -> None:
    dir_path = tmp_path / "tr-config"
    dir_path.mkdir(mode=0o700)
    lock_path = dir_path / "lifecycle.lock"
    fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    plan = _lock_plan(
        tmp_path,
        may_create_directory=False,
        may_create_lock=False,
        dir_path=str(dir_path),
        lock_path=str(lock_path),
    )
    dir_fd, lock_fd = open_lock_infrastructure(plan, UID)
    try:
        validate_lock_infrastructure(plan, dir_fd, lock_fd, UID)
    finally:
        os.close(lock_fd)
        os.close(dir_fd)


def test_open_lock_infrastructure_never_repairs_mode(tmp_path: Path) -> None:
    dir_path = tmp_path / "tr-config"
    dir_path.mkdir(mode=0o700)
    lock_path = dir_path / "lifecycle.lock"
    lock_path.write_bytes(b"")
    lock_path.chmod(0o644)  # wrong mode
    plan = _lock_plan(
        tmp_path,
        may_create_directory=False,
        may_create_lock=False,
        dir_path=str(dir_path),
        lock_path=str(lock_path),
    )
    dir_fd, lock_fd = open_lock_infrastructure(plan, UID)
    try:
        with pytest.raises(UnsafeLifecyclePath):
            validate_lock_infrastructure(plan, dir_fd, lock_fd, UID)
        assert stat.S_IMODE(os.lstat(lock_path).st_mode) == 0o644
    finally:
        os.close(lock_fd)
        os.close(dir_fd)


def test_open_lock_infrastructure_refuses_unexpected_preexisting_directory(tmp_path: Path) -> None:
    plan = _lock_plan(tmp_path, may_create_directory=True, may_create_lock=True)
    # pre-create the directory that the plan authorizes creating -> refusal
    os.mkdir(plan.directory_path, 0o700)
    with pytest.raises(UnsafeLifecyclePath):
        open_lock_infrastructure(plan, UID)


def test_open_lock_infrastructure_refuses_unexpected_preexisting_lock(tmp_path: Path) -> None:
    dir_path = tmp_path / "tr-config"
    dir_path.mkdir(mode=0o700)
    lock_path = dir_path / "lifecycle.lock"
    lock_path.write_bytes(b"")
    lock_path.chmod(0o600)
    plan = _lock_plan(
        tmp_path,
        may_create_directory=False,
        may_create_lock=True,
        dir_path=str(dir_path),
        lock_path=str(lock_path),
    )
    with pytest.raises(UnsafeLifecyclePath):
        open_lock_infrastructure(plan, UID)


def test_lock_refuses_symlink_as_lock(tmp_path: Path) -> None:
    sentinel = tmp_path / "secret"
    sentinel.write_bytes(b"x")
    dir_path = tmp_path / "tr-config"
    dir_path.mkdir(mode=0o700)
    lock_path = dir_path / "lifecycle.lock"
    os.symlink(sentinel, lock_path)
    plan = _lock_plan(
        tmp_path,
        may_create_directory=False,
        may_create_lock=False,
        dir_path=str(dir_path),
        lock_path=str(lock_path),
    )
    with pytest.raises(UnsafeLifecyclePath):
        open_lock_infrastructure(plan, UID)
    assert sentinel.read_bytes() == b"x"
    assert os.path.islink(lock_path)


def test_lock_refuses_directory_as_lock(tmp_path: Path) -> None:
    dir_path = tmp_path / "tr-config"
    dir_path.mkdir(mode=0o700)
    lock_path = dir_path / "lifecycle.lock"
    lock_path.mkdir(mode=0o600)
    plan = _lock_plan(
        tmp_path,
        may_create_directory=False,
        may_create_lock=False,
        dir_path=str(dir_path),
        lock_path=str(lock_path),
    )
    with pytest.raises(UnsafeLifecyclePath):
        open_lock_infrastructure(plan, UID)


def test_lock_refuses_fifo_as_lock(tmp_path: Path) -> None:
    dir_path = tmp_path / "tr-config"
    dir_path.mkdir(mode=0o700)
    lock_path = dir_path / "lifecycle.lock"
    os.mkfifo(lock_path, 0o600)
    plan = _lock_plan(
        tmp_path,
        may_create_directory=False,
        may_create_lock=False,
        dir_path=str(dir_path),
        lock_path=str(lock_path),
    )
    with pytest.raises(UnsafeLifecyclePath):
        open_lock_infrastructure(plan, UID)


def test_lock_refuses_hardlinked_lock(tmp_path: Path) -> None:
    dir_path = tmp_path / "tr-config"
    dir_path.mkdir(mode=0o700)
    other = dir_path / "other"
    other.write_bytes(b"")
    other.chmod(0o600)
    lock_path = dir_path / "lifecycle.lock"
    os.link(other, lock_path)
    plan = _lock_plan(
        tmp_path,
        may_create_directory=False,
        may_create_lock=False,
        dir_path=str(dir_path),
        lock_path=str(lock_path),
    )
    dir_fd, lock_fd = open_lock_infrastructure(plan, UID)
    try:
        with pytest.raises(UnsafeLifecyclePath):
            validate_lock_infrastructure(plan, dir_fd, lock_fd, UID)
    finally:
        os.close(lock_fd)
        os.close(dir_fd)


def test_lock_refuses_foreign_owner(tmp_path: Path, monkeypatch) -> None:
    dir_path = tmp_path / "tr-config"
    dir_path.mkdir(mode=0o700)
    lock_path = dir_path / "lifecycle.lock"
    fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    plan = _lock_plan(
        tmp_path,
        may_create_directory=False,
        may_create_lock=False,
        dir_path=str(dir_path),
        lock_path=str(lock_path),
    )
    dir_fd, lock_fd = open_lock_infrastructure(plan, UID)
    try:
        lock_ino = os.fstat(lock_fd).st_ino
        _patch_stat(monkeypatch, lock_ino, uid=UID + 1)
        with pytest.raises(UnsafeLifecyclePath):
            validate_lock_infrastructure(plan, dir_fd, lock_fd, UID)
    finally:
        os.close(lock_fd)
        os.close(dir_fd)


def test_lock_refuses_group_writable_directory(tmp_path: Path) -> None:
    dir_path = tmp_path / "tr-config"
    dir_path.mkdir(mode=0o770)
    plan = _lock_plan(
        tmp_path,
        may_create_directory=False,
        may_create_lock=False,
        dir_path=str(dir_path),
    )
    with pytest.raises(UnsafeLifecyclePath):
        open_lock_infrastructure(plan, UID)


def test_lock_refuses_path_substitution_between_open_and_validate(tmp_path: Path) -> None:
    dir_path = tmp_path / "tr-config"
    dir_path.mkdir(mode=0o700)
    lock_path = dir_path / "lifecycle.lock"
    fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    plan = _lock_plan(
        tmp_path,
        may_create_directory=False,
        may_create_lock=False,
        dir_path=str(dir_path),
        lock_path=str(lock_path),
    )
    dir_fd, lock_fd = open_lock_infrastructure(plan, UID)
    try:
        # swap the lock inode by rename-over
        impostor = dir_path / "impostor"
        impostor.write_bytes(b"")
        impostor.chmod(0o600)
        os.rename(impostor, lock_path)
        with pytest.raises(ConcurrentLifecycleChange):
            validate_lock_infrastructure(plan, dir_fd, lock_fd, UID)
    finally:
        os.close(lock_fd)
        os.close(dir_fd)


def test_lock_creation_preserves_external_sentinel(tmp_path: Path) -> None:
    sentinel = tmp_path / "external-secret"
    sentinel.write_bytes(b"kept")
    # an attacker places a symlink lock pointing at the sentinel
    dir_path = tmp_path / "tr-config"
    dir_path.mkdir(mode=0o700)
    lock_path = dir_path / "lifecycle.lock"
    os.symlink(sentinel, lock_path)
    plan = _lock_plan(
        tmp_path,
        may_create_directory=False,
        may_create_lock=True,  # authorize create -> O_EXCL must refuse the existing symlink
        dir_path=str(dir_path),
        lock_path=str(lock_path),
    )
    with pytest.raises(UnsafeLifecyclePath):
        open_lock_infrastructure(plan, UID)
    assert sentinel.read_bytes() == b"kept"
    assert os.path.islink(lock_path)  # not replaced


def test_lifecycle_lock_is_exclusive_and_released(tmp_path: Path) -> None:
    import fcntl

    dir_path = tmp_path / "tr-config"
    dir_path.mkdir(mode=0o700)
    lock_path = dir_path / "lifecycle.lock"
    fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    plan = _lock_plan(
        tmp_path,
        may_create_directory=False,
        may_create_lock=False,
        dir_path=str(dir_path),
        lock_path=str(lock_path),
    )
    dir_fd, lock_fd = open_lock_infrastructure(plan, UID)
    other_fd = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
    try:
        with acquire_lifecycle_lock(lock_fd):
            with pytest.raises(BlockingIOError):
                fcntl.flock(other_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # released after context exit
        fcntl.flock(other_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(other_fd, fcntl.LOCK_UN)
    finally:
        os.close(other_fd)
        os.close(lock_fd)
        os.close(dir_fd)


# ---------------------------------------------------------------------------
# Structural deletion
# ---------------------------------------------------------------------------


def test_real_venv_with_leaf_symlinks_is_deleted(secure_tree: SecureTree) -> None:
    secure_tree.make_venv()
    assert (secure_tree.root / "venv").exists()
    secure_tree.delete_generation()
    assert not secure_tree.root.exists()


def test_leaf_symlink_never_reaches_external_sentinel(secure_tree: SecureTree) -> None:
    secure_tree.make_venv()
    secure_tree.add_leaf_symlink("escape", str(secure_tree.sentinel))
    secure_tree.delete_generation()
    assert not secure_tree.root.exists()
    assert secure_tree.sentinel_bytes == b"operator-owned"


def test_delete_tree_structural_real_venv(secure_tree: SecureTree) -> None:
    secure_tree.make_venv()
    root_ident = _ident(secure_tree.root)
    policy = TreePolicy(
        root_device=root_ident.device,
        uid=UID,
        top_level_allowlist=frozenset({MARKER_NAME, "venv"}),
    )
    delete_tree_structural(secure_tree.root, root_ident, policy)
    assert not secure_tree.root.exists()


def test_delete_refuses_missing_top_level_entry(secure_tree: SecureTree) -> None:
    secure_tree.make_venv()
    marker = secure_tree.marker_identity()  # capture before removal
    # remove the marker so top-level is only "venv"
    (secure_tree.root / MARKER_NAME).unlink()
    with pytest.raises(UnsafeLifecyclePath):
        verified_delete_generation(secure_tree.root, marker, UID)
    assert secure_tree.root.exists()
    assert secure_tree.sentinel_bytes == b"operator-owned"


def test_delete_refuses_extra_top_level_entry(secure_tree: SecureTree) -> None:
    secure_tree.make_venv()
    secure_tree.add_top_level("unauthorized")
    with pytest.raises(UnsafeLifecyclePath):
        secure_tree.delete_generation()
    assert secure_tree.root.exists()
    assert (secure_tree.root / "unauthorized").exists()
    assert secure_tree.sentinel_bytes == b"operator-owned"


def test_delete_refuses_marker_hardlink(secure_tree: SecureTree) -> None:
    secure_tree.make_venv()
    # turn the marker into a 2-link file
    other = secure_tree.root / "marker-copy"
    os.link(secure_tree.root / MARKER_NAME, other)
    with pytest.raises(UnsafeLifecyclePath):
        secure_tree.delete_generation()
    assert secure_tree.root.exists()
    assert secure_tree.sentinel_bytes == b"operator-owned"


def test_delete_refuses_noncanonical_marker_bytes(secure_tree: SecureTree) -> None:
    secure_tree.make_venv()
    secure_tree.make_marker(canonical=False)
    with pytest.raises(UnsafeLifecyclePath):
        secure_tree.delete_generation()
    assert secure_tree.root.exists()


def test_delete_refuses_marker_content_mismatch(secure_tree: SecureTree) -> None:
    secure_tree.make_venv()
    # claim a hash that does not match on-disk bytes
    real = secure_tree.marker_identity()
    bogus = MarkerIdentity(real.path, "0" * 64, real.mode)
    with pytest.raises(UnsafeLifecyclePath):
        verified_delete_generation(secure_tree.root, bogus, UID)
    assert secure_tree.root.exists()


def test_delete_refuses_marker_wrong_mode(secure_tree: SecureTree) -> None:
    secure_tree.make_venv()
    secure_tree.make_marker(mode=0o644)
    with pytest.raises(UnsafeLifecyclePath):
        secure_tree.delete_generation()
    assert secure_tree.root.exists()


def test_delete_refuses_descendant_hardlink(secure_tree: SecureTree) -> None:
    secure_tree.make_venv()
    secure_tree.add_hardlink_to_sentinel("evil")
    with pytest.raises(UnsafeLifecyclePath):
        secure_tree.delete_generation()
    assert secure_tree.root.exists()
    assert secure_tree.sentinel_bytes == b"operator-owned"


def test_delete_refuses_fifo(secure_tree: SecureTree) -> None:
    secure_tree.make_venv()
    secure_tree.add_fifo("pipe")
    with pytest.raises(UnsafeLifecyclePath):
        secure_tree.delete_generation()
    assert secure_tree.root.exists()
    assert secure_tree.sentinel_bytes == b"operator-owned"


def test_delete_refuses_socket(secure_tree: SecureTree) -> None:
    secure_tree.make_venv()
    secure_tree.add_socket("sock")
    with pytest.raises(UnsafeLifecyclePath):
        secure_tree.delete_generation()
    assert secure_tree.root.exists()


def test_delete_refuses_special_device(secure_tree: SecureTree, monkeypatch) -> None:
    secure_tree.make_venv()
    secure_tree.add_regular("device-like", b"")
    target_ino = os.lstat(secure_tree.root / "venv" / "device-like").st_ino
    _patch_stat(monkeypatch, target_ino, mode=stat.S_IFCHR | 0o600)
    with pytest.raises(UnsafeLifecyclePath):
        secure_tree.delete_generation()
    assert secure_tree.root.exists()
    assert secure_tree.sentinel_bytes == b"operator-owned"


def test_delete_unlinks_directory_symlink_without_following(secure_tree: SecureTree) -> None:
    secure_tree.make_venv()
    secure_tree.add_leaf_symlink("dirlink", str(secure_tree.sentinel_home))
    secure_tree.delete_generation()
    assert not secure_tree.root.exists()
    # the sentinel home (target of the dir symlink) survives untouched
    assert (secure_tree.sentinel_home / "operator-secret").read_bytes() == b"operator-owned"


def test_delete_refuses_foreign_owned_descendant(secure_tree: SecureTree, monkeypatch) -> None:
    secure_tree.make_venv()
    secure_tree.add_regular("foreign", b"x")
    target_ino = os.lstat(secure_tree.root / "venv" / "foreign").st_ino
    _patch_stat(monkeypatch, target_ino, uid=UID + 1)
    with pytest.raises(UnsafeLifecyclePath):
        secure_tree.delete_generation()
    assert secure_tree.root.exists()


def test_delete_refuses_descendant_device_change(secure_tree: SecureTree, monkeypatch) -> None:
    secure_tree.make_venv()
    secure_tree.add_regular("on-other-dev", b"x")
    target_ino = os.lstat(secure_tree.root / "venv" / "on-other-dev").st_ino
    _patch_stat(monkeypatch, target_ino, device=999)
    with pytest.raises(UnsafeLifecyclePath):
        secure_tree.delete_generation()
    assert secure_tree.root.exists()
    assert secure_tree.sentinel_bytes == b"operator-owned"


def test_delete_refuses_writable_owned_root(secure_tree: SecureTree) -> None:
    secure_tree.make_venv()
    secure_tree.root.chmod(0o777)
    with pytest.raises(UnsafeLifecyclePath):
        secure_tree.delete_generation()
    assert secure_tree.root.exists()


def test_delete_tree_structural_refuses_root_inode_replacement(secure_tree: SecureTree) -> None:
    secure_tree.make_venv()
    expected = _ident(secure_tree.root)
    # swap the root by replacing it with a fresh directory of the same name
    old = secure_tree.root.parent / "old-gen"
    os.rename(secure_tree.root, old)
    secure_tree.root.mkdir(mode=0o700)
    shutil.copytree(old / "venv", secure_tree.root / "venv")
    shutil.copy2(old / MARKER_NAME, secure_tree.root / MARKER_NAME)
    policy = TreePolicy(expected.device, UID, frozenset({MARKER_NAME, "venv"}))
    with pytest.raises(ConcurrentLifecycleChange):
        delete_tree_structural(secure_tree.root, expected, policy)
    # original-old generation still intact (refusal touched nothing)
    assert (old / "venv").exists()
    assert secure_tree.sentinel_bytes == b"operator-owned"


def test_delete_tree_structural_refuses_wrong_device(secure_tree: SecureTree) -> None:
    secure_tree.make_venv()
    root_ident = _ident(secure_tree.root)
    policy = TreePolicy(
        root_device=root_ident.device + 1,
        uid=UID,
        top_level_allowlist=frozenset({MARKER_NAME, "venv"}),
    )
    with pytest.raises((UnsafeLifecyclePath, ConcurrentLifecycleChange)):
        delete_tree_structural(secure_tree.root, root_ident, policy)
    assert secure_tree.root.exists()


def test_delete_tree_structural_no_leaf_symlinks(secure_tree: SecureTree) -> None:
    secure_tree.make_venv()
    secure_tree.add_leaf_symlink("plain", "/anything")
    root_ident = _ident(secure_tree.root)
    policy = TreePolicy(
        root_device=root_ident.device,
        uid=UID,
        top_level_allowlist=frozenset({MARKER_NAME, "venv"}),
        allow_leaf_symlinks=False,
    )
    with pytest.raises(UnsafeLifecyclePath):
        delete_tree_structural(secure_tree.root, root_ident, policy)
    assert secure_tree.root.exists()


# ---------------------------------------------------------------------------
# remove_created_parents
# ---------------------------------------------------------------------------


def test_remove_created_parents_removes_empty_chain(tmp_path: Path) -> None:
    a = tmp_path / "a"
    b = a / "b"
    c = b / "c"
    c.mkdir(parents=True, mode=0o700)
    removed = remove_created_parents([c, b, a], UID)
    assert set(removed) == {a, b, c}
    assert not a.exists()


def test_remove_created_parents_stops_at_non_empty(tmp_path: Path) -> None:
    a = tmp_path / "a"
    b = a / "b"
    b.mkdir(parents=True, mode=0o700)
    (a / "keep").write_bytes(b"x")
    removed = remove_created_parents([b, a], UID)
    assert removed == ()
    assert a.exists() and b.exists()


def test_remove_created_parents_skips_absent(tmp_path: Path) -> None:
    a = tmp_path / "a"
    b = a / "b"
    a.mkdir(mode=0o700)
    removed = remove_created_parents([b, a], UID)
    assert removed == (a,)
    assert not a.exists()


# ---------------------------------------------------------------------------
# Quarantine
# ---------------------------------------------------------------------------


def _state_layout(tmp_path: Path) -> tuple[Path, Path]:
    """A state root and its sibling quarantine parent under one state home.

    The quarantine parent lives directly under the state home so that
    ``quarantine_parent.parent`` is the recorded source parent (the state
    home), matching the real ``${XDG_STATE_HOME}/.termrecall-quarantine``
    layout used by the lifecycle transaction.
    """
    state_home = tmp_path / "state"
    state_home.mkdir(mode=0o700)
    state_root = state_home / "termrecall"
    state_root.mkdir(mode=0o700)
    (state_root / "recovery").mkdir(mode=0o700)
    (state_root / "recovery" / "session.json").write_bytes(b'{"k":1}')
    (state_root / "recovery" / "session.json").chmod(0o600)
    os.symlink("/usr/bin/true", state_root / "recovery" / "leaf")
    quarantine_parent = state_home / ".termrecall-quarantine"
    return state_root, quarantine_parent


def _populate_state(state_root: Path) -> None:
    state_root.mkdir(mode=0o700)
    (state_root / "recovery").mkdir(mode=0o700)
    (state_root / "recovery" / "session.json").write_bytes(b'{"k":1}')
    (state_root / "recovery" / "session.json").chmod(0o600)
    os.symlink("/usr/bin/true", state_root / "recovery" / "leaf")


def test_quarantine_state_moves_tree_and_restores(tmp_path: Path) -> None:
    state_root, quarantine_parent = _state_layout(tmp_path)
    tree = quarantine_state(state_root, quarantine_parent, "inst-1", UID)
    assert not state_root.exists()
    assert quarantine_parent.exists() and quarantine_parent.stat().st_mode & 0o777 == 0o700
    restore_quarantine(tree, UID)
    assert state_root.exists()
    assert (state_root / "recovery" / "session.json").read_bytes() == b'{"k":1}'


def test_quarantine_creates_and_removes_parent(tmp_path: Path) -> None:
    state_root, quarantine_parent = _state_layout(tmp_path)
    assert not quarantine_parent.exists()
    tree = quarantine_state(state_root, quarantine_parent, "inst-1", UID)
    assert tree.created_parent is True
    delete_quarantine(tree, UID)
    assert not quarantine_parent.exists()


def test_quarantine_keeps_preexisting_parent(tmp_path: Path) -> None:
    state_root, quarantine_parent = _state_layout(tmp_path)
    quarantine_parent.mkdir(mode=0o700)
    tree = quarantine_state(state_root, quarantine_parent, "inst-1", UID)
    assert tree.created_parent is False
    delete_quarantine(tree, UID)
    assert quarantine_parent.exists()  # not removed (preexisted)


def test_quarantine_delete_removes_quarantined_tree(tmp_path: Path) -> None:
    state_root, quarantine_parent = _state_layout(tmp_path)
    tree = quarantine_state(state_root, quarantine_parent, "inst-1", UID)
    delete_quarantine(tree, UID)
    assert not (quarantine_parent / tree.quarantine_name).exists()
    assert not state_root.exists()


def test_quarantine_delete_refuses_identity_race(tmp_path: Path) -> None:
    state_root, quarantine_parent = _state_layout(tmp_path)
    tree = quarantine_state(state_root, quarantine_parent, "inst-1", UID)
    target = quarantine_parent / tree.quarantine_name
    old = quarantine_parent / "old-swapped"
    os.rename(target, old)
    target.mkdir(mode=0o700)
    (target / "venv").mkdir()
    with pytest.raises((ConcurrentLifecycleChange, UnsafeLifecyclePath, CleanupFailure)):
        delete_quarantine(tree, UID)
    assert target.exists()


def test_quarantine_no_live_path_fallback(tmp_path: Path) -> None:
    state_root, quarantine_parent = _state_layout(tmp_path)
    tree = quarantine_state(state_root, quarantine_parent, "inst-1", UID)
    # attacker re-creates the live state path with a sentinel file inside
    _populate_state(state_root)
    sentinel = state_root / "live-secret"
    sentinel.write_bytes(b"must-survive")
    delete_quarantine(tree, UID)
    assert sentinel.read_bytes() == b"must-survive"
    assert not (quarantine_parent / tree.quarantine_name).exists()


def test_quarantine_refuses_cross_device_parent(tmp_path: Path) -> None:
    state_root, _ = _state_layout(tmp_path)
    # /dev/shm is a separate filesystem from /tmp on this host; it is NOT under
    # the state home, so quarantine_state must refuse before any rename.
    quarantine_parent = Path("/dev/shm") / f"tr-quarantine-cross-{os.getpid()}"
    try:
        if os.stat("/dev/shm").st_dev == os.stat(tmp_path).st_dev:
            pytest.skip("no separate filesystem available for cross-device test")
        with pytest.raises(UnsafeLifecyclePath):
            quarantine_state(state_root, quarantine_parent, "inst-1", UID)
        assert state_root.exists()
    finally:
        if quarantine_parent.exists():
            _rmtree(quarantine_parent)


def test_quarantine_refuses_unsafe_state_tree(tmp_path: Path) -> None:
    state_root, quarantine_parent = _state_layout(tmp_path)
    os.mkfifo(state_root / "recovery" / "pipe", 0o600)
    with pytest.raises(UnsafeLifecyclePath):
        quarantine_state(state_root, quarantine_parent, "inst-1", UID)
    assert state_root.exists()
    assert (state_root / "recovery" / "pipe").exists()


def test_quarantine_collision_uses_unique_leaves(tmp_path: Path) -> None:
    state_root, quarantine_parent = _state_layout(tmp_path)
    tree1 = quarantine_state(state_root, quarantine_parent, "inst-1", UID)
    # a later transaction recreates the state root and must reserve a new leaf
    # that does not collide with the retained prior-quarantine leaf.
    _populate_state(state_root)
    tree2 = quarantine_state(state_root, quarantine_parent, "inst-1", UID)
    assert tree1.quarantine_name != tree2.quarantine_name
    assert (quarantine_parent / tree1.quarantine_name).exists()
    assert (quarantine_parent / tree2.quarantine_name).exists()


def test_quarantine_precommit_restore_reverses(tmp_path: Path) -> None:
    state_root, quarantine_parent = _state_layout(tmp_path)
    tree = quarantine_state(state_root, quarantine_parent, "inst-1", UID)
    # simulate a precommit failure: restore must move the tree back
    restore_quarantine(tree, UID)
    assert state_root.exists()
    assert (state_root / "recovery" / "session.json").exists()
    assert not (quarantine_parent / tree.quarantine_name).exists()


def test_restore_quarantine_refuses_if_source_replaced(tmp_path: Path) -> None:
    state_root, quarantine_parent = _state_layout(tmp_path)
    tree = quarantine_state(state_root, quarantine_parent, "inst-1", UID)
    # an attacker already recreated the source path
    _populate_state(state_root)
    (state_root / "live-secret").write_bytes(b"kept")
    with pytest.raises(ConcurrentLifecycleChange):
        restore_quarantine(tree, UID)
    assert (state_root / "live-secret").read_bytes() == b"kept"
