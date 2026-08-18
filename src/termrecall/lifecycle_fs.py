# SPDX-License-Identifier: GPL-3.0-or-later
"""Descriptor-relative atomic filesystem operations and safe structural deletion.

All mutating operations open paths from ``/`` using ``O_NOFOLLOW`` and
``O_DIRECTORY`` for directories so that symlinked components cannot redirect a
write, a lock, or a deletion.  No unchecked recursive pathname deletion, no
symlink-repair shell helpers, no privilege escalation, and no unchecked
pathname recursion is ever used.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import ContextManager, Sequence

from termrecall.installer_contract import (
    BeforeImage,
    LockInfrastructurePlan,
    MarkerIdentity,
    ObjectKind,
)

MARKER_NAME = ".termrecall-generation.json"
_MAX_READ_BYTES = 1_048_576
_O_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_O_REG_RO = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
_O_REG_RW = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC


class UnsafeLifecyclePath(Exception):
    """An object is not the kind we may safely mutate or delete."""


class ConcurrentLifecycleChange(Exception):
    """An object's identity changed between observation and mutation."""


class CleanupFailure(Exception):
    """A structural cleanup could not be completed safely."""


@dataclass(frozen=True, slots=True)
class NodeIdentity:
    device: int
    inode: int
    uid: int
    mode: int
    nlink: int


@dataclass(frozen=True, slots=True)
class SafeSnapshot:
    images: tuple[BeforeImage, ...]
    ancestors: tuple[tuple[str, NodeIdentity], ...]


@dataclass(frozen=True, slots=True)
class TreePolicy:
    root_device: int
    uid: int
    top_level_allowlist: frozenset[str]
    allow_leaf_symlinks: bool = True


@dataclass(frozen=True, slots=True)
class QuarantinedTree:
    source_parent: NodeIdentity
    destination_parent: NodeIdentity
    root: NodeIdentity
    source_name: str
    quarantine_name: str
    quarantine_parent: Path
    created_parent: bool


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _identity(st: os.stat_result) -> NodeIdentity:
    return NodeIdentity(st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode), st.st_nlink)


def _validate_canonical_abs(path: Path) -> None:
    text = os.fspath(path)
    if not os.path.isabs(text) or os.path.normpath(text) != text:
        raise UnsafeLifecyclePath("path must be a canonical absolute path")


def _open_dir_chain(path: Path) -> tuple[int, NodeIdentity]:
    """Open an absolute directory path descriptor-relatively from ``/``.

    Each component is opened with ``O_DIRECTORY | O_NOFOLLOW`` so a symlinked
    component is refused.  ``FileNotFoundError`` propagates so callers can
    treat a missing path as absent; other ``OSError`` values become
    :class:`UnsafeLifecyclePath`.
    """
    _validate_canonical_abs(path)
    parts = [part for part in path.parts[1:]]
    fd = os.open(os.path.sep, _O_DIR)
    for part in parts:
        try:
            child = os.open(part, _O_DIR, dir_fd=fd)
        except FileNotFoundError:
            os.close(fd)
            raise
        except OSError as exc:
            os.close(fd)
            raise UnsafeLifecyclePath(f"unsafe path component {part!r}") from exc
        os.close(fd)
        fd = child
    st = os.fstat(fd)
    return fd, _identity(st)


def _read_fd(fd: int, size: int, max_bytes: int = _MAX_READ_BYTES) -> bytes:
    if size < 0 or size > max_bytes:
        raise UnsafeLifecyclePath("read exceeds configured bound")
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = os.read(fd, remaining)
        if not chunk:
            raise UnsafeLifecyclePath("unexpected end of file while reading")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    written = 0
    while written < len(view):
        n = os.write(fd, view[written:])
        if n <= 0:
            raise UnsafeLifecyclePath("write did not make progress")
        written += n


def _unique_name(prefix: str) -> str:
    return f"{prefix}{secrets.token_hex(12)}"


def _validate_parent_fd(parent_fd: int, uid: int) -> None:
    st = os.fstat(parent_fd)
    if not stat.S_ISDIR(st.st_mode):
        raise UnsafeLifecyclePath("parent is not a directory")
    if st.st_uid != uid:
        raise UnsafeLifecyclePath("parent is owned by a foreign user")
    if st.st_mode & 0o022:
        raise UnsafeLifecyclePath("parent is group or other writable")


# ---------------------------------------------------------------------------
# capture / inspect / revalidate
# ---------------------------------------------------------------------------


def capture_before(path: Path, uid: int, *, max_bytes: int = _MAX_READ_BYTES) -> BeforeImage:
    p = os.fspath(path)
    _validate_canonical_abs(path)
    try:
        parent_fd, _ = _open_dir_chain(path.parent)
    except FileNotFoundError:
        return BeforeImage(p, ObjectKind.ABSENT, None, None, None, None)
    try:
        try:
            st = os.lstat(path.name, dir_fd=parent_fd)
        except FileNotFoundError:
            return BeforeImage(p, ObjectKind.ABSENT, None, None, None, None)
        if stat.S_ISLNK(st.st_mode):
            target = os.readlink(path.name, dir_fd=parent_fd)
            return BeforeImage(p, ObjectKind.SYMLINK, stat.S_IMODE(st.st_mode), target, None, None)
        if not stat.S_ISREG(st.st_mode):
            raise UnsafeLifecyclePath(f"unsafe object type at {p}")
        if st.st_size > max_bytes:
            raise UnsafeLifecyclePath(f"object exceeds capture bound at {p}")
        fd = os.open(path.name, _O_REG_RO, dir_fd=parent_fd)
        try:
            fst = os.fstat(fd)
            if not stat.S_ISREG(fst.st_mode) or fst.st_ino != st.st_ino or fst.st_dev != st.st_dev:
                raise ConcurrentLifecycleChange(f"object raced during capture at {p}")
            raw = _read_fd(fd, fst.st_size, max_bytes)
        finally:
            os.close(fd)
        return BeforeImage(
            p,
            ObjectKind.FILE,
            stat.S_IMODE(st.st_mode),
            None,
            raw,
            hashlib.sha256(raw).hexdigest(),
        )
    finally:
        os.close(parent_fd)


def inspect_paths(paths: Sequence[Path], uid: int) -> SafeSnapshot:
    images = tuple(capture_before(Path(p), uid) for p in paths)
    ancestors: list[tuple[str, NodeIdentity]] = []
    seen: set[Path] = set()
    for raw in paths:
        current = Path(raw)
        while current not in seen:
            try:
                st = os.lstat(current)
            except FileNotFoundError:
                break
            ancestors.append((str(current), _identity(st)))
            seen.add(current)
            if current.parent == current:
                break
            current = current.parent
    return SafeSnapshot(images, tuple(ancestors))


def revalidate(snapshot: SafeSnapshot, uid: int) -> None:
    del uid
    for name, ident in snapshot.ancestors:
        try:
            st = os.lstat(name)
        except FileNotFoundError:
            raise ConcurrentLifecycleChange(name) from None
        if _identity(st) != ident:
            raise ConcurrentLifecycleChange(name)


# ---------------------------------------------------------------------------
# atomic write / symlink / rename / restore
# ---------------------------------------------------------------------------


def atomic_write(path: Path, data: bytes, mode: int, uid: int) -> None:
    target = Path(path)
    _validate_canonical_abs(target)
    parent_fd, _ = _open_dir_chain(target.parent)
    temp_fd: int | None = None
    temp_name = _unique_name(".tr-write-")
    try:
        _validate_parent_fd(parent_fd, uid)
        try:
            temp_fd = os.open(
                temp_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=parent_fd,
                mode=mode & 0o7777,
            )
        except OSError as exc:
            raise UnsafeLifecyclePath("temp file creation failed") from exc
        try:
            os.fchmod(temp_fd, mode & 0o7777)
            st = os.fstat(temp_fd)
            if (
                not stat.S_ISREG(st.st_mode)
                or stat.S_IMODE(st.st_mode) != (mode & 0o7777)
                or st.st_uid != uid
                or st.st_nlink != 1
            ):
                raise UnsafeLifecyclePath("temp file identity unsafe")
            _write_all(temp_fd, data)
            os.fsync(temp_fd)
        finally:
            os.close(temp_fd)
            temp_fd = None
        try:
            os.rename(temp_name, target.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        except OSError as exc:
            raise UnsafeLifecyclePath("atomic replace failed") from exc
        temp_name = ""  # promoted successfully
        os.fsync(parent_fd)
    finally:
        if temp_name:
            try:
                os.unlink(temp_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        os.close(parent_fd)


def atomic_symlink(path: Path, literal_target: str, uid: int) -> None:
    target = Path(path)
    _validate_canonical_abs(target)
    parent_fd, _ = _open_dir_chain(target.parent)
    temp_name = _unique_name(".tr-link-")
    created = False
    try:
        _validate_parent_fd(parent_fd, uid)
        try:
            os.symlink(literal_target, temp_name, dir_fd=parent_fd)
            created = True
        except OSError as exc:
            raise UnsafeLifecyclePath("temp symlink creation failed") from exc
        try:
            actual = os.readlink(temp_name, dir_fd=parent_fd)
            if actual != literal_target:
                raise ConcurrentLifecycleChange("temp symlink target tampered")
            try:
                os.rename(temp_name, target.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            except OSError as exc:
                raise UnsafeLifecyclePath("atomic link replace failed") from exc
            created = False
            os.fsync(parent_fd)
        except BaseException:
            if created:
                try:
                    os.unlink(temp_name, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass
            raise
    finally:
        os.close(parent_fd)


def atomic_rename(source: Path, destination: Path, expected: NodeIdentity, uid: int) -> NodeIdentity:
    src = Path(source)
    dst = Path(destination)
    _validate_canonical_abs(src)
    _validate_canonical_abs(dst)
    if src.parent != dst.parent:
        raise UnsafeLifecyclePath("source and destination must share a parent directory")
    parent_fd, _ = _open_dir_chain(dst.parent)
    try:
        _validate_parent_fd(parent_fd, uid)
        try:
            dst_st = os.lstat(dst.name, dir_fd=parent_fd)
        except FileNotFoundError:
            raise ConcurrentLifecycleChange("destination is absent")
        if _identity(dst_st) != expected:
            raise ConcurrentLifecycleChange("destination identity changed")
        try:
            src_st = os.lstat(src.name, dir_fd=parent_fd)
        except FileNotFoundError:
            raise ConcurrentLifecycleChange("source is absent")
        if src_st.st_uid != uid or src_st.st_nlink != 1:
            raise UnsafeLifecyclePath("source is not a single-owner leaf")
        try:
            os.rename(src.name, dst.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        except OSError as exc:
            raise UnsafeLifecyclePath("checked rename failed") from exc
        os.fsync(parent_fd)
        return _identity(os.lstat(dst.name, dir_fd=parent_fd))
    finally:
        os.close(parent_fd)


def _unlink_leaf_if_present(path: Path, uid: int) -> None:
    _validate_canonical_abs(path)
    try:
        parent_fd, _ = _open_dir_chain(path.parent)
    except FileNotFoundError:
        return
    try:
        _validate_parent_fd(parent_fd, uid)
        try:
            st = os.lstat(path.name, dir_fd=parent_fd)
        except FileNotFoundError:
            return
        if stat.S_ISDIR(st.st_mode):
            raise UnsafeLifecyclePath("cannot remove a directory as a leaf")
        policy = TreePolicy(st.st_dev, uid, frozenset(), allow_leaf_symlinks=True)
        if stat.S_ISLNK(st.st_mode):
            _safe_unlink_symlink(parent_fd, path.name, policy)
        elif stat.S_ISREG(st.st_mode):
            if st.st_uid != uid or st.st_nlink != 1:
                raise UnsafeLifecyclePath("unsafe leaf file to remove")
            _safe_unlink_regular(parent_fd, path.name, st, policy)
        else:
            raise UnsafeLifecyclePath("unsafe leaf object type")
    finally:
        os.close(parent_fd)


def restore_before(image: BeforeImage, uid: int) -> None:
    path = Path(image.path)
    _validate_canonical_abs(path)
    if image.kind is ObjectKind.ABSENT:
        _unlink_leaf_if_present(path, uid)
    elif image.kind is ObjectKind.FILE:
        atomic_write(path, image.content or b"", image.mode or 0o600, uid)
    elif image.kind is ObjectKind.SYMLINK:
        atomic_symlink(path, image.literal_target or "", uid)
    else:
        raise UnsafeLifecyclePath("unknown before-image kind")


# ---------------------------------------------------------------------------
# lock infrastructure
# ---------------------------------------------------------------------------


def _validate_lock_dir(dir_fd: int, plan: LockInfrastructurePlan, uid: int) -> None:
    st = os.fstat(dir_fd)
    if not stat.S_ISDIR(st.st_mode):
        raise UnsafeLifecyclePath("lock directory is not a directory")
    if stat.S_IMODE(st.st_mode) != plan.directory_mode:
        raise UnsafeLifecyclePath("lock directory has the wrong mode")
    if st.st_uid != uid:
        raise UnsafeLifecyclePath("lock directory is foreign-owned")
    if st.st_mode & 0o022:
        raise UnsafeLifecyclePath("lock directory is group or other writable")


def open_lock_infrastructure(plan: LockInfrastructurePlan, uid: int) -> tuple[int, int]:
    dir_path = Path(plan.directory_path)
    lock_path = Path(plan.lock_path)
    _validate_canonical_abs(dir_path)
    _validate_canonical_abs(lock_path)
    if lock_path.parent != dir_path:
        raise UnsafeLifecyclePath("lock must live directly inside the planned directory")
    if plan.directory_mode != 0o700 or plan.lock_mode != 0o600:
        raise UnsafeLifecyclePath("lock infrastructure modes must be 0700/0600")
    dir_parent_fd, _ = _open_dir_chain(dir_path.parent)
    dir_fd: int | None = None
    lock_fd: int | None = None
    try:
        if plan.may_create_directory:
            try:
                os.mkdir(dir_path.name, plan.directory_mode & 0o7777, dir_fd=dir_parent_fd)
            except FileExistsError:
                raise UnsafeLifecyclePath("planned directory unexpectedly exists") from None
            except OSError as exc:
                raise UnsafeLifecyclePath("planned directory creation failed") from exc
        try:
            dir_fd = os.open(dir_path.name, _O_DIR, dir_fd=dir_parent_fd)
        except OSError as exc:
            raise UnsafeLifecyclePath("unsafe lock directory") from exc
        _validate_lock_dir(dir_fd, plan, uid)
        if plan.may_create_lock:
            try:
                lock_fd = os.open(
                    lock_path.name,
                    os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=dir_fd,
                    mode=plan.lock_mode & 0o7777,
                )
            except FileExistsError:
                raise UnsafeLifecyclePath("planned lock unexpectedly exists") from None
            except OSError as exc:
                raise UnsafeLifecyclePath("unsafe lock creation") from exc
        else:
            try:
                lock_fd = os.open(lock_path.name, _O_REG_RW, dir_fd=dir_fd)
            except OSError as exc:
                raise UnsafeLifecyclePath("unsafe lock open") from exc
        # a freshly opened lock must be a regular file: refuse FIFOs/sockets
        lst = os.fstat(lock_fd)
        if not stat.S_ISREG(lst.st_mode):
            raise UnsafeLifecyclePath("lock is not a regular file")
        result = (dir_fd, lock_fd)
        dir_fd = None
        lock_fd = None
        return result
    finally:
        os.close(dir_parent_fd)
        if lock_fd is not None:
            os.close(lock_fd)
        if dir_fd is not None:
            os.close(dir_fd)


def validate_lock_infrastructure(
    plan: LockInfrastructurePlan, directory_fd: int, lock_fd: int, uid: int
) -> None:
    dst = os.fstat(directory_fd)
    lst = os.fstat(lock_fd)
    try:
        dir_lstat = os.lstat(plan.directory_path)
    except OSError as exc:
        raise UnsafeLifecyclePath("lock directory path missing") from exc
    try:
        lock_lstat = os.lstat(plan.lock_path)
    except OSError as exc:
        raise UnsafeLifecyclePath("lock path missing") from exc
    if dst.st_dev != dir_lstat.st_dev or dst.st_ino != dir_lstat.st_ino:
        raise ConcurrentLifecycleChange("directory descriptor and path disagree")
    if lst.st_dev != lock_lstat.st_dev or lst.st_ino != lock_lstat.st_ino:
        raise ConcurrentLifecycleChange("lock descriptor and path disagree")
    if not stat.S_ISDIR(dst.st_mode):
        raise UnsafeLifecyclePath("directory is not a directory")
    if stat.S_IMODE(dst.st_mode) != plan.directory_mode:
        raise UnsafeLifecyclePath("directory has the wrong mode")
    if dst.st_uid != uid or dir_lstat.st_uid != uid:
        raise UnsafeLifecyclePath("directory is foreign-owned")
    if dst.st_mode & 0o022:
        raise UnsafeLifecyclePath("directory is group or other writable")
    if not stat.S_ISREG(lst.st_mode):
        raise UnsafeLifecyclePath("lock is not a regular file")
    if stat.S_IMODE(lst.st_mode) != plan.lock_mode:
        raise UnsafeLifecyclePath("lock has the wrong mode")
    if lst.st_uid != uid or lock_lstat.st_uid != uid:
        raise UnsafeLifecyclePath("lock is foreign-owned")
    if lst.st_nlink != 1:
        raise UnsafeLifecyclePath("lock is hard-linked")


@contextlib.contextmanager
def acquire_lifecycle_lock(lock_fd: int) -> ContextManager[None]:  # type: ignore[override]
    """Acquire the lifecycle lock on a validated descriptor and release it on every path."""
    fcntl.flock(lock_fd, fcntl.LOCK_EX)
    try:
        yield
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)


# ---------------------------------------------------------------------------
# structural walker
# ---------------------------------------------------------------------------


def _safe_unlink_symlink(parent_fd: int, name: str, policy: TreePolicy) -> None:
    rst = os.lstat(name, dir_fd=parent_fd)
    if not stat.S_ISLNK(rst.st_mode):
        raise ConcurrentLifecycleChange(f"symlink raced for {name}")
    if rst.st_uid != policy.uid or rst.st_dev != policy.root_device:
        raise UnsafeLifecyclePath(f"unsafe leaf symlink {name}")
    os.unlink(name, dir_fd=parent_fd)


def _safe_unlink_regular(parent_fd: int, name: str, expected: os.stat_result, policy: TreePolicy) -> None:
    fd = os.open(name, _O_REG_RO, dir_fd=parent_fd)
    try:
        fst = os.fstat(fd)
        if fst.st_ino != expected.st_ino or fst.st_dev != expected.st_dev:
            raise ConcurrentLifecycleChange(f"file raced for {name}")
        if fst.st_uid != policy.uid:
            raise UnsafeLifecyclePath(f"file foreign-owned {name}")
        if fst.st_dev != policy.root_device:
            raise UnsafeLifecyclePath(f"file device change {name}")
        if fst.st_nlink != 1:
            raise UnsafeLifecyclePath(f"file hard-linked {name}")
        rst = os.lstat(name, dir_fd=parent_fd)
        if rst.st_ino != fst.st_ino or rst.st_dev != fst.st_dev:
            raise ConcurrentLifecycleChange(f"file raced before unlink {name}")
        os.unlink(name, dir_fd=parent_fd)
        pst = os.fstat(fd)
        if pst.st_nlink != 0:
            raise ConcurrentLifecycleChange(f"unlink raced for {name}")
    finally:
        os.close(fd)


def _walk_entry(parent_fd: int, name: str, st: os.stat_result, policy: TreePolicy, *, delete: bool) -> None:
    mode = st.st_mode
    if stat.S_ISLNK(mode):
        if not policy.allow_leaf_symlinks:
            raise UnsafeLifecyclePath(f"leaf symlink not allowed: {name}")
        if st.st_uid != policy.uid or st.st_dev != policy.root_device:
            raise UnsafeLifecyclePath(f"unsafe leaf symlink {name}")
        if delete:
            _safe_unlink_symlink(parent_fd, name, policy)
        return
    if stat.S_ISDIR(mode):
        try:
            child_fd = os.open(name, _O_DIR, dir_fd=parent_fd)
        except OSError as exc:
            raise UnsafeLifecyclePath(f"unsafe directory {name}") from exc
        try:
            cst = os.fstat(child_fd)
            if cst.st_uid != policy.uid:
                raise UnsafeLifecyclePath(f"directory foreign-owned {name}")
            if cst.st_dev != policy.root_device:
                raise UnsafeLifecyclePath(f"directory device change {name}")
            rst = os.lstat(name, dir_fd=parent_fd)
            if rst.st_ino != cst.st_ino or rst.st_dev != cst.st_dev:
                raise ConcurrentLifecycleChange(f"directory raced {name}")
            _walk_dir(child_fd, policy, top_level=False, delete=delete)
            if delete:
                os.fsync(child_fd)
        finally:
            os.close(child_fd)
        if delete:
            try:
                os.rmdir(name, dir_fd=parent_fd)
            except OSError as exc:
                raise ConcurrentLifecycleChange(f"directory rmdir failed {name}") from exc
        return
    if stat.S_ISREG(mode):
        if st.st_uid != policy.uid:
            raise UnsafeLifecyclePath(f"file foreign-owned {name}")
        if st.st_dev != policy.root_device:
            raise UnsafeLifecyclePath(f"file device change {name}")
        if st.st_nlink != 1:
            raise UnsafeLifecyclePath(f"file hard-linked {name}")
        if delete:
            _safe_unlink_regular(parent_fd, name, st, policy)
        return
    raise UnsafeLifecyclePath(f"unsafe special file {name}")


def _walk_dir(dir_fd: int, policy: TreePolicy, *, top_level: bool, delete: bool) -> None:
    names = sorted(os.listdir(dir_fd))
    if top_level:
        if frozenset(names) != policy.top_level_allowlist:
            raise UnsafeLifecyclePath("top-level entries do not match the allowlist")
    for name in names:
        st = os.lstat(name, dir_fd=dir_fd)
        _walk_entry(dir_fd, name, st, policy, delete=delete)
    if delete:
        os.fsync(dir_fd)


def delete_tree_structural(root: Path, expected: NodeIdentity, policy: TreePolicy) -> None:
    target = Path(root)
    _validate_canonical_abs(target)
    parent_fd, _ = _open_dir_chain(target.parent)
    try:
        try:
            root_fd = os.open(target.name, _O_DIR, dir_fd=parent_fd)
        except FileNotFoundError:
            raise ConcurrentLifecycleChange(f"root missing {target}") from None
        except OSError as exc:
            raise UnsafeLifecyclePath(f"unsafe root {target}") from exc
        try:
            st = os.fstat(root_fd)
            ident = _identity(st)
            if ident != expected:
                raise ConcurrentLifecycleChange(f"root identity changed {target}")
            if not stat.S_ISDIR(st.st_mode):
                raise UnsafeLifecyclePath("root is not a directory")
            if st.st_uid != policy.uid:
                raise UnsafeLifecyclePath("root is foreign-owned")
            if st.st_dev != policy.root_device:
                raise UnsafeLifecyclePath("root device change")
            if st.st_mode & 0o022:
                raise UnsafeLifecyclePath("root is group or other writable")
            _walk_dir(root_fd, policy, top_level=True, delete=True)
            os.fsync(root_fd)
        finally:
            os.close(root_fd)
        try:
            os.rmdir(target.name, dir_fd=parent_fd)
        except OSError as exc:
            raise ConcurrentLifecycleChange(f"root rmdir failed {target}") from exc
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


# ---------------------------------------------------------------------------
# generation deletion
# ---------------------------------------------------------------------------


def _validate_marker(root_fd: int, root: Path, marker: MarkerIdentity, root_device: int, uid: int) -> None:
    try:
        mst = os.lstat(MARKER_NAME, dir_fd=root_fd)
    except FileNotFoundError:
        raise UnsafeLifecyclePath("generation marker missing") from None
    if not stat.S_ISREG(mst.st_mode):
        raise UnsafeLifecyclePath("generation marker is not a regular file")
    if stat.S_IMODE(mst.st_mode) != 0o600:
        raise UnsafeLifecyclePath("generation marker has the wrong mode")
    if mst.st_uid != uid:
        raise UnsafeLifecyclePath("generation marker is foreign-owned")
    if mst.st_dev != root_device:
        raise UnsafeLifecyclePath("generation marker device change")
    if mst.st_nlink != 1:
        raise UnsafeLifecyclePath("generation marker is hard-linked")
    if marker.mode != 0o600:
        raise UnsafeLifecyclePath("expected marker mode is not 0600")
    if str(root / MARKER_NAME) != marker.path:
        raise UnsafeLifecyclePath("marker path does not match the generation root")
    mfd = os.open(MARKER_NAME, _O_REG_RO, dir_fd=root_fd)
    try:
        fst = os.fstat(mfd)
        if fst.st_ino != mst.st_ino or fst.st_dev != mst.st_dev:
            raise ConcurrentLifecycleChange("generation marker raced")
        if fst.st_nlink != 1:
            raise UnsafeLifecyclePath("generation marker is hard-linked")
        raw = _read_fd(mfd, fst.st_size)
        if hashlib.sha256(raw).hexdigest() != marker.content_sha256:
            raise UnsafeLifecyclePath("generation marker content mismatch")
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise UnsafeLifecyclePath("generation marker is not canonical JSON") from exc
        canonical = (
            json.dumps(parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            .encode("utf-8")
            + b"\n"
        )
        if canonical != raw:
            raise UnsafeLifecyclePath("generation marker is not canonical JSON")
        pst = os.fstat(mfd)
        if pst.st_ino != fst.st_ino or pst.st_size != len(raw):
            raise ConcurrentLifecycleChange("generation marker raced during read")
    finally:
        os.close(mfd)


def verified_delete_generation(path: Path, marker: MarkerIdentity, uid: int) -> None:
    root = Path(path)
    _validate_canonical_abs(root)
    parent_fd, _ = _open_dir_chain(root.parent)
    try:
        try:
            root_fd = os.open(root.name, _O_DIR, dir_fd=parent_fd)
        except FileNotFoundError:
            raise UnsafeLifecyclePath("generation root missing") from None
        except OSError as exc:
            raise UnsafeLifecyclePath("unsafe generation root") from exc
        try:
            st = os.fstat(root_fd)
            if not stat.S_ISDIR(st.st_mode):
                raise UnsafeLifecyclePath("generation root is not a directory")
            if st.st_uid != uid:
                raise UnsafeLifecyclePath("generation root is foreign-owned")
            if stat.S_IMODE(st.st_mode) != 0o700:
                raise UnsafeLifecyclePath("generation root has the wrong mode")
            allowlist = frozenset({MARKER_NAME, "venv"})
            names = sorted(os.listdir(root_fd))
            if frozenset(names) != allowlist:
                raise UnsafeLifecyclePath("generation root top-level entries are invalid")
            _validate_marker(root_fd, root, marker, st.st_dev, uid)
            vst = os.lstat("venv", dir_fd=root_fd)
            if not stat.S_ISDIR(vst.st_mode):
                raise UnsafeLifecyclePath("venv is not a directory")
            policy = TreePolicy(st.st_dev, uid, allowlist, allow_leaf_symlinks=True)
            _walk_dir(root_fd, policy, top_level=True, delete=True)
            os.fsync(root_fd)
        finally:
            os.close(root_fd)
        os.rmdir(root.name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def remove_created_parents(paths: Sequence[Path], uid: int) -> tuple[Path, ...]:
    created = {Path(p) for p in paths}
    ordered = sorted(created, key=lambda p: len(p.parts), reverse=True)
    removable: set[Path] = set()
    for path in ordered:
        _validate_canonical_abs(path)
        try:
            parent_fd, _ = _open_dir_chain(path.parent)
        except FileNotFoundError:
            continue  # parent absent -> path absent
        try:
            try:
                fd = os.open(path.name, _O_DIR, dir_fd=parent_fd)
            except FileNotFoundError:
                continue
            except OSError:
                return ()
            try:
                st = os.fstat(fd)
                if not stat.S_ISDIR(st.st_mode) or st.st_uid != uid:
                    return ()
                entries = os.listdir(fd)
            finally:
                os.close(fd)
            for entry in entries:
                child = path / entry
                if child in created and child in removable:
                    continue
                return ()  # a non-removable entry makes the whole chain unsafe
            removable.add(path)
        finally:
            os.close(parent_fd)
    removed: list[Path] = []
    for path in sorted(removable, key=lambda p: len(p.parts), reverse=True):
        try:
            parent_fd, _ = _open_dir_chain(path.parent)
        except FileNotFoundError:
            break
        try:
            os.rmdir(path.name, dir_fd=parent_fd)
            os.fsync(parent_fd)
            removed.append(path)
        except OSError:
            break
        finally:
            os.close(parent_fd)
    return tuple(removed)


# ---------------------------------------------------------------------------
# quarantine
# ---------------------------------------------------------------------------


def _open_or_create_quarantine_parent(
    path: Path, expected_device: int, uid: int
) -> tuple[int, NodeIdentity, bool]:
    grandparent_fd, _ = _open_dir_chain(path.parent)
    created = False
    try:
        try:
            qfd = os.open(path.name, _O_DIR, dir_fd=grandparent_fd)
        except FileNotFoundError:
            try:
                os.mkdir(path.name, 0o700, dir_fd=grandparent_fd)
                created = True
            except OSError as exc:
                raise UnsafeLifecyclePath("quarantine parent creation failed") from exc
            try:
                qfd = os.open(path.name, _O_DIR, dir_fd=grandparent_fd)
            except OSError as exc:
                raise UnsafeLifecyclePath("unsafe quarantine parent") from exc
        except OSError as exc:
            raise UnsafeLifecyclePath("unsafe quarantine parent") from exc
        st = os.fstat(qfd)
        if not stat.S_ISDIR(st.st_mode):
            raise UnsafeLifecyclePath("quarantine parent is not a directory")
        if st.st_uid != uid:
            raise UnsafeLifecyclePath("quarantine parent is foreign-owned")
        if st.st_dev != expected_device:
            raise UnsafeLifecyclePath("quarantine parent is on a different device")
        if stat.S_IMODE(st.st_mode) != 0o700:
            raise UnsafeLifecyclePath("quarantine parent has the wrong mode")
        if st.st_mode & 0o022:
            raise UnsafeLifecyclePath("quarantine parent is group or other writable")
        return qfd, _identity(st), created
    finally:
        os.close(grandparent_fd)


def _reserve_leaf(q_parent_fd: int, install_id: str) -> str:
    for _ in range(512):
        name = f".termrecall-{install_id}-{secrets.token_hex(12)}"
        try:
            os.lstat(name, dir_fd=q_parent_fd)
        except FileNotFoundError:
            return name
    raise UnsafeLifecyclePath("could not reserve an absent quarantine leaf")


def quarantine_state(
    state_root: Path, quarantine_parent: Path, install_id: str, uid: int
) -> QuarantinedTree:
    root = Path(state_root)
    qparent = Path(quarantine_parent)
    _validate_canonical_abs(root)
    _validate_canonical_abs(qparent)
    # the quarantine parent must live under the state home so that the source
    # parent (state home) is recoverable as quarantine_parent.parent.
    if qparent.parent != root.parent:
        raise UnsafeLifecyclePath("quarantine parent must live under the state home")
    src_parent_fd, _ = _open_dir_chain(root.parent)
    root_fd: int | None = None
    q_parent_fd: int | None = None
    try:
        try:
            root_fd = os.open(root.name, _O_DIR, dir_fd=src_parent_fd)
        except FileNotFoundError:
            raise UnsafeLifecyclePath("state root missing") from None
        except OSError as exc:
            raise UnsafeLifecyclePath("unsafe state root") from exc
        try:
            st = os.fstat(root_fd)
            if not stat.S_ISDIR(st.st_mode):
                raise UnsafeLifecyclePath("state root is not a directory")
            if st.st_uid != uid:
                raise UnsafeLifecyclePath("state root is foreign-owned")
            if stat.S_IMODE(st.st_mode) != 0o700:
                raise UnsafeLifecyclePath("state root has the wrong mode")
            if st.st_mode & 0o022:
                raise UnsafeLifecyclePath("state root is group or other writable")
            root_ident = _identity(st)
            names = sorted(os.listdir(root_fd))
            policy = TreePolicy(st.st_dev, uid, frozenset(names), allow_leaf_symlinks=True)
            _walk_dir(root_fd, policy, top_level=True, delete=False)
            q_parent_fd, q_parent_ident, created_parent = _open_or_create_quarantine_parent(
                qparent, st.st_dev, uid
            )
            quarantine_name = _reserve_leaf(q_parent_fd, install_id)
            try:
                os.rename(
                    root.name,
                    quarantine_name,
                    src_dir_fd=src_parent_fd,
                    dst_dir_fd=q_parent_fd,
                )
            except OSError as exc:
                raise UnsafeLifecyclePath("quarantine rename failed") from exc
            os.fsync(src_parent_fd)
            os.fsync(q_parent_fd)
            # record parent identities as observed after the atomic rename so
            # restore_quarantine/delete_quarantine can detect a swapped parent
            # (the quarantine parent gained a leaf; the source parent lost one).
            src_parent_ident = _identity(os.fstat(src_parent_fd))
            q_parent_ident = _identity(os.fstat(q_parent_fd))
        finally:
            if q_parent_fd is not None:
                os.close(q_parent_fd)
    finally:
        if root_fd is not None:
            os.close(root_fd)
        os.close(src_parent_fd)
    return QuarantinedTree(
        source_parent=src_parent_ident,
        destination_parent=q_parent_ident,
        root=root_ident,
        source_name=root.name,
        quarantine_name=quarantine_name,
        quarantine_parent=qparent,
        created_parent=created_parent,
    )


def _open_quarantine_parent(tree: QuarantinedTree, uid: int) -> tuple[int, NodeIdentity]:
    qpath = tree.quarantine_parent
    grandparent_fd, _ = _open_dir_chain(qpath.parent)
    try:
        try:
            qfd = os.open(qpath.name, _O_DIR, dir_fd=grandparent_fd)
        except OSError as exc:
            raise UnsafeLifecyclePath("quarantine parent missing or unsafe") from exc
        st = os.fstat(qfd)
        if not stat.S_ISDIR(st.st_mode):
            raise UnsafeLifecyclePath("quarantine parent is not a directory")
        if st.st_uid != uid:
            raise UnsafeLifecyclePath("quarantine parent is foreign-owned")
        if st.st_mode & 0o022:
            raise UnsafeLifecyclePath("quarantine parent is group or other writable")
        return qfd, _identity(st)
    finally:
        os.close(grandparent_fd)


def _open_source_parent(tree: QuarantinedTree, uid: int) -> tuple[int, NodeIdentity]:
    """Open the state home (``quarantine_parent.parent``) no-follow."""
    src_parent_path = tree.quarantine_parent.parent
    parent_fd, _ = _open_dir_chain(src_parent_path)
    try:
        st = os.fstat(parent_fd)
        if not stat.S_ISDIR(st.st_mode):
            raise UnsafeLifecyclePath("source parent is not a directory")
        if st.st_uid != uid:
            raise UnsafeLifecyclePath("source parent is foreign-owned")
        if st.st_mode & 0o022:
            raise UnsafeLifecyclePath("source parent is group or other writable")
        return parent_fd, _identity(st)
    except BaseException:
        os.close(parent_fd)
        raise


def restore_quarantine(tree: QuarantinedTree, uid: int) -> None:
    q_parent_fd, q_parent_ident = _open_quarantine_parent(tree, uid)
    src_parent_fd: int | None = None
    try:
        if q_parent_ident != tree.destination_parent:
            raise ConcurrentLifecycleChange("quarantine parent identity changed")
        src_parent_fd, src_parent_ident = _open_source_parent(tree, uid)
        if src_parent_ident != tree.source_parent:
            raise ConcurrentLifecycleChange("source parent identity changed")
        # the original source name must be absent; only then may we rename back
        try:
            os.lstat(tree.source_name, dir_fd=src_parent_fd)
            raise ConcurrentLifecycleChange("source name is still occupied")
        except FileNotFoundError:
            pass
        try:
            qroot_fd = os.open(tree.quarantine_name, _O_DIR, dir_fd=q_parent_fd)
        except FileNotFoundError:
            raise ConcurrentLifecycleChange("quarantine root missing") from None
        except OSError as exc:
            raise UnsafeLifecyclePath("unsafe quarantine root") from exc
        try:
            qst = os.fstat(qroot_fd)
            if _identity(qst) != tree.root:
                raise ConcurrentLifecycleChange("quarantine root identity changed")
        finally:
            os.close(qroot_fd)
        try:
            os.rename(
                tree.quarantine_name,
                tree.source_name,
                src_dir_fd=q_parent_fd,
                dst_dir_fd=src_parent_fd,
            )
        except OSError as exc:
            raise UnsafeLifecyclePath("quarantine restore rename failed") from exc
        os.fsync(q_parent_fd)
        os.fsync(src_parent_fd)
    finally:
        if src_parent_fd is not None:
            os.close(src_parent_fd)
        os.close(q_parent_fd)


def _maybe_remove_quarantine_parent(
    qpath: Path, expected_ident: NodeIdentity, uid: int
) -> None:
    grandparent_fd, _ = _open_dir_chain(qpath.parent)
    try:
        try:
            qfd = os.open(qpath.name, _O_DIR, dir_fd=grandparent_fd)
        except OSError:
            return
        try:
            st = os.fstat(qfd)
            # compare the stable identity only (device/inode/uid); nlink is
            # expected to differ because we just removed the quarantined leaf.
            if (st.st_dev, st.st_ino, st.st_uid) != (
                expected_ident.device,
                expected_ident.inode,
                expected_ident.uid,
            ):
                return
            if st.st_mode & 0o022:
                return
            if os.listdir(qfd):
                return
        finally:
            os.close(qfd)
        try:
            os.rmdir(qpath.name, dir_fd=grandparent_fd)
            os.fsync(grandparent_fd)
        except OSError:
            return
    finally:
        os.close(grandparent_fd)


def delete_quarantine(tree: QuarantinedTree, uid: int) -> None:
    q_parent_fd, q_parent_ident = _open_quarantine_parent(tree, uid)
    try:
        if q_parent_ident != tree.destination_parent:
            raise CleanupFailure("quarantine parent identity changed")
        try:
            qroot_fd = os.open(tree.quarantine_name, _O_DIR, dir_fd=q_parent_fd)
        except FileNotFoundError:
            raise CleanupFailure("quarantine root missing") from None
        except OSError as exc:
            raise UnsafeLifecyclePath("unsafe quarantine root") from exc
        try:
            qst = os.fstat(qroot_fd)
            if _identity(qst) != tree.root:
                raise CleanupFailure("quarantine root identity changed")
            names = sorted(os.listdir(qroot_fd))
            policy = TreePolicy(qst.st_dev, uid, frozenset(names), allow_leaf_symlinks=True)
            _walk_dir(qroot_fd, policy, top_level=True, delete=True)
            os.fsync(qroot_fd)
        finally:
            os.close(qroot_fd)
        try:
            os.rmdir(tree.quarantine_name, dir_fd=q_parent_fd)
        except OSError as exc:
            raise CleanupFailure("quarantine root rmdir failed") from exc
        os.fsync(q_parent_fd)
        if tree.created_parent:
            _maybe_remove_quarantine_parent(tree.quarantine_parent, tree.destination_parent, uid)
    finally:
        os.close(q_parent_fd)


__all__ = [
    "NodeIdentity",
    "SafeSnapshot",
    "TreePolicy",
    "QuarantinedTree",
    "UnsafeLifecyclePath",
    "ConcurrentLifecycleChange",
    "CleanupFailure",
    "capture_before",
    "inspect_paths",
    "revalidate",
    "atomic_write",
    "atomic_symlink",
    "atomic_rename",
    "restore_before",
    "open_lock_infrastructure",
    "validate_lock_infrastructure",
    "acquire_lifecycle_lock",
    "delete_tree_structural",
    "verified_delete_generation",
    "remove_created_parents",
    "quarantine_state",
    "restore_quarantine",
    "delete_quarantine",
]
