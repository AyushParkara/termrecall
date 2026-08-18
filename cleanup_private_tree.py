#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Descriptor-relative structural cleanup helper for build/staging trees.

Invoked as::

    cleanup_private_tree.py ROOT EXPECTED_PARENT \\
        EXPECTED_PARENT_DEVICE EXPECTED_PARENT_INODE \\
        EXPECTED_ROOT_DEVICE EXPECTED_ROOT_INODE EXPECTED_UID

This is a standalone standard-library helper duplicated from
``src/termrecall/lifecycle_fs.py`` so it can run before the wheel is
installed.  It never shells out and never uses unchecked recursive pathname
deletion.  On any validation or cleanup failure the tree is retained
and a path-only warning is printed to standard error; the exit status is
nonzero but never masks an authoritative launcher/delegate status recorded by
the caller.
"""

from __future__ import annotations

import os
import stat
import sys

_O_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_O_REG_RO = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC


def _canonical_abs(path: str) -> bool:
    return os.path.isabs(path) and os.path.normpath(path) == path


def _open_dir_chain(path: str) -> tuple[int, "os.stat_result"]:
    """Open an absolute directory path from ``/`` with O_NOFOLLOW components."""
    fd = os.open(os.path.sep, _O_DIR)
    parts = [p for p in os.path.split(path)[0].split(os.path.sep) if p]
    for part in parts:
        try:
            child = os.open(part, _O_DIR, dir_fd=fd)
        except FileNotFoundError:
            os.close(fd)
            raise
        except OSError as exc:
            os.close(fd)
            raise UnsafePath(f"unsafe path component {part!r}") from exc
        os.close(fd)
        fd = child
    try:
        leaf = os.path.basename(path)
        if leaf:
            child = os.open(leaf, _O_DIR, dir_fd=fd)
            os.close(fd)
            fd = child
    except FileNotFoundError:
        os.close(fd)
        raise
    except OSError as exc:
        os.close(fd)
        raise UnsafePath(f"unsafe leaf {leaf!r}") from exc
    return fd, os.fstat(fd)


class UnsafePath(Exception):
    """An object is not safe to delete."""


class Race(Exception):
    """An object's identity changed during deletion."""


def _walk_entry(parent_fd: int, name: str, allow_leaf_symlinks: bool, root_device: int, uid: int) -> None:
    st = os.lstat(name, dir_fd=parent_fd)
    mode = st.st_mode
    if stat.S_ISLNK(mode):
        if not allow_leaf_symlinks:
            raise UnsafePath(f"leaf symlink not allowed: {name}")
        if st.st_uid != uid or st.st_dev != root_device:
            raise UnsafePath(f"unsafe leaf symlink: {name}")
        rst = os.lstat(name, dir_fd=parent_fd)
        if not stat.S_ISLNK(rst.st_mode) or rst.st_uid != uid or rst.st_dev != root_device:
            raise Race(f"symlink raced: {name}")
        os.unlink(name, dir_fd=parent_fd)
        return
    if stat.S_ISDIR(mode):
        try:
            child_fd = os.open(name, _O_DIR, dir_fd=parent_fd)
        except OSError as exc:
            raise UnsafePath(f"unsafe directory {name}") from exc
        try:
            cst = os.fstat(child_fd)
            if cst.st_uid != uid or cst.st_dev != root_device:
                raise UnsafePath(f"unsafe directory {name}")
            rst = os.lstat(name, dir_fd=parent_fd)
            if rst.st_ino != cst.st_ino or rst.st_dev != cst.st_dev:
                raise Race(f"directory raced: {name}")
            _walk_dir(child_fd, allow_leaf_symlinks, root_device, uid)
            os.fsync(child_fd)
        finally:
            os.close(child_fd)
        os.rmdir(name, dir_fd=parent_fd)
        return
    if stat.S_ISREG(mode):
        if st.st_uid != uid or st.st_dev != root_device or st.st_nlink != 1:
            raise UnsafePath(f"unsafe regular file: {name}")
        fd = os.open(name, _O_REG_RO, dir_fd=parent_fd)
        try:
            fst = os.fstat(fd)
            if fst.st_ino != st.st_ino or fst.st_dev != st.st_dev:
                raise Race(f"file raced: {name}")
            if fst.st_uid != uid or fst.st_dev != root_device or fst.st_nlink != 1:
                raise UnsafePath(f"unsafe regular file: {name}")
            rst = os.lstat(name, dir_fd=parent_fd)
            if rst.st_ino != fst.st_ino or rst.st_dev != fst.st_dev:
                raise Race(f"file raced before unlink: {name}")
            os.unlink(name, dir_fd=parent_fd)
            if os.fstat(fd).st_nlink != 0:
                raise Race(f"unlink raced: {name}")
        finally:
            os.close(fd)
        return
    raise UnsafePath(f"unsafe special file: {name}")


def _walk_dir(dir_fd: int, allow_leaf_symlinks: bool, root_device: int, uid: int) -> None:
    for name in sorted(os.listdir(dir_fd)):
        _walk_entry(dir_fd, name, allow_leaf_symlinks, root_device, uid)
    os.fsync(dir_fd)


def _parse_uint(text: str) -> int:
    if not text or not text.lstrip("+").isdigit():
        raise ValueError(f"not a non-negative integer: {text!r}")
    value = int(text, 10)
    if value < 0:
        raise ValueError(f"not a non-negative integer: {text!r}")
    return value


def main(argv: list[str]) -> int:
    if len(argv) != 8:
        sys.stderr.write(
            "usage: cleanup_private_tree.py ROOT EXPECTED_PARENT "
            "EXPECTED_PARENT_DEVICE EXPECTED_PARENT_INODE "
            "EXPECTED_ROOT_DEVICE EXPECTED_ROOT_INODE EXPECTED_UID\n"
        )
        return 2
    root_path = argv[1]
    parent_path = argv[2]
    for label, raw in (
        ("EXPECTED_PARENT_DEVICE", argv[3]),
        ("EXPECTED_PARENT_INODE", argv[4]),
        ("EXPECTED_ROOT_DEVICE", argv[5]),
        ("EXPECTED_ROOT_INODE", argv[6]),
        ("EXPECTED_UID", argv[7]),
    ):
        try:
            _parse_uint(raw)
        except ValueError:
            sys.stderr.write(f"cleanup_private_tree: invalid {label}: {raw!r}\n")
            return 2
    parent_device = int(argv[3], 10)
    parent_inode = int(argv[4], 10)
    root_device = int(argv[5], 10)
    root_inode = int(argv[6], 10)
    uid = int(argv[7], 10)
    if not _canonical_abs(root_path) or not _canonical_abs(parent_path):
        sys.stderr.write("cleanup_private_tree: paths must be canonical absolute\n")
        return 2
    if os.path.dirname(root_path) != parent_path:
        sys.stderr.write(
            f"cleanup_private_tree: retained {root_path} (not a direct child of expected parent)\n"
        )
        return 1
    parent_fd: int | None = None
    root_fd: int | None = None
    try:
        try:
            parent_fd, parent_st = _open_dir_chain(parent_path)
        except FileNotFoundError:
            sys.stderr.write(f"cleanup_private_tree: retained {root_path} (expected parent missing)\n")
            return 1
        except UnsafePath as exc:
            sys.stderr.write(f"cleanup_private_tree: retained {root_path} ({exc})\n")
            return 1
        if (
            parent_st.st_dev != parent_device
            or parent_st.st_ino != parent_inode
            or parent_st.st_uid != uid
        ):
            sys.stderr.write(f"cleanup_private_tree: retained {root_path} (parent identity mismatch)\n")
            return 1
        try:
            root_fd = os.open(os.path.basename(root_path), _O_DIR, dir_fd=parent_fd)
        except OSError as exc:
            sys.stderr.write(f"cleanup_private_tree: retained {root_path} (unsafe root: {exc})\n")
            return 1
        root_st = os.fstat(root_fd)
        if (
            not stat.S_ISDIR(root_st.st_mode)
            or root_st.st_dev != root_device
            or root_st.st_ino != root_inode
            or root_st.st_uid != uid
            or stat.S_IMODE(root_st.st_mode) != 0o700
        ):
            sys.stderr.write(f"cleanup_private_tree: retained {root_path} (root identity mismatch)\n")
            return 1
        names = sorted(os.listdir(root_fd))
        _walk_dir(root_fd, True, root_st.st_dev, uid)
        os.fsync(root_fd)
    except (UnsafePath, Race, OSError) as exc:
        sys.stderr.write(f"cleanup_private_tree: retained {root_path} ({exc})\n")
        return 1
    finally:
        if root_fd is not None:
            os.close(root_fd)
        if parent_fd is not None:
            try:
                os.rmdir(os.path.basename(root_path), dir_fd=parent_fd)
                os.fsync(parent_fd)
            except OSError:
                # deletion already succeeded for the contents; a failure to
                # remove the now-empty root is reported but not fatal.
                pass
            os.close(parent_fd)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
