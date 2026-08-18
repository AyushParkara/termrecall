# SPDX-License-Identifier: GPL-3.0-or-later
"""Regression tests for audit findings #12 and #13.

#12: ``SnapshotStore`` must reject a state path that escapes the declared
     ``root_boundary`` via ``..`` traversal (``Path.absolute()`` does not
     normalize ``..``).
#13: ``staged_self_check`` must reject symlinked staged executables instead of
     accepting them via ``Path.exists()`` (which follows symlinks).
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path

import pytest

from termrecall.lifecycle import LifecycleError, staged_self_check
from termrecall.store import SnapshotStore, UnsafeStatePath


def test_snapshot_store_rejects_dotdot_escape_from_root_boundary(tmp_path: Path) -> None:
    # Finding #12: ``/root/../victim/state`` must not escape root_boundary.
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    victim = tmp_path / "victim"
    victim.mkdir()
    escape = root / ".." / "victim" / "state"

    with pytest.raises(UnsafeStatePath, match="boundary"):
        with SnapshotStore(escape, root_boundary=root):
            pass

    # The victim directory must not have been created outside the boundary.
    assert not (victim / "state").exists()


def test_snapshot_store_accepts_legitimate_path_inside_boundary(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    state = root / "nested" / "state"
    with SnapshotStore(state, create_parents=True, root_boundary=root):
        pass
    assert state.is_dir()


def test_staged_self_check_rejects_symlinked_executable(tmp_path: Path) -> None:
    # Finding #13: a symlinked venv executable must be rejected.
    stage = tmp_path / "stage"
    venv_bin = stage / "venv" / "bin"
    venv_bin.mkdir(parents=True, mode=0o700)
    for name in ("termrecall", "termrecall-bridge", "termrecall-nonblock"):
        exe = venv_bin / name
        exe.write_bytes(b"#!/bin/sh\necho ok\n")
        exe.chmod(0o755)
    marker = stage / ".termrecall-generation.json"
    marker.write_bytes(json.dumps({"schema": 2}).encode())
    marker.chmod(0o600)

    attacker = stage / "attacker"
    attacker.write_bytes(b"#!/bin/sh\necho pwned\n")
    attacker.chmod(0o755)
    (venv_bin / "termrecall").unlink()
    (venv_bin / "termrecall").symlink_to(attacker)

    with pytest.raises(LifecycleError, match="symlink"):
        staged_self_check(stage, None, None, os.getuid())


def test_staged_self_check_rejects_wrong_mode(tmp_path: Path) -> None:
    stage = tmp_path / "stage"
    venv_bin = stage / "venv" / "bin"
    venv_bin.mkdir(parents=True, mode=0o700)
    for name in ("termrecall", "termrecall-bridge", "termrecall-nonblock"):
        exe = venv_bin / name
        exe.write_bytes(b"#!/bin/sh\necho ok\n")
        exe.chmod(0o755)
    marker = stage / ".termrecall-generation.json"
    marker.write_bytes(json.dumps({"schema": 2}).encode())
    marker.chmod(0o600)
    (venv_bin / "termrecall").chmod(0o777)

    with pytest.raises(LifecycleError, match="mode"):
        staged_self_check(stage, None, None, os.getuid())


def test_staged_self_check_accepts_legitimate_executables(tmp_path: Path) -> None:
    stage = tmp_path / "stage"
    venv_bin = stage / "venv" / "bin"
    venv_bin.mkdir(parents=True, mode=0o700)
    for name in ("termrecall", "termrecall-bridge", "termrecall-nonblock"):
        exe = venv_bin / name
        exe.write_bytes(b"#!/bin/sh\necho ok\n")
        exe.chmod(0o755)
    marker = stage / ".termrecall-generation.json"
    marker.write_bytes(json.dumps({"schema": 2}).encode())
    marker.chmod(0o600)

    # Must not raise.
    staged_self_check(stage, None, None, os.getuid())
