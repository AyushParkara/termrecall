# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import fcntl
import os
import subprocess
from pathlib import Path

import pytest


@pytest.fixture(scope="session")
def nonblock_helper(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = Path(__file__).parents[2]
    output = tmp_path_factory.mktemp("native") / "termrecall-nonblock"
    subprocess.run(
        [
            os.environ.get("CC", "cc"),
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            str(root / "native" / "termrecall-nonblock.c"),
            "-o",
            str(output),
        ],
        check=True,
        timeout=10,
    )
    return output


def test_helper_changes_the_parent_pipe_open_description(nonblock_helper: Path) -> None:
    read_fd, write_fd = os.pipe()
    try:
        subprocess.run(
            [str(nonblock_helper)],
            stdin=write_fd,
            close_fds=True,
            check=True,
            timeout=1,
        )
        assert fcntl.fcntl(write_fd, fcntl.F_GETFL) & os.O_NONBLOCK
    finally:
        os.close(read_fd)
        os.close(write_fd)


def test_helper_rejects_arguments_and_emits_nothing(nonblock_helper: Path) -> None:
    result = subprocess.run(
        [str(nonblock_helper), "unexpected"], capture_output=True, check=False, timeout=1
    )
    assert result.returncode == 64
    assert result.stdout == result.stderr == b""


def test_helper_reports_fcntl_failure(nonblock_helper: Path) -> None:
    result = subprocess.run(
        ["bash", "-c", 'exec 0<&-; exec "$1"', "bash", str(nonblock_helper)],
        capture_output=True,
        check=False,
        timeout=1,
    )
    assert result.returncode == 1
    assert result.stdout == result.stderr == b""
