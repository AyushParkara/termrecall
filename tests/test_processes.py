# SPDX-License-Identifier: GPL-3.0-or-later

import errno
import os
from pathlib import Path

import pytest

from termrecall.model import ProcessIdentity
from termrecall.processes import (
    ProcessInspectionError,
    ProcessStatus,
    current_identity,
    identity_status,
    read_process_start_time,
)

BOOT_ID = "11111111-1111-1111-1111-111111111111"
OTHER_BOOT_ID = "22222222-2222-2222-2222-222222222222"


def write_stat(root: Path, pid: int, comm: str, start: int) -> None:
    directory = root / str(pid)
    directory.mkdir()
    suffix = ["S"] + ["0"] * 18 + [str(start)] + ["0"] * 5
    (directory / "stat").write_text(
        f"{pid} ({comm}) {' '.join(suffix)}\n", encoding="ascii"
    )


def test_start_time_parser_handles_spaces_and_close_parens(tmp_path: Path) -> None:
    write_stat(tmp_path, 71, "bash worker) name", 98765)

    assert read_process_start_time(71, tmp_path) == 98765


def test_matching_identity_is_alive(tmp_path: Path) -> None:
    write_stat(tmp_path, 71, "secret-command-text", 123)
    saved = ProcessIdentity(BOOT_ID, 71, 123)

    probe = identity_status(saved, BOOT_ID, tmp_path)

    assert probe.status is ProcessStatus.ALIVE
    assert probe.diagnostic is None


def test_pid_reuse_is_dead_without_exposing_command(tmp_path: Path) -> None:
    write_stat(tmp_path, 71, "secret-command-text", 999)
    saved = ProcessIdentity(BOOT_ID, 71, 123)

    probe = identity_status(saved, BOOT_ID, tmp_path)

    assert probe.status is ProcessStatus.DEAD
    assert probe.diagnostic is not None
    assert "71" in probe.diagnostic
    assert "dead" in probe.diagnostic.lower()
    assert "secret-command-text" not in probe.diagnostic


@pytest.mark.parametrize("missing_component", ["pid", "stat"])
def test_anchored_open_absence_is_dead(
    tmp_path: Path, missing_component: str
) -> None:
    if missing_component == "stat":
        (tmp_path / "71").mkdir()
    saved = ProcessIdentity(BOOT_ID, 71, 123)

    probe = identity_status(saved, BOOT_ID, tmp_path)

    assert probe.status is ProcessStatus.DEAD
    assert probe.diagnostic is not None
    assert "71" in probe.diagnostic
    assert "dead" in probe.diagnostic.lower()


def test_previous_boot_is_unknown_without_probing(tmp_path: Path) -> None:
    saved = ProcessIdentity(BOOT_ID, 71, 123)

    probe = identity_status(saved, OTHER_BOOT_ID, tmp_path / "missing")

    assert probe.status is ProcessStatus.UNKNOWN
    assert probe.diagnostic is not None
    assert "71" in probe.diagnostic
    assert "unknown" in probe.diagnostic.lower()


@pytest.mark.parametrize("error_number", [errno.ENOENT, errno.EACCES, errno.EPERM, errno.EIO])
@pytest.mark.parametrize("stage", ["proc_root", "pid_dir", "stat"])
def test_open_error_status_depends_on_anchored_absence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
    error_number: int,
) -> None:
    write_stat(tmp_path, 71, "secret-command-text", 123)
    saved = ProcessIdentity(BOOT_ID, 71, 123)
    real_open = os.open

    def failing_open(path: str | bytes, flags: int, *args: object, **kwargs: object) -> int:
        failing_stage = {
            tmp_path: "proc_root",
            "71": "pid_dir",
            "stat": "stat",
        }.get(path)
        if failing_stage == stage:
            raise OSError(error_number, os.strerror(error_number))
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", failing_open)

    probe = identity_status(saved, BOOT_ID, tmp_path)

    expected = (
        ProcessStatus.DEAD
        if stage in {"pid_dir", "stat"} and error_number == errno.ENOENT
        else ProcessStatus.UNKNOWN
    )
    assert probe.status is expected
    assert probe.diagnostic is not None
    assert "71" in probe.diagnostic
    assert expected.value in probe.diagnostic.lower()
    assert "secret-command-text" not in probe.diagnostic


@pytest.mark.parametrize("error_number", [errno.ENOENT, errno.EACCES, errno.EPERM, errno.EIO])
def test_read_errors_are_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error_number: int,
) -> None:
    write_stat(tmp_path, 71, "secret-command-text", 123)
    saved = ProcessIdentity(BOOT_ID, 71, 123)

    def failing_read(fd: int, length: int) -> bytes:
        raise OSError(error_number, os.strerror(error_number))

    monkeypatch.setattr(os, "read", failing_read)

    probe = identity_status(saved, BOOT_ID, tmp_path)

    assert probe.status is ProcessStatus.UNKNOWN
    assert probe.diagnostic is not None
    assert "71" in probe.diagnostic
    assert "unknown" in probe.diagnostic.lower()
    assert "secret-command-text" not in probe.diagnostic


@pytest.mark.parametrize(
    "stat_text",
    [
        "71 bash S 0 0\n",
        "71 (bash) S 0 0\n",
        "71 (bash) " + " ".join(["S"] + ["0"] * 18 + ["not-an-int"]) + "\n",
        "72 (bash) " + " ".join(["S"] + ["0"] * 18 + ["123"]) + "\n",
    ],
)
def test_malformed_or_truncated_stat_is_unknown(
    tmp_path: Path, stat_text: str
) -> None:
    directory = tmp_path / "71"
    directory.mkdir()
    (directory / "stat").write_text(stat_text, encoding="ascii")
    saved = ProcessIdentity(BOOT_ID, 71, 123)

    probe = identity_status(saved, BOOT_ID, tmp_path)

    assert probe.status is ProcessStatus.UNKNOWN
    assert probe.diagnostic is not None
    assert "71" in probe.diagnostic
    assert "unknown" in probe.diagnostic.lower()
    assert "bash" not in probe.diagnostic


@pytest.mark.parametrize(
    "stat_bytes",
    [
        b"71 (b\xffsh) " + b" ".join([b"S"] + [b"0"] * 18 + [b"123"]) + b"\n",
        b"71 (bash) " + b" ".join([b"S"] + [b"0"] * 18 + [b"-1"]) + b"\n",
        b"x" * 65_537,
    ],
    ids=["non-ascii", "negative-start-time", "oversized"],
)
def test_invalid_stat_bytes_are_unknown(tmp_path: Path, stat_bytes: bytes) -> None:
    directory = tmp_path / "71"
    directory.mkdir()
    (directory / "stat").write_bytes(stat_bytes)
    saved = ProcessIdentity(BOOT_ID, 71, 123)

    probe = identity_status(saved, BOOT_ID, tmp_path)

    assert probe.status is ProcessStatus.UNKNOWN
    assert probe.diagnostic is not None
    assert "71" in probe.diagnostic
    assert "unknown" in probe.diagnostic.lower()
    assert "bash" not in probe.diagnostic


def test_stat_symlink_is_unknown(tmp_path: Path) -> None:
    write_stat(tmp_path, 72, "secret-command-text", 123)
    directory = tmp_path / "71"
    directory.mkdir()
    (directory / "stat").symlink_to(tmp_path / "72" / "stat")
    saved = ProcessIdentity(BOOT_ID, 71, 123)

    probe = identity_status(saved, BOOT_ID, tmp_path)

    assert probe.status is ProcessStatus.UNKNOWN
    assert probe.diagnostic is not None
    assert "unknown" in probe.diagnostic.lower()
    assert "secret-command-text" not in probe.diagnostic


def test_pid_directory_symlink_is_unknown(tmp_path: Path) -> None:
    write_stat(tmp_path, 72, "secret-command-text", 123)
    (tmp_path / "71").symlink_to(tmp_path / "72", target_is_directory=True)
    saved = ProcessIdentity(BOOT_ID, 71, 123)

    probe = identity_status(saved, BOOT_ID, tmp_path)

    assert probe.status is ProcessStatus.UNKNOWN
    assert probe.diagnostic is not None
    assert "unknown" in probe.diagnostic.lower()
    assert "secret-command-text" not in probe.diagnostic


def test_disappearance_after_successful_open_is_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_stat(tmp_path, 71, "secret-command-text", 123)
    saved = ProcessIdentity(BOOT_ID, 71, 123)

    def disappearing_read(fd: int, length: int) -> bytes:
        raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))

    monkeypatch.setattr(os, "read", disappearing_read)

    probe = identity_status(saved, BOOT_ID, tmp_path)

    assert probe.status is ProcessStatus.UNKNOWN
    assert probe.diagnostic is not None
    assert "71" in probe.diagnostic
    assert "unknown" in probe.diagnostic.lower()
    assert "secret-command-text" not in probe.diagnostic


def test_read_start_time_distinguishes_absence_from_ambiguity(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        read_process_start_time(71, tmp_path)

    directory = tmp_path / "72"
    directory.mkdir()
    (directory / "stat").write_text("malformed\n", encoding="ascii")
    with pytest.raises(ProcessInspectionError):
        read_process_start_time(72, tmp_path)


def test_current_process_identity_smoke(tmp_path: Path) -> None:
    boot_id_path = tmp_path / "boot_id"
    boot_id_path.write_text(f"{BOOT_ID}\n", encoding="ascii")

    identity = current_identity(os.getpid(), boot_id_path, Path("/proc"))

    assert identity.pid == os.getpid()
    assert identity.boot_id == BOOT_ID
    assert identity_status(identity, BOOT_ID, Path("/proc")).status is ProcessStatus.ALIVE
