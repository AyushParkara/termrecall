# SPDX-License-Identifier: GPL-3.0-or-later

import errno
import os
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from termrecall.model import ProcessIdentity
from termrecall.paths import read_boot_id

_MAX_STAT_BYTES = 65_536
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW


class ProcessInspectionError(RuntimeError):
    """Raised when process absence cannot be proven safely."""


class ProcessStatus(StrEnum):
    ALIVE = "alive"
    DEAD = "dead"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ProcessProbe:
    status: ProcessStatus
    diagnostic: str | None = None


def read_process_start_time(
    pid: int, proc_root: Path = Path("/proc")
) -> int:
    """Read Linux stat field 22 through a no-follow, directory-anchored path."""
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise ProcessInspectionError("process PID must be a positive integer")

    root_fd: int | None = None
    pid_fd: int | None = None
    stat_fd: int | None = None
    try:
        try:
            root_fd = os.open(proc_root, _DIRECTORY_FLAGS)
        except OSError as exc:
            raise ProcessInspectionError("unable to open process filesystem") from exc

        try:
            pid_fd = os.open(str(pid), _DIRECTORY_FLAGS, dir_fd=root_fd)
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                raise FileNotFoundError(pid) from exc
            raise ProcessInspectionError("unable to open process directory") from exc

        try:
            stat_fd = os.open("stat", _FILE_FLAGS, dir_fd=pid_fd)
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                raise FileNotFoundError(pid) from exc
            raise ProcessInspectionError("unable to open process stat") from exc

        try:
            data = os.read(stat_fd, _MAX_STAT_BYTES + 1)
        except OSError as exc:
            raise ProcessInspectionError("unable to read process stat") from exc
        if len(data) > _MAX_STAT_BYTES:
            raise ProcessInspectionError("process stat is oversized")
        return _parse_process_stat(pid, data)
    finally:
        for fd in (stat_fd, pid_fd, root_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass


def identity_status(
    identity: ProcessIdentity,
    current_boot_id: str,
    proc_root: Path = Path("/proc"),
) -> ProcessProbe:
    if identity.boot_id != current_boot_id:
        return ProcessProbe(
            ProcessStatus.UNKNOWN,
            f"process {identity.pid} status unknown: boot ID differs",
        )

    try:
        start_time = read_process_start_time(identity.pid, proc_root)
    except FileNotFoundError:
        return ProcessProbe(
            ProcessStatus.DEAD,
            f"process {identity.pid} is dead: process path is absent",
        )
    except ProcessInspectionError:
        return ProcessProbe(
            ProcessStatus.UNKNOWN,
            f"process {identity.pid} status unknown: inspection was inconclusive",
        )

    if start_time != identity.start_time:
        return ProcessProbe(
            ProcessStatus.DEAD,
            f"process {identity.pid} is dead: start time differs",
        )
    return ProcessProbe(ProcessStatus.ALIVE)


def current_identity(
    pid: int, boot_id_path: Path, proc_root: Path
) -> ProcessIdentity:
    return ProcessIdentity(
        boot_id=read_boot_id(boot_id_path),
        pid=pid,
        start_time=read_process_start_time(pid, proc_root),
    )


def _parse_process_stat(pid: int, data: bytes) -> int:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ProcessInspectionError("process stat is not ASCII") from exc

    close_paren = text.rfind(")")
    if close_paren < 0:
        raise ProcessInspectionError("process stat has no command terminator")

    prefix = text[:close_paren]
    open_paren = prefix.find("(")
    if open_paren < 0:
        raise ProcessInspectionError("process stat has no command opener")
    try:
        stat_pid = int(prefix[:open_paren].strip())
    except ValueError as exc:
        raise ProcessInspectionError("process stat has an invalid PID") from exc
    if stat_pid != pid:
        raise ProcessInspectionError("process stat PID does not match")

    suffix = text[close_paren + 1 :].split()
    if len(suffix) <= 19:
        raise ProcessInspectionError("process stat is truncated")
    try:
        start_time = int(suffix[19])
    except ValueError as exc:
        raise ProcessInspectionError("process stat has an invalid start time") from exc
    if start_time < 0:
        raise ProcessInspectionError("process stat has a negative start time")
    return start_time
