# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import errno
import fcntl
import json
import os
import shutil
import socket
import stat
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from termrecall.adapters.base import TerminalAdapter
from termrecall.adapters.registry import (
    SUPPORTED_ADAPTERS,
    SUPPORTED_DESKTOPS,
    detect_adapter,
)
from termrecall.client import ServiceClient, ServiceUnavailable
from termrecall.installer_contract import (
    LifecyclePaths,
    manifest_from_bytes,
    resolve_lifecycle_paths,
)
from termrecall.model import recovery_from_dict, snapshot_from_dict
from termrecall.paths import XDGPaths, read_boot_id
from termrecall.protocol import ErrorResponse, StatusRequest, StatusResponse

_PACKAGE_DIR = Path(__file__).resolve().parent
BASH_HOOK_PATH = _PACKAGE_DIR / "data" / "bash" / "termrecall.bash"
NATIVE_HELPER_PATH = _PACKAGE_DIR / "libexec" / "termrecall-nonblock"
CHOOSER_PATH = _PACKAGE_DIR / "data" / "xdg" / "termrecall.desktop"
_CONFIG_NAME = "config.json"
_SOCKET_NAME = "service.sock"
_LOCK_NAME = "service.lock"
_V1_BASH_MARKER = b">>> termrecall v1 >>>"
_DESKTOP_EXEC_PREFIX = b"Exec="


@dataclass(frozen=True, slots=True)
class Diagnostic:
    name: str
    status: Literal["ok", "warning", "error"]
    message: str
    remedy: str | None = None


def _file_check(name: str, path: Path, *, executable: bool = False) -> Diagnostic:
    try:
        metadata = path.stat()
    except OSError:
        return Diagnostic(name, "error", f"package file is missing: {path}", "reinstall the termrecall package")
    if not stat.S_ISREG(metadata.st_mode) or not os.access(path, os.R_OK):
        return Diagnostic(name, "error", f"package file is not a readable regular file: {path}", "reinstall the termrecall package")
    if executable and not os.access(path, os.X_OK):
        return Diagnostic(name, "error", f"package helper is not executable: {path}", "reinstall the termrecall package")
    return Diagnostic(name, "ok", f"available at {path}")


def _directory_check(name: str, path: Path, *, required_mode: int = 0o700) -> Diagnostic:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return Diagnostic(name, "warning", f"directory does not exist yet: {path}", "start TermRecall once to create it safely")
    except OSError:
        return Diagnostic(name, "error", f"directory cannot be inspected: {path}", "inspect the path ownership and permissions")
    if not stat.S_ISDIR(metadata.st_mode):
        return Diagnostic(name, "error", f"path is not a directory: {path}", "move the entry aside and recreate a private directory")
    mode = stat.S_IMODE(metadata.st_mode)
    if metadata.st_uid != os.getuid() or mode != required_mode:
        return Diagnostic(name, "error", f"unsafe owner or mode for {path}; expected current UID and {required_mode:04o}", f"verify ownership and set mode {required_mode:04o}")
    return Diagnostic(name, "ok", f"private current-user directory mode {mode:04o}")


def _open_verified_runtime(path: Path) -> int:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        raise RuntimeError("stale socket cleanup refused: unsafe runtime directory") from exc
    metadata = os.fstat(fd)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        os.close(fd)
        raise RuntimeError("stale socket cleanup refused: unsafe runtime directory owner or mode")
    return fd


def _acquire_existing_lock(runtime_fd: int) -> int:
    try:
        fd = os.open(_LOCK_NAME, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=runtime_fd)
    except OSError as exc:
        raise RuntimeError("stale socket cleanup refused: safe singleton lock is unavailable") from exc
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise RuntimeError("stale socket cleanup refused: unsafe singleton lock")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("stale socket cleanup refused: singleton lock is held") from exc
        return fd
    except BaseException:
        os.close(fd)
        raise


def _socket_metadata(runtime_fd: int) -> os.stat_result:
    try:
        metadata = os.stat(_SOCKET_NAME, dir_fd=runtime_fd, follow_symlinks=False)
    except OSError as exc:
        raise RuntimeError("stale socket cleanup refused: socket entry is unavailable") from exc
    if (
        not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise RuntimeError("stale socket cleanup refused: entry is not a mode 0600 current-user socket")
    return metadata


def _probe_refused(runtime_fd: int) -> None:
    address = f"/proc/self/fd/{runtime_fd}/{_SOCKET_NAME}"
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
            probe.settimeout(0.25)
            probe.connect(address)
    except ConnectionRefusedError:
        return
    except OSError as exc:
        if exc.errno == errno.ECONNREFUSED:
            return
        raise RuntimeError("stale socket cleanup refused: socket could not be verified as refused") from exc
    raise RuntimeError("stale socket cleanup refused: service socket is live")


def _verified_stale_identity(paths: XDGPaths) -> tuple[int, int] | None:
    try:
        runtime_fd = _open_verified_runtime(paths.runtime_dir)
        try:
            lock_fd = _acquire_existing_lock(runtime_fd)
            try:
                metadata = _socket_metadata(runtime_fd)
                _probe_refused(runtime_fd)
                return metadata.st_dev, metadata.st_ino
            finally:
                os.close(lock_fd)
        finally:
            os.close(runtime_fd)
    except RuntimeError:
        return None


def cleanup_stale_socket(paths: XDGPaths) -> tuple[int, int]:
    """Explicitly remove only one twice-refused, identity-stable socket under lock."""
    runtime_fd = _open_verified_runtime(paths.runtime_dir)
    try:
        lock_fd = _acquire_existing_lock(runtime_fd)
        try:
            original = _socket_metadata(runtime_fd)
            identity = (original.st_dev, original.st_ino)
            _probe_refused(runtime_fd)
            _probe_refused(runtime_fd)
            current = _socket_metadata(runtime_fd)
            if (current.st_dev, current.st_ino) != identity:
                raise RuntimeError("stale socket cleanup refused: socket inode changed")
            os.unlink(_SOCKET_NAME, dir_fd=runtime_fd)
            os.fsync(runtime_fd)
            return identity
        finally:
            os.close(lock_fd)
    finally:
        os.close(runtime_fd)


def _socket_check(paths: XDGPaths) -> Diagnostic:
    path = paths.runtime_dir / _SOCKET_NAME
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return Diagnostic("socket", "warning", f"service socket is absent: {path}", "start TermRecall from the supported login integration")
    except OSError:
        return Diagnostic("socket", "error", f"service socket cannot be inspected: {path}", "inspect the runtime directory")
    if (
        not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        return Diagnostic("socket", "error", f"unsafe service socket type, owner, or mode: {path}; expected current UID socket mode 0600", "do not remove it automatically; inspect the verified path manually")
    try:
        ServiceClient(path, timeout=0.25).request(StatusRequest())
    except ServiceUnavailable:
        identity = _verified_stale_identity(paths)
        if identity is not None:
            return Diagnostic("socket", "warning", f"verified stale socket candidate: {path} inode {identity[0]}:{identity[1]}", "termrecall doctor --cleanup-stale-socket")
        return Diagnostic("socket", "error", f"socket is unreachable but could not be verified stale: {path}", "stop the owning service or inspect the singleton lock; no automatic deletion was performed")
    return Diagnostic("socket", "ok", f"service is reachable at {path}")


def _state_check(path: Path) -> Diagnostic:
    directory = _directory_check("state store", path)
    if directory.status != "ok":
        return directory
    try:
        names = sorted(path.glob("checkpoint-*.json"), reverse=True)
        if names:
            candidate = names[0]
            metadata = candidate.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or not os.access(candidate, os.R_OK):
                raise ValueError("latest checkpoint is not a readable current-user regular file")
            payload = json.loads(candidate.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("checkpoint root is not an object")
            snapshot_from_dict(payload)
        recovery = path / "recovery.json"
        if recovery.exists():
            metadata = recovery.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or not os.access(recovery, os.R_OK):
                raise ValueError("recovery record is not a readable current-user regular file")
            payload = json.loads(recovery.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("recovery root is not an object")
            recovery_from_dict(payload)
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        return Diagnostic("state store", "error", f"checkpoint readability/schema check failed: {type(exc).__name__}", "preserve the file and inspect it; doctor will not modify invalid checkpoints")
    return Diagnostic("state store", "ok", "state directory and latest checkpoint schema are readable")


def _chooser_config_check(paths: XDGPaths) -> Diagnostic:
    path = paths.config_dir / _CONFIG_NAME
    try:
        directory = paths.config_dir.lstat()
        metadata = path.lstat()
        if (
            not stat.S_ISDIR(directory.st_mode)
            or directory.st_uid != os.getuid()
            or stat.S_IMODE(directory.st_mode) != 0o700
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ValueError("unsafe owner, mode, type, or symlink")
        payload = json.loads(path.read_text(encoding="utf-8"))
        if (
            not isinstance(payload, dict)
            or set(payload) != {"schema_version", "login_chooser_enabled"}
            or payload.get("schema_version") != 1
            or type(payload.get("login_chooser_enabled")) is not bool
        ):
            raise ValueError("unsupported chooser config schema")
    except FileNotFoundError:
        if path.is_symlink():
            return Diagnostic("chooser config", "warning", "unsafe chooser config symlink disables login chooser", "replace it with termrecall chooser enable")
        return Diagnostic("chooser config", "ok", "login chooser is enabled by default")
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        return Diagnostic("chooser config", "warning", f"invalid or unsafe chooser config disables login chooser: {type(exc).__name__}", "run termrecall chooser enable or disable")
    enabled = payload["login_chooser_enabled"]
    return Diagnostic("chooser config", "ok", f"login chooser is explicitly {'enabled' if enabled else 'disabled'}")


def _durability_check(paths: XDGPaths) -> Diagnostic:
    try:
        response = ServiceClient(paths.runtime_dir / _SOCKET_NAME, timeout=0.25).request(StatusRequest())
    except ServiceUnavailable:
        return Diagnostic("durability", "warning", "durability status is unavailable while the service is unreachable", "start or diagnose the service")
    if isinstance(response, ErrorResponse) or not isinstance(response, StatusResponse):
        return Diagnostic("durability", "error", "service did not return durability status", "inspect service diagnostics")
    if response.durability_degraded or response.dirty_generation > response.durable_generation or response.last_error is not None:
        return Diagnostic("durability", "warning", f"durability degraded at dirty/durable generation {response.dirty_generation}/{response.durable_generation}", "run termrecall snapshot after resolving the reported write error")
    return Diagnostic("durability", "ok", f"durable generation {response.durable_generation}")


def _lifecycle_diagnostics(paths: LifecyclePaths, uid: int) -> list[Diagnostic]:
    """Read-only installed integration diagnostics (no lock/write/service call).

    A missing installation is informational; present installations are checked
    for schema-2 manifest lifecycle, current/command literal targets, managed
    Bash block, autostart entry, chooser ownership, state safety, and PATH
    visibility.  State descendants are never printed.
    """
    diagnostics: list[Diagnostic] = []
    if not paths.manifest.exists():
        diagnostics.append(Diagnostic("install manifest", "warning", "no installed TermRecall application manifest was found", "run ./install.sh to install or upgrade per-user"))
        return diagnostics
    try:
        manifest = manifest_from_bytes(paths.manifest.read_bytes(), paths, uid)
    except (OSError, ValueError) as exc:
        diagnostics.append(Diagnostic("install manifest", "error", f"manifest is unreadable or not schema-2 canonical: {type(exc).__name__}", "rerun ./install.sh to repair the installation"))
        return diagnostics
    diagnostics.append(Diagnostic("install manifest", "ok", f"schema-2 manifest for generation {manifest.generation_id}"))
    generation = paths.generations / manifest.generation_id
    try:
        current_target = os.readlink(paths.current)
    except OSError:
        diagnostics.append(Diagnostic("current link", "error", "the active current generation symlink is missing", "rerun ./install.sh or termrecall uninstall before reinstalling"))
    else:
        if current_target != str(generation):
            diagnostics.append(Diagnostic("current link", "error", "the current link target does not match the manifest generation", "rerun ./install.sh to realign the active generation"))
        else:
            diagnostics.append(Diagnostic("current link", "ok", "current link target matches the manifest generation"))
    for link in paths.command_links:
        label = f"command link {link.name}"
        try:
            target = os.readlink(link)
        except OSError:
            diagnostics.append(Diagnostic(label, "error", f"command link is missing: {link}", "rerun ./install.sh to recreate command links"))
            continue
        expected = str(paths.current / f"venv/bin/{link.name}")
        if target != expected:
            diagnostics.append(Diagnostic(label, "error", f"command link target is not the active executable: {link}", "rerun ./install.sh to repair command links"))
        else:
            diagnostics.append(Diagnostic(label, "ok", f"command link resolves to the active executable"))
    try:
        bashrc_bytes = paths.bashrc.read_bytes() if paths.bashrc.exists() else b""
    except OSError:
        bashrc_bytes = b""
    if _V1_BASH_MARKER in bashrc_bytes:
        diagnostics.append(Diagnostic("bash integration", "ok" if manifest.bash_enabled else "warning", "managed V1 Bash block is present" + ("" if manifest.bash_enabled else " but disabled in the manifest"), "run termrecall setup --bash enable to re-enable"))
    else:
        diagnostics.append(Diagnostic("bash integration", "warning", "managed V1 Bash block is absent", "run termrecall setup --bash enable if Bash capture is desired"))
    if paths.autostart.exists():
        diagnostics.append(Diagnostic("autostart entry", "ok" if manifest.autostart_enabled else "warning", "autostart desktop entry is present" + ("" if manifest.autostart_enabled else " but disabled in the manifest"), "run termrecall autostart enable to re-enable"))
    else:
        diagnostics.append(Diagnostic("autostart entry", "warning", "autostart desktop entry is absent", "run termrecall autostart enable if login coordinator startup is desired"))
    chooser_state = "managed" if manifest.chooser.changed else ("original" if paths.chooser.exists() else "absent")
    diagnostics.append(Diagnostic("chooser ownership", "ok", f"chooser ownership is {chooser_state}"))
    try:
        state_st = paths.state_root.lstat()
        if not stat.S_ISDIR(state_st.st_mode) or state_st.st_uid != uid or stat.S_IMODE(state_st.st_mode) != 0o700:
            diagnostics.append(Diagnostic("state safety", "error", "state root is not a private current-user 0700 directory", "inspect the state root ownership and mode"))
        else:
            diagnostics.append(Diagnostic("state safety", "ok", "state root is a private 0700 directory"))
    except FileNotFoundError:
        diagnostics.append(Diagnostic("state safety", "warning", "state root does not exist yet", "start the service once to create it safely"))
    bin_root = str(paths.bin_root)
    path_env = os.environ.get("PATH", os.defpath)
    if bin_root in path_env.split(os.pathsep):
        diagnostics.append(Diagnostic("PATH visibility", "ok", f"{bin_root} is on PATH"))
    else:
        diagnostics.append(Diagnostic("PATH visibility", "warning", f"{bin_root} is not on PATH", "add it to your shell profile so the installed commands resolve"))
    return diagnostics


def run_doctor(paths: XDGPaths, adapter: TerminalAdapter) -> Sequence[Diagnostic]:
    diagnostics: list[Diagnostic] = [
        _file_check("bash hook", BASH_HOOK_PATH),
        _file_check("native helper", NATIVE_HELPER_PATH, executable=True),
        _directory_check("runtime directory", paths.runtime_dir),
        _socket_check(paths),
        _state_check(paths.state_dir),
    ]
    try:
        boot_id = read_boot_id()
    except (OSError, ValueError):
        diagnostics.append(Diagnostic("boot ID", "error", "current Linux boot ID is unreadable or invalid", "verify /proc/sys/kernel/random/boot_id"))
    else:
        diagnostics.append(Diagnostic("boot ID", "ok", f"current boot ID is readable ({boot_id})"))

    desktop = os.environ.get("XDG_CURRENT_DESKTOP", "")
    desktops = [name for name in desktop.split(":") if name in SUPPORTED_DESKTOPS]
    if desktops:
        diagnostics.append(Diagnostic("desktop session", "ok", f"XDG_CURRENT_DESKTOP={desktop}"))
    else:
        diagnostics.append(Diagnostic("desktop session", "warning", "supported desktop was not detected", "run in a Cinnamon, GNOME, XFCE, or KDE session"))
    screen = os.environ.get("GNOME_TERMINAL_SCREEN")
    diagnostics.append(Diagnostic("GNOME Terminal shell context", "ok", "GNOME_TERMINAL_SCREEN is present (informational only)" if screen else "GNOME_TERMINAL_SCREEN is absent (informational only)"))

    detected_name = detect_adapter(shutil.which)
    detected = adapter.detect()
    if detected_name is not None and detected:
        diagnostics.append(Diagnostic("terminal adapter", "ok", f"{detected_name} adapter detected"))
    else:
        diagnostics.append(Diagnostic("terminal adapter", "error", "no supported terminal adapter was detected", f"install one of: {', '.join(sorted(SUPPORTED_ADAPTERS))}"))

    capabilities = adapter.capabilities()
    unsupported = [name for name in ("windows", "panes", "scrollback", "deterministic_grouping") if not getattr(capabilities, name)]
    if unsupported:
        diagnostics.append(Diagnostic("adapter capabilities", "warning", "unsupported restoration capabilities: " + ", ".join(unsupported), "expect partial or reconstructed restoration; process memory is never resumed"))
    else:
        diagnostics.append(Diagnostic("adapter capabilities", "ok", "all advertised adapter capabilities are available"))
    diagnostics.append(_file_check("login chooser", CHOOSER_PATH))
    diagnostics.append(_chooser_config_check(paths))
    diagnostics.append(_durability_check(paths))
    try:
        lifecycle_paths = resolve_lifecycle_paths(os.environ, Path(os.environ.get("HOME", str(Path.home()))))
        diagnostics.extend(_lifecycle_diagnostics(lifecycle_paths, os.getuid()))
    except (OSError, ValueError):
        diagnostics.append(Diagnostic("install manifest", "warning", "installed lifecycle paths could not be resolved from the environment", "set HOME and XDG roots or run ./install.sh"))
    return tuple(diagnostics)
