# SPDX-License-Identifier: GPL-3.0-or-later
"""Local installer lifecycle CLI adapters and the hidden delegate entry.

This module owns the service-independent installed lifecycle commands
(``setup``, ``autostart``, ``uninstall``) and the hidden ``installer-bootstrap``
entry that ``install.sh``'s launcher spawns with two bounded pipe pairs.  Exit
codes follow :class:`~termrecall.installer_contract.LifecycleExit`
exactly: the public commands never construct a service client, never touch
``XDG_RUNTIME_DIR``, and never build, pip-install, create/switch/delete
generations, or remove the application.  Application fresh install/upgrade is
exclusively ``install.sh`` via the hidden bootstrap; application removal is
exclusively manifest-driven ``uninstall``.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import sys
from pathlib import Path
from typing import Literal, Sequence, TextIO

from termrecall.installer_contract import (
    DesiredState,
    IntegrationSetupRequest,
    LifecycleExit,
    LifecyclePaths,
    SetupMode,
    SetupRequest,
    UninstallRequest,
    MAX_PAYLOAD_BYTES,
    manifest_from_bytes,
    resolve_lifecycle_paths,
)
from termrecall.installer_probe import (
    compute_plan_digest,
    plan_from_bytes,
    plan_to_bytes,
)
from termrecall.lifecycle import (
    LifecycleError,
    execute_integration_setup,
    execute_setup,
    execute_uninstall,
    plan_uninstall,
    revalidate_probe_plan_prelock,
    set_autostart,
)

__all__ = [
    "installer_bootstrap",
    "main",
    "run_autostart",
    "run_integration_setup",
    "run_uninstall",
]

MARKER_NAME = ".termrecall-generation.json"
_SHA256_ALPHABET = frozenset("0123456789abcdef")
_PACKAGE_DIR = Path(__file__).resolve().parent
_BASH_HOOK = _PACKAGE_DIR / "data" / "bash" / "termrecall.bash"
_DESKTOP_ENTRY = _PACKAGE_DIR / "data" / "xdg" / "termrecall.desktop"


# ---------------------------------------------------------------------------
# environment + verification helpers
# ---------------------------------------------------------------------------


def _lifecycle_paths() -> LifecyclePaths:
    """Resolve lifecycle paths from the process environment (no runtime dir)."""
    from termrecall.paths import resolve_lifecycle_paths_from_env

    return resolve_lifecycle_paths_from_env(os.environ)


def _exit_code(result: LifecycleExit) -> int:
    return int(result)


def _verify_symlink(path: Path, expected_target: str, uid: int) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise LifecycleError(LifecycleExit.REFUSED, "installed command link is missing") from exc
    if not stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != uid:
        raise LifecycleError(LifecycleExit.REFUSED, "installed command link is unsafe")
    if os.readlink(path) != expected_target:
        raise LifecycleError(LifecycleExit.REFUSED, "installed command link target changed")


def _verify_marker(marker: Path, expected: object, uid: int) -> None:
    try:
        metadata = marker.lstat()
    except OSError as exc:
        raise LifecycleError(LifecycleExit.REFUSED, "installed generation marker is missing") from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != uid or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise LifecycleError(LifecycleExit.REFUSED, "installed generation marker is unsafe")
    raw = marker.read_bytes()
    if hashlib.sha256(raw).hexdigest() != getattr(expected, "content_sha256"):
        raise LifecycleError(LifecycleExit.REFUSED, "installed generation marker changed")


def _verify_package_resources() -> None:
    for label, path in (("bash hook", _BASH_HOOK), ("desktop entry", _DESKTOP_ENTRY)):
        try:
            metadata = path.stat()
        except OSError as exc:
            raise LifecycleError(LifecycleExit.REFUSED, f"{label} package resource is missing") from exc
        if not stat.S_ISREG(metadata.st_mode) or not os.access(path, os.R_OK):
            raise LifecycleError(LifecycleExit.REFUSED, f"{label} package resource is unreadable")


def _verify_generation_executables(generation: Path, uid: int) -> None:
    venv_bin = generation / "venv" / "bin"
    for name in ("termrecall", "termrecall-bridge", "termrecall-nonblock"):
        exe = venv_bin / name
        try:
            metadata = exe.lstat()
        except OSError as exc:
            raise LifecycleError(LifecycleExit.REFUSED, "installed generation executable is missing") from exc
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != uid or not os.access(exe, os.X_OK):
            raise LifecycleError(LifecycleExit.REFUSED, "installed generation executable is unsafe")


def _verify_installation(paths: LifecyclePaths, uid: int) -> object:
    """Load and strictly verify the manifest, current, generation, executables."""
    if not paths.manifest.exists():
        raise LifecycleError(LifecycleExit.REFUSED, "no installed manifest")
    manifest = manifest_from_bytes(paths.manifest.read_bytes(), paths, uid)
    generation = paths.generations / manifest.generation_id
    _verify_symlink(paths.current, str(generation), uid)
    _verify_marker(generation / MARKER_NAME, manifest.marker, uid)
    _verify_generation_executables(generation, uid)
    for link in paths.command_links:
        _verify_symlink(link, str(paths.current / f"venv/bin/{link.name}"), uid)
    _verify_package_resources()
    return manifest


def _render_integration_plan(request: IntegrationSetupRequest, stdout: TextIO) -> None:
    print("TermRecall integration setup (dry run)", file=stdout)
    for name in ("bash", "autostart", "chooser"):
        print(f"{name}: {getattr(request, name).value}", file=stdout)


# ---------------------------------------------------------------------------
# public installed setup
# ---------------------------------------------------------------------------


def run_integration_setup(
    request: IntegrationSetupRequest, stdout: TextIO, stderr: TextIO
) -> int:
    """Public installed ``setup``: integration-only planning and transaction."""
    paths = _lifecycle_paths()
    uid = os.getuid()
    try:
        prior = _verify_installation(paths, uid)
    except LifecycleError as exc:
        print(f"error: {exc.message}", file=stderr)
        return _exit_code(exc.exit_code)
    if request.dry_run:
        _render_integration_plan(request, stdout)
        return _exit_code(LifecycleExit.OK)
    # plan against the verified installation to surface REFUSED before locking
    try:
        from termrecall.lifecycle_integrations import plan_installed_integrations

        plan_installed_integrations(request, paths, prior, uid)  # type: ignore[arg-type]
    except (LifecycleError, ValueError) as exc:
        print(f"error: {exc}", file=stderr)
        return _exit_code(LifecycleExit.REFUSED)
    result = execute_integration_setup(request, paths, uid)
    if result is LifecycleExit.OK:
        print("setup: integration changes applied", file=stdout)
    else:
        print(f"setup: {result.name.lower()}", file=stderr)
    return _exit_code(result)


# ---------------------------------------------------------------------------
# public installed autostart
# ---------------------------------------------------------------------------


def run_autostart(
    setting: Literal["enable", "disable"], stdout: TextIO, stderr: TextIO
) -> int:
    """Public installed ``autostart enable|disable`` adapter."""
    paths = _lifecycle_paths()
    uid = os.getuid()
    try:
        _verify_installation(paths, uid)
    except LifecycleError as exc:
        print(f"error: {exc.message}", file=stderr)
        return _exit_code(exc.exit_code)
    result = set_autostart(setting == "enable", paths, uid)
    if result is LifecycleExit.OK:
        print(f"autostart: {setting}d", file=stdout)
    else:
        print(f"autostart: {result.name.lower()}", file=stderr)
    return _exit_code(result)


# ---------------------------------------------------------------------------
# public installed uninstall (interactive re-prompting)
# ---------------------------------------------------------------------------


def _yes_uninstall_request(purge_state: bool) -> UninstallRequest:
    """Noninteractive consistent full removal preserving chooser/state."""
    return UninstallRequest(
        remove_application=True,
        remove_bash=True,
        remove_autostart=True,
        restore_chooser=False,
        purge_state=purge_state,
        assume_yes=True,
    )


def _readline(stdin: TextIO) -> str | None:
    try:
        value = stdin.readline()
    except KeyboardInterrupt:
        return None
    return None if value == "" else value.rstrip("\r\n")


def _ask_yes_no(stdin: TextIO, stdout: TextIO, prompt: str, default: bool) -> bool | None:
    suffix = "[Y/n]" if default else "[y/N]"
    print(f"{prompt} {suffix} ", end="", file=stdout)
    stdout.flush()
    line = _readline(stdin)
    if line is None:
        return None
    answer = line.strip().casefold()
    if not answer:
        return default
    return answer in {"y", "yes"}


def _collect_uninstall_answers(
    paths: LifecyclePaths,
    uid: int,
    stdin: TextIO,
    stdout: TextIO,
    stderr: TextIO,
) -> dict[str, bool] | None:
    autostart_installed = paths.autostart.exists()
    app = _ask_yes_no(stdin, stdout, "Remove the TermRecall application?", default=True)
    if app is None:
        return None
    bash = _ask_yes_no(stdin, stdout, "Remove the Bash integration?", default=True)
    if bash is None:
        return None
    autostart = _ask_yes_no(stdin, stdout, "Remove the autostart entry?", default=autostart_installed)
    if autostart is None:
        return None
    chooser = _ask_yes_no(stdin, stdout, "Restore the original chooser config?", default=False)
    if chooser is None:
        return None
    purge = _ask_yes_no(stdin, stdout, "Permanently purge recovery state?", default=False)
    if purge is None:
        return None
    if purge:
        print("Type 'yes' (case-sensitive) to confirm permanent state purge: ", end="", file=stdout)
        stdout.flush()
        confirm = _readline(stdin)
        if confirm is None:
            return None
        if confirm != "yes":
            print("purge refused; recovery state will be retained", file=stdout)
            purge = False
    # invariant resolution: removing the app requires Bash and autostart removal
    while app and not (bash and autostart):
        print("Removing the application also requires Bash and autostart removal.", file=stdout)
        bash = _ask_yes_no(stdin, stdout, "Remove the Bash integration?", default=True)
        if bash is None:
            return None
        autostart = _ask_yes_no(stdin, stdout, "Remove the autostart entry?", default=autostart_installed)
        if autostart is None:
            return None
        if not bash or not autostart:
            keep = _ask_yes_no(stdin, stdout, "Keep the TermRecall application installed?", default=True)
            if keep is None:
                return None
            if keep:
                app = False
    return {"app": app, "bash": bash, "autostart": autostart, "chooser": chooser, "purge": purge}


def _build_uninstall_request(answers: dict[str, bool]) -> UninstallRequest:
    return UninstallRequest(
        remove_application=answers["app"],
        remove_bash=answers["bash"],
        remove_autostart=answers["autostart"],
        restore_chooser=answers["chooser"],
        purge_state=answers["purge"],
        assume_yes=False,
    )


def run_uninstall(
    args: argparse.Namespace, stdin: TextIO, stdout: TextIO, stderr: TextIO
) -> int:
    """Public installed ``uninstall`` with interactive re-prompting."""
    paths = _lifecycle_paths()
    uid = os.getuid()
    purge_state = bool(getattr(args, "purge_state", False))
    assume_yes = bool(getattr(args, "yes", False))
    if purge_state and not assume_yes:
        print("error: --purge-state requires --yes", file=stderr)
        return _exit_code(LifecycleExit.USAGE)
    if assume_yes:
        request = _yes_uninstall_request(purge_state)
    else:
        if not stdin.isatty():
            print("error: interactive uninstall requires a terminal or --yes", file=stderr)
            return _exit_code(LifecycleExit.USAGE)
        answers = _collect_uninstall_answers(paths, uid, stdin, stdout, stderr)
        if answers is None:
            return _exit_code(LifecycleExit.USAGE)
        request = _build_uninstall_request(answers)
    try:
        plan = plan_uninstall(request, paths, uid)
    except LifecycleError as exc:
        print(f"error: {exc.message}", file=stderr)
        return _exit_code(exc.exit_code)
    result = execute_uninstall(plan, uid)
    if result is LifecycleExit.OK:
        if request.remove_application:
            print("uninstall: TermRecall application removed", file=stdout)
        else:
            print("uninstall: selected integrations removed", file=stdout)
    else:
        print(f"uninstall: {result.name.lower()}", file=stderr)
    return _exit_code(result)


# ---------------------------------------------------------------------------
# hidden installer-bootstrap delegate entry
# ---------------------------------------------------------------------------


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(char in _SHA256_ALPHABET for char in value)


def _exactly_one(values: list[str] | None, name: str) -> str:
    if values is None or len(values) != 1:
        raise ValueError(f"{name} must occur exactly once")
    return values[0]


def _parse_fd(value: str, name: str) -> int:
    if not value.lstrip("+").isdigit():
        raise ValueError(f"{name} must be a non-negative integer")
    fd = int(value, 10)
    if fd < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return fd


def _read_fd_bounded(fd: int) -> bytes:
    limit = MAX_PAYLOAD_BYTES + 1
    data = b""
    while len(data) < limit:
        try:
            chunk = os.read(fd, limit - len(data))
        except OSError:
            break
        if not chunk:
            break
        data += chunk
    return data


def _close_fd(fd: int) -> None:
    try:
        os.close(fd)
    except OSError:
        pass


def _bootstrap_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="termrecall installer-bootstrap", add_help=False, allow_abbrev=False
    )
    parser.add_argument("--request-fd", action="append", required=True)
    parser.add_argument("--plan-fd", action="append", required=True)
    parser.add_argument("--expected-digest", action="append", required=True)
    parser.add_argument("--wheel", action="append", required=True)
    return parser


def installer_bootstrap(argv: Sequence[str] | None = None) -> int:
    """Hidden delegate entry invoked only by ``installer_probe.py launch-delegate``."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        namespace = _bootstrap_parser().parse_args(arguments)
    except SystemExit:
        return _exit_code(LifecycleExit.USAGE)
    try:
        request_fd = _parse_fd(_exactly_one(namespace.request_fd, "--request-fd"), "--request-fd")
        plan_fd = _parse_fd(_exactly_one(namespace.plan_fd, "--plan-fd"), "--plan-fd")
        expected_digest = _exactly_one(namespace.expected_digest, "--expected-digest")
        wheel = Path(_exactly_one(namespace.wheel, "--wheel"))
    except (ValueError, TypeError):
        return _exit_code(LifecycleExit.USAGE)
    if not _is_sha256(expected_digest):
        return _exit_code(LifecycleExit.USAGE)
    if not wheel.is_absolute():
        return _exit_code(LifecycleExit.USAGE)
    request_raw = b""
    plan_raw = b""
    try:
        request_raw = _read_fd_bounded(request_fd)
        plan_raw = _read_fd_bounded(plan_fd)
    finally:
        _close_fd(request_fd)
        _close_fd(plan_fd)
    try:
        from termrecall.installer_probe import _load  # type: ignore[attr-defined]

        request_obj = _load(request_raw)
    except Exception:
        return _exit_code(LifecycleExit.REFUSED)
    try:
        plan_obj = plan_from_bytes(plan_raw, request_obj)
    except Exception:
        return _exit_code(LifecycleExit.REFUSED)
    if compute_plan_digest(plan_obj) != expected_digest:
        return _exit_code(LifecycleExit.REFUSED)
    try:
        setup_request = SetupRequest(
            mode=SetupMode(request_obj["mode"]),
            dry_run=bool(request_obj["dry_run"]),
            bash=DesiredState(request_obj["bash"]),
            autostart=DesiredState(request_obj["autostart"]),
            chooser=DesiredState(request_obj["chooser"]),
            source_root=Path(request_obj["source_root"]),
            wheel=wheel,
            probe_request=None,
            probe_plan=None,
            probe_plan_digest=None,
        )
    except Exception:
        return _exit_code(LifecycleExit.USAGE)
    paths = resolve_lifecycle_paths(
        {
            "XDG_DATA_HOME": request_obj["xdg_data_home"],
            "XDG_CONFIG_HOME": request_obj["xdg_config_home"],
            "XDG_STATE_HOME": request_obj["xdg_state_home"],
        },
        Path(request_obj["home"]),
    )
    uid = os.getuid()
    try:
        fresh_plan = revalidate_probe_plan_prelock(setup_request, paths, uid)
    except LifecycleError:
        return _exit_code(LifecycleExit.REFUSED)
    if fresh_plan.plan_digest != expected_digest:
        return _exit_code(LifecycleExit.REFUSED)
    result = execute_setup(fresh_plan, setup_request, paths, uid)
    return _exit_code(result)


def main() -> None:
    """Dispatch the hidden ``installer-bootstrap`` subcommand for ``-m`` use."""
    arguments = list(sys.argv[1:])
    if not arguments or arguments[0] != "installer-bootstrap":
        print(
            "usage: python -m termrecall.installer installer-bootstrap "
            "--request-fd FD --plan-fd FD --expected-digest SHA --wheel PATH",
            file=sys.stderr,
        )
        raise SystemExit(_exit_code(LifecycleExit.USAGE))
    raise SystemExit(installer_bootstrap(arguments[1:]))


if __name__ == "__main__":
    main()
