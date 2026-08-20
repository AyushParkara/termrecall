# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import argparse
import asyncio
import fcntl
import json
import os
import shutil
import signal
import stat
import sys
import time
import secrets
from collections.abc import Awaitable, Callable, Sequence
from contextlib import redirect_stderr, suppress
from pathlib import Path
from typing import TextIO

from termrecall.client import ServiceClient, ServiceUnavailable
from termrecall.adapters.resume import build_resume_argv, find_resume_adapter
from termrecall.classifier import _parse_one_simple_command
from termrecall.sessions import find_sessions_for_cwd
from termrecall.paths import XDGPaths, resolve_paths
from termrecall.protocol import (
    DiscardRequest,
    DiscardResponse,
    ErrorCode,
    ErrorResponse,
    RecoveryItemView,
    RestoreExecuteRequest,
    RestoreListRequest,
    RestoreListResponse,
    RestoreResultResponse,
    RestoreRetryRequest,
    SnapshotRequest,
    SnapshotResponse,
    StatusRequest,
    StatusResponse,
)

EXIT_OK = 0
EXIT_WARNING = 1
EXIT_REFUSED = 2
EXIT_FAILURE = 3
MAX_CHOOSER_CONFIG_BYTES = 4096
_CONFIG_NAME = "config.json"


class _UniqueStore(argparse.Action):
    """Store an option value exactly once; reject duplicate occurrences."""

    def __call__(self, parser, namespace, values, option_string=None) -> None:  # type: ignore[override]
        if getattr(namespace, f"_seen_{self.dest}", False):
            parser.error(f"{option_string} must occur at most once")
        setattr(namespace, f"_seen_{self.dest}", True)
        setattr(namespace, self.dest, values)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="termrecall")
    commands = parser.add_subparsers(
        dest="command",
        required=True,
        metavar="{status,snapshot,list,restore,discard,doctor,setup,autostart,uninstall,chooser}",
    )
    commands.add_parser("status", help="show service and durability status")
    commands.add_parser("snapshot", help="synchronously save current state")
    commands.add_parser("list", help="list recoverable terminal items")
    restore = commands.add_parser("restore", help="restore selected terminal items")
    selection = restore.add_mutually_exclusive_group()
    selection.add_argument("--all", action="store_true", help="select every item")
    selection.add_argument("--retry", metavar="ATTEMPT", help="retry an incomplete attempt")
    restore.add_argument("--directory-only", action="store_true", help="never rerun commands")
    discard = commands.add_parser("discard", help="permanently discard one recovery workspace")
    discard.add_argument("workspace")
    discard.add_argument("--yes", action="store_true", help="skip typed confirmation")
    doctor = commands.add_parser("doctor", help="check local integration and safety")
    doctor.add_argument("--cleanup-stale-socket", action="store_true", help="remove only a lock-verified stale socket")
    setup = commands.add_parser("setup", help="configure installed Bash, autostart, and chooser integrations")
    setup.add_argument("--bash", choices=("enable", "disable", "preserve"), default="preserve", action=_UniqueStore)
    setup.add_argument("--autostart", choices=("enable", "disable", "preserve"), default="preserve", action=_UniqueStore)
    setup.add_argument("--chooser", choices=("enable", "disable", "preserve"), default="preserve", action=_UniqueStore)
    setup.add_argument("--dry-run", action="store_true", help="render the integration plan without writing")
    autostart = commands.add_parser("autostart", help="enable or disable the Cinnamon autostart entry")
    autostart.add_argument("setting", choices=("enable", "disable"))
    uninstall = commands.add_parser("uninstall", help="remove installed TermRecall integrations and application")
    uninstall.add_argument("--yes", action="store_true", help="noninteractive full application removal")
    uninstall.add_argument("--purge-state", action="store_true", help="also permanently purge recovery state (requires --yes)")
    chooser = commands.add_parser("chooser", help="configure the login restore chooser")
    chooser.add_argument("setting", choices=("enable", "disable"))
    commands.add_parser("login-coordinator", help=argparse.SUPPRESS)
    commands._choices_actions = [
        action for action in commands._choices_actions
        if action.dest != "login-coordinator"
    ]
    return parser


def _paths() -> XDGPaths:
    return resolve_paths(os.environ, os.getuid(), Path.home())


def _service_client() -> ServiceClient:
    return ServiceClient(_paths().runtime_dir / "service.sock")


def _safe_value(value: object) -> str:
    return str(getattr(value, "value", value))


def _print_error(response: ErrorResponse, stderr: TextIO) -> int:
    if response.error.code is ErrorCode.ADAPTER_UNAVAILABLE:
        print("only GNOME Terminal is supported", file=stderr)
    else:
        print(f"error: {response.error.message}", file=stderr)
    return EXIT_FAILURE


def _request(client: ServiceClient, request: object, stderr: TextIO) -> object | None:
    try:
        response = client.request(request)  # type: ignore[arg-type]
    except (ServiceUnavailable, ValueError) as exc:
        print(f"error: {exc}", file=stderr)
        return None
    if isinstance(response, ErrorResponse):
        _print_error(response, stderr)
    return response


def _status(client: ServiceClient, stdout: TextIO, stderr: TextIO) -> int:
    response = _request(client, StatusRequest(), stderr)
    if not isinstance(response, StatusResponse):
        return EXIT_FAILURE
    print("service: reachable", file=stdout)
    print(f"registered shells: {response.registered_shells}", file=stdout)
    print(f"dirty/durable generation: {response.dirty_generation}/{response.durable_generation}", file=stdout)
    print(f"write active: {'yes' if response.write_active else 'no'}", file=stdout)
    print(f"recovery items: {response.recovery_item_count}", file=stdout)
    if response.last_error is not None:
        print(f"last write error: {_safe_value(response.last_error)}", file=stdout)
    for diagnostic in response.diagnostics:
        print(f"diagnostic: {_safe_value(diagnostic)}", file=stdout)
    degraded = (
        response.durability_degraded
        or response.dirty_generation > response.durable_generation
        or response.last_error is not None
        or bool(response.diagnostics)
    )
    print(f"durability: {'degraded' if degraded else 'healthy'}", file=stdout)
    return EXIT_WARNING if degraded else EXIT_OK


def _snapshot(client: ServiceClient, stdout: TextIO, stderr: TextIO) -> int:
    response = _request(client, SnapshotRequest(), stderr)
    if not isinstance(response, SnapshotResponse):
        return EXIT_FAILURE
    print(f"snapshot saved at durable generation {response.durable_generation}", file=stdout)
    return EXIT_OK


def _resume_display_for_item(item: RecoveryItemView) -> tuple[str, str, int, str]:
    """Return the server-authoritative resume plan for display.

    Uses the resume_command/resume_summary/resume_session_count the server
    populated in _recovery_view, so the UI shows exactly what build_attempt will
    run — no client-side recomputation that could diverge.  Returns
    (resume_command, summary, session_count, tool_name).  When the item is not
    a resume-capable tool, resume_command is "" and tool_name is the plain
    executable for the replay-warning fallback.
    """
    if item.resume_command:
        # Tool name is the first token of the resume command.
        tool = item.resume_command.split(" ", 1)[0] if item.resume_command else ""
        return item.resume_command, item.resume_summary, item.resume_session_count, tool
    # No resume plan: plain replayable command.
    command_text = item.replay_display.value if item.replay_display else ""
    tool = ""
    if command_text:
        try:
            tool = _parse_one_simple_command(command_text).executable
        except ValueError:
            tool = ""
    return command_text, "", 0, tool


def _show_item(item: RecoveryItemView, stdout: TextIO) -> None:
    print(f"  {item.item_id} (shell {item.shell_id})", file=stdout)
    print(f"    restoration level: {item.level.value.upper()}", file=stdout)
    print(f"    reason: {_safe_value(item.reason)}", file=stdout)
    print(f"    directory: {item.directory}", file=stdout)
    if item.directory_warning is not None:
        print(f"    directory warning: {_safe_value(item.directory_warning)}", file=stdout)
    if item.replay_display is not None:
        # The server pre-resolves resume_command/summary/session_count (single
        # source of truth).  An empty resume_command means this is a plain
        # replayable command, not a resume-capable tool.
        resume_command = item.resume_command
        summary = item.resume_summary
        session_count = item.resume_session_count
        if resume_command and session_count > 0:
            # Session-persistent tool: show what will actually run + context.
            print(f"    will resume: {resume_command}", file=stdout)
            if summary:
                print(f"    session summary: {summary}", file=stdout)
            print(f"    sessions in this directory: {session_count} (most recent selected)", file=stdout)
        elif resume_command:
            # Resume-capable tool but no stored session found yet.
            print(f"    will resume: {resume_command}", file=stdout)
            print("    note: no matching session found; will start fresh", file=stdout)
        else:
            # Plain replayable command (no resume semantics).
            print(f"    active command: {_safe_value(item.replay_display)}", file=stdout)
            print("    warning: this command would be restarted, not resumed", file=stdout)
    elif item.level.value == "partial":
        print("    warning: only the terminal and directory can be restored", file=stdout)


def _list_response(
    client: ServiceClient,
    stdout: TextIO,
    stderr: TextIO,
    *,
    display: bool,
    request: RestoreListRequest | None = None,
) -> RestoreListResponse | None:
    response = _request(client, request or RestoreListRequest(), stderr)
    if not isinstance(response, RestoreListResponse):
        return None
    if response.workspace_id is None:
        if display:
            print("no recovery workspace is available", file=stdout)
        return response
    if display:
        print(f"workspace: {response.workspace_id}", file=stdout)
        for item in response.items:
            _show_item(item, stdout)
        for diagnostic in response.diagnostics:
            print(f"diagnostic: {_safe_value(diagnostic)}", file=stdout)
    return response


def _readline(stdin: TextIO) -> str | None:
    try:
        value = stdin.readline()
    except KeyboardInterrupt:
        raise
    return None if value == "" else value.rstrip("\r\n")


def _select_items(items: Sequence[RecoveryItemView], stdin: TextIO, stdout: TextIO) -> tuple[str, ...] | None:
    for index, item in enumerate(items, 1):
        print(f"{index}: {item.item_id} — {item.directory} [{item.level.value.upper()}]", file=stdout)
    print("Select item numbers (comma-separated), or press Enter to cancel: ", end="", file=stdout)
    answer = _readline(stdin)
    if answer is None or not answer.strip():
        return None
    try:
        indices = tuple(int(part.strip()) for part in answer.split(","))
    except ValueError:
        return None
    if not indices or len(indices) != len(set(indices)) or any(index < 1 or index > len(items) for index in indices):
        return None
    return tuple(items[index - 1].item_id for index in indices)


def _requires_interactive_approval(
    items: Sequence[RecoveryItemView], selected: set[str]
) -> bool:
    return any(
        item.item_id in selected
        and item.replay_eligible
        and item.replay_display is not None
        for item in items
    )


def _approvals(items: Sequence[RecoveryItemView], selected: set[str], stdin: TextIO, stdout: TextIO, *, directory_only: bool) -> tuple[str, ...]:
    if directory_only:
        return ()
    approved: list[str] = []
    for item in items:
        if item.item_id not in selected or not item.replay_eligible or item.replay_display is None:
            continue
        resume_command, summary, session_count, tool = _resume_display_for_item(item)
        # Server-authoritative: a non-empty resume_command means this item is a
        # resume-capable tool (no client-side probe needed).
        is_resume = bool(item.resume_command)
        if is_resume:
            print(f"Restore item {item.item_id}:", file=stdout)
            print(f"  command: {resume_command}", file=stdout)
            # If multiple sessions match this cwd, offer a picker so the user
            # can choose which historical session to resume.
            # Filter by tool so the picker count matches the server-side
            # count (which counts only this tool sessions in the cwd).
            tool_name = resume_command.split(" ", 1)[0] if resume_command else ""
            matches = [m for m in find_sessions_for_cwd(str(item.directory)) if m.tool == tool_name] if session_count > 1 else []
            if len(matches) > 1:
                print(f"  {len(matches)} sessions found in {item.directory}:", file=stdout)
                for idx, m in enumerate(matches, 1):
                    label = m.summary or m.title or m.session_id
                    span = f"{m.first_activity[:10]}..{m.last_activity[:10]}" if m.first_activity else "unknown date"
                    print(f"    {idx}: {label}  [{m.tool}]  {span}", file=stdout)
                print(f"  Resume session number (1-{len(matches)}, Enter=most-recent, 0=skip): ", end="", file=stdout)
                answer = _readline(stdin)
                if answer is None or answer.strip() == "" or answer.strip() == "0":
                    if answer is not None and answer.strip() == "0":
                        continue
                    chosen = matches[0]
                else:
                    try:
                        chosen = matches[int(answer.strip()) - 1]
                    except (ValueError, IndexError):
                        continue
                match = find_resume_adapter(tool)
                resume_command = " ".join(build_resume_argv(match, chosen.session_id))
                print(f"  resuming: {resume_command}", file=stdout)
            elif summary:
                print(f"  session: {summary}", file=stdout)
            print(f"Resume this session? [Y/n] ", end="", file=stdout)
        else:
            print(f"Stored command for {item.item_id}: {resume_command or _safe_value(item.replay_display)}", file=stdout)
            print(f"Run this command in restored item {item.item_id}? [y/N] ", end="", file=stdout)
        answer = _readline(stdin)
        default_yes = is_resume  # resume defaults to yes (sensible); replay defaults to no
        if answer is None:
            continue
        ok = answer.strip().casefold() in {"y", "yes"} or (default_yes and answer.strip() == "")
        if ok:
            approved.append(item.item_id)
    return tuple(approved)


def _show_result(response: RestoreResultResponse, stdout: TextIO) -> int:
    print(f"restore attempt: {response.attempt_id}", file=stdout)
    for outcome in response.outcomes:
        print(f"  {outcome.item_id}: {outcome.kind.value} ({_safe_value(outcome.message)})", file=stdout)
    if response.remaining_item_ids:
        print(f"remaining retryable items: {', '.join(response.remaining_item_ids)}", file=stdout)
        return EXIT_WARNING
    print("restore state saved", file=stdout)
    return EXIT_OK


def _restore(args: argparse.Namespace, client: ServiceClient, stdin: TextIO, stdout: TextIO, stderr: TextIO) -> int:
    listed = _list_response(client, stdout, stderr, display=False)
    if listed is None:
        return EXIT_FAILURE
    if listed.workspace_id is None:
        print("no recovery workspace is available", file=stdout)
        return EXIT_WARNING
    try:
        if args.retry:
            retry_listed = _list_response(
                client,
                stdout,
                stderr,
                display=False,
                request=RestoreListRequest(listed.workspace_id, args.retry),
            )
            if retry_listed is None:
                return EXIT_FAILURE
            listed = retry_listed
            selected = {item.item_id for item in listed.items}
            if (
                not args.directory_only
                and _requires_interactive_approval(listed.items, selected)
                and not stdin.isatty()
            ):
                print("restore refused: command approval requires an interactive terminal", file=stderr)
                return EXIT_REFUSED
            approved = _approvals(listed.items, selected, stdin, stdout, directory_only=args.directory_only)
            request = RestoreRetryRequest(listed.workspace_id, args.retry, approved)
        else:
            if args.all:
                selected_ids = tuple(item.item_id for item in listed.items)
            else:
                if not stdin.isatty():
                    print("restore refused: item selection requires an interactive terminal", file=stderr)
                    return EXIT_REFUSED
                selected_ids = _select_items(listed.items, stdin, stdout)
                if selected_ids is None:
                    print("restore cancelled; no command was approved", file=stderr)
                    return EXIT_REFUSED
            selected = set(selected_ids)
            if (
                not args.directory_only
                and _requires_interactive_approval(listed.items, selected)
                and not stdin.isatty()
            ):
                print("restore refused: command approval requires an interactive terminal", file=stderr)
                return EXIT_REFUSED
            approved = _approvals(listed.items, selected, stdin, stdout, directory_only=args.directory_only)
            request = RestoreExecuteRequest(listed.workspace_id, selected_ids, approved)
    except KeyboardInterrupt:
        print("restore cancelled; no command was approved", file=stderr)
        return EXIT_REFUSED
    response = _request(client, request, stderr)
    if not isinstance(response, RestoreResultResponse):
        return EXIT_FAILURE
    return _show_result(response, stdout)


def _discard(args: argparse.Namespace, client: ServiceClient, stdin: TextIO, stdout: TextIO, stderr: TextIO) -> int:
    listed = _list_response(client, stdout, stderr, display=False)
    if listed is None:
        return EXIT_FAILURE
    if listed.workspace_id != args.workspace:
        print("refused: workspace does not match the current recovery workspace", file=stderr)
        return EXIT_REFUSED
    print(f"This permanently deletes {len(listed.items)} recovery items from workspace {args.workspace}.", file=stdout)
    if not args.yes:
        print(f"Type 'discard {args.workspace}' to continue: ", end="", file=stdout)
        try:
            answer = _readline(stdin)
        except KeyboardInterrupt:
            answer = None
        if answer != f"discard {args.workspace}":
            print("discard refused; recovery remains available", file=stderr)
            return EXIT_REFUSED
    response = _request(client, DiscardRequest(args.workspace, True), stderr)
    if not isinstance(response, DiscardResponse):
        return EXIT_FAILURE
    print(f"discarded workspace {response.workspace_id}", file=stdout)
    return EXIT_OK


def _open_config_directory(path: Path, *, create: bool) -> int:
    absolute = path.absolute()
    name = absolute.name
    if not name or name in (".", ".."):
        raise OSError("unsafe chooser configuration directory")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent_fd = os.open(absolute.anchor, flags)
    try:
        for component in absolute.parent.parts[1:]:
            try:
                next_fd = os.open(component, flags, dir_fd=parent_fd)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(component, mode=0o700, dir_fd=parent_fd)
                next_fd = os.open(component, flags, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = next_fd
        try:
            config_fd = os.open(name, flags, dir_fd=parent_fd)
        except FileNotFoundError:
            if not create:
                raise
            os.mkdir(name, mode=0o700, dir_fd=parent_fd)
            config_fd = os.open(name, flags, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    metadata = os.fstat(config_fd)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        os.close(config_fd)
        raise OSError("unsafe chooser configuration directory")
    return config_fd


def login_chooser_enabled(paths: XDGPaths) -> bool:
    config_fd: int | None = None
    file_fd: int | None = None
    try:
        config_fd = _open_config_directory(paths.config_dir, create=False)
        file_fd = os.open(_CONFIG_NAME, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=config_fd)
        metadata = os.fstat(file_fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            return False
        raw = os.read(file_fd, MAX_CHOOSER_CONFIG_BYTES + 1)
        if len(raw) > MAX_CHOOSER_CONFIG_BYTES:
            return False
        payload = json.loads(raw.decode("utf-8"))
    except FileNotFoundError:
        return config_fd is None or file_fd is None
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if config_fd is not None:
            os.close(config_fd)
    return (
        isinstance(payload, dict)
        and set(payload) == {"schema_version", "login_chooser_enabled"}
        and payload.get("schema_version") == 1
        and type(payload.get("login_chooser_enabled")) is bool
        and payload["login_chooser_enabled"]
    )


def _write_chooser_setting(paths: XDGPaths, enabled: bool) -> None:
    payload = json.dumps(
        {"schema_version": 1, "login_chooser_enabled": enabled},
        separators=(",", ":"),
    ).encode("utf-8") + b"\n"
    config_fd = _open_config_directory(paths.config_dir, create=True)
    temporary = f".config-{secrets.token_hex(16)}"
    file_fd: int | None = None
    try:
        file_fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=config_fd,
        )
        os.fchmod(file_fd, 0o600)
        metadata = os.fstat(file_fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise OSError("unsafe temporary chooser configuration")
        view = memoryview(payload)
        while view:
            written = os.write(file_fd, view)
            if written == 0:
                raise OSError("short chooser configuration write")
            view = view[written:]
        os.fsync(file_fd)
        os.close(file_fd)
        file_fd = None
        os.replace(
            temporary,
            _CONFIG_NAME,
            src_dir_fd=config_fd,
            dst_dir_fd=config_fd,
        )
        os.fsync(config_fd)
    finally:
        if file_fd is not None:
            os.close(file_fd)
        with suppress(FileNotFoundError):
            os.unlink(temporary, dir_fd=config_fd)
        os.close(config_fd)


def _supported_cinnamon() -> bool:
    return "cinnamon" in os.environ.get("XDG_CURRENT_DESKTOP", "").casefold()


def _acquire_login_lock(paths: XDGPaths) -> tuple[int, int] | None:
    from termrecall.server import TermRecallServer, UnsafeRuntimePath

    runtime_fd = TermRecallServer._open_runtime_directory(paths.runtime_dir)
    lock_fd: int | None = None
    try:
        lock_fd = os.open(
            "login-coordinator.lock",
            os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW,
            0o600,
            dir_fd=runtime_fd,
        )
        metadata = os.fstat(lock_fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise UnsafeRuntimePath("unsafe login-coordinator.lock")
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(lock_fd)
            os.close(runtime_fd)
            return None
        return runtime_fd, lock_fd
    except BaseException:
        if lock_fd is not None:
            os.close(lock_fd)
        os.close(runtime_fd)
        raise


async def run_login_coordinator(
    paths: XDGPaths,
    stop: asyncio.Event,
    server_factory: Callable[[], object],
    client_factory: Callable[[], ServiceClient],
    chooser: Callable[[RestoreListResponse], Awaitable[None]],
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> int:
    if not _supported_cinnamon():
        return EXIT_OK
    held = _acquire_login_lock(paths)
    if held is None:
        return EXIT_OK
    runtime_fd, login_lock_fd = held
    server: object | None = None
    service_task: asyncio.Task[object] | None = None
    chooser_task: asyncio.Task[None] | None = None
    result = EXIT_OK
    try:
        server = server_factory()
        await server.start()  # type: ignore[attr-defined]
        service_task = asyncio.create_task(server.serve(stop))  # type: ignore[attr-defined]
        client = client_factory()
        response: object | None = None
        for poll in range(50):
            if service_task.done():
                service_task.result()
                raise RuntimeError("service stopped before readiness")
            response = await asyncio.to_thread(client.request, StatusRequest())
            if isinstance(response, StatusResponse) and response.ready is True:
                break
            if poll < 49:
                await sleep(0.1)
        else:
            return EXIT_FAILURE
        listed = await asyncio.to_thread(client.request, RestoreListRequest())
        if (
            login_chooser_enabled(paths)
            and isinstance(listed, RestoreListResponse)
            and listed.workspace_id is not None
        ):
            chooser_task = asyncio.create_task(chooser(listed))
            chooser_task.add_done_callback(lambda task: task.exception() if not task.cancelled() else None)
        stop_task = asyncio.create_task(stop.wait())
        done, pending = await asyncio.wait(
            {stop_task, service_task}, return_when=asyncio.FIRST_COMPLETED
        )
        for task in pending:
            if task is stop_task:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
        if service_task in done and not stop.is_set():
            service_task.result()
            result = EXIT_FAILURE
    except asyncio.CancelledError:
        stop.set()
        raise
    except Exception:
        result = EXIT_FAILURE
    finally:
        stop.set()
        if chooser_task is not None and not chooser_task.done():
            chooser_task.cancel()
            with suppress(asyncio.CancelledError):
                await chooser_task
        if service_task is not None:
            try:
                await asyncio.wait_for(asyncio.shield(service_task), timeout=1.0)
            except asyncio.TimeoutError:
                service_task.cancel()
                await asyncio.gather(service_task, return_exceptions=True)
            except Exception:
                result = EXIT_FAILURE
        if server is not None:
            try:
                await server.close()  # type: ignore[attr-defined]
            except Exception:
                result = EXIT_FAILURE
        fcntl.flock(login_lock_fd, fcntl.LOCK_UN)
        os.close(login_lock_fd)
        os.close(runtime_fd)
    return result


def _production_server(paths: XDGPaths, *, state_root: Path | None = None) -> object:
    from termrecall.adapters.registry import create_adapter, detect_adapter
    from termrecall.checkpoint import CheckpointManager
    from termrecall.model import Snapshot
    from termrecall.server import TermRecallServer
    from termrecall.state import EngineState
    from termrecall.store import SnapshotStore

    if state_root is None:
        home = Path.home().absolute()
        state = paths.state_dir.absolute()
        try:
            state.relative_to(home)
        except ValueError:
            boundary = state.parent
            while not boundary.exists() and boundary != boundary.parent:
                boundary = boundary.parent
        else:
            boundary = home
    else:
        boundary = Path(state_root)
    store = SnapshotStore(
        paths.state_dir,
        create_parents=True,
        root_boundary=boundary,
    )
    snapshot = store.load_latest() or Snapshot(1, 0, time.time(), ())
    state = EngineState(snapshot, {}, snapshot.generation)
    checkpoints = CheckpointManager(store, lambda: server.state.snapshot, time.monotonic, asyncio.sleep)
    server = TermRecallServer(
        paths.runtime_dir / "service.sock",
        os.getuid(),
        state,
        checkpoints,
        store,
        adapter=create_adapter(detect_adapter(shutil.which) or "gnome-terminal", shutil.which),
    )
    return server


async def _production_chooser(response: RestoreListResponse) -> None:
    del response
    executable = shutil.which("gnome-terminal")
    if executable is None:
        return
    process = await asyncio.create_subprocess_exec(
        executable,
        "--",
        sys.executable,
        "-m",
        "termrecall",
        "restore",
    )
    await process.wait()


def _run_login_command(paths: XDGPaths) -> int:
    async def coordinate() -> int:
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        installed: list[signal.Signals] = []
        for signum in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(signum, stop.set)
            except (NotImplementedError, RuntimeError):
                continue
            installed.append(signum)
        try:
            return await run_login_coordinator(
                paths,
                stop,
                lambda: _production_server(paths),
                lambda: ServiceClient(paths.runtime_dir / "service.sock"),
                _production_chooser,
            )
        finally:
            for signum in installed:
                loop.remove_signal_handler(signum)

    return asyncio.run(coordinate())


def _doctor(args: argparse.Namespace, stdout: TextIO, stderr: TextIO) -> int:
    from termrecall.adapters.registry import create_adapter, detect_adapter
    from termrecall.doctor import cleanup_stale_socket, run_doctor

    paths = _paths()
    if args.cleanup_stale_socket:
        try:
            identity = cleanup_stale_socket(paths)
        except RuntimeError as exc:
            print(f"error: {exc}", file=stderr)
            return EXIT_FAILURE
        print(f"removed verified stale socket inode {identity[0]}:{identity[1]}", file=stdout)
        return EXIT_OK
    adapter = create_adapter(detect_adapter(shutil.which) or "gnome-terminal", shutil.which)
    diagnostics = run_doctor(paths, adapter)
    for diagnostic in diagnostics:
        print(f"[{diagnostic.status.upper()}] {diagnostic.name}: {diagnostic.message}", file=stdout)
        if diagnostic.remedy:
            print(f"  remedy: {diagnostic.remedy}", file=stdout)
    if any(item.status == "error" for item in diagnostics):
        return EXIT_FAILURE
    if any(item.status == "warning" for item in diagnostics):
        return EXIT_WARNING
    return EXIT_OK


def run(argv: Sequence[str], stdin: TextIO, stdout: TextIO, stderr: TextIO) -> int:
    parser = build_parser()
    try:
        with redirect_stderr(stderr):
            args = parser.parse_args(tuple(argv))
    except SystemExit as exc:
        return int(exc.code)
    if args.command == "doctor":
        try:
            return _doctor(args, stdout, stderr)
        except (OSError, ValueError) as exc:
            print(f"error: {exc}", file=stderr)
            return EXIT_FAILURE
    if args.command == "chooser":
        try:
            _write_chooser_setting(_paths(), args.setting == "enable")
        except (OSError, ValueError) as exc:
            print(f"error: {exc}", file=stderr)
            return EXIT_FAILURE
        return EXIT_OK
    if args.command == "setup":
        from termrecall.installer import run_integration_setup
        from termrecall.installer_contract import DesiredState, IntegrationSetupRequest

        request = IntegrationSetupRequest(
            dry_run=args.dry_run,
            bash=DesiredState(args.bash),
            autostart=DesiredState(args.autostart),
            chooser=DesiredState(args.chooser),
        )
        return run_integration_setup(request, stdout, stderr)
    if args.command == "autostart":
        from termrecall.installer import run_autostart

        return run_autostart(args.setting, stdout, stderr)
    if args.command == "uninstall":
        from termrecall.installer import run_uninstall

        return run_uninstall(args, stdin, stdout, stderr)
    if args.command == "login-coordinator":
        try:
            return _run_login_command(_paths())
        except (OSError, ValueError) as exc:
            print(f"error: {exc}", file=stderr)
            return EXIT_FAILURE
    try:
        client = _service_client()
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=stderr)
        return EXIT_FAILURE
    if args.command == "status":
        return _status(client, stdout, stderr)
    if args.command == "snapshot":
        return _snapshot(client, stdout, stderr)
    if args.command == "list":
        response = _list_response(client, stdout, stderr, display=True)
        if response is None:
            return EXIT_FAILURE
        return EXIT_WARNING if response.workspace_id is None or response.diagnostics else EXIT_OK
    if args.command == "restore":
        return _restore(args, client, stdin, stdout, stderr)
    if args.command == "discard":
        return _discard(args, client, stdin, stdout, stderr)
    return EXIT_FAILURE


def main() -> None:
    raise SystemExit(run(sys.argv[1:], sys.stdin, sys.stdout, sys.stderr))
