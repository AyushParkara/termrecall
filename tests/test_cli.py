# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import io
import os
import stat
from pathlib import Path

import pytest

from termrecall import cli
from termrecall.model import OutcomeKind, RestorationLevel
from termrecall.protocol import (
    DiscardRequest,
    DiscardResponse,
    ErrorCode,
    ErrorResponse,
    OutcomeView,
    ProtocolError,
    RecoveryItemView,
    RestoreExecuteRequest,
    RestoreListRequest,
    RestoreListResponse,
    RestoreResultResponse,
    RestoreRetryRequest,
    SafeExternalText,
    SnapshotResponse,
    StatusResponse,
)


class TTYInput(io.StringIO):
    def isatty(self) -> bool:
        return True


class NonTTYInput(io.StringIO):
    def isatty(self) -> bool:
        return False


class FakeClient:
    def __init__(self, responses: list[object]) -> None:
        self.responses = responses
        self.requests: list[object] = []

    def request(self, request: object) -> object:
        self.requests.append(request)
        return self.responses.pop(0)


def streams(stdin: str = "") -> tuple[TTYInput, io.StringIO, io.StringIO]:
    return TTYInput(stdin), io.StringIO(), io.StringIO()


def test_production_server_creates_default_fresh_xdg_state_hierarchy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", str(home))
    runtime = tmp_path / "run" / "termrecall"
    paths = cli.resolve_paths(
        {"XDG_RUNTIME_DIR": str(tmp_path / "run")},
        os.getuid(),
        home,
    )

    server = cli._production_server(paths)

    try:
        assert paths.state_dir.is_dir()
        assert stat.S_IMODE((home / ".local").stat().st_mode) == 0o700
        assert stat.S_IMODE((home / ".local" / "state").stat().st_mode) == 0o700
        assert stat.S_IMODE(paths.state_dir.stat().st_mode) == 0o700
        assert server.socket_path == runtime / "service.sock"
    finally:
        server.store.close()


def test_production_server_creates_fresh_explicit_xdg_state_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", str(home))
    user_root = tmp_path / "user-owned"
    user_root.mkdir(mode=0o700)
    explicit = user_root / "private-state"
    paths = cli.resolve_paths(
        {
            "XDG_RUNTIME_DIR": str(tmp_path / "run"),
            "XDG_STATE_HOME": str(explicit),
        },
        os.getuid(),
        home,
    )

    server = cli._production_server(paths)

    try:
        assert paths.state_dir.is_dir()
        assert stat.S_IMODE(explicit.stat().st_mode) == 0o700
        assert stat.S_IMODE(paths.state_dir.stat().st_mode) == 0o700
    finally:
        server.store.close()


def test_production_server_rejects_symlinked_state_ancestor_without_touching_external(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    external = tmp_path / "external"
    external.mkdir(mode=0o700)
    marker = external / "operator-owned"
    marker.write_text("untouched", encoding="utf-8")
    (home / ".local").symlink_to(external, target_is_directory=True)
    paths = cli.resolve_paths(
        {"XDG_RUNTIME_DIR": str(tmp_path / "run")},
        os.getuid(),
        home,
    )

    with pytest.raises(RuntimeError, match="ancestor"):
        cli._production_server(paths, state_root=home)

    assert marker.read_text(encoding="utf-8") == "untouched"
    assert not (external / "state").exists()


@pytest.mark.parametrize("command", ["status", "snapshot", "list", "restore", "discard", "doctor"])
def test_required_command_parses(command: str) -> None:
    argv = [command] + (["workspace-a"] if command == "discard" else [])
    assert cli.build_parser().parse_args(argv).command == command


@pytest.mark.parametrize("command", ["setup", "autostart", "uninstall"])
def test_lifecycle_command_parses(command: str) -> None:
    argv = {"setup": ["setup"], "autostart": ["autostart", "enable"], "uninstall": ["uninstall", "--yes"]}[command]
    assert cli.build_parser().parse_args(argv).command == command


def test_lifecycle_commands_dispatch_before_service_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from termrecall import installer
    from termrecall.installer_contract import LifecycleExit, resolve_lifecycle_paths

    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    paths = resolve_lifecycle_paths({}, home)
    monkeypatch.setattr(installer, "_lifecycle_paths", lambda: paths)
    monkeypatch.setattr(cli, "_service_client", lambda: pytest.fail("service client must not be constructed for lifecycle commands"))
    # no installed manifest -> REFUSED, but the service client was never constructed
    stdin, stdout, stderr = streams()
    assert cli.run(["setup", "--bash", "enable"], stdin, stdout, stderr) == int(LifecycleExit.REFUSED)
    assert cli.run(["autostart", "enable"], stdin, stdout, stderr) == int(LifecycleExit.REFUSED)
    assert cli.run(["uninstall", "--yes"], stdin, stdout, stderr) == int(LifecycleExit.REFUSED)


def test_status_reports_degradation_and_warning_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeClient([StatusResponse(True, 2, 5, 3, True, True, SafeExternalText.catalog("details unavailable"), 1, (SafeExternalText.catalog("process_unknown"),))])
    monkeypatch.setattr(cli, "_service_client", lambda: client)
    stdin, stdout, stderr = streams()
    assert cli.run(["status"], stdin, stdout, stderr) == 1
    assert "registered shells: 2" in stdout.getvalue()
    assert "dirty/durable generation: 5/3" in stdout.getvalue()
    assert "process_unknown" in stdout.getvalue()
    assert "details unavailable" in stdout.getvalue()


def test_snapshot_waits_for_durable_response(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeClient([SnapshotResponse(9)])
    monkeypatch.setattr(cli, "_service_client", lambda: client)
    stdin, stdout, stderr = streams()
    assert cli.run(["snapshot"], stdin, stdout, stderr) == 0
    assert "durable generation 9" in stdout.getvalue()


def items() -> tuple[RecoveryItemView, ...]:
    return (
        RecoveryItemView("item-a", "shell-a", SafeExternalText.catalog("previous_boot"), RestorationLevel.RECONSTRUCTED, "/srv/a", None, type("Display", (), {"value": "python app.py"})(), True),
        RecoveryItemView("item-b", "shell-b", SafeExternalText.catalog("same_boot_dead"), RestorationLevel.PARTIAL, "/home/u", SafeExternalText.catalog("details unavailable"), None, False),
    )


def test_list_shows_levels_metadata_and_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeClient([RestoreListResponse("workspace-a", items(), ())])
    monkeypatch.setattr(cli, "_service_client", lambda: client)
    stdin, stdout, stderr = streams()
    assert cli.run(["list"], stdin, stdout, stderr) == 0
    output = stdout.getvalue()
    assert "workspace-a" in output and "RECONSTRUCTED" in output and "PARTIAL" in output
    assert "python app.py" in output and "directory warning: details unavailable" in output


def test_restore_approval_sends_only_ids_never_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    result = RestoreResultResponse("workspace-a", "attempt-a", (), ())
    client = FakeClient([RestoreListResponse("workspace-a", items(), ()), result])
    monkeypatch.setattr(cli, "_service_client", lambda: client)
    stdin, stdout, stderr = streams("1\ny\n")
    assert cli.run(["restore"], stdin, stdout, stderr) == 0
    request = client.requests[-1]
    assert request == RestoreExecuteRequest("workspace-a", ("item-a",), ("item-a",))
    assert "python app.py" not in repr(request)


def test_restore_eof_defaults_to_no_command(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeClient([RestoreListResponse("workspace-a", items(), ()), RestoreResultResponse("workspace-a", "attempt-a", (), ("item-a",))])
    monkeypatch.setattr(cli, "_service_client", lambda: client)
    stdin, stdout, stderr = streams("1\n")
    assert cli.run(["restore"], stdin, stdout, stderr) == 1
    assert client.requests[-1] == RestoreExecuteRequest("workspace-a", ("item-a",), ())


def test_non_tty_cannot_drive_interactive_item_selection(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeClient([RestoreListResponse("workspace-a", items(), ())])
    monkeypatch.setattr(cli, "_service_client", lambda: client)
    stdin = NonTTYInput("1\ny\n")
    stdout, stderr = io.StringIO(), io.StringIO()
    assert cli.run(["restore", "--directory-only"], stdin, stdout, stderr) == 2
    assert client.requests == [RestoreListRequest()]
    assert "interactive terminal" in stderr.getvalue()


@pytest.mark.parametrize("argv", [["restore", "--all"], ["restore", "--retry", "attempt-a"]])
def test_non_tty_cannot_approve_replayable_commands_or_send_restore_request(
    monkeypatch: pytest.MonkeyPatch, argv: list[str]
) -> None:
    responses: list[object] = [RestoreListResponse("workspace-a", items(), ())]
    if "--retry" in argv:
        responses.append(RestoreListResponse("workspace-a", (items()[0],), ()))
    client = FakeClient(responses)
    monkeypatch.setattr(cli, "_service_client", lambda: client)
    stdin = NonTTYInput("y\n")
    stdout, stderr = io.StringIO(), io.StringIO()
    assert cli.run(argv, stdin, stdout, stderr) == 2
    expected_count = 2 if "--retry" in argv else 1
    assert len(client.requests) == expected_count
    assert not any(isinstance(request, (RestoreExecuteRequest, RestoreRetryRequest)) for request in client.requests)
    assert "interactive terminal" in stderr.getvalue()


def test_directory_only_never_prompts_for_command(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeClient([RestoreListResponse("workspace-a", items(), ()), RestoreResultResponse("workspace-a", "attempt-a", (), ())])
    monkeypatch.setattr(cli, "_service_client", lambda: client)
    stdin = NonTTYInput("y\n")
    stdout, stderr = io.StringIO(), io.StringIO()
    assert cli.run(["restore", "--all", "--directory-only"], stdin, stdout, stderr) == 0
    assert client.requests[-1] == RestoreExecuteRequest("workspace-a", ("item-a", "item-b"), ())


def test_discard_requires_exact_confirmation(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeClient([RestoreListResponse("workspace-a", items(), ())])
    monkeypatch.setattr(cli, "_service_client", lambda: client)
    stdin, stdout, stderr = streams("yes\n")
    assert cli.run(["discard", "workspace-a"], stdin, stdout, stderr) == 2
    assert len(client.requests) == 1
    assert "2 recovery items" in stdout.getvalue()


def test_discard_yes_sends_exact_schema(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeClient([RestoreListResponse("workspace-a", items(), ()), DiscardResponse("workspace-a", True)])
    monkeypatch.setattr(cli, "_service_client", lambda: client)
    stdin, stdout, stderr = streams()
    assert cli.run(["discard", "workspace-a", "--yes"], stdin, stdout, stderr) == 0
    assert client.requests[-1] == DiscardRequest("workspace-a", True)


def test_no_recovery_and_service_error_exit_codes(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeClient([RestoreListResponse(None, (), ()), ErrorResponse(ProtocolError(ErrorCode.PERSISTENCE_FAILED, "recovery state was not saved"))])
    monkeypatch.setattr(cli, "_service_client", lambda: client)
    stdin, stdout, stderr = streams()
    assert cli.run(["list"], stdin, stdout, stderr) == 1
    assert cli.run(["snapshot"], stdin, stdout, stderr) == 3


def test_retry_uses_fresh_id_only_approvals(monkeypatch: pytest.MonkeyPatch) -> None:
    retry_items = (items()[0],)
    client = FakeClient([
        RestoreListResponse("workspace-a", items(), ()),
        RestoreListResponse("workspace-a", retry_items, ()),
        RestoreResultResponse("workspace-a", "attempt-b", (), ()),
    ])
    monkeypatch.setattr(cli, "_service_client", lambda: client)
    stdin, stdout, stderr = streams("y\n")
    assert cli.run(["restore", "--retry", "attempt-a"], stdin, stdout, stderr) == 0
    assert client.requests[1] == RestoreListRequest("workspace-a", "attempt-a")
    request = client.requests[-1]
    assert request.workspace_id == "workspace-a"
    assert request.attempt_id == "attempt-a"
    assert request.approved_item_ids == ("item-a",)
    assert "python app.py" not in repr(request)


def test_retry_never_shows_or_approves_item_outside_attempt(monkeypatch: pytest.MonkeyPatch) -> None:
    unrelated = items()[0]
    retryable = RecoveryItemView(
        "item-b",
        "shell-b",
        SafeExternalText.catalog("same_boot_dead"),
        RestorationLevel.RECONSTRUCTED,
        "/srv/b",
        None,
        type("Display", (), {"value": "make serve"})(),
        True,
    )
    client = FakeClient([
        RestoreListResponse("workspace-a", (unrelated, retryable), ()),
        RestoreListResponse("workspace-a", (retryable,), ()),
        RestoreResultResponse("workspace-a", "attempt-b", (), ()),
    ])
    monkeypatch.setattr(cli, "_service_client", lambda: client)
    stdin, stdout, stderr = streams("y\n")
    assert cli.run(["restore", "--retry", "attempt-a"], stdin, stdout, stderr) == 0
    assert "python app.py" not in stdout.getvalue()
    assert "make serve" in stdout.getvalue()
    assert client.requests[-1].approved_item_ids == ("item-b",)
    assert "make serve" not in repr(client.requests[-1])


def test_unsupported_adapter_has_required_message(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeClient([RestoreListResponse("workspace-a", items(), ()), ErrorResponse(ProtocolError(ErrorCode.ADAPTER_UNAVAILABLE, "terminal adapter unavailable"))])
    monkeypatch.setattr(cli, "_service_client", lambda: client)
    stdin, stdout, stderr = streams()
    assert cli.run(["restore", "--all", "--directory-only"], stdin, stdout, stderr) == 3
    assert "only GNOME Terminal is supported" in stderr.getvalue()


def test_usage_error_is_written_to_supplied_stderr() -> None:
    stdin, stdout, stderr = streams()
    assert cli.run(["restore", "--all", "--retry", "attempt-a"], stdin, stdout, stderr) == 2
    assert "not allowed" in stderr.getvalue()


def test_ctrl_c_is_refused_without_request(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeClient([RestoreListResponse("workspace-a", items(), ())])
    monkeypatch.setattr(cli, "_service_client", lambda: client)
    class Interrupt(io.StringIO):
        def readline(self, *args: object) -> str:
            raise KeyboardInterrupt
    assert cli.run(["restore"], Interrupt(), io.StringIO(), io.StringIO()) == 2
    assert len(client.requests) == 1


# ---------------------------------------------------------------------------
# Resume-aware restore UI (real resume command + summary + multi-session picker)
# ---------------------------------------------------------------------------

def _codex_item(item_id: str = "item-c", cwd: str = "/srv/codex", *,
    resume_command: str = "codex resume --last", resume_summary: str = "", resume_session_count: int = 1,
) -> RecoveryItemView:
    """A recovery item whose stored command is a resume-capable tool (codex).

    Carries the server-resolved resume fields (what _recovery_view produces)
    so the UI reads them directly rather than recomputing client-side.
    """
    display = type("Display", (), {"value": "codex"})()
    return RecoveryItemView(item_id, "shell-c", SafeExternalText.catalog("previous_boot"), RestorationLevel.RECONSTRUCTED, cwd, None, display, True, resume_command, resume_summary, resume_session_count)


def test_show_item_displays_resume_command_not_restart_warning() -> None:
    # The server pre-resolves resume_command + summary; the UI just displays them.
    item = _codex_item(resume_command="codex resume abc-123", resume_summary="fix the login bug", resume_session_count=1)
    stdout = io.StringIO()
    cli._show_item(item, stdout)
    out = stdout.getvalue()
    assert "will resume: codex resume abc-123" in out
    assert "session summary: fix the login bug" in out
    assert "sessions in this directory: 1" in out
    assert "would be restarted, not resumed" not in out


def test_show_item_falls_back_to_replay_warning_for_plain_commands() -> None:
    # A plain (non-resume) command: server leaves resume_command empty.
    display = type("Display", (), {"value": "python app.py"})()
    item = RecoveryItemView("item-d", "shell-d", SafeExternalText.catalog("previous_boot"), RestorationLevel.RECONSTRUCTED, "/srv", None, display, True, "", "", 0)
    stdout = io.StringIO()
    cli._show_item(item, stdout)
    out = stdout.getvalue()
    assert "active command: python app.py" in out
    assert "would be restarted, not resumed" in out


def test_approvals_resume_defaults_to_yes_on_enter(monkeypatch: pytest.MonkeyPatch) -> None:
    # Server resolved resume_command; picker only needs find_sessions_for_cwd
    # when session_count > 1, so stub it for the picker (empty here).
    monkeypatch.setattr(cli, "find_sessions_for_cwd", lambda cwd: [])
    item = _codex_item(resume_command="codex resume --last", resume_session_count=0)
    stdin = io.StringIO("\n")  # Enter = default yes
    stdout = io.StringIO()
    approved = cli._approvals((item,), {item.item_id}, stdin, stdout, directory_only=False)
    assert approved == (item.item_id,)
    assert "Resume this session? [Y/n]" in stdout.getvalue()


def test_approvals_multi_session_picker_shows_summary(monkeypatch: pytest.MonkeyPatch) -> None:
    sessions = [
        type("S", (), {"session_id": "sess-1", "summary": "", "first_activity": "2026-08-01", "last_activity": "2026-08-01", "title": "", "tool": "codex"}),
        type("S", (), {"session_id": "sess-2", "summary": "build the dashboard", "first_activity": "2026-07-01", "last_activity": "2026-07-05", "title": "", "tool": "codex"}),
    ]
    monkeypatch.setattr(cli, "find_sessions_for_cwd", lambda cwd: sessions)
    monkeypatch.setattr(cli, "build_resume_argv", lambda m, sid: ("codex", "resume", sid))
    monkeypatch.setattr(cli, "find_resume_adapter", lambda exe: type("M", (), {"executable": exe, "contract": type("C",(),{"build":staticmethod(lambda self,exe,sid:("codex","resume",sid))})()})() if exe == "codex" else None)
    item = _codex_item(resume_command="codex resume sess-1", resume_session_count=2)
    stdin = io.StringIO("2\n\n")
    stdout = io.StringIO()
    approved = cli._approvals((item,), {item.item_id}, stdin, stdout, directory_only=False)
    out = stdout.getvalue()
    assert "2 sessions found" in out
    assert "build the dashboard" in out
    assert "resuming: codex resume sess-2" in out
    assert approved == (item.item_id,)
