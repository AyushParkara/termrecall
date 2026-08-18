# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import asyncio
import io
import json
import os
import stat
from importlib.resources import files
from pathlib import Path

import pytest

from termrecall import cli


@pytest.fixture(autouse=True)
def cinnamon_desktop(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CURRENT_DESKTOP", "X-Cinnamon")
from termrecall.paths import XDGPaths
from termrecall.protocol import RestoreListRequest, RestoreListResponse, StatusRequest, StatusResponse


def configured_paths(tmp_path: Path) -> XDGPaths:
    return XDGPaths(
        tmp_path / "run" / "termrecall",
        tmp_path / "state" / "termrecall",
        tmp_path / "config" / "termrecall",
    )


def ready() -> StatusResponse:
    return StatusResponse(True, 0, 0, 0, False, False, None, 0, ())


def recovery() -> RestoreListResponse:
    return RestoreListResponse("workspace-a", (), ())


class FakeClient:
    def __init__(self, statuses: list[object], listed: object | None = None) -> None:
        self.statuses = statuses
        self.listed = listed if listed is not None else recovery()
        self.requests: list[object] = []

    def request(self, request: object) -> object:
        self.requests.append(request)
        if isinstance(request, StatusRequest):
            return self.statuses.pop(0)
        if isinstance(request, RestoreListRequest):
            return self.listed
        raise AssertionError(f"unexpected request: {request!r}")


class FakeServer:
    def __init__(self, *, start_error: BaseException | None = None, serve_error: BaseException | None = None) -> None:
        self.start_error = start_error
        self.serve_error = serve_error
        self.started = asyncio.Event()
        self.serving = asyncio.Event()
        self.closed = 0
        self.events: list[str] = []

    async def start(self) -> None:
        self.events.append("start")
        if self.start_error is not None:
            raise self.start_error
        self.started.set()

    async def serve(self, stop: asyncio.Event) -> None:
        assert self.started.is_set()
        self.events.append("serve")
        self.serving.set()
        if self.serve_error is not None:
            raise self.serve_error
        await stop.wait()

    async def close(self) -> None:
        self.events.append("close")
        self.closed += 1


def test_autostart_entry_is_the_only_default_enabled_desktop_target() -> None:
    root = files("termrecall") / "data" / "xdg"
    desktop = (root / "termrecall.desktop").read_text(encoding="utf-8")
    assert desktop == (
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=TermRecall\n"
        "Exec={executable} login-coordinator\n"
        "OnlyShowIn=X-Cinnamon;Cinnamon;\n"
        "X-GNOME-Autostart-enabled=true\n"
        "Terminal=false\n"
        "NoDisplay=true\n"
    )
    assert not (root / "termrecall-chooser.desktop").is_file()
    assert not (root / "termrecall-service.desktop").is_file()


def test_chooser_setting_defaults_enabled_and_rejects_unsafe_or_invalid_config(tmp_path: Path) -> None:
    paths = configured_paths(tmp_path)
    assert cli.login_chooser_enabled(paths) is True
    paths.config_dir.mkdir(parents=True, mode=0o700)
    config = paths.config_dir / "config.json"
    invalid = (
        {"schema_version": 2, "login_chooser_enabled": True},
        {"schema_version": 1, "login_chooser_enabled": 1},
        {"schema_version": 1, "login_chooser_enabled": True, "extra": False},
    )
    for value in invalid:
        config.write_text(json.dumps(value), encoding="utf-8")
        config.chmod(0o600)
        assert cli.login_chooser_enabled(paths) is False
    config.unlink()
    config.symlink_to(tmp_path / "missing")
    assert cli.login_chooser_enabled(paths) is False


def test_chooser_config_read_is_bounded(tmp_path: Path) -> None:
    paths = configured_paths(tmp_path)
    paths.config_dir.mkdir(parents=True, mode=0o700)
    config = paths.config_dir / "config.json"
    config.write_bytes(b" " * (cli.MAX_CHOOSER_CONFIG_BYTES + 1))
    config.chmod(0o600)
    assert cli.login_chooser_enabled(paths) is False


def test_chooser_config_read_stays_anchored_when_directory_path_is_swapped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = configured_paths(tmp_path)
    paths.config_dir.mkdir(parents=True, mode=0o700)
    config = paths.config_dir / "config.json"
    config.write_text('{"schema_version":1,"login_chooser_enabled":true}', encoding="utf-8")
    config.chmod(0o600)
    verified = tmp_path / "verified-config"
    attacker = tmp_path / "attacker-config"
    real_open = os.open
    swapped = False

    def swap_after_directory_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        fd = real_open(path, flags, mode, dir_fd=dir_fd)
        if (
            not swapped
            and flags & os.O_DIRECTORY
            and Path(f"/proc/self/fd/{fd}").resolve() == paths.config_dir
        ):
            swapped = True
            paths.config_dir.rename(verified)
            attacker.mkdir(mode=0o700)
            (attacker / "config.json").write_text('{"schema_version":1,"login_chooser_enabled":false}')
            (attacker / "config.json").chmod(0o600)
            paths.config_dir.symlink_to(attacker, target_is_directory=True)
        return fd

    monkeypatch.setattr(cli.os, "open", swap_after_directory_open)
    assert cli.login_chooser_enabled(paths) is True
    assert json.loads((attacker / "config.json").read_text())["login_chooser_enabled"] is False


def test_chooser_config_write_stays_anchored_when_directory_path_is_swapped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = configured_paths(tmp_path)
    paths.config_dir.mkdir(parents=True, mode=0o700)
    verified = tmp_path / "verified-config"
    attacker = tmp_path / "attacker-config"
    real_open = os.open
    swapped = False

    def swap_after_directory_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        fd = real_open(path, flags, mode, dir_fd=dir_fd)
        if (
            not swapped
            and flags & os.O_DIRECTORY
            and Path(f"/proc/self/fd/{fd}").resolve() == paths.config_dir
        ):
            swapped = True
            paths.config_dir.rename(verified)
            attacker.mkdir(mode=0o700)
            (attacker / "config.json").write_text("external")
            paths.config_dir.symlink_to(attacker, target_is_directory=True)
        return fd

    monkeypatch.setattr(cli.os, "open", swap_after_directory_open)
    cli._write_chooser_setting(paths, False)
    assert json.loads((verified / "config.json").read_text()) == {
        "schema_version": 1,
        "login_chooser_enabled": False,
    }
    assert (attacker / "config.json").read_text() == "external"


def test_chooser_enable_disable_atomically_writes_exact_private_schema(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths = configured_paths(tmp_path)
    monkeypatch.setattr(cli, "_paths", lambda: paths)
    stdin, stdout, stderr = io.StringIO(), io.StringIO(), io.StringIO()
    assert cli.run(["chooser", "disable"], stdin, stdout, stderr) == 0
    config = paths.config_dir / "config.json"
    assert json.loads(config.read_text()) == {"schema_version": 1, "login_chooser_enabled": False}
    assert stat.S_IMODE(config.stat().st_mode) == 0o600
    assert cli.run(["chooser", "enable"], stdin, stdout, stderr) == 0
    assert json.loads(config.read_text()) == {"schema_version": 1, "login_chooser_enabled": True}


@pytest.mark.asyncio
async def test_readiness_starts_service_first_then_schedules_exactly_one_chooser_and_keeps_serving(tmp_path: Path) -> None:
    paths = configured_paths(tmp_path)
    server = FakeServer()
    client = FakeClient([ready()])
    stop = asyncio.Event()
    chooser_calls: list[RestoreListResponse] = []
    chooser_done = asyncio.Event()

    async def chooser(response: RestoreListResponse) -> None:
        chooser_calls.append(response)
        chooser_done.set()

    task = asyncio.create_task(cli.run_login_coordinator(paths, stop, lambda: server, lambda: client, chooser))
    await asyncio.wait_for(chooser_done.wait(), 1)
    await asyncio.sleep(0)
    assert server.events[:2] == ["start", "serve"]
    assert [type(request) for request in client.requests] == [StatusRequest, RestoreListRequest]
    assert chooser_calls == [client.listed]
    assert not task.done()
    stop.set()
    assert await asyncio.wait_for(task, 1) == 0
    assert server.closed == 1


@pytest.mark.asyncio
async def test_readiness_timeout_polls_50_times_sleeps_49_and_never_lists_or_chooses(tmp_path: Path) -> None:
    paths = configured_paths(tmp_path)
    server = FakeServer()
    client = FakeClient([object()] * 50)
    sleeps: list[float] = []
    chooser_calls = 0

    async def sleep(delay: float) -> None:
        sleeps.append(delay)

    async def chooser(response: RestoreListResponse) -> None:
        nonlocal chooser_calls
        chooser_calls += 1

    result = await cli.run_login_coordinator(paths, asyncio.Event(), lambda: server, lambda: client, chooser, sleep)
    assert result == cli.EXIT_FAILURE
    assert sum(isinstance(request, StatusRequest) for request in client.requests) == 50
    assert sleeps == [0.1] * 49
    assert not any(isinstance(request, RestoreListRequest) for request in client.requests)
    assert chooser_calls == 0
    assert server.closed == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["disabled", "malformed", "no-recovery"])
async def test_disabled_malformed_or_no_recovery_never_starts_chooser(tmp_path: Path, mode: str) -> None:
    paths = configured_paths(tmp_path)
    if mode != "no-recovery":
        paths.config_dir.mkdir(parents=True, mode=0o700)
        config = paths.config_dir / "config.json"
        config.write_text(
            json.dumps({"schema_version": 1, "login_chooser_enabled": False}) if mode == "disabled" else "not json",
            encoding="utf-8",
        )
        config.chmod(0o600)
    listed = RestoreListResponse(None, (), ()) if mode == "no-recovery" else recovery()
    client = FakeClient([ready()], listed)
    server = FakeServer()
    stop = asyncio.Event()
    calls = 0

    async def chooser(response: RestoreListResponse) -> None:
        nonlocal calls
        calls += 1

    task = asyncio.create_task(cli.run_login_coordinator(paths, stop, lambda: server, lambda: client, chooser))
    await server.serving.wait()
    await asyncio.sleep(0.05)
    assert calls == 0
    assert sum(isinstance(request, RestoreListRequest) for request in client.requests) == 1
    stop.set()
    assert await task == 0


@pytest.mark.asyncio
async def test_chooser_failure_is_not_recovered_and_service_remains_until_stop(tmp_path: Path) -> None:
    paths = configured_paths(tmp_path)
    server = FakeServer()
    stop = asyncio.Event()
    calls = 0

    async def chooser(response: RestoreListResponse) -> None:
        nonlocal calls
        calls += 1
        raise RuntimeError("chooser failed")

    task = asyncio.create_task(cli.run_login_coordinator(paths, stop, lambda: server, lambda: FakeClient([ready()]), chooser))
    await server.serving.wait()
    await asyncio.sleep(0.05)
    assert calls == 1
    assert not task.done()
    stop.set()
    assert await task == 0
    assert calls == 1


@pytest.mark.asyncio
async def test_active_chooser_is_cancelled_and_awaited_once_on_shutdown(tmp_path: Path) -> None:
    paths = configured_paths(tmp_path)
    server = FakeServer()
    stop = asyncio.Event()
    entered = asyncio.Event()
    cancelled = 0

    async def chooser(response: RestoreListResponse) -> None:
        nonlocal cancelled
        entered.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancelled += 1
            raise

    task = asyncio.create_task(cli.run_login_coordinator(paths, stop, lambda: server, lambda: FakeClient([ready()]), chooser))
    await entered.wait()
    stop.set()
    assert await asyncio.wait_for(task, 1) == 0
    assert cancelled == 1
    assert server.closed == 1


@pytest.mark.asyncio
async def test_second_coordinator_exits_silently_without_constructing_server_or_chooser(tmp_path: Path) -> None:
    paths = configured_paths(tmp_path)
    first_server = FakeServer()
    first_stop = asyncio.Event()
    chooser_started = asyncio.Event()

    async def first_chooser(response: RestoreListResponse) -> None:
        chooser_started.set()

    first = asyncio.create_task(cli.run_login_coordinator(paths, first_stop, lambda: first_server, lambda: FakeClient([ready()]), first_chooser))
    await chooser_started.wait()
    second_servers = 0
    second_choosers = 0

    def second_factory() -> FakeServer:
        nonlocal second_servers
        second_servers += 1
        return FakeServer()

    async def second_chooser(response: RestoreListResponse) -> None:
        nonlocal second_choosers
        second_choosers += 1

    assert await cli.run_login_coordinator(paths, asyncio.Event(), second_factory, lambda: FakeClient([ready()]), second_chooser) == 0
    assert second_servers == second_choosers == 0
    first_stop.set()
    assert await first == 0
    assert not (paths.runtime_dir / "login-coordinator.lock").is_dir()


@pytest.mark.asyncio
async def test_unsupported_desktop_does_not_acquire_lock_or_construct_server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CURRENT_DESKTOP", "GNOME")
    paths = configured_paths(tmp_path)
    constructed = 0

    def factory() -> FakeServer:
        nonlocal constructed
        constructed += 1
        return FakeServer()

    assert await cli.run_login_coordinator(paths, asyncio.Event(), factory, lambda: FakeClient([ready()]), lambda response: asyncio.sleep(0)) == 0
    assert constructed == 0
    assert not (paths.runtime_dir / "login-coordinator.lock").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["start", "serve", "status", "list"])
async def test_failures_close_server_exactly_once_and_release_login_lock(tmp_path: Path, failure: str) -> None:
    paths = configured_paths(tmp_path)
    server = FakeServer(
        start_error=RuntimeError("start") if failure == "start" else None,
        serve_error=RuntimeError("serve") if failure == "serve" else None,
    )
    statuses: list[object] = [ready()]
    listed: object = recovery()
    if failure == "status":
        class FailingStatusClient(FakeClient):
            def request(self, request: object) -> object:
                raise RuntimeError("status")
        client: FakeClient = FailingStatusClient([])
    else:
        client = FakeClient(statuses, listed)
    if failure == "list":
        class FailingListClient(FakeClient):
            def request(self, request: object) -> object:
                if isinstance(request, RestoreListRequest):
                    raise RuntimeError("list")
                return super().request(request)
        client = FailingListClient(statuses)

    result = await cli.run_login_coordinator(paths, asyncio.Event(), lambda: server, lambda: client, lambda response: asyncio.sleep(0))
    assert result == cli.EXIT_FAILURE
    assert server.closed == 1

    fresh = FakeServer()
    fresh_stop = asyncio.Event()
    started = asyncio.create_task(cli.run_login_coordinator(paths, fresh_stop, lambda: fresh, lambda: FakeClient([ready()], RestoreListResponse(None, (), ())), lambda response: asyncio.sleep(0)))
    await fresh.serving.wait()
    fresh_stop.set()
    assert await started == 0


def test_login_coordinator_is_hidden_and_there_is_no_service_command() -> None:
    help_text = cli.build_parser().format_help()
    assert "login-coordinator" not in help_text
    parser = cli.build_parser()
    assert parser.parse_args(["login-coordinator"]).command == "login-coordinator"
    with pytest.raises(SystemExit):
        parser.parse_args(["service"])
