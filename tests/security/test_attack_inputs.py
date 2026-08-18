# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import asyncio
import json
import os
import socket
from pathlib import Path

import pytest

from termrecall.client import ServiceClient
from termrecall.model import OutcomeKind
from termrecall.processes import ProcessStatus
from termrecall.protocol import ErrorCode, ErrorResponse, RestoreExecuteRequest
from termrecall.server import PeerCredentials
from termrecall.store import SnapshotStore


async def raw_exchange(path: Path, payload: bytes) -> dict[str, object]:
    def exchange() -> dict[str, object]:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(2)
            connection.connect(str(path))
            connection.sendall(payload)
            return json.loads(connection.makefile("rb").readline())

    return await asyncio.to_thread(exchange)


@pytest.mark.asyncio
async def test_hostile_event_never_executes_unique_absolute_marker(
    system_harness, tmp_path: Path
) -> None:
    marker = (tmp_path / "termrecall-attack-7f4b0e2d").resolve()
    payload = json.dumps({
        "schema_version": 1,
        "type": "prompt_ready",
        "cwd": f"/tmp; touch {marker}",
    }).encode() + b"\n"
    response = await raw_exchange(system_harness.socket_path, payload)
    assert response["ok"] is False
    assert not marker.exists()
    assert system_harness.socket_path.is_socket()


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [b"{" + b"x" * 20000 + b"}\n", b"\xff\xfe\n"])
async def test_malformed_hostile_events_do_not_crash(system_harness, payload: bytes) -> None:
    assert (await raw_exchange(system_harness.socket_path, payload))["ok"] is False
    assert system_harness.socket_path.is_socket()


@pytest.mark.asyncio
async def test_wrong_uid_is_rejected_before_dispatch(
    system_harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "termrecall.server.get_peer_credentials",
        lambda _: PeerCredentials(os.getpid(), os.getuid() + 1, os.getgid()),
    )
    response = await raw_exchange(
        system_harness.socket_path,
        b'{"schema_version":1,"operation":"status"}\n',
    )
    assert response["error"]["code"] == ErrorCode.PEER_REJECTED.value


@pytest.mark.asyncio
async def test_real_socket_unsupported_adapter_gets_no_capability_or_mutation(system_harness) -> None:
    before = system_harness.server.state
    response = await raw_exchange(
        system_harness.socket_path,
        json.dumps({
            "schema_version": 1,
            "operation": "register",
            "shell_id": "unsupported-shell-id",
            "identity": {
                "boot_id": "11111111-1111-1111-1111-111111111111",
                "pid": 32123,
                "start_time": 456,
            },
            "adapter": "wezterm",
            "cwd": str(system_harness.root),
            "sequence": 0,
        }).encode() + b"\n",
    )
    assert response["error"]["code"] == ErrorCode.INVALID_REQUEST.value
    assert "capability" not in response
    assert system_harness.server.state is before
    assert system_harness.server.state.dirty_generation == 0
    assert system_harness.socket_path.is_socket()


@pytest.mark.asyncio
async def test_capability_identity_sequence_and_cross_shell_authority_fail_closed(
    system_harness,
) -> None:
    first = await system_harness.register_shell(system_harness.root / "first")
    second = await system_harness.register_shell(system_harness.root / "second")
    identity = {
        "boot_id": first.identity.boot_id,
        "pid": first.identity.pid,
        "start_time": first.identity.start_time,
    }

    async def event(capability: str, sequence: int, *, event_identity=identity):
        return await raw_exchange(
            system_harness.socket_path,
            json.dumps({
                "schema_version": 1,
                "operation": "cwd_changed",
                "shell_id": first.id,
                "capability": capability,
                "identity": event_identity,
                "sequence": sequence,
                "cwd": str(system_harness.root),
            }).encode() + b"\n",
        )

    assert (await event("x" * 43, 2))["error"]["code"] == ErrorCode.UNAUTHORIZED.value
    assert (await event(second.bridge.capability, 2))["error"]["code"] == ErrorCode.UNAUTHORIZED.value
    wrong_identity = {**identity, "start_time": first.identity.start_time + 1}
    assert (await event(first.bridge.capability, 2, event_identity=wrong_identity))["error"]["code"] == ErrorCode.UNAUTHORIZED.value
    assert (await event(first.bridge.capability, 1))["error"]["code"] == ErrorCode.SEQUENCE_REJECTED.value
    assert system_harness.socket_path.is_socket()


@pytest.mark.asyncio
async def test_unapproved_hostile_commands_never_reach_adapter_argv_or_logs(
    system_harness, caplog: pytest.LogCaptureFixture
) -> None:
    hostile = "printf '$TOKEN'; touch /tmp/nope; $(id)\nprintf '\\e[31m'"
    shell = await system_harness.register_shell(system_harness.root / "privacy")
    assert not await shell.command_started(1, hostile)
    assert system_harness.server.state.snapshot.shells[0].command is None
    assert system_harness.adapter.actions == []
    assert hostile not in caplog.text


@pytest.mark.asyncio
async def test_secret_forms_absent_from_every_layer_after_failure_retry_and_reopen(
    system_harness, caplog: pytest.LogCaptureFixture
) -> None:
    secrets = (
        "AKIAIOSFODNN7EXAMPLE",
        "postgres://user:password@localhost/db",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "token='termrecall-secret-value'",
        "Authorization: Bearer termrecall-bearer",
        "--password=termrecall-option-secret",
    )
    for index, secret in enumerate(secrets, 1):
        shell = await system_harness.register_shell(system_harness.root / f"secret-{index}")
        assert await shell.command_started(1, f"printf %s {secret}")
        system_harness.mark_process(shell.identity, ProcessStatus.DEAD)
    newline_secret = "termrecall-newline-secret\nsecond-line"
    ansi_secret = "termrecall-ansi-secret\x1b[31m"
    newline_shell = await system_harness.register_shell(system_harness.root / "newline-secret")
    assert not await newline_shell.command_started(1, f"printf {newline_secret}")
    assert not await newline_shell.command_started(2, f"printf {ansi_secret}")
    await system_harness.snapshot()
    response = await system_harness.list_recovery()
    assert not isinstance(response, ErrorResponse), repr(response)
    item_ids = tuple(item.item_id for item in response.items)
    system_harness.adapter.failures.update(item_ids)
    first = await system_harness.restore(response.workspace_id, item_ids, ())
    system_harness.adapter.failures.clear()
    retry = await system_harness.retry(response.workspace_id, first.attempt_id)

    files = tuple(path for path in system_harness.state.iterdir() if path.is_file())
    retained = b"".join(path.read_bytes() for path in files)
    decoded = b"".join(
        repr(snapshot).encode() for snapshot in system_harness.store.list_valid()
    )
    reopened = SnapshotStore(system_harness.state)
    decoded += repr(reopened.load_recovery()).encode()
    reopened.close()
    wire_and_outcomes = (
        repr(response) + repr(first) + repr(retry) + caplog.text
    ).encode()
    adapter_argv = repr(system_harness.adapter.actions).encode()
    for secret in (*secrets, newline_secret, ansi_secret):
        literal = secret.encode()
        assert literal not in retained
        assert literal not in decoded
        assert literal not in wire_and_outcomes
        assert literal not in adapter_argv


@pytest.mark.asyncio
async def test_runtime_socket_replacement_is_not_removed_on_shutdown(
    system_harness,
) -> None:
    original = system_harness.socket_path
    moved = original.with_suffix(".owned")
    original.rename(moved)
    replacement = original
    replacement.write_text("attacker replacement")
    await system_harness.server.close()
    assert replacement.read_text() == "attacker replacement"
    moved.unlink()


def test_xdg_fixture_is_temporary_and_private(xdg_env: dict[str, str], tmp_path: Path) -> None:
    assert all(Path(value).is_relative_to(tmp_path) for value in xdg_env.values())
    assert Path(xdg_env["HOME"]).stat().st_mode & 0o777 == 0o700
