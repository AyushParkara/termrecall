# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import io
import json
import socket
import threading
from pathlib import Path

import pytest

from termrecall.bridge import Bridge
from termrecall.protocol import MAX_LOCAL_FRAME_BYTES
from termrecall.model import ProcessIdentity

SHELL_ID = "shell-aaaaaaaaaaa"
IDENTITY = ProcessIdentity("3f2504e0-4f89-41d3-9a0c-0305e82c3301", 4242, 123456)
CAPABILITY_A = "a" * 43
CAPABILITY_B = "b" * 43


class RecordingBridge(Bridge):
    def __init__(self, replies: list[dict[str, object] | BaseException]) -> None:
        super().__init__(Path("/unused/service.sock"), SHELL_ID, IDENTITY)
        self.replies = replies
        self.service_requests: list[dict[str, object]] = []

    def _exchange(self, request: dict[str, object]) -> dict[str, object]:
        self.service_requests.append(request)
        reply = self.replies.pop(0)
        if isinstance(reply, BaseException):
            raise reply
        return reply


def local(event_type: str, **fields: object) -> bytes:
    return (json.dumps({"schema_version": 1, "type": event_type, "shell_id": SHELL_ID, **fields}, separators=(",", ":")) + "\n").encode()


def register_reply(capability: str) -> dict[str, object]:
    return {"schema_version": 1, "ok": True, "response": "register", "capability": capability}


def event_reply(sequence: int) -> dict[str, object]:
    return {"schema_version": 1, "ok": True, "response": "event", "sequence": sequence}


def test_bridge_injects_authority_not_present_in_local_frame() -> None:
    bridge = RecordingBridge([register_reply(CAPABILITY_A), event_reply(1)])

    assert bridge.process_frame(local("prompt_ready", cwd="/srv/app"))

    register, event = bridge.service_requests
    assert register == {
        "schema_version": 1,
        "operation": "register",
        "shell_id": SHELL_ID,
        "identity": {"boot_id": IDENTITY.boot_id, "pid": IDENTITY.pid, "start_time": IDENTITY.start_time},
        "adapter": "gnome-terminal",
        "cwd": "/srv/app",
        "sequence": 0,
    }
    assert event == {
        "schema_version": 1,
        "operation": "prompt_ready",
        "shell_id": SHELL_ID,
        "capability": CAPABILITY_A,
        "identity": register["identity"],
        "sequence": 1,
        "cwd": "/srv/app",
    }
    assert bridge.next_sequence == 2


@pytest.mark.parametrize("field,value", [("capability", CAPABILITY_A), ("identity", {}), ("sequence", 9)])
def test_bridge_rejects_local_authority_fields(field: str, value: object) -> None:
    bridge = RecordingBridge([])
    payload = json.loads(local("prompt_ready", cwd="/srv/app"))
    payload[field] = value

    assert not bridge.process_frame((json.dumps(payload) + "\n").encode())
    assert bridge.service_requests == []


def test_bridge_reregisters_with_new_authority_after_service_restart() -> None:
    bridge = RecordingBridge([
        register_reply(CAPABILITY_A),
        event_reply(1),
        ConnectionResetError(),
        register_reply(CAPABILITY_B),
        event_reply(1),
    ])
    assert bridge.process_frame(local("prompt_ready", cwd="/one"))
    assert not bridge.process_frame(local("command_started", command_sequence=1, command="sleep 1"))
    assert bridge.capability is None
    assert bridge.next_sequence == 1
    bridge._retry_at = 0.0

    assert bridge.process_frame(local("cwd_changed", cwd="/two"))

    second_register = bridge.service_requests[3]
    second_event = bridge.service_requests[4]
    assert second_register["cwd"] == "/two"
    assert second_register["sequence"] == 0
    assert second_event["capability"] == CAPABILITY_B
    assert second_event["sequence"] == 1


def test_bridge_rejects_malformed_or_mismatched_service_responses() -> None:
    bridge = RecordingBridge([{"schema_version": 1, "ok": True, "response": "event", "sequence": 0}])
    assert not bridge.process_frame(local("prompt_ready", cwd="/srv/app"))
    assert bridge.capability is None

    bridge = RecordingBridge([register_reply(CAPABILITY_A), {"schema_version": 1, "ok": True, "response": "event", "sequence": 2}])
    assert not bridge.process_frame(local("prompt_ready", cwd="/srv/app"))
    assert bridge.capability is None
    assert bridge.next_sequence == 1


def test_bridge_diagnostics_are_fixed_and_command_free() -> None:
    diagnostics: list[str] = []
    bridge = RecordingBridge([ConnectionRefusedError("secret-command --token=x")])
    bridge.diagnostic = diagnostics.append

    assert not bridge.process_frame(local("prompt_ready", cwd="/srv/app"))
    assert diagnostics == ["termrecall bridge: service unavailable"]
    assert "secret-command" not in diagnostics[0]


class BoundedStream:
    def __init__(self, raw: bytes) -> None:
        self.stream = io.BytesIO(raw)
        self.readline_sizes: list[int] = []
        self.read_sizes: list[int] = []

    def readline(self, size: int = -1) -> bytes:
        self.readline_sizes.append(size)
        return self.stream.readline(size)

    def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        return self.stream.read(size)


def test_bridge_discards_oversized_terminated_frame_then_processes_valid_frame() -> None:
    bridge = RecordingBridge([register_reply(CAPABILITY_A), event_reply(1)])
    stream = BoundedStream(b"x" * (MAX_LOCAL_FRAME_BYTES * 3) + b"\n" + local("prompt_ready", cwd="/valid"))

    bridge.run(stream)  # type: ignore[arg-type]

    assert len(bridge.service_requests) == 2
    assert bridge.service_requests[0]["cwd"] == "/valid"
    assert stream.readline_sizes and set(stream.readline_sizes) == {MAX_LOCAL_FRAME_BYTES + 1}
    assert stream.read_sizes == []


def test_bridge_discards_oversized_unterminated_eof_with_bounded_reads() -> None:
    bridge = RecordingBridge([])
    stream = BoundedStream(b"x" * (MAX_LOCAL_FRAME_BYTES * 20))

    bridge.run(stream)  # type: ignore[arg-type]

    assert bridge.service_requests == []
    assert len(stream.readline_sizes) > 1
    assert set(stream.readline_sizes) == {MAX_LOCAL_FRAME_BYTES + 1}
    assert stream.read_sizes == []


def test_bridge_real_socket_reconnects_after_malformed_reply_and_uses_new_capability(
    tmp_path: Path,
) -> None:
    socket_path = tmp_path / "service.sock"
    requests: list[dict[str, object]] = []
    ready = threading.Event()

    def service() -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(socket_path))
            listener.listen(1)
            ready.set()
            for connection_index in range(2):
                connection, _ = listener.accept()
                with connection, connection.makefile("rwb", buffering=0) as stream:
                    register = json.loads(stream.readline())
                    requests.append(register)
                    capability = CAPABILITY_A if connection_index == 0 else CAPABILITY_B
                    stream.write((json.dumps(register_reply(capability)) + "\n").encode())
                    event = json.loads(stream.readline())
                    requests.append(event)
                    if connection_index == 0:
                        stream.write(b"{malformed}\n")
                    else:
                        stream.write((json.dumps(event_reply(1)) + "\n").encode())

    thread = threading.Thread(target=service)
    thread.start()
    assert ready.wait(1)
    bridge = Bridge(socket_path, SHELL_ID, IDENTITY)
    bridge.diagnostic = lambda message: None

    assert not bridge.process_frame(local("prompt_ready", cwd="/one"))
    bridge._retry_at = 0.0
    assert bridge.process_frame(local("cwd_changed", cwd="/two"))
    bridge.close()
    thread.join(1)

    assert not thread.is_alive()
    assert requests[2]["operation"] == "register"
    assert requests[2]["cwd"] == "/two"
    assert requests[3]["capability"] == CAPABILITY_B
    assert requests[3]["sequence"] == 1
