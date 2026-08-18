# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import argparse
import importlib.resources
import json
import os
import select
import socket
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO

from termrecall.adapters.registry import SUPPORTED_ADAPTERS, detect_adapter
from termrecall.model import ProcessIdentity
from termrecall.protocol import (
    MAX_LOCAL_FRAME_BYTES,
    MAX_MESSAGE_BYTES,
    MAX_RESPONSE_BYTES,
    EventType,
    LocalEvent,
    decode_local_frame,
)

_CONNECT_TIMEOUT = 0.2
_RETRY_DELAYS = (0.05, 0.1, 0.25, 0.5, 1.0)
_DIAGNOSTIC = "termrecall bridge: service unavailable"


class Bridge:
    """Translate unprivileged local shell frames onto an authenticated service stream."""

    def __init__(
        self,
        socket_path: Path,
        shell_id: str,
        identity: ProcessIdentity,
        adapter: str = "gnome-terminal",
    ) -> None:
        self.socket_path = Path(socket_path)
        self.shell_id = shell_id
        self.identity = identity
        self.adapter = adapter
        self.capability: str | None = None
        self.next_sequence = 1
        self.cwd: str | None = None
        self.diagnostic: Callable[[str], None] = lambda message: print(message, file=sys.stderr)
        self._socket: socket.socket | None = None
        self._receive_buffer = bytearray()
        self._retry_index = 0
        self._retry_at = 0.0

    @property
    def identity_dict(self) -> dict[str, object]:
        return {
            "boot_id": self.identity.boot_id,
            "pid": self.identity.pid,
            "start_time": self.identity.start_time,
        }

    def close(self) -> None:
        if self._socket is not None:
            self._socket.close()
            self._socket = None
        self._receive_buffer.clear()
        self.capability = None
        # Do NOT reset next_sequence here: the last-acknowledged sequence is
        # preserved so already-accepted events are not replayed after a
        # transient disconnect. The authoritative resume point comes from the
        # server's register response on the next _register().

    def _fail(self) -> None:
        self.close()
        self.diagnostic(_DIAGNOSTIC)
        delay = _RETRY_DELAYS[min(self._retry_index, len(_RETRY_DELAYS) - 1)]
        self._retry_index = min(self._retry_index + 1, len(_RETRY_DELAYS) - 1)
        self._retry_at = time.monotonic() + delay

    def _connect(self) -> None:
        if self._socket is not None:
            return
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(_CONNECT_TIMEOUT)
        try:
            connection.connect(str(self.socket_path))
        except BaseException:
            connection.close()
            raise
        self._socket = connection

    def _exchange(self, request: dict[str, object]) -> dict[str, object]:
        self._connect()
        assert self._socket is not None
        raw = json.dumps(request, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"
        if len(raw) > MAX_MESSAGE_BYTES:
            raise ValueError("request too large")
        self._socket.sendall(raw)
        while b"\n" not in self._receive_buffer:
            chunk = self._socket.recv(MAX_RESPONSE_BYTES + 1 - len(self._receive_buffer))
            if not chunk:
                raise EOFError("service closed")
            self._receive_buffer.extend(chunk)
            if len(self._receive_buffer) > MAX_RESPONSE_BYTES:
                raise ValueError("response too large")
        line, _, remainder = self._receive_buffer.partition(b"\n")
        self._receive_buffer[:] = remainder
        payload = json.loads(line)
        if not isinstance(payload, dict):
            raise ValueError("response must be an object")
        return payload

    def _register(self) -> None:
        if self.cwd is None:
            raise ValueError("registration requires cwd")
        response = self._exchange({
            "schema_version": 1,
            "operation": "register",
            "shell_id": self.shell_id,
            "identity": self.identity_dict,
            "adapter": self.adapter,
            "cwd": self.cwd,
            "sequence": 0,
        })
        if set(response) != {"schema_version", "ok", "response", "capability", "resume_sequence"}:
            raise ValueError("invalid register response")
        capability = response.get("capability")
        if (
            response.get("schema_version") != 1
            or response.get("ok") is not True
            or response.get("response") != "register"
            or not isinstance(capability, str)
            or not 32 <= len(capability) <= 128
        ):
            raise ValueError("invalid register response")
        self.capability = capability
        # Resume from the server's persisted sequence watermark so events
        # already accepted before the disconnect are not replayed (finding #11).
        resume_sequence = response.get("resume_sequence", 0)
        if not isinstance(resume_sequence, int) or resume_sequence < 0:
            resume_sequence = 0
        self.next_sequence = resume_sequence + 1
        self._retry_index = 0
        self._retry_at = 0.0

    def _event_request(self, event: LocalEvent) -> dict[str, object]:
        assert self.capability is not None
        request: dict[str, object] = {
            "schema_version": 1,
            "operation": event.event_type.value,
            "shell_id": self.shell_id,
            "capability": self.capability,
            "identity": self.identity_dict,
            "sequence": self.next_sequence,
        }
        if event.event_type in (EventType.PROMPT_READY, EventType.CWD_CHANGED):
            request["cwd"] = event.cwd
        elif event.event_type is EventType.COMMAND_STARTED:
            request.update(command_sequence=event.command_sequence, command=event.command)
        elif event.event_type is EventType.COMMAND_FINISHED:
            request.update(command_sequence=event.command_sequence, exit_status=event.exit_status)
        return request

    def process_frame(self, raw: bytes) -> bool:
        try:
            event = decode_local_frame(raw)
        except (ValueError, TypeError, UnicodeError):
            return False
        if event.shell_id != self.shell_id:
            return False
        if event.cwd is not None:
            self.cwd = event.cwd
        if self.cwd is None or time.monotonic() < self._retry_at:
            return False
        try:
            if self.capability is None:
                self._register()
            response = self._exchange(self._event_request(event))
            expected = self.next_sequence
            if response != {
                "schema_version": 1,
                "ok": True,
                "response": "event",
                "sequence": expected,
            }:
                raise ValueError("invalid event response")
            self.next_sequence += 1
            return True
        except (OSError, EOFError, TimeoutError, ValueError, json.JSONDecodeError):
            self._fail()
            return False

    @staticmethod
    def _discard_to_newline(stream: BinaryIO) -> bool:
        while True:
            chunk = stream.readline(MAX_LOCAL_FRAME_BYTES + 1)
            if not chunk:
                return False
            if chunk.endswith(b"\n"):
                return True

    def run(self, stream: BinaryIO = sys.stdin.buffer) -> None:
        try:
            while True:
                raw = stream.readline(MAX_LOCAL_FRAME_BYTES + 1)
                if not raw:
                    break
                if len(raw) <= MAX_LOCAL_FRAME_BYTES and raw.endswith(b"\n"):
                    self.process_frame(raw)
                    continue
                if raw.endswith(b"\n"):
                    continue
                if not self._discard_to_newline(stream):
                    break
        finally:
            self.close()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="termrecall-bridge", allow_abbrev=False)
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--shell-id", required=True)
    parser.add_argument("--boot-id", required=True)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--start-time", type=int, required=True)
    parser.add_argument(
        "--adapter",
        choices=sorted(SUPPORTED_ADAPTERS),
        default=None,
        help="terminal adapter name; auto-detected when omitted",
    )
    return parser


def bridge_main() -> None:
    args = _parser().parse_args()
    adapter = args.adapter or detect_adapter() or "gnome-terminal"
    Bridge(
        args.socket,
        args.shell_id,
        ProcessIdentity(args.boot_id, args.pid, args.start_time),
        adapter=adapter,
    ).run()


def nonblock_helper_main() -> None:
    helper = importlib.resources.files("termrecall").joinpath(
        "libexec", "termrecall-nonblock"
    )
    with importlib.resources.as_file(helper) as path:
        os.execv(path, ["termrecall-nonblock", *sys.argv[1:]])


if __name__ == "__main__":
    bridge_main()
