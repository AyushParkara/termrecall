# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import socket
from pathlib import Path

from termrecall.protocol import (
    MAX_RESPONSE_BYTES,
    ServiceRequest,
    ServiceResponse,
    decode_response,
    encode_request,
)


class ServiceUnavailable(RuntimeError):
    """The local service could not return one valid bounded response."""


class ServiceClient:
    def __init__(self, socket_path: Path, timeout: float = 1.0) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.socket_path = Path(socket_path)
        self.timeout = timeout

    def request(self, request: ServiceRequest) -> ServiceResponse:
        payload = encode_request(request)
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self.timeout)
                connection.connect(str(self.socket_path))
                connection.sendall(payload)
                raw = self._receive_response(connection)
        except (TimeoutError, socket.timeout) as exc:
            raise ServiceUnavailable("service request timed out") from exc
        except (FileNotFoundError, ConnectionRefusedError, ConnectionResetError, BrokenPipeError, OSError) as exc:
            raise ServiceUnavailable("service is not available") from exc
        try:
            return decode_response(raw)
        except (UnicodeError, ValueError, TypeError) as exc:
            raise ServiceUnavailable("service returned a malformed response") from exc

    @staticmethod
    def _receive_response(connection: socket.socket) -> bytes:
        raw = bytearray()
        while b"\n" not in raw and len(raw) <= MAX_RESPONSE_BYTES:
            chunk = connection.recv(MAX_RESPONSE_BYTES + 1 - len(raw))
            if not chunk:
                raise ServiceUnavailable("service response ended before newline")
            raw.extend(chunk)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ServiceUnavailable("service response is too large")
        newline = raw.find(b"\n")
        if newline < 0:
            raise ServiceUnavailable("service response ended before newline")
        if newline != len(raw) - 1:
            raise ServiceUnavailable("service response contains extra bytes")
        if connection.recv(1):
            raise ServiceUnavailable("service response contains extra bytes")
        return bytes(raw)
