# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import socket
import threading
from contextlib import contextmanager
from pathlib import Path

import pytest

from termrecall.client import ServiceClient, ServiceUnavailable
from termrecall.protocol import MAX_RESPONSE_BYTES, StatusRequest, StatusResponse, encode_response


@contextmanager
def unix_server(path: Path, response: bytes | None, delayed_extra: bytes = b""):
    ready = threading.Event()

    def serve() -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(path))
            listener.listen(1)
            ready.set()
            connection, _ = listener.accept()
            with connection:
                connection.recv(16_385)
                if response is None:
                    threading.Event().wait(0.2)
                else:
                    connection.sendall(response)
                    if delayed_extra:
                        threading.Event().wait(0.01)
                        connection.sendall(delayed_extra)

    thread = threading.Thread(target=serve)
    thread.start()
    ready.wait(1)
    try:
        yield path
    finally:
        thread.join(1)


def valid_response() -> bytes:
    return encode_response(StatusResponse(True, 0, 0, 0, False, False, None, 0, ()))


def test_missing_socket_reports_service_unavailable(tmp_path: Path) -> None:
    client = ServiceClient(tmp_path / "missing.sock", timeout=0.01)
    with pytest.raises(ServiceUnavailable, match="not available"):
        client.request(StatusRequest())


def test_response_is_bounded_by_timeout(tmp_path: Path) -> None:
    with unix_server(tmp_path / "service.sock", None) as path:
        with pytest.raises(ServiceUnavailable, match="timed out"):
            ServiceClient(path, timeout=0.01).request(StatusRequest())


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (valid_response().rstrip(b"\n"), "before newline"),
        (b"x" * (MAX_RESPONSE_BYTES + 1), "too large"),
        (valid_response() + b"x", "extra bytes"),
        (b"{}\n", "malformed"),
    ],
)
def test_rejects_malformed_or_unframed_response(
    tmp_path: Path, response: bytes, message: str
) -> None:
    with unix_server(tmp_path / "service.sock", response) as path:
        with pytest.raises(ServiceUnavailable, match=message):
            ServiceClient(path, timeout=0.2).request(StatusRequest())


def test_rejects_extra_bytes_arriving_after_newline(tmp_path: Path) -> None:
    with unix_server(tmp_path / "service.sock", valid_response(), b"x") as path:
        with pytest.raises(ServiceUnavailable, match="extra bytes"):
            ServiceClient(path, timeout=0.2).request(StatusRequest())


def test_exact_codec_round_trip(tmp_path: Path) -> None:
    expected = StatusResponse(True, 2, 4, 4, False, False, None, 1, ())
    with unix_server(tmp_path / "service.sock", encode_response(expected)) as path:
        assert ServiceClient(path).request(StatusRequest()) == expected
