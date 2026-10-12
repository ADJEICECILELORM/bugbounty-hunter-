import io
import ipaddress

import pytest

from gateway import dns_pin
from gateway.dns_pin import PinnedTarget, TargetRejected
from verification import http_probe


class FakeSocket:
    def __init__(self) -> None:
        self.sent = bytearray()
        self.closed = False

    def setsockopt(self, *_args: object) -> None:
        pass

    def sendall(self, data: bytes) -> None:
        self.sent.extend(data)

    def makefile(self, mode: str) -> io.BytesIO:
        assert mode == "rb"
        return io.BytesIO(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Length: 4\r\n"
            b"X-Probe: visible\r\n"
            b"Set-Cookie: session=secret\r\n"
            b"Authorization: Bearer secret\r\n"
            b"sEt-CoOkIe: other=secret\r\n\r\nbody"
        )

    def close(self) -> None:
        self.closed = True


class FakeTLSContext:
    def __init__(self, server_names: list[str]) -> None:
        self.server_names = server_names

    def wrap_socket(self, sock: FakeSocket, *, server_hostname: str) -> FakeSocket:
        self.server_names.append(server_hostname)
        return sock


def test_successful_probe_connects_to_pinned_ip_and_sanitizes_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = PinnedTarget(
        "https://example.test/path?q=1",
        "example.test",
        443,
        (ipaddress.ip_address("93.184.216.34"),),
    )
    socket_addresses: list[tuple[str, int]] = []
    server_names: list[str] = []
    fake_socket = FakeSocket()
    fake_context = FakeTLSContext(server_names)

    def fake_pin_url(url: str, *, authorize: object) -> PinnedTarget:
        assert url == target.url
        assert callable(authorize) and authorize(url)
        return target

    def fake_create_connection(
        address: tuple[str, int],
        _timeout: float | None,
        _source_address: tuple[str, int] | None,
    ) -> FakeSocket:
        socket_addresses.append(address)
        return fake_socket

    monkeypatch.setattr(dns_pin, "pin_url", fake_pin_url)
    monkeypatch.setattr(http_probe.socket, "create_connection", fake_create_connection)
    monkeypatch.setattr(
        http_probe.http.client,
        "_create_https_context",
        lambda _http_version: fake_context,
    )

    result = http_probe.probe_endpoint(target.url, authorize=lambda _: True)

    assert socket_addresses == [("93.184.216.34", 443)]
    assert server_names == ["example.test"]
    assert b"GET /path?q=1 HTTP/1.1" in fake_socket.sent
    assert b"Host: example.test" in fake_socket.sent
    assert b"93.184.216.34" not in fake_socket.sent
    assert result["status_code"] == 200
    assert result["headers"] == {
        "content-length": "4",
        "x-probe": "visible",
    }
    assert result["content_length"] == 4
    assert isinstance(result["response_time_seconds"], float)
    assert result["response_time_seconds"] >= 0
    assert fake_socket.closed


def test_out_of_scope_url_is_rejected_before_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection_attempts: list[tuple[str, int]] = []
    monkeypatch.setattr(
        http_probe.socket,
        "create_connection",
        lambda address, *_args: connection_attempts.append(address),
    )

    with pytest.raises(TargetRejected, match="outside authorized scope"):
        http_probe.probe_endpoint(
            "https://outside.example/path",
            authorize=lambda _: False,
        )

    assert connection_attempts == []