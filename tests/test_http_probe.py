import hashlib
import ipaddress
from typing import Any

import pytest
import requests

from gateway import dns_pin
from gateway.dns_pin import PinnedTarget, TargetRejected
from verification import http_probe
from verification.http_probe import ProbeConnectionError, ProbeResult, ProbeTimeoutError

_RESPONSE_BODY = b"probe response"
_LONG_HEADER_VALUE = "x" * 2001


class FakeResponse:
    status_code = 202
    headers = {
        "Content-Length": str(len(_RESPONSE_BODY)),
        "X-Probe": "visible",
        "Set-Cookie": "session=secret",
        "Authorization": "Bearer secret",
        "Proxy-Authorization": "Basic secret",
        "WWW-Authenticate": 'Basic realm="private"',
        "X-Large": _LONG_HEADER_VALUE,
    }

    def __init__(self) -> None:
        self.closed = False

    def iter_content(self, chunk_size: int):
        assert chunk_size == 64 * 1024
        yield _RESPONSE_BODY

    def close(self) -> None:
        self.closed = True


class FakeSession:
    def __init__(self, response: FakeResponse | None = None, error: Exception | None = None):
        self.trust_env = True
        self.response = response
        self.error = error
        self.adapters: dict[str, Any] = {}
        self.get_calls: list[tuple[str, dict[str, Any]]] = []
        self.closed = False

    def mount(self, prefix: str, adapter: Any) -> None:
        self.adapters[prefix] = adapter

    def get(self, url: str, **kwargs: Any) -> FakeResponse:
        self.get_calls.append((url, kwargs))
        if self.error is not None:
            raise self.error
        assert self.response is not None
        return self.response

    def close(self) -> None:
        self.closed = True


def test_successful_probe_hashes_body_and_sanitizes_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = PinnedTarget(
        "https://example.test/path?q=1",
        "example.test",
        443,
        (ipaddress.ip_address("93.184.216.34"),),
    )
    resolver = lambda _hostname, _port: ["93.184.216.34"]
    authorizer = lambda _url: True
    pin_calls: list[tuple[str, object, object]] = []
    response = FakeResponse()
    session = FakeSession(response=response)

    def fake_pin_url(url: str, *, authorize: object, resolver: object) -> PinnedTarget:
        pin_calls.append((url, authorize, resolver))
        return target

    monkeypatch.setattr(dns_pin, "pin_url", fake_pin_url)
    monkeypatch.setattr(http_probe.requests, "Session", lambda: session)

    result = http_probe.probe_endpoint(
        target.url,
        authorize=authorizer,
        resolver=resolver,
        timeout_seconds=1.25,
    )

    assert isinstance(result, ProbeResult)
    assert pin_calls == [(target.url, authorizer, resolver)]
    assert session.trust_env is False
    assert list(session.adapters) == ["https://"]
    adapter = session.adapters["https://"]
    assert isinstance(adapter, http_probe._PinnedHTTPAdapter)
    assert adapter._pinned_ip == "93.184.216.34"
    assert adapter.max_retries.total == 0
    assert len(session.get_calls) == 1
    request_url, request_kwargs = session.get_calls[0]
    assert request_url == target.url
    assert request_kwargs["allow_redirects"] is False
    assert request_kwargs["stream"] is True
    assert request_kwargs["timeout"] == (1.25, 1.25)
    assert result.url == target.url
    assert result.status_code == 202
    assert result.content_length == len(_RESPONSE_BODY)
    assert result.body_sha256 == hashlib.sha256(_RESPONSE_BODY).hexdigest()
    assert not hasattr(result, "body")
    assert result.response_time_ms >= 0
    assert result.headers["x-probe"] == "visible"
    assert result.headers["x-large"] == _LONG_HEADER_VALUE[:2000]
    assert not {
        "set-cookie",
        "authorization",
        "proxy-authorization",
        "www-authenticate",
    } & result.headers.keys()
    assert response.closed
    assert session.closed


def test_adapter_connects_to_pinned_ip_but_keeps_hostname_for_tls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = PinnedTarget(
        "https://example.test/",
        "example.test",
        443,
        (ipaddress.ip_address("93.184.216.34"),),
    )
    socket_calls: list[tuple[str, int]] = []
    fake_socket = object()

    def fake_create_connection(address: tuple[str, int], *_args: Any, **_kwargs: Any) -> object:
        socket_calls.append(address)
        return fake_socket

    monkeypatch.setattr(
        http_probe.urllib3_connection,
        "create_connection",
        fake_create_connection,
    )
    adapter = http_probe._PinnedHTTPAdapter(target, target.addresses[0])
    prepared_request = requests.Request("GET", target.url).prepare()
    pool = adapter.get_connection_with_tls_context(prepared_request, verify=True, proxies={})
    connection = pool._new_conn()
    connection._new_conn()

    assert socket_calls == [("93.184.216.34", 443)]
    assert connection.host == "example.test"
    assert connection._pinned_ip == "93.184.216.34"
    assert pool.ConnectionCls is http_probe._PinnedHTTPSConnection
    adapter.close()


def test_out_of_scope_url_is_rejected_before_any_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_creations: list[bool] = []
    resolver_calls: list[tuple[str, int]] = []

    def resolver(hostname: str, port: int) -> list[str]:
        resolver_calls.append((hostname, port))
        return ["93.184.216.34"]

    monkeypatch.setattr(
        http_probe.requests,
        "Session",
        lambda: session_creations.append(True),
    )

    with pytest.raises(TargetRejected, match="outside authorized scope"):
        http_probe.probe_endpoint(
            "https://outside.example/path",
            authorize=lambda _: False,
            resolver=resolver,
        )

    assert resolver_calls == []
    assert session_creations == []


def test_timeout_is_wrapped_and_chained(monkeypatch: pytest.MonkeyPatch) -> None:
    target = PinnedTarget(
        "https://example.test/",
        "example.test",
        443,
        (ipaddress.ip_address("93.184.216.34"),),
    )
    timeout = requests.Timeout("read timed out")
    session = FakeSession(error=timeout)
    monkeypatch.setattr(dns_pin, "pin_url", lambda *_args, **_kwargs: target)
    monkeypatch.setattr(http_probe.requests, "Session", lambda: session)

    with pytest.raises(ProbeTimeoutError) as error:
        http_probe.probe_endpoint(target.url, authorize=lambda _: True)

    assert error.value.__cause__ is timeout
    assert session.closed


def test_wrapped_read_timeout_is_reported_as_probe_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = PinnedTarget(
        "https://example.test/",
        "example.test",
        443,
        (ipaddress.ip_address("93.184.216.34"),),
    )
    read_timeout = TimeoutError("read timed out")
    request_error = requests.ConnectionError(read_timeout)
    request_error.__cause__ = read_timeout
    session = FakeSession(error=request_error)
    monkeypatch.setattr(dns_pin, "pin_url", lambda *_args, **_kwargs: target)
    monkeypatch.setattr(http_probe.requests, "Session", lambda: session)

    with pytest.raises(ProbeTimeoutError) as error:
        http_probe.probe_endpoint(target.url, authorize=lambda _: True)

    assert error.value.__cause__ is request_error
    assert session.closed


def test_connection_failure_is_wrapped_and_chained(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = PinnedTarget(
        "https://example.test/",
        "example.test",
        443,
        (ipaddress.ip_address("93.184.216.34"),),
    )
    failure = requests.ConnectionError("connection reset")
    session = FakeSession(error=failure)
    monkeypatch.setattr(dns_pin, "pin_url", lambda *_args, **_kwargs: target)
    monkeypatch.setattr(http_probe.requests, "Session", lambda: session)

    with pytest.raises(ProbeConnectionError) as error:
        http_probe.probe_endpoint(target.url, authorize=lambda _: True)

    assert error.value.__cause__ is failure
    assert session.closed