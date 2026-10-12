"""Make one bounded, authorized HTTP GET request to a pinned address."""

from __future__ import annotations

import http.client
import socket
import time
from urllib.parse import urlsplit, urlunsplit

from gateway import dns_pin
from gateway.dns_pin import IPAddress, PinnedTarget, URLAuthorizer

_REQUEST_TIMEOUT_SECONDS = 5.0
_SENSITIVE_RESPONSE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "set-cookie",
    "set-cookie2",
}


class _PinnedConnectionMixin:
    _pinned_ip: str
    port: int

    def _create_pinned_connection(
        self,
        _address: tuple[str, int],
        timeout: float | None,
        source_address: tuple[str, int] | None,
    ) -> socket.socket:
        return socket.create_connection(
            (self._pinned_ip, self.port),
            timeout,
            source_address,
        )


class _PinnedHTTPConnection(_PinnedConnectionMixin, http.client.HTTPConnection):
    def __init__(self, target: PinnedTarget, pinned_ip: IPAddress) -> None:
        self._pinned_ip = str(pinned_ip)
        super().__init__(target.hostname, target.port, timeout=_REQUEST_TIMEOUT_SECONDS)
        self._create_connection = self._create_pinned_connection


class _PinnedHTTPSConnection(_PinnedConnectionMixin, http.client.HTTPSConnection):
    def __init__(self, target: PinnedTarget, pinned_ip: IPAddress) -> None:
        self._pinned_ip = str(pinned_ip)
        super().__init__(target.hostname, target.port, timeout=_REQUEST_TIMEOUT_SECONDS)
        self._create_connection = self._create_pinned_connection


def _connection_for_target(
    target: PinnedTarget,
    pinned_ip: IPAddress,
) -> http.client.HTTPConnection:
    if urlsplit(target.url).scheme == "https":
        return _PinnedHTTPSConnection(target, pinned_ip)
    return _PinnedHTTPConnection(target, pinned_ip)


def _content_length(response: http.client.HTTPResponse) -> int | None:
    value = response.getheader("Content-Length")
    if value is None:
        return None
    try:
        length = int(value)
    except ValueError:
        return None
    return length if length >= 0 else None


def probe_endpoint(url: str, *, authorize: URLAuthorizer) -> dict[str, object]:
    """Pin, GET once, and return status, sanitized headers, time, and length.

    Response bodies are not read and redirects are not followed. The content
    length is the valid ``Content-Length`` declared by the response, if any.
    """
    target = dns_pin.pin_url(url, authorize=authorize)
    connection = _connection_for_target(target, target.addresses[0])
    parsed_url = urlsplit(target.url)
    request_target = urlunsplit(("", "", parsed_url.path or "/", parsed_url.query, ""))

    started_at = time.perf_counter()
    try:
        connection.request("GET", request_target, headers={"Connection": "close"})
        response = connection.getresponse()
        response_time = time.perf_counter() - started_at
        headers = {
            name.lower(): value
            for name, value in response.getheaders()
            if name.lower() not in _SENSITIVE_RESPONSE_HEADERS
        }
        return {
            "status_code": response.status,
            "headers": headers,
            "response_time_seconds": response_time,
            "content_length": _content_length(response),
        }
    finally:
        connection.close()