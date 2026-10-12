"""Make one bounded, authorized HTTP GET request to a pinned address."""

from __future__ import annotations

import hashlib
import math
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.exceptions import ConnectTimeoutError, NewConnectionError
from urllib3.exceptions import TimeoutError as Urllib3TimeoutError
from urllib3.util import connection as urllib3_connection

from gateway import dns_pin
from gateway.dns_pin import IPAddress, PinnedTarget, URLAuthorizer

_SENSITIVE_RESPONSE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "set-cookie",
    "set-cookie2",
    "www-authenticate",
}
_MAX_HEADER_VALUE_LENGTH = 2000
_BODY_READ_SIZE = 64 * 1024


@dataclass(frozen=True)
class ProbeResult:
    url: str
    status_code: int
    headers: dict[str, str]
    response_time_ms: float
    content_length: int
    body_sha256: str


class ProbeTimeoutError(TimeoutError):
    """Raised when the HTTP probe exceeds its connect or read timeout."""


class ProbeConnectionError(ConnectionError):
    """Raised when the HTTP probe cannot complete its request."""


class _PinnedConnectionMixin:
    _pinned_ip: str

    def __init__(self, *args: object, pinned_ip: str, **kwargs: object) -> None:
        self._pinned_ip = pinned_ip
        super().__init__(*args, **kwargs)

    def _new_conn(self):
        connect_timeout = getattr(self.timeout, "connect_timeout", self.timeout)
        try:
            return urllib3_connection.create_connection(
                (self._pinned_ip, self.port),
                connect_timeout,
                source_address=self.source_address,
                socket_options=self.socket_options,
            )
        except TimeoutError as error:
            raise ConnectTimeoutError(
                self,
                f"Connection to {self.host} timed out",
            ) from error
        except OSError as error:
            raise NewConnectionError(
                self,
                f"Failed to connect to pinned address {self._pinned_ip}: {error}",
            ) from error


class _PinnedHTTPConnection(_PinnedConnectionMixin, HTTPConnection):
    pass


class _PinnedHTTPSConnection(_PinnedConnectionMixin, HTTPSConnection):
    pass


class _PinnedHTTPAdapter(HTTPAdapter):
    def __init__(self, target: PinnedTarget, pinned_ip: IPAddress) -> None:
        self._target = target
        self._pinned_ip = str(pinned_ip)
        super().__init__(max_retries=0)

    def get_connection_with_tls_context(
        self,
        request,
        verify,
        proxies=None,
        cert=None,
    ):
        if requests.utils.select_proxy(request.url, proxies):
            raise requests.exceptions.ProxyError("Proxies are disabled for pinned probes")

        pool = super().get_connection_with_tls_context(request, verify, proxies, cert)
        # This adapter and its pool are scoped to one target and one request.
        pool.ConnectionCls = (
            _PinnedHTTPSConnection
            if urlsplit(self._target.url).scheme == "https"
            else _PinnedHTTPConnection
        )
        pool.conn_kw["pinned_ip"] = self._pinned_ip
        return pool


def _is_timeout_error(error: BaseException) -> bool:
    pending: BaseException | None = error
    while pending is not None:
        if isinstance(pending, (TimeoutError, Urllib3TimeoutError)):
            return True
        pending = pending.__cause__ or pending.__context__
    return False


def probe_endpoint(
    url: str,
    *,
    authorize: URLAuthorizer,
    resolver: dns_pin.Resolver | None = None,
    timeout_seconds: float = 5.0,
) -> ProbeResult:
    """Pin and GET once, recording sanitized metadata and a body hash only."""
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be a positive finite number")

    target = dns_pin.pin_url(url, authorize=authorize, resolver=resolver)
    session = requests.Session()
    session.trust_env = False
    session.mount(
        f"{urlsplit(target.url).scheme}://",
        _PinnedHTTPAdapter(target, target.addresses[0]),
    )
    response = None
    started_at = time.perf_counter()
    try:
        response = session.get(
            target.url,
            headers={"Accept-Encoding": "identity", "Connection": "close"},
            allow_redirects=False,
            stream=True,
            timeout=(timeout_seconds, timeout_seconds),
        )
        body_hash = hashlib.sha256()
        content_length = 0
        for chunk in response.iter_content(chunk_size=_BODY_READ_SIZE):
            if not chunk:
                continue
            body_hash.update(chunk)
            content_length += len(chunk)

        response_time_ms = (time.perf_counter() - started_at) * 1000
        headers = {
            name.lower(): str(value)[:_MAX_HEADER_VALUE_LENGTH]
            for name, value in response.headers.items()
            if name.lower() not in _SENSITIVE_RESPONSE_HEADERS
        }
        return ProbeResult(
            url=target.url,
            status_code=response.status_code,
            headers=headers,
            response_time_ms=response_time_ms,
            content_length=content_length,
            body_sha256=body_hash.hexdigest(),
        )
    except requests.Timeout as error:
        raise ProbeTimeoutError("HTTP probe timed out") from error
    except requests.RequestException as error:
        if _is_timeout_error(error):
            raise ProbeTimeoutError("HTTP probe timed out") from error
        raise ProbeConnectionError("HTTP probe connection failed") from error
    finally:
        if response is not None:
            response.close()
        session.close()