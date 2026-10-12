"""Make one bounded, authorized HTTP GET request to a pinned address."""

from __future__ import annotations

import hashlib
import math
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.exceptions import ConnectTimeoutError, HTTPError as Urllib3HTTPError
from urllib3.exceptions import NewConnectionError
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
_MAX_BODY_BYTES = 1024 * 1024


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


class ProbeResponseTooLargeError(ValueError):
    """Raised when a response exceeds the probe's evidence size limit."""


class _RequestDeadline:
    def __init__(self, timeout_seconds: float) -> None:
        self._lock = threading.Lock()
        self._expired = False
        self._connections: set[HTTPConnection] = set()
        self._timer = threading.Timer(timeout_seconds, self._expire)
        self._timer.daemon = True

    @property
    def expired(self) -> bool:
        with self._lock:
            return self._expired

    @property
    def remaining_seconds(self) -> float:
        return self._timer.interval - (time.monotonic() - self._started_at)

    def start(self) -> None:
        self._started_at = time.monotonic()
        self._timer.start()

    def register(self, connection: HTTPConnection, sock: object) -> None:
        with self._lock:
            if self._expired:
                sock.close()
                raise TimeoutError("HTTP probe deadline expired")
            connection.sock = sock
            self._connections.add(connection)

    def _expire(self) -> None:
        with self._lock:
            self._expired = True
            sockets = [connection.sock for connection in self._connections]
        for sock in sockets:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    def cancel(self) -> None:
        self._timer.cancel()


class _PinnedConnectionMixin:
    _pinned_ip: str
    _request_deadline: _RequestDeadline

    def __init__(
        self,
        *args: object,
        pinned_ip: str,
        request_deadline: _RequestDeadline,
        **kwargs: object,
    ) -> None:
        self._pinned_ip = pinned_ip
        self._request_deadline = request_deadline
        super().__init__(*args, **kwargs)

    def _new_conn(self):
        connect_timeout = getattr(self.timeout, "connect_timeout", self.timeout)
        remaining = self._request_deadline.remaining_seconds
        if remaining <= 0:
            raise ConnectTimeoutError(self, "HTTP probe deadline expired")
        if connect_timeout is None or connect_timeout > remaining:
            connect_timeout = remaining
        try:
            sock = urllib3_connection.create_connection(
                (self._pinned_ip, self.port),
                connect_timeout,
                source_address=self.source_address,
                socket_options=self.socket_options,
            )
            self._request_deadline.register(self, sock)
            return sock
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
    def __init__(
        self,
        target: PinnedTarget,
        pinned_ip: IPAddress,
        request_deadline: _RequestDeadline,
    ) -> None:
        self._target = target
        self._pinned_ip = str(pinned_ip)
        self._request_deadline = request_deadline
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
        pool.conn_kw["request_deadline"] = self._request_deadline
        return pool


def _is_timeout_error(error: BaseException) -> bool:
    pending: BaseException | None = error
    while pending is not None:
        if isinstance(pending, (TimeoutError, Urllib3TimeoutError)):
            return True
        pending = pending.__cause__ or pending.__context__
    return False


def _validate_timeout(timeout_seconds: float) -> None:
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be a positive finite number")


def _probe_pinned_target(
    target: PinnedTarget,
    *,
    timeout_seconds: float,
    extra_headers: dict[str, str] | None,
) -> ProbeResult:
    """Send one request using an already-authorized and pinned target."""
    _validate_timeout(timeout_seconds)
    request_headers = {"Accept-Encoding": "identity", "Connection": "close"}
    for name, value in (extra_headers or {}).items():
        if name.lower() == "host":
            raise ValueError("The Host header is controlled by the pinned target")
        for existing_name in tuple(request_headers):
            if existing_name.lower() == name.lower():
                del request_headers[existing_name]
        request_headers[name] = value

    request_deadline = _RequestDeadline(timeout_seconds)
    session = requests.Session()
    session.trust_env = False
    session.mount(
        f"{urlsplit(target.url).scheme}://",
        _PinnedHTTPAdapter(target, target.addresses[0], request_deadline),
    )
    response = None
    started_at = time.perf_counter()
    request_deadline.start()
    try:
        response = session.get(
            target.url,
            headers=request_headers,
            allow_redirects=False,
            stream=True,
            timeout=(timeout_seconds, timeout_seconds),
        )
        body_hash = hashlib.sha256()
        content_length = 0
        for chunk in response.raw.stream(
            _BODY_READ_SIZE,
            decode_content=False,
        ):
            if not chunk:
                continue
            if content_length + len(chunk) > _MAX_BODY_BYTES:
                raise ProbeResponseTooLargeError(
                    f"HTTP response exceeds {_MAX_BODY_BYTES} bytes"
                )
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
    except (requests.RequestException, Urllib3HTTPError, OSError) as error:
        if request_deadline.expired or _is_timeout_error(error):
            raise ProbeTimeoutError("HTTP probe timed out") from error
        raise ProbeConnectionError("HTTP probe connection failed") from error
    finally:
        request_deadline.cancel()
        if response is not None:
            response.close()
        session.close()


def probe_endpoint(
    url: str,
    *,
    authorize: URLAuthorizer,
    resolver: dns_pin.Resolver | None = None,
    timeout_seconds: float = 5.0,
    extra_headers: dict[str, str] | None = None,
) -> ProbeResult:
    """Authorize, pin, and GET once through the normal public-target gateway."""
    _validate_timeout(timeout_seconds)
    target = dns_pin.pin_url(url, authorize=authorize, resolver=resolver)
    return _probe_pinned_target(
        target,
        timeout_seconds=timeout_seconds,
        extra_headers=extra_headers,
    )