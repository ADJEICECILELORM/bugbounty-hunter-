"""Resolve authorized HTTP targets into validated, pinned IP addresses."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit, urlunsplit

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Resolver = Callable[[str, int], Iterable[str | IPAddress]]
URLAuthorizer = Callable[[str], bool]


class TargetRejected(ValueError):
    """Raised when a URL or one of its resolved addresses is not permitted."""


@dataclass(frozen=True)
class PinnedTarget:
    """A validated URL and the exact addresses its transport must connect to.

    The HTTP Host header and TLS server name must remain ``hostname``; only
    the socket destination should use one of ``addresses``.

    ``is_lab_target`` marks a target produced by the explicit, manually invoked
    lab-only escape hatch. Public targets are never lab-marked, so a lab-only
    transport can refuse a target that did not come from that escape hatch.
    """

    url: str
    hostname: str
    port: int
    addresses: tuple[IPAddress, ...]
    is_lab_target: bool = False


def _system_resolver(hostname: str, port: int) -> Iterable[str]:
    return (
        result[4][0]
        for result in socket.getaddrinfo(
            hostname, port, type=socket.SOCK_STREAM
        )
    )


def _canonical_hostname(hostname: str) -> str:
    if "%" in hostname:
        raise TargetRejected("Scoped IP addresses are not permitted")
    try:
        return ipaddress.ip_address(hostname).compressed
    except ValueError:
        try:
            canonical = hostname.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError as error:
            raise TargetRejected("Invalid hostname") from error
        if not canonical or len(canonical) > 253:
            raise TargetRejected("Invalid hostname")
        return canonical


def _parse_url(url: str) -> tuple[str, str, int]:
    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            raise TargetRejected("Only HTTP and HTTPS URLs are permitted")
        if parsed.username is not None or parsed.password is not None:
            raise TargetRejected("URL credentials are not permitted")
        if parsed.hostname is None:
            raise TargetRejected("URL must include a hostname")
        hostname = _canonical_hostname(parsed.hostname)
        explicit_port = parsed.port
        port = explicit_port if explicit_port is not None else (443 if scheme == "https" else 80)
    except ValueError as error:
        if isinstance(error, TargetRejected):
            raise
        raise TargetRejected("Invalid URL or port") from error

    if not 1 <= port <= 65535:
        raise TargetRejected("Port must be between 1 and 65535")

    authority_host = f"[{hostname}]" if ":" in hostname else hostname
    authority = authority_host
    if parsed.port is not None:
        authority = f"{authority}:{port}"
    normalized_url = urlunsplit(
        (scheme, authority, parsed.path or "/", parsed.query, "")
    )
    return normalized_url, hostname, port


def pin_url(
    url: str,
    *,
    authorize: URLAuthorizer,
    resolver: Resolver | None = None,
) -> PinnedTarget:
    """Authorize a URL and resolve it to public IPs for a pinned connection.

    Every returned address must be used as the network destination. Do not
    pass ``url`` to a client that resolves the hostname again on its own.
    """
    normalized_url, hostname, port = _parse_url(url)
    if not authorize(normalized_url):
        raise TargetRejected("URL is outside authorized scope")

    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            resolver_function = resolver if resolver is not None else _system_resolver
            resolved = resolver_function(hostname, port)
            addresses = tuple(dict.fromkeys(ipaddress.ip_address(item) for item in resolved))
        except (OSError, ValueError) as error:
            raise TargetRejected("Hostname could not be safely resolved") from error
    else:
        addresses = (literal,)

    if not addresses:
        raise TargetRejected("Hostname resolved to no addresses")
    if any(not address.is_global for address in addresses):
        raise TargetRejected("Hostname resolved to a non-public address")

    return PinnedTarget(normalized_url, hostname, port, addresses)


def validate_redirect(
    current_url: str,
    location: str,
    *,
    authorize: URLAuthorizer,
    resolver: Resolver = _system_resolver,
) -> PinnedTarget:
    """Resolve and authorize one redirect before the client follows it."""
    return pin_url(
        urljoin(current_url, location),
        authorize=authorize,
        resolver=resolver,
    )