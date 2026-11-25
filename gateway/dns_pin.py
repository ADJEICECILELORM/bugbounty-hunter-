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

_ORCHIDV2_NETWORK = ipaddress.ip_network("2001:20::/28")


def is_public_unicast(address: IPAddress) -> bool:
    """Return whether ``address`` is a globally routable, non-special unicast IP.

    ``ipaddress``'s ``is_global`` alone is insufficient on Python 3.14: it
    returns ``True`` for IPv4/IPv6 multicast (224.0.0.0/4 and ff00::/8) and for
    the non-routable ORCHIDv2 range (2001:20::/28). This predicate layers the
    explicit special-address checks on top of ``is_global`` so the public-target
    policy rejects every special-purpose or non-unicast answer while continuing
    to accept ordinary public IPv4 and IPv6 unicast addresses.

    It deliberately does not define lab policy: private, loopback, and
    link-local addresses are rejected here, and lab mode remains a separate,
    explicitly authorized path (:func:`gateway.lab_mode.pin_lab_url`).
    """
    if address.is_multicast:
        return False
    if address.is_unspecified:
        return False
    if address.is_reserved:
        return False
    if address.is_private:
        return False
    if address.is_loopback:
        return False
    if address.is_link_local:
        return False
    if isinstance(address, ipaddress.IPv6Address):
        mapped = address.ipv4_mapped
        if mapped is not None:
            return is_public_unicast(mapped)
        if address in _ORCHIDV2_NETWORK:
            return False
    return bool(address.is_global)


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
    if any(not is_public_unicast(address) for address in addresses):
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