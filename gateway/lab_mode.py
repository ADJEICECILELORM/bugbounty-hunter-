"""Explicitly opted-in URL pinning for manually invoked local lab targets.

This module is intentionally not used by normal workers or verification flows.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from gateway.dns_pin import (
    IPAddress,
    PinnedTarget,
    Resolver,
    TargetRejected,
    URLAuthorizer,
    _parse_url,
    _system_resolver,
)


class LabModeNotExplicitlyEnabled(Exception):
    """Raised unless a caller explicitly opts into private-network targets."""


@dataclass(frozen=True)
class LabPinnedTarget(PinnedTarget):
    """A pinned target whose origin is explicitly marked as a lab run."""

    is_lab_target: bool = True


def pin_lab_url(
    url: str,
    *,
    allow_private_network: bool,
    authorize: URLAuthorizer,
    resolver: Resolver | None = None,
) -> LabPinnedTarget:
    """Authorize and pin a manually selected lab URL, including private IPs."""
    if allow_private_network is not True:
        raise LabModeNotExplicitlyEnabled(
            "Pass allow_private_network=True to explicitly enable lab mode"
        )

    normalized_url, hostname, port = _parse_url(url)
    if not authorize(normalized_url):
        raise TargetRejected("URL is outside authorized scope")

    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            resolver_function = resolver if resolver is not None else _system_resolver
            resolved = resolver_function(hostname, port)
            addresses = tuple(
                dict.fromkeys(ipaddress.ip_address(item) for item in resolved)
            )
        except (OSError, ValueError) as error:
            raise TargetRejected("Hostname could not be safely resolved") from error
    else:
        addresses = (literal,)

    if not addresses:
        raise TargetRejected("Hostname resolved to no addresses")

    return LabPinnedTarget(normalized_url, hostname, port, addresses)