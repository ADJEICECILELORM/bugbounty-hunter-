"""Scope-checked entry point for resolving and pinning target hostnames."""

from __future__ import annotations

from urllib.parse import urlsplit

from gateway import dns_pin
from gateway.scope_policy import ScopePolicy


class UnauthorizedTargetError(PermissionError):
    """Raised before resolution when a hostname is outside authorized scope."""


def authorized_resolve(hostname: str, policy: ScopePolicy) -> str:
    """Authorize a hostname, resolve it safely, and return a pinned public IP."""
    if not policy.is_authorized(hostname):
        raise UnauthorizedTargetError(f"Hostname is outside authorized scope: {hostname}")

    target = dns_pin.pin_url(
        f"https://{hostname}/",
        authorize=lambda url: policy.is_authorized(urlsplit(url).hostname or ""),
    )
    return target.addresses[0].compressed