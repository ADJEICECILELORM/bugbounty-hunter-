"""Passive DNS record discovery for authorized hostnames."""

from __future__ import annotations

from typing import TypedDict

import dns.exception
import dns.resolver

from gateway.resolver import authorized_resolve
from gateway.rate_limiter import RateLimiter
from gateway.scope_policy import ScopePolicy


class DNSObservation(TypedDict):
    type: str
    record_type: str
    value: str


def passive_discover(
    hostname: str,
    policy: ScopePolicy,
    rate_limiter: RateLimiter,
) -> list[DNSObservation]:
    """Collect public DNS records after verifying scope and pinning the host."""
    authorized_resolve(hostname, policy)

    observations: list[DNSObservation] = []
    for record_type in ("A", "AAAA", "MX", "TXT"):
        if not rate_limiter.allow():
            break
        try:
            answers = dns.resolver.resolve(hostname, record_type, lifetime=2.0)
        except dns.exception.DNSException:
            continue

        observations.extend(
            {
                "type": "dns_record",
                "record_type": record_type,
                "value": str(answer),
            }
            for answer in answers
        )
    return observations