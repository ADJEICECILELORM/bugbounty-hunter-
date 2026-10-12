"""Deterministically compare two independently authorized HTTP probes."""

from __future__ import annotations

from dataclasses import dataclass

from gateway.dns_pin import Resolver, URLAuthorizer
from verification.http_probe import ProbeResult, probe_endpoint


@dataclass(frozen=True)
class DiffResult:
    url_a: str
    url_b: str
    status_match: bool
    status_a: int
    status_b: int
    body_match: bool
    content_length_delta: int
    header_differences: dict[str, tuple[str | None, str | None]]
    probe_a: ProbeResult
    probe_b: ProbeResult


def _casefold_headers(headers: dict[str, str]) -> dict[str, str]:
    return {name.lower(): value for name, value in headers.items()}


def compare_requests(
    url_a: str,
    url_b: str,
    *,
    authorize: URLAuthorizer,
    extra_headers_a: dict[str, str] | None = None,
    extra_headers_b: dict[str, str] | None = None,
    resolver: Resolver | None = None,
    timeout_seconds: float = 5.0,
) -> DiffResult:
    """Run two independent probes and return only deterministic differences."""
    probe_a = probe_endpoint(
        url_a,
        authorize=authorize,
        resolver=resolver,
        timeout_seconds=timeout_seconds,
        extra_headers=extra_headers_a,
    )
    probe_b = probe_endpoint(
        url_b,
        authorize=authorize,
        resolver=resolver,
        timeout_seconds=timeout_seconds,
        extra_headers=extra_headers_b,
    )

    headers_a = _casefold_headers(probe_a.headers)
    headers_b = _casefold_headers(probe_b.headers)
    header_differences = {
        name: (headers_a.get(name), headers_b.get(name))
        for name in sorted(headers_a.keys() | headers_b.keys())
        if headers_a.get(name) != headers_b.get(name)
    }

    return DiffResult(
        url_a=url_a,
        url_b=url_b,
        status_match=probe_a.status_code == probe_b.status_code,
        status_a=probe_a.status_code,
        status_b=probe_b.status_code,
        body_match=probe_a.body_sha256 == probe_b.body_sha256,
        content_length_delta=abs(probe_a.content_length - probe_b.content_length),
        header_differences=header_differences,
        probe_a=probe_a,
        probe_b=probe_b,
    )