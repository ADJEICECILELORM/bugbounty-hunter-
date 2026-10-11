"""Hostname authorization policy for explicitly scoped programs."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable


def _canonical_hostname(hostname: str) -> str:
    if not isinstance(hostname, str) or not hostname or hostname != hostname.strip():
        raise ValueError("Hostname must be a non-empty string without surrounding whitespace")
    if "%" in hostname:
        raise ValueError("Scoped IP addresses are not permitted")

    try:
        return ipaddress.ip_address(hostname).compressed
    except ValueError:
        try:
            canonical = hostname.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError as error:
            raise ValueError("Invalid hostname") from error

    if not canonical or len(canonical) > 253:
        raise ValueError("Invalid hostname")
    labels = canonical.split(".")
    if any(
        not label
        or len(label) > 63
        or not label[0].isalnum()
        or not label[-1].isalnum()
        or any(not (character.isalnum() or character == "-") for character in label)
        for label in labels
    ):
        raise ValueError("Invalid hostname")
    return canonical


def _canonical_pattern(pattern: str) -> str:
    if not isinstance(pattern, str):
        raise ValueError("Scope entries must be strings")
    if pattern.startswith("*."):
        return f"*.{_canonical_hostname(pattern[2:])}"
    if "*" in pattern:
        raise ValueError("Wildcards are only permitted as a leading '*.'")
    return _canonical_hostname(pattern)


def _matches(hostname: str, pattern: str) -> bool:
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return hostname.endswith(suffix) and hostname != suffix[1:]
    return hostname == pattern


class ScopePolicy:
    """Authorize exact hostnames and explicit wildcard subdomain patterns."""

    def __init__(
        self,
        authorized_scope: Iterable[str],
        excluded_scope: Iterable[str] = (),
    ) -> None:
        self.authorized_scope = tuple(_canonical_pattern(entry) for entry in authorized_scope)
        self.excluded_scope = tuple(_canonical_pattern(entry) for entry in excluded_scope)

    def is_authorized(self, hostname: str) -> bool:
        try:
            canonical = _canonical_hostname(hostname)
        except ValueError:
            return False

        if any(_matches(canonical, pattern) for pattern in self.excluded_scope):
            return False
        return any(_matches(canonical, pattern) for pattern in self.authorized_scope)