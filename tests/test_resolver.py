import ipaddress

import pytest

from gateway import dns_pin
from gateway.dns_pin import PinnedTarget
from gateway.resolver import UnauthorizedTargetError, authorized_resolve
from gateway.scope_policy import ScopePolicy


def test_authorized_hostname_returns_pinned_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, object]] = []

    def fake_pin_url(url: str, *, authorize: object) -> PinnedTarget:
        calls.append((url, authorize))
        assert callable(authorize) and authorize("https://api.example.test/")
        return PinnedTarget(
            "https://api.example.test/",
            "api.example.test",
            443,
            (ipaddress.ip_address("93.184.216.34"),),
        )

    monkeypatch.setattr(dns_pin, "pin_url", fake_pin_url)

    result = authorized_resolve(
        "api.example.test",
        ScopePolicy(["*.example.test"]),
    )

    assert result == "93.184.216.34"
    assert calls[0][0] == "https://api.example.test/"


def test_unauthorized_hostname_is_rejected_before_pin_or_dns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(dns_pin, "pin_url", lambda url, **_kwargs: calls.append(url))

    with pytest.raises(UnauthorizedTargetError):
        authorized_resolve(
            "private.example.test",
            ScopePolicy(["*.example.test"], ["private.example.test"]),
        )

    assert calls == []