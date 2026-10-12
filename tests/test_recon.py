import dns.resolver
import pytest

from gateway.resolver import UnauthorizedTargetError
from gateway.rate_limiter import RateLimiter
from gateway.scope_policy import ScopePolicy
from workers import recon


def test_authorized_hostname_returns_passive_dns_observations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authorization_calls: list[str] = []
    dns_calls: list[tuple[str, str]] = []
    expected_records = {
        "A": ["93.184.216.34"],
        "AAAA": ["2001:db8::1"],
        "MX": ["10 mail.example.test."],
        "TXT": ['"v=spf1 -all"'],
    }

    def fake_authorized_resolve(hostname: str, policy: ScopePolicy) -> str:
        authorization_calls.append(hostname)
        assert policy.is_authorized(hostname)
        return "93.184.216.34"

    def fake_resolve(hostname: str, record_type: str, *, lifetime: float) -> list[str]:
        assert hostname == "api.example.test"
        assert lifetime == 2.0
        dns_calls.append((hostname, record_type))
        return expected_records[record_type]

    monkeypatch.setattr(recon, "authorized_resolve", fake_authorized_resolve)
    monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)

    observations = recon.passive_discover(
        "api.example.test",
        ScopePolicy(["*.example.test"]),
        RateLimiter(4),
    )

    assert authorization_calls == ["api.example.test"]
    assert [record_type for _, record_type in dns_calls] == ["A", "AAAA", "MX", "TXT"]
    assert observations == [
        {"type": "dns_record", "record_type": record_type, "value": value}
        for record_type, values in expected_records.items()
        for value in values
    ]


def test_rate_limit_stops_scan_early_with_partial_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dns_calls: list[str] = []
    expected_records = {
        "A": ["93.184.216.34"],
        "AAAA": ["2001:db8::1"],
        "MX": ["10 mail.example.test."],
        "TXT": ['"v=spf1 -all"'],
    }

    def fake_resolve(_hostname: str, record_type: str, **_kwargs: object) -> list[str]:
        dns_calls.append(record_type)
        return expected_records[record_type]

    monkeypatch.setattr(recon, "authorized_resolve", lambda *_args: "93.184.216.34")
    monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)

    observations = recon.passive_discover(
        "api.example.test",
        ScopePolicy(["*.example.test"]),
        RateLimiter(2),
    )

    assert dns_calls == ["A", "AAAA"]
    assert observations == [
        {"type": "dns_record", "record_type": "A", "value": "93.184.216.34"},
        {"type": "dns_record", "record_type": "AAAA", "value": "2001:db8::1"},
    ]


def test_unauthorized_hostname_raises_before_dns_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dns_calls: list[str] = []

    def reject_target(hostname: str, _policy: ScopePolicy) -> str:
        raise UnauthorizedTargetError(hostname)

    monkeypatch.setattr(recon, "authorized_resolve", reject_target)
    monkeypatch.setattr(
        dns.resolver,
        "resolve",
        lambda *_args, **_kwargs: dns_calls.append("called"),
    )

    with pytest.raises(UnauthorizedTargetError):
        recon.passive_discover(
            "outside.test",
            ScopePolicy(["*.example.test"]),
            RateLimiter(4),
        )

    assert dns_calls == []


def test_missing_dns_record_type_does_not_discard_other_answers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_resolve(_hostname: str, record_type: str, **_kwargs: object) -> list[str]:
        if record_type == "AAAA":
            raise dns.resolver.NoAnswer
        return [record_type.lower()]

    monkeypatch.setattr(recon, "authorized_resolve", lambda *_args: "93.184.216.34")
    monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)

    observations = recon.passive_discover(
        "api.example.test",
        ScopePolicy(["*.example.test"]),
        RateLimiter(4),
    )

    assert [item["record_type"] for item in observations] == ["A", "MX", "TXT"]