import ipaddress

import pytest

from gateway.dns_pin import TargetRejected, pin_url, validate_redirect


def test_pin_url_authorizes_and_returns_resolved_addresses() -> None:
    authorized_urls: list[str] = []
    resolver_calls: list[tuple[str, int]] = []

    def authorize(url: str) -> bool:
        authorized_urls.append(url)
        return url.startswith("https://example.com/")

    def resolver(hostname: str, port: int) -> list[str]:
        resolver_calls.append((hostname, port))
        return ["93.184.216.34", "93.184.216.35"]

    target = pin_url(
        "HTTPS://Example.COM/path#fragment",
        authorize=authorize,
        resolver=resolver,
    )

    assert target.url == "https://example.com/path"
    assert target.hostname == "example.com"
    assert target.port == 443
    assert target.addresses == (
        ipaddress.ip_address("93.184.216.34"),
        ipaddress.ip_address("93.184.216.35"),
    )
    assert authorized_urls == [target.url]
    assert resolver_calls == [("example.com", 443)]


def test_pin_url_rejects_any_non_public_dns_answer() -> None:
    with pytest.raises(TargetRejected, match="non-public"):
        pin_url(
            "https://example.com",
            authorize=lambda _: True,
            resolver=lambda _host, _port: ["93.184.216.34", "127.0.0.1"],
        )


def test_redirect_is_resolved_and_reauthorized() -> None:
    checked_urls: list[str] = []

    def authorize(url: str) -> bool:
        checked_urls.append(url)
        return url.startswith("https://example.com/")

    target = validate_redirect(
        "https://example.com/start",
        "/next",
        authorize=authorize,
        resolver=lambda _host, _port: ["93.184.216.34"],
    )

    assert target.url == "https://example.com/next"
    assert checked_urls == [target.url]


def test_redirect_outside_scope_is_rejected_before_resolution() -> None:
    resolver_calls: list[str] = []

    with pytest.raises(TargetRejected, match="outside authorized scope"):
        validate_redirect(
            "https://example.com/start",
            "https://outside.example/next",
            authorize=lambda url: url.startswith("https://example.com/"),
            resolver=lambda host, _port: resolver_calls.append(host) or ["93.184.216.34"],
        )

    assert resolver_calls == []


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "https://user:password@example.com/",
        "https://example.com:0/",
        "https://example.com:99999/",
    ],
)
def test_pin_url_rejects_unsafe_url_forms(url: str) -> None:
    with pytest.raises(TargetRejected):
        pin_url(url, authorize=lambda _: True)