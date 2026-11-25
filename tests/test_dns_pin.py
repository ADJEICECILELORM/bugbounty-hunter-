import ipaddress
import socket

import pytest

from gateway.dns_pin import TargetRejected, is_public_unicast, pin_url, validate_redirect


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


@pytest.mark.parametrize(
    "answers",
    [
        ["127.0.0.1"],  # IPv4 loopback
        ["::1"],  # IPv6 loopback
        ["::ffff:127.0.0.1"],  # IPv4-mapped loopback
        ["fe80::1%eth0"],  # scoped link-local
        ["169.254.169.254"],  # cloud metadata
        ["100.64.0.1"],  # carrier-grade NAT
        ["0.0.0.0"],
        ["224.0.0.1"],  # IPv4 multicast
        ["239.255.255.250"],  # IPv4 multicast (SSDP)
        ["ff02::1"],  # IPv6 multicast
        ["2001:20::1"],  # ORCHIDv2 (non-routable)
        ["93.184.216.34", "::1"],  # one private answer rejects the whole target
        ["93.184.216.34", "224.0.0.1"],  # one multicast answer rejects the target
        ["2606:2800:220:1:248:1893:25c8:1946", "ff02::1"],  # mixed public + IPv6 multicast
    ],
)
def test_pin_url_rejects_every_non_public_answer(answers: list[str]) -> None:
    with pytest.raises(TargetRejected, match="non-public"):
        pin_url(
            "https://example.com",
            authorize=lambda _: True,
            resolver=lambda _host, _port, answers=answers: answers,
        )


def test_pin_url_accepts_a_public_ipv6_answer() -> None:
    target = pin_url(
        "https://example.com",
        authorize=lambda _: True,
        resolver=lambda _host, _port: ["2606:2800:220:1:248:1893:25c8:1946"],
    )

    assert target.addresses == (
        ipaddress.ip_address("2606:2800:220:1:248:1893:25c8:1946"),
    )


@pytest.mark.parametrize("answers", [[], ["not-an-ip"]])
def test_pin_url_rejects_unusable_resolver_answers(answers: list[str]) -> None:
    with pytest.raises(TargetRejected):
        pin_url(
            "https://example.com",
            authorize=lambda _: True,
            resolver=lambda _host, _port, answers=answers: answers,
        )
@pytest.mark.parametrize(
    "address",
    [
        "224.0.0.1",  # IPv4 multicast
        "239.255.255.250",  # IPv4 multicast (SSDP)
        "ff02::1",  # IPv6 multicast
        "2001:20::1",  # ORCHIDv2 (non-routable)
        "0.0.0.0",  # IPv4 unspecified
        "::",  # IPv6 unspecified
        "::1",  # IPv6 loopback
        "127.0.0.1",  # IPv4 loopback
        "10.0.0.1",  # IPv4 private
        "192.168.1.1",  # IPv4 private
        "169.254.169.254",  # IPv4 link-local / cloud metadata
        "fe80::1",  # IPv6 link-local
        "fc00::1",  # IPv6 unique-local
        "240.0.0.1",  # IPv4 reserved
        "::ffff:127.0.0.1",  # IPv4-mapped loopback
        "::ffff:10.0.0.1",  # IPv4-mapped private
    ],
)
def test_is_public_unicast_rejects_special_purpose_addresses(address: str) -> None:
    assert not is_public_unicast(ipaddress.ip_address(address))


@pytest.mark.parametrize(
    "address",
    [
        "93.184.216.34",  # public IPv4
        "8.8.8.8",  # public IPv4
        "2606:2800:220:1:248:1893:25c8:1946",  # public IPv6
    ],
)
def test_is_public_unicast_accepts_public_addresses(address: str) -> None:
    assert is_public_unicast(ipaddress.ip_address(address))


@pytest.mark.parametrize(
    "error",
    [
        OSError("resolver temporarily unavailable"),
        socket.gaierror(socket.EAI_NONAME, "no address associated with hostname"),
    ],
)
def test_pin_url_fails_closed_when_the_resolver_raises(error: Exception) -> None:
    def resolver(_host: str, _port: int) -> list[str]:
        raise error

    with pytest.raises(TargetRejected, match="could not be safely resolved"):
        pin_url(
            "https://example.com",
            authorize=lambda _: True,
            resolver=resolver,
        )





def test_pin_url_authorizes_before_it_resolves() -> None:
    resolver_calls: list[str] = []

    with pytest.raises(TargetRejected, match="outside authorized scope"):
        pin_url(
            "https://outside.example/",
            authorize=lambda _: False,
            resolver=lambda host, _port: (
                resolver_calls.append(host) or ["93.184.216.34"]
            ),
        )

    assert resolver_calls == []


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.com\\@good.com/",
        "https://example.com\\@evil.com/",
        "https://user@example.com/",
        "https://exa%20mple.com/",
        "https://example.com:70000/",
        "https:///nohost",
        "gopher://example.com/",
    ],
)
def test_pin_url_rejects_authority_confusion_forms(url: str) -> None:
    with pytest.raises(TargetRejected):
        pin_url(url, authorize=lambda _: True)


def test_url_fragment_cannot_change_the_pinned_host() -> None:
    seen: list[str] = []

    def authorize(url: str) -> bool:
        seen.append(url)
        return True

    target = pin_url(
        "https://example.com#@evil.com/",
        authorize=authorize,
        resolver=lambda _host, _port: ["93.184.216.34"],
    )

    assert target.hostname == "example.com"
    assert target.url == "https://example.com/"
    assert seen == ["https://example.com/"]


def test_pin_url_does_not_canonicalize_the_default_port() -> None:
    """Pin a documented, fail-closed property of the authorize() input.

    An explicit default port is preserved, so an exact-URL allowlist that only
    lists the port-less form rejects it instead of silently widening scope.
    """
    seen: list[str] = []

    def authorize(url: str) -> bool:
        seen.append(url)
        return url.startswith("https://example.com/")

    with pytest.raises(TargetRejected, match="outside authorized scope"):
        pin_url(
            "https://example.com:443/",
            authorize=authorize,
            resolver=lambda _host, _port: ["93.184.216.34"],
        )

    assert seen == ["https://example.com:443/"]


def test_protocol_relative_redirect_is_reauthorized_against_its_own_host() -> None:
    resolver_calls: list[str] = []

    with pytest.raises(TargetRejected, match="outside authorized scope"):
        validate_redirect(
            "https://example.com/start",
            "//outside.example/next",
            authorize=lambda url: url.startswith("https://example.com/"),
            resolver=lambda host, _port: (
                resolver_calls.append(host) or ["93.184.216.34"]
            ),
        )

    assert resolver_calls == []