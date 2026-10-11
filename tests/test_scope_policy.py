import pytest

from gateway.scope_policy import ScopePolicy


def test_exact_hostname_is_authorized() -> None:
    policy = ScopePolicy(["Example.Test"])

    assert policy.is_authorized("example.test")
    assert not policy.is_authorized("sub.example.test")


def test_wildcard_authorizes_subdomains_but_not_apex() -> None:
    policy = ScopePolicy(["*.example.test"])

    assert policy.is_authorized("api.example.test")
    assert policy.is_authorized("deep.api.example.test")
    assert not policy.is_authorized("example.test")
    assert not policy.is_authorized("notexample.test")


def test_excluded_subdomain_overrides_authorized_wildcard() -> None:
    policy = ScopePolicy(
        authorized_scope=["*.example.test"],
        excluded_scope=["private.example.test"],
    )

    assert policy.is_authorized("public.example.test")
    assert not policy.is_authorized("private.example.test")


def test_unlisted_hostname_is_unauthorized() -> None:
    policy = ScopePolicy(["example.test"])

    assert not policy.is_authorized("outside.test")


@pytest.mark.parametrize("hostname", ["", " example.test", "bad..example.test", "example.test%eth0"])
def test_invalid_hostname_fails_closed(hostname: str) -> None:
    assert not ScopePolicy(["*.example.test"]).is_authorized(hostname)


def test_invalid_scope_wildcard_is_rejected() -> None:
    with pytest.raises(ValueError, match="Wildcards"):
        ScopePolicy(["api.*.example.test"])