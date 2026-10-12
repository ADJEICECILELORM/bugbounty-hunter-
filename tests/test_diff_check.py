from dataclasses import FrozenInstanceError

import pytest

from gateway.dns_pin import TargetRejected
from verification import diff_check
from verification.http_probe import ProbeResult


def make_probe(
    *,
    url: str = "https://example.test/resource",
    status: int = 200,
    length: int = 4,
    body_hash: str = "same-hash",
    headers: dict[str, str] | None = None,
) -> ProbeResult:
    return ProbeResult(
        url=url,
        status_code=status,
        headers={} if headers is None else headers,
        response_time_ms=1.5,
        content_length=length,
        body_sha256=body_hash,
    )


def patch_probe_results(monkeypatch: pytest.MonkeyPatch, *results: ProbeResult) -> None:
    result_iter = iter(results)
    monkeypatch.setattr(diff_check, "probe_endpoint", lambda *_args, **_kwargs: next(result_iter))


def test_identical_responses_have_no_differences(monkeypatch: pytest.MonkeyPatch) -> None:
    probe = make_probe(headers={"content-type": "application/json"})
    patch_probe_results(monkeypatch, probe, probe)

    result = diff_check.compare_requests(
        "https://example.test/a",
        "https://example.test/b",
        authorize=lambda _: True,
    )

    assert result.url_a == "https://example.test/a"
    assert result.url_b == "https://example.test/b"
    assert result.status_match
    assert result.body_match
    assert result.content_length_delta == 0
    assert result.header_differences == {}


def test_different_status_codes_are_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_probe_results(monkeypatch, make_probe(status=200), make_probe(status=403))

    result = diff_check.compare_requests("https://example.test/a", "https://example.test/b", authorize=lambda _: True)

    assert not result.status_match
    assert result.status_a == 200
    assert result.status_b == 403


def test_different_bodies_with_same_status_are_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_probe_results(
        monkeypatch,
        make_probe(body_hash="hash-a", length=3),
        make_probe(body_hash="hash-b", length=9),
    )

    result = diff_check.compare_requests(
        "https://example.test/a",
        "https://example.test/b",
        authorize=lambda _: True,
    )

    assert result.status_match
    assert not result.body_match
    assert result.content_length_delta == 6


def test_header_differences_include_changed_and_missing_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    patch_probe_results(
        monkeypatch,
        make_probe(
            headers={
                "content-type": "application/json",
                "x-changed": "a",
                "x-only-a": "left",
            }
        ),
        make_probe(
            headers={
                "content-type": "application/json",
                "x-changed": "b",
                "x-only-b": "right",
            }
        ),
    )

    result = diff_check.compare_requests(
        "https://example.test/a",
        "https://example.test/b",
        authorize=lambda _: True,
    )

    assert result.header_differences == {
        "x-changed": ("a", "b"),
        "x-only-a": ("left", None),
        "x-only-b": (None, "right"),
    }


def test_distinct_extra_headers_are_passed_only_to_their_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe_calls: list[tuple[str, dict[str, str] | None, object]] = []
    authorizer = lambda _: True

    def fake_probe(
        url: str,
        *,
        authorize: object,
        resolver: object,
        timeout_seconds: float,
        extra_headers: dict[str, str] | None,
    ) -> ProbeResult:
        probe_calls.append((url, extra_headers, authorize))
        return make_probe(url=url, headers={"content-type": "application/json"})

    monkeypatch.setattr(diff_check, "probe_endpoint", fake_probe)
    secret_a = "Bearer account-a-secret"
    secret_b = "Bearer account-b-secret"
    result = diff_check.compare_requests(
        "https://example.test/resource",
        "https://example.test/resource",
        authorize=authorizer,
        extra_headers_a={"Authorization": secret_a},
        extra_headers_b={"Authorization": secret_b},
    )

    assert probe_calls == [
        ("https://example.test/resource", {"Authorization": secret_a}, authorizer),
        ("https://example.test/resource", {"Authorization": secret_b}, authorizer),
    ]
    assert not hasattr(result, "extra_headers_a")
    assert not hasattr(result, "extra_headers_b")
    assert secret_a not in repr(result)
    assert secret_b not in repr(result)


def test_probe_failure_propagates_without_partial_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def fail_on_second_probe(*_args: object, **_kwargs: object) -> ProbeResult:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise TargetRejected("second target rejected")
        return make_probe()

    monkeypatch.setattr(diff_check, "probe_endpoint", fail_on_second_probe)

    with pytest.raises(TargetRejected, match="second target rejected"):
        diff_check.compare_requests(
            "https://example.test/a",
            "https://outside.example/b",
            authorize=lambda _: True,
        )

    assert calls == 2


def test_diff_result_is_frozen(monkeypatch: pytest.MonkeyPatch) -> None:
    probe = make_probe()
    patch_probe_results(monkeypatch, probe, probe)

    result = diff_check.compare_requests("https://example.test/a", "https://example.test/b", authorize=lambda _: True)

    with pytest.raises(FrozenInstanceError):
        result.status_match = False  # type: ignore[misc]