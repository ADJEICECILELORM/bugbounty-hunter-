import pytest

from gateway import rate_limiter
from gateway.rate_limiter import RateLimiter


def test_requests_under_limit_are_allowed() -> None:
    limiter = RateLimiter(requests_per_minute=2)

    assert limiter.allow()
    assert limiter.allow()


def test_requests_over_limit_are_rejected() -> None:
    limiter = RateLimiter(requests_per_minute=2)

    assert limiter.allow()
    assert limiter.allow()
    assert not limiter.allow()


def test_limit_resets_after_sliding_window(monkeypatch: pytest.MonkeyPatch) -> None:
    now = [100.0]
    monkeypatch.setattr(rate_limiter.time, "monotonic", lambda: now[0])
    limiter = RateLimiter(requests_per_minute=1)

    assert limiter.allow()
    now[0] = 159.9
    assert not limiter.allow()
    now[0] = 160.0
    assert limiter.allow()


@pytest.mark.parametrize("limit", [0, -1, True, 1.5])
def test_invalid_limit_is_rejected(limit: int) -> None:
    with pytest.raises(ValueError, match="positive integer"):
        RateLimiter(limit)