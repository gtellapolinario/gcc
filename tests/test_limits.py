from __future__ import annotations

from gcc_mcp.limits import RateLimiter


class _FakeClock:
    def __init__(self) -> None:
        self.current = 0.0

    def now(self) -> float:
        return self.current

    def advance(self, seconds: float) -> None:
        self.current += seconds


def test_rate_limiter_disabled_allows_unlimited_calls() -> None:
    limiter = RateLimiter(limit_per_minute=0)
    for _ in range(100):
        allowed, retry_after = limiter.allow()
        assert allowed is True
        assert retry_after == 0


def test_rate_limiter_enforces_window_and_retry_after() -> None:
    clock = _FakeClock()
    limiter = RateLimiter(limit_per_minute=2, now_fn=clock.now)

    assert limiter.allow() == (True, 0)
    assert limiter.allow() == (True, 0)

    allowed, retry_after = limiter.allow()
    assert allowed is False
    assert retry_after == 60

    clock.advance(59)
    allowed, retry_after = limiter.allow()
    assert allowed is False
    assert retry_after == 1

    clock.advance(1)
    assert limiter.allow() == (True, 0)


def test_rate_limiter_configure_resets_existing_window() -> None:
    clock = _FakeClock()
    limiter = RateLimiter(limit_per_minute=1, now_fn=clock.now)
    assert limiter.allow() == (True, 0)
    assert limiter.allow()[0] is False

    limiter.configure(2)
    assert limiter.allow() == (True, 0)
    assert limiter.allow() == (True, 0)
