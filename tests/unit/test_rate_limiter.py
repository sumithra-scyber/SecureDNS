"""Unit tests for TokenBucketRateLimiter."""
from __future__ import annotations

import time
import pytest

from securedns.security.rate_limiter import TokenBucketRateLimiter


def test_first_query_allowed():
    """A fresh client's first query should always be allowed."""
    rl = TokenBucketRateLimiter(rate=10, burst=10)
    assert rl.is_allowed("192.168.1.1") is True


def test_burst_is_respected():
    """After exhausting the burst allowance, subsequent queries are denied."""
    burst = 5
    rl = TokenBucketRateLimiter(rate=10, burst=burst)
    client = "10.0.0.1"

    # Consume entire burst
    for i in range(burst):
        result = rl.is_allowed(client)
        assert result is True, f"Query {i + 1} should be allowed (within burst)"

    # Next query should be denied
    assert rl.is_allowed(client) is False


def test_refill_over_time(monkeypatch):
    """Tokens refill at the configured rate as time advances."""
    base = 1_000_000.0  # arbitrary monotonic base
    current_time = [base]
    monkeypatch.setattr(
        "securedns.security.rate_limiter.time.monotonic",
        lambda: current_time[0],
    )

    rl = TokenBucketRateLimiter(rate=5, burst=5)
    client = "172.16.0.1"

    # Drain the bucket completely
    for _ in range(5):
        rl.is_allowed(client)
    assert rl.is_allowed(client) is False  # empty

    # Advance time by 1 second -> 5 tokens refilled (rate=5)
    current_time[0] = base + 1.0
    # Should allow up to 5 again
    assert rl.is_allowed(client) is True


def test_different_clients_independent():
    """Rate limits for different client IPs must not affect each other."""
    rl = TokenBucketRateLimiter(rate=10, burst=2)

    # Drain client A
    rl.is_allowed("client_a")
    rl.is_allowed("client_a")
    assert rl.is_allowed("client_a") is False

    # Client B should still be at full burst
    assert rl.is_allowed("client_b") is True
    assert rl.is_allowed("client_b") is True
