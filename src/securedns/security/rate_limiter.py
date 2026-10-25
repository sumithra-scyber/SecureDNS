"""Per-client sliding-window rate limiter using token bucket algorithm."""
from __future__ import annotations

import time


class TokenBucketRateLimiter:
    """Token bucket rate limiter.

    Each client gets a virtual bucket that refills at ``rate`` tokens/second
    up to a maximum of ``burst`` tokens.  Every query consumes 1 token.
    When the bucket is empty the query is denied (rate-limited).

    This implementation is designed for single-threaded asyncio use.
    """

    def __init__(self, rate: float, burst: int) -> None:
        self.rate = rate    # tokens refilled per second
        self.burst = burst  # maximum bucket size (burst allowance)
        # _buckets[client_ip] = (tokens_remaining: float, last_refill_time: float)
        self._buckets: dict[str, tuple[float, float]] = {}

    # ------------------------------------------------------------------
    # Core decision
    # ------------------------------------------------------------------

    def is_allowed(self, client_ip: str) -> bool:
        """Return True if the query is allowed, False if rate-limited."""
        now = time.monotonic()
        tokens, last_time = self._buckets.get(client_ip, (float(self.burst), now))

        # Refill tokens proportional to elapsed time
        elapsed = now - last_time
        tokens = min(float(self.burst), tokens + elapsed * self.rate)

        if tokens >= 1.0:
            self._buckets[client_ip] = (tokens - 1.0, now)
            return True
        else:
            self._buckets[client_ip] = (tokens, now)
            return False

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def get_rate(self, client_ip: str) -> float:
        """Return the approximate current token fill level (not query rate).

        Returns the number of tokens available divided by the burst size,
        expressed as a fraction 0.0–1.0.  Callers can use this as a proxy
        for how busy a client is relative to its allowed rate.
        """
        now = time.monotonic()
        if client_ip not in self._buckets:
            return float(self.burst)
        tokens, last_time = self._buckets[client_ip]
        elapsed = now - last_time
        return min(float(self.burst), tokens + elapsed * self.rate)

    # ------------------------------------------------------------------
    # Housekeeping
    # ------------------------------------------------------------------

    def cleanup_stale(self, max_age_seconds: float = 300.0) -> int:
        """Remove entries for clients not seen in the last *max_age_seconds*.

        Returns the number of entries removed.
        """
        now = time.monotonic()
        stale_keys = [
            ip
            for ip, (_, last_time) in self._buckets.items()
            if (now - last_time) > max_age_seconds
        ]
        for key in stale_keys:
            del self._buckets[key]
        return len(stale_keys)
