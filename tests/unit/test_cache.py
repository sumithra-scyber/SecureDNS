"""Unit tests for TTLCache."""
from __future__ import annotations

import time
import pytest

from securedns.cache.ttl_cache import TTLCache


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FAKE_RESPONSE = b"\x00\x01\x81\x80" + b"\x00" * 20  # 24-byte fake DNS response


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

async def test_cache_miss_on_empty():
    """Getting from an empty cache returns None."""
    cache = TTLCache(capacity=100)
    result = cache.get(("example.com.", "A"))
    assert result is None


async def test_cache_store_and_retrieve():
    """Stored values are retrievable before TTL expires."""
    cache = TTLCache(capacity=100)
    key = ("example.com.", "A")
    cache.put(key, FAKE_RESPONSE, ttl_seconds=60)
    result = cache.get(key)
    assert result == FAKE_RESPONSE


async def test_cache_ttl_expiration(monkeypatch):
    """Entries are considered expired once their TTL has elapsed."""
    cache = TTLCache(capacity=100)
    key = ("expire.com.", "A")

    # Freeze monotonic clock at t=0
    base_time = time.monotonic()
    monkeypatch.setattr("securedns.cache.ttl_cache.time.monotonic", lambda: base_time)

    cache.put(key, FAKE_RESPONSE, ttl_seconds=10)
    assert cache.get(key) == FAKE_RESPONSE

    # Advance clock past TTL
    monkeypatch.setattr("securedns.cache.ttl_cache.time.monotonic", lambda: base_time + 11)
    result = cache.get(key)
    assert result is None


async def test_cache_lru_eviction():
    """When at capacity, the least-recently-used entry is evicted."""
    cache = TTLCache(capacity=2)
    key_a = ("a.com.", "A")
    key_b = ("b.com.", "A")
    key_c = ("c.com.", "A")

    cache.put(key_a, b"resp_a", ttl_seconds=60)
    cache.put(key_b, b"resp_b", ttl_seconds=60)

    # Access key_a to make key_b the LRU
    cache.get(key_a)

    # Adding key_c should evict key_b (LRU)
    cache.put(key_c, b"resp_c", ttl_seconds=60)

    assert cache.get(key_a) == b"resp_a"
    assert cache.get(key_c) == b"resp_c"
    assert cache.get(key_b) is None  # evicted


async def test_cache_zero_ttl_not_stored():
    """Entries with TTL=0 must never be stored (uncacheable responses)."""
    cache = TTLCache(capacity=100)
    key = ("nocache.com.", "A")
    cache.put(key, FAKE_RESPONSE, ttl_seconds=0)
    assert cache.get(key) is None


async def test_cache_stats_tracking():
    """Cache statistics (hits, misses, evictions) are tracked correctly."""
    cache = TTLCache(capacity=2)
    key_a = ("a.com.", "A")
    key_b = ("b.com.", "A")
    key_c = ("c.com.", "A")

    cache.put(key_a, b"resp_a", ttl_seconds=60)
    cache.put(key_b, b"resp_b", ttl_seconds=60)

    cache.get(key_a)   # hit
    cache.get(key_b)   # hit
    cache.get(("miss.com.", "A"))  # miss

    # Adding key_c evicts one entry (LRU = key_a now since key_b was accessed last)
    # Actually: key_a was accessed first (making it most recently used from the pair),
    # then key_b; so after two gets the LRU is key_a. Let's just check eviction count.
    cache.put(key_c, b"resp_c", ttl_seconds=60)

    stats = cache.stats()
    assert stats["hits"] == 2
    assert stats["misses"] == 1
    assert stats["evictions"] == 1
    assert stats["current_size"] == 2
