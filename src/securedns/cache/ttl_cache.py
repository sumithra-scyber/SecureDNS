"""TTL-based LRU cache for DNS responses (asyncio-safe)."""
from __future__ import annotations

import time
from collections import OrderedDict
from typing import Optional


class TTLCache:
    """TTL-respecting LRU cache backed by an OrderedDict.

    Key  : ``(domain: str, record_type: str)``
    Value: raw DNS response bytes

    The cache is designed for single-threaded asyncio use.  OrderedDict
    operations are atomic at the Python level, so no explicit lock is needed
    for the GIL-protected asyncio event loop.
    """

    def __init__(self, capacity: int = 1000) -> None:
        self._capacity = capacity
        self._store: OrderedDict[tuple, tuple[bytes, float]] = OrderedDict()
        self._hits = 0
        self._misses = 0
        self._evictions = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, key: tuple) -> Optional[bytes]:
        """Return cached response bytes, or None on miss/expiry.

        A hit moves the entry to the *most-recently-used* end of the
        OrderedDict, maintaining LRU order.
        """
        entry = self._store.get(key)
        if entry is None:
            self._misses += 1
            return None

        response_bytes, expire_at = entry
        if time.monotonic() > expire_at:
            # Entry has expired – remove it and report a miss
            del self._store[key]
            self._misses += 1
            return None

        # Move to end (most recently used)
        self._store.move_to_end(key)
        self._hits += 1
        return response_bytes

    def put(self, key: tuple, response_bytes: bytes, ttl_seconds: float) -> None:
        """Store a DNS response with the given TTL.

        Does nothing if ``ttl_seconds`` is 0 (uncacheable responses).
        Evicts the least-recently-used entry when at capacity.
        """
        if ttl_seconds <= 0:
            return  # Do not cache zero-TTL responses

        expire_at = time.monotonic() + ttl_seconds

        if key in self._store:
            # Update existing entry and refresh LRU position
            self._store.move_to_end(key)
            self._store[key] = (response_bytes, expire_at)
            return

        # Evict LRU if at capacity
        if len(self._store) >= self._capacity:
            self._store.popitem(last=False)  # remove least-recently-used (front)
            self._evictions += 1

        self._store[key] = (response_bytes, expire_at)

    def stats(self) -> dict:
        """Return a snapshot of cache statistics."""
        return {
            "hits": self._hits,
            "misses": self._misses,
            "evictions": self._evictions,
            "current_size": len(self._store),
        }
