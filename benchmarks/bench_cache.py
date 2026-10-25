"""
Benchmark: cache-enabled vs cache-disabled DNS resolution.

Measures:
- Throughput (queries/sec)
- Latency percentiles (p50, p95, p99)
- Cache hit ratio
- Error rates

Run with: python benchmarks/bench_cache.py
"""
import asyncio
import statistics
import time

from securedns.cache.ttl_cache import TTLCache
from securedns.config import ResolverConfig


async def bench_cache_hits(n: int = 10_000) -> None:
    cache = TTLCache(capacity=1000)
    key = ("example.com.", "A")
    fake_response = b"x" * 50
    cache.put(key, fake_response, ttl_seconds=300)

    latencies: list[float] = []
    for _ in range(n):
        start = time.perf_counter()
        result = cache.get(key)
        latencies.append(time.perf_counter() - start)

    assert result == fake_response, "All gets should return the cached value"

    sorted_lat = sorted(latencies)
    print(f"Cache GET ({n:,} hits):")
    print(f"  Throughput : {n / sum(latencies):.0f} ops/sec")
    print(f"  p50        : {statistics.median(latencies) * 1e6:.2f} µs")
    print(f"  p95        : {sorted_lat[int(n * 0.95)] * 1e6:.2f} µs")
    print(f"  p99        : {sorted_lat[int(n * 0.99)] * 1e6:.2f} µs")


async def bench_cache_misses(n: int = 10_000) -> None:
    cache = TTLCache(capacity=1000)
    latencies: list[float] = []
    for i in range(n):
        key = (f"miss{i}.example.com.", "A")
        start = time.perf_counter()
        cache.get(key)
        latencies.append(time.perf_counter() - start)

    sorted_lat = sorted(latencies)
    print(f"Cache GET ({n:,} misses):")
    print(f"  Throughput : {n / sum(latencies):.0f} ops/sec")
    print(f"  p50        : {statistics.median(latencies) * 1e6:.2f} µs")
    print(f"  p95        : {sorted_lat[int(n * 0.95)] * 1e6:.2f} µs")
    print(f"  p99        : {sorted_lat[int(n * 0.99)] * 1e6:.2f} µs")


async def bench_mixed(n: int = 10_000, hit_ratio: float = 0.8) -> None:
    """Simulate a realistic workload with a mix of hits and misses."""
    cache = TTLCache(capacity=500)
    # Pre-populate 500 entries
    hot_keys = [(f"hot{i}.example.com.", "A") for i in range(500)]
    for k in hot_keys:
        cache.put(k, b"x" * 50, ttl_seconds=300)

    import random
    rng = random.Random(42)
    hit_count = 0
    miss_count = 0
    latencies: list[float] = []

    for i in range(n):
        if rng.random() < hit_ratio:
            key = rng.choice(hot_keys)
        else:
            key = (f"cold{i}.example.com.", "A")

        start = time.perf_counter()
        result = cache.get(key)
        latencies.append(time.perf_counter() - start)

        if result is not None:
            hit_count += 1
        else:
            miss_count += 1

    actual_ratio = hit_count / n
    print(f"Mixed workload ({n:,} ops, target hit ratio {hit_ratio:.0%}):")
    print(f"  Actual hit ratio : {actual_ratio:.1%}")
    print(f"  Throughput       : {n / sum(latencies):.0f} ops/sec")
    print(f"  p50              : {statistics.median(latencies) * 1e6:.2f} µs")

    stats = cache.stats()
    print(f"  Cache stats      : {stats}")


if __name__ == "__main__":
    print("=" * 60)
    asyncio.run(bench_cache_hits())
    print()
    asyncio.run(bench_cache_misses())
    print()
    asyncio.run(bench_mixed())
    print()

    # Demonstrate stats tracking
    print("=" * 60)
    cache = TTLCache(capacity=1000)
    key = ("example.com.", "A")
    cache.put(key, b"x" * 50, 300)
    cache.get(key)
    cache.get(("miss.com.", "A"))
    print("Cache stats after put + 1 hit + 1 miss:", cache.stats())
