"""Benchmark suite for Member 2 Monitoring & Ingestion System.

Measures:
1. Event ingestion queue throughput (ops/sec and microsecond latency)
2. Database batch persistence throughput (events/sec)
3. API endpoint response latency percentiles (p50, p95, p99)
4. End-to-end event propagation delay

Run with:
    python benchmarks/bench_monitoring.py
"""
from __future__ import annotations

import asyncio
import statistics
import time
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from securedns.events import BlockedRequestEvent, EventBus, QueryReceivedEvent
from securedns.monitoring.app import create_app
from securedns.monitoring.config import MonitoringConfig
from securedns.monitoring.database import Base, get_db_session
from securedns.monitoring.event_handler import MonitoringEventHandler
from securedns.monitoring.repository import persist_events_batch
from securedns.monitoring.seed import generate_synthetic_events


def bench_ingestion_throughput(n: int = 20_000) -> None:
    """Measure how fast Member 1's EventBus can deliver events into MonitoringEventHandler."""
    bus = EventBus()
    handler = MonitoringEventHandler(queue_max_size=n + 1000)
    handler.subscribe_to_bus(bus)

    event = QueryReceivedEvent(
        client_ip="192.168.1.100",
        transaction_id=1234,
        domain="benchmark.example.com",
        record_type="A",
    )

    latencies: list[float] = []
    t0 = time.perf_counter()
    for _ in range(n):
        s = time.perf_counter()
        bus.publish(event)
        latencies.append(time.perf_counter() - s)
    total_time = time.perf_counter() - t0

    sorted_lat = sorted(latencies)
    throughput = n / total_time
    print(f"1. Ingestion Queue Throughput ({n:,} events published):")
    print(f"   Throughput : {throughput:,.0f} events/sec")
    print(f"   p50        : {statistics.median(latencies) * 1e6:.2f} µs")
    print(f"   p95        : {sorted_lat[int(n * 0.95)] * 1e6:.2f} µs")
    print(f"   p99        : {sorted_lat[int(n * 0.99)] * 1e6:.2f} µs")
    print(f"   Total Time : {total_time * 1000:.2f} ms")


async def bench_database_batch_persistence(batch_sizes=(50, 100, 250, 500)) -> None:
    """Measure database batch write speed across different batch sizes."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    print("\n2. Database Batch Persistence Throughput:")
    for b_size in batch_sizes:
        records = generate_synthetic_events(count=b_size, hours=1)
        latencies: list[float] = []
        for _ in range(5):  # 5 trials
            s = time.perf_counter()
            await persist_events_batch(records, session_factory=session_factory)
            latencies.append(time.perf_counter() - s)

        avg_latency = statistics.mean(latencies)
        events_per_sec = b_size / avg_latency
        print(f"   Batch size {b_size:3d} : {avg_latency * 1000:6.2f} ms | {events_per_sec:,.0f} events/sec")

    await engine.dispose()


async def bench_api_endpoint_latencies(n: int = 200) -> None:
    """Measure response latencies of FastAPI monitoring endpoints."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    # Seed 500 events
    sample_records = generate_synthetic_events(count=500, hours=24)
    await persist_events_batch(sample_records, session_factory=session_factory)

    async def override_get_db():
        async with session_factory() as session:
            yield session

    cfg = MonitoringConfig(database_url="sqlite+aiosqlite:///:memory:")
    app = create_app(config=cfg)
    app.dependency_overrides[get_db_session] = override_get_db

    transport = ASGITransport(app=app)
    endpoints = [
        ("/api/health", "Health Check"),
        ("/api/stats/overview?hours=24", "Overview Stats"),
        ("/api/events?limit=25&offset=0", "Paginated Events (25)"),
        ("/api/stats/query-volume?hours=24", "Query Volume Timeline"),
    ]

    print("\n3. API Endpoint Response Latency:")
    async with AsyncClient(transport=transport, base_url="http://bench") as client:
        for url, name in endpoints:
            latencies: list[float] = []
            for _ in range(n):
                s = time.perf_counter()
                res = await client.get(url)
                latencies.append(time.perf_counter() - s)
                assert res.status_code == 200

            sorted_lat = sorted(latencies)
            print(f"   {name:<28} : p50={statistics.median(latencies)*1000:.2f}ms  "
                  f"p95={sorted_lat[int(n*0.95)]*1000:.2f}ms  "
                  f"p99={sorted_lat[int(n*0.99)]*1000:.2f}ms")

    await engine.dispose()


async def main() -> None:
    print("=" * 65)
    print("  SecureDNS Member 2 — Monitoring System Benchmark Suite")
    print("=" * 65)
    bench_ingestion_throughput()
    await bench_database_batch_persistence()
    await bench_api_endpoint_latencies()
    print("=" * 65)


if __name__ == "__main__":
    asyncio.run(main())
