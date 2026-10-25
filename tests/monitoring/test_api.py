"""Integration tests for SecureDNS FastAPI Monitoring endpoints."""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from securedns.config import ResolverConfig
from securedns.events import EventBus, QueryReceivedEvent
from securedns.monitoring.app import create_app
from securedns.monitoring.config import MonitoringConfig
from securedns.monitoring.database import Base, get_db_session
from securedns.monitoring.event_handler import MonitoringEventHandler
from securedns.monitoring.repository import persist_events_batch
from securedns.monitoring.seed import generate_synthetic_events
from securedns.server import SecureDNSServer


@pytest_asyncio.fixture
async def api_client():
    """Create test client backed by in-memory SQLite database."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    # Seed 40 events
    sample_records = generate_synthetic_events(count=40, hours=12)
    await persist_events_batch(sample_records, session_factory=session_factory)

    async def override_get_db():
        async with session_factory() as session:
            yield session

    config = MonitoringConfig(database_url="sqlite+aiosqlite:///:memory:")
    handler = MonitoringEventHandler(
        queue_max_size=100,
        batch_size=10,
        flush_interval=0.01,
        persist_callback=lambda batch: persist_events_batch(batch, session_factory=session_factory),
    )

    test_app = create_app(config=config, event_handler=handler)
    test_app.dependency_overrides[get_db_session] = override_get_db

    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client, session_factory, handler

    await engine.dispose()


@pytest.mark.asyncio
async def test_health_endpoint(api_client):
    client, _, handler = api_client
    resp = await client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["database"] == "connected"
    assert "ingestion" in data


@pytest.mark.asyncio
async def test_events_list_and_pagination(api_client):
    client, _, _ = api_client
    resp = await client.get("/api/events?limit=10&offset=0")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["items"]) == 10
    assert data["limit"] == 10
    assert data["offset"] == 0
    assert data["total"] >= 40
    assert data["has_more"] is True


@pytest.mark.asyncio
async def test_events_filtering(api_client):
    client, _, _ = api_client
    resp = await client.get("/api/events?severity=high")
    assert resp.status_code == 200
    data = resp.json()
    for item in data["items"]:
        assert item["severity"] == "high"


@pytest.mark.asyncio
async def test_event_detail_and_not_found(api_client):
    client, _, _ = api_client
    list_resp = await client.get("/api/events?limit=1")
    first_event = list_resp.json()["items"][0]
    event_id = first_event["id"]

    detail_resp = await client.get(f"/api/events/{event_id}")
    assert detail_resp.status_code == 200
    assert detail_resp.json()["id"] == event_id

    missing_resp = await client.get("/api/events/9999999")
    assert missing_resp.status_code == 404


@pytest.mark.asyncio
async def test_stats_endpoints(api_client):
    client, _, _ = api_client

    # 1. Overview
    overview_resp = await client.get("/api/stats/overview?hours=24")
    assert overview_resp.status_code == 200
    overview = overview_resp.json()
    assert "total_queries" in overview
    assert "queries_per_second" in overview
    assert "cache_hit_rate_pct" in overview

    # 2. Query volume timeline
    volume_resp = await client.get("/api/stats/query-volume?hours=12")
    assert volume_resp.status_code == 200
    volume = volume_resp.json()
    assert len(volume["series"]) > 0

    # 3. Event distribution
    dist_resp = await client.get("/api/stats/event-distribution?hours=24")
    assert dist_resp.status_code == 200
    dist = dist_resp.json()
    assert len(dist["distribution"]) > 0

    # 4. Top domains
    top_resp = await client.get("/api/stats/top-domains?limit=5")
    assert top_resp.status_code == 200
    top = top_resp.json()
    assert len(top["domains"]) <= 5

    # 5. Security summary
    sec_resp = await client.get("/api/stats/security-summary")
    assert sec_resp.status_code == 200
    sec = sec_resp.json()
    assert "total_security_events" in sec


@pytest.mark.asyncio
async def test_end_to_end_resolver_to_api_flow(api_client):
    """Publish via Member 1 EventBus -> Ingestion -> DB -> API retrieval."""
    client, session_factory, handler = api_client

    bus = EventBus()
    handler.subscribe_to_bus(bus)
    await handler.start()

    # Emit a blocked request event
    bus.publish(
        QueryReceivedEvent(
            client_ip="192.168.99.123",
            transaction_id=8888,
            domain="custom-e2e-test.org",
            record_type="A",
        )
    )

    # Let the background queue flush
    import asyncio
    await asyncio.sleep(0.1)

    # Query the API to verify the event arrived in the DB
    resp = await client.get("/api/events?domain=custom-e2e-test.org")
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert len(items) == 1
    assert items[0]["client_ip"] == "192.168.99.123"
    assert items[0]["domain"] == "custom-e2e-test.org"

    await handler.stop()
