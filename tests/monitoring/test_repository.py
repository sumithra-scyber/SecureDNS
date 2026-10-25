"""Tests for monitoring repository and database integration."""
from __future__ import annotations

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from securedns.monitoring.database import Base, check_db_health
from securedns.monitoring.models import SecurityEventModel
from securedns.monitoring.repository import (
    get_dashboard_overview,
    get_event_by_id,
    get_event_distribution,
    get_events,
    get_query_volume_timeline,
    get_top_domains,
    persist_events_batch,
)
from securedns.monitoring.seed import generate_synthetic_events


@pytest_asyncio.fixture
async def test_db():
    """In-memory SQLite async database for ultra-fast, isolated testing."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    yield engine, session_factory

    await engine.dispose()


@pytest.mark.asyncio
async def test_db_health_check(test_db):
    engine, _ = test_db
    is_healthy = await check_db_health(engine)
    assert is_healthy is True


@pytest.mark.asyncio
async def test_persist_and_retrieve_events(test_db):
    engine, session_factory = test_db

    sample_records = [
        {
            "event_type": "query_received",
            "severity": "info",
            "action_taken": "RECEIVED",
            "domain": "example.com",
            "client_ip": "192.168.1.1",
            "record_type": "A",
            "metadata_json": {"transaction_id": 42},
            "is_synthetic": False,
        },
        {
            "event_type": "blocked_request",
            "severity": "high",
            "action_taken": "BLOCKED",
            "domain": "malicious.org",
            "client_ip": "192.168.1.5",
            "record_type": "A",
            "metadata_json": {"reason": "Blocklist match"},
            "is_synthetic": False,
        },
    ]

    inserted = await persist_events_batch(sample_records, session_factory=session_factory)
    assert inserted == 2

    async with session_factory() as session:
        # 1. Fetch all
        items, total = await get_events(session)
        assert total == 2
        assert len(items) == 2

        # 2. Filter by severity
        high_items, high_total = await get_events(session, severity="high")
        assert high_total == 1
        assert high_items[0].domain == "malicious.org"

        # 3. Filter by domain
        domain_items, _ = await get_events(session, domain="example.com")
        assert len(domain_items) == 1
        assert domain_items[0].event_type == "query_received"

        # 4. Fetch by ID
        first_id = items[0].id
        retrieved = await get_event_by_id(session, first_id)
        assert retrieved is not None
        assert retrieved.id == first_id


@pytest.mark.asyncio
async def test_dashboard_aggregations(test_db):
    engine, session_factory = test_db

    # Seed 50 synthetic events
    records = generate_synthetic_events(count=50, hours=12)
    await persist_events_batch(records, session_factory=session_factory)

    async with session_factory() as session:
        overview = await get_dashboard_overview(session, hours=24)
        assert overview["total_events"] > 0
        assert "cache_hit_rate_pct" in overview
        assert "security_incidents_total" in overview

        distribution = await get_event_distribution(session, hours=24)
        assert len(distribution) > 0

        top_domains = await get_top_domains(session, limit=5, hours=24)
        assert len(top_domains) <= 5

        timeline = await get_query_volume_timeline(session, hours=12)
        assert len(timeline) > 0
        assert "queries" in timeline[0]
