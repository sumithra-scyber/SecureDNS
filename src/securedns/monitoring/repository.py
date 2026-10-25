"""Database repository for querying and persisting security events and metrics."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from securedns.monitoring.database import get_sessionmaker
from securedns.monitoring.models import SecurityEventModel

logger = logging.getLogger(__name__)


async def persist_events_batch(
    records: list[dict[str, Any]],
    session_factory=None,
) -> int:
    """Bulk insert normalized event records into the database."""
    if not records:
        return 0

    factory = session_factory or get_sessionmaker()
    async with factory() as session:
        try:
            models = [
                SecurityEventModel(
                    timestamp=rec.get("timestamp") or datetime.now(timezone.utc),
                    event_type=rec["event_type"],
                    severity=rec.get("severity", "info"),
                    action_taken=rec.get("action_taken", "PROCESSED"),
                    domain=rec.get("domain"),
                    client_ip=rec.get("client_ip"),
                    record_type=rec.get("record_type"),
                    metadata_json=rec.get("metadata_json") or {},
                    is_synthetic=rec.get("is_synthetic", False),
                )
                for rec in records
            ]
            session.add_all(models)
            await session.commit()
            return len(models)
        except Exception as exc:
            await session.rollback()
            logger.error("Failed to persist event batch (%d items): %s", len(records), exc)
            raise


async def get_events(
    session: AsyncSession,
    *,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    domain: Optional[str] = None,
    client_ip: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    include_synthetic: bool = True,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[SecurityEventModel], int]:
    """Retrieve filtered security events with pagination and total count."""
    query = select(SecurityEventModel)
    count_query = select(func.count(SecurityEventModel.id))

    filters = []
    if event_type:
        filters.append(SecurityEventModel.event_type == event_type)
    if severity:
        filters.append(SecurityEventModel.severity == severity)
    if domain:
        filters.append(SecurityEventModel.domain.ilike(f"%{domain.rstrip('.')}%"))
    if client_ip:
        filters.append(SecurityEventModel.client_ip == client_ip)
    if start_time:
        filters.append(SecurityEventModel.timestamp >= start_time)
    if end_time:
        filters.append(SecurityEventModel.timestamp <= end_time)
    if not include_synthetic:
        filters.append(SecurityEventModel.is_synthetic == False)  # noqa: E712

    if filters:
        query = query.where(*filters)
        count_query = count_query.where(*filters)

    # Order newest first
    query = query.order_by(desc(SecurityEventModel.timestamp), desc(SecurityEventModel.id))
    query = query.limit(limit).offset(offset)

    total_result = await session.execute(count_query)
    total = total_result.scalar_one()

    results = await session.execute(query)
    items = list(results.scalars().all())

    return items, total


async def get_event_by_id(session: AsyncSession, event_id: int) -> Optional[SecurityEventModel]:
    """Fetch single event by its primary key ID."""
    query = select(SecurityEventModel).where(SecurityEventModel.id == event_id)
    result = await session.execute(query)
    return result.scalar_one_or_none()


async def get_dashboard_overview(session: AsyncSession, hours: int = 24) -> dict[str, Any]:
    """Aggregate high-level overview metrics across the specified time window."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    # 1. Total events
    total_q = select(func.count(SecurityEventModel.id)).where(SecurityEventModel.timestamp >= since)
    total_events = (await session.execute(total_q)).scalar_one()

    # 2. Total queries received
    queries_q = select(func.count(SecurityEventModel.id)).where(
        SecurityEventModel.timestamp >= since,
        SecurityEventModel.event_type == "query_received",
    )
    total_queries = (await session.execute(queries_q)).scalar_one()

    # 3. Blocked queries
    blocked_q = select(func.count(SecurityEventModel.id)).where(
        SecurityEventModel.timestamp >= since,
        SecurityEventModel.event_type == "blocked_request",
    )
    total_blocked = (await session.execute(blocked_q)).scalar_one()

    # 4. Rate limited queries
    rate_limited_q = select(func.count(SecurityEventModel.id)).where(
        SecurityEventModel.timestamp >= since,
        SecurityEventModel.event_type == "rate_limited",
    )
    total_rate_limited = (await session.execute(rate_limited_q)).scalar_one()

    # 5. Suspicious queries
    suspicious_q = select(func.count(SecurityEventModel.id)).where(
        SecurityEventModel.timestamp >= since,
        SecurityEventModel.event_type == "suspicious_activity",
    )
    total_suspicious = (await session.execute(suspicious_q)).scalar_one()

    # 6. Cache stats
    cache_hits_q = select(func.count(SecurityEventModel.id)).where(
        SecurityEventModel.timestamp >= since,
        SecurityEventModel.event_type == "cache_hit",
    )
    cache_misses_q = select(func.count(SecurityEventModel.id)).where(
        SecurityEventModel.timestamp >= since,
        SecurityEventModel.event_type == "cache_miss",
    )
    cache_hits = (await session.execute(cache_hits_q)).scalar_one()
    cache_misses = (await session.execute(cache_misses_q)).scalar_one()
    total_cache_lookups = cache_hits + cache_misses
    cache_hit_rate = (cache_hits / total_cache_lookups * 100.0) if total_cache_lookups > 0 else 0.0

    # 7. Upstream failures
    failures_q = select(func.count(SecurityEventModel.id)).where(
        SecurityEventModel.timestamp >= since,
        SecurityEventModel.event_type == "upstream_failure",
    )
    upstream_failures = (await session.execute(failures_q)).scalar_one()

    # Queries per second average over window
    window_seconds = hours * 3600
    qps = total_queries / window_seconds if window_seconds > 0 else 0.0

    return {
        "time_window_hours": hours,
        "total_events": total_events,
        "total_queries": total_queries,
        "queries_per_second": round(qps, 2),
        "blocked_queries": total_blocked,
        "rate_limited_queries": total_rate_limited,
        "suspicious_queries": total_suspicious,
        "security_incidents_total": total_blocked + total_rate_limited + total_suspicious,
        "cache_hits": cache_hits,
        "cache_misses": cache_misses,
        "cache_hit_rate_pct": round(cache_hit_rate, 1),
        "upstream_failures": upstream_failures,
    }


async def get_event_distribution(session: AsyncSession, hours: int = 24) -> list[dict[str, Any]]:
    """Group events by type and severity."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    query = (
        select(
            SecurityEventModel.event_type,
            SecurityEventModel.severity,
            func.count(SecurityEventModel.id).label("count"),
        )
        .where(SecurityEventModel.timestamp >= since)
        .group_by(SecurityEventModel.event_type, SecurityEventModel.severity)
        .order_by(desc("count"))
    )
    result = await session.execute(query)
    return [
        {"event_type": row.event_type, "severity": row.severity, "count": row.count}
        for row in result.all()
    ]


async def get_top_domains(
    session: AsyncSession,
    limit: int = 10,
    hours: int = 24,
    blocked_only: bool = False,
) -> list[dict[str, Any]]:
    """Return top queried or top blocked domains."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    query = select(
        SecurityEventModel.domain,
        func.count(SecurityEventModel.id).label("query_count"),
    ).where(
        SecurityEventModel.timestamp >= since,
        SecurityEventModel.domain.is_not(None),
        SecurityEventModel.domain != "",
    )

    if blocked_only:
        query = query.where(SecurityEventModel.event_type == "blocked_request")

    query = (
        query.group_by(SecurityEventModel.domain)
        .order_by(desc("query_count"))
        .limit(limit)
    )
    result = await session.execute(query)
    return [
        {"domain": row.domain, "count": row.query_count}
        for row in result.all()
    ]


async def get_query_volume_timeline(
    session: AsyncSession,
    hours: int = 24,
) -> list[dict[str, Any]]:
    """Return hourly bucketed event counts for charting."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    # To remain database-agnostic across both PostgreSQL and SQLite,
    # we query timestamp and event_type and bucket in Python.
    query = select(
        SecurityEventModel.timestamp,
        SecurityEventModel.event_type,
    ).where(
        SecurityEventModel.timestamp >= since
    ).order_by(SecurityEventModel.timestamp.asc())

    result = await session.execute(query)
    rows = result.all()

    # Bucket by ISO hour "YYYY-MM-DDTHH:00:00"
    buckets: dict[str, dict[str, int]] = {}
    current_time = since.replace(minute=0, second=0, microsecond=0)
    end_time = datetime.now(timezone.utc)

    while current_time <= end_time:
        iso_hour = current_time.strftime("%Y-%m-%dT%H:00:00Z")
        buckets[iso_hour] = {
            "timestamp": iso_hour,
            "queries": 0,
            "blocked": 0,
            "security_alerts": 0,
            "cache_hits": 0,
        }
        current_time += timedelta(hours=1)

    for ts, ev_type in rows:
        if ts is None:
            continue
        hour_key = ts.replace(minute=0, second=0, microsecond=0).strftime("%Y-%m-%dT%H:00:00Z")
        if hour_key not in buckets:
            buckets[hour_key] = {
                "timestamp": hour_key,
                "queries": 0,
                "blocked": 0,
                "security_alerts": 0,
                "cache_hits": 0,
            }
        b = buckets[hour_key]
        if ev_type == "query_received":
            b["queries"] += 1
        elif ev_type == "blocked_request":
            b["blocked"] += 1
            b["security_alerts"] += 1
        elif ev_type in ("rate_limited", "suspicious_activity"):
            b["security_alerts"] += 1
        elif ev_type == "cache_hit":
            b["cache_hits"] += 1

    return list(buckets.values())
