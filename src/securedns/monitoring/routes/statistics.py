"""Dashboard statistics and metrics endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from securedns.monitoring.database import get_db_session
from securedns.monitoring.repository import (
    get_dashboard_overview,
    get_event_distribution,
    get_query_volume_timeline,
    get_top_domains,
)
from securedns.monitoring.schemas import (
    EventDistributionResponse,
    OverviewStatsResponse,
    QueryVolumePoint,
    QueryVolumeResponse,
    SecuritySummaryResponse,
    TopDomainItem,
    TopDomainsResponse,
)

router = APIRouter(prefix="/stats", tags=["Dashboard Statistics"])


@router.get("/overview", response_model=OverviewStatsResponse)
async def get_overview(
    hours: int = Query(24, ge=1, le=168, description="Time window in hours"),
    session: AsyncSession = Depends(get_db_session),
) -> OverviewStatsResponse:
    """Return high-level summary metrics (queries, QPS, cache hit rate, blocked)."""
    data = await get_dashboard_overview(session, hours=hours)
    return OverviewStatsResponse(**data)


@router.get("/query-volume", response_model=QueryVolumeResponse)
async def get_query_volume(
    hours: int = Query(24, ge=1, le=168, description="Time window in hours"),
    session: AsyncSession = Depends(get_db_session),
) -> QueryVolumeResponse:
    """Return time-series query volume bucketed by hour."""
    series = await get_query_volume_timeline(session, hours=hours)
    return QueryVolumeResponse(
        time_window_hours=hours,
        series=[QueryVolumePoint(**pt) for pt in series],
    )


@router.get("/event-distribution", response_model=EventDistributionResponse)
async def get_distribution(
    hours: int = Query(24, ge=1, le=168, description="Time window in hours"),
    session: AsyncSession = Depends(get_db_session),
) -> EventDistributionResponse:
    """Return breakdown of events categorized by type and severity."""
    distribution = await get_event_distribution(session, hours=hours)
    return EventDistributionResponse(
        time_window_hours=hours,
        distribution=distribution,
    )


@router.get("/top-domains", response_model=TopDomainsResponse)
async def get_top_query_domains(
    limit: int = Query(10, ge=1, le=50, description="Max domains to return"),
    hours: int = Query(24, ge=1, le=168, description="Time window in hours"),
    blocked_only: bool = Query(False, description="Filter for blocked domains only"),
    session: AsyncSession = Depends(get_db_session),
) -> TopDomainsResponse:
    """Return top queried or top blocked domains."""
    domains = await get_top_domains(session, limit=limit, hours=hours, blocked_only=blocked_only)
    return TopDomainsResponse(
        time_window_hours=hours,
        domains=[TopDomainItem(**d) for d in domains],
    )


@router.get("/security-summary", response_model=SecuritySummaryResponse)
async def get_security_summary(
    hours: int = Query(24, ge=1, le=168, description="Time window in hours"),
    session: AsyncSession = Depends(get_db_session),
) -> SecuritySummaryResponse:
    """Return security incident breakdown (blocked, rate-limited, suspicious)."""
    overview = await get_dashboard_overview(session, hours=hours)
    top_blocked = await get_top_domains(session, limit=5, hours=hours, blocked_only=True)

    return SecuritySummaryResponse(
        time_window_hours=hours,
        blocked_queries=overview["blocked_queries"],
        rate_limited_queries=overview["rate_limited_queries"],
        suspicious_queries=overview["suspicious_queries"],
        total_security_events=overview["security_incidents_total"],
        top_blocked_domains=[TopDomainItem(**d) for d in top_blocked],
    )
