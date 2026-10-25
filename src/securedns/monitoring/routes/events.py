"""Security events querying and detail endpoints."""
from __future__ import annotations

from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from securedns.monitoring.database import get_db_session
from securedns.monitoring.repository import get_event_by_id, get_events
from securedns.monitoring.schemas import PaginatedEventsResponse, SecurityEventResponse

router = APIRouter(prefix="/events", tags=["Security Events"])


@router.get("", response_model=PaginatedEventsResponse)
async def list_events(
    session: AsyncSession = Depends(get_db_session),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    severity: Optional[str] = Query(None, description="Filter by severity (info, medium, high, critical)"),
    domain: Optional[str] = Query(None, description="Filter by domain name substring"),
    client_ip: Optional[str] = Query(None, description="Filter by client IP"),
    start_time: Optional[datetime] = Query(None, description="ISO timestamp start filter"),
    end_time: Optional[datetime] = Query(None, description="ISO timestamp end filter"),
    include_synthetic: bool = Query(True, description="Whether to include synthetic demo records"),
    limit: int = Query(50, ge=1, le=500, description="Page size"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
) -> PaginatedEventsResponse:
    """Retrieve security and resolution events, sorted newest first."""
    items, total = await get_events(
        session,
        event_type=event_type,
        severity=severity,
        domain=domain,
        client_ip=client_ip,
        start_time=start_time,
        end_time=end_time,
        include_synthetic=include_synthetic,
        limit=limit,
        offset=offset,
    )

    return PaginatedEventsResponse(
        items=[SecurityEventResponse.model_validate(item) for item in items],
        total=total,
        limit=limit,
        offset=offset,
        has_more=(offset + limit) < total,
    )


@router.get("/{event_id}", response_model=SecurityEventResponse)
async def get_single_event(
    event_id: int,
    session: AsyncSession = Depends(get_db_session),
) -> SecurityEventResponse:
    """Retrieve complete details of a specific security event."""
    item = await get_event_by_id(session, event_id)
    if not item:
        raise HTTPException(status_code=404, detail=f"Event {event_id} not found")
    return SecurityEventResponse.model_validate(item)
