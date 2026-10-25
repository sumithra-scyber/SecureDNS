"""Health check endpoint for the SecureDNS monitoring service."""
from __future__ import annotations

from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from securedns.monitoring.database import check_db_health, get_db_session
from securedns.monitoring.schemas import HealthResponse

router = APIRouter(tags=["Health"])


@router.get("/health", response_model=HealthResponse)
async def get_health(request: Request, session: AsyncSession = Depends(get_db_session)) -> HealthResponse:
    """Return health status of the API, database connectivity, and ingestion buffer."""
    is_db_connected = await check_db_health(session.bind)

    event_handler = getattr(request.app.state, "event_handler", None)
    ingestion_stats = event_handler.stats() if event_handler else {"status": "inactive"}

    return HealthResponse(
        status="ok",
        version="1.0.0",
        timestamp=datetime.now(timezone.utc),
        database="connected" if is_db_connected else "disconnected",
        ingestion=ingestion_stats,
    )
