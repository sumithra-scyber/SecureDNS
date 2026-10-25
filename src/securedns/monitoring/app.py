"""FastAPI application factory for SecureDNS monitoring."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from securedns.monitoring.config import MonitoringConfig, get_monitoring_config
from securedns.monitoring.database import close_db, init_db
from securedns.monitoring.event_handler import MonitoringEventHandler
from securedns.monitoring.repository import persist_events_batch
from securedns.monitoring.routes import events, health, statistics
from securedns.monitoring.seed import seed_database

logger = logging.getLogger(__name__)


def create_app(
    config: Optional[MonitoringConfig] = None,
    event_handler: Optional[MonitoringEventHandler] = None,
) -> FastAPI:
    """Create and configure the FastAPI monitoring application."""
    cfg = config or get_monitoring_config()

    # If an event_handler is not supplied, create one wired to our database
    handler = event_handler
    if handler is None:
        handler = MonitoringEventHandler(
            queue_max_size=cfg.queue_max_size,
            batch_size=cfg.batch_size,
            flush_interval=cfg.flush_interval_seconds,
            persist_callback=persist_events_batch,
        )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Startup
        logger.info("Initializing SecureDNS Monitoring Service...")
        await init_db()
        app.state.event_handler = handler
        await handler.start()
        yield
        # Shutdown
        logger.info("Shutting down SecureDNS Monitoring Service...")
        await handler.stop()
        await close_db()

    app = FastAPI(
        title=cfg.api_title,
        version=cfg.api_version,
        description="High-performance monitoring & security intelligence API for SecureDNS",
        lifespan=lifespan,
    )

    # CORS configuration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Mount API routes under /api
    app.include_router(health.router, prefix="/api")
    app.include_router(events.router, prefix="/api")
    app.include_router(statistics.router, prefix="/api")

    # Development convenience endpoint to seed synthetic data
    @app.post("/api/dev/seed", tags=["Development"])
    async def seed_data(count: int = 250):
        inserted = await seed_database(count=count)
        return {"status": "ok", "seeded_events": inserted}

    return app


# Default app instance for running via uvicorn
app = create_app()
