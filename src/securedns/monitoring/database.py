"""Database connectivity and async session management for SecureDNS monitoring."""
from __future__ import annotations

import logging
from collections.abc import AsyncGenerator
from typing import Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import declarative_base

from securedns.monitoring.config import MonitoringConfig, get_monitoring_config

logger = logging.getLogger(__name__)

Base = declarative_base()

_engine: Optional[AsyncEngine] = None
_sessionmaker: Optional[async_sessionmaker[AsyncSession]] = None


def get_engine(config: Optional[MonitoringConfig] = None) -> AsyncEngine:
    """Return the global async engine or create one if not initialized."""
    global _engine
    if _engine is None:
        cfg = config or get_monitoring_config()
        # Enable connection pooling and pre-ping to detect stale connections
        engine_args = {"echo": cfg.database_echo, "future": True}
        if "sqlite" in cfg.database_url:
            # SQLite does not support pool_size / max_overflow
            pass
        else:
            engine_args.update({
                "pool_size": 10,
                "max_overflow": 20,
                "pool_pre_ping": True,
            })
        _engine = create_async_engine(cfg.database_url, **engine_args)
    return _engine


def get_sessionmaker(config: Optional[MonitoringConfig] = None) -> async_sessionmaker[AsyncSession]:
    """Return the global async session factory."""
    global _sessionmaker
    if _sessionmaker is None:
        engine = get_engine(config)
        _sessionmaker = async_sessionmaker(
            bind=engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )
    return _sessionmaker


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency for yielding database sessions with automatic rollback on error."""
    session_factory = get_sessionmaker()
    async with session_factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


async def init_db(engine: Optional[AsyncEngine] = None) -> None:
    """Create all registered database tables."""
    eng = engine or get_engine()
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables initialized successfully")


async def check_db_health(engine: Optional[AsyncEngine] = None) -> bool:
    """Execute a simple query to verify database connectivity."""
    try:
        eng = engine or get_engine()
        async with eng.connect() as conn:
            result = await conn.execute(text("SELECT 1"))
            return result.scalar() == 1
    except Exception as exc:
        logger.warning("Database health check failed: %s", exc)
        return False


async def close_db() -> None:
    """Dispose the engine connections on shutdown."""
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _sessionmaker = None
        logger.info("Database engine disposed")
