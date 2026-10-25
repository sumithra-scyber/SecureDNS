"""Configuration for SecureDNS monitoring service."""
from __future__ import annotations

import os
from pydantic_settings import BaseSettings, SettingsConfigDict


class MonitoringConfig(BaseSettings):
    """Settings for the monitoring API and event ingestion pipeline."""

    model_config = SettingsConfigDict(
        env_prefix="SECUREDNS_",
        env_file=".env",
        extra="ignore",
    )

    # Database
    # Default to a local SQLite database for standalone development and automated tests,
    # or override with PostgreSQL: postgresql+asyncpg://user:pass@localhost:5432/securedns
    database_url: str = "sqlite+aiosqlite:///./securedns_monitoring.db"
    database_echo: bool = False

    # Event ingestion buffer
    queue_max_size: int = 10000
    batch_size: int = 100
    flush_interval_seconds: float = 0.5

    # Monitoring API server
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    api_title: str = "SecureDNS Monitoring API"
    api_version: str = "1.0.0"

    # CORS origins for frontend
    cors_origins: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]


def get_monitoring_config() -> MonitoringConfig:
    """Load monitoring configuration from environment or .env file."""
    # Also support standard DATABASE_URL env var if set
    db_url = os.getenv("DATABASE_URL")
    if db_url:
        return MonitoringConfig(database_url=db_url)
    return MonitoringConfig()
