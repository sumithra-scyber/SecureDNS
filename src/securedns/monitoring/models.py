"""SQLAlchemy ORM models for SecureDNS security events and monitoring."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Index,
    Integer,
    String,
    Text,
)

from securedns.monitoring.database import Base


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SecurityEventModel(Base):
    """Persisted security and DNS resolution event record."""

    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(
        DateTime(timezone=True),
        default=_utc_now,
        nullable=False,
        index=True,
    )
    event_type = Column(String(64), nullable=False, index=True)
    severity = Column(String(16), nullable=False, default="info", index=True)
    action_taken = Column(String(32), nullable=False, default="PROCESSED", index=True)

    domain = Column(String(255), nullable=True, index=True)
    client_ip = Column(String(64), nullable=True, index=True)
    record_type = Column(String(16), nullable=True)

    # JSON metadata for payload specifics (e.g. latency_ms, warnings list, transport, etc.)
    metadata_json = Column(JSON, nullable=False, default=dict)

    # Distinguishes genuine runtime events from synthetic demo data
    is_synthetic = Column(Boolean, nullable=False, default=False, index=True)

    __table_args__ = (
        Index("ix_security_events_time_type", "timestamp", "event_type"),
        Index("ix_security_events_time_severity", "timestamp", "severity"),
        Index("ix_security_events_domain_type", "domain", "event_type"),
    )

    def to_dict(self) -> dict[str, Any]:
        """Convert ORM model to dictionary."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "event_type": self.event_type,
            "severity": self.severity,
            "action_taken": self.action_taken,
            "domain": self.domain,
            "client_ip": self.client_ip,
            "record_type": self.record_type,
            "metadata_json": self.metadata_json or {},
            "is_synthetic": self.is_synthetic,
        }
