"""Pydantic request and response schemas for SecureDNS Monitoring API."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Health Schemas
# ---------------------------------------------------------------------------

class HealthResponse(BaseModel):
    status: str = Field(..., json_schema_extra={"example": "ok"})
    version: str = Field(..., json_schema_extra={"example": "1.0.0"})
    timestamp: datetime
    database: str = Field(..., json_schema_extra={"example": "connected"})
    ingestion: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Event Schemas
# ---------------------------------------------------------------------------

class SecurityEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    event_type: str
    severity: str
    action_taken: str
    domain: Optional[str] = None
    client_ip: Optional[str] = None
    record_type: Optional[str] = None
    metadata_json: dict[str, Any] = Field(default_factory=dict)
    is_synthetic: bool = False


class PaginatedEventsResponse(BaseModel):
    items: list[SecurityEventResponse]
    total: int
    limit: int
    offset: int
    has_more: bool


# ---------------------------------------------------------------------------
# Statistics Schemas
# ---------------------------------------------------------------------------

class OverviewStatsResponse(BaseModel):
    time_window_hours: int
    total_events: int
    total_queries: int
    queries_per_second: float
    blocked_queries: int
    rate_limited_queries: int
    suspicious_queries: int
    security_incidents_total: int
    cache_hits: int
    cache_misses: int
    cache_hit_rate_pct: float
    upstream_failures: int


class QueryVolumePoint(BaseModel):
    timestamp: str
    queries: int
    blocked: int
    security_alerts: int
    cache_hits: int


class QueryVolumeResponse(BaseModel):
    time_window_hours: int
    series: list[QueryVolumePoint]


class EventDistributionItem(BaseModel):
    event_type: str
    severity: str
    count: int


class EventDistributionResponse(BaseModel):
    time_window_hours: int
    distribution: list[EventDistributionItem]


class TopDomainItem(BaseModel):
    domain: str
    count: int


class TopDomainsResponse(BaseModel):
    time_window_hours: int
    domains: list[TopDomainItem]


class SecuritySummaryResponse(BaseModel):
    time_window_hours: int
    blocked_queries: int
    rate_limited_queries: int
    suspicious_queries: int
    total_security_events: int
    top_blocked_domains: list[TopDomainItem]
