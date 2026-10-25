"""Typed event dataclasses for SecureDNS monitoring integration."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


class EventType(str, Enum):
    QUERY_RECEIVED = "query_received"
    CACHE_HIT = "cache_hit"
    CACHE_MISS = "cache_miss"
    CACHE_EVICTION = "cache_eviction"
    UPSTREAM_SUCCESS = "upstream_success"
    UPSTREAM_FAILURE = "upstream_failure"
    BLOCKED_REQUEST = "blocked_request"
    RATE_LIMITED = "rate_limited"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    SERVER_START = "server_start"
    SERVER_STOP = "server_stop"


@dataclass
class BaseEvent:
    event_type: EventType
    timestamp: datetime = field(default_factory=_now)


@dataclass
class QueryReceivedEvent(BaseEvent):
    event_type: EventType = field(default=EventType.QUERY_RECEIVED)
    client_ip: str = ""
    transaction_id: int = 0
    domain: str = ""
    record_type: str = ""
    transport: str = "udp"  # "udp" or "tcp"


@dataclass
class CacheHitEvent(BaseEvent):
    event_type: EventType = field(default=EventType.CACHE_HIT)
    domain: str = ""
    record_type: str = ""
    client_ip: str = ""


@dataclass
class CacheMissEvent(BaseEvent):
    event_type: EventType = field(default=EventType.CACHE_MISS)
    domain: str = ""
    record_type: str = ""
    client_ip: str = ""


@dataclass
class CacheEvictionEvent(BaseEvent):
    event_type: EventType = field(default=EventType.CACHE_EVICTION)
    domain: str = ""
    record_type: str = ""
    reason: str = "lru"  # "lru" or "ttl"


@dataclass
class UpstreamSuccessEvent(BaseEvent):
    event_type: EventType = field(default=EventType.UPSTREAM_SUCCESS)
    domain: str = ""
    record_type: str = ""
    upstream_host: str = ""
    latency_ms: float = 0.0
    transport: str = "udp"


@dataclass
class UpstreamFailureEvent(BaseEvent):
    event_type: EventType = field(default=EventType.UPSTREAM_FAILURE)
    domain: str = ""
    record_type: str = ""
    upstream_host: str = ""
    error: str = ""
    transport: str = "udp"


@dataclass
class BlockedRequestEvent(BaseEvent):
    event_type: EventType = field(default=EventType.BLOCKED_REQUEST)
    client_ip: str = ""
    domain: str = ""
    record_type: str = ""


@dataclass
class RateLimitedEvent(BaseEvent):
    event_type: EventType = field(default=EventType.RATE_LIMITED)
    client_ip: str = ""
    domain: str = ""
    record_type: str = ""


@dataclass
class SuspiciousActivityEvent(BaseEvent):
    event_type: EventType = field(default=EventType.SUSPICIOUS_ACTIVITY)
    client_ip: str = ""
    domain: str = ""
    warnings: list = field(default_factory=list)


@dataclass
class ServerStartEvent(BaseEvent):
    event_type: EventType = field(default=EventType.SERVER_START)
    listen_host: str = ""
    listen_port: int = 0


@dataclass
class ServerStopEvent(BaseEvent):
    event_type: EventType = field(default=EventType.SERVER_STOP)
    listen_host: str = ""
    listen_port: int = 0


class EventBus:
    """Simple publish/subscribe mechanism for delivering events to registered handlers.

    Member 2 can register a handler that writes to PostgreSQL. We keep event
    delivery separate from persistence.
    """

    def __init__(self):
        self._handlers: list[Callable[[BaseEvent], Any]] = []

    def subscribe(self, handler: Callable[[BaseEvent], Any]) -> None:
        """Register a handler function that will be called for every published event."""
        self._handlers.append(handler)

    def publish(self, event: BaseEvent) -> None:
        """Deliver an event to all registered handlers.

        Errors in individual handlers are swallowed so a bad handler can never
        crash the resolver.
        """
        for h in self._handlers:
            try:
                h(event)
            except Exception:
                pass  # never let a bad handler crash the resolver
