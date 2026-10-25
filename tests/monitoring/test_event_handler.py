"""Unit tests for Member 2's MonitoringEventHandler."""
from __future__ import annotations

import asyncio
import pytest

from securedns.events import (
    BlockedRequestEvent,
    CacheHitEvent,
    EventBus,
    EventType,
    QueryReceivedEvent,
    RateLimitedEvent,
    SuspiciousActivityEvent,
    UpstreamSuccessEvent,
)
from securedns.monitoring.event_handler import (
    MonitoringEventHandler,
    normalize_event,
)


def test_normalize_event_blocked_request():
    event = BlockedRequestEvent(
        client_ip="192.168.1.100",
        domain="malware.example.com.",
        record_type="A",
    )
    record = normalize_event(event)

    assert record["event_type"] == "blocked_request"
    assert record["severity"] == "high"
    assert record["action_taken"] == "BLOCKED"
    assert record["domain"] == "malware.example.com"  # stripped trailing dot
    assert record["client_ip"] == "192.168.1.100"
    assert record["record_type"] == "A"


def test_normalize_event_suspicious_activity():
    event = SuspiciousActivityEvent(
        client_ip="10.0.0.5",
        domain="verylonglabelthatistunneling.com",
        warnings=["Domain length exceeds limit", "Excessive query rate"],
    )
    record = normalize_event(event)

    assert record["event_type"] == "suspicious_activity"
    assert record["severity"] == "critical"
    assert record["action_taken"] == "FLAGGED"
    assert record["metadata_json"]["warnings"] == [
        "Domain length exceeds limit",
        "Excessive query rate",
    ]


def test_normalize_event_upstream_success():
    event = UpstreamSuccessEvent(
        domain="google.com",
        record_type="AAAA",
        upstream_host="8.8.8.8",
        latency_ms=14.2,
        transport="udp",
    )
    record = normalize_event(event)

    assert record["event_type"] == "upstream_success"
    assert record["severity"] == "info"
    assert record["action_taken"] == "RESOLVED"
    assert record["metadata_json"]["latency_ms"] == 14.2
    assert record["metadata_json"]["upstream_host"] == "8.8.8.8"


@pytest.mark.asyncio
async def test_event_bus_integration_and_batch_processing():
    """Verify that Member 1's EventBus seamlessly delivers events into the handler."""
    bus = EventBus()
    persisted_batches: list[list[dict]] = []

    async def mock_persist(batch: list[dict]) -> None:
        persisted_batches.append(batch)

    handler = MonitoringEventHandler(
        queue_max_size=50,
        batch_size=5,
        flush_interval=0.05,
        persist_callback=mock_persist,
    )
    handler.subscribe_to_bus(bus)
    await handler.start()

    # Publish 7 events via Member 1's EventBus
    for i in range(7):
        bus.publish(
            QueryReceivedEvent(
                client_ip=f"10.0.0.{i}",
                transaction_id=100 + i,
                domain=f"test{i}.com",
                record_type="A",
            )
        )

    # Wait for the background worker to flush
    await asyncio.sleep(0.15)
    await handler.stop()

    total_persisted = sum(len(b) for b in persisted_batches)
    assert total_persisted == 7

    stats = handler.stats()
    assert stats["total_received"] == 7
    assert stats["total_persisted"] == 7
    assert stats["total_dropped"] == 0


@pytest.mark.asyncio
async def test_queue_overflow_drops_oldest():
    """Verify that buffer overflow drops oldest events without blocking or crashing."""
    handler = MonitoringEventHandler(queue_max_size=3)

    for i in range(5):
        handler.handle_event(
            QueryReceivedEvent(
                client_ip=f"192.168.0.{i}",
                transaction_id=i,
                domain=f"domain{i}.com",
                record_type="A",
            )
        )

    stats = handler.stats()
    assert stats["total_received"] == 5
    assert stats["total_dropped"] == 2
    assert stats["queue_current_size"] == 3
