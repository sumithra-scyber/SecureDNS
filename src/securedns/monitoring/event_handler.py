"""Event ingestion pipeline connecting Member 1's EventBus to persistence.

Implements an asynchronous, non-blocking producer-consumer buffer.
The DNS resolver synchronously publishes events; this handler puts them
into an asyncio.Queue to ensure the resolver's event loop is never blocked
by database network I/O.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine, Optional

from securedns.events import (
    BaseEvent,
    BlockedRequestEvent,
    CacheEvictionEvent,
    CacheHitEvent,
    CacheMissEvent,
    EventBus,
    EventType,
    QueryReceivedEvent,
    RateLimitedEvent,
    ServerStartEvent,
    ServerStopEvent,
    SuspiciousActivityEvent,
    UpstreamFailureEvent,
    UpstreamSuccessEvent,
)

logger = logging.getLogger(__name__)


def determine_severity_and_action(event: BaseEvent) -> tuple[str, str]:
    """Map event types to human-readable security severity and action taken."""
    match event.event_type:
        case EventType.SUSPICIOUS_ACTIVITY:
            return "critical", "FLAGGED"
        case EventType.BLOCKED_REQUEST:
            return "high", "BLOCKED"
        case EventType.RATE_LIMITED:
            return "medium", "RATE_LIMITED"
        case EventType.UPSTREAM_FAILURE:
            return "warning", "FAILED"
        case EventType.CACHE_HIT:
            return "info", "CACHE_HIT"
        case EventType.CACHE_MISS:
            return "info", "CACHE_MISS"
        case EventType.CACHE_EVICTION:
            return "info", "EVICTED"
        case EventType.UPSTREAM_SUCCESS:
            return "info", "RESOLVED"
        case EventType.QUERY_RECEIVED:
            return "info", "RECEIVED"
        case EventType.SERVER_START:
            return "info", "STARTED"
        case EventType.SERVER_STOP:
            return "info", "STOPPED"
        case _:
            return "info", "PROCESSED"


def normalize_event(event: BaseEvent) -> dict[str, Any]:
    """Extract standard fields and metadata from any BaseEvent subclass."""
    event_type_str = (
        event.event_type.value
        if isinstance(event.event_type, EventType)
        else str(event.event_type)
    )
    severity, action = determine_severity_and_action(event)

    record: dict[str, Any] = {
        "event_type": event_type_str,
        "timestamp": getattr(event, "timestamp", datetime.now(timezone.utc)),
        "severity": severity,
        "action_taken": action,
        "domain": getattr(event, "domain", None),
        "client_ip": getattr(event, "client_ip", None),
        "record_type": getattr(event, "record_type", None),
        "metadata_json": {},
    }

    # Normalize domain: strip trailing dot if present
    if record["domain"]:
        record["domain"] = record["domain"].rstrip(".")

    # Extract event-specific metadata
    meta = record["metadata_json"]
    if isinstance(event, QueryReceivedEvent):
        meta["transaction_id"] = event.transaction_id
        meta["transport"] = event.transport
    elif isinstance(event, UpstreamSuccessEvent):
        meta["upstream_host"] = event.upstream_host
        meta["latency_ms"] = event.latency_ms
        meta["transport"] = event.transport
    elif isinstance(event, UpstreamFailureEvent):
        meta["upstream_host"] = event.upstream_host
        meta["error"] = event.error
        meta["transport"] = event.transport
    elif isinstance(event, SuspiciousActivityEvent):
        meta["warnings"] = event.warnings
    elif isinstance(event, CacheEvictionEvent):
        meta["reason"] = event.reason
    elif isinstance(event, (ServerStartEvent, ServerStopEvent)):
        meta["listen_host"] = event.listen_host
        meta["listen_port"] = event.listen_port

    return record


class MonitoringEventHandler:
    """Consumes events from Member 1's EventBus and feeds an async persistence worker.

    Reliability & Performance Guarantees:
    1. Zero-latency impact: EventBus.publish() invokes handle_event() synchronously.
       handle_event() calls queue.put_nowait() which executes in microseconds.
    2. Backpressure management: If database writes lag and the queue reaches max size,
       the oldest event is dropped, a drop counter is incremented, and a warning is logged.
       The DNS server never crashes and never runs out of memory.
    """

    def __init__(
        self,
        queue_max_size: int = 10000,
        batch_size: int = 100,
        flush_interval: float = 0.5,
        persist_callback: Optional[Callable[[list[dict[str, Any]]], Coroutine[Any, Any, None]]] = None,
    ) -> None:
        self.queue_max_size = queue_max_size
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.persist_callback = persist_callback

        self.queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=queue_max_size)
        self._worker_task: Optional[asyncio.Task] = None
        self._running = False

        # Metrics counters
        self.total_received = 0
        self.total_persisted = 0
        self.total_dropped = 0

    def subscribe_to_bus(self, event_bus: EventBus) -> None:
        """Register our synchronous handler with Member 1's EventBus."""
        event_bus.subscribe(self.handle_event)
        logger.info("MonitoringEventHandler subscribed to EventBus")

    def handle_event(self, event: BaseEvent) -> None:
        """Synchronously handle an event published by SecureDNSServer.

        MUST be synchronous because EventBus.publish() invokes handlers synchronously.
        """
        self.total_received += 1
        try:
            record = normalize_event(event)
        except Exception as exc:
            logger.error("Failed to normalize event %r: %s", event, exc)
            return

        try:
            self.queue.put_nowait(record)
        except asyncio.QueueFull:
            # Under extreme load or DB outage, drop oldest to avoid memory exhaustion
            try:
                self.queue.get_nowait()
                self.queue.task_done()
                self.queue.put_nowait(record)
                self.total_dropped += 1
                logger.warning(
                    "Monitoring event buffer full (%d items); dropped oldest event",
                    self.queue_max_size,
                )
            except Exception:
                self.total_dropped += 1

    async def start(self) -> None:
        """Start the background consumer task."""
        if self._running:
            return
        self._running = True
        self._worker_task = asyncio.create_task(self._run_consumer(), name="monitoring_ingestion_worker")
        logger.info("Monitoring ingestion worker started")

    async def stop(self) -> None:
        """Gracefully shut down the consumer, draining remaining queued events."""
        if not self._running:
            return
        self._running = False
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
            self._worker_task = None

        # Drain any remaining items in queue
        remaining_items: list[dict[str, Any]] = []
        while not self.queue.empty():
            try:
                remaining_items.append(self.queue.get_nowait())
                self.queue.task_done()
            except asyncio.QueueEmpty:
                break

        if remaining_items and self.persist_callback:
            try:
                await self.persist_callback(remaining_items)
                self.total_persisted += len(remaining_items)
                logger.info("Flushed %d remaining events during shutdown", len(remaining_items))
            except Exception as exc:
                logger.error("Failed to flush remaining events on shutdown: %s", exc)

    async def _run_consumer(self) -> None:
        """Continuously pull events in batches and send to persistence callback."""
        while self._running:
            batch: list[dict[str, Any]] = []
            try:
                # Wait for the first item with timeout
                first_item = await asyncio.wait_for(
                    self.queue.get(),
                    timeout=self.flush_interval,
                )
                batch.append(first_item)
                self.queue.task_done()

                # Collect more available items up to batch_size
                while len(batch) < self.batch_size and not self.queue.empty():
                    item = self.queue.get_nowait()
                    batch.append(item)
                    self.queue.task_done()

            except (asyncio.TimeoutError, TimeoutError):
                # No new items arrived within flush_interval
                pass
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Error in ingestion queue consumer: %s", exc)

            if batch and self.persist_callback:
                try:
                    await self.persist_callback(batch)
                    self.total_persisted += len(batch)
                except Exception as exc:
                    logger.error("Persistence callback failed for %d events: %s", len(batch), exc)

    def stats(self) -> dict[str, Any]:
        """Return snapshot of event ingestion buffer statistics."""
        return {
            "total_received": self.total_received,
            "total_persisted": self.total_persisted,
            "total_dropped": self.total_dropped,
            "queue_current_size": self.queue.qsize(),
            "queue_max_size": self.queue_max_size,
        }
