"""Integrated runner for SecureDNS: runs Member 1 Resolver + Member 2 Monitoring API.

Demonstrates end-to-end integration:
1. Initializes the database and starts the event buffer worker.
2. Subscribes Member 2's event handler to Member 1's EventBus.
3. Boots Member 1's SecureDNSServer (UDP+TCP).
4. Serves Member 2's FastAPI monitoring API via Uvicorn.
5. Shuts down all components cleanly upon Ctrl+C.
"""
from __future__ import annotations

import asyncio
import logging
import uvicorn

from securedns.config import ResolverConfig
from securedns.events import EventBus
from securedns.monitoring.app import create_app
from securedns.monitoring.config import get_monitoring_config
from securedns.monitoring.event_handler import MonitoringEventHandler
from securedns.monitoring.repository import persist_events_batch
from securedns.server import SecureDNSServer

logger = logging.getLogger("securedns.system")


async def run_system() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    logger.info("Starting integrated SecureDNS Resolver & Security Monitoring Suite...")

    # 1. Configuration
    dns_config = ResolverConfig.from_env()
    mon_config = get_monitoring_config()

    # 2. Member 1 EventBus
    event_bus = EventBus()

    # 3. Member 2 Ingestion Handler subscribed to EventBus
    event_handler = MonitoringEventHandler(
        queue_max_size=mon_config.queue_max_size,
        batch_size=mon_config.batch_size,
        flush_interval=mon_config.flush_interval_seconds,
        persist_callback=persist_events_batch,
    )
    event_handler.subscribe_to_bus(event_bus)

    # 4. Member 1 SecureDNSServer
    dns_server = SecureDNSServer(config=dns_config, event_bus=event_bus)

    # 5. Member 2 FastAPI App
    fastapi_app = create_app(config=mon_config, event_handler=event_handler)

    # Configure Uvicorn server
    uvicorn_config = uvicorn.Config(
        app=fastapi_app,
        host=mon_config.api_host,
        port=mon_config.api_port,
        log_level="info",
    )
    api_server = uvicorn.Server(uvicorn_config)

    # Start DNS server
    await dns_server.start()
    logger.info("SecureDNS Resolver started on %s:%d (UDP+TCP)", dns_config.listen_host, dns_config.listen_port)
    logger.info("Monitoring API starting at http://%s:%d/api", mon_config.api_host, mon_config.api_port)

    # Run Uvicorn API server
    try:
        await api_server.serve()
    except (asyncio.CancelledError, KeyboardInterrupt):
        pass
    finally:
        logger.info("Initiating graceful system shutdown...")
        await dns_server.stop()
        logger.info("All SecureDNS components stopped cleanly.")


if __name__ == "__main__":
    asyncio.run(run_system())
