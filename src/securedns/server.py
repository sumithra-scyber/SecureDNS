"""Main SecureDNS async server.

Ties together the forwarder, TTL cache, blocklist, rate limiter, and
inspector into a single UDP+TCP DNS server.
"""
from __future__ import annotations

import asyncio
import logging
import struct
import time
from typing import Optional

import dns.message
import dns.rcode

from securedns.cache.ttl_cache import TTLCache
from securedns.config import ResolverConfig
from securedns.events import (
    EventBus,
    BlockedRequestEvent,
    CacheHitEvent,
    CacheMissEvent,
    QueryReceivedEvent,
    RateLimitedEvent,
    ServerStartEvent,
    ServerStopEvent,
    SuspiciousActivityEvent,
    UpstreamFailureEvent,
    UpstreamSuccessEvent,
)
from securedns.resolver.forwarder import DNSForwarder, UpstreamError
from securedns.resolver.message import (
    MalformedDNSMessage,
    DNSResponseReceived,
    UnsupportedQuestionCount,
    parse_dns_query,
)
from securedns.security.blocklist import DomainBlocklist
from securedns.security.inspector import QueryInspector
from securedns.security.rate_limiter import TokenBucketRateLimiter

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helper response builders
# ---------------------------------------------------------------------------

def make_refused_response(raw_query: bytes) -> bytes:
    """Build a REFUSED DNS response for the given raw query bytes.

    Falls back to a minimal REFUSED header if the query cannot be parsed.
    """
    try:
        query = dns.message.from_wire(raw_query)
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.REFUSED)
        return response.to_wire()
    except Exception:
        import struct as _struct
        txid = _struct.unpack("!H", raw_query[:2])[0] if len(raw_query) >= 2 else 0
        # FLAGS: QR=1, OPCODE=0, RCODE=5 (REFUSED)
        flags = 0x8185
        return _struct.pack("!HHHHHH", txid, flags, 0, 0, 0, 0)


def make_servfail_response(raw_query: bytes) -> bytes:
    """Build a SERVFAIL DNS response for the given raw query bytes.

    If the query cannot be parsed (e.g. it is completely malformed), a
    minimal SERVFAIL response is synthesised using only the 2-byte
    transaction ID from the raw bytes (or ID=0 if even that is absent).
    """
    try:
        query = dns.message.from_wire(raw_query)
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.SERVFAIL)
        return response.to_wire()
    except Exception:
        # Build a bare-minimum SERVFAIL header (12 bytes):
        #   ID (2) | FLAGS=0x8182 QR+SERVFAIL (2) | QDCOUNT=0 (2)
        #   | ANCOUNT=0 (2) | NSCOUNT=0 (2) | ARCOUNT=0 (2)
        import struct as _struct
        txid = _struct.unpack("!H", raw_query[:2])[0] if len(raw_query) >= 2 else 0
        # FLAGS: QR=1, OPCODE=0, AA=0, TC=0, RD=1, RA=0, Z=0, RCODE=2 (SERVFAIL)
        flags = 0x8182
        return _struct.pack("!HHHHHH", txid, flags, 0, 0, 0, 0)


def _rewrite_transaction_id(response_bytes: bytes, new_id: int) -> bytes:
    """Replace the first 2 bytes (transaction ID) in a DNS wire-format message."""
    if len(response_bytes) < 2:
        return response_bytes
    return struct.pack("!H", new_id) + response_bytes[2:]


def _get_min_ttl(msg: dns.message.Message) -> int:
    """Return the minimum TTL across all answer RRsets, or 0 if no answers."""
    ttls = [rrset.ttl for rrset in msg.answer]
    return min(ttls) if ttls else 0


# ---------------------------------------------------------------------------
# Main server class
# ---------------------------------------------------------------------------

class SecureDNSServer:
    """Async DNS server that proxies queries to an upstream resolver.

    Features:
    - UDP + TCP listeners
    - TTL-respecting LRU response cache
    - Domain blocklist (exact + subdomain matching)
    - Per-client token-bucket rate limiter
    - Anomaly/suspicious-pattern inspector
    - EventBus integration for monitoring
    """

    def __init__(
        self,
        config: ResolverConfig,
        event_bus: Optional[EventBus] = None,
    ) -> None:
        self.config = config
        self.event_bus = event_bus or EventBus()
        self.forwarder = DNSForwarder(config)
        self.cache: Optional[TTLCache] = (
            TTLCache(capacity=config.cache_capacity) if config.cache_enabled else None
        )
        self.blocklist = DomainBlocklist()
        if config.blocklist_file:
            self.blocklist.load_from_file(config.blocklist_file)
        self.rate_limiter = TokenBucketRateLimiter(
            rate=config.rate_limit_qps,
            burst=config.rate_limit_burst,
        )
        self.inspector = QueryInspector(
            max_domain_length=config.max_domain_length,
            suspicious_qps_threshold=config.suspicious_qps_threshold,
        )
        self._udp_transport: Optional[asyncio.DatagramTransport] = None
        self._tcp_server: Optional[asyncio.Server] = None

    # ------------------------------------------------------------------
    # Core query handler
    # ------------------------------------------------------------------

    async def handle_query(
        self, raw_data: bytes, client_ip: str, transport: str = "udp"
    ) -> bytes:
        """Process one DNS query end-to-end and return raw response bytes."""

        # 1. Parse the query -------------------------------------------------
        try:
            parsed = parse_dns_query(raw_data)
        except (MalformedDNSMessage, DNSResponseReceived, UnsupportedQuestionCount) as exc:
            logger.warning("Bad query from %s: %s", client_ip, exc)
            return make_servfail_response(raw_data)

        domain: str = parsed["domain"]
        record_type: str = parsed["record_type"]
        txid: int = parsed["transaction_id"]

        # 2. Publish query-received event ------------------------------------
        self.event_bus.publish(
            QueryReceivedEvent(
                client_ip=client_ip,
                transaction_id=txid,
                domain=domain,
                record_type=record_type,
                transport=transport,
            )
        )

        # 3. Rate limiting ---------------------------------------------------
        if not self.rate_limiter.is_allowed(client_ip):
            logger.info("Rate limited: %s", client_ip)
            self.event_bus.publish(
                RateLimitedEvent(
                    client_ip=client_ip,
                    domain=domain,
                    record_type=record_type,
                )
            )
            return make_refused_response(raw_data)

        # 4. Blocklist check -------------------------------------------------
        if self.blocklist.is_blocked(domain):
            logger.info("Blocked domain: %s from %s", domain, client_ip)
            self.event_bus.publish(
                BlockedRequestEvent(
                    client_ip=client_ip,
                    domain=domain,
                    record_type=record_type,
                )
            )
            return make_refused_response(raw_data)

        # 5. Anomaly inspection (non-blocking; generates warnings only) -------
        client_qps = self.rate_limiter.get_rate(client_ip)
        warnings = self.inspector.inspect(domain, client_ip, client_qps)
        if warnings:
            logger.warning("Suspicious activity from %s: %s", client_ip, warnings)
            self.event_bus.publish(
                SuspiciousActivityEvent(
                    client_ip=client_ip,
                    domain=domain,
                    warnings=warnings,
                )
            )

        # 6. Cache lookup ----------------------------------------------------
        cache_key = (domain, record_type)
        if self.cache is not None:
            cached = self.cache.get(cache_key)
            if cached is not None:
                logger.debug("Cache HIT: %s %s", domain, record_type)
                self.event_bus.publish(
                    CacheHitEvent(
                        domain=domain,
                        record_type=record_type,
                        client_ip=client_ip,
                    )
                )
                # IMPORTANT: rewrite transaction ID to match the client's request
                return _rewrite_transaction_id(cached, txid)

            logger.debug("Cache MISS: %s %s", domain, record_type)
            self.event_bus.publish(
                CacheMissEvent(
                    domain=domain,
                    record_type=record_type,
                    client_ip=client_ip,
                )
            )

        # 7. Forward to upstream ---------------------------------------------
        t0 = time.monotonic()
        try:
            response = await self.forwarder.forward(raw_data)
        except UpstreamError as exc:
            logger.error("Upstream failed: %s", exc)
            self.event_bus.publish(
                UpstreamFailureEvent(
                    domain=domain,
                    record_type=record_type,
                    upstream_host=self.config.upstream_host,
                    error=str(exc),
                )
            )
            return make_servfail_response(raw_data)

        latency_ms = (time.monotonic() - t0) * 1000
        self.event_bus.publish(
            UpstreamSuccessEvent(
                domain=domain,
                record_type=record_type,
                upstream_host=self.config.upstream_host,
                latency_ms=latency_ms,
            )
        )

        # 8. Cache the response ----------------------------------------------
        try:
            resp_msg = dns.message.from_wire(response)
            min_ttl = _get_min_ttl(resp_msg)
            if self.cache is not None and min_ttl > 0:
                ttl = max(
                    self.config.cache_ttl_min,
                    min(self.config.cache_ttl_max, min_ttl),
                )
                self.cache.put(cache_key, response, ttl)
        except Exception as exc:
            logger.warning("Could not parse upstream response for caching: %s", exc)

        return response

    # ------------------------------------------------------------------
    # Server lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start both the UDP and TCP listeners."""
        loop = asyncio.get_running_loop()

        # -- UDP server ------------------------------------------------------
        server_ref = self  # capture for nested class

        class _UDPProtocol(asyncio.DatagramProtocol):
            def __init__(self_) -> None:  # noqa: N805
                self_._transport: asyncio.DatagramTransport | None = None

            def connection_made(self_, transport: asyncio.DatagramTransport) -> None:  # noqa: N805
                self_._transport = transport

            def datagram_received(self_, data: bytes, addr: tuple) -> None:  # noqa: N805
                asyncio.ensure_future(self_._handle_udp(data, addr))

            async def _handle_udp(self_, data: bytes, addr: tuple) -> None:  # noqa: N805
                response = await server_ref.handle_query(data, addr[0], transport="udp")
                if response and self_._transport is not None:
                    self_._transport.sendto(response, addr)

        transport, _ = await loop.create_datagram_endpoint(
            _UDPProtocol,
            local_addr=(self.config.listen_host, self.config.listen_port),
        )
        self._udp_transport = transport

        # -- TCP server ------------------------------------------------------
        async def handle_tcp_client(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            peer = writer.get_extra_info("peername")
            client_ip: str = peer[0] if peer else "unknown"
            try:
                while True:
                    raw_len_bytes = await asyncio.wait_for(
                        reader.readexactly(2), timeout=30
                    )
                    msg_len = struct.unpack("!H", raw_len_bytes)[0]
                    raw_data = await asyncio.wait_for(
                        reader.readexactly(msg_len), timeout=30
                    )
                    response = await self.handle_query(raw_data, client_ip, transport="tcp")
                    if response:
                        writer.write(struct.pack("!H", len(response)) + response)
                        await writer.drain()
            except (asyncio.IncompleteReadError, TimeoutError, asyncio.TimeoutError, ConnectionResetError):
                pass
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

        self._tcp_server = await asyncio.start_server(
            handle_tcp_client,
            self.config.listen_host,
            self.config.listen_port,
        )

        self.event_bus.publish(
            ServerStartEvent(
                listen_host=self.config.listen_host,
                listen_port=self.config.listen_port,
            )
        )
        logger.info(
            "SecureDNS listening on %s:%d (UDP+TCP)",
            self.config.listen_host,
            self.config.listen_port,
        )

    async def stop(self) -> None:
        """Gracefully shut down both listeners."""
        if self._udp_transport:
            self._udp_transport.close()
        if self._tcp_server:
            self._tcp_server.close()
            await self._tcp_server.wait_closed()
        self.event_bus.publish(
            ServerStopEvent(
                listen_host=self.config.listen_host,
                listen_port=self.config.listen_port,
            )
        )
        logger.info("SecureDNS stopped.")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

async def main() -> None:
    """Entry point for running the server from the command line."""
    logging.basicConfig(level=logging.INFO)
    config = ResolverConfig.from_env()
    server = SecureDNSServer(config)
    await server.start()
    try:
        await asyncio.sleep(float("inf"))
    except (asyncio.CancelledError, KeyboardInterrupt):
        await server.stop()


if __name__ == "__main__":
    asyncio.run(main())
