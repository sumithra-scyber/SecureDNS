"""Async DNS forwarder: forwards queries to upstream and returns responses."""
from __future__ import annotations

import asyncio
import struct

import dns.exception
import dns.flags
import dns.message

from securedns.config import ResolverConfig


class UpstreamError(Exception):
    """Raised when the upstream DNS server is unreachable or returns invalid data."""


class DNSForwarder:
    """Forwards raw DNS query bytes to an upstream resolver and returns the response."""

    def __init__(self, config: ResolverConfig) -> None:
        self.config = config

    # ------------------------------------------------------------------
    # UDP forwarding
    # ------------------------------------------------------------------

    async def forward_udp(self, raw_query: bytes) -> bytes:
        """Forward *raw_query* to the upstream server via UDP.

        Returns the raw response bytes.  Raises :exc:`UpstreamError` on
        timeout or transport-level failure.
        """
        loop = asyncio.get_running_loop()
        future: asyncio.Future[bytes] = loop.create_future()

        class _Protocol(asyncio.DatagramProtocol):
            def datagram_received(self, data: bytes, addr: tuple) -> None:  # noqa: N805
                if not future.done():
                    future.set_result(data)

            def error_received(self, exc: Exception) -> None:  # noqa: N805
                if not future.done():
                    future.set_exception(UpstreamError(str(exc)))

            def connection_lost(self, exc: Exception | None) -> None:  # noqa: N805
                if not future.done():
                    future.set_exception(UpstreamError("Connection lost"))

        transport, _ = await loop.create_datagram_endpoint(
            _Protocol,
            remote_addr=(self.config.upstream_host, self.config.upstream_port),
        )
        transport.sendto(raw_query)
        try:
            return await asyncio.wait_for(
                future, timeout=self.config.upstream_timeout
            )
        except (TimeoutError, asyncio.TimeoutError):
            raise UpstreamError(
                f"UDP timeout after {self.config.upstream_timeout}s"
            )
        finally:
            transport.close()

    # ------------------------------------------------------------------
    # TCP forwarding
    # ------------------------------------------------------------------

    async def forward_tcp(self, raw_query: bytes) -> bytes:
        """Forward *raw_query* to the upstream server via TCP.

        DNS-over-TCP (RFC 1035 §4.2.2): each message is prefixed with a
        2-byte big-endian length field.

        Returns the raw response bytes.  Raises :exc:`UpstreamError` on
        connection failure, timeout, or incomplete read.
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self.config.upstream_host, self.config.upstream_port
                ),
                timeout=self.config.upstream_timeout,
            )
        except (TimeoutError, asyncio.TimeoutError, OSError) as exc:
            raise UpstreamError(f"TCP connect failed: {exc}") from exc

        try:
            # Send: 2-byte length prefix + query
            length_prefix = struct.pack("!H", len(raw_query))
            writer.write(length_prefix + raw_query)
            await writer.drain()

            # Receive: read 2-byte length, then that many bytes
            raw_len = await asyncio.wait_for(
                reader.readexactly(2), timeout=self.config.upstream_timeout
            )
            resp_len = struct.unpack("!H", raw_len)[0]
            response = await asyncio.wait_for(
                reader.readexactly(resp_len), timeout=self.config.upstream_timeout
            )
            return response
        except (asyncio.IncompleteReadError, TimeoutError, asyncio.TimeoutError, OSError) as exc:
            raise UpstreamError(f"TCP read failed: {exc}") from exc
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Unified entry point with automatic fallback
    # ------------------------------------------------------------------

    async def forward(self, raw_query: bytes, prefer_tcp: bool = False) -> bytes:
        """Forward a DNS query, falling back from UDP to TCP when needed.

        If *prefer_tcp* is True, skips UDP entirely.  Otherwise tries UDP
        first and retries over TCP when:

        * The response has the TC (truncation) flag set, or
        * The UDP attempt raises :exc:`UpstreamError`.
        """
        if prefer_tcp:
            return await self.forward_tcp(raw_query)

        try:
            response = await self.forward_udp(raw_query)
            # If the response is truncated, retry over TCP
            try:
                msg = dns.message.from_wire(response)
                if msg.flags & dns.flags.TC:
                    return await self.forward_tcp(raw_query)
            except dns.exception.DNSException:
                pass  # can't parse – return as-is and let caller handle it
            return response
        except UpstreamError:
            # UDP failed – fall back to TCP
            return await self.forward_tcp(raw_query)
