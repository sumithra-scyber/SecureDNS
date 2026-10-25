"""Unit tests for DNSForwarder – no real network access required."""
from __future__ import annotations

import asyncio
import struct

import dns.message
import dns.rdatatype
import dns.rcode
import pytest

from securedns.config import ResolverConfig
from securedns.resolver.forwarder import DNSForwarder, UpstreamError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_a_query(domain: str = "example.com") -> bytes:
    """Build a DNS A-record query in wire format."""
    return dns.message.make_query(domain, dns.rdatatype.A).to_wire()


def make_noerror_response(query_bytes: bytes) -> bytes:
    """Build a minimal NOERROR response for the given query wire bytes."""
    query = dns.message.from_wire(query_bytes)
    response = dns.message.make_response(query)
    response.set_rcode(dns.rcode.NOERROR)
    return response.to_wire()


# ---------------------------------------------------------------------------
# Fixtures – fake UDP upstream server
# ---------------------------------------------------------------------------

@pytest.fixture
async def fake_udp_upstream():
    """Spin up a local UDP server that echoes back a real NOERROR response.

    Yields the port number the server is listening on.
    """
    loop = asyncio.get_running_loop()
    response_data: dict[str, bytes] = {}  # written by test if needed

    class _FakeUDPProtocol(asyncio.DatagramProtocol):
        def __init__(self_) -> None:  # noqa: N805
            self_._transport: asyncio.DatagramTransport | None = None

        def connection_made(self_, transport):  # noqa: N805
            self_._transport = transport

        def datagram_received(self_, data: bytes, addr: tuple) -> None:  # noqa: N805
            resp = response_data.get("response") or make_noerror_response(data)
            if self_._transport is not None:
                self_._transport.sendto(resp, addr)

    transport, _ = await loop.create_datagram_endpoint(
        _FakeUDPProtocol, local_addr=("127.0.0.1", 0)
    )
    port: int = transport.get_extra_info("sockname")[1]
    yield port, response_data
    transport.close()


# ---------------------------------------------------------------------------
# Fixtures – fake TCP upstream server
# ---------------------------------------------------------------------------

@pytest.fixture
async def fake_tcp_upstream():
    """Spin up a local TCP server that handles DNS-over-TCP framing.

    Yields the port number the server is listening on.
    """
    response_data: dict[str, bytes] = {}

    async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            raw_len = await reader.readexactly(2)
            msg_len = struct.unpack("!H", raw_len)[0]
            data = await reader.readexactly(msg_len)
            resp = response_data.get("response") or make_noerror_response(data)
            writer.write(struct.pack("!H", len(resp)) + resp)
            await writer.drain()
        except asyncio.IncompleteReadError:
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
    port: int = server.sockets[0].getsockname()[1]
    async with server:
        yield port, response_data


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

async def test_forward_udp_success(fake_udp_upstream):
    """DNSForwarder.forward_udp returns a valid response from a fake upstream."""
    port, _ = fake_udp_upstream
    config = ResolverConfig(upstream_host="127.0.0.1", upstream_port=port, upstream_timeout=2.0)
    forwarder = DNSForwarder(config)

    query = make_a_query()
    response = await forwarder.forward_udp(query)

    assert len(response) >= 12  # at least a DNS header


async def test_forward_udp_timeout():
    """forward_udp raises UpstreamError when the upstream never responds."""
    # Use a port where nothing is listening; UDP won't get ICMP back reliably,
    # so we rely purely on the timeout.
    config = ResolverConfig(
        upstream_host="127.0.0.1",
        upstream_port=19999,  # hopefully nothing here
        upstream_timeout=0.2,
    )
    forwarder = DNSForwarder(config)

    with pytest.raises(UpstreamError):
        await forwarder.forward_udp(make_a_query())


async def test_forward_tcp_success(fake_tcp_upstream):
    """DNSForwarder.forward_tcp returns a valid response from a fake TCP upstream."""
    port, _ = fake_tcp_upstream
    config = ResolverConfig(upstream_host="127.0.0.1", upstream_port=port, upstream_timeout=2.0)
    forwarder = DNSForwarder(config)

    query = make_a_query()
    response = await forwarder.forward_tcp(query)

    assert len(response) >= 12


async def test_forward_tcp_connection_refused():
    """forward_tcp raises UpstreamError when the connection is actively refused."""
    config = ResolverConfig(
        upstream_host="127.0.0.1",
        upstream_port=19998,  # nothing listening here
        upstream_timeout=2.0,
    )
    forwarder = DNSForwarder(config)

    with pytest.raises(UpstreamError):
        await forwarder.forward_tcp(make_a_query())
