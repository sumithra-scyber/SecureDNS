"""Integration tests for SecureDNSServer – no real internet required.

A fake upstream UDP DNS server is spun up locally.  SecureDNSServer is
configured to forward to it.  Tests send real DNS queries via UDP to
SecureDNSServer and verify end-to-end behaviour.
"""
from __future__ import annotations

import asyncio
import socket
import struct

import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset
import dns.name
import dns.rdtypes.IN.A
import pytest

from securedns.config import ResolverConfig
from securedns.events import EventBus
from securedns.server import SecureDNSServer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_a_query(domain: str = "example.com", txid: int | None = None) -> bytes:
    q = dns.message.make_query(domain, dns.rdatatype.A)
    if txid is not None:
        q.id = txid
    return q.to_wire()


def make_noerror_response_with_a_record(query_bytes: bytes, ip: str = "1.2.3.4") -> bytes:
    """Build a NOERROR response with one A record and TTL=300."""
    query = dns.message.from_wire(query_bytes)
    response = dns.message.make_response(query)
    response.set_rcode(dns.rcode.NOERROR)

    # Add an A record to the answer section
    if query.question:
        qname = query.question[0].name
        rrset = dns.rrset.RRset(qname, dns.rdataclass.IN, dns.rdatatype.A)
        rrset.ttl = 300
        rdata = dns.rdtypes.IN.A.A(dns.rdataclass.IN, dns.rdatatype.A, ip)
        rrset.add(rdata)
        response.answer.append(rrset)

    return response.to_wire()


async def send_udp_query(host: str, port: int, raw_query: bytes, timeout: float = 2.0) -> bytes:
    """Send a raw DNS query over UDP and return the raw response."""
    loop = asyncio.get_running_loop()
    future: asyncio.Future[bytes] = loop.create_future()

    class _Proto(asyncio.DatagramProtocol):
        def datagram_received(self, data, addr):
            if not future.done():
                future.set_result(data)

    transport, _ = await loop.create_datagram_endpoint(
        _Proto, remote_addr=(host, port)
    )
    transport.sendto(raw_query)
    try:
        return await asyncio.wait_for(future, timeout=timeout)
    finally:
        transport.close()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
async def fake_upstream():
    """Fake upstream UDP DNS server that returns NOERROR with one A record.

    Yields (port, response_override_dict).
    Set ``response_override_dict["response"]`` to return a custom raw response.
    """
    loop = asyncio.get_running_loop()
    state: dict = {}  # state["response"] = bytes to override

    class _FakeUpstream(asyncio.DatagramProtocol):
        def __init__(self_) -> None:  # noqa: N805
            self_._transport = None

        def connection_made(self_, transport):  # noqa: N805
            self_._transport = transport

        def datagram_received(self_, data: bytes, addr: tuple) -> None:  # noqa: N805
            if state.get("drop"):
                return
            resp = state.get("response") or make_noerror_response_with_a_record(data)
            self_._transport.sendto(resp, addr)

    transport, _ = await loop.create_datagram_endpoint(
        _FakeUpstream, local_addr=("127.0.0.1", 0)
    )
    upstream_port: int = transport.get_extra_info("sockname")[1]
    yield upstream_port, state
    transport.close()


@pytest.fixture
async def server(fake_upstream):
    """SecureDNSServer wired to the fake upstream, running on a free local port."""
    upstream_port, state = fake_upstream
    local_port = _get_free_port()

    config = ResolverConfig(
        upstream_host="127.0.0.1",
        upstream_port=upstream_port,
        upstream_timeout=2.0,
        listen_host="127.0.0.1",
        listen_port=local_port,
        cache_enabled=True,
        cache_capacity=100,
        cache_ttl_min=1,
        cache_ttl_max=600,
        rate_limit_qps=100,
        rate_limit_burst=200,
    )
    srv = SecureDNSServer(config)
    await srv.start()
    yield srv, local_port, state
    await srv.stop()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

async def test_query_forwarded_and_responded(server):
    """A normal query reaches the fake upstream and the client gets a response."""
    srv, port, _ = server
    raw_query = make_a_query("example.com", txid=1234)
    response_bytes = await send_udp_query("127.0.0.1", port, raw_query)

    assert len(response_bytes) >= 12
    resp = dns.message.from_wire(response_bytes)
    assert resp.id == 1234
    assert resp.rcode() == dns.rcode.NOERROR


async def test_blocked_domain_returns_refused(server):
    """Querying a blocked domain returns REFUSED without hitting upstream."""
    srv, port, _ = server
    srv.blocklist.add("blocked.example.com")

    raw_query = make_a_query("blocked.example.com")
    response_bytes = await send_udp_query("127.0.0.1", port, raw_query)

    resp = dns.message.from_wire(response_bytes)
    assert resp.rcode() == dns.rcode.REFUSED


async def test_rate_limited_client_gets_refused(server):
    """Exhausting the rate limit returns REFUSED for subsequent queries."""
    srv, port, _ = server
    # Override to very tight limits for this test
    from securedns.security.rate_limiter import TokenBucketRateLimiter
    srv.rate_limiter = TokenBucketRateLimiter(rate=1, burst=1)

    client_ip = "127.0.0.1"

    # First query should succeed
    raw_query = make_a_query("allowed.com")
    resp1 = await send_udp_query("127.0.0.1", port, raw_query)
    msg1 = dns.message.from_wire(resp1)
    assert msg1.rcode() == dns.rcode.NOERROR

    # Subsequent queries before refill should be refused
    raw_query2 = make_a_query("allowed.com", txid=999)
    resp2 = await send_udp_query("127.0.0.1", port, raw_query2)
    msg2 = dns.message.from_wire(resp2)
    assert msg2.rcode() == dns.rcode.REFUSED


async def test_cached_response_returned_on_second_query(server):
    """The second query for the same domain hits the cache."""
    srv, port, state = server
    # Ensure cache is enabled
    assert srv.cache is not None

    # First query – goes to upstream
    raw_query = make_a_query("cached.example.com", txid=100)
    resp1 = await send_udp_query("127.0.0.1", port, raw_query)
    msg1 = dns.message.from_wire(resp1)
    assert msg1.rcode() == dns.rcode.NOERROR

    # Make the upstream drop all packets; second query must be served from cache
    state["drop"] = True
    raw_query2 = make_a_query("cached.example.com", txid=200)
    resp2 = await send_udp_query("127.0.0.1", port, raw_query2)
    msg2 = dns.message.from_wire(resp2)

    # Transaction ID should match the second query
    assert msg2.id == 200
    assert msg2.rcode() == dns.rcode.NOERROR

    # Cache should have registered a hit
    stats = srv.cache.stats()
    assert stats["hits"] >= 1


async def test_malformed_query_returns_servfail(server):
    """A malformed query (random bytes) returns SERVFAIL."""
    srv, port, _ = server

    # Build something that looks like a DNS header but is actually garbage.
    # We need 12+ bytes so dnspython parses the header, but make the question
    # section invalid.  Simplest: just send garbage bytes.
    raw_garbage = b"\x12\x34" + b"\x00" * 4 + b"\x00\x01" + b"\x00" * 4 + b"\xff\xff\xff"
    response_bytes = await send_udp_query("127.0.0.1", port, raw_garbage)

    # The server builds a minimal 12-byte SERVFAIL when it cannot parse the
    # query with dnspython.  Check the transaction ID echo and RCODE bytes.
    assert len(response_bytes) >= 4
    import struct
    txid = struct.unpack("!H", response_bytes[:2])[0]
    flags = struct.unpack("!H", response_bytes[2:4])[0]
    rcode = flags & 0x000F
    assert txid == 0x1234          # transaction ID echoed back
    assert rcode == 2              # SERVFAIL = 2
