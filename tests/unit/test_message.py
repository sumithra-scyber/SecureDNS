"""
Unit tests for the DNS message parser (securedns.resolver.message).

Each test is self-contained and requires NO network access -- dnspython
builds real DNS wire-format bytes locally.
"""

import pytest
import dns.flags
import dns.message
import dns.rdatatype

from securedns.resolver.message import (
    parse_dns_query,
    MalformedDNSMessage,
    DNSResponseReceived,
    UnsupportedQuestionCount,
)


# ---------------------------------------------------------------------------
# Happy-path tests: well-formed queries of various record types
# ---------------------------------------------------------------------------

def test_parse_a_query():
    """A record query (IPv4 address lookup) -- the most common DNS query."""
    query = dns.message.make_query("example.com", dns.rdatatype.A)

    result = parse_dns_query(query.to_wire())

    assert result["transaction_id"] == query.id
    assert result["domain"] == "example.com."   # trailing dot = absolute name
    assert result["record_type"] == "A"
    assert result["record_class"] == 1           # 1 = IN (Internet class)


def test_parse_aaaa_query():
    """AAAA record query (IPv6 address lookup)."""
    query = dns.message.make_query("example.com", dns.rdatatype.AAAA)

    result = parse_dns_query(query.to_wire())

    assert result["domain"] == "example.com."
    assert result["record_type"] == "AAAA"


def test_parse_cname_query():
    """CNAME query -- clients ask for aliases, e.g. www.example.com -> example.com."""
    query = dns.message.make_query("www.example.com", dns.rdatatype.CNAME)

    result = parse_dns_query(query.to_wire())

    assert result["domain"] == "www.example.com."
    assert result["record_type"] == "CNAME"


def test_parse_mx_query():
    """MX record query -- used for mail server discovery."""
    query = dns.message.make_query("example.com", dns.rdatatype.MX)

    result = parse_dns_query(query.to_wire())

    assert result["domain"] == "example.com."
    assert result["record_type"] == "MX"


def test_transaction_id_is_preserved():
    """The transaction ID in the parsed result must match the original query.

    Why this matters: when we forward a query and get a response, we must
    send back the ORIGINAL client's transaction ID, not the upstream's ID.
    """
    query = dns.message.make_query("example.com", dns.rdatatype.A)
    # dnspython auto-assigns a random 16-bit ID; we read it back to verify.
    result = parse_dns_query(query.to_wire())
    assert result["transaction_id"] == query.id
    assert 0 <= result["transaction_id"] <= 65535  # must fit in 16 bits


# ---------------------------------------------------------------------------
# Error-path tests: malformed or semantically wrong messages
# ---------------------------------------------------------------------------

def test_rejects_truncated_bytes():
    """Garbage / truncated bytes must raise MalformedDNSMessage.

    A real attacker or buggy client might send random bytes.  We must not
    crash -- we raise a specific exception so the caller can log and drop
    the packet gracefully.
    """
    with pytest.raises(MalformedDNSMessage):
        parse_dns_query(b"this is not a dns message at all!!")


def test_rejects_empty_bytes():
    """Empty payload is clearly malformed."""
    with pytest.raises(MalformedDNSMessage):
        parse_dns_query(b"")


def test_rejects_too_short_header():
    """A DNS header is 12 bytes minimum; anything shorter is invalid."""
    with pytest.raises(MalformedDNSMessage):
        parse_dns_query(b"\x00" * 5)


def test_rejects_dns_response():
    """If a DNS *response* is passed where we expect a query, raise DNSResponseReceived.

    Why this matters: a forged or misrouted response must not be re-processed
    as a new query.  This prevents response-injection attacks.
    """
    # Build a real response by toggling the QR bit on a query.
    query = dns.message.make_query("example.com", dns.rdatatype.A)
    response = dns.message.make_response(query)
    # make_response() already sets the QR flag -- this IS a response.

    with pytest.raises(DNSResponseReceived):
        parse_dns_query(response.to_wire())


def test_rejects_zero_questions():
    """A DNS message with zero questions is technically valid wire format
    but useless to us as a resolver -- we reject it explicitly.

    Why: forwarding a zero-question message to upstream would be pointless
    and could confuse upstream servers.
    """
    # Build a query and manually remove all questions.
    query = dns.message.make_query("example.com", dns.rdatatype.A)
    query.question.clear()

    with pytest.raises(UnsupportedQuestionCount):
        parse_dns_query(query.to_wire())
