"""
DNS message parsing utilities.

This module provides functions to parse raw DNS wire-format messages
into structured Python dictionaries, with validation and error handling.

DNS messages travel over the network as binary (bytes).  dnspython gives
us a high-level API to decode them without touching raw binary manually.
"""

from __future__ import annotations

import dns.exception
import dns.flags
import dns.message
import dns.rdatatype


class MalformedDNSMessage(ValueError):
    """Raised when the raw bytes cannot be decoded as a valid DNS message."""


class DNSResponseReceived(ValueError):
    """Raised when a DNS response is given where a query was expected."""


class UnsupportedQuestionCount(ValueError):
    """Raised when the DNS message contains an unexpected number of questions."""


def parse_dns_query(raw_message: bytes) -> dict:
    """Parse a DNS query from wire format and return its key fields.

    Parameters
    ----------
    raw_message:
        Raw bytes received from the network (UDP payload or TCP body).

    Returns
    -------
    dict with keys:
        - ``transaction_id`` (int): 16-bit query identifier used to match
          replies back to the request that caused them.
        - ``domain`` (str): The fully-qualified domain name being queried,
          e.g. ``"example.com."``.  Note the trailing dot -- that is how DNS
          represents absolute names.
        - ``record_type`` (str): Human-readable record type, e.g. ``"A"``,
          ``"AAAA"``, ``"MX"``, ``"CNAME"``.
        - ``record_class`` (int): The DNS class.  Almost always 1 (IN =
          Internet).

    Raises
    ------
    MalformedDNSMessage
        If ``raw_message`` cannot be decoded as a DNS message at all.
    DNSResponseReceived
        If the message has the QR bit set (it is a response, not a query).
    UnsupportedQuestionCount
        If the message does not contain exactly one question section entry.
    """
    # -- Step 1: decode raw bytes ------------------------------------------
    # dns.message.from_wire() parses the binary DNS wire format.
    # It raises dns.exception.FormError for truncated or structurally
    # invalid data.
    try:
        query = dns.message.from_wire(raw_message)
    except dns.exception.FormError as exc:
        raise MalformedDNSMessage(f"Cannot decode DNS wire format: {exc}") from exc
    except Exception as exc:  # catch-all for any other dnspython error
        raise MalformedDNSMessage(f"Unexpected parse error: {exc}") from exc

    # -- Step 2: verify this is a QUERY, not a RESPONSE -------------------
    # The QR (Query/Response) flag lives in the 2-byte FLAGS field of every
    # DNS header.  0 = query, 1 = response.  We only accept queries here.
    if query.flags & dns.flags.QR:
        raise DNSResponseReceived("Expected a DNS query, not a response")

    # -- Step 3: enforce exactly one question -----------------------------
    # Standard client resolvers always send exactly one question per packet.
    # Zero questions is pointless; multiple questions are rarely supported
    # by real servers and create ambiguity in our forwarding logic.
    if len(query.question) != 1:
        raise UnsupportedQuestionCount(
            f"Expected exactly one DNS question, got {len(query.question)}"
        )

    question = query.question[0]

    return {
        # The 16-bit ID that the client chose.  We MUST echo it in the reply
        # so the client can match the answer to its original request.
        "transaction_id": query.id,
        # to_text() returns the absolute name with a trailing dot, e.g.
        # "example.com." -- this is standard DNS notation.
        "domain": question.name.to_text(),
        # Human-readable type string like "A", "AAAA", "MX", "CNAME".
        "record_type": dns.rdatatype.to_text(question.rdtype),
        # DNS class -- almost always 1 (IN = Internet class).
        "record_class": question.rdclass,
    }
