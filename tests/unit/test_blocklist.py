"""Unit tests for DomainBlocklist."""
from __future__ import annotations

import pytest

from securedns.security.blocklist import DomainBlocklist


def test_exact_domain_blocked():
    bl = DomainBlocklist({"ads.example.com"})
    assert bl.is_blocked("ads.example.com") is True


def test_subdomain_of_blocked_domain_is_blocked():
    bl = DomainBlocklist({"example.com"})
    assert bl.is_blocked("ads.example.com") is True
    assert bl.is_blocked("deep.sub.example.com") is True


def test_unrelated_domain_not_blocked():
    bl = DomainBlocklist({"evil.com"})
    assert bl.is_blocked("good.com") is False
    assert bl.is_blocked("example.com") is False


def test_case_insensitive_matching():
    bl = DomainBlocklist({"Evil.Com"})
    assert bl.is_blocked("evil.com") is True
    assert bl.is_blocked("Sub.EVIL.COM") is True


def test_trailing_dot_normalised():
    bl = DomainBlocklist({"example.com."})
    # Query with trailing dot should still match
    assert bl.is_blocked("example.com.") is True
    assert bl.is_blocked("example.com") is True
    # Subdomain with trailing dot
    assert bl.is_blocked("sub.example.com.") is True


def test_add_and_remove():
    bl = DomainBlocklist()
    assert bl.is_blocked("new.com") is False

    bl.add("new.com")
    assert bl.is_blocked("new.com") is True
    assert bl.size() == 1

    bl.remove("new.com")
    assert bl.is_blocked("new.com") is False
    assert bl.size() == 0


def test_load_from_file(tmp_path):
    """load_from_file should parse domains, skip comments and blank lines."""
    blocklist_file = tmp_path / "blocklist.txt"
    blocklist_file.write_text(
        "# This is a comment\n"
        "\n"
        "evil.com\n"
        "  \n"
        "# Another comment\n"
        "malware.net\n"
        "Ads.BadSite.Org\n",
        encoding="utf-8",
    )

    bl = DomainBlocklist()
    bl.load_from_file(str(blocklist_file))

    assert bl.is_blocked("evil.com") is True
    assert bl.is_blocked("sub.evil.com") is True
    assert bl.is_blocked("malware.net") is True
    assert bl.is_blocked("ads.badsite.org") is True
    assert bl.is_blocked("safe.com") is False
    assert bl.size() == 3
