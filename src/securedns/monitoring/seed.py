"""Synthetic seed data generator for testing and demoing the SecureDNS dashboard.

All generated records are explicitly tagged with `is_synthetic = True` so they
can never be confused with genuine runtime resolver events.
"""
from __future__ import annotations

import asyncio
import random
from datetime import datetime, timedelta, timezone

from securedns.monitoring.database import get_engine, init_db
from securedns.monitoring.repository import persist_events_batch

POPULAR_DOMAINS = [
    "google.com",
    "github.com",
    "cloudflare.com",
    "microsoft.com",
    "amazon.com",
    "wikipedia.org",
    "apple.com",
    "netflix.com",
    "reddit.com",
    "stackoverflow.com",
]

MALICIOUS_DOMAINS = [
    "malware-traffic-analysis.net",
    "phishing-update-login.xyz",
    "crypto-stealer-botnet.biz",
    "c2-command-server.ru",
    "data-exfiltration-tunnel.cc",
    "suspicious-dns-payload.top",
    "ad-tracker-network.online",
]

CLIENT_IPS = [
    "192.168.1.10",
    "192.168.1.25",
    "192.168.1.42",
    "10.0.0.15",
    "10.0.0.88",
    "172.16.5.99",
]

ATTACKER_IPS = [
    "203.0.113.195",
    "198.51.100.44",
    "192.0.2.111",
]


def generate_synthetic_events(count: int = 300, hours: int = 24) -> list[dict]:
    """Generate realistic synthetic security events spread over the past `hours`."""
    now = datetime.now(timezone.utc)
    records: list[dict] = []
    rng = random.Random(42)  # Deterministic seed for reproducible testing

    for _ in range(count):
        # Random timestamp within the last `hours`
        seconds_ago = rng.uniform(0, hours * 3600)
        ts = now - timedelta(seconds=seconds_ago)

        roll = rng.random()
        if roll < 0.60:
            # 60% normal queries & cache lookups
            domain = rng.choice(POPULAR_DOMAINS)
            client_ip = rng.choice(CLIENT_IPS)
            record_type = rng.choice(["A", "AAAA", "CNAME"])

            records.append({
                "event_type": "query_received",
                "timestamp": ts,
                "severity": "info",
                "action_taken": "RECEIVED",
                "domain": domain,
                "client_ip": client_ip,
                "record_type": record_type,
                "metadata_json": {"transaction_id": rng.randint(1000, 65535), "transport": "udp"},
                "is_synthetic": True,
            })

            # Follow up with cache hit or upstream resolve
            if rng.random() < 0.70:
                records.append({
                    "event_type": "cache_hit",
                    "timestamp": ts + timedelta(milliseconds=2),
                    "severity": "info",
                    "action_taken": "CACHE_HIT",
                    "domain": domain,
                    "client_ip": client_ip,
                    "record_type": record_type,
                    "metadata_json": {},
                    "is_synthetic": True,
                })
            else:
                latency = rng.uniform(8.0, 45.0)
                records.append({
                    "event_type": "upstream_success",
                    "timestamp": ts + timedelta(milliseconds=latency),
                    "severity": "info",
                    "action_taken": "RESOLVED",
                    "domain": domain,
                    "client_ip": client_ip,
                    "record_type": record_type,
                    "metadata_json": {"upstream_host": "8.8.8.8", "latency_ms": round(latency, 2)},
                    "is_synthetic": True,
                })

        elif roll < 0.80:
            # 20% Blocked requests
            domain = rng.choice(MALICIOUS_DOMAINS)
            client_ip = rng.choice(CLIENT_IPS + ATTACKER_IPS)
            records.append({
                "event_type": "blocked_request",
                "timestamp": ts,
                "severity": "high",
                "action_taken": "BLOCKED",
                "domain": domain,
                "client_ip": client_ip,
                "record_type": "A",
                "metadata_json": {"reason": "Domain found in active blocklist"},
                "is_synthetic": True,
            })

        elif roll < 0.92:
            # 12% Rate-limited requests
            client_ip = rng.choice(ATTACKER_IPS)
            domain = rng.choice(POPULAR_DOMAINS)
            records.append({
                "event_type": "rate_limited",
                "timestamp": ts,
                "severity": "medium",
                "action_taken": "RATE_LIMITED",
                "domain": domain,
                "client_ip": client_ip,
                "record_type": "A",
                "metadata_json": {"reason": "Token bucket exhausted (exceeded QPS limit)"},
                "is_synthetic": True,
            })

        else:
            # 8% Suspicious activity (tunneling, excessive label length, flood)
            client_ip = rng.choice(ATTACKER_IPS)
            domain = f"exfil-{rng.randint(100000, 999999)}.tunneling.biz"
            records.append({
                "event_type": "suspicious_activity",
                "timestamp": ts,
                "severity": "critical",
                "action_taken": "FLAGGED",
                "domain": domain,
                "client_ip": client_ip,
                "record_type": "TXT",
                "metadata_json": {
                    "warnings": [
                        "Domain length exceeds limit (potential DNS tunneling)",
                        f"Client {client_ip} QPS 64.0 exceeds threshold 50",
                    ]
                },
                "is_synthetic": True,
            })

    # Sort oldest to newest
    records.sort(key=lambda r: r["timestamp"])
    return records


async def seed_database(count: int = 300, hours: int = 24) -> int:
    """Initialize DB tables and populate with synthetic seed data."""
    await init_db()
    records = generate_synthetic_events(count=count, hours=hours)
    inserted = await persist_events_batch(records)
    print(f"Successfully seeded {inserted} synthetic events into database.")
    return inserted


if __name__ == "__main__":
    asyncio.run(seed_database())
