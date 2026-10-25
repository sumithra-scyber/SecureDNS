"""Central configuration for SecureDNS using dataclasses."""
from __future__ import annotations

from dataclasses import dataclass, field
import os


@dataclass
class ResolverConfig:
    # Upstream DNS (forwarding target)
    upstream_host: str = "8.8.8.8"
    upstream_port: int = 53
    upstream_timeout: float = 5.0

    # Local listening
    listen_host: str = "127.0.0.1"
    listen_port: int = 5300   # non-privileged port for dev

    # Cache
    cache_enabled: bool = True
    cache_capacity: int = 1000   # max entries
    cache_ttl_min: int = 30      # clamp TTL below this to this value (seconds)
    cache_ttl_max: int = 3600    # clamp TTL above this to this value

    # Security
    blocklist_file: str | None = None
    rate_limit_qps: int = 20          # queries per second per client IP
    rate_limit_burst: int = 40        # burst allowance
    max_domain_length: int = 253      # RFC 1035 limit
    suspicious_qps_threshold: int = 50  # flag if client exceeds this rate

    # Logging
    log_level: str = "INFO"

    @classmethod
    def from_env(cls) -> "ResolverConfig":
        """Build config from environment variables with sensible defaults."""
        return cls(
            upstream_host=os.getenv("SECUREDNS_UPSTREAM_HOST", "8.8.8.8"),
            upstream_port=int(os.getenv("SECUREDNS_UPSTREAM_PORT", "53")),
            upstream_timeout=float(os.getenv("SECUREDNS_TIMEOUT", "5.0")),
            listen_host=os.getenv("SECUREDNS_LISTEN_HOST", "127.0.0.1"),
            listen_port=int(os.getenv("SECUREDNS_LISTEN_PORT", "5300")),
            cache_enabled=os.getenv("SECUREDNS_CACHE", "true").lower() == "true",
            cache_capacity=int(os.getenv("SECUREDNS_CACHE_CAPACITY", "1000")),
            rate_limit_qps=int(os.getenv("SECUREDNS_RATE_LIMIT_QPS", "20")),
            rate_limit_burst=int(os.getenv("SECUREDNS_RATE_LIMIT_BURST", "40")),
            blocklist_file=os.getenv("SECUREDNS_BLOCKLIST_FILE"),
        )
