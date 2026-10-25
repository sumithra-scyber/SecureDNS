"""Anomaly and suspicious query pattern detection."""
from __future__ import annotations


class QueryInspector:
    """Detects suspicious DNS query patterns.

    Checks performed:
    - Domain names exceeding RFC maximum length (possible DNS tunneling)
    - Individual labels exceeding 63 characters (RFC 1035)
    - Excessive query rates that may indicate DDoS or tunneling
    """

    def __init__(
        self,
        max_domain_length: int = 253,
        suspicious_qps_threshold: int = 50,
    ) -> None:
        self.max_domain_length = max_domain_length
        self.suspicious_qps_threshold = suspicious_qps_threshold

    def inspect(self, domain: str, client_ip: str, client_qps: float) -> list[str]:
        """Inspect a query and return a list of warning strings.

        An empty list means nothing suspicious was detected.

        Parameters
        ----------
        domain:
            The fully-qualified domain name being queried (trailing dot OK).
        client_ip:
            The IP address of the querying client (used in warning messages).
        client_qps:
            The current estimated queries-per-second rate for *client_ip*.
        """
        warnings: list[str] = []
        name = domain.rstrip(".")

        # Check 1: total domain length (RFC 1035 §2.3.4 limits to 253 chars)
        if len(name) > self.max_domain_length:
            warnings.append(
                f"Domain length {len(name)} exceeds limit {self.max_domain_length}"
            )

        # Check 2: individual label length (each label max 63 chars)
        for label in name.split("."):
            if len(label) > 63:
                warnings.append(
                    f"Label '{label[:20]}...' exceeds 63-char RFC limit"
                )
                break  # one warning is enough

        # Check 3: excessive query rate
        if client_qps > self.suspicious_qps_threshold:
            warnings.append(
                f"Client {client_ip} QPS {client_qps:.1f} exceeds threshold "
                f"{self.suspicious_qps_threshold}"
            )

        return warnings
