"""Domain blocklist with exact and subdomain matching."""
from __future__ import annotations


class DomainBlocklist:
    """Maintains a set of blocked domains and checks queries against them.

    Supports exact matching and subdomain matching:
    if ``example.com`` is blocked, then ``ads.example.com`` is also blocked.
    """

    def __init__(self, blocked_domains: set[str] | None = None) -> None:
        # Normalise: lowercase, strip trailing dots
        self._blocked: set[str] = set()
        for d in (blocked_domains or set()):
            normalised = d.lower().rstrip(".")
            if normalised:
                self._blocked.add(normalised)

    # ------------------------------------------------------------------
    # Bulk loading
    # ------------------------------------------------------------------

    def load_from_file(self, path: str) -> None:
        """Load one domain per line; skip ``#`` comments and blank lines."""
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                self.add(line)

    # ------------------------------------------------------------------
    # Query interface
    # ------------------------------------------------------------------

    def is_blocked(self, domain: str) -> bool:
        """Return True if *domain* or any of its parent domains is blocked.

        ``ads.example.com`` is blocked if ``ads.example.com``, ``example.com``
        or ``com`` appears in the blocklist.
        """
        name = domain.lower().rstrip(".")
        parts = name.split(".")
        for i in range(len(parts)):
            candidate = ".".join(parts[i:])
            if candidate in self._blocked:
                return True
        return False

    # ------------------------------------------------------------------
    # Mutation helpers
    # ------------------------------------------------------------------

    def add(self, domain: str) -> None:
        """Add a single domain to the blocklist (normalised)."""
        normalised = domain.lower().rstrip(".")
        if normalised:
            self._blocked.add(normalised)

    def remove(self, domain: str) -> None:
        """Remove a domain from the blocklist; silently ignores missing entries."""
        self._blocked.discard(domain.lower().rstrip("."))

    def size(self) -> int:
        """Return the number of entries in the blocklist."""
        return len(self._blocked)
