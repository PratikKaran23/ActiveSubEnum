"""
core/wildcard.py — Wildcard Subdomain Detector

Thread-safe wildcard detection using random probe names.
Uses a lock to ensure thread-safe updates to the wildcard IP set.
"""

import random
import string
from threading import Lock
from typing import List, Optional, Set


class WildcardDetector:
    """Detect and filter wildcard DNS responses.

    Probes random subdomain names and collects all IPs they resolve to.
    If multiple random names resolve to the same IP(s), it's a wildcard.
    Subdomains matching only wildcard IPs are filtered out.

    Thread-safe: uses a Lock when updating shared state from multiple threads.
    """

    def __init__(self, domain: str, pool: "ResolverPool"):
        self.domain = domain
        self.pool = pool
        self.wildcard_ips: Set[str] = set()
        self.active: bool = False
        self._lock = Lock()
        self._probes_sent: int = 0
        self._probes_hit: int = 0

    def _random_probe(self) -> str:
        """Generate a random subdomain probe name."""
        k = random.randint(8, 16)
        return f"{''.join(random.choices(string.ascii_lowercase, k=k))}.{self.domain}"

    def detect(self) -> bool:
        """Send multiple random probes to detect wildcard patterns.

        Returns True if wildcard is active, False otherwise.
        """
        from rich.console import Console
        console = Console()
        console.print("\n[bold yellow][*][/bold yellow] Wildcard Detection")

        probes = [self._random_probe() for _ in range(6)]
        for name in probes:
            from .resolver import resolve_a
            ips = resolve_a(name, self.pool)
            if ips:
                self._probes_hit += 1
                with self._lock:
                    self.wildcard_ips.update(ips)
                    self.active = True
            self._probes_sent += 1

        if self.active:
            console.print(
                f"  [bold yellow][!][/bold yellow] Wildcard detected "
                f"→ [red]{', '.join(sorted(self.wildcard_ips))}[/red]  "
                f"(will filter {self._probes_hit}/{self._probes_sent} probes)"
            )
        else:
            console.print("  [dim]No wildcard detected — clean DNS ✓[/dim]")
        return self.active

    def is_wildcard(self, ips: List[str]) -> bool:
        """Return True if ALL IPs of this subdomain overlap exclusively with wildcard IPs.

        Logic:
        - If no wildcard active → False (nothing to filter)
        - If no overlap with wildcard IPs → False (legitimate, non-wildcard subdomain)
        - If ALL IPs are in the wildcard set → True (likely a wildcard artifact)
        - If SOME IPs overlap but not ALL → False (legitimate subdomain with
          multi-homed DNS that happens to include a wildcard IP)

        This conservative approach avoids false negatives on legitimate subdomains
        that happen to share an IP with wildcard infrastructure.
        """
        if not self.active or not ips:
            return False
        with self._lock:
            overlap = set(ips) & self.wildcard_ips
            if not overlap:
                return False  # No overlap → definitely not a wildcard
            return set(ips).issubset(self.wildcard_ips)  # All IPs match wildcard set

    def get_wildcard_ips(self) -> Set[str]:
        """Return the set of known wildcard IPs (thread-safe copy)."""
        with self._lock:
            return set(self.wildcard_ips)