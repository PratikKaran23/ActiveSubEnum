"""
core/saturation.py — Saturation Detector (Part 10, Q9)

Monitors discovery rate across techniques and warns when the scan is
approaching diminishing returns. Pro hunters know when to stop.

Metrics tracked:
  - new subs found per technique
  - discovery_rate = new_found / time_spent (subs/minute)
  - Consecutive techniques with low/no discovery

Signals:
  - NEAR SATURATION: rate < 0.1 subs/min for 3 consecutive techniques
  - SATURATED: zero discovery in last 2 techniques
  - ACTIVE: good discovery rate
"""

from dataclasses import dataclass, field
from typing import Dict, List

from rich.console import Console


@dataclass
class TechniqueStats:
    name: str
    found: int = 0
    start: float = 0.0
    end: float = 0.0

    @property
    def elapsed(self) -> float:
        if self.start and self.end:
            return max(0.1, self.end - self.start)
        return 0.1  # minimum 0.1s to avoid division by zero

    @property
    def rate(self) -> float:
        """Subs per minute."""
        return (self.found / self.elapsed) * 60


class SaturationDetector:
    """Monitor discovery rate and detect when enumeration is saturating."""

    def __init__(
        self,
        low_rate_threshold: float = 0.1,  # subs/min
        consecutive_low_count: int = 3,
        zero_count: int = 2,
    ):
        self.low_rate_threshold = low_rate_threshold
        self.consecutive_low_count = consecutive_low_count
        self.zero_count = zero_count
        self.stats: List[TechniqueStats] = []
        self._console = Console()

    def record(self, name: str, found: int, start: float, end: float):
        """Record a technique's stats."""
        stats = TechniqueStats(name=name, found=found, start=start, end=end)
        self.stats.append(stats)

    def _compute_status(self) -> tuple:
        """Compute saturation status from recorded stats.

        Returns (status: str, rate: float, message: str)
        """
        if len(self.stats) < 2:
            return "ACTIVE", 0.0, ""

        # Look at last N techniques
        recent = self.stats[-self.consecutive_low_count:]
        if len(recent) < self.consecutive_low_count:
            return "ACTIVE", 0.0, ""

        rates = [s.rate for s in recent]
        avg_rate = sum(rates) / len(rates)

        # Check for zero discovery
        zero_in_last = sum(1 for s in recent if s.found == 0)

        # Check consecutive techniques with low discovery
        low_count = sum(1 for r in rates if r < self.low_rate_threshold)

        if zero_in_last >= self.zero_count:
            return "SATURATED", avg_rate, (
                f"No new subdomains in last {self.consecutive_low_count} techniques. "
                f"Enumeration likely saturated for current wordlist. "
                f"Try: (1) larger wordlist, (2) different techniques, "
                f"(3) target-specific wordlist from tools/build_wordlist.py"
            )
        elif low_count >= self.consecutive_low_count:
            return "NEAR_SATURATION", avg_rate, (
                f"Discovery rate dropping to {avg_rate:.1f} subs/min. "
                f"Near saturation for current wordlist. "
                f"Consider stopping or switching to a larger wordlist."
            )
        else:
            return "ACTIVE", avg_rate, ""

    def check(self) -> Dict:
        """Check saturation and return status dict.

        Also prints a warning to console if needed.
        """
        status, rate, message = self._compute_status()

        result = {
            "status": status,
            "rate": rate,
            "message": message,
        }

        if status in ("SATURATED", "NEAR_SATURATION"):
            self._console.print(f"\n[bold yellow][~] SATURATION WARNING:[/bold yellow] {message}\n")

        return result

    def last_n_rates(self, n: int = 3) -> List[float]:
        """Return the last N technique discovery rates."""
        return [s.rate for s in self.stats[-n:]] if len(self.stats) >= n else []