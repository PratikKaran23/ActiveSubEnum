"""
techniques/base.py — Base Technique Abstract Class

All technique modules must subclass BaseTechnique.
This ensures a consistent interface across all 15 techniques.

Each technique MUST implement:
  name        — Short name (e.g. "DNS Brute Force")
  aliases     — List of alternative names for CLI matching
  description — One-line description
  stealth_level — "high", "medium", or "low" (noise/detection risk)
  run()       — The main technique logic

Optional lifecycle hooks:
  setup()     — Called before run() (e.g. resolve NS IPs, load data)
  teardown()  — Called after run() (e.g. cleanup temp files)

HUNTER NOTE: Each technique module should include a comment block at the top
explaining its detection risk, why a pro hunter would use it, and what
it finds that other techniques don't.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Set


class BaseTechnique(ABC):
    """Abstract base class for all enumeration techniques.

    Subclass this to create a new technique. Each technique is standalone —
    it receives everything it needs (config, resolver pool, etc.) as arguments.

    Example:
        class MyNewTechnique(BaseTechnique):
            name = "My Technique"
            aliases = ["mytech", "new"]
            description = "Does something cool"
            stealth_level = "medium"

            def run(self, cfg, pool, wc, results, **kwargs) -> Set[str]:
                # ... implementation ...
                return found_subdomains
    """

    name: str = "Base Technique"
    aliases: List[str] = []
    description: str = ""
    stealth_level: str = "medium"  # high, medium, low
    technique_id: str = "t00"

    @abstractmethod
    def run(
        self,
        cfg: "Config",
        pool: "ResolverPool",
        wc: "WildcardDetector",
        results: "ResultCollector",
        **kwargs,
    ) -> Set[str]:
        """Execute the technique.

        Args:
            cfg:       Config dataclass with all scan parameters
            pool:      ResolverPool instance for DNS queries
            wc:        WildcardDetector instance for filtering
            results:   ResultCollector for storing findings
            **kwargs:  Technique-specific arguments

        Returns:
            Set[str] of discovered subdomain FQDNs (just found this run,
            not cumulative — results.found already has the cumulative set)
        """
        ...

    def setup(self, cfg: "Config", pool: "ResolverPool") -> bool:
        """Optional setup before run(). Return True to proceed, False to skip.

        Use for: resolving NS IPs, loading data files, validation checks.
        If False, run() is skipped and the technique reports 0 findings.
        """
        return True

    def teardown(self) -> None:
        """Optional cleanup after run(). Use for: closing temp files, etc."""
        pass

    def get_info(self) -> Dict[str, Any]:
        """Return technique metadata as a dict."""
        return {
            "id": self.technique_id,
            "name": self.name,
            "aliases": self.aliases,
            "description": self.description,
            "stealth_level": self.stealth_level,
        }

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} [{self.technique_id}] '{self.name}'>"
