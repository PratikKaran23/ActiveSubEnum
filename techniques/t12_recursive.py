"""
techniques/t12_recursive.py — Recursive Enumeration

TECHNIQUE: Recursive Subdomain Enumeration
TECHNIQUE_ID: t12
STEALTH: MEDIUM — makes many DNS queries for sub-subdomains
HUNTER NOTE: After you find api.example.com, run recursive to find
  dev.api.example.com, staging.api.example.com. This finds the
  forgotten infrastructure beneath discovered subdomains.
  Best applied to "interesting" seeds: api, dev, staging, internal, admin.
  Run at depth 2 by default, depth 3 for comprehensive scans.

References:
  - shubhamrooter.medium.com deep subdomain methodology
  - Our earlier conversation
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set, Tuple

from .base import BaseTechnique

RECURSIVE_SEEDS = [
    "api", "dev", "staging", "internal", "admin", "test",
    "app", "v1", "v2", "service", "backend", "frontend",
    "auth", "login", "portal", "dashboard", "management",
    "data", "prod", "qa", "old", "new", "cdn", "assets",
    "static", "git", "jenkins", "monitor", "monitoring",
]


class RecursiveTechnique(BaseTechnique):
    name = "Recursive Enumeration"
    aliases = ["recursive", "sub-subdomain", "deep-brute", "recursive-brute", "12"]
    description = "Use discovered subdomains as seeds to brute force sub-subdomains (depth=2 recommended)"
    stealth_level = "medium"
    technique_id = "t12"

    def _resolve_under(
        self, args: Tuple[str, str]
    ) -> Tuple[str, List[str]]:
        """Resolve a sub-subdomain: word.seed.example.com."""
        word, seed_fqdn = args
        from core.resolver import resolve_a
        fqdn = f"{word}.{seed_fqdn}"
        ips = resolve_a(fqdn, self.pool)
        if ips and not self.wc.is_wildcard(ips):
            return fqdn, ips
        return None

    def run(self, cfg, pool, wc, results, **kwargs) -> Set[str]:
        from rich.console import Console
        console = Console()

        self.cfg = cfg
        self.pool = pool
        self.wc = wc
        self.results = results

        known: Set[str] = kwargs.get("known", set())
        depth: int = kwargs.get("depth", cfg.depth)
        seeds_override: List[str] = kwargs.get("seeds", RECURSIVE_SEEDS)

        console.print(
            f"\n[bold blue][12][/bold blue] Recursive Enumeration "
            f"(depth={depth}, {len(known)} seeds)"
        )

        all_new: Set[str] = set()
        seeds = set(known)

        for level in range(1, depth + 1):
            if not seeds:
                break
            console.print(f"  [dim]→ Level {level}: {len(seeds)} seeds[/dim]")
            new: Set[str] = set()

            pairs = [(w, s) for s in seeds for w in seeds_override]
            if not pairs:
                break

            with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
                fs = {ex.submit(self._resolve_under, p): p for p in pairs}
                for f in as_completed(fs):
                    r = f.result()
                    if r:
                        fqdn, ips = r
                        if fqdn not in all_new:
                            results.add_sync(fqdn, ips, f"recursive-l{level}")
                            new.add(fqdn)
                            all_new.add(fqdn)

            seeds = new

        console.print(f"  [dim]→ {len(all_new)} sub-subdomains found recursively[/dim]")
        return all_new