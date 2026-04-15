"""
techniques/t06_ipv6.py — IPv6 AAAA Enumeration

TECHNIQUE: IPv6 AAAA Enumeration
TECHNIQUE_ID: t06
STEALTH: MEDIUM — standard AAAA DNS queries
HUNTER NOTE: The 95% blind spot. Nobody enumerates IPv6. You will find things
  here that no other technique finds. IPv6-only subdomains are often forgotten
  infrastructure — staging servers, internal tools, monitoring endpoints.
  Run this concurrently with brute force for best results.

References:
  - shubhamrooter.medium.com deep subdomain methodology
  - Our earlier conversation — IPv6 is the 95% blind spot
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set, Tuple

from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn

from .base import BaseTechnique


class IPv6Technique(BaseTechnique):
    name = "IPv6 AAAA Enumeration"
    aliases = ["aaaa", "ipv6-brute", "ipv6-enum", "ipv6", "06"]
    description = "Brute force AAAA record resolution — finds IPv6-only subdomains (the 95% blind spot)"
    stealth_level = "medium"
    technique_id = "t06"

    def _try(self, word: str) -> Tuple[str, List[str]]:
        """Attempt to resolve AAAA record for a word."""
        from core.resolver import resolve_aaaa, ResolverPool

        fqdn = f"{word}.{self.cfg.domain}"
        pool = self.pool or ResolverPool(self.cfg.resolvers, self.cfg.timeout)
        ips = resolve_aaaa(fqdn, pool)
        if ips:
            return fqdn, [f"[IPv6] {ip}" for ip in ips]
        return None

    def run(self, cfg, pool, wc, results, **kwargs) -> Set[str]:
        from core.resolver import ResolverPool
        from rich.console import Console
        console = Console()

        self.cfg = cfg
        self.pool = pool or ResolverPool(cfg.resolvers, cfg.timeout)
        self.wc = wc

        wordlist: List[str] = kwargs.get("wordlist", [])
        console.print(
            f"\n[bold blue][06][/bold blue] IPv6 AAAA Enumeration — "
            f"[cyan]{len(wordlist):,}[/cyan] words"
        )

        found: Set[str] = set()
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
            transient=True,
        ) as prog:
            task = prog.add_task("[cyan]IPv6 probing...", total=len(wordlist))
            with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
                fs = {ex.submit(self._try, w): w for w in wordlist}
                for f in as_completed(fs):
                    prog.advance(task)
                    r = f.result()
                    if r:
                        fqdn, ips = r
                        results.add_sync(fqdn, ips, "ipv6-aaaa")
                        found.add(fqdn)

        console.print(f"  [dim]→ {len(found)} IPv6-only subdomains[/dim]")
        return found