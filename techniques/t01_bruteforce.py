"""
techniques/t01_bruteforce.py — DNS Brute Force

TECHNIQUE: DNS Brute Force
TECHNIQUE_ID: t01
STEALTH: MEDIUM — makes N DNS queries, rate-limited by thread pool
HUNTER NOTE: Always run this. It's the workhorse that finds 80% of subdomains.
  But run it AFTER zone transfer and NSEC (which are free). Brute force with a
  good wordlist (jhaddix-all) finds more than any permutation or recursive approach.

References:
  - https://sidxparab.gitbook.io/subdomain-enumeration-guide
  - https://medium.com/@rajeshsahan507/subdomain-enumeration-like-a-pro
  - puredns + massdns pattern
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set, Tuple

from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn

from .base import BaseTechnique


class BruteForceTechnique(BaseTechnique):
    name = "DNS Brute Force"
    aliases = ["bruteforce", "dns-brute", "wordlist-brute", "brute", "01"]
    description = "Threaded A/CNAME resolution against wordlist with wildcard filtering"
    stealth_level = "medium"
    technique_id = "t01"

    def _try(self, word: str) -> Tuple[str, List[str]]:
        """Attempt to resolve a single word. Returns (fqdn, ips) or None."""
        from core.resolver import resolve_a, ResolverPool
        from core.config import DEFAULT_RESOLVERS

        fqdn = f"{word}.{self.cfg.domain}"
        pool = self.pool or ResolverPool(self.cfg.resolvers, self.cfg.timeout)
        ips = resolve_a(fqdn, pool)

        if ips and not self.wc.is_wildcard(ips):
            return fqdn, ips

        if ips is None:
            # CNAME fallback
            from core.resolver import resolve_cname
            cname = resolve_cname(fqdn, pool)
            if cname:
                return fqdn, [cname]

        return None

    def run(self, cfg: "Config", pool, wc, results, **kwargs) -> Set[str]:
        from core.resolver import ResolverPool
        from rich.console import Console

        self.cfg = cfg
        self.pool = pool or ResolverPool(cfg.resolvers, cfg.timeout)
        self.wc = wc
        self.results = results
        console = Console()

        wordlist: List[str] = kwargs.get("wordlist", [])
        label = kwargs.get("label", "01")

        console.print(
            f"\n[bold blue][{label}][/bold blue] DNS Brute Force — "
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
            task = prog.add_task("[cyan]Resolving...", total=len(wordlist))
            with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
                fs = {ex.submit(self._try, w): w for w in wordlist}
                for f in as_completed(fs):
                    prog.advance(task)
                    r = f.result()
                    if r:
                        fqdn, ips = r
                        results.add_sync(fqdn, ips, f"brute[{label}]")
                        found.add(fqdn)

        console.print(f"  [dim]→ {len(found)} found[/dim]")
        return found