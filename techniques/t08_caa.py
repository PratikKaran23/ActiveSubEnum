"""
techniques/t08_caa.py — CAA Record Pivoting

TECHNIQUE: CAA Record Pivoting
TECHNIQUE_ID: t08
STEALTH: HIGH — DNS queries only, no HTTP interaction with target
HUNTER NOTE: This is the most underrated technique. The key insight:
  NoAnswer != NXDOMAIN. When you query CAA for a subdomain:
  - NXDOMAIN → subdomain definitely doesn't exist
  - NoAnswer → subdomain EXISTS but has no CAA record
  This confirms existence without needing an A record.
  A CAA pivot can confirm existence of subdomains that return SERVFAIL
  on A queries (misconfigured split-horizon).

References:
  - Our earlier conversation — less-known technique
  - RFC 6844: CAA record format
  - Key: dns.resolver.NoAnswer means name EXISTS
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set, Tuple

import dns.resolver

from .base import BaseTechnique


class CAATechnique(BaseTechnique):
    name = "CAA Record Pivoting"
    aliases = ["caa", "caa-pivot", "caa-probe", "08"]
    description = "Probe CAA records to confirm subdomain existence — NoAnswer confirms, NXDOMAIN denies"
    stealth_level = "high"
    technique_id = "t08"

    def _probe(self, word: str) -> Tuple[str, List[str], bool]:
        """Probe CAA for a word. Returns (fqdn, data, is_caa_record)."""
        fqdn = f"{word}.{self.cfg.domain}"
        try:
            ans = self.pool.random().resolve(fqdn, "CAA")
            recs = [f"{r.flags} {r.tag.decode()} {r.value.decode()}" for r in ans]
            return fqdn, recs, True
        except dns.resolver.NoAnswer:
            # Name exists but has no CAA record
            from core.resolver import resolve_a
            ips = resolve_a(fqdn, self.pool)
            if ips:
                return fqdn, ips, False
        except dns.resolver.NXDOMAIN:
            pass
        except Exception:
            pass
        return None

    def run(self, cfg, pool, wc, results, **kwargs) -> Set[str]:
        from rich.console import Console
        console = Console()

        self.cfg = cfg
        self.pool = pool

        wordlist: List[str] = kwargs.get("wordlist", [])
        console.print(
            f"\n[bold blue][08][/bold blue] CAA Record Pivoting — "
            f"[cyan]{len(wordlist):,}[/cyan] words"
        )

        found: Set[str] = set()
        with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
            fs = {ex.submit(self._probe, w): w for w in wordlist}
            for f in as_completed(fs):
                r = f.result()
                if r:
                    fqdn, recs, is_caa = r
                    tag = "caa-record" if is_caa else "caa-confirmed"
                    results.add_sync(fqdn, recs, tag)
                    found.add(fqdn)

        console.print(f"  [dim]→ {len(found)} confirmed via CAA[/dim]")
        return found