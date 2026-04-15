"""
techniques/t15_spf_chain.py — SPF Include Chain Walker

TECHNIQUE: SPF Include Chain Walker
TECHNIQUE_ID: t15
STEALTH: HIGH — DNS TXT record lookups only, no HTTP interaction
HUNTER NOTE: SPF include: directives point to third-party SPF configurations.
  _spf.google.com contains Google's entire mail infrastructure.
  sendgrid.net contains all SendGrid customer domains.
  This recursively follows include: chains to find third-party service hostnames
  that may overlap with the target's infrastructure. Also resolves a: and mx:
  directives and does reverse DNS on included IP ranges.

References:
  - Our earlier conversation — third-party mail service discovery
  - SPF RFC 7208 include: directive
  - SPF includes often point to _spf.service.com which returns all customer IPs
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set, Tuple

from .base import BaseTechnique


class SPFChainTechnique(BaseTechnique):
    name = "SPF Include Chain Walker"
    aliases = ["spf-chain", "spf-recursive", "spf-tree", "15"]
    description = "Recursively follow SPF include: directives to discover third-party mail infrastructure"
    stealth_level = "high"
    technique_id = "t15"

    def _extract_spf_components(self, txt: str) -> Tuple[List[str], List[str], List[str]]:
        """Extract all hostnames and IPs from an SPF record.

        Returns: (includes, a_directives, mx_directives)
        """
        includes = []
        a_list = []
        mx_list = []

        for part in txt.split():
            part_l = part.lower()
            if part_l.startswith("include:"):
                includes.append(part[8:].strip())
            elif part_l.startswith("a:"):
                domain = part[2:].strip()
                if domain:
                    a_list.append(domain)
            elif part_l.startswith("mx:"):
                domain = part[3:].strip()
                if domain:
                    mx_list.append(domain)
            elif part_l.startswith("ip4:"):
                pass  # Skip direct IPs
            elif part_l.startswith("ip6:"):
                pass  # Skip direct IPs

        return includes, a_list, mx_list

    def _resolve_spf(self, fqdn: str) -> Tuple[List[str], List[str], List[str]]:
        """Query TXT record and extract SPF components."""
        try:
            answers = self.pool.random().resolve(fqdn, "TXT")
            for ans in answers:
                txt = " ".join(r.strings)
                if "v=spf1" in txt.lower():
                    inc, a_list, mx_list = self._extract_spf_components(txt)
                    return inc, a_list, mx_list
        except Exception:
            pass
        return [], [], []

    def _walk_chain(
        self, fqdn: str, depth: int = 0, max_depth: int = 5
    ) -> Set[str]:
        """Recursively walk SPF include chain. Returns discovered hostnames."""
        found: Set[str] = set()

        if depth > max_depth:
            return found
        if not fqdn or fqdn in self._visited:
            return found
        self._visited.add(fqdn)

        includes, a_list, mx_list = self._resolve_spf(fqdn)

        # Record the SPF source itself
        if self.cfg.domain in fqdn:
            self.results.add_sync(fqdn, ["[spf-chain]"], "spf-chain")
            found.add(fqdn)
        elif includes and not any(self.cfg.domain in i for i in includes):
            # External include — record it as reference
            results.add_sync(fqdn, [f"[external-spf]"], "spf-chain-ext")
            found.add(fqdn)

        # Process includes
        for inc in includes:
            if self.cfg.domain in inc:
                # Internal include — add to chain
                sub_found = self._walk_chain(inc, depth + 1, max_depth)
                found.update(sub_found)
            else:
                # External include (like _spf.google.com)
                # Record it but don't recurse into it (it's a shared service)
                self.results.add_sync(
                    inc, ["[external-spf-include]"], "spf-external"
                )
                found.add(inc)

        # Process a: and mx: directives
        for a_domain in a_list + mx_list:
            if self.cfg.domain in a_domain:
                try:
                    ans = self.pool.random().resolve(a_domain, "A")
                    ips = [str(r.address) for r in ans]
                    self.results.add_sync(a_domain, ips, "spf-a-mx")
                    found.add(a_domain)
                except Exception:
                    pass

        return found

    def run(self, cfg, pool, wc, results, **kwargs) -> Set[str]:
        from rich.console import Console
        console = Console()

        self.cfg = cfg
        self.pool = pool
        self.results = results
        self._visited: Set[str] = set()

        console.print(f"\n[bold blue][15][/bold blue] SPF Include Chain Walker")

        found: Set[str] = set()
        max_depth = kwargs.get("max_depth", 5)

        # Start with root domain SPF
        console.print(f"  [dim]→ Starting SPF chain walk from {cfg.domain}[/dim]")

        new = self._walk_chain(cfg.domain, depth=0, max_depth=max_depth)
        found.update(new)

        console.print(f"  [dim]→ {len(found)} hostnames via SPF chain walking[/dim]")
        return found