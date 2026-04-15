"""
techniques/t05_cachesnoop.py — DNS Cache Snooping

TECHNIQUE: DNS Cache Snooping
TECHNIQUE_ID: t05
STEALTH: HIGH — queries public resolvers, non-recursive (RD bit cleared)
HUNTER NOTE: This finds subdomains that are ACTUALLY IN USE by querying
  resolvers without recursion. If a resolver has a cached answer, the
  subdomain is live. This is stealthy because it queries public resolvers
  (8.8.8.8, 1.1.1.1) and the target's NS never sees it.
  Target only sees queries from resolvers, not from you directly.

References:
  - Our earlier conversation — less-known technique
  - Key: req.flags &= ~dns.flags.RD clears the Recursion Desired bit
  - Only ANSWER section (not AUTHORITY) confirms cached entry
"""

from typing import List, Set

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rdatatype

from .base import BaseTechnique

# Default public resolvers for cache snooping
DEFAULT_SNOOP_RESOLVERS = ["8.8.8.8", "1.1.1.1", "208.67.222.222", "9.9.9.9"]


class CacheSnoopTechnique(BaseTechnique):
    name = "DNS Cache Snooping"
    aliases = ["cache-snoop", "cache-probe", "non-recursive-query", "cachesnoop", "05"]
    description = "Non-recursive DNS queries to public resolvers to detect cached (actively used) subdomains"
    stealth_level = "high"
    technique_id = "t05"

    def _snoop(self, fqdn: str, ns_ip: str) -> List[str]:
        """Send a non-recursive query. If answer exists, it was cached."""
        try:
            req = dns.message.make_query(fqdn, dns.rdatatype.A)
            req.flags &= ~dns.flags.RD  # Clear RD bit — non-recursive
            resp = dns.query.udp(req, ns_ip, timeout=3)
            if resp.answer:
                for rrset in resp.answer:
                    if rrset.rdtype == dns.rdatatype.A:
                        return [str(r.address) for r in rrset]
        except Exception:
            pass
        return []

    def run(self, cfg, pool, wc, results, **kwargs) -> Set[str]:
        from rich.console import Console
        console = Console()

        self.cfg = cfg
        console.print(f"\n[bold blue][05][/bold blue] DNS Cache Snooping")

        found: Set[str] = set()
        known: Set[str] = kwargs.get("known", set())

        # Default probe list: known + common targets
        targets = list(known) if known else []
        for word in ["www", "mail", "admin", "vpn", "internal", "api",
                     "dev", "staging", "intranet", "corp", "git", "jenkins",
                     "portal", "cdn", "api2", "api3", "vpn", "crm"]:
            targets.append(f"{word}.{cfg.domain}")
        targets = list(set(targets))

        probes_ns = kwargs.get("resolvers", DEFAULT_SNOOP_RESOLVERS)
        hits = 0
        for ns_ip in probes_ns:
            for fqdn in targets:
                ips = self._snoop(fqdn, ns_ip)
                if ips:
                    results.add_sync(fqdn, ips, f"cache-snoop@{ns_ip}")
                    found.add(fqdn)
                    hits += 1

        console.print(
            f"  [dim]→ {hits} cached entries across {len(probes_ns)} resolvers[/dim]"
        )
        return found