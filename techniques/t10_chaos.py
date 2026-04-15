"""
techniques/t10_chaos.py — DNS CHAOS Class Queries

TECHNIQUE: DNS CHAOS Class
TECHNIQUE_ID: t10
STEALTH: HIGH — queries NS directly with CHAOS rdclass, zero noise to target
HUNTER NOTE: Queries version.bind, hostname.bind on authoritative NS.
  Reveals NS software and version. Sometimes returns hostname in the answer.
  This is zero-noise recon — the target's NS doesn't log these differently
  from normal queries and it tells you about the infrastructure.

References:
  - Our earlier conversation
  - dig CHAOS TXT version.bind @ns.example.com
  - RFC 6195: CHAOS rdclass
"""

import re
from typing import Set

import dns.message
import dns.query
import dns.rdataclass
import dns.rdatatype

from .base import BaseTechnique

CHAOS_QUERIES = [
    "version.bind",
    "version.server",
    "hostname.bind",
    "id.server",
    "authors.bind",
    "build.bind",
]


class CHAOSTechnique(BaseTechnique):
    name = "DNS CHAOS Class"
    aliases = ["chaos", "chaos-txt", "version-bind", "dns-chaos", "10"]
    description = "Query CHAOS rdclass TXT records to extract NS software/version leaks and hostname information"
    stealth_level = "high"
    technique_id = "t10"

    def _query(self, qname: str, ns_ip: str) -> str:
        """Query a CHAOS TXT record."""
        try:
            req = dns.message.make_query(
                qname, dns.rdatatype.TXT, rdclass=dns.rdataclass.CHAOS
            )
            resp = dns.query.udp(req, ns_ip, timeout=5)
            for rrset in resp.answer:
                for rdata in rrset:
                    if hasattr(rdata, "strings"):
                        return b"".join(rdata.strings).decode("utf-8", errors="ignore")
        except Exception:
            pass
        return None

    def run(self, cfg, pool, wc, results, **kwargs) -> Set[str]:
        from core.resolver import resolve_ns, resolve_a
        from rich.console import Console
        console = Console()

        self.cfg = cfg
        console.print(f"\n[bold blue][10][/bold blue] DNS CHAOS Class Queries")

        found: Set[str] = set()
        ns_ips = resolve_ns(cfg.domain, pool)
        if not ns_ips:
            console.print("  [dim]→ No NS resolved[/dim]")
            return found

        hits = []
        for ns_ip in ns_ips:
            for qname in CHAOS_QUERIES:
                val = self._query(qname, ns_ip)
                if val:
                    hits.append(f"{qname}@{ns_ip}: {val}")
                    console.print(
                        f"  [bold magenta][chaos][/bold magenta] "
                        f"{qname} → [yellow]{val}[/yellow]"
                    )
                    # Extract subdomains from response
                    pattern = rf'[a-zA-Z0-9._-]+\.{re.escape(cfg.domain)}'
                    for h in re.findall(pattern, val):
                        ips = resolve_a(h, pool) or ["[chaos-leak]"]
                        results.add_sync(h, ips, "chaos-class")
                        found.add(h)

        if not hits:
            console.print(
                "  [dim]→ No CHAOS responses (well-configured servers)[/dim]"
            )
        return found