"""
techniques/t03_zonetransfer.py — Zone Transfer (AXFR/IXFR)

TECHNIQUE: Zone Transfer
TECHNIQUE_ID: t03
STEALTH: LOW — direct query to authoritative NS, very noisy if logged
HUNTER NOTE: ALWAYS TRY THIS FIRST. Zone transfer is free intel — zero
  time cost, massive reward if it works. Most targets refuse it (good opssec
  practice) but when it works you get the entire DNS namespace.
  ALWAYS run this before brute force.

References:
  - https://0xffsec.com/handbook/information-gathering/subdomain-enumeration/
"""

from typing import Set

import dns.exception
import dns.resolver
import dns.zone

from .base import BaseTechnique


class ZoneTransferTechnique(BaseTechnique):
    name = "Zone Transfer"
    aliases = ["axfr", "ixfr", "zonetransfer", "zone-transfer", "zone", "03"]
    description = "AXFR/IXFR zone transfer against all authoritative nameservers"
    stealth_level = "low"
    technique_id = "t03"

    def setup(self, cfg, pool) -> bool:
        """Resolve nameservers before attempting zone transfer."""
        from core.resolver import resolve_ns
        self.ns_ips = resolve_ns(cfg.domain, pool or
                                  __import__("core.resolver", fromlist=["ResolverPool"]).ResolverPool(cfg.resolvers, cfg.timeout))
        return bool(self.ns_ips)

    def run(self, cfg, pool, wc, results, **kwargs) -> Set[str]:
        from core.resolver import resolve_ns, resolve_a
        from rich.console import Console
        console = Console()

        self.cfg = cfg
        self.pool = pool
        console.print(f"\n[bold blue][03][/bold blue] Zone Transfer (AXFR/IXFR)")

        found: Set[str] = set()
        ns_ips = resolve_ns(cfg.domain, pool)
        if not ns_ips:
            console.print("  [dim]→ Could not resolve nameservers[/dim]")
            return found

        console.print(f"  [dim]→ Trying {len(ns_ips)} nameservers...[/dim]")
        for ns_ip in ns_ips:
            try:
                zone = dns.zone.from_xfr(
                    dns.query.xfr(ns_ip, cfg.domain, timeout=10)
                )
                for name in zone.nodes:
                    s = str(name).rstrip(".")
                    if s in ("@", ""):
                        continue
                    fqdn = f"{s}.{cfg.domain}"
                    ips = resolve_a(fqdn, pool) or ["[zone-record]"]
                    results.add_sync(fqdn, ips, "zonetransfer")
                    found.add(fqdn)
                console.print(
                    f"  [bold green]✓ ZONE TRANSFER SUCCESS on {ns_ip}![/bold green] "
                    f"Got {len(found)} records."
                )
                break  # One success is enough
            except dns.exception.FormError:
                console.print(f"  [dim]→ {ns_ip}: refused[/dim]")
            except Exception as e:
                console.print(f"  [dim]→ {ns_ip}: {str(e)[:60]}[/dim]")

        if not found:
            console.print("  [dim]→ All NS refused zone transfer (expected in modern configs)[/dim]")
        return found