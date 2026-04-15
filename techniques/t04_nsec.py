"""
techniques/t04_nsec.py — DNSSEC NSEC Walking

TECHNIQUE: DNSSEC NSEC Walking
TECHNIQUE_ID: t04
STEALTH: MEDIUM — queries authoritative NS with DNSSEC validation
HUNTER NOTE: Provably complete enumeration IF the zone uses NSEC (not NSEC3).
  Most modern zones use NSEC3 (hashed names) which defeats this technique.
  But .gov, .edu, and banking zones often still use plain NSEC.
  Run this before brute force — it's free and provably complete.

References:
  - ldns-walk tool behavior
  - NSEC chain: non-existent name → NSEC denial → extract next name → repeat

References:
  - https://0xffsec.com/handbook/information-gathering/subdomain-enumeration/
  - RFC 4035, RFC 7129 for NSEC semantics
"""

from typing import Set, Tuple, Optional

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver

from .base import BaseTechnique


class NSECTechnique(BaseTechnique):
    name = "DNSSEC NSEC Walking"
    aliases = ["nsec-walk", "nsec3", "dnssec-walk", "zone-walk", "nsec", "04"]
    description = "Follow DNSSEC NSEC chain for provably complete zone enumeration"
    stealth_level = "medium"
    technique_id = "t04"

    def _nsec(self, name: str, ns: str) -> Optional[Tuple[str, str]]:
        """Query NSEC record for a name. Returns (name, next_name) or None."""
        try:
            req = dns.message.make_query(name, dns.rdatatype.A, want_dnssec=True)
            req.flags |= dns.flags.CD  # Disable validation check
            resp = dns.query.udp(req, ns, timeout=5)
            for rrset in resp.authority:
                if rrset.rdtype == dns.rdatatype.NSEC:
                    for rdata in rrset:
                        cur = str(rrset.name).rstrip(".")
                        nxt = str(rdata.next).rstrip(".")
                        return cur, nxt
        except Exception:
            pass
        return None

    def run(self, cfg, pool, wc, results, **kwargs) -> Set[str]:
        from core.resolver import resolve_ns
        from rich.console import Console
        console = Console()

        self.cfg = cfg
        console.print(f"\n[bold blue][04][/bold blue] DNSSEC NSEC/NSEC3 Walking")

        found: Set[str] = set()
        ns_ips = resolve_ns(cfg.domain, pool)
        if not ns_ips:
            console.print("  [dim]→ No NS resolved[/dim]")
            return found

        ns = ns_ips[0]
        current = cfg.domain
        visited: Set[str] = set()
        max_steps = 1000

        for _ in range(max_steps):
            if current in visited:
                break
            visited.add(current)

            pair = self._nsec(current, ns)
            if not pair:
                break
            _, nxt = pair

            if nxt.endswith(f".{cfg.domain}"):
                from core.resolver import resolve_a
                ips = resolve_a(nxt, pool) or ["[nsec-only]"]
                results.add_sync(nxt, ips, "nsec-walk")
                found.add(nxt)

            # Proper DNS name comparison for wrap-around detection
            try:
                nxt_name = dns.name.from_text(nxt)
                cur_name = dns.name.from_text(current)
                wrapped = nxt == cfg.domain
                fewer_labels = len(nxt_name.labels) < len(cur_name.labels)
                lexicographic_wrap = nxt_name < cur_name
                if wrapped or (lexicographic_wrap and fewer_labels):
                    break
            except Exception:
                if nxt == cfg.domain:
                    break

            current = nxt

        if found:
            console.print(
                f"  [bold green]✓ NSEC walk found {len(found)} names![/bold green]"
            )
        else:
            console.print(
                "  [dim]→ NSEC3 (hashed) or no DNSSEC — walk not possible[/dim]"
            )
        return found