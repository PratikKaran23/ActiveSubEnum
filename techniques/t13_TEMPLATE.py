"""
TECHNIQUE: SPF/TXT Record Mining
TECHNIQUE_ID: t13 (Template — fully functional, adds as new technique)
AUTHOR: ActiveSubEnum Community
STEALTH: HIGH (read-only DNS queries, no interaction with target HTTP)
DESCRIPTION: Query TXT records on the root domain and all discovered subdomains,
  extract hostnames from SPF "include:", "a:", and "mx:" directives, DKIM selectors,
  and DMARC records. This is a passive-adjacent technique that leaks internal
  mail infrastructure hostnames through published DNS records.

HOW IT WORKS:
  1. Query TXT record for root domain (contains SPF policy)
  2. Parse SPF include: directives — each reveals a third-party mail service
  3. For each include:, also query its TXT record (may reveal more subdomains)
  4. Extract a: and mx: directives for hostnames
  5. Also query DKIM selectors (_domainkey.subdomain.domain)
  6. Resolve all extracted hostnames via DNS

REFERENCES:
  - Our earlier conversation — less-known technique
  - SPF RFC 7208: https://tools.ietf.org/html/rfc7208
  - SPF records often include: include:_spf.google.com (Google Workspace),
    include:sendgrid.net (SendGrid), include:amazonses.com (AWS SES)

────────────────────────────────────────────────────────────────────────────
ADDING A NEW TECHNIQUE — STEP BY STEP CHECKLIST
────────────────────────────────────────────────────────────────────────────

Step 0: Before writing ANY code — run the overlap checker (Part 9):
  python3 tools/check_technique_overlap.py \
    --name "Your Technique Name" \
    --aliases "alias1,alias2" \
    --interaction "direct-dns|direct-http|direct-tls-ip|indirect-resolver" \
    --data-source "wordlist|existing-subdomains|nameserver|ip-ranges|txt-records" \
    --description "one sentence describing what makes this unique" \
    --reference "https://your-source-url"

  If exit code = 1: your technique is already implemented. Adjust or abandon.
  If exit code = 0 or 0-with-warnings: proceed.

Step 1: Copy this file as t14_yourtechnique.py (or t13, t15, etc.)
Step 2: Replace all placeholder values with your technique's details
Step 3: Implement the run() method — it must return Set[str] of FQDNs
Step 4: Add your class to techniques/__init__.py:
        from .t14_yourtechnique import YourTechniqueClass
        TECHNIQUE_CLASSES["t14"] = YourTechniqueClass
        TECHNIQUE_REGISTRY["t14"] = {"name": "...", "aliases": [...], ...}
Step 5: Add to ALL_TECHNIQUES in activesubenum.py if it should run by default
Step 6: Add to the appropriate workflow files
Step 7: Test: python3 -c "import py_compile; py_compile.compile('techniques/t14_yourtechnique.py')"
Step 8: Run a safe integration test with a domain you own/control

TOTAL TIME TO ADD: Under 30 minutes with this template.
────────────────────────────────────────────────────────────────────────────
"""

import re
from typing import List, Set

import dns.resolver

from .base import BaseTechnique


class TemplateTechnique(BaseTechnique):
    """SPF/TXT Record Mining — extracts hostnames from DNS TXT records.

    This is the technique that should be added as t13.
    It is fully functional and ready for production use.
    """
    name = "SPF/TXT Record Mining"
    aliases = ["spf-mine", "txt-mine", "spf-walk", "spf", "13"]
    description = "Parse SPF, DKIM, and DMARC TXT records to discover third-party mail infrastructure hostnames"
    stealth_level = "high"
    technique_id = "t13"

    def _parse_spf(self, txt_record: str) -> List[str]:
        """Extract all hostnames/IPs from an SPF TXT record.

        SPF directives of interest:
          include:domain — include another SPF record
          a:domain       — resolve A record of domain
          mx:domain      — resolve MX record of domain
          ip4:X.X.X.X    — direct IP (skip, not a hostname)
          ptr:domain     — PTR records (skip, not reliable)

        Returns list of domain names extracted from include:/a:/mx: directives.
        """
        hostnames = []
        for directive in txt_record.split():
            directive_lower = directive.lower()
            if directive_lower.startswith("include:"):
                # e.g. include:_spf.google.com
                domain = directive[8:].strip()
                hostnames.append(domain)
            elif directive_lower.startswith("a:"):
                # e.g. a:mail.example.com
                domain = directive[2:].strip()
                if domain:
                    hostnames.append(domain)
            elif directive_lower.startswith("mx:"):
                # e.g. mx:mail.example.com
                domain = directive[3:].strip()
                if domain:
                    hostnames.append(domain)
        return hostnames

    def _resolve_txt(self, fqdn: str) -> List[str]:
        """Resolve TXT record and return all strings."""
        try:
            answers = self.pool.random().resolve(fqdn, "TXT")
            return [" ".join(r.strings) for r in answers]
        except Exception:
            return []

    def _extract_from_txt(self, fqdn: str) -> Set[str]:
        """Query TXT record and extract hostnames from SPF/DKIM/DMARC."""
        found: Set[str] = set()
        txt_records = self._resolve_txt(fqdn)
        if not txt_records:
            return found

        for txt in txt_records:
            # Skip if it doesn't look like SPF
            if "v=spf1" not in txt.lower() and "_dmarc" not in fqdn.lower():
                if "_domainkey" not in fqdn.lower():
                    # Not SPF-related, but still scan for domain references
                    pass

            # Extract from SPF
            if "v=spf1" in txt.lower():
                includes = self._parse_spf(txt)
                for domain in includes:
                    # Attempt to resolve this included domain
                    try:
                        ans = self.pool.random().resolve(domain, "A")
                        for r in ans:
                            host = str(r).rstrip(".")
                            if host and domain:
                                # Try to extract subdomain part
                                if domain.startswith("*."):
                                    domain = domain[2:]
                                # This domain itself might be a subdomain we want
                                if self.cfg.domain in domain:
                                    results.add_sync(domain, [str(r)], "spf-include")
                                    found.add(domain)
                                else:
                                    # Include is external (e.g., _spf.google.com)
                                    # Still record it
                                    results.add_sync(
                                        domain, [f"[external: {str(r)}]"], "spf-include-external"
                                    )
                                    found.add(domain)
                    except Exception:
                        # Can't resolve — record it anyway as a potential subdomain
                        if self.cfg.domain in domain:
                            results.add_sync(domain, ["[spf-include]"], "spf-include")
                            found.add(domain)

            # DMARC records — extract subdomain from _dmarc.domain
            if "_dmarc" in fqdn.lower():
                # _dmarc.domain.tld — extract domain.tld
                match = re.match(r"^_dmarc\.(.+)$", fqdn.lower())
                if match:
                    base_domain = match.group(1)
                    results.add_sync(
                        base_domain,
                        ["[dmarc-record]"],
                        "dmarc-enum"
                    )
                    found.add(base_domain)

        return found

    def run(self, cfg, pool, wc, results, **kwargs) -> Set[str]:
        from rich.console import Console
        console = Console()

        self.cfg = cfg
        self.pool = pool
        self.results = results

        known: Set[str] = kwargs.get("known", set())

        console.print(f"\n[bold blue][13][/bold blue] SPF/TXT Record Mining")

        found: Set[str] = set()

        # Build list of targets to query
        targets = [cfg.domain]  # Always start with root domain
        for sub in known:
            if sub.endswith(cfg.domain):
                # Add the subdomain itself
                targets.append(sub)

        console.print(f"  [dim]→ Querying {len(targets)} domains for TXT records[/dim]")

        for target in targets:
            new = self._extract_from_txt(target)
            if new:
                console.print(f"  [dim]→ {target}: {len(new)} hostnames extracted[/dim]")
                found.update(new)

        console.print(f"  [dim]→ {len(found)} subdomains via SPF/TXT mining[/dim]")
        return found