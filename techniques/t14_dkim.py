"""
techniques/t14_dkim.py — DKIM Selector Bruteforce

TECHNIQUE: DKIM Selector Bruteforce
TECHNIQUE_ID: t14
STEALTH: HIGH — DNS TXT record lookups only
HUNTER NOTE: DKIM selectors reveal mail vendor integrations.
  google._domainkey.example.com → Google Workspace
  sendgrid._domainkey.example.com → SendGrid
  amazonses._domainkey.example.com → AWS SES
  Each selector is a potential subdomain. If it resolves, the organization
  uses that vendor for email. If it returns a CNAME, that's a subdomain.
  This is passive-adjacent — just DNS lookups.

References:
  - Our earlier conversation — less-known technique
  - Common DKIM selector patterns: google, google2, k1, s1, selector1
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set, Tuple

from .base import BaseTechnique

# Common DKIM selectors — expand this list for better coverage
DKIM_SELECTORS = [
    "google", "google2", "google3", "google4",
    "k1", "k2", "s1", "s2", "s3", "selector1", "selector2", "selector3",
    "mail", "smtp", "dkim", "dkim1", "dkim2", "default", "key1", "key2",
    "email", "mx", "mx1", "mx2",
    "sendgrid", "sendgrid2",
    "mandrill", "mailgun", "amazonses", "amazonses2",
    "postmark", "sparkpost", "mailchimp",
    "provedmarc", "dmarc", "dkim._domainkey",
    "2022", "2023", "2024", "2025",  # Year-based selectors
    "sig1", "sig2", "sig3", "mail2022", "mail2023", "mail2024",
]


class DKIMTechnique(BaseTechnique):
    name = "DKIM Selector Bruteforce"
    aliases = ["dkim", "dkim-selector", "domainkey", "14"]
    description = "Probe DKIM selectors to reveal mail vendor integrations and discover subdomains"
    stealth_level = "high"
    technique_id = "t14"

    def _probe_selector(self, selector: str) -> Tuple[str, List[str], str]:
        """Probe a single DKIM selector. Returns (fqdn, ips, type)."""
        fqdn = f"{selector}._domainkey.{self.cfg.domain}"
        try:
            # Try TXT record first
            ans = self.pool.random().resolve(fqdn, "TXT")
            if ans:
                txt = " ".join(" ".join(r.strings) for r in ans)
                return fqdn, [txt[:100]], "dkim-txt"
        except dns.resolver.NXDOMAIN:
            pass
        except Exception:
            pass

        # Try CNAME
        try:
            cname = self.pool.random().resolve(fqdn, "CNAME")
            if cname:
                return fqdn, [str(cname[0].target).rstrip(".")], "dkim-cname"
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

        console.print(f"\n[bold blue][14][/bold blue] DKIM Selector Bruteforce")

        found: Set[str] = set()

        import dns.resolver  # noqa: E402

        # Build selector list
        selectors = kwargs.get("selectors", DKIM_SELECTORS)

        console.print(f"  [dim]→ Probing {len(selectors)} DKIM selectors[/dim]")

        def probe(s):
            return self._probe_selector(s)

        with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
            futures = {ex.submit(probe, s): s for s in selectors}
            for f in as_completed(futures):
                r = f.result()
                if r:
                    fqdn, ips, rec_type = r
                    results.add_sync(fqdn, ips, f"dkim-{rec_type}")
                    found.add(fqdn)
                    console.print(
                        f"  [dim]→ {fqdn} → {rec_type}: {ips[0][:60]}[/dim]"
                    )

        console.print(f"  [dim]→ {len(found)} DKIM selectors responded[/dim]")
        return found