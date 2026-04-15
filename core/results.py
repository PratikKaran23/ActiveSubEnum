"""
core/results.py — Thread-Safe Result Accumulator for ActiveSubEnum

Provides ResultCollector: a deduplicated, thread-safe store for found subdomains.
Each subdomain maps to: IPs, techniques used, HTTP probe status, takeover risk, notes.

Part 7: Added takeover_risk, http_status, notes
Part 9: TECHNIQUE_REGISTRY alias collision detection
Part 10: Added annotation support
"""

import asyncio
from dataclasses import dataclass, field
from threading import Lock
from typing import Dict, List, Optional, Set


@dataclass
class SubdomainResult:
    """Single subdomain result with full metadata."""
    fqdn: str
    ips: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)
    http_status: Optional[str] = None  # e.g. "LIVE-200", "DEAD", "NO-HTTP"
    takeover_risk: Optional[str] = None  # "HIGH", "MEDIUM", "LOW", "CLOUDFLARE", etc.
    takeover_provider: Optional[str] = None  # e.g. "Heroku", "GitHub Pages", "S3"
    score: int = 0
    note: Optional[str] = None
    confirmed: bool = False  # True if confirmed live via HTTP


class ResultCollector:
    """Thread-safe, deduplicated result store for discovered subdomains.

    Supports both sync (ThreadPoolExecutor) and async (asyncio) usage.
    Uses separate locks for sync and async contexts to avoid deadlocks.
    """

    def __init__(self, verbose: bool = False):
        self.found: Dict[str, SubdomainResult] = {}
        self._async_lock = asyncio.Lock()
        self._sync_lock = Lock()
        self.verbose = verbose
        # Part 7: track technique stats
        self._technique_stats: Dict[str, Dict] = {}

    def _clean(self, sub: str) -> str:
        """Normalize subdomain: lowercase, strip trailing dots."""
        return sub.lower().rstrip(".").strip()

    def _emit(self, sub: str, ips: List[str], technique: str):
        """Print a discovery line to console."""
        from rich.console import Console
        console = Console()
        console.print(
            f"  [bold green][+][/bold green] [cyan]{sub}[/cyan]"
            f"  [dim]→[/dim]  [yellow]{', '.join(ips[:3])}[/yellow]"
            f"  [dim]({technique})[/dim]"
        )

    def _track_technique(self, technique: str, found: bool):
        """Track stats per technique: count, time."""
        if technique not in self._technique_stats:
            self._technique_stats[technique] = {"count": 0, "start": None, "end": None}
        if found:
            self._technique_stats[technique]["count"] += 1

    # ── Sync API (for ThreadPoolExecutor) ──────────────────────────────────

    def add_sync(self, sub: str, ips: List[str], technique: str) -> bool:
        """Add a subdomain from a synchronous thread context."""
        sub = self._clean(sub)
        if not sub:
            return False
        with self._sync_lock:
            if sub not in self.found:
                self.found[sub] = SubdomainResult(fqdn=sub, ips=ips, techniques=[technique])
                if self.verbose:
                    self._emit(sub, ips, technique)
                return True
            else:
                if technique not in self.found[sub].techniques:
                    self.found[sub].techniques.append(technique)
                # Merge IPs
                for ip in ips:
                    if ip not in self.found[sub].ips:
                        self.found[sub].ips.append(ip)
                return False

    def update_sync(self, sub: str, **kwargs):
        """Update fields on an existing subdomain (sync)."""
        sub = self._clean(sub)
        with self._sync_lock:
            if sub in self.found:
                for k, v in kwargs.items():
                    if hasattr(self.found[sub], k):
                        setattr(self.found[sub], k, v)

    # ── Async API (for asyncio coroutines) ──────────────────────────────────

    async def add(self, sub: str, ips: List[str], technique: str) -> bool:
        """Add a subdomain from an async coroutine context."""
        sub = self._clean(sub)
        if not sub:
            return False
        async with self._async_lock:
            if sub not in self.found:
                self.found[sub] = SubdomainResult(fqdn=sub, ips=ips, techniques=[technique])
                if self.verbose:
                    self._emit(sub, ips, technique)
                return True
            else:
                if technique not in self.found[sub].techniques:
                    self.found[sub].techniques.append(technique)
                for ip in ips:
                    if ip not in self.found[sub].ips:
                        self.found[sub].ips.append(ip)
                return False

    async def update(self, sub: str, **kwargs):
        """Update fields on an existing subdomain (async)."""
        sub = self._clean(sub)
        async with self._async_lock:
            if sub in self.found:
                for k, v in kwargs.items():
                    if hasattr(self.found[sub], k):
                        setattr(self.found[sub], k, v)

    # ── Query API ───────────────────────────────────────────────────────────

    def all_subs(self) -> Set[str]:
        """Return all discovered subdomain FQDNs."""
        return set(self.found.keys())

    def items(self):
        """Return all (fqdn, SubdomainResult) pairs."""
        return self.found.items()

    def technique_stats(self) -> Dict[str, Dict]:
        """Return per-technique statistics."""
        return self._technique_stats

    def set_technique_start(self, technique: str):
        """Mark technique start time."""
        with self._sync_lock:
            if technique not in self._technique_stats:
                self._technique_stats[technique] = {"count": 0, "start": None, "end": None}
            self._technique_stats[technique]["start"] = __import__("time").time()

    def set_technique_end(self, technique: str):
        """Mark technique end time and record count."""
        with self._sync_lock:
            if technique in self._technique_stats:
                self._technique_stats[technique]["end"] = __import__("time").time()

    def add_note(self, sub: str, note: str):
        """Add a hunter's annotation to a subdomain."""
        sub = self._clean(sub)
        if sub in self.found:
            with self._sync_lock:
                self.found[sub].note = note

    def export_json(self) -> dict:
        """Export all results as a JSON-serializable dict."""
        return {
            sub: {
                "ips": r.ips,
                "techniques": r.techniques,
                "http_status": r.http_status,
                "takeover_risk": r.takeover_risk,
                "takeover_provider": r.takeover_provider,
                "score": r.score,
                "note": r.note,
            }
            for sub, r in self.found.items()
        }


# ─── TECHNIQUE REGISTRY (Part 9) ─────────────────────────────────────────────

TECHNIQUE_REGISTRY = {
    "t01": {
        "name": "DNS Brute Force",
        "aliases": ["bruteforce", "dns-brute", "wordlist-brute", "brute"],
        "dns_methods": ["A", "CNAME"],
        "interaction": "direct-dns",
        "data_source": "wordlist",
        "key_logic": "resolve_a(word.domain) for word in wordlist",
        "references": [
            "https://sidxparab.gitbook.io/subdomain-enumeration-guide",
            "https://medium.com/@rajeshsahan507/subdomain-enumeration-like-a-pro",
        ],
    },
    "t02": {
        "name": "Permutation Engine",
        "aliases": ["mutation", "permutation", "alteration", "perm"],
        "dns_methods": ["A", "CNAME"],
        "interaction": "direct-dns",
        "data_source": "existing-subdomains",
        "key_logic": "mutate known subs with prefix/suffix/number patterns",
        "references": [
            "https://www.yeswehack.com/learn-bug-bounty/subdomain-enumeration-expand-attack-surface",
            "gotator tool, mksub by trickest",
        ],
    },
    "t03": {
        "name": "Zone Transfer",
        "aliases": ["axfr", "ixfr", "zonetransfer", "zone-transfer", "dns-transfer"],
        "dns_methods": ["AXFR", "IXFR"],
        "interaction": "direct-dns-authoritative",
        "data_source": "nameserver",
        "key_logic": "dns.zone.from_xfr() against each NS IP",
        "references": ["https://0xffsec.com/handbook/information-gathering/subdomain-enumeration/"],
    },
    "t04": {
        "name": "DNSSEC NSEC Walking",
        "aliases": ["nsec-walk", "nsec3", "dnssec-walk", "zone-walk", "nsec"],
        "dns_methods": ["NSEC", "NSEC3", "RRSIG"],
        "interaction": "direct-dns-dnssec",
        "data_source": "dnssec-chain",
        "key_logic": "follow NSEC next-name chain until wrap-around",
        "references": ["ldns-walk, nsec3map tool"],
    },
    "t05": {
        "name": "DNS Cache Snooping",
        "aliases": ["cache-snoop", "cache-probe", "non-recursive-query", "cachesnoop"],
        "dns_methods": ["A"],
        "interaction": "indirect-resolver",
        "data_source": "resolver-cache",
        "key_logic": "clear RD bit, check if resolver has cached answer",
        "references": ["less-known technique — RD bit must be cleared"],
    },
    "t06": {
        "name": "IPv6 AAAA Enumeration",
        "aliases": ["aaaa", "ipv6-brute", "ipv6-enum", "ipv6"],
        "dns_methods": ["AAAA"],
        "interaction": "direct-dns",
        "data_source": "wordlist",
        "key_logic": "resolve_aaaa(word.domain) for word in wordlist",
        "references": ["shubhamrooter.medium.com deep subdomain methodology"],
    },
    "t07": {
        "name": "TLS SNI Probing",
        "aliases": ["sni-probe", "tls-probe", "sni-scan", "ip-range-scan", "tlssni"],
        "dns_methods": [],
        "interaction": "direct-tls-ip",
        "data_source": "ip-ranges",
        "key_logic": "TLS ClientHello with SNI, check cert SANs for domain match",
        "references": ["less-known technique — bypass DNS entirely"],
    },
    "t08": {
        "name": "CAA Record Pivoting",
        "aliases": ["caa", "caa-pivot", "caa-probe"],
        "dns_methods": ["CAA", "A"],
        "interaction": "direct-dns",
        "data_source": "wordlist",
        "key_logic": "NoAnswer != NXDOMAIN — confirms existence without A record",
        "references": ["less-known technique — DNS confirmation via absence of record"],
    },
    "t09": {
        "name": "CORS Origin Reflection",
        "aliases": ["cors", "cors-mining", "cors-reflection", "origin-probe"],
        "dns_methods": [],
        "interaction": "direct-http",
        "data_source": "wordlist + live-endpoints",
        "key_logic": "send Origin: https://word.domain, check ACAO header reflection",
        "references": ["less-known technique — HTTP-layer subdomain discovery"],
    },
    "t10": {
        "name": "DNS CHAOS Class",
        "aliases": ["chaos", "chaos-txt", "version-bind", "dns-chaos"],
        "dns_methods": ["TXT/CHAOS"],
        "interaction": "direct-dns-chaos-class",
        "data_source": "nameserver",
        "key_logic": "query rdclass=CHAOS for version.bind, hostname.bind",
        "references": ["dig CHAOS TXT version.bind — zero noise recon"],
    },
    "t11": {
        "name": "VHost Fuzzing",
        "aliases": ["vhost", "virtual-host", "host-header-fuzz", "vhost-scan"],
        "dns_methods": [],
        "interaction": "direct-http",
        "data_source": "wordlist + live-ips",
        "key_logic": "Host: word.domain header fuzzing, diff baseline response",
        "references": ["https://www.yeswehack.com/learn-bug-bounty/subdomain-enumeration"],
    },
    "t12": {
        "name": "Recursive Enumeration",
        "aliases": ["recursive", "sub-subdomain", "deep-brute", "recursive-brute"],
        "dns_methods": ["A"],
        "interaction": "direct-dns",
        "data_source": "existing-subdomains",
        "key_logic": "use found subs as new roots, brute force beneath them",
        "references": ["shubhamrooter.medium.com, our earlier conversation"],
    },
    "t13": {
        "name": "SPF/TXT Record Mining",
        "aliases": ["spf-mine", "txt-mine", "spf-walk", "spf"],
        "dns_methods": ["TXT", "MX"],
        "interaction": "direct-dns",
        "data_source": "txt-records",
        "key_logic": "parse SPF include: a: mx: directives, extract hostnames",
        "references": ["less-known technique — SPF records leak internal hostnames"],
    },
    "t14": {
        "name": "DKIM Selector Bruteforce",
        "aliases": ["dkim", "dkim-selector", "domainkey"],
        "dns_methods": ["TXT", "CNAME"],
        "interaction": "direct-dns",
        "data_source": "selector-wordlist",
        "key_logic": "query {selector}._domainkey.{domain} TXT records",
        "references": ["less-known technique — reveals mail vendor stack"],
    },
    "t15": {
        "name": "SPF Include Chain Walker",
        "aliases": ["spf-chain", "spf-recursive", "spf-tree"],
        "dns_methods": ["TXT"],
        "interaction": "direct-dns",
        "data_source": "spf-includes",
        "key_logic": "recursively follow include: directives across domains",
        "references": ["less-known technique — third-party mail service discovery"],
    },
}


def check_alias_collision(name: str) -> Optional[Dict]:
    """Check if a technique name/alias collides with TECHNIQUE_REGISTRY.

    Part 9 runtime duplicate check. Returns the conflicting entry or None.
    Does NOT block execution — only warns.
    """
    normalized = name.lower().strip().replace(" ", "-").replace("_", "-")
    for tid, entry in TECHNIQUE_REGISTRY.items():
        for alias in entry["aliases"]:
            if alias.lower() == normalized:
                return {"tid": tid, "entry": entry, "colliding_alias": alias}
    return None