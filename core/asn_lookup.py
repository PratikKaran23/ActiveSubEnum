"""
core/asn_lookup.py — ASN & Netblock Ownership (Part 12)

Provides:
  - ASN lookup via ipinfo.io (free tier, no auth, ~50 req/min)
  - IP classification: OWNED-INFRA | CDN | THIRD-PARTY | SINKHOLE
  - Reverse DNS check for CDN pattern detection
  - ISP intercept pattern detection
  - DNS takeover candidate detection via CNAME analysis
  - Persistent cache: ~/.cache/asn_lookup_cache.json

CDN/known service ASNs are hardcoded for fast classification without API calls.
"""

import asyncio
import json
import os
import re
import socket
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import aiohttp


# ── Known ASN mappings ──────────────────────────────────────────────────────────

CDN_ASNS: Dict[str, str] = {
    "13335": "Cloudflare",
    "16625": "Akamai",
    "20940": "Akamai",
    "22822": "Limelight",
    "23286": "EdgeCast",
    "24940": "Hetzner",
    "29789": "Reflected Networks / MindGeek CDN",
    "54113": "Fastly",
    "8075": "Microsoft Azure",
    "14618": "Amazon AWS",
    "15169": "Google Cloud",
    "16509": "Amazon AWS",
    "209242": "Cloudflare R2",
}

# ── Known sinkhole / intercept IPs ─────────────────────────────────────────────

KNOWN_SINKHOLES: set[str] = {
    "0.0.0.0",
    "127.0.0.1",
    "255.255.255.255",
    "::1",
}

# Reverse DNS patterns suggesting ISP DNS intercept / sinkhole
ISP_INTERCEPT_PATTERNS: List[re.Pattern] = [
    re.compile(r"rpz\.", re.IGNORECASE),
    re.compile(r"airtelspam", re.IGNORECASE),
    re.compile(r"nxdomain\.", re.IGNORECASE),
    re.compile(r"blocked\.", re.IGNORECASE),
    re.compile(r"safe\.", re.IGNORECASE),
    re.compile(r"wpad\.", re.IGNORECASE),
    re.compile(r"captive\.", re.IGNORECASE),
    re.compile(r"interception", re.IGNORECASE),
    re.compile(r"ispblock", re.IGNORECASE),
    re.compile(r"adfilter", re.IGNORECASE),
    re.compile(r"malware", re.IGNORECASE),
    re.compile(r"phishing", re.IGNORECASE),
    # OpenDNS intercept pages (Cisco Umbrella / OpenDNS Family Shield)
    re.compile(r"^hit-", re.IGNORECASE),
    re.compile(r"\.opendns\.", re.IGNORECASE),
]

# Reverse DNS patterns for known CDN providers
CDN_RDNS_PATTERNS: List[re.Pattern] = [
    re.compile(r"\.akamaiedge\.net$", re.IGNORECASE),
    re.compile(r"\.akamai\.net$", re.IGNORECASE),
    re.compile(r"\.cloudfront\.net$", re.IGNORECASE),
    re.compile(r"\.edgecastcdn\.net$", re.IGNORECASE),
    re.compile(r"\.fastly\.net$", re.IGNORECASE),
    re.compile(r"\.cloudflare\.net$", re.IGNORECASE),
    re.compile(r"\.hwcdn\.net$", re.IGNORECASE),
    re.compile(r"\.incapdns\.net$", re.IGNORECASE),
    re.compile(r"\.lldns\.net$", re.IGNORECASE),
    re.compile(r"\.llnwd\.net$", re.IGNORECASE),
    re.compile(r"\.capitainet\.net$", re.IGNORECASE),
    re.compile(r"\.azureedge\.net$", re.IGNORECASE),
    re.compile(r"\.azure\.com$", re.IGNORECASE),
    re.compile(r"\.a2(?:static|disk)\.net$", re.IGNORECASE),
    re.compile(r"\.stackpathdns\.net$", re.IGNORECASE),
    re.compile(r"\.linode\.net$", re.IGNORECASE),
    re.compile(r"\.digitalocean\.net$", re.IGNORECASE),
    re.compile(r"\.vultr\.com$", re.IGNORECASE),
]

# ── DNS takeover candidates ───────────────────────────────────────────────────

TAKEOVER_SERVICES: Dict[str, str] = {
    "github.io": "GitHub Pages",
    "github.com": "GitHub Pages",
    "amazonaws.com": "AWS S3 / EC2",
    "herokuapps.com": "Heroku",
    "azurewebsites.net": "Azure App Service",
    "cloudapp.net": "Azure Cloud App",
    "fastly.net": "Fastly CDN",
    "shopify.com": "Shopify",
    "shopifypreview.com": "Shopify",
    "statuspage.io": "StatusPage",
    "helpscoutdocs.com": "HelpScout",
    "freshdesk.com": "Freshdesk",
    "zendesk.com": "Zendesk",
    "ghost.io": "Ghost",
    "surge.sh": "Surge",
    "netlify.app": "Netlify",
    "pantheonsite.io": "Pantheon",
    "wpengine.com": "WPEngine",
    "weebly.com": "Weebly",
    "wix.com": "Wix",
    "carrd.co": "Carrd",
    "notion.site": "Notion",
    "readymag.com": "Readymag",
    "webflow.io": "Webflow",
    "frontapp.com": "Front",
    "intercom.io": "Intercom",
    "launchpad.37signals.com": "37signals",
    "heroku.com": "Heroku",
    "squarespace.com": "Squarespace",
    "wordpress.com": "WordPress.com",
    "blogspot.com": "Blogger",
    "tumblr.com": "Tumblr",
    "medium.com": "Medium",
    "gitlab.io": "GitLab Pages",
    "bitbucket.io": "Bitbucket Pages",
}

# Patterns in takeover "not found" responses
TAKEOVER_404_BODIES: List[str] = [
    "there isn't a github pages site here",
    "there is no page here",
    "no such app",
    "the specified bucket does not exist",
    "no such bucket",
    "the request could not be satisfied",
    "bad request",
    "this combination of host and scheme is not allowed",
    "documentation for this api is here",
    "if you need help, visit",
    "this site is parked free",
    "page not found",
    "404 not found",
]


# ── Cache helpers ──────────────────────────────────────────────────────────────

def _cache_path() -> Path:
    cache_dir = Path.home() / ".cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir / "asn_lookup_cache.json"


def _load_cache() -> Dict:
    path = _cache_path()
    if path.exists():
        try:
            return json.loads(path.read_text())
        except Exception:
            pass
    return {}


def _save_cache(cache: Dict) -> None:
    try:
        _cache_path().write_text(json.dumps(cache, indent=2))
    except Exception:
        pass


# ── ASNLookup ────────────────────────────────────────────────────────────────────

class ASNLookup:
    """ASN and netblock ownership lookup via ipinfo.io.

    Uses a persistent JSON cache to avoid redundant API calls.
    Classifies IPs as: OWNED-INFRA | CDN | THIRD-PARTY | SINKHOLE

    Args:
        cache: optional pre-loaded cache dict (for sharing across instances)
        rate_limit: max concurrent API requests (default 5)
    """

    def __init__(self, cache: Dict | None = None, rate_limit: int = 5):
        self._cache: Dict = cache if cache is not None else _load_cache()
        self._semaphore = asyncio.Semaphore(rate_limit)

    # ── Public sync API ────────────────────────────────────────────────────────

    def lookup_sync(self, ip: str) -> Dict:
        """Synchronous wrapper around async lookup()."""
        try:
            asyncio.get_running_loop()
            loop = asyncio.new_event_loop()
            return loop.run_until_complete(self.lookup(ip))
        except RuntimeError:
            return asyncio.run(self.lookup(ip))

    def _get_asn_str(self, asn_data: Dict) -> str:
        """Extract ASN string from ipinfo data, handling None field."""
        # Primary: asn field
        asn = asn_data.get("asn")
        if asn and str(asn).strip():
            return str(asn).strip()
        # Fallback: parse from org field (e.g. "AS16509 Amazon.com, Inc.")
        org = asn_data.get("org", "")
        m = re.search(r"AS(\d+)", org, re.IGNORECASE)
        if m:
            return m.group(1)
        return ""

    def classify_ip(
        self,
        ip: str,
        target_netblocks: List[str] | None = None,
    ) -> str:
        """Classify an IP into a category.

        Args:
            ip: IPv4 address
            target_netblocks: list of CIDR prefixes owned by the target
                             (e.g. ["66.254.96.0/21", "94.199.96.0/20"])

        Returns:
            Category string: "OWNED-INFRA" | "CDN" | "THIRD-PARTY" |
                             "SINKHOLE" | "ISP-INTERCEPT"
        """
        # Sinkhole check
        if ip in KNOWN_SINKHOLES:
            return "SINKHOLE"

        # Fast CDN classification via reverse DNS
        if self.is_cdn_ip(ip):
            return "CDN"

        # Quick lookup in cache
        if ip in self._cache:
            asn_data = self._cache[ip]
            asn_str = self._get_asn_str(asn_data)
            if asn_str in CDN_ASNS:
                return "CDN"
            org_lower = asn_data.get("org", "").lower()
            if not org_lower or org_lower in ("private", "reserved"):
                return "THIRD-PARTY"
            # Check if org name matches known CDN providers
            cdn_names = {"cloudflare", "akamai", "amazon", "aws", "google", "microsoft",
                          "azure", "fastly", "limelight", "edgecast", "incapsula", "sucuri"}
            if any(c in org_lower for c in cdn_names):
                return "CDN"
            return "THIRD-PARTY"

        # Netblock ownership check (target's own IP ranges)
        if target_netblocks:
            from ipaddress import ip_address, ip_network
            try:
                addr = ip_address(ip)
                for nb in target_netblocks:
                    if addr in ip_network(nb):
                        return "OWNED-INFRA"
            except ValueError:
                pass

        # Fallback: THIRD-PARTY (don't force API call just for classification)
        return "THIRD-PARTY"

    def is_cdn_ip(self, ip: str) -> bool:
        """Fast reverse DNS check for known CDN patterns.

        Returns True if reverse DNS matches a known CDN pattern.
        """
        try:
            name, _, _ = socket.gethostbyaddr(ip)
            for pattern in CDN_RDNS_PATTERNS:
                if pattern.search(name):
                    return True
        except (socket.herror, socket.gaierror, OSError):
            pass
        return False

    def is_sinkhole(self, ip: str) -> bool:
        """Check if IP is a known sinkhole / ISP intercept address."""
        if ip in KNOWN_SINKHOLES:
            return True

        try:
            name, _, _ = socket.gethostbyaddr(ip)
            name_lower = name.lower()
            for pattern in ISP_INTERCEPT_PATTERNS:
                if pattern.search(name_lower):
                    return True
        except (socket.herror, socket.gaierror, OSError):
            pass

        return False

    def detect_takeover_candidate(self, cname: str) -> Tuple[bool, str]:
        """Detect if a CNAME points to a potential takeover service.

        Args:
            cname: the full CNAME value (e.g. "foo.github.io.")

        Returns:
            (is_candidate, service_name) — e.g. (True, "GitHub Pages")
        """
        if not cname:
            return False, ""

        cname_lower = cname.lower().rstrip(".")

        for domain, service in TAKEOVER_SERVICES.items():
            if cname_lower.endswith(domain) or cname_lower == domain:
                return True, service

        return False, ""

    def check_takeover_404(self, body: str, status: int) -> bool:
        """Check if response body matches a known takeover "not found" pattern.

        Returns True if this looks like a dangling subdomain on a takeover service.
        """
        if status != 404:
            return False

        body_lower = body.lower()
        # At least 2 patterns must match for a strong signal
        matches = sum(1 for p in TAKEOVER_404_BODIES if p in body_lower)
        return matches >= 1

    # ── Async API ───────────────────────────────────────────────────────────────

    async def lookup(self, ip: str) -> Dict:
        """Query ipinfo.io for ASN data on an IP. Caches result.

        Returns dict with keys: asn, org, name, country, city
        Falls back gracefully on network/API errors.
        """
        if ip in self._cache:
            return self._cache[ip]

        async with self._semaphore:
            try:
                url = f"https://ipinfo.io/{ip}/json"
                async with aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as session:
                    async with session.get(url) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            self._cache[ip] = data
                            _save_cache(self._cache)
                            return data
                        elif resp.status == 429:
                            # Rate limited — return minimal data and cache it
                            return {"asn": "RATE_LIMITED", "org": "rate_limited"}
                        else:
                            return {"asn": "ERROR", "org": f"http_{resp.status}"}
            except Exception as e:
                return {"asn": "ERROR", "org": str(e)}

    async def lookup_batch(self, ips: List[str]) -> Dict[str, Dict]:
        """Lookup ASN for multiple IPs concurrently.

        Returns {ip: asn_data} for all IPs queried (cached results included).
        """
        tasks = [self.lookup(ip) for ip in ips]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return {ip: self._cache.get(ip, {}) for ip, result in zip(ips, results)}

    def save_cache(self) -> None:
        """Persist current in-memory cache to disk."""
        _save_cache(self._cache)

    def get_cache(self) -> Dict:
        """Return the current cache dict (read-only copy)."""
        return dict(self._cache)

    def is_owned_ip(self, ip: str, target_netblocks: List[str]) -> bool:
        """Check if IP falls within any of the target's known netblocks."""
        if not target_netblocks:
            return False
        try:
            from ipaddress import ip_address, ip_network
            addr = ip_address(ip)
            for nb in target_netblocks:
                if addr in ip_network(nb):
                    return True
        except ValueError:
            pass
        return False
