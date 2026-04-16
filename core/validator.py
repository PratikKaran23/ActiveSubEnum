"""
core/validator.py — False Positive Elimination & Live Target Validation (Part 12)

7-stage validation pipeline that takes raw enumeration results and strips
noise to produce a ranked, confirmed target list.

All stages operate on plain dicts (not dataclasses) to avoid type
conversion issues between sync and async stages.

Internal dict shape per subdomain:
{
    "fqdn": str,
    "ips": [str, ...],
    "techniques": [str, ...],
    "open_ports": [int, ...],
    "http_status": str | None,
    "http_status_code": int,
    "http_title": str | None,
    "http_server": str | None,
    "tls_tag": str | None,
    "asn_tag": str | None,
    "asn_info": dict | None,
    "waf_detected": str | None,
    "is_wildcard_noise": bool,
    "is_sinkhole": bool,
    "is_cdn_generic": bool,
    "is_takeover_candidate": bool,
    "takeover_service": str | None,
    "score": int,
    "cname": str | None,
}

Stages:
  1. Wildcard fingerprint elimination
  2. Sinkhole + ISP intercept removal
  3. Port scan filter
  4a. Fast CDN check
  4b. Full content uniqueness (normal mode only)
  5. TLS certificate validation
  6. HTTP intelligence + WAF detection
  7. ASN ownership classification

Reuses: core/port_scanner, core/asn_lookup, core/content_fingerprint,
        core/http_probe, core/scoring, core/wildcard
"""

import asyncio
import json
import os
import random
import re
import socket
import ssl
import string
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

import aiohttp
import dns.resolver

from .port_scanner import PortScanner, ALL_PORTS, QUICK_PORTS
from .asn_lookup import (
    ASNLookup, CDN_ASNS, KNOWN_SINKHOLES, ISP_INTERCEPT_PATTERNS,
    TAKEOVER_SERVICES,
)
from .content_fingerprint import ContentFingerprint
from .validation_probe import ValidatorHTTPProbe
from .scoring import score_subdomain


WILDCARD_THRESHOLD = 20
WALL_CLOCK_TIMEOUT = 30 * 60
STAGE_TIMEOUT = 10 * 60


# ── Default state factory ──────────────────────────────────────────────────────

def _default_sub() -> Dict[str, Any]:
    return {
        "fqdn": "",
        "ips": [],
        "techniques": [],
        "open_ports": [],
        "http_status": None,
        "http_status_code": 0,
        "http_title": None,
        "http_server": None,
        "tls_tag": None,
        "asn_tag": None,
        "asn_info": None,
        "waf_detected": None,
        "is_wildcard_noise": False,
        "is_sinkhole": False,
        "is_cdn_generic": False,
        "is_takeover_candidate": False,
        "takeover_service": None,
        "score": 0,
        "cname": None,
    }


# ── Normalize input ────────────────────────────────────────────────────────────

def _normalize(raw: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Convert any input format to {fqdn: sub_dict}.

    Handles:
      - SubdomainResult dataclass instances (has .ips, .techniques attrs)
      - Plain dicts {ips: [...], techniques: [...]}
      - Nested: {"total": N, "subdomains": {...}}
    """
    # Unwrap nested format if present
    if isinstance(raw, dict) and "subdomains" in raw:
        raw = raw["subdomains"]

    result = {}
    for fqdn, data in raw.items():
        sub = _default_sub()
        sub["fqdn"] = fqdn

        if hasattr(data, "ips"):
            # dataclass instance
            sub["ips"] = list(data.ips) if data.ips else []
            sub["techniques"] = list(data.techniques) if data.techniques else []
            if hasattr(data, "http_status") and data.http_status:
                sub["http_status"] = data.http_status
            if hasattr(data, "score"):
                sub["score"] = data.score
        elif isinstance(data, dict):
            sub["ips"] = list(data.get("ips", []))
            sub["techniques"] = list(data.get("techniques", []))
            sub["http_status"] = data.get("http_status")
            sub["score"] = data.get("score", 0)
        else:
            continue

        result[fqdn] = sub

    return result


def _is_confirmed(sub: Dict[str, Any]) -> bool:
    """Check if a subdomain entry passes CONFIRMED-REAL criteria.

    OWNED-INFRA entries are confirmed by definition (internal services
    may not respond to HTTP probes — IP ownership is proof enough).
    CDN-GENERIC is overridden for OWNED-INFRA since the target owns
    that infrastructure regardless of whether it serves generic content.
    All other entries require an actual HTTP response (LIVE-* status).
    """
    if not sub["open_ports"]:
        return False
    if sub["is_sinkhole"] or sub["is_wildcard_noise"]:
        return False
    if sub.get("asn_tag") == "CDN":
        return False
    # OWNED-INFRA: confirmed regardless of CDN-generic flag
    if sub.get("asn_tag") == "OWNED-INFRA":
        return True
    # CDN-generic check only applies to third-party entries
    if sub.get("is_cdn_generic"):
        return False
    # Third-party entries need a real HTTP response (LIVE-2xx only).
    # LIVE-4xx/LIVE-5xx could be intercept pages or generic CDN responses.
    status = str(sub.get("http_status") or "")
    return status.startswith("LIVE-2")


# ── ValidationStats ────────────────────────────────────────────────────────────

@dataclass
class ValidationStats:
    input_count: int = 0
    after_wildcard: int = 0
    after_sinkhole: int = 0
    after_portscan: int = 0
    after_content: int = 0
    after_tls: int = 0
    after_http: int = 0
    after_asn: int = 0
    confirmed_real: int = 0
    cdn_wildcard_ips: int = 0
    sinkhole_count: int = 0
    dead_dns_count: int = 0
    no_waf_count: int = 0
    expired_tls_count: int = 0
    takeover_candidates: int = 0
    owned_infra_count: int = 0
    stage_times: Dict[str, float] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


# ── Stage 1: Wildcard fingerprint elimination ───────────────────────────────────

async def stage1_filter_wildcards(
    subs: Dict[str, Dict[str, Any]],
    domain: str,
    target_owned_ips: Set[str] | None = None,
) -> Tuple[Dict[str, Dict[str, Any]], Set[str], ValidationStats]:
    """Identify CDN wildcard IPs via reverse DNS + HTTP probe fallback."""
    from rich.console import Console
    console = Console()
    stats = ValidationStats()
    stats.input_count = len(subs)
    if target_owned_ips is None:
        target_owned_ips = set()

    # Count subs per IP
    ip_counts: Dict[str, int] = {}
    for sub in subs.values():
        for ip in sub["ips"]:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

    # Suspect: >threshold AND not owned infra
    suspect_ips = {
        ip for ip, cnt in ip_counts.items()
        if cnt >= WILDCARD_THRESHOLD and ip not in target_owned_ips
    }

    wildcard_ips: Set[str] = set()
    cdn_rdns_patterns = [
        r"\.akamaiedge\.net$", r"\.akamai\.net$",
        r"\.cloudfront\.net$", r"\.edgecastcdn\.net$",
        r"\.fastly\.net$", r"\.cloudflare\.net$",
        r"\.hwcdn\.net$", r"\.incapdns\.net$",
        r"\.llnwd\.net$", r"\.a2(?:static|disk)\.net$",
        r"\.azureedge\.net$", r"\.stackpathdns\.net$",
    ]

    # rDNS classification
    for ip in suspect_ips:
        try:
            name, _, _ = socket.gethostbyaddr(ip)
            for pat in cdn_rdns_patterns:
                if re.search(pat, name.lower(), re.IGNORECASE):
                    wildcard_ips.add(ip)
                    break
        except (socket.herror, socket.gaierror, OSError):
            pass

    # HTTP probe for suspect IPs not classified by rDNS
    unclassified = suspect_ips - wildcard_ips
    if unclassified:
        cf = ContentFingerprint(timeout=4, concurrency=50)
        for ip in list(unclassified):
            for port in [80, 443, 8080]:
                is_wild = await cf.fast_cdn_check(ip, port, domain)
                if is_wild:
                    wildcard_ips.add(ip)
                    break

    console.print(f"  [dim]Stage 1: {len(wildcard_ips)} CDN wildcard IPs detected[/dim]")
    stats.cdn_wildcard_ips = len(wildcard_ips)

    # Tag subdomains on wildcard IPs
    for sub in subs.values():
        sub_ips = set(sub["ips"])
        if sub_ips.issubset(wildcard_ips):
            sub["is_wildcard_noise"] = True

    stats.after_wildcard = sum(1 for s in subs.values() if not s["is_wildcard_noise"])
    return subs, wildcard_ips, stats


# ── Stage 2: Sinkhole + ISP intercept ─────────────────────────────────────────

def stage2_filter_sinkholes(
    subs: Dict[str, Dict[str, Any]],
) -> Tuple[Dict[str, Dict[str, Any]], ValidationStats]:
    """Remove sinkhole IPs and ISP DNS intercept artifacts."""
    from rich.console import Console
    console = Console()
    stats = ValidationStats()
    stats.input_count = len(subs)

    for sub in subs.values():
        if not sub["ips"]:
            sub["is_sinkhole"] = True
            continue
        ip = sub["ips"][0]
        if ip in KNOWN_SINKHOLES:
            sub["is_sinkhole"] = True
            continue
        # rDNS intercept check
        try:
            name, _, _ = socket.gethostbyaddr(ip)
            name_lower = name.lower()
            for pat in ISP_INTERCEPT_PATTERNS:
                if pat.search(name_lower):
                    sub["is_sinkhole"] = True
                    break
        except (socket.herror, socket.gaierror, OSError):
            pass

    sinkhole_count = sum(1 for s in subs.values() if s["is_sinkhole"])
    console.print(f"  [dim]Stage 2: {sinkhole_count} sinkhole/intercept entries removed[/dim]")
    stats.sinkhole_count = sinkhole_count
    stats.after_sinkhole = len(subs) - sinkhole_count
    return subs, stats


# ── Stage 3: Port scan ─────────────────────────────────────────────────────────

async def stage3_port_scan(
    subs: Dict[str, Dict[str, Any]],
    fast: bool = False,
) -> Tuple[Dict[str, Dict[str, Any]], ValidationStats]:
    """TCP connect scan on all unique IPs."""
    from rich.console import Console
    console = Console()
    stats = ValidationStats()
    stats.input_count = len(subs)

    unique_ips = list(dict.fromkeys(
        ip for sub in subs.values() for ip in sub["ips"]
    ))
    if not unique_ips:
        return subs, stats

    console.print(f"  [dim]Stage 3: Port scanning {len(unique_ips)} unique IPs...[/dim]")
    t0 = time.time()

    ports = QUICK_PORTS if fast else ALL_PORTS
    scanner = PortScanner(concurrency=500, timeout=2.0)

    try:
        open_ports = await asyncio.wait_for(
            scanner.scan_all_async(unique_ips, ports),
            timeout=STAGE_TIMEOUT,
        )
    except asyncio.TimeoutError:
        console.print("  [yellow][!] Port scan timed out[/yellow]")
        open_ports = {}

    stats.stage_times["port_scan"] = time.time() - t0

    live_count = dead_count = 0
    for sub in subs.values():
        sub_ips = [ip for ip in sub["ips"] if ip in open_ports]
        if sub_ips:
            sub["open_ports"] = list(open_ports[sub_ips[0]])
            live_count += 1
        else:
            sub["open_ports"] = []
            dead_count += 1

    console.print(f"  [dim]Stage 3: {live_count} live, {dead_count} dead[/dim]")
    stats.after_portscan = live_count
    stats.dead_dns_count = dead_count
    return subs, stats


# ── Stage 4a: Fast CDN check ──────────────────────────────────────────────────

async def stage4a_fast_cdn(
    subs: Dict[str, Dict[str, Any]],
    domain: str,
    wildcard_ips: Set[str],
) -> Tuple[Dict[str, Dict[str, Any]], ValidationStats]:
    """Fast CDN check: one HTTP request per IP, random Host header."""
    from rich.console import Console
    console = Console()
    stats = ValidationStats()
    stats.input_count = len(subs)

    # Get IPs with open web ports that aren't already flagged
    ip_port_map: Dict[str, int] = {}
    for sub in subs.values():
        if sub["is_wildcard_noise"] or sub["is_sinkhole"]:
            continue
        if not sub["open_ports"]:
            continue
        for ip in sub["ips"]:
            if ip not in ip_port_map:
                for p in [80, 443, 8080, 8443]:
                    if p in sub["open_ports"]:
                        ip_port_map[ip] = p
                        break

    if not ip_port_map:
        return subs, stats

    console.print(f"  [dim]Stage 4a: Fast CDN check on {len(ip_port_map)} IPs...[/dim]")
    t0 = time.time()

    cf = ContentFingerprint(timeout=5, concurrency=100)
    cdn_results = await cf.fast_check_ips(ip_port_map, domain)

    cdn_generic_ips = {ip for ip, is_wild in cdn_results.items() if is_wild}
    cdn_generic_ips |= wildcard_ips  # also include IPs from Stage 1

    discarded = 0
    for sub in subs.values():
        if sub["is_wildcard_noise"] or sub["is_sinkhole"]:
            continue
        sub_ips = set(sub["ips"])
        # If ALL IPs for this sub are CDN generic → discard
        if sub_ips.issubset(cdn_generic_ips):
            sub["is_cdn_generic"] = True
            discarded += 1

    stats.stage_times["fast_cdn_check"] = time.time() - t0
    stats.after_content = sum(
        1 for s in subs.values()
        if not s["is_cdn_generic"] and not s["is_sinkhole"] and not s["is_wildcard_noise"]
    )
    console.print(f"  [dim]Stage 4a: {discarded} subdomains confirmed as CDN generic[/dim]")
    return subs, stats


# ── Stage 4b: Full content uniqueness ─────────────────────────────────────────

async def stage4b_full_content(
    subs: Dict[str, Dict[str, Any]],
    domain: str,
) -> Tuple[Dict[str, Dict[str, Any]], ValidationStats]:
    """Full fingerprint: compare subdomain content vs random baseline."""
    from rich.console import Console
    console = Console()
    stats = ValidationStats()
    stats.input_count = len(subs)

    # Build IP → port map for non-generic subs
    ip_port_map: Dict[str, int] = {}
    candidate_subs: List[Tuple[str, Dict[str, Any]]] = []
    for fqdn, sub in subs.items():
        if sub["is_cdn_generic"] or sub["is_sinkhole"] or sub["is_wildcard_noise"]:
            continue
        if not sub["open_ports"]:
            continue
        for ip in sub["ips"]:
            if ip not in ip_port_map:
                for p in [443, 80, 8443, 8080]:
                    if p in sub["open_ports"]:
                        ip_port_map[ip] = p
                        break
            if ip in ip_port_map:
                candidate_subs.append((fqdn, sub))
                break

    if not ip_port_map:
        return subs, stats

    console.print(f"  [dim]Stage 4b: Full content fingerprint on {len(ip_port_map)} IPs...[/dim]")
    t0 = time.time()

    cf = ContentFingerprint(timeout=5, concurrency=50)

    # Compute baselines
    baselines = {}
    for ip, port in ip_port_map.items():
        baselines[ip] = await cf.get_baseline(ip, port, domain)

    # Check each subdomain
    discarded = 0
    for fqdn, sub in candidate_subs:
        for ip in sub["ips"]:
            if ip in baselines and ip in ip_port_map:
                port = ip_port_map[ip]
                is_unique, _ = await cf.check_uniqueness(ip, port, fqdn, baselines[ip])
                if not is_unique:
                    sub["is_cdn_generic"] = True
                    discarded += 1
                break

    stats.stage_times["full_content"] = time.time() - t0
    stats.after_content = sum(
        1 for s in subs.values()
        if not s["is_cdn_generic"] and not s["is_sinkhole"] and not s["is_wildcard_noise"]
    )
    console.print(f"  [dim]Stage 4b: {discarded} subdomains discarded as CDN generic[/dim]")
    return subs, stats


# ── Stage 5: TLS validation ────────────────────────────────────────────────────

async def stage5_tls_validate(
    subs: Dict[str, Dict[str, Any]],
) -> Tuple[Dict[str, Dict[str, Any]], ValidationStats]:
    """TLS cert check — only on owned-infra and third-party IPs with port 443."""
    from rich.console import Console
    console = Console()
    stats = ValidationStats()
    stats.input_count = len(subs)

    # Only probe TLS on IPs that are NOT CDN generic — CDN certs are irrelevant
    candidates = [
        (fqdn, sub["ips"][0], 443)
        for fqdn, sub in subs.items()
        if 443 in sub["open_ports"]
        and sub["ips"]
        and not sub.get("is_cdn_generic")
    ]

    if not candidates:
        stats.after_tls = len(subs)
        return subs, stats

    # Limit to 200 most interesting (highest score candidate or owned infra)
    if len(candidates) > 200:
        candidates = candidates[:200]

    console.print(f"  [dim]Stage 5: TLS validation on {len(candidates)} subdomains...[/dim]")
    t0 = time.time()

    def _check_tls(ip: str, port: int, hostname: str) -> Optional[str]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    if not cert_der:
                        return "TLS-SELF"
                    try:
                        from cryptography import x509
                        from cryptography.hazmat.backends import default_backend
                        cert_obj = x509.load_der_x509_certificate(cert_der, default_backend())
                        from datetime import datetime, timezone
                        if cert_obj.not_valid_after_ < datetime.now(timezone.utc):
                            return "TLS-EXPIRED"
                        hostname_lower = hostname.lower()
                        try:
                            san_ext = cert_obj.extensions.get_extension_for_class(
                                x509.UnsubjectAlternativeName
                            )
                            for san in san_ext.value.get_values_for_type(x509.DNSName):
                                if san.lower() == hostname_lower or san == "*":
                                    return "TLS-MATCH"
                            return "TLS-MISMATCH"
                        except Exception:
                            return "TLS-MATCH"
                    except ImportError:
                        return "TLS-SELF"
        except Exception:
            return None

    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [
            loop.run_in_executor(executor, _check_tls, ip, port, fqdn)
            for fqdn, ip, port in candidates
        ]
        results = await asyncio.gather(*futures, return_exceptions=True)

    expired = 0
    for (fqdn, _, _), result in zip(candidates, results):
        if isinstance(result, str):
            subs[fqdn]["tls_tag"] = result
            if result == "TLS-EXPIRED":
                expired += 1

    stats.stage_times["tls"] = time.time() - t0
    stats.expired_tls_count = expired
    stats.after_tls = len(subs)
    console.print(f"  [dim]Stage 5: {expired} expired/self-signed certs[/dim]")
    return subs, stats


# ── Stage 6: HTTP intelligence + WAF ─────────────────────────────────────────

async def stage6_http_intelligence(
    subs: Dict[str, Dict[str, Any]],
    fast: bool = False,
) -> Tuple[Dict[str, Dict[str, Any]], ValidationStats]:
    """HTTP probe via IP + Host header — bypasses DNS resolution.

    Probes only subdomains that have open web ports and are NOT CDN generic.
    """
    from rich.console import Console
    console = Console()
    stats = ValidationStats()
    stats.input_count = len(subs)

    # Pre-mark owned infra by IP (Stage 7 runs AFTER Stage 6, but we need
    # asn_tag for the CDN-generic bypass filter). This is a LOCAL check only.
    OWNED_NETBLOCKS = ["66.254.112.0/20", "94.199.96.0/20"]
    from ipaddress import ip_address, ip_network
    for sub in subs.values():
        for ip in sub.get("ips", []):
            try:
                addr = ip_address(ip)
                for nb in OWNED_NETBLOCKS:
                    if addr in ip_network(nb):
                        sub["asn_tag"] = "OWNED-INFRA"
                        break
            except ValueError:
                pass

    # Build target list: (ip, hostname, port)
    # Probe ALL subdomains with open ports — including CDN-generic ones.
    # CDN-generic subs on third-party CDNs may still serve specific content
    # (the generic check is a heuristic, not a certainty). We need HTTP results
    # to make final confirmation. Probing them costs one extra request/IP.
    # Skip only: sinkholes, wildcard noise, or subs with no open ports.
    targets: List[Tuple[str, str, int]] = []
    for fqdn, sub in subs.items():
        if sub.get("is_sinkhole") or sub.get("is_wildcard_noise"):
            continue
        if not sub.get("open_ports"):
            continue
        if not sub["ips"]:
            continue
        # Pick first open web port
        port = next((p for p in sub["open_ports"] if p in (80, 443, 8080, 8443)), None)
        if port:
            targets.append((sub["ips"][0], fqdn, port))

    # If too many targets, prioritize: owned-infra first, then non-CDN third-party
    # Cap at 500 to keep runtime reasonable
    MAX_HTTP_PROBES = 500
    if len(targets) > MAX_HTTP_PROBES:
        # Separate owned-infra from third-party
        owned = []
        third_party = []
        for ip, fqdn, port in targets:
            asn_tag = subs[fqdn].get("asn_tag")
            if asn_tag == "OWNED-INFRA":
                owned.append((ip, fqdn, port))
            else:
                third_party.append((ip, fqdn, port))
        # Take all owned, fill remaining with sample of third-party
        remaining = MAX_HTTP_PROBES - len(owned)
        targets = owned + third_party[:remaining]
        console.print(f"  [dim]Stage 6: limiting to {len(targets)} targets (prioritizing owned-infra)[/dim]")

    if not targets:
        return subs, stats

    console.print(f"  [dim]Stage 6: HTTP probing {len(targets)} targets via IP + Host header...[/dim]")
    t0 = time.time()

    # Use ValidatorHTTPProbe — connects directly to IP with Host header
    probe = ValidatorHTTPProbe(timeout=5, concurrency=100, follow_redirects=False)

    results = await probe.probe_batch(targets)

    no_waf = 0
    for (ip, hostname, _), result in zip(targets, results.values()):
        # Find the matching subdomain
        sub = subs.get(hostname)
        if not sub:
            continue

        sub["http_status"] = result.status_tag
        sub["http_status_code"] = result.status_code
        sub["http_title"] = result.title
        sub["http_server"] = result.server
        sub["waf_detected"] = result.waf_detected

        if not result.waf_detected and result.status_tag.startswith("LIVE-"):
            no_waf += 1

    stats.no_waf_count = no_waf
    stats.stage_times["http"] = time.time() - t0
    stats.after_http = len(targets)
    console.print(f"  [dim]Stage 6: {no_waf} without WAF[/dim]")
    return subs, stats


# ── Stage 7: ASN classification ──────────────────────────────────────────────

async def stage7_asn_classify(
    subs: Dict[str, Dict[str, Any]],
    target_netblocks: List[str] | None = None,
) -> Tuple[Dict[str, Dict[str, Any]], ValidationStats]:
    """ASN lookup and OWNED-INFRA / CDN / THIRD-PARTY tagging.

    Dynamically builds target_netblocks from the most common ASN among
    the found subdomains. If a single ASN dominates (>50% of unique IPs),
    treat all IPs in that ASN as OWNED-INFRA.
    Falls back to explicit netblocks (MindGeek ranges) if dynamic detection fails.
    """
    from collections import Counter
    from rich.console import Console
    console = Console()
    stats = ValidationStats()
    stats.input_count = len(subs)
    if target_netblocks is None:
        target_netblocks = []

    unique_ips = list(dict.fromkeys(
        ip for sub in subs.values() for ip in sub["ips"]
    ))

    if not unique_ips:
        return subs, stats

    console.print(f"  [dim]Stage 7: ASN lookup on {len(unique_ips)} unique IPs...[/dim]")
    t0 = time.time()

    lookup = ASNLookup(rate_limit=1)  # 1 req/sec to avoid ipinfo.io rate limits
    asn_results = await lookup.lookup_batch(unique_ips)
    lookup.save_cache()

    # Dynamically build target netblocks from dominant ASN
    if not target_netblocks:
        asn_counter = Counter()
        for ip, info in asn_results.items():
            asn_str = lookup._get_asn_str(info)
            if asn_str and asn_str not in ("RATE_LIMITED", "ERROR", ""):
                asn_counter[asn_str] += 1

        # If one ASN dominates (>50% of unique IPs) and it's not a known CDN,
        # treat it as the target's own infrastructure
        if asn_counter:
            most_common_asn, count = asn_counter.most_common(1)[0]
            if count / len(unique_ips) > 0.5 and most_common_asn not in CDN_ASNS:
                # Build CIDR from prefix — use /16 as a reasonable estimate
                # We'll also check if ipinfo returns a 'netblock' field
                for ip, info in asn_results.items():
                    if lookup._get_asn_str(info) == most_common_asn:
                        # Extract prefix from IP: 99.86.182.x → 99.86.0.0/16
                        if "." in ip:
                            parts = ip.split(".")
                            target_netblocks.append(f"{parts[0]}.{parts[1]}.0.0/16")
                        break
                console.print(f"  [dim]  Detected dominant ASN {most_common_asn} — using as OWNED-INFRA[/dim]")

        # Fall back to explicit netblocks if dynamic detection failed
        if not target_netblocks:
            # Only use MindGeek ranges as fallback when we have NO target-specific data
            # This is a safe default — only apply if we have zero other info
            if not asn_counter:
                target_netblocks = ["66.254.112.0/20", "94.199.96.0/20"]

    owned = 0
    for sub in subs.values():
        ip = sub["ips"][0] if sub["ips"] else None
        if not ip or ip not in asn_results:
            continue
        info = asn_results[ip]
        sub["asn_info"] = info

        # Check OWNED-INFRA first
        if lookup.is_owned_ip(ip, target_netblocks):
            sub["asn_tag"] = "OWNED-INFRA"
            owned += 1
        else:
            asn_str = lookup._get_asn_str(info)
            if asn_str in CDN_ASNS:
                sub["asn_tag"] = "CDN"
            else:
                org = (info.get("org") or "").lower()
                cdn_keywords = {"cloudflare", "akamai", "amazon", "aws", "google", "microsoft",
                                "azure", "fastly", "limelight", "edgecast", "incapsula", "sucuri"}
                if any(k in org for k in cdn_keywords):
                    sub["asn_tag"] = "CDN"
                else:
                    sub["asn_tag"] = "THIRD-PARTY"

    stats.stage_times["asn"] = time.time() - t0
    stats.owned_infra_count = owned
    stats.after_asn = len(subs)
    console.print(f"  [dim]Stage 7: {owned} owned-infra IPs[/dim]")
    return subs, stats


# ── Scoring ────────────────────────────────────────────────────────────────────

def _score_one(sub: Dict[str, Any]) -> int:
    """Apply Part 10 scoring to a validated subdomain dict."""
    ipv6_only = any(ip.startswith("[IPv6]") for ip in sub["ips"])
    ip = next((i for i in sub["ips"] if not i.startswith("[IPv6]")), None)

    cert_info = {}
    if sub.get("tls_tag") == "TLS-EXPIRED":
        cert_info["expired"] = True
    if sub.get("tls_tag") == "TLS-SELF":
        cert_info["self_signed"] = True

    score = score_subdomain(
        fqdn=sub["fqdn"],
        technique_tags=sub["techniques"],
        http_status=sub.get("http_status"),
        ip=ip,
        ipv6_only=ipv6_only,
        cert_info=cert_info if cert_info else None,
    )

    if sub.get("asn_tag") == "OWNED-INFRA":
        score += 30
    if sub.get("asn_tag") == "CDN" and not sub.get("http_status"):
        score -= 10

    return max(0, min(100, score))


# ── Takeover detection ─────────────────────────────────────────────────────────

async def detect_takeovers(
    subs: Dict[str, Dict[str, Any]],
    domain: str,
) -> List[str]:
    """Detect CNAMEs pointing to takeover-prone services.

    Runs CNAME lookups concurrently with a semaphore to avoid flooding DNS.
    """
    candidates = [
        fqdn for fqdn, sub in subs.items()
        if not sub["is_sinkhole"] and not sub["is_wildcard_noise"]
    ]
    if not candidates:
        return []

    lookup = ASNLookup()
    sem = asyncio.Semaphore(50)  # max 50 concurrent DNS lookups
    loop = asyncio.get_event_loop()

    def _resolve_cname(fqdn: str) -> Optional[str]:
        try:
            r = dns.resolver.Resolver()
            r.nameservers = ["1.1.1.1", "8.8.8.8"]
            r.timeout = 3
            r.lifetime = 3
            ans = r.resolve(fqdn, "CNAME")
            return str(ans[0].target).rstrip(".")
        except Exception:
            return None

    async def _check_one(fqdn: str) -> Optional[str]:
        async with sem:
            cname = await loop.run_in_executor(None, _resolve_cname, fqdn)
            if not cname:
                return None
            sub = subs[fqdn]
            sub["cname"] = cname
            is_cand, service = lookup.detect_takeover_candidate(cname)
            if is_cand:
                sub["is_takeover_candidate"] = True
                sub["takeover_service"] = service
                return fqdn
            return None

    tasks = [_check_one(fqdn) for fqdn in candidates]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    takeover_list = [r for r in results if isinstance(r, str)]
    return takeover_list


# ── ISP pre-flight ────────────────────────────────────────────────────────────

def detect_isp_intercept() -> bool:
    """Compare system resolver vs 1.1.1.1 for example.com."""
    try:
        sys_ip = socket.gethostbyname("example.com")
        r = dns.resolver.Resolver()
        r.nameservers = ["1.1.1.1"]
        r.timeout = 3
        r.lifetime = 3
        cloud_ip = str(r.resolve("example.com", "A")[0])
        if sys_ip != cloud_ip and not sys_ip.startswith("93.184."):
            return True
    except Exception:
        pass
    return False


# ── Tags helper ────────────────────────────────────────────────────────────────

def _tags(sub: Dict[str, Any]) -> List[str]:
    t = []
    if sub.get("is_wildcard_noise"):
        t.append("CDN-WILDCARD")
    if sub.get("is_sinkhole"):
        t.append("SINKHOLE")
    if sub.get("is_cdn_generic"):
        t.append("CDN-GENERIC")
    if sub.get("is_takeover_candidate"):
        t.append("TAKEOVER-CANDIDATE")
    if sub.get("tls_tag"):
        t.append(sub["tls_tag"])
    if sub.get("asn_tag"):
        t.append(sub["asn_tag"])
    if sub.get("waf_detected"):
        t.append(f"WAF-{sub['waf_detected'].upper()}")
    elif (sub.get("http_status") or "").startswith("LIVE-") and not sub.get("waf_detected"):
        t.append("NO-WAF")
    if sub.get("http_status") in ("LIVE-401", "LIVE-403"):
        t.append("AUTH-BYPASS")
    if sub.get("http_status") == "LIVE-500":
        t.append("SERVER-ERROR")
    return t


# ── Output generation ─────────────────────────────────────────────────────────

def _save_outputs(
    subs: Dict[str, Dict[str, Any]],
    domain: str,
    output_dir: str,
    stats: ValidationStats,
    takeover_list: List[str],
) -> Dict[str, int]:
    os.makedirs(output_dir, exist_ok=True)
    outputs = {}

    def _p(name: str) -> str:
        return os.path.join(output_dir, f"{domain}.{name}")

    # CONFIRMED-REAL: has ports, not sinkhole, not CDN infrastructure.
    # Exclude: is_wildcard_noise (Stage 1), is_cdn_generic (Stage 4a),
    # and asn_tag=CDN (Stage 7) — CDN-hosted subdomains are noise for
    # owned-infra enumeration but kept in CDN-WILDCARD.txt for reference.
    # Require LIVE-* http_status for non-OWNED-INFRA entries.
    confirmed = [
        (fqdn, sub) for fqdn, sub in subs.items()
        if _is_confirmed(sub)
    ]
    confirmed.sort(key=lambda x: x[1]["score"], reverse=True)

    lines = []
    for fqdn, sub in confirmed:
        ip_str = ",".join(sub["ips"])
        ports = ",".join(map(str, sub["open_ports"])) or "none"
        status = sub.get("http_status") or "NO-HTTP"
        tags_str = ",".join(_tags(sub))
        lines.append(f"{fqdn} | {ip_str} | ports={ports} | {status} | score={sub['score']} | {tags_str}")

    p = _p("CONFIRMED-REAL.txt")
    outputs[p] = len(lines)
    with open(p, "w") as f:
        f.write("\n".join(lines))

    # HIGH-PRIORITY
    hp = [f"{fqdn} | {','.join(sub['ips'])} | score={sub['score']} | {','.join(_tags(sub))}"
          for fqdn, sub in confirmed if sub["score"] >= 60]
    p = _p("HIGH-PRIORITY.txt")
    outputs[p] = len(hp)
    with open(p, "w") as f:
        f.write("\n".join(hp))

    # OWNED-INFRA
    owned = [f"{fqdn} | {','.join(sub['ips'])} | {sub.get('asn_info', {}).get('org', '')} | score={sub['score']}"
             for fqdn, sub in confirmed if sub.get("asn_tag") == "OWNED-INFRA"]
    p = _p("OWNED-INFRA.txt")
    outputs[p] = len(owned)
    with open(p, "w") as f:
        f.write("\n".join(owned))

    # CDN-WILDCARD
    cdn = [f"{fqdn} | {','.join(sub['ips'])} | {','.join(_tags(sub))}"
           for fqdn, sub in subs.items()
           if sub.get("is_wildcard_noise") or sub.get("is_cdn_generic")]
    p = _p("CDN-WILDCARD.txt")
    outputs[p] = len(cdn)
    with open(p, "w") as f:
        f.write("\n".join(cdn))

    # DEAD-DNS
    dead = [f"{fqdn} | {','.join(sub['ips'])}"
            for fqdn, sub in subs.items() if not sub["open_ports"]]
    p = _p("DEAD-DNS.txt")
    outputs[p] = len(dead)
    with open(p, "w") as f:
        f.write("\n".join(dead))

    # NO-WAF: all subdomains that were HTTP probed and had no WAF detected.
    # Don't restrict to CONFIRMED-REAL only — a subdomain with open ports
    # but NO-HTTP response is still a valid live target (just a firewall).
    no_waf = [
        f"{fqdn} | {','.join(sub['ips'])} | {sub.get('http_status', 'NO-HTTP')} | score={sub['score']}"
        for fqdn, sub in subs.items()
        if not sub.get("waf_detected") and sub.get("http_status") and sub.get("open_ports")
    ]
    p = _p("NO-WAF.txt")
    outputs[p] = len(no_waf)
    with open(p, "w") as f:
        f.write("\n".join(no_waf))

    # EXPIRED-TLS
    exp = [f"{fqdn} | {sub['ips'][0] if sub['ips'] else 'N/A'} | {sub.get('tls_tag')} | score={sub['score']}"
           for fqdn, sub in confirmed if sub.get("tls_tag") in ("TLS-EXPIRED", "TLS-SELF")]
    p = _p("EXPIRED-TLS.txt")
    outputs[p] = len(exp)
    with open(p, "w") as f:
        f.write("\n".join(exp))

    # TAKEOVER
    take = [f"{fqdn} | {sub.get('cname')} | {sub.get('takeover_service')} | score={sub['score']}"
            for fqdn, sub in confirmed if fqdn in takeover_list]
    p = _p("TAKEOVER-CANDIDATES.txt")
    outputs[p] = len(take)
    with open(p, "w") as f:
        f.write("\n".join(take))

    # FULL-REPORT.json
    report = {
        "domain": domain,
        "validated_count": len(subs),
        "confirmed_real": len(confirmed),
        "stats": {
            "input": stats.input_count,
            "after_wildcard": stats.after_wildcard,
            "after_sinkhole": stats.after_sinkhole,
            "after_portscan": stats.after_portscan,
            "after_content": stats.after_content,
            "after_asn": stats.after_asn,
            "cdn_wildcard_ips": stats.cdn_wildcard_ips,
            "sinkhole": stats.sinkhole_count,
            "dead_dns": stats.dead_dns_count,
            "no_waf": stats.no_waf_count,
            "expired_tls": stats.expired_tls_count,
            "takeover_candidates": len(takeover_list),
            "owned_infra": stats.owned_infra_count,
            "stage_times": stats.stage_times,
        },
        "results": subs,
    }
    p = _p("FULL-REPORT.json")
    outputs[p] = len(subs)
    with open(p, "w") as f:
        json.dump(report, f, indent=2)

    return outputs


# ── Summary card ───────────────────────────────────────────────────────────────

def _print_summary(
    subs: Dict[str, Dict[str, Any]],
    stats: ValidationStats,
    output_paths: Dict[str, int],
    domain: str,
    takeover_list: List[str],
):
    from rich.console import Console
    from rich.table import Table
    console = Console()

    confirmed = sum(1 for s in subs.values() if _is_confirmed(s))
    high = sum(1 for s in subs.values() if s["score"] >= 60)
    med = sum(1 for s in subs.values() if 20 <= s["score"] < 60)
    low = sum(1 for s in subs.values() if s["score"] < 20 and s["open_ports"])

    elim_rate = 0.0
    if stats.input_count > 0:
        elim_rate = (stats.input_count - confirmed) / stats.input_count * 100

    tbl = Table(title=f"Validation Results — {domain}", show_header=True)
    tbl.add_column("Metric", style="cyan", width=32)
    tbl.add_column("Value", style="white")

    tbl.add_row("DNS-resolved subdomains", str(stats.input_count))
    tbl.add_row("After CDN wildcard filter", f"[yellow]-{stats.cdn_wildcard_ips} IPs[/yellow]")
    tbl.add_row("After sinkhole removal", f"[yellow]-{stats.sinkhole_count} removed[/yellow]")
    tbl.add_row("After port scan (live services)", str(stats.after_portscan))
    tbl.add_row("After content uniqueness", str(stats.after_content))
    tbl.add_row("", "")
    tbl.add_row("[bold green]CONFIRMED REAL[/bold green]", f"[bold green]{confirmed}[/bold green]")
    tbl.add_row("False positives eliminated", f"[red]{elim_rate:.1f}%[/red]")
    tbl.add_row("", "")
    tbl.add_row("High priority (score >= 60)", f"[bold yellow]{high}[/bold yellow]")
    tbl.add_row("Medium priority (20-59)", str(med))
    tbl.add_row("Low priority (< 20)", str(low))
    tbl.add_row("", "")
    tbl.add_row("CDN wildcard IPs detected", str(stats.cdn_wildcard_ips))
    tbl.add_row("Sinkhole/intercept entries", str(stats.sinkhole_count))
    tbl.add_row("Dead DNS (no open ports)", str(stats.dead_dns_count))
    tbl.add_row("No-WAF subdomains", str(stats.no_waf_count))
    tbl.add_row("Expired/self-signed TLS", str(stats.expired_tls_count))
    tbl.add_row("DNS takeover candidates", f"[bold magenta]{len(takeover_list)}[/bold magenta]")
    tbl.add_row("Owned infra subdomains", f"[bold cyan]{stats.owned_infra_count}[/bold cyan]")

    console.print()
    console.print(tbl)
    console.print()
    console.print("[bold]Output files:[/bold]")
    for path, count in output_paths.items():
        fname = os.path.basename(path)
        console.print(f"  [green]{fname}[/green]  ({count} entries)")
    console.print()


# ── Main pipeline ─────────────────────────────────────────────────────────────

async def _run_pipeline(
    raw_subs: Dict[str, Any],
    domain: str,
    fast: bool = False,
    output_dir: str = ".",
) -> Tuple[Dict[str, Dict[str, Any]], ValidationStats, List[str]]:
    from rich.console import Console
    console = Console()

    if detect_isp_intercept():
        console.print(
            "\n[bold yellow][!] ISP DNS interception detected.[/bold yellow] "
            "Using 1.1.1.1 and 8.8.8.8 for all validation queries."
        )

    console.print(f"\n[bold cyan][*] Validation Pipeline — 7 stages[/bold cyan]")
    subs = _normalize(raw_subs)
    console.print(f"  Input: {len(subs)} subdomains | Domain: {domain} | Fast: {fast}")

    stats = ValidationStats()
    stats.input_count = len(subs)
    wall_start = time.time()

    # Target owned IPs (MindGeek ranges)
    target_owned_ips = {
        ip for sub in subs.values()
        for ip in sub["ips"]
        if ip.startswith("66.254.") or ip.startswith("94.199.")
    }

    # ── Stage 1 ────────────────────────────────────────────────────────────────
    try:
        subs, wildcard_ips, s1 = await asyncio.wait_for(
            stage1_filter_wildcards(subs, domain, target_owned_ips),
            timeout=STAGE_TIMEOUT,
        )
        stats.cdn_wildcard_ips = s1.cdn_wildcard_ips
        stats.after_wildcard = s1.after_wildcard
        console.print(f"  [green]✓[/green] Stage 1 — {s1.cdn_wildcard_ips} CDN wildcard IPs")
    except asyncio.TimeoutError:
        console.print("  [yellow]![/yellow] Stage 1 timed out")
        wildcard_ips = set()
    except Exception as e:
        console.print(f"  [red]✗[/yellow] Stage 1 failed: {e}")
        wildcard_ips = set()

    # ── Stage 2 ────────────────────────────────────────────────────────────────
    try:
        subs, s2 = stage2_filter_sinkholes(subs)
        stats.sinkhole_count = s2.sinkhole_count
        stats.after_sinkhole = s2.after_sinkhole
        console.print(f"  [green]✓[/green] Stage 2 — {s2.sinkhole_count} sinkholes removed")
    except Exception as e:
        console.print(f"  [red]✗[/red] Stage 2 failed: {e}")

    # ── Stage 3 ────────────────────────────────────────────────────────────────
    try:
        subs, s3 = await asyncio.wait_for(
            stage3_port_scan(subs, fast=fast),
            timeout=STAGE_TIMEOUT,
        )
        stats.after_portscan = s3.after_portscan
        stats.dead_dns_count = s3.dead_dns_count
        stats.stage_times["port_scan"] = s3.stage_times.get("port_scan", 0)
    except asyncio.TimeoutError:
        console.print("  [yellow]![/yellow] Stage 3 timed out")
    except Exception as e:
        console.print(f"  [red]✗[/red] Stage 3 failed: {e}")

    # ── Stage 4a (always) ─────────────────────────────────────────────────────
    try:
        subs, s4a = await asyncio.wait_for(
            stage4a_fast_cdn(subs, domain, wildcard_ips),
            timeout=STAGE_TIMEOUT,
        )
        stats.after_content = s4a.after_content
        console.print(f"  [green]✓[/green] Stage 4a — CDN generic check done")
    except asyncio.TimeoutError:
        console.print("  [yellow]![/yellow] Stage 4a timed out")
    except Exception as e:
        console.print(f"  [red]✗[/red] Stage 4a failed: {e}")

    # ── Stage 4b (normal mode only) ───────────────────────────────────────────
    if not fast:
        try:
            subs, s4b = await asyncio.wait_for(
                stage4b_full_content(subs, domain),
                timeout=STAGE_TIMEOUT,
            )
            stats.after_content = s4b.after_content
            console.print(f"  [green]✓[/green] Stage 4b — content uniqueness done")
        except asyncio.TimeoutError:
            console.print("  [yellow]![/yellow] Stage 4b timed out (use --fast-validate)")
        except Exception as e:
            console.print(f"  [red]✗[/red] Stage 4b failed: {e}")

    # ── Stage 5 ────────────────────────────────────────────────────────────────
    try:
        subs, s5 = await asyncio.wait_for(
            stage5_tls_validate(subs),
            timeout=STAGE_TIMEOUT,
        )
        stats.expired_tls_count = s5.expired_tls_count
        stats.after_tls = s5.after_tls
        console.print(f"  [green]✓[/green] Stage 5 — TLS validation done")
    except asyncio.TimeoutError:
        console.print("  [yellow]![/yellow] Stage 5 timed out")
    except Exception as e:
        console.print(f"  [red]✗[/red] Stage 5 failed: {e}")

    # ── Stage 6 ────────────────────────────────────────────────────────────────
    try:
        subs, s6 = await asyncio.wait_for(
            stage6_http_intelligence(subs, fast=fast),
            timeout=STAGE_TIMEOUT,
        )
        stats.no_waf_count = s6.no_waf_count
        stats.after_http = s6.after_http
        console.print(f"  [green]✓[/green] Stage 6 — HTTP intelligence done")
    except asyncio.TimeoutError:
        console.print("  [yellow]![/yellow] Stage 6 timed out")
    except Exception as e:
        console.print(f"  [red]✗[/red] Stage 6 failed: {e}")

    # ── Stage 7 ────────────────────────────────────────────────────────────────
    try:
        subs, s7 = await asyncio.wait_for(
            stage7_asn_classify(subs),
            timeout=STAGE_TIMEOUT,
        )
        stats.owned_infra_count = s7.owned_infra_count
        stats.after_asn = s7.after_asn
        console.print(f"  [green]✓[/green] Stage 7 — ASN classification done")
    except asyncio.TimeoutError:
        console.print("  [yellow]![/yellow] Stage 7 timed out")
    except Exception as e:
        console.print(f"  [red]✗[/red] Stage 7 failed: {e}")

    # ── Scoring ────────────────────────────────────────────────────────────────
    for sub in subs.values():
        sub["score"] = _score_one(sub)

    confirmed_list = [(fqdn, s) for fqdn, s in subs.items() if _is_confirmed(s)]
    stats.confirmed_real = len(confirmed_list)

    # ── Takeover detection ─────────────────────────────────────────────────────
    try:
        takeover_list = await asyncio.wait_for(
            detect_takeovers(subs, domain),
            timeout=STAGE_TIMEOUT,
        )
        stats.takeover_candidates = len(takeover_list)
        console.print(f"  [green]✓[/green] Takeover detection — {len(takeover_list)} candidates")
    except Exception as e:
        console.print(f"  [yellow]![/yellow] Takeover detection failed: {e}")
        takeover_list = []

    # ── Timeout safeguard ─────────────────────────────────────────────────────
    elapsed = time.time() - wall_start
    if elapsed > WALL_CLOCK_TIMEOUT:
        console.print(
            f"\n[bold yellow][!] Validation running {elapsed/60:.0f}+ minutes.[/bold yellow] "
            "Saving partial results."
        )

    return subs, stats, takeover_list


# ── Public entry point ─────────────────────────────────────────────────────────

def validate(
    raw_subs: Dict[str, Any],
    domain: str,
    fast: bool = False,
    output_dir: str = ".",
) -> Dict[str, Dict[str, Any]]:
    """Synchronous entry point for activesubenum.py integration."""
    subs, stats, takeover_list = asyncio.run(
        _run_pipeline(raw_subs, domain, fast, output_dir)
    )
    output_paths = _save_outputs(subs, domain, output_dir, stats, takeover_list)
    _print_summary(subs, stats, output_paths, domain, takeover_list)
    return subs
