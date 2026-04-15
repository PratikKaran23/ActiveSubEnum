"""
core/scoring.py — Subdomain Interestingness Scorer (Part 10, Q5)

Scores each discovered subdomain 0-100 based on likelihood of being interesting.
Higher scores = more worth hunting. Output is sorted by score descending.

Scoring logic (pro bug bounty hunter perspective):
  +20  infra/auth keywords: admin, internal, corp, panel, dashboard, console
  +15  env/testing keywords: dev, staging, test, qa, uat, sandbox, debug
  +15  api/service keywords: api, graphql, grpc, ws, gateway, proxy
  +10  remote access keywords: vpn, bastion, jump, ssh, rdp, citrix
  +10  IPv6 only (rare, likely forgotten infrastructure)
  +10  Private/RFC1918 IP (misconfigured split-horizon DNS)
  +10  Self-signed or expired TLS cert
  +10  HTTP 401/403 (protected but accessible — path traversal target)
  +8   old/legacy keywords
  +8   discovered by non-standard technique (nsec, cache-snoop, chaos, etc.)
  +5   payment/financial keywords
  +5   mail infrastructure keywords
  -10  Common boring names: www, mail, ftp, blog, shop
  -5   discovered only by brute force with small wordlist
"""

import re
from typing import Dict, List


# Keyword → score boost mapping
SCORE_PATTERNS = [
    # +20: High-value infrastructure keywords
    (r"\b(admin|manage|corp|corporate|intranet|internal|panel|dashboard|portal|console|"
     r"backend|control|root|system|infra|ops|master|backup-server)\b", 20),

    # +15: Environment/testing keywords
    (r"\b(dev|develop|staging|stage|test|qa|uat|sit|sandbox|debug|preprod|preview|"
     r"review|integration|perf|load-test|demo|trial|demo)\b", 15),

    # +15: API/service keywords
    (r"\b(api|graphql|grpc|gql|rest|soap|ws|websocket|socket|stream|gateway|proxy|"
     r"service|microservice|v1|v2|v3|v4|version|app-server|worker|job)\b", 15),

    # +10: Remote access / privileged
    (r"\b(vpn|bastion|jump|jumpserver|ssh|rdp|remote|citrix|anyconnect|vnc|"
     r"jumpgate|jumphost|admin-ui|admin-panel)\b", 10),

    # +8: Old/legacy keywords
    (r"\b(old|legacy|archive|bak|backup|backup-old|deprecated|abandoned|"
     r"decommissioned|end-of-life)\b", 8),

    # +5: Payment/financial keywords
    (r"\b(pay|payment|payments|checkout|billing|invoice|subscription|subscription|"
     r"crm|erp|finance|accounting|bookkeeping|subscription|stripe)\b", 5),

    # +5: Mail infrastructure
    (r"\b(mail|smtp|smtp2|pop|imap|relay|bounce|mx|exchange|sendgrid|mailgun|"
     r"ses|postfix|mailer|newsletter|campaign)\b", 5),

    # -10: Common boring names
    (r"^\b(www|ftp|blog|shop|store|forum|wiki|cdn|assets|static|media|"
     r"img|images|files|downloads|upload|mobile-app|api-docs|status|"
     r"health|ping|smoketest)\b$", -10),
]


def score_subdomain(fqdn: str, technique_tags: List[str], http_status: str = None,
                    ip: str = None, ipv6_only: bool = False, cert_info: dict = None) -> int:
    """Score a subdomain 0-100 for interestingness to a bug bounty hunter."""
    name = fqdn.lower()
    score = 0
    matched_patterns = []

    for pattern, weight in SCORE_PATTERNS:
        if re.search(pattern, name):
            score += weight
            matched_patterns.append((pattern, weight))

    # +10: IPv6 only (rare, often forgotten infrastructure)
    if ipv6_only:
        score += 10

    # +10: Private/RFC1918 IP (misconfigured split-horizon)
    if ip:
        ip_lower = ip.lower()
        if any(ip_lower.startswith(p) for p in ["10.", "172.16.", "172.17.", "172.18.",
                                                  "172.19.", "172.20.", "172.21.", "172.22.",
                                                  "172.23.", "172.24.", "172.25.", "172.26.",
                                                  "172.27.", "172.28.", "172.29.", "172.30.",
                                                  "172.31.", "192.168.", "127."]):
            score += 10

    # +10: HTTP 401 or 403 (interesting errors)
    if http_status in ("LIVE-401", "LIVE-403"):
        score += 10

    # +10: HTTP 500 (server errors)
    if http_status == "LIVE-500":
        score += 10

    # +8: discovered via non-standard technique (higher value per finding)
    high_value_tags = {"nsec-walk", "cache-snoop", "chaos-class", "caa-confirmed",
                       "caa-record", "zonetransfer", "dns-chaos"}
    if any(t in high_value_tags for t in technique_tags):
        score += 8

    # +5: TLS cert issues
    if cert_info:
        if cert_info.get("self_signed"):
            score += 5
        if cert_info.get("expired"):
            score += 5

    # Clamp to 0-100
    return max(0, min(100, score))


def score_all(results: Dict[str, "SubdomainResult"]) -> None:
    """Score all results in-place."""
    for sub, result in results.items():
        ipv6_only = any(ip.startswith("[IPv6]") for ip in result.ips)
        ip = next((ip for ip in result.ips if not ip.startswith("[IPv6]")), None)
        result.score = score_subdomain(
            sub, result.techniques, result.http_status, ip, ipv6_only
        )


# ─── HTML/Text highlight helpers ─────────────────────────────────────────────

def score_label(score: int) -> str:
    """Return a color-coded score label for rich output."""
    if score >= 80:
        return f"[bold red]★{score}[/bold red]"
    elif score >= 50:
        return f"[bold yellow]★{score}[/bold yellow]"
    elif score >= 20:
        return f"[white]★{score}[/white]"
    else:
        return f"[dim]★{score}[/dim]"


def score_tag(score: int) -> str:
    """Return a one-word tag for the score range."""
    if score >= 80:
        return "CRITICAL"
    elif score >= 50:
        return "HUNT"
    elif score >= 20:
        return "STANDARD"
    else:
        return "LOW"