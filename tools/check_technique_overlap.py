#!/usr/bin/env python3
"""
tools/check_technique_overlap.py — Technique Overlap Detection (Part 9)

Run this BEFORE adding a new technique to the codebase. It checks whether
your proposed technique overlaps with existing ones.

USAGE:
  python3 tools/check_technique_overlap.py \
    --name "My New Technique" \
    --aliases "http-probe,web-probe" \
    --dns-methods "A,CNAME" \
    --interaction "direct-http" \
    --data-source "wordlist" \
    --description "Sends HTTP requests with custom headers to discover subs" \
    --reference "https://some-blog.com/technique"

EXIT CODES:
  0 = all checks pass (or warnings only — review required)
  1 = BLOCK — technique is already implemented or too similar

This is a developer tool, not a runtime check. Runtime duplicate detection
is handled in core/results.py (check_alias_collision()).
"""

import argparse
import re
import sys
from pathlib import Path

# ─── Registry (copied from techniques/__init__.py) ───────────────────────────

TECHNIQUE_REGISTRY = {
    "t01": {
        "name": "DNS Brute Force",
        "aliases": ["bruteforce", "dns-brute", "wordlist-brute", "brute"],
        "dns_methods": ["A", "CNAME"],
        "interaction": "direct-dns",
        "data_source": "wordlist",
        "key_logic": "resolve_a(word.domain) for word in wordlist",
    },
    "t02": {
        "name": "Permutation Engine",
        "aliases": ["mutation", "permutation", "alteration", "permutation"],
        "dns_methods": ["A", "CNAME"],
        "interaction": "direct-dns",
        "data_source": "existing-subdomains",
        "key_logic": "mutate known subs with prefix/suffix/number patterns",
    },
    "t03": {
        "name": "Zone Transfer",
        "aliases": ["axfr", "ixfr", "zonetransfer", "zone-transfer"],
        "dns_methods": ["AXFR", "IXFR"],
        "interaction": "direct-dns-authoritative",
        "data_source": "nameserver",
        "key_logic": "dns.zone.from_xfr() against each NS IP",
    },
    "t04": {
        "name": "DNSSEC NSEC Walking",
        "aliases": ["nsec-walk", "nsec3", "dnssec-walk", "zone-walk", "nsec"],
        "dns_methods": ["NSEC", "NSEC3", "RRSIG"],
        "interaction": "direct-dns-dnssec",
        "data_source": "dnssec-chain",
        "key_logic": "follow NSEC next-name chain until wrap-around",
    },
    "t05": {
        "name": "DNS Cache Snooping",
        "aliases": ["cache-snoop", "cache-probe", "non-recursive-query", "cachesnoop"],
        "dns_methods": ["A"],
        "interaction": "indirect-resolver",
        "data_source": "resolver-cache",
        "key_logic": "clear RD bit, check if resolver has cached answer",
    },
    "t06": {
        "name": "IPv6 AAAA Enumeration",
        "aliases": ["aaaa", "ipv6-brute", "ipv6-enum", "ipv6"],
        "dns_methods": ["AAAA"],
        "interaction": "direct-dns",
        "data_source": "wordlist",
        "key_logic": "resolve_aaaa(word.domain) for word in wordlist",
    },
    "t07": {
        "name": "TLS SNI Probing",
        "aliases": ["sni-probe", "tls-probe", "sni-scan", "ip-range-scan", "tlssni"],
        "dns_methods": [],
        "interaction": "direct-tls-ip",
        "data_source": "ip-ranges",
        "key_logic": "TLS ClientHello with SNI, check cert SANs for domain match",
    },
    "t08": {
        "name": "CAA Record Pivoting",
        "aliases": ["caa", "caa-pivot", "caa-probe"],
        "dns_methods": ["CAA", "A"],
        "interaction": "direct-dns",
        "data_source": "wordlist",
        "key_logic": "NoAnswer != NXDOMAIN — confirms existence without A record",
    },
    "t09": {
        "name": "CORS Origin Reflection",
        "aliases": ["cors", "cors-mining", "cors-reflection", "origin-probe"],
        "dns_methods": [],
        "interaction": "direct-http",
        "data_source": "wordlist + live-endpoints",
        "key_logic": "send Origin: https://word.domain, check ACAO header reflection",
    },
    "t10": {
        "name": "DNS CHAOS Class",
        "aliases": ["chaos", "chaos-txt", "version-bind", "dns-chaos"],
        "dns_methods": ["TXT/CHAOS"],
        "interaction": "direct-dns-chaos-class",
        "data_source": "nameserver",
        "key_logic": "query rdclass=CHAOS for version.bind, hostname.bind",
    },
    "t11": {
        "name": "VHost Fuzzing",
        "aliases": ["vhost", "virtual-host", "host-header-fuzz", "vhost-scan"],
        "dns_methods": [],
        "interaction": "direct-http",
        "data_source": "wordlist + live-ips",
        "key_logic": "Host: word.domain header fuzzing, diff baseline response",
    },
    "t12": {
        "name": "Recursive Enumeration",
        "aliases": ["recursive", "sub-subdomain", "deep-brute", "recursive-brute"],
        "dns_methods": ["A"],
        "interaction": "direct-dns",
        "data_source": "existing-subdomains",
        "key_logic": "use found subs as new roots, brute force beneath them",
    },
    "t13": {
        "name": "SPF/TXT Record Mining",
        "aliases": ["spf-mine", "txt-mine", "spf-walk", "spf"],
        "dns_methods": ["TXT", "MX"],
        "interaction": "direct-dns",
        "data_source": "txt-records",
        "key_logic": "parse SPF include: a: mx: directives, extract hostnames",
    },
    "t14": {
        "name": "DKIM Selector Bruteforce",
        "aliases": ["dkim", "dkim-selector", "domainkey"],
        "dns_methods": ["TXT", "CNAME"],
        "interaction": "direct-dns",
        "data_source": "selector-wordlist",
        "key_logic": "query {selector}._domainkey.{domain} TXT records",
    },
    "t15": {
        "name": "SPF Include Chain Walker",
        "aliases": ["spf-chain", "spf-recursive", "spf-tree"],
        "dns_methods": ["TXT"],
        "interaction": "direct-dns",
        "data_source": "spf-includes",
        "key_logic": "recursively follow include: directives across domains",
    },
}


def _normalize(s: str) -> str:
    """Normalize a string for comparison."""
    return re.sub(r"[^a-z0-9]", "", s.lower())


def _extract_domain(url: str) -> str:
    """Extract domain from URL for reference cross-check."""
    m = re.search(r"https?://([^/]+)", url)
    return m.group(1) if m else ""


def _tokenize(s: str) -> set:
    """Tokenize a description for keyword overlap detection."""
    words = re.findall(r"[a-z]{3,}", s.lower())
    return set(words)


def _keyword_overlap(tokens1: set, tokens2: set) -> float:
    """Return overlap ratio (0.0 to 1.0) between two token sets."""
    if not tokens1 or not tokens2:
        return 0.0
    intersection = len(tokens1 & tokens2)
    union = len(tokens1 | tokens2)
    return intersection / union if union else 0.0


def check(args) -> int:
    """Run all overlap checks. Returns exit code (0=pass, 1=block)."""
    from rich.console import Console
    from rich.table import Table
    console = Console()

    name = args.name
    new_aliases = [a.strip().lower().replace(" ", "-") for a in args.aliases.split(",")]
    new_dns_methods = [m.strip().upper() for m in args.dns_methods.split(",")]
    new_interaction = args.interaction.strip().lower()
    new_data_source = args.data_source.strip().lower()
    new_description = args.description.strip()
    new_reference = args.reference.strip()
    new_ref_domain = _extract_domain(new_reference)
    new_tokens = _tokenize(new_description)

    blocks = []
    warnings = []

    # ── CHECK A: Alias Collision ───────────────────────────────────────────
    alias_collisions = []
    for tid, entry in TECHNIQUE_REGISTRY.items():
        for alias in entry["aliases"]:
            if _normalize(alias) in [_normalize(a) for a in new_aliases]:
                alias_collisions.append((tid, entry["name"], alias))
    if alias_collisions:
        blocks.append(
            f"[red]BLOCK[/red] Alias collision: "
            + ", ".join(f"'{a[2]}' already used by {a[0]} ({a[1]})" for a in alias_collisions)
        )

    # ── CHECK B: Interaction + Data Source Overlap ─────────────────────────
    interaction_collisions = []
    for tid, entry in TECHNIQUE_REGISTRY.items():
        if (entry["interaction"] == new_interaction and
                entry["data_source"] == new_data_source):
            interaction_collisions.append((tid, entry["name"]))
    if interaction_collisions:
        warnings.append(
            f"[yellow]WARN[/yellow] Interaction + data_source match: "
            + ", ".join(f"{t} ({n})" for t, n in interaction_collisions)
        )
        warnings.append(
            "    Your technique must have meaningfully different key_logic. "
            "Describe the difference or it will be rejected."
        )

    # ── CHECK C: DNS Method Overlap ─────────────────────────────────────────
    dns_method_collisions = []
    for tid, entry in TECHNIQUE_REGISTRY.items():
        if entry["interaction"] == new_interaction:
            overlap = set(m.upper() for m in entry["dns_methods"]) & set(new_dns_methods)
            if overlap and entry["dns_methods"]:
                dns_method_collisions.append(
                    (tid, entry["name"], entry["key_logic"][:80])
                )
    if dns_method_collisions:
        warnings.append(
            f"[yellow]WARN[/yellow] DNS method overlap with same interaction:"
        )
        for tid, entry_name, key_logic in dns_method_collisions:
            warnings.append(
                f"    {tid} ({entry_name}): key_logic: {key_logic}"
            )

    # ── CHECK D: Reference Domain Cross-Check ──────────────────────────────
    if new_ref_domain:
        ref_domain_techniques = []
        for tid, entry in TECHNIQUE_REGISTRY.items():
            refs = entry.get("references", [])
            for ref in refs:
                if isinstance(ref, str) and _extract_domain(ref) == new_ref_domain:
                    ref_domain_techniques.append((tid, entry["name"]))
        if ref_domain_techniques:
            warnings.append(
                f"[yellow]WARN[/yellow] Reference domain '{new_ref_domain}' "
                f"already used by: "
                + ", ".join(f"{t} ({n})" for t, n in ref_domain_techniques)
            )
            warnings.append(
                "    Verify the technique from this source is not already covered."
            )

    # ── CHECK E: Keyword Similarity ────────────────────────────────────────
    keyword_similar = []
    for tid, entry in TECHNIQUE_REGISTRY.items():
        existing_tokens = _tokenize(entry.get("key_logic", ""))
        overlap = _keyword_overlap(new_tokens, existing_tokens)
        if overlap >= 0.6:
            keyword_similar.append(
                (tid, entry["name"], entry["key_logic"][:80], overlap)
            )
    if keyword_similar:
        for tid, entry_name, key_logic, overlap in keyword_similar:
            warnings.append(
                f"[yellow]WARN[/yellow] High keyword similarity ({overlap:.0%}) "
                f"with {tid} ({entry_name}): {key_logic}"
            )

    # ── Output ────────────────────────────────────────────────────────────
    print()
    console.print(f"[bold]Checking:[/bold] {name}")
    console.print(f"[bold]Aliases:[/bold] {', '.join(new_aliases)}")
    console.print(f"[bold]Interaction:[/bold] {new_interaction}")
    console.print(f"[bold]Data source:[/bold] {new_data_source}")
    console.print(f"[bold]DNS methods:[/bold] {', '.join(new_dns_methods)}")
    print()

    if blocks:
        console.print("[bold red]BLOCKS:[/bold red]")
        for b in blocks:
            console.print(f"  {b}")
        print()
        console.print("[bold red]✗ Technique blocked. Resolve conflicts before adding.[/bold red]")
        return 1

    if warnings:
        console.print("[bold yellow]WARNINGS:[/bold yellow]")
        for w in warnings:
            console.print(f"  {w}")
        print()
        console.print("[bold yellow]⚠ Potential overlap. Review warnings and confirm.[/bold yellow]")

        # Print suggested registry entry
        suggested_id = "t16"  # next available
        console.print(f"\n[bold]Suggested registry entry:[/bold]")
        console.print(f"""
{suggested_id.upper()}: {{
    "name": "{name}",
    "aliases": {new_aliases},
    "dns_methods": {new_dns_methods},
    "interaction": "{new_interaction}",
    "data_source": "{new_data_source}",
    "key_logic": "...",
    "references": ["{new_reference}"],
}},
""")
        return 1  # Still exit code 1 for warnings in CI/CD

    # All checks pass
    console.print("[bold green]✓ No overlap detected. Safe to add.[/bold green]")
    suggested_id = "t16"
    console.print(f"\n[bold]Registry entry for {suggested_id}:[/bold]")
    console.print(f"""
{suggested_id.upper()}: {{
    "name": "{name}",
    "aliases": {new_aliases},
    "dns_methods": {new_dns_methods},
    "interaction": "{new_interaction}",
    "data_source": "{new_data_source}",
    "key_logic": "...",
    "references": ["{new_reference}"],
}},
""")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Check technique overlap before adding to the codebase",
        epilog="""
Examples:
  # Check a new HTTP technique
  python3 tools/check_technique_overlap.py \\
    --name "HTTP Header Mining" \\
    --aliases "header-mine,http-probe" \\
    --interaction "direct-http" \\
    --data-source "wordlist" \\
    --description "Sends custom HTTP headers to discover API subdomains" \\
    --reference "https://blog.example.com/technique"

  # Check a new DNS technique
  python3 tools/check_technique_overlap.py \\
    --name "MX Record Enumeration" \\
    --aliases "mx-enum,mail-srv" \\
    --dns-methods "MX" \\
    --interaction "direct-dns" \\
    --data-source "wordlist" \\
    --description "Brute force MX records to find mail server subdomains" \\
    --reference "https://another-blog.com/mx-enum"
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--name", required=True, help="Technique name")
    parser.add_argument("--aliases", required=True, help="Comma-separated aliases")
    parser.add_argument("--dns-methods", default="",
                       help="Comma-separated DNS methods (e.g. A,CNAME,TXT)")
    parser.add_argument("--interaction", required=True,
                       choices=["direct-dns", "direct-http", "direct-tls-ip",
                               "indirect-resolver", "direct-dns-authoritative",
                               "direct-dns-dnssec", "direct-dns-chaos-class"],
                       help="Interaction type")
    parser.add_argument("--data-source", required=True,
                       choices=["wordlist", "existing-subdomains", "nameserver",
                               "dnssec-chain", "resolver-cache", "ip-ranges",
                               "wordlist+live-endpoints", "wordlist+live-ips",
                               "txt-records", "selector-wordlist", "spf-includes"],
                       help="Data source")
    parser.add_argument("--description", required=True,
                       help="One-sentence description of what makes this unique")
    parser.add_argument("--reference", default="",
                       help="Source reference URL")

    args = parser.parse_args()
    sys.exit(check(args))


if __name__ == "__main__":
    main()
