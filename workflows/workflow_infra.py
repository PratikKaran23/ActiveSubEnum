#!/usr/bin/env python3
"""
workflow_infra.py — "Infrastructure Deep Dive" (bypass DNS entirely)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Philosophy:
  Most hunters stop at DNS. This workflow ignores DNS entirely and finds
  what's actually running on the wire. It finds services that bypass DNS
  completely — split-horizon DNS, IPv6-only servers, internal vhosts sharing
  a CDN IP, services visible only via IP.

Required: --ip-ranges (exits with error if not provided)

Techniques:
  - IPv6 AAAA enumeration (finds IPv6-only infrastructure)
  - TLS SNI probing (finds DNS-invisible vhosts)
  - VHost fuzzing (finds internal hostnames on shared IPs)
  - Cache snooping (public resolver cache reveals active subs)
  - DNS CHAOS (NS software/version enumeration)

Usage:
  python3 workflows/workflow_infra.py -d example.com --ip-ranges 104.21.0.0/24,172.67.0.0/24

Get IP ranges from:
  - bgp.he.net (AS number lookup)
  - ASN lookup via pdml: https://bgp.he.net/
  - Shodan: https://www.shodan.io
"""

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.config import Config
from core.resolver import ResolverPool, ResolverHealth
from core.wildcard import WildcardDetector
from core.output import print_banner, hunter_debrief, save_results, HUNTER_USER_AGENTS
from core.scoring import score_all
from core.http_probe import HTTPProbe, update_results_with_probe


def load_wordlist(path: str = ""):
    base = Path(__file__).parent.parent / "wordlists"
    if not path:
        path = base / "builtin_medium.txt"
    if not Path(path).exists():
        return []
    with open(path) as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


def main():
    parser = argparse.ArgumentParser(description="Infrastructure-focused enumeration")
    parser.add_argument("-d", "--domain", required=True)
    parser.add_argument("--ip-ranges", required=True,
                       help="Required: IP ranges for TLS SNI and VHost (comma-separated)")
    parser.add_argument("-w", "--wordlist", default="")
    parser.add_argument("-t", "--threads", type=int, default=50)
    parser.add_argument("--timeout", type=int, default=3)
    parser.add_argument("-o", "--output", default="")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    from rich.console import Console
    from rich.panel import Panel
    console = Console()

    ip_ranges = [r.strip() for r in args.ip_ranges.split(",") if r.strip()]
    if not ip_ranges:
        console.print("[bold red][!] --ip-ranges is REQUIRED for workflow_infra[/bold red]")
        console.print("  Get IP ranges from: bgp.he.net (AS lookup for target)")
        sys.exit(1)

    print_banner()

    cfg = Config(
        domain=args.domain.lower().strip(),
        threads=args.threads,
        timeout=args.timeout,
        verbose=args.verbose,
        ip_ranges=ip_ranges,
    )

    console.print(Panel(
        f"[bold cyan]workflow_infra[/bold cyan] — Infrastructure Deep Dive\n"
        f"[bold]Target:[/bold]   [cyan]{cfg.domain}[/cyan]\n"
        f"[bold]IP Ranges:[/bold] {', '.join(ip_ranges)}\n"
        f"[bold]Threads:[/bold]  {cfg.threads}  [bold]Timeout:[/bold] {cfg.timeout}s\n"
        f"[dim]Bypass DNS. Find what's actually running on the wire.[/dim]",
        title="[bold yellow]⚡  Infrastructure Recon[/bold yellow]",
        expand=False,
    ))

    start = time.time()
    wordlist = load_wordlist(args.wordlist)

    # Validate resolvers
    health = ResolverHealth(cfg.resolvers, cfg.timeout)
    validated = health.check()
    if validated:
        cfg.resolvers = [r for r, _ in validated[:50]]
    pool = ResolverPool(cfg.resolvers, cfg.timeout)

    try:
        from core.results import ResultCollector
    except ImportError:
        from activesubenum import ResultCollector as RC
        ResultCollector = RC

    results = ResultCollector(verbose=cfg.verbose)
    wc = WildcardDetector(cfg.domain, pool)
    wc.detect()

    technique_stats = {}
    found = set()

    console.print("\n[bold]Infrastructure Techniques[/bold]\n")

    infra_techniques = [
        ("IPv6 AAAA", "t06_ipv6", "IPv6Technique", dict(wordlist=wordlist)),
        ("TLS SNI Probing", "t07_tlssni", "TLSSNITechnique", dict(wordlist=wordlist)),
        ("VHost Fuzzing", "t11_vhost", "VHostTechnique", dict(wordlist=wordlist)),
        ("Cache Snooping", "t05_cachesnoop", "CacheSnoopTechnique", {}),
        ("CHAOS", "t10_chaos", "CHAOSTechnique", {}),
    ]

    for label, module_name, class_name, kwargs in infra_techniques:
        t_start = time.time()
        try:
            mod = __import__(f"techniques.{module_name}", fromlist=[class_name])
            cls = getattr(mod, class_name)
            t = cls()
            prev = len(found)
            result = t.run(cfg, pool, wc, results, known=found, **kwargs)
            found |= result
            technique_stats[label.lower().replace(" ", "-")] = {
                "count": len(found) - prev,
                "start": t_start,
                "end": time.time(),
            }
        except Exception as e:
            console.print(f"  [dim]{label}: {e}[/dim]")

    # HTTP Probe on found subdomains
    score_all(results.found)
    console.print(f"\n[bold]HTTP Probe Phase[/bold]")
    if found:
        try:
            probe = HTTPProbe(timeout=cfg.http_timeout, user_agents=HUNTER_USER_AGENTS)
            probe_results = probe.probe_all_sync(results.all_subs())
            http_stats = update_results_with_probe(results, probe_results)
        except Exception as e:
            console.print(f"  [dim]HTTP probe: {e}[/dim]")
            http_stats = {}
    else:
        http_stats = {}

    if args.output:
        save_results(
            results, args.output, domain=cfg.domain,
            scan_start=start, technique_stats=technique_stats,
            http_stats=http_stats,
        )

    hunter_debrief(
        cfg.domain, results, start, technique_stats,
        http_stats=http_stats,
        resolver_count=len(cfg.resolvers),
    )


if __name__ == "__main__":
    main()
