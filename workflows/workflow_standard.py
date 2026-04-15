#!/usr/bin/env python3
"""
workflow_standard.py — "Bug Bounty Workhorse" (30–60 min)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

REAL HUNTER WORKFLOW (how a top hunter actually runs this):

Phase 0 — Sanity (30 seconds)
  - Wildcard check
  - Zone transfer attempt (free, instant, high reward if it works)
  - CHAOS query (free, no noise, reveals NS software/version)
  - NSEC walk attempt (free, provably complete if NSEC)

Phase 1 — High Signal, Low Noise (5–15 min)
  - CAA pivot with medium wordlist (confirms existence, no HTTP)
  - AAAA enumeration (everyone skips this, you won't)
  - Cache snooping on 3 public resolvers (reveals actively used subs)
  - SPF/TXT mining (free intel from DNS records already published)
  - DKIM selector probe (reveals mail vendor stack)

Phase 2 — Brute Force (15–45 min depending on wordlist)
  - DNS brute with medium wordlist + validated resolvers
  - Permutation on everything found so far (not just brute results)
  - Recursive enum depth=2 on interesting-looking subs
    (api.*, dev.*, staging.*, internal.* get deeper treatment)

Phase 3 — HTTP Layer (20–40 min, needs live IPs)
  - VHost fuzzing on all unique IPs found
  - CORS reflection on all live HTTP endpoints
  - TLS SNI probing if IP ranges available

Phase 4 — Cross-reference & Triage
  - Flag any sub resolving to cloud IP ranges (takeover check)
  - Sort output by "interestingness" not alphabetically

Usage:
  python3 workflows/workflow_standard.py -d example.com
  python3 workflows/workflow_standard.py -d example.com -w /path/to/medium.txt -t 100
"""

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.config import Config
from core.resolver import ResolverPool, ResolverHealth
from core.wildcard import WildcardDetector
from core.output import (
    print_banner, hunter_debrief, save_results, HUNTER_USER_AGENTS,
)
from core.scoring import score_all
from core.http_probe import HTTPProbe, update_results_with_probe
from core.saturation import SaturationDetector


def load_wordlist(path: str = ""):
    """Load wordlist, defaulting to builtin_medium.txt."""
    base = Path(__file__).parent.parent / "wordlists"
    if not path:
        path = base / "builtin_medium.txt"
    if not Path(path).exists():
        path = base / "builtin_small.txt"
    if not Path(path).exists():
        return []
    with open(path) as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


def main():
    parser = argparse.ArgumentParser(description="Standard bug bounty enumeration (30–60 min)")
    parser.add_argument("-d", "--domain", required=True)
    parser.add_argument("-w", "--wordlist", default="")
    parser.add_argument("-t", "--threads", type=int, default=100)
    parser.add_argument("--timeout", type=int, default=3)
    parser.add_argument("--depth", type=int, default=2, help="Recursive depth (default: 2)")
    parser.add_argument("--ip-ranges", default="", help="Comma-separated IP ranges for TLS SNI")
    parser.add_argument("-o", "--output", default="")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--skip-http-probe", action="store_true")
    args = parser.parse_args()

    from rich.console import Console
    from rich.panel import Panel
    console = Console()

    print_banner()

    cfg = Config(
        domain=args.domain.lower().strip(),
        threads=args.threads,
        timeout=args.timeout,
        verbose=args.verbose,
        depth=args.depth,
        ip_ranges=[r.strip() for r in args.ip_ranges.split(",") if r.strip()],
        skip_http_probe=args.skip_http_probe,
    )

    console.print(Panel(
        f"[bold cyan]workflow_standard[/bold cyan] — Bug Bounty Workhorse (30–60 min)\n"
        f"[bold]Target:[/bold]   [cyan]{cfg.domain}[/cyan]\n"
        f"[bold]Wordlist:[/bold] builtin_medium (~2K words)\n"
        f"[bold]Threads:[/bold]  {cfg.threads}  [bold]Timeout:[/bold] {cfg.timeout}s\n"
        f"[bold]Depth:[/bold]     {cfg.depth}",
        title="[bold yellow]⚡  Standard Recon[/bold yellow]",
        expand=False,
    ))

    start = time.time()
    wordlist = load_wordlist(args.wordlist)

    # Validate resolvers
    health = ResolverHealth(cfg.resolvers, cfg.timeout)
    validated = health.check()
    if validated:
        cfg.resolvers = [r for r, _ in validated[:100]]
        console.print(
            f"  [dim]→ Resolver pool: {len(validated)} healthy | "
            f"fastest: {validated[0][0]} ({validated[0][1]:.0f}ms)[/dim]"
        )
    pool = ResolverPool(cfg.resolvers, cfg.timeout)

    try:
        from core.results import ResultCollector
    except ImportError:
        from activesubenum import ResultCollector as RC
        ResultCollector = RC

    results = ResultCollector(verbose=cfg.verbose)
    wc = WildcardDetector(cfg.domain, pool)
    wc.detect()

    found = set()
    technique_stats = {}
    saturation = SaturationDetector()

    # ── Phase 0: Sanity ──────────────────────────────────────────────────
    console.print("\n[bold]Phase 0 — Sanity (free intel)[/bold]")

    phases = [
        ("Zone Transfer", "t03_zonetransfer", "ZoneTransferTechnique"),
        ("NSEC Walk", "t04_nsec", "NSECTechnique"),
        ("CHAOS", "t10_chaos", "CHAOSTechnique"),
        ("Cache Snooping", "t05_cachesnoop", "CacheSnoopTechnique"),
    ]

    for label, module_name, class_name in phases:
        t_start = time.time()
        try:
            mod = __import__(f"techniques.{module_name}", fromlist=[class_name])
            cls = getattr(mod, class_name)
            t = cls()
            prev_count = len(found)
            new = t.run(cfg, pool, wc, results, known=found)
            found |= new
            technique_stats[label.lower().replace(" ", "-")] = {
                "count": len(found) - prev_count,
                "start": t_start,
                "end": time.time(),
            }
            saturation.record(label.lower(), len(found) - prev_count, t_start, time.time())
        except Exception as e:
            console.print(f"  [dim]{label}: skipped ({e})[/dim]")
            technique_stats[label.lower().replace(" ", "-")] = {
                "count": 0, "start": t_start, "end": time.time()
            }

    # ── Phase 1: DNS enumeration ──────────────────────────────────────────
    console.print("\n[bold]Phase 1 — DNS Enumeration[/bold]")

    dns_techniques = [
        ("IPv6 AAAA", "t06_ipv6", "IPv6Technique", dict(wordlist=wordlist)),
        ("CAA Pivot", "t08_caa", "CAATechnique", dict(wordlist=wordlist)),
        ("SPF/TXT Mining", "t13_TEMPLATE", "TemplateTechnique", dict(known=found)),
        ("DKIM Selector", "t14_dkim", "DKIMTechnique", {}),
        ("Brute Force", "t01_bruteforce", "BruteForceTechnique", dict(wordlist=wordlist)),
    ]

    for label, module_name, class_name, kwargs in dns_techniques:
        if label.lower() in ("brute force",):
            console.print(f"\n[bold]Phase 2 — Brute Force & Mutation[/bold]")
        elif label.lower() == "caapivot":
            pass

        t_start = time.time()
        try:
            mod = __import__(f"techniques.{module_name}", fromlist=[class_name])
            cls = getattr(mod, class_name)
            t = cls()
            prev_count = len(found)
            new = t.run(cfg, pool, wc, results, known=found, **kwargs)
            found |= new
            technique_stats[label.lower().replace(" ", "-")] = {
                "count": len(found) - prev_count,
                "start": t_start,
                "end": time.time(),
            }
            saturation.record(label.lower(), len(found) - prev_count, t_start, time.time())
        except Exception as e:
            console.print(f"  [dim]{label}: {e}[/dim]")

    # Permutation
    t_start = time.time()
    try:
        from techniques.t02_permutation import PermutationTechnique
        t = PermutationTechnique()
        prev_count = len(found)
        new = t.run(cfg, pool, wc, results, known=found)
        found |= new
        technique_stats["permutation"] = {
            "count": len(found) - prev_count,
            "start": t_start,
            "end": time.time(),
        }
    except Exception as e:
        console.print(f"  [dim]Permutation: {e}[/dim]")

    # Recursive
    t_start = time.time()
    try:
        from techniques.t12_recursive import RecursiveTechnique
        t = RecursiveTechnique()
        prev_count = len(found)
        new = t.run(cfg, pool, wc, results, known=found, depth=cfg.depth)
        found |= new
        technique_stats["recursive"] = {
            "count": len(found) - prev_count,
            "start": t_start,
            "end": time.time(),
        }
        saturation.record("recursive", len(found) - prev_count, t_start, time.time())
    except Exception as e:
        console.print(f"  [dim]Recursive: {e}[/dim]")

    # ── Phase 3: HTTP Layer ───────────────────────────────────────────────
    console.print("\n[bold]Phase 3 — HTTP Layer[/bold]")

    http_techniques = [
        ("VHost Fuzzing", "t11_vhost", "VHostTechnique"),
        ("CORS Reflection", "t09_cors", "CORSTechnique"),
        ("TLS SNI Probing", "t07_tlssni", "TLSSNITechnique"),
    ]

    for label, module_name, class_name in http_techniques:
        if label == "TLS SNI Probing" and not cfg.ip_ranges:
            console.print(f"  [dim]{label}: skipped (no --ip-ranges)[/dim]")
            continue
        t_start = time.time()
        try:
            mod = __import__(f"techniques.{module_name}", fromlist=[class_name])
            cls = getattr(mod, class_name)
            t = cls()
            prev_count = len(found)
            new = t.run(cfg, pool, wc, results, known=found, wordlist=wordlist)
            found |= new
            technique_stats[label.lower().replace(" ", "-")] = {
                "count": len(found) - prev_count,
                "start": t_start,
                "end": time.time(),
            }
        except Exception as e:
            console.print(f"  [dim]{label}: {e}[/dim]")

    # ── Post-processing ───────────────────────────────────────────────────
    score_all(results.found)

    # HTTP Probe
    if not cfg.skip_http_probe and found:
        console.print(f"\n[bold]Phase 4 — HTTP Probe[/bold]")
        try:
            probe = HTTPProbe(
                timeout=cfg.http_timeout,
                user_agents=HUNTER_USER_AGENTS,
            )
            probe_results = probe.probe_all_sync(results.all_subs())
            http_stats = update_results_with_probe(results, probe_results)
        except Exception as e:
            console.print(f"  [dim]HTTP probe skipped: {e}[/dim]")
            http_stats = {}
    else:
        http_stats = {}

    sat_result = saturation.check()

    # Save
    if args.output:
        save_results(
            results, args.output, domain=cfg.domain,
            scan_start=start, technique_stats=technique_stats,
            http_stats=http_stats, saturation=sat_result,
        )

    # Hunter debrief
    hunter_debrief(
        cfg.domain, results, start, technique_stats,
        http_stats=http_stats,
        saturation=sat_result,
        resolver_count=len(cfg.resolvers),
    )


if __name__ == "__main__":
    main()
