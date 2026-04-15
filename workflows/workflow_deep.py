#!/usr/bin/env python3
"""
workflow_deep.py — "Leave No Stone Unturned" (hours)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Philosophy:
  Maximum coverage. Acceptable to take hours. If you have time and authorization,
  be thorough. This runs EVERY technique including t13 (SPF Mining), t14 (DKIM),
  t15 (SPF Chain), permutation TWICE, and recursive at depth 3.

Usage:
  python3 workflows/workflow_deep.py -d example.com
  python3 workflows/workflow_deep.py -d example.com -w wordlists/builtin_large.txt -t 200

NOTE: Requires significant time. Consider running with --output for partial results.
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
    base = Path(__file__).parent.parent / "wordlists"
    if not path:
        candidates = [base / "builtin_large.txt", base / "builtin_medium.txt"]
        for p in candidates:
            if p.exists():
                path = p
                break
    if not path or not Path(path).exists():
        return []
    with open(path) as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


def run_technique(module_name, class_name, cfg, pool, wc, results, known=None, **kwargs):
    """Safely run a technique, returning (new_found_count, duration)."""
    start = time.time()
    try:
        mod = __import__(f"techniques.{module_name}", fromlist=[class_name])
        cls = getattr(mod, class_name)
        t = cls()
        prev = len(known) if known else len(results.all_subs())
        result = t.run(cfg, pool, wc, results, known=known or results.all_subs(), **kwargs)
        return len(result), time.time() - start
    except Exception as e:
        return 0, time.time() - start


def main():
    parser = argparse.ArgumentParser(description="Deep comprehensive scan (hours)")
    parser.add_argument("-d", "--domain", required=True)
    parser.add_argument("-w", "--wordlist", default="")
    parser.add_argument("-t", "--threads", type=int, default=200)
    parser.add_argument("--timeout", type=int, default=5)
    parser.add_argument("--depth", type=int, default=3)
    parser.add_argument("--ip-ranges", default="")
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
        f"[bold red]workflow_deep[/bold red] — Leave No Stone Unturned\n"
        f"[bold]Target:[/bold]   [cyan]{cfg.domain}[/cyan]\n"
        f"[bold]Wordlist:[/bold] builtin_large (~5K words)\n"
        f"[bold]Threads:[/bold]  {cfg.threads}  [bold]Timeout:[/bold] {cfg.timeout}s\n"
        f"[bold]Depth:[/bold]     {cfg.depth}",
        title="[bold yellow]⚡  Deep Recon[/bold yellow]",
        expand=False,
    ))

    start = time.time()
    wordlist = load_wordlist(args.wordlist)

    # Validate resolvers
    health = ResolverHealth(cfg.resolvers, cfg.timeout)
    validated = health.check()
    if validated:
        cfg.resolvers = [r for r, _ in validated[:100]]
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
    saturation = SaturationDetector()
    found = set()

    # ── All techniques: Phase by Phase ────────────────────────────────────

    techniques_sequence = [
        # Phase 0: Free intel
        ("Zone Transfer", "t03_zonetransfer", "ZoneTransferTechnique", {}),
        ("NSEC Walk", "t04_nsec", "NSECTechnique", {}),
        ("CHAOS", "t10_chaos", "CHAOSTechnique", {}),
        ("Cache Snooping", "t05_cachesnoop", "CacheSnoopTechnique", {}),
        # Phase 1: High-value DNS
        ("IPv6 AAAA", "t06_ipv6", "IPv6Technique", dict(wordlist=wordlist)),
        ("CAA Pivot", "t08_caa", "CAATechnique", dict(wordlist=wordlist)),
        ("SPF/TXT Mining", "t13_TEMPLATE", "TemplateTechnique", {}),
        ("DKIM Selector", "t14_dkim", "DKIMTechnique", {}),
        ("SPF Chain Walker", "t15_spf_chain", "SPFChainTechnique", {}),
        # Phase 2: Brute force + mutation
        ("Brute Force", "t01_bruteforce", "BruteForceTechnique", dict(wordlist=wordlist)),
        ("Permutation (1)", "t02_permutation", "PermutationTechnique", {}),
        # Phase 3: Recursive at depth 3
        ("Recursive Depth-1", "t12_recursive", "RecursiveTechnique", dict(depth=1)),
        ("Recursive Depth-2", "t12_recursive", "RecursiveTechnique", dict(depth=2)),
        ("Recursive Depth-3", "t12_recursive", "RecursiveTechnique", dict(depth=3)),
        # Phase 4: HTTP layer
        ("VHost Fuzzing", "t11_vhost", "VHostTechnique", dict(wordlist=wordlist)),
        ("CORS Reflection", "t09_cors", "CORSTechnique", dict(wordlist=wordlist)),
        ("TLS SNI Probing", "t07_tlssni", "TLSSNITechnique", dict(wordlist=wordlist)),
        # Phase 5: Second permutation pass (after recursive)
        ("Permutation (2)", "t02_permutation", "PermutationTechnique", {}),
    ]

    for label, module_name, class_name, kwargs in techniques_sequence:
        if label == "TLS SNI Probing" and not cfg.ip_ranges:
            console.print(f"  [dim]{label}: skipped (no --ip-ranges)[/dim]")
            technique_stats[label.lower().replace(" ", "-")] = {"count": 0, "start": time.time(), "end": time.time()}
            continue

        console.print(f"\n[bold blue]→[/bold blue] {label}")
        count, duration = run_technique(
            module_name, class_name, cfg, pool, wc, results,
            known=results.all_subs(), **kwargs
        )
        technique_stats[label.lower().replace(" ", "-")] = {
            "count": count,
            "start": time.time() - duration,
            "end": time.time(),
        }
        saturation.record(label.lower(), count, time.time() - duration, time.time())
        console.print(f"  [dim]→ {count} found ({duration:.1f}s)[/dim]")

    # ── Post-processing ───────────────────────────────────────────────────
    score_all(results.found)

    if not cfg.skip_http_probe:
        console.print(f"\n[bold]HTTP Probe Phase[/bold]")
        try:
            probe = HTTPProbe(timeout=cfg.http_timeout, user_agents=HUNTER_USER_AGENTS)
            probe_results = probe.probe_all_sync(results.all_subs())
            http_stats = update_results_with_probe(results, probe_results)
        except Exception as e:
            console.print(f"  [dim]HTTP probe: {e}[/dim]")
            http_stats = {}
    else:
        http_stats = {}

    sat_result = saturation.check()

    if args.output:
        save_results(
            results, args.output, domain=cfg.domain,
            scan_start=start, technique_stats=technique_stats,
            http_stats=http_stats, saturation=sat_result,
        )

    hunter_debrief(
        cfg.domain, results, start, technique_stats,
        http_stats=http_stats, saturation=sat_result,
        resolver_count=len(cfg.resolvers),
    )


if __name__ == "__main__":
    main()
