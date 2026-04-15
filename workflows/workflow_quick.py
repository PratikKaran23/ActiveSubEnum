#!/usr/bin/env python3
"""
workflow_quick.py — "Fast First Look" (5–10 min)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Real Hunter Philosophy:
  High-signal, low-time. Zone transfer and NSEC are free intel — always try
  them first. Brute force with small list for quick wins. No HTTP, no TLS SNI,
  no VHost — those are time sinks for a quick scan. This is what you run when
  you have 10 minutes before a scope review or when you need a first-pass
  recon on a target you've never touched.

Phase breakdown:
  1. Zone Transfer (free, instant) — get everything if lucky
  2. NSEC Walk (free, provably complete if NSEC)
  3. CHAOS (free, reveals NS software)
  4. Cache Snooping (high stealth, reveals actively-used subs)
  5. Brute Force (small wordlist, 150 words)

Usage:
  python3 workflows/workflow_quick.py -d example.com
  python3 workflows/workflow_quick.py -d example.com -w /path/to/wordlist.txt

For quick workflow with external wordlist:
  python3 workflows/workflow_quick.py -d example.com \
    -w <(curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt)
"""

import argparse
import sys
import time
from pathlib import Path

# Add parent to path so we can import core and techniques
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.config import Config, DEFAULT_RESOLVERS
from core.resolver import ResolverPool
from core.wildcard import WildcardDetector
from core.output import print_banner, hunter_debrief, save_results
from core.scoring import score_all
from core.http_probe import HTTPProbe
from core.rate_limiter import RateLimiter
from core.saturation import SaturationDetector
from core.output import HUNTER_USER_AGENTS


def load_wordlist(path: str = ""):
    """Load wordlist, defaulting to builtin_small.txt."""
    base = Path(__file__).parent.parent / "wordlists"
    if not path:
        path = base / "builtin_small.txt"
    if not Path(path).exists():
        # Fallback to inline small list
        return [
            "www", "mail", "api", "admin", "dev", "staging", "test", "vpn",
            "blog", "cdn", "ftp", "server", "portal", "secure", "internal",
        ]
    with open(path) as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


def main():
    parser = argparse.ArgumentParser(description="Quick subdomain enumeration (5–10 min)")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-w", "--wordlist", default="", help="Path to wordlist")
    parser.add_argument("-t", "--threads", type=int, default=150, help="Threads (default: 150)")
    parser.add_argument("--timeout", type=int, default=2, help="DNS timeout (default: 2s)")
    parser.add_argument("-o", "--output", default="", help="Output file")
    parser.add_argument("-v", "--verbose", action="store_true")
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
    )

    console.print(Panel(
        f"[bold cyan]workflow_quick[/bold cyan] — Fast First Look (5–10 min)\n"
        f"[bold]Target:[/bold]   [cyan]{cfg.domain}[/cyan]\n"
        f"[bold]Wordlist:[/bold] builtin_small (~150 words)\n"
        f"[bold]Threads:[/bold]  {cfg.threads}  [bold]Timeout:[/bold] {cfg.timeout}s",
        title="[bold yellow]⚡  Quick Recon[/bold yellow]",
        expand=False,
    ))

    start = time.time()
    wordlist = load_wordlist(args.wordlist)

    # Use core components if available, fallback gracefully
    try:
        from core.results import ResultCollector
    except ImportError:
        from activesubenum import ResultCollector as RC
        ResultCollector = RC

    try:
        from core.resolver import ResolverPool, ResolverHealth
    except ImportError:
        from activesubenum import ResolverPool, DEFAULT_RESOLVERS
        pool = ResolverPool(list(DEFAULT_RESOLVERS), cfg.timeout)
    else:
        # Validate resolvers
        health = ResolverHealth(cfg.resolvers, cfg.timeout)
        validated = health.check()
        if validated:
            cfg.resolvers = [r for r, _ in validated[:50]]
            console.print(
                f"  [dim]→ Resolver pool: {len(validated)} healthy, "
                f"fastest: {validated[0][0]} ({validated[0][1]:.0f}ms)[/dim]"
            )
        pool = ResolverPool(cfg.resolvers, cfg.timeout)

    results = ResultCollector(verbose=cfg.verbose)
    wc = WildcardDetector(cfg.domain, pool)
    wc.detect()

    found = set()
    technique_stats = {}

    # ── Phase 0: Sanity ───────────────────────────────────────────────────
    console.print("\n[bold]Phase 0 — Sanity Checks[/bold]")

    # Zone Transfer
    t_start = time.time()
    try:
        from techniques.t03_zonetransfer import ZoneTransferTechnique
        t = ZoneTransferTechnique()
        new = t.run(cfg, pool, wc, results)
        found |= new
    except Exception as e:
        console.print(f"  [red]Zone transfer error: {e}[/red]")
    technique_stats["zonetransfer"] = {
        "count": len(found),
        "start": t_start,
        "end": time.time(),
    }

    # NSEC Walk
    t_start = time.time()
    try:
        from techniques.t04_nsec import NSECTechnique
        t = NSECTechnique()
        new = t.run(cfg, pool, wc, results)
        found |= new
    except Exception as e:
        console.print(f"  [red]NSEC error: {e}[/red]")
    technique_stats["nsec"] = {
        "count": len(found),
        "start": t_start,
        "end": time.time(),
    }

    # CHAOS
    t_start = time.time()
    try:
        from techniques.t10_chaos import CHAOSTechnique
        t = CHAOSTechnique()
        new = t.run(cfg, pool, wc, results)
        found |= new
    except Exception:
        pass
    technique_stats["chaos"] = {
        "count": 0,
        "start": t_start,
        "end": time.time(),
    }

    # ── Phase 1: Cache Snooping ───────────────────────────────────────────
    t_start = time.time()
    try:
        from techniques.t05_cachesnoop import CacheSnoopTechnique
        t = CacheSnoopTechnique()
        new = t.run(cfg, pool, wc, results, known=found)
        found |= new
    except Exception:
        pass
    technique_stats["cache-snoop"] = {
        "count": 0,
        "start": t_start,
        "end": time.time(),
    }

    # ── Phase 2: Brute Force (small list) ─────────────────────────────────
    t_start = time.time()
    try:
        from techniques.t01_bruteforce import BruteForceTechnique
        t = BruteForceTechnique()
        new = t.run(cfg, pool, wc, results, wordlist=wordlist)
        found |= new
    except Exception as e:
        console.print(f"  [red]Brute force error: {e}[/red]")
    technique_stats["bruteforce"] = {
        "count": len(found),
        "start": t_start,
        "end": time.time(),
    }

    # Score results
    score_all(results.found)

    # HTTP Probe
    console.print(f"\n[bold]HTTP Probe Phase[/bold]")
    if not cfg.skip_http_probe and found:
        try:
            probe = HTTPProbe(
                timeout=cfg.http_timeout,
                user_agents=HUNTER_USER_AGENTS,
            )
            probe_results = probe.probe_all_sync(results.all_subs())
            from core.http_probe import update_results_with_probe
            http_stats = update_results_with_probe(results, probe_results)
        except Exception as e:
            console.print(f"  [dim]HTTP probe skipped: {e}[/dim]")
            http_stats = {}

    # Save
    if args.output:
        save_results(
            results, args.output, domain=cfg.domain,
            scan_start=start,
            technique_stats=technique_stats,
        )

    # Hunter debrief
    hunter_debrief(
        cfg.domain, results, start, technique_stats,
        resolver_count=len(cfg.resolvers),
    )


if __name__ == "__main__":
    main()
