#!/usr/bin/env python3
"""
workflow_custom.py — Template / Example for Custom Workflows
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

This is a heavily-commented example showing how to build a custom workflow.
It demonstrates:
  1. Importing techniques from the techniques/ module
  2. Chaining techniques together (output of one feeds into the next)
  3. Adding a custom logic (not shown — extend as needed)
  4. Calling a technique as a template example (t13_TEMPLATE)

HOW TO CREATE YOUR OWN WORKFLOW:
  1. Copy this file to workflow_mytarget.py
  2. Edit the TECHNIQUE_SEQUENCE list below
  3. Add your own custom logic between technique calls
  4. Run: python3 workflows/workflow_mytarget.py -d yourtarget.com

TECHNIQUE_SEQUENCE controls what runs and in what order.
Each entry is: (label, module_name, class_name, kwargs_dict)

Available techniques:
  t01_bruteforce.BruteForceTechnique     — wordlist=[...]
  t02_permutation.PermutationTechnique  — (uses found subs as seeds)
  t03_zonetransfer.ZoneTransferTechnique
  t04_nsec.NSECTechnique
  t05_cachesnoop.CacheSnoopTechnique    — resolvers=[...]
  t06_ipv6.IPv6Technique                 — wordlist=[...]
  t07_tlssni.TLSSNITechnique             — wordlist=[...], requires cfg.ip_ranges
  t08_caa.CAATechnique                   — wordlist=[...]
  t09_cors.CORSTechnique                 — wordlist=[...]
  t10_chaos.CHAOSTechnique
  t11_vhost.VHostTechnique               — wordlist=[...]
  t12_recursive.RecursiveTechnique       — depth=N
  t13_TEMPLATE.TemplateTechnique         — known=[...]
  t14_dkim.DKIMTechnique
  t15_spf_chain.SPFChainTechnique        — max_depth=N
"""

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.config import Config
from core.resolver import ResolverPool, ResolverHealth
from core.wildcard import WildcardDetector
from core.output import print_banner, save_results
from core.scoring import score_all
from core.http_probe import HTTPProbe, update_results_with_probe
from core.output import HUNTER_USER_AGENTS


# ─── YOUR CUSTOM WORKFLOW CONFIGURATION ────────────────────────────────────

# Edit this list to customize your workflow.
# Each entry: (label, module_name, class_name, extra_kwargs_dict)
#
# Example: to run just zone transfer, NSEC, and a small brute force:
#   TECHNIQUE_SEQUENCE = [
#       ("Zone Transfer", "t03_zonetransfer", "ZoneTransferTechnique", {}),
#       ("NSEC Walk", "t04_nsec", "NSECTechnique", {}),
#       ("Brute Force", "t01_bruteforce", "BruteForceTechnique",
#        dict(wordlist=["www", "mail", "api", "admin", "dev"])),
#   ]

TECHNIQUE_SEQUENCE = [
    # Phase 0: Free intel
    ("Zone Transfer", "t03_zonetransfer", "ZoneTransferTechnique", {}),
    ("NSEC Walk", "t04_nsec", "NSECTechnique", {}),
    ("CHAOS", "t10_chaos", "CHAOSTechnique", {}),
    # Phase 1: High-value DNS-only
    ("Cache Snooping", "t05_cachesnoop", "CacheSnoopTechnique", {}),
    ("SPF/TXT Mining (t13 template)", "t13_TEMPLATE", "TemplateTechnique", {}),
    # Phase 2: Your choice — edit TECHNIQUE_SEQUENCE above
    # Example: brute force with a specific wordlist
    # ("Custom Brute", "t01_bruteforce", "BruteForceTechnique",
    #  dict(wordlist=["api", "v1", "v2", "internal", "admin"])),
]

WORKFLOW_NAME = "workflow_custom"
WORKFLOW_DESC = "Custom enumeration — edit TECHNIQUE_SEQUENCE in this file"


def load_wordlist(path: str = ""):
    base = Path(__file__).parent.parent / "wordlists"
    candidates = [base / "builtin_small.txt", base / "builtin_medium.txt"]
    if path:
        candidates.insert(0, Path(path))
    for p in candidates:
        if p.exists():
            with open(p) as f:
                return [l.strip() for l in f if l.strip() and not l.startswith("#")]
    return []


def run_technique(module_name, class_name, cfg, pool, wc, results, known=None, **kwargs):
    """Safely run a technique. Extends known set with results found so far."""
    start = time.time()
    try:
        mod = __import__(f"techniques.{module_name}", fromlist=[class_name])
        cls = getattr(mod, class_name)
        t = cls()
        prev = len(known) if known else len(results.all_subs())
        result = t.run(
            cfg, pool, wc, results,
            known=known or results.all_subs(), **kwargs
        )
        return len(result), time.time() - start
    except Exception as e:
        return 0, time.time() - start


def main():
    parser = argparse.ArgumentParser(description=WORKFLOW_DESC)
    parser.add_argument("-d", "--domain", required=True)
    parser.add_argument("-w", "--wordlist", default="")
    parser.add_argument("-t", "--threads", type=int, default=100)
    parser.add_argument("--timeout", type=int, default=3)
    parser.add_argument("--depth", type=int, default=2)
    parser.add_argument("--ip-ranges", default="")
    parser.add_argument("-o", "--output", default="")
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
        depth=args.depth,
        ip_ranges=[r.strip() for r in args.ip_ranges.split(",") if r.strip()],
    )

    console.print(Panel(
        f"[bold magenta]{WORKFLOW_NAME}[/bold magenta] — {WORKFLOW_DESC}\n"
        f"[bold]Target:[/bold]   [cyan]{cfg.domain}[/cyan]\n"
        f"[bold]Techniques:[/bold] {len(TECHNIQUE_SEQUENCE)}\n"
        f"[bold]Threads:[/bold]  {cfg.threads}  [bold]Timeout:[/bold] {cfg.timeout}s",
        title="[bold yellow]⚡  Custom Workflow[/bold yellow]",
        expand=False,
    ))

    start = time.time()
    wordlist = load_wordlist(args.wordlist)

    # Resolve wordlist into kwargs for techniques that need it
    def _kw(wordlist_override=None):
        wl = wordlist_override or wordlist
        return dict(wordlist=wl)

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

    console.print("\n[bold]Running Custom Technique Sequence[/bold]\n")

    for label, module_name, class_name, base_kwargs in TECHNIQUE_SEQUENCE:
        # Inject wordlist into kwargs for techniques that need it
        kwargs = dict(base_kwargs)
        if "wordlist" not in kwargs and module_name in (
            "t01_bruteforce", "t06_ipv6", "t08_caa", "t09_cors",
            "t11_vhost", "t07_tlssni"
        ):
            kwargs["wordlist"] = wordlist

        console.print(f"  [cyan]→[/cyan] {label}")
        count, duration = run_technique(
            module_name, class_name, cfg, pool, wc, results,
            known=results.all_subs(), **kwargs
        )
        technique_stats[label.lower().replace(" ", "-")] = {
            "count": count,
            "start": start,
            "end": time.time(),
        }
        console.print(f"    [dim]{count} found ({duration:.1f}s)[/dim]")

    score_all(results.found)

    if args.output:
        save_results(
            results, args.output, domain=cfg.domain,
            scan_start=start, technique_stats=technique_stats,
        )

    console.print(
        f"\n[bold green][✓] Custom workflow complete: "
        f"{len(results.found)} subdomains found in {time.time() - start:.1f}s[/bold green]"
    )


if __name__ == "__main__":
    main()
