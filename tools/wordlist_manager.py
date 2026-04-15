#!/usr/bin/env python3
"""
tools/wordlist_manager.py — Community Wordlist Manager (Part 11)

Downloads, manages, and combines community wordlists for subdomain enumeration.

COMMANDS:
  python3 tools/wordlist_manager.py list
  python3 tools/wordlist_manager.py download --tier 1
  python3 tools/wordlist_manager.py download --id jhaddix-all
  python3 tools/wordlist_manager.py download --all
  python3 tools/wordlist_manager.py update
  python3 tools/wordlist_manager.py build --profile quick
  python3 tools/wordlist_manager.py stats
"""

import argparse
import os
import sys
import time
from pathlib import Path

# ─── Wordlist Registry ────────────────────────────────────────────────────────

WORDLIST_REGISTRY = [
    # ── TIER 1: MUST-HAVES ───────────────────────────────────────────────
    {
        "id": "jhaddix-all",
        "name": "Jason Haddix all.txt",
        "url": "https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/all.txt",
        "size_hint": "~2M words",
        "tier": 1,
        "why": "The gold standard. Jason Haddix compiled this from multiple sources + "
               "real bug bounty recon. Used by 90% of serious hunters.",
        "credit": "Jason Haddix (@jhaddix)",
    },
    {
        "id": "assetnote-manual",
        "name": "Assetnote best-dns-wordlist",
        "url": "https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt",
        "size_hint": "~9M words",
        "tier": 1,
        "why": "Built from real internet data — subdomains Assetnote observed "
               "across millions of domains. Statistically derived.",
        "credit": "Assetnote (assetnote.io)",
    },
    {
        "id": "assetnote-2m",
        "name": "Assetnote 2m subdomains",
        "url": "https://wordlists-cdn.assetnote.io/data/manual/2m-subdomains.txt",
        "size_hint": "~2M words",
        "tier": 1,
        "why": "Lighter version. Good balance of coverage vs. speed.",
        "credit": "Assetnote (assetnote.io)",
    },
    {
        "id": "seclists-dns-jhaddix",
        "name": "SecLists DNS Jhaddix.txt",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/dns-Jhaddix.txt",
        "size_hint": "~1.9M words",
        "tier": 1,
        "why": "Daniel Miessler's SecLists DNS collection. Community-maintained.",
        "credit": "Daniel Miessler (@danielmiessler) + SecLists community",
    },
    # ── TIER 2: SPECIALIZED / COMPLEMENTARY ─────────────────────────────
    {
        "id": "seclists-subdomains-top1m",
        "name": "SecLists subdomains-top1million",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt",
        "size_hint": "~110K words",
        "tier": 2,
        "why": "Fast, high-signal. Derived from Alexa/Tranco top 1M domains.",
        "credit": "SecLists community",
    },
    {
        "id": "trickest-inventory",
        "name": "Trickest Inventory",
        "url": "https://raw.githubusercontent.com/trickest/inventory/main/subdomains.txt",
        "size_hint": "~6M words",
        "tier": 2,
        "why": "Built from continuous recon across HackerOne and Bugcrowd programs. "
               "Actual subdomains from real bug bounty targets.",
        "credit": "Trickest (trickest.io)",
    },
    {
        "id": "commonspeak2",
        "name": "Commonspeak2",
        "url": "https://raw.githubusercontent.com/assetnote/commonspeak2-wordlists/master/subdomains/subdomains.txt",
        "size_hint": "~1.6M words",
        "tier": 2,
        "why": "Generated from Google BigQuery analysis of real internet data. "
               "Good for modern cloud-native naming patterns.",
        "credit": "Assetnote (Shubham Shah + team)",
    },
    {
        "id": "n0kovo-subdomains",
        "name": "n0kovo huge subdomains",
        "url": "https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_huge.txt",
        "size_hint": "~3M words",
        "tier": 2,
        "why": "Community-compiled and cleaned. Good supplementary list.",
        "credit": "n0kovo (@n0kovo)",
    },
    {
        "id": "six2dez-onelistforall",
        "name": "six2dez OneListForAll micro",
        "url": "https://raw.githubusercontent.com/six2dez/OneListForAll/main/onelistforallmicro.txt",
        "size_hint": "~1M words",
        "tier": 2,
        "why": "Built by a top-ranked Bugcrowd hunter from years of real recon.",
        "credit": "six2dez (@six2dez) — top Bugcrowd hunter",
    },
    {
        "id": "altdns-words",
        "name": "AltDNS words.txt (permutation source)",
        "url": "https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt",
        "size_hint": "~240K words",
        "tier": 2,
        "why": "Specifically designed for PERMUTATION — not brute force. "
               "These are the words that appear as prefixes/suffixes in mutations.",
        "special_use": "permutation_engine_only",
        "credit": "infosec-au (altdns project)",
    },
    {
        "id": "seclists-top5k",
        "name": "SecLists top 5000 subdomains",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
        "size_hint": "~5K words",
        "tier": 2,
        "why": "Ultra-fast, ultra-high-signal. Use as warmup before larger lists.",
        "credit": "SecLists community",
    },
    # ── TIER 3: SITUATIONAL ──────────────────────────────────────────────
    {
        "id": "seclists-fierce",
        "name": "SecLists fierce-hostlist",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/fierce-hostlist.txt",
        "size_hint": "~2.2K words",
        "tier": 3,
        "why": "Classic Fierce tool wordlist. Small but time-tested.",
        "credit": "RSnake + SecLists community",
    },
    {
        "id": "seclists-bitquark",
        "name": "SecLists bitquark top 100K",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/bitquark-subdomains-top100000.txt",
        "size_hint": "~100K words",
        "tier": 3,
        "why": "Statistically ranked by frequency of occurrence on the internet.",
        "credit": "bitquark + SecLists",
    },
]

COMBINED_PROFILES = {
    "quick": {
        "description": "Fast first look (quick workflow)",
        "sources": ["seclists-top5k", "seclists-fierce"],
        "output_name": "combined_quick.txt",
    },
    "standard": {
        "description": "Standard bug bounty (standard workflow)",
        "sources": ["jhaddix-all", "assetnote-2m"],
        "output_name": "combined_standard.txt",
    },
    "deep": {
        "description": "Deep comprehensive (deep workflow)",
        "sources": ["jhaddix-all", "assetnote-manual", "trickest-inventory",
                    "commonspeak2", "n0kovo-subdomains", "six2dez-onelistforall"],
        "output_name": "combined_deep.txt",
    },
    "stealth": {
        "description": "Stealthy recon (stealth workflow)",
        "sources": ["seclists-top5k"],
        "output_name": "combined_stealth.txt",
    },
    "infra": {
        "description": "Infrastructure focus (infra workflow)",
        "sources": ["assetnote-manual", "seclists-subdomains-top1m"],
        "output_name": "combined_infra.txt",
    },
}


# ─── CLI Implementation ────────────────────────────────────────────────────────

def cmd_list(args):
    """List all known wordlists."""
    from rich.console import Console
    from rich.table import Table
    console = Console()

    table = Table(title="Known Community Wordlists", show_header=True)
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="yellow")
    table.add_column("Tier", style="magenta")
    table.add_column("Size", style="green")
    table.add_column("Special Use", style="dim")
    table.add_column("Downloaded?", style="bold")

    base = Path(__file__).parent.parent / "wordlists" / "external"
    for wl in WORDLIST_REGISTRY:
        filename = wl["id"].replace("/", "_") + ".txt"
        downloaded = "[green]YES[/green]" if (base / filename).exists() else "[red]no[/red]"
        special = wl.get("special_use", "") or ""
        table.add_row(
            wl["id"],
            wl["name"],
            f"[{'★' * wl['tier']}]",
            wl["size_hint"],
            special,
            downloaded,
        )

    console.print(table)
    console.print(f"\n[dim]{len(WORDLIST_REGISTRY)} wordlists in registry[/dim]")
    console.print("\n[cyan]To download: python3 tools/wordlist_manager.py download --tier 1[/cyan]")
    console.print("[cyan]To build combined: python3 tools/wordlist_manager.py build --profile standard[/cyan]")


def cmd_download(args):
    """Download wordlists."""
    from rich.console import Console
    from rich.progress import Progress, DownloadColumn, BarColumn, TextColumn
    console = Console()

    base = Path(__file__).parent.parent / "wordlists" / "external"
    base.mkdir(exist_ok=True)

    targets = []
    if args.tier:
        targets = [wl for wl in WORDLIST_REGISTRY if wl["tier"] <= args.tier]
    elif args.id:
        targets = [wl for wl in WORDLIST_REGISTRY if wl["id"] == args.id]
        if not targets:
            console.print(f"[red]Unknown wordlist ID: {args.id}[/red]")
            return
    elif args.all:
        targets = WORDLIST_REGISTRY
    else:
        console.print("[yellow]Specify --tier, --id, or --all[/yellow]")
        return

    console.print(f"[cyan]Downloading {len(targets)} wordlist(s)...[/cyan]\n")

    try:
        import httpx
        client = httpx.Client(timeout=60.0)

        for wl in targets:
            filename = wl["id"].replace("/", "_") + ".txt"
            out_path = base / filename

            if out_path.exists() and not args.update:
                console.print(f"  [dim]→ {wl['id']} already downloaded (use --update to re-download)[/dim]")
                continue

            console.print(f"  [cyan]Downloading:[/cyan] {wl['name']} ({wl['size_hint']})")
            try:
                resp = client.get(wl["url"], timeout=60.0)
                if resp.status_code == 200:
                    lines = len(resp.text.splitlines())
                    with open(out_path, "w") as f:
                        f.write(resp.text)
                    size_kb = len(resp.text) / 1024
                    console.print(
                        f"  [green]✓[/green] {wl['id']}: {lines:,} words, {size_kb:.0f}KB "
                        f"→ {out_path.name}"
                    )
                else:
                    console.print(
                        f"  [red]✗[/red] {wl['id']}: HTTP {resp.status_code}"
                    )
            except Exception as e:
                console.print(f"  [red]✗[/red] {wl['id']}: {e}")

        client.close()

    except ImportError:
        console.print("[yellow]httpx not installed — using urllib instead[/yellow]")
        import urllib.request

        for wl in targets:
            filename = wl["id"].replace("/", "_") + ".txt"
            out_path = base / filename

            console.print(f"  [cyan]Downloading:[/cyan] {wl['name']}")
            try:
                urllib.request.urlretrieve(wl["url"], out_path)
                lines = sum(1 for _ in open(out_path))
                console.print(f"  [green]✓[/green] {wl['id']}: {lines:,} words → {out_path.name}")
            except Exception as e:
                console.print(f"  [red]✗[/red] {wl['id']}: {e}")


def cmd_update(args):
    """Re-download all previously downloaded wordlists."""
    from rich.console import Console
    console = Console()
    console.print("[cyan]Update: re-downloading all downloaded wordlists...[/cyan]")
    args.update = True
    args.tier = None
    args.id = None
    args.all = True
    cmd_download(args)


def cmd_build(args):
    """Build combined wordlist from sources."""
    from rich.console import Console
    console = Console()

    base = Path(__file__).parent.parent / "wordlists" / "external"
    combined_base = Path(__file__).parent.parent / "wordlists" / "combined"
    combined_base.mkdir(exist_ok=True)

    profile = COMBINED_PROFILES.get(args.profile)
    if not profile:
        console.print(f"[red]Unknown profile: {args.profile}[/red]")
        console.print(f"Available: {', '.join(COMBINED_PROFILES.keys())}")
        return

    console.print(f"[cyan]Building combined wordlist: {args.profile}[/cyan]")
    console.print(f"[dim]Description: {profile['description']}[/dim]\n")

    all_words = set()
    found = []
    missing = []

    for wl_id in profile["sources"]:
        filename = wl_id.replace("/", "_") + ".txt"
        path = base / filename
        if path.exists():
            with open(path) as f:
                before = len(all_words)
                for line in f:
                    w = line.strip()
                    if w and not w.startswith("#"):
                        all_words.add(w)
                after = len(all_words)
                found.append((wl_id, after - before))
        else:
            missing.append(wl_id)

    if missing:
        console.print(
            f"[yellow]⚠ Missing wordlists: {', '.join(missing)}[/yellow]"
        )
        console.print(
            f"[yellow]  Download them first: python3 tools/wordlist_manager.py download --id {missing[0]}[/yellow]"
        )

    sorted_words = sorted(all_words)
    out_path = combined_base / profile["output_name"]
    with open(out_path, "w") as f:
        f.write(f"# Combined wordlist: {args.profile}\n")
        f.write(f"# Description: {profile['description']}\n")
        f.write(f"# Sources: {', '.join(profile['sources'])}\n")
        f.write(f"# Word count: {len(sorted_words):,}\n\n")
        for w in sorted_words:
            f.write(w + "\n")

    console.print(f"\n[green]✓[/green] Built: {out_path.name}")
    console.print(f"  [cyan]Total unique words: {len(sorted_words):,}[/cyan]")
    for wl_id, count in found:
        console.print(f"  [dim]  {wl_id}: +{count:,}[/dim]")


def cmd_stats(args):
    """Show statistics for downloaded wordlists."""
    from rich.console import Console
    from rich.table import Table
    console = Console()

    base = Path(__file__).parent.parent / "wordlists" / "external"

    table = Table(title="Downloaded Wordlist Statistics", show_header=True)
    table.add_column("ID", style="cyan")
    table.add_column("Words", style="green")
    table.add_column("Avg Len", style="yellow")
    table.add_column("Top 10 Prefixes", style="dim")

    for wl in WORDLIST_REGISTRY:
        filename = wl["id"].replace("/", "_") + ".txt"
        path = base / filename
        if not path.exists():
            continue

        with open(path) as f:
            words = [w.strip() for w in f if w.strip() and not w.startswith("#")]

        if not words:
            continue

        avg_len = sum(len(w) for w in words) / len(words)

        # Top 10 most common prefixes
        from collections import Counter
        prefixes = [w.split("-")[0].split(".")[0] for w in words if w]
        top_prefixes = [p for p, _ in Counter(prefixes).most_common(10)]
        prefix_str = ", ".join(top_prefixes[:5])

        table.add_row(wl["id"], f"{len(words):,}", f"{avg_len:.1f}", prefix_str)

    console.print(table)


def cmd_permutation_lists(args):
    """Show permutation-only wordlists."""
    from rich.console import Console
    console = Console()
    console.print("[bold]Wordlists tagged for permutation engine only:[/bold]\n")
    for wl in WORDLIST_REGISTRY:
        if wl.get("special_use") == "permutation_engine_only":
            console.print(f"  [cyan]{wl['id']}[/cyan] — {wl['size_hint']}")
            console.print(f"    {wl['why']}")
            console.print(f"    Use with: python3 activesubenum.py --permutation-wordlist <path>\n")


def main():
    parser = argparse.ArgumentParser(
        prog="wordlist_manager.py",
        description="Community wordlist manager for ActiveSubEnum",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # list
    sub.add_parser("list", help="List all known wordlists")

    # download
    dl = sub.add_parser("download", help="Download wordlists")
    dl.add_argument("--tier", type=int, choices=[1, 2, 3],
                    help="Download all wordlists of a given tier")
    dl.add_argument("--id", help="Download a specific wordlist by ID")
    dl.add_argument("--all", action="store_true", help="Download ALL wordlists")
    dl.add_argument("--update", action="store_true",
                    help="Re-download even if already present")

    # update
    sub.add_parser("update", help="Re-download all previously downloaded wordlists")

    # build
    build = sub.add_parser("build", help="Build a combined wordlist profile")
    build.add_argument("--profile", required=True,
                       choices=list(COMBINED_PROFILES.keys()),
                       help="Profile to build")

    # stats
    sub.add_parser("stats", help="Show statistics for downloaded wordlists")

    # permutation-lists
    sub.add_parser("permutation-lists",
                   help="Show wordlists tagged for permutation engine only")

    args = parser.parse_args()

    commands = {
        "list": cmd_list,
        "download": cmd_download,
        "update": cmd_update,
        "build": cmd_build,
        "stats": cmd_stats,
        "permutation-lists": cmd_permutation_lists,
    }

    commands[args.cmd](args)


if __name__ == "__main__":
    main()
