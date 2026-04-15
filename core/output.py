"""
core/output.py — Output formatting, saving, and hunter debrief

Part 6: Added hunter_debrief() with full technique breakdown
Part 7: Added multiple format support (json, txt, csv, md)
Part 7: Added progress persistence (partial results written during scan)
Part 7: Added take-over pre-check (cloud IP flagging)
Part 10: Added interestingness scoring + sort + annotation
"""

import csv
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from rich.console import Console
from rich.table import Table

# OpsEC rotating User-Agents (Part 10)
HUNTER_USER_AGENTS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 "
    "Firefox/121.0",
]


# ─── Cloud Provider IP Ranges (for takeover detection) ─────────────────────

CLOUD_RANGES = {
    "Heroku": ["52.x.x.x", "50.x.x.x"],
    "GitHub Pages": ["185.199.x.x"],
    "AWS S3/CloudFront": ["52.x.x.x", "54.x.x.x", "13.x.x.x", "3.x.x.x"],
    "Netlify": ["75.2.x.x", "104.x.x.x"],
    "Vercel": ["76.x.x.x"],
    "Cloudflare": ["104.x.x.x", "172.x.x.x", "198.x.x.x"],
    "Azure": ["20.x.x.x", "40.x.x.x", "13.x.x.x"],
    "Google Cloud": ["35.x.x.x", "34.x.x.x", "74.x.x.x", "104.x.x.x"],
    "DigitalOcean": ["68.x.x.x", "64.x.x.x", "104.x.x.x"],
    "Fly.io": ["66.x.x.x"],
    "Render": ["45.x.x.x", "172.x.x.x"],
    "Surge.sh": ["45.x.x.x"],
}


def check_takeover(ips: List[str]) -> Optional[Dict]:
    """Check if IPs belong to known cloud providers — potential takeover candidates.

    Returns dict with provider info if found, None otherwise.
    """
    for ip in ips:
        if ip.startswith("[IPv6]"):
            continue
        for provider, prefixes in CLOUD_RANGES.items():
            for prefix in prefixes:
                parts = prefix.split(".")
                ip_parts = ip.split(".")
                match = all(
                    parts[i] == "x" or parts[i] == ip_parts[i]
                    for i in range(len(parts))
                )
                if match:
                    return {"provider": provider, "ip": ip}
    return None


# ─── Save Results ───────────────────────────────────────────────────────────

def save_results(
    results: "ResultCollector",
    path: str,
    format: str = "auto",
    domain: str = "",
    scan_start: float = 0,
    technique_stats: Optional[Dict] = None,
    partial: bool = False,
    http_stats: Optional[Dict] = None,
    saturation: Optional[Dict] = None,
    takeover_candidates: Optional[List] = None,
    notes: Optional[Dict] = None,
) -> str:
    """Save results to file in the specified format.

    Args:
        results: ResultCollector instance
        path: Output file path (format inferred if 'auto')
        format: auto, json, txt, csv, md
        domain: Target domain (for JSON metadata)
        scan_start: Start timestamp (for JSON metadata)
        technique_stats: Per-technique {count, start, end} dict
        partial: If True, adds "PARTIAL RESULTS" header
        http_stats: {status: count} dict from HTTP probe phase
        saturation: {rate, status} dict
        takeover_candidates: List of {sub, provider, ip} dicts
        notes: {subdomain: note} dict
    """
    if not path:
        return ""

    if format == "auto":
        format = Path(path).suffix.lstrip(".") or "txt"
        if format not in ("json", "txt", "csv", "md"):
            format = "txt"

    results_dict = results.export_json()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if format == "json":
        metadata = {
            "domain": domain,
            "scan_time": datetime.now().isoformat(),
            "elapsed_seconds": round(time.time() - scan_start, 1),
            "total": len(results_dict),
            "techniques": list(technique_stats.keys()) if technique_stats else [],
            "technique_stats": {
                t: {
                    "found": s["count"],
                    "elapsed": round(s["end"] - s["start"], 1) if s.get("end") and s.get("start") else 0,
                }
                for t, s in (technique_stats or {}).items()
            },
            "http_stats": http_stats or {},
            "saturation": saturation or {},
            "takeover_candidates": takeover_candidates or [],
            "notes": notes or {},
        }
        data = {"metadata": metadata, "subdomains": results_dict}
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    elif format == "md":
        with open(path, "w") as f:
            if partial:
                f.write("> **PARTIAL RESULTS — scan in progress**\n\n")
            f.write(f"# Subdomain Enumeration — {domain}\n\n")
            f.write(f"**Scan:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | ")
            f.write(f"**Found:** {len(results_dict)} | ")
            f.write(f"**Elapsed:** {time.time() - scan_start:.1f}s\n\n")

            if technique_stats:
                f.write("## Technique Breakdown\n\n")
                f.write("| Technique | Found | Elapsed |\n")
                f.write("|-----------|-------|--------|\n")
                for t, s in technique_stats.items():
                    elapsed = s.get("end", 0) - s.get("start", 0)
                    f.write(f"| {t} | {s.get('count', 0)} | {elapsed:.1f}s |\n")
                f.write("\n")

            if http_stats:
                f.write("## HTTP Probe Summary\n\n")
                for status, count in sorted(http_stats.items()):
                    f.write(f"- {status}: {count}\n")
                f.write("\n")

            f.write("## Subdomains\n\n")
            f.write("| Subdomain | IPs | Score | HTTP | Technique(s) |\n")
            f.write("|-----------|-----|-------|------|--------------|\n")
            for sub, r in sorted(results_dict.items(), key=lambda x: -x[1].get("score", 0)):
                http_tag = r.get("http_status", "")
                score = r.get("score", 0)
                f.write(f"| {sub} | {', '.join(r['ips'][:2])} | {score} | {http_tag} | {', '.join(r['techniques'])} |\n")

            if notes:
                f.write("\n## Notes\n\n")
                for sub, note in notes.items():
                    f.write(f"- **{sub}**: {note}\n")

    elif format == "csv":
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["subdomain", "ip", "score", "http_status",
                             "takeover_risk", "takeover_provider", "techniques", "note"])
            for sub, r in results_dict.items():
                writer.writerow([
                    sub,
                    ", ".join(r["ips"][:3]),
                    r.get("score", 0),
                    r.get("http_status", ""),
                    r.get("takeover_risk", ""),
                    r.get("takeover_provider", ""),
                    ", ".join(r["techniques"]),
                    r.get("note", ""),
                ])

    else:  # txt
        with open(path, "w") as f:
            if partial:
                f.write(f"# PARTIAL RESULTS — scan in progress\n")
            for sub in sorted(results_dict):
                f.write(sub + "\n")

    console = Console()
    console.print(f"\n[bold green][✓] Saved {len(results_dict)} results → {path}[/bold green]")
    return path


# ─── Summary Table ──────────────────────────────────────────────────────────

def print_summary(results: "ResultCollector", start: float, sort_by: str = "score"):
    """Print the results summary table, sorted by the specified key."""
    elapsed = time.time() - start
    console = Console()

    items = list(results.items())
    if sort_by == "score":
        items.sort(key=lambda x: -x[1].score)
    elif sort_by == "ip":
        items.sort(key=lambda x: x[1].ips[0] if x[1].ips else "")
    elif sort_by == "technique":
        items.sort(key=lambda x: ",".join(x[1].techniques))

    table = Table(
        title="\n[bold]Active Subdomain Enumeration — Results[/bold]",
        show_header=True, header_style="bold magenta",
        show_lines=False,
    )
    table.add_column("Subdomain", style="cyan", no_wrap=True)
    table.add_column("IP(s) / Record(s)", style="yellow")
    table.add_column("Tech(s)", style="green")
    table.add_column("Score", style="magenta")

    for sub, r in items:
        score_str = str(r.score)
        if r.score >= 80:
            score_str = f"[bold red]{r.score}[/bold red]"
        elif r.score >= 50:
            score_str = f"[bold yellow]{r.score}[/bold yellow]"

        table.add_row(
            sub,
            ", ".join(r.ips[:2]),
            ", ".join(r.techniques),
            score_str,
        )
    console.print(table)
    console.print(
        f"\n  [bold]Total:[/bold] [bold green]{len(results.found)}[/bold green] unique subdomains  "
        f"[bold]Time:[/bold] {elapsed:.1f}s\n"
    )


# ─── Hunter Debrief (Part 10) ────────────────────────────────────────────────

def hunter_debrief(
    domain: str,
    results: "ResultCollector",
    scan_start: float,
    technique_stats: Dict,
    http_stats: Optional[Dict] = None,
    saturation: Optional[Dict] = None,
    takeover_candidates: Optional[List] = None,
    resolver_count: int = 0,
) -> None:
    """Print the pro hunter's debrief — the summary that replaces generic output.

    This is the format described in Part 10. Color-coded, scannable, action-oriented.
    """
    console = Console()
    elapsed = time.time() - scan_start
    total_mins = int(elapsed // 60)
    total_secs = int(elapsed % 60)
    elapsed_str = f"{total_mins}m {total_secs}s"

    console.print()

    # Header
    console.print("[bold cyan]╔" + "═" * 62 + "╗[/bold cyan]")
    console.print("[bold cyan]║[/bold cyan] [bold white]HUNT COMPLETE — {}[/bold white]{}║".format(
        domain,
        " " * max(0, 49 - len(domain)),
    ))
    console.print("[bold cyan]╠" + "═" * 62 + "╣[/bold cyan]")

    # Stats row
    def stat_row(label: str, value: str, right_label: str = "", right_value: str = ""):
        left = f"  {label}: {value}"
        if right_label:
            padding = 62 - len(left) - len(f"{right_label}: {right_value}") - 3
            line = left + " " * max(1, padding) + f"{right_label}: {right_value}"
        else:
            line = left + " " * (62 - len(left))
        console.print("[bold cyan]║[/bold cyan] [dim]" + line + "[/dim] [bold cyan]║[/bold cyan]")

    stat_row("TOTAL FOUND", f"{len(results.found)} subdomains")
    stat_row("SCAN TIME", elapsed_str)
    stat_row("TECHNIQUES RUN", str(len(technique_stats)))
    stat_row("RESOLVERS USED", f"{resolver_count} healthy")
    console.print("[bold cyan]╠" + "═" * 62 + "╣[/bold cyan]")
    console.print("[bold cyan]║[/bold cyan] [bold white]TECHNIQUE BREAKDOWN[/bold white]" + " " * 39 + "[bold cyan]║[/bold cyan]")
    console.print("[bold cyan]╠" + "═" * 62 + "╣[/bold cyan]")

    technique_order = ["brute", "mutation", "zone", "nsec", "cache", "ipv6",
                        "tlssni", "caa", "cors", "chaos", "vhost", "recursive",
                        "spf", "dkim", "chaos"]
    sorted_techs = sorted(
        technique_stats.items(),
        key=lambda x: (technique_order.index(x[0].split("[")[0]) if x[0].split("[")[0] in technique_order else 99, x[0])
    )

    for tech_name, stats in sorted_techs:
        count = stats.get("count", 0)
        elapsed_t = 0
        if stats.get("start") and stats.get("end"):
            t = stats["end"] - stats["start"]
            elapsed_t = f"{int(t // 60)}m {int(t % 60)}s"
        else:
            elapsed_t = "?"
        found_str = f"{count} found" if count > 0 else "0  found"
        tech_display = tech_name.ljust(20)
        console.print("[bold cyan]║[/bold cyan]  " + f"[{tech_display}]".ljust(23) +
                      f"→ {found_str}  ({elapsed_t})".ljust(37) + "[bold cyan]║[/bold cyan]")

    if http_stats:
        console.print("[bold cyan]╠" + "═" * 62 + "╣[/bold cyan]")
        console.print("[bold cyan]║[/bold cyan] [bold white]HTTP PROBE SUMMARY[/bold white]" + " " * 41 + "[bold cyan]║[/bold cyan]")
        console.print("[bold cyan]╠" + "═" * 62 + "╣[/bold cyan]")
        status_order = ["LIVE-200", "LIVE-30x", "LIVE-401", "LIVE-403", "LIVE-500", "NO-HTTP", "DEAD"]
        for i in range(0, len(http_stats), 3):
            chunk = list(http_stats.items())[i:i+3]
            line_parts = []
            for status, count in chunk:
                if status in status_order:
                    line_parts.append(f"{status}: {count}")
            if line_parts:
                line = "  " + "    ".join(line_parts)
                console.print("[bold cyan]║[/bold cyan] [dim]" + line.ljust(60) + "[/dim] [bold cyan]║[/bold cyan]")

    # High priority targets
    high_priority = [(sub, r) for sub, r in results.items() if r.score >= 60]
    high_priority.sort(key=lambda x: -x[1].score)

    console.print("[bold cyan]╠" + "═" * 62 + "╣[/bold cyan]")
    console.print("[bold cyan]║[/bold cyan] [bold red]HIGH PRIORITY TARGETS (score >= 60) — HUNT THESE FIRST[/bold red]" +
                  " " * 3 + "[bold cyan]║[/bold cyan]")
    console.print("[bold cyan]╠" + "═" * 62 + "╣[/bold cyan]")

    if not high_priority:
        console.print("[bold cyan]║[/bold cyan]  [dim]No high-priority targets found[/dim]" +
                      " " * 39 + "[bold cyan]║[/bold cyan]")
    else:
        for sub, r in high_priority[:10]:
            http_tag = r.http_status or "?"
            score_str = f"[{r.score}]"
            console.print("[bold cyan]║[/bold cyan]  " + f"{score_str} {sub}".ljust(40) +
                          f"[{http_tag}]".ljust(20) + "[bold cyan]║[/bold cyan]")

    # Takeover candidates
    console.print("[bold cyan]╠" + "═" * 62 + "╣[/bold cyan]")
    console.print("[bold cyan]║[/bold cyan] [bold yellow]TAKEOVER CANDIDATES[/bold yellow]" + " " * 41 + "[bold cyan]║[/bold cyan]")
    console.print("[bold cyan]╠" + "═" * 62 + "╣[/bold cyan]")

    if not takeover_candidates:
        console.print("[bold cyan]║[/bold cyan]  [dim]No takeover candidates detected[/dim]" +
                      " " * 39 + "[bold cyan]║[/bold cyan]")
    else:
        for tc in takeover_candidates[:5]:
            console.print("[bold cyan]║[/bold cyan]  " +
                          f"{tc['sub']} → {tc['ip']} ({tc['provider']})".ljust(59) +
                          "[bold cyan]║[/bold cyan]")

    # Saturation
    if saturation:
        console.print("[bold cyan]╠" + "═" * 62 + "╣[/bold cyan]")
        console.print("[bold cyan]║[/bold cyan] [bold white]SATURATION[/bold white]" + " " * 50 + "[bold cyan]║[/bold cyan]")
        console.print("[bold cyan]╠" + "═" * 62 + "╣[/bold cyan]")
        rate = saturation.get("rate", 0)
        status = saturation.get("status", "unknown")
        console.print("[bold cyan]║[/bold cyan]  " +
                      f"Discovery rate: {rate:.1f} subs/min (last 3 techniques)".ljust(60) +
                      "[bold cyan]║[/bold cyan]")
        console.print("[bold cyan]║[/bold cyan]  " +
                      f"Status: {status}".ljust(60) +
                      "[bold cyan]║[/bold cyan]")

    # Next steps
    console.print("[bold cyan]╚" + "═" * 62 + "╝[/bold cyan]")

    console.print("\n[dim]Next steps:[/dim]")
    console.print("  → Run workflow_deep.py with builtin_large.txt for more coverage")
    console.print("  → Manually check HIGH PRIORITY targets above")
    if takeover_candidates:
        for tc in takeover_candidates[:3]:
            console.print(f"  → Investigate takeover candidate: {tc['sub']}")


def print_banner():
    """Print the tool banner."""
    from rich.console import Console
    from rich.panel import Panel
    console = Console()
    BANNER = """[bold cyan]
 ▄▄▄       ▄████▄  ▄▄▄█████▓ ██▓ ██▒   █▓▓█████
▒████▄    ▒██▀ ▀█  ▓  ██▒ ▓▒▓██▒▓██░   █▒▓█   ▀
▒██  ▀█▄  ▒▓█    ▄ ▒ ▓██░ ▒░▒██▒ ▓██  █▒░▒███
░██▄▄▄▄██ ▒▓▓▄ ▄██▒░ ▓██▓ ░ ░██░  ▒██ █░░▒▓█  ▄
 ▓█   ▓██▒▒ ▓███▀ ░  ▒██▒ ░ ░██░   ▒▀█░  ░▒████▒
 ▒▒   ▓▒█░░ ░▒ ▒  ░  ▒ ░░   ░▓     ░ ▐░  ░░ ▒░ ░
  ▒   ▒▒ ░  ░  ▒       ░     ▒ ░   ░ ░░   ░ ░  ░
  ░   ▒   ░          ░       ▒ ░     ░░     ░
      ░  ░░ ░                ░        ░     ░  ░[/bold cyan]
[bold yellow]       SubEnum v1.0 — Active Only — 12+ Techniques[/bold yellow]
[dim]       Beyond wordlists. Beyond CT logs. Beyond passive.[/dim]
"""
    console.print(BANNER)