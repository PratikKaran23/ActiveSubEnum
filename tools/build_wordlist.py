#!/usr/bin/env python3
"""
tools/build_wordlist.py — Target-Specific Wordlist Builder (Part 10, Q10)

Builds a target-specific wordlist from:
  1. Naming patterns extracted from already-discovered subdomains
  2. Job posting URLs for tech stack clues (flagged for manual check)
  3. Homepage content extraction (HTML parse, no scraping)
  4. Number range inference from existing subdomain patterns

Usage:
  python3 tools/build_wordlist.py -d example.com -i already_found.json
  python3 tools/build_wordlist.py -d example.com --fetch-homepage

Output: wordlists/target/example.com_wordlist.txt
"""

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def extract_patterns(subdomains: list) -> set:
    """Extract naming patterns from known subdomains."""
    patterns = set()

    for sub in subdomains:
        # Strip domain
        name = sub.split(".")[0] if "." in sub else sub

        # Number ranges: api01, api02, app01 → api03-app20
        num_match = re.search(r"(\D+?)(\d+)", name)
        if num_match:
            prefix, num_str = num_match.groups()
            num = int(num_str)
            for n in range(max(1, num - 2), num + 20):
                patterns.add(f"{prefix}{n:02d}")
                patterns.add(f"{prefix}{n}")

        # Prefix/suffix patterns: api-v1, dev-api, staging-api
        if "-" in name:
            parts = name.split("-")
            for i in range(1, len(parts)):
                patterns.add("-".join(parts[i:]))  # suffix
                patterns.add("-".join(parts[:i]))  # prefix

        # Region patterns: us-east, eu-west
        regions = ["us", "eu", "uk", "ap", "sg", "de", "fr", "au", "in", "jp",
                   "east", "west", "north", "south", "central"]
        for region in regions:
            if region in name:
                for alt in regions:
                    if alt != region:
                        patterns.add(name.replace(region, alt))
                        patterns.add(f"{alt}-{name}")

    return patterns


def extract_from_homepage(domain: str) -> set:
    """Fetch homepage and extract keywords from HTML."""
    keywords = set()
    try:
        import httpx
        try:
            resp = httpx.get(f"https://{domain}/", timeout=5.0, follow_redirects=True)
            text = resp.text

            # Extract title
            title_match = re.search(r"<title[^>]*>([^<]+)</title>", text, re.IGNORECASE)
            if title_match:
                title_words = re.findall(r"[a-z]{3,}", title_match.group(1))
                keywords.update(w.lower() for w in title_words)

            # Extract meta description
            desc_match = re.search(
                r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)["\']',
                text, re.IGNORECASE
            )
            if desc_match:
                desc_words = re.findall(r"[a-z]{3,}", desc_match.group(1))
                keywords.update(w.lower() for w in desc_words)

            # Extract h1/h2 headings
            headings = re.findall(r"<h[12][^>]*>([^<]+)</h[12]>", text, re.IGNORECASE)
            for h in headings:
                heading_words = re.findall(r"[a-z]{3,}", h)
                keywords.update(w.lower() for w in heading_words)

        except Exception:
            pass
    except ImportError:
        pass

    return keywords


def suggest_job_urls(domain: str) -> list:
    """Suggest job posting URLs for manual tech stack research."""
    suggestions = []
    company = domain.split(".")[0]

    # LinkedIn Jobs
    suggestions.append(
        f"https://www.linkedin.com/jobs/search/?keywords={domain}&location=any"
    )
    # Greenhouse
    suggestions.append(
        f"https://boards.greenhouse.io/{company}"
    )
    # Lever
    suggestions.append(
        f"https://jobs.lever.co/{company}"
    )
    # Indeed
    suggestions.append(
        f"https://www.indeed.com/jobs?q={domain}"
    )

    return suggestions


def main():
    parser = argparse.ArgumentParser(description="Build target-specific wordlist")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-i", "--input", default="",
                       help="JSON file with already-found subdomains")
    parser.add_argument("--fetch-homepage", action="store_true",
                       help="Fetch homepage and extract keywords")
    parser.add_argument("-o", "--output", default="",
                       help="Output file (default: wordlists/target/{domain}.txt)")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    from rich.console import Console
    console = Console()

    console.print(f"[cyan]Building target-specific wordlist for:[/cyan] {args.domain}\n")

    words = set()

    # Load from JSON input
    if args.input and Path(args.input).exists():
        import json
        with open(args.input) as f:
            data = json.load(f)
        subs = list(data.get("subdomains", {}).keys()) if isinstance(data, dict) else data
        console.print(f"  [dim]Loaded {len(subs)} subdomains from input[/dim]")

        patterns = extract_patterns(subs)
        console.print(f"  [dim]Extracted {len(patterns)} naming patterns[/dim]")
        words.update(patterns)

    # Fetch homepage
    if args.fetch_homepage:
        console.print("  [dim]Fetching homepage for keyword extraction...[/dim]")
        homepage_words = extract_from_homepage(args.domain)
        if homepage_words:
            console.print(f"  [dim]Found {len(homepage_words)} keywords from homepage[/dim]")
            words.update(homepage_words)
        else:
            console.print("  [dim]No keywords extracted (httpx not available or page unreachable)[/dim]")

    # Job URLs
    console.print("\n[bold]Job Posting URLs (for manual tech stack research):[/bold]")
    for url in suggest_job_urls(args.domain):
        console.print(f"  [cyan]→[/cyan] {url}")
    console.print()

    # Save output
    if not args.output:
        base = Path(__file__).parent.parent / "wordlists" / "target"
        base.mkdir(exist_ok=True)
        args.output = base / f"{args.domain.replace('.', '_')}_wordlist.txt"

    with open(args.output, "w") as f:
        f.write(f"# Target-specific wordlist for {args.domain}\n")
        f.write(f"# Generated by ActiveSubEnum build_wordlist.py\n")
        f.write(f"# Word count: {len(words)}\n\n")
        for word in sorted(words):
            f.write(word + "\n")

    console.print(f"\n[green]✓[/green] Built: {args.output}")
    console.print(f"  [cyan]Total new words: {len(words)}[/cyan]")
    console.print(f"\n[dim]Next: prepend this to your wordlist[/dim]")
    console.print(f"  python3 activesubenum.py -d {args.domain} "
                 f"-w {args.output} -w /path/to/jhaddix-all.txt")


if __name__ == "__main__":
    main()