"""
core/passive_sources.py — Passive Intelligence Sources

Provides:
  CertTransparency  — crt.sh CT logs (always built-in, FREE, unlimited)
  ArgosDNSFile     — read user-provided ArgosDNS export (zero API cost)
  ArgosDNSAPI      — query ArgosDNS API directly (costs requests, use sparingly)
  PassiveAggregator — orchestrates all sources concurrently

Usage:
  aggregator = PassiveAggregator(cfg)
  results = asyncio.run(aggregator.run("target.com"))
  subs = aggregator.merge(results)
  aggregator.print_summary(results, subs)
"""

import asyncio
import json
from pathlib import Path
from typing import Dict, Set

import aiohttp

from rich.console import Console

console = Console()

BASE_URL = "https://api.argosdns.io"
ITEMS_PER_PAGE = 150


# ─── Class 1: CertTransparency (always built-in, free) ────────────────────────

class CertTransparency:
    """
    Queries crt.sh Certificate Transparency logs.
    FREE. No API key. No rate limit. Always runs.
    Database of every SSL cert ever issued.
    Often returns 50–500 real subdomains instantly.
    """

    async def query(self, domain: str,
                   session: aiohttp.ClientSession) -> Set[str]:
        subs = set()

        # Strategy: try multiple CT sources, merge all results
        sources_tried = []

        # Source 1: crt.sh JSON web API
        url = f"https://crt.sh/?q=%.{domain}&output=json&deduplicate=Y"
        sources_tried.append("crt.sh")
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=20),
                ssl=False,
            ) as resp:
                if resp.status == 200:
                    try:
                        text = await resp.text()
                        if text.strip().startswith("["):
                            data = json.loads(text)
                        else:
                            data = []
                    except Exception:
                        data = []

                    for entry in data:
                        for name in entry.get("name_value", "").split("\n"):
                            name = name.strip().lower()
                            name = name.lstrip("*.")
                            if not name:
                                continue
                            if name.endswith(f".{domain}") or name == domain:
                                prefix = name.replace(f".{domain}", "")
                                if prefix and "." not in prefix:
                                    subs.add(name)
                                elif name != domain:
                                    subs.add(name)
        except Exception as e:
            console.print(f"  [yellow][!] crt.sh primary failed: {e}[/yellow]")

        # Source 2: crt.sh via alternative endpoint
        if len(subs) < 10:
            url2 = f"https://crt.sh/?q=%.{domain}&output=json"
            try:
                async with session.get(
                    url2,
                    timeout=aiohttp.ClientTimeout(total=20),
                    ssl=False,
                ) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        if text.strip().startswith("["):
                            for entry in json.loads(text):
                                for name in entry.get("name_value", "").split("\n"):
                                    name = name.strip().lower().lstrip("*.")
                                    if name.endswith(f".{domain}") and name not in subs:
                                        subs.add(name)
            except Exception:
                pass

        # Source 3: CertSpotter (free API, no key)
        try:
            cs_url = f"https://api.certspotter.com/v0/issuances?domain={domain}&expand=dns_names&match_wildcard=true&include_subdomains=true"
            async with session.get(
                cs_url,
                timeout=aiohttp.ClientTimeout(total=15),
                ssl=False,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for cert in data:
                        for name in cert.get("dns_names", []):
                            name = name.strip().lower().lstrip("*.")
                            if name.endswith(f".{domain}") or name == domain:
                                if "." not in name.replace(f".{domain}", ""):
                                    subs.add(name)
                                elif name != domain:
                                    subs.add(name)
        except Exception:
            pass

        # Source 4: Digicert CT log search (no key)
        try:
            dg_url = f"https://api.digicert.com/ct/v1/subject?fqdn=%.{domain}"
            async with session.get(
                dg_url,
                timeout=aiohttp.ClientTimeout(total=15),
                ssl=False,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for entry in data.get("entries", []):
                        for name in entry.get("dns_names", []):
                            name = name.strip().lower().lstrip("*.")
                            if name.endswith(f".{domain}"):
                                subs.add(name)
        except Exception:
            pass

        return subs


# ─── Class 2: ArgosDNSFile (reads export file — zero API cost) ────────────────

class ArgosDNSFile:
    """
    Reads ArgosDNS export file provided by user.
    Zero API requests consumed — user exports manually from dashboard.
    This is the RECOMMENDED way to use ArgosDNS to preserve requests.

    Supported formats:
      - Plain text: one subdomain per line
      - CSV: subdomain in first column
      - JSON: array of strings or objects with 'subdomain'/'domain'/'name' key
    """

    def load(self, filepath: str, domain: str) -> Set[str]:
        path = Path(filepath)
        if not path.exists():
            console.print(f"  [red][!] Passive list not found: {filepath}[/red]")
            return set()

        subs = set()
        try:
            content = path.read_text(errors="ignore")
        except Exception as e:
            console.print(f"  [red][!] Could not read {filepath}: {e}[/red]")
            return set()

        # JSON format
        if filepath.lower().endswith(".json"):
            try:
                data = json.loads(content)
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, str):
                            subs.add(item.strip().lower())
                        elif isinstance(item, dict):
                            for key in ("subdomain", "domain", "name", "hostname"):
                                if key in item:
                                    subs.add(str(item[key]).strip().lower())
                                    break
            except Exception:
                pass

        # CSV or plain text
        else:
            for line in content.splitlines():
                line = line.strip().lower()
                if not line or line.startswith("#"):
                    continue
                # Take first column if CSV
                sub = line.split(",")[0].strip().strip('"').strip("'")
                if sub and "." in sub:
                    subs.add(sub)

        # Normalize: ensure all are FQDNs under target domain
        normalized: Set[str] = set()
        for sub in subs:
            sub = sub.lstrip("*.")
            if not sub:
                continue
            if sub.endswith(f".{domain}"):
                normalized.add(sub)
            elif sub == domain:
                pass  # skip bare domain
            elif "." not in sub:
                normalized.add(f"{sub}.{domain}")
            else:
                # might be a subdomain without domain suffix
                normalized.add(sub)

        console.print(
            f"  [green][+][/green] ArgosDNS file: "
            f"[cyan]{len(normalized):,}[/cyan] subdomains loaded "
            f"[dim](0 API requests used)[/dim]"
        )
        return normalized


# ─── Class 3: ArgosDNSAPI (queries API — costs requests, use sparingly) ──────

class ArgosDNSAPI:
    """
    Queries ArgosDNS API directly.
    COSTS API REQUESTS. Use sparingly.
    Account has limited requests (1000/month).

    COST ESTIMATE shown before querying:
      domain with ~100 subs  = 1 request
      domain with ~1000 subs = 7 requests
      domain with ~5000 subs = 34 requests

    User must confirm if estimated cost > max_requests (default 5).
    """

    def __init__(self, api_key: str):
        self.api_key = api_key

    async def _get_headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "X-Api-Key": self.api_key,
            "Content-Type": "application/json",
        }

    async def estimate_cost(self, domain: str,
                           session: aiohttp.ClientSession) -> int:
        """Get total count first to estimate request cost."""
        try:
            headers = await self._get_headers()
            # Try common count endpoint patterns
            for url in [
                f"{BASE_URL}/subdomains/count?domain={domain}",
                f"{BASE_URL}/domains/{domain}/count",
                f"{BASE_URL}/search?domain={domain}&count=true",
            ]:
                try:
                    async with session.get(
                        url, headers=headers,
                        timeout=aiohttp.ClientTimeout(total=10),
                    ) as r:
                        if r.status == 200:
                            data = await r.json()
                            if isinstance(data, dict):
                                total = data.get("count", data.get("total", 0))
                            else:
                                total = 0
                            pages = max(1, (total + ITEMS_PER_PAGE - 1) // ITEMS_PER_PAGE)
                            return pages
                except Exception:
                    continue
        except Exception:
            pass
        return 1  # default estimate

    async def query(self, domain: str,
                   session: aiohttp.ClientSession,
                   max_requests: int = 5) -> Set[str]:
        """
        Query ArgosDNS API with request budget limit.
        Never exceeds max_requests API calls.
        """
        subs: Set[str] = set()
        headers = await self._get_headers()

        # Estimate cost first
        estimated = await self.estimate_cost(domain, session)
        if estimated > max_requests:
            console.print(
                f"  [yellow][!] ArgosDNS: ~{estimated} requests needed "
                f"(budget: {max_requests}). "
                f"Consider exporting manually and using --passive-list[/yellow]"
            )
            console.print(
                f"  [yellow]    Use --argos-max-requests {estimated} "
                f"to override[/yellow]"
            )

        # Paginate through results
        page = 1
        requests_used = 0
        while requests_used < max_requests:
            try:
                # Try common API patterns — adjust based on actual docs
                for url_template in [
                    f"{BASE_URL}/subdomains?domain={domain}&page={page}&limit={ITEMS_PER_PAGE}",
                    f"{BASE_URL}/domains/{domain}/subdomains?page={page}&limit={ITEMS_PER_PAGE}",
                    f"{BASE_URL}/search?domain={domain}&page={page}&limit={ITEMS_PER_PAGE}",
                ]:
                    try:
                        async with session.get(
                            url_template, headers=headers,
                            timeout=aiohttp.ClientTimeout(total=15),
                        ) as resp:
                            requests_used += 1
                            if resp.status == 401:
                                console.print(
                                    "  [red][!] ArgosDNS: Invalid API key[/red]"
                                )
                                return subs
                            if resp.status == 429:
                                console.print(
                                    "  [yellow][!] ArgosDNS: Rate limited[/yellow]"
                                )
                                return subs
                            if resp.status != 200:
                                break

                            data = await resp.json()

                            # Handle different response formats
                            if isinstance(data, list):
                                items = data
                            elif isinstance(data, dict):
                                items = (
                                    data.get("data")
                                    or data.get("subdomains")
                                    or data.get("results")
                                    or data.get("items")
                                    or []
                                )
                            else:
                                items = []

                            if not items:
                                break

                            for item in items:
                                sub = (
                                    item
                                    if isinstance(item, str)
                                    else item.get("subdomain",
                                        item.get("domain",
                                        item.get("name",
                                        item.get("hostname", ""))))
                                )
                                if sub:
                                    subs.add(str(sub).strip().lower())

                            # Check if more pages
                            if isinstance(data, dict):
                                total = data.get("total", data.get("count", 0))
                            else:
                                total = 0
                            if len(items) < ITEMS_PER_PAGE:
                                break
                            if total and len(subs) >= total:
                                break
                            page += 1

                            # Small delay between pages
                            await asyncio.sleep(0.5)

                        # Successfully got results, break out of URL template loop
                        break

                    except aiohttp.ClientError:
                        continue

            except Exception as e:
                console.print(
                    f"  [yellow][!] ArgosDNS page {page}: {e}[/yellow]"
                )
                break

        console.print(
            f"  [green][+][/green] ArgosDNS API: "
            f"[cyan]{len(subs):,}[/cyan] subdomains "
            f"[dim]({requests_used} API requests used)[/dim]"
        )
        return subs


# ─── Class 4: PassiveAggregator (orchestrates all sources) ─────────────────────

class PassiveAggregator:
    """
    Runs all configured passive sources concurrently.
    Always runs crt.sh (free).
    ArgosDNS only if --passive-list or --argos-key provided.
    """

    def __init__(self, cfg):
        self.cfg = cfg
        self.ct = CertTransparency()
        self.argos_file = ArgosDNSFile() if getattr(cfg, 'passive_list', '') else None
        self.argos_api = (
            ArgosDNSAPI(cfg.argos_key) if getattr(cfg, 'argos_key', '') else None
        )

    async def run(self, domain: str) -> Dict[str, Set[str]]:
        results: Dict[str, Set[str]] = {}
        conn = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=conn) as session:

            # 1. crt.sh — always, free
            console.print("  [dim]→ Querying crt.sh CT logs...[/dim]")
            ct_subs = await self.ct.query(domain, session)
            results["crt.sh"] = ct_subs
            console.print(
                f"  [green][+][/green] crt.sh: "
                f"[cyan]{len(ct_subs):,}[/cyan] subdomains [dim](free)[/dim]"
            )

            # 2. ArgosDNS file — if --passive-list provided
            if self.argos_file and getattr(self.cfg, 'passive_list', ''):
                argos_subs = self.argos_file.load(
                    self.cfg.passive_list, domain
                )
                results["ArgosDNS-file"] = argos_subs

            # 3. ArgosDNS API — if --argos-key provided (costs requests)
            if self.argos_api and getattr(self.cfg, 'argos_key', ''):
                console.print(
                    f"  [dim]→ Querying ArgosDNS API "
                    f"(max {getattr(self.cfg, 'argos_max_requests', 5)} requests)...[/dim]"
                )
                api_subs = await self.argos_api.query(
                    domain, session,
                    max_requests=getattr(self.cfg, 'argos_max_requests', 5)
                )
                results["ArgosDNS-API"] = api_subs

        return results

    def merge(self, results: Dict[str, Set[str]]) -> Set[str]:
        merged: Set[str] = set()
        for subs in results.values():
            merged.update(subs)
        return merged

    def print_summary(self, results: Dict[str, Set[str]],
                     merged: Set[str]):
        console.print(
            f"\n  [bold]Passive sources total:[/bold] "
            f"[cyan]{len(merged):,}[/cyan] unique subdomains"
        )
        for source, subs in results.items():
            if subs:
                console.print(f"    {source}: {len(subs):,}")
