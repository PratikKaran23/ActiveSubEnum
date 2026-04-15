"""
techniques/t09_cors.py — CORS Origin Reflection

TECHNIQUE: CORS Origin Reflection Mining
TECHNIQUE_ID: t09
STEALTH: MEDIUM — HTTP requests to target infrastructure
HUNTER NOTE: CORS misconfigurations reveal subdomains that the target trusts.
  If a subdomain reflects your Origin header in Access-Control-Allow-Origin,
  it trusts that origin. This often means internal tools, dev environments,
  or API endpoints that trust specific subdomains.
  NOTE: ACAO: * is NOT a finding — it confirms nothing about our specific subdomain.
  Only exact match (ACAO == Origin we sent) is meaningful.

References:
  - Our earlier conversation — HTTP-layer subdomain discovery
  - Key: Origin header must EXACTLY match what we sent
  - Key: ACAO: * should NOT be counted
"""

import asyncio
from typing import List, Set

import aiohttp

from .base import BaseTechnique


class CORSTechnique(BaseTechnique):
    name = "CORS Origin Reflection"
    aliases = ["cors", "cors-mining", "cors-reflection", "origin-probe", "09"]
    description = "Send crafted Origin headers to live endpoints to discover CORS-trusted subdomains"
    stealth_level = "medium"
    technique_id = "t09"

    async def _probe(
        self, sess: aiohttp.ClientSession, endpoint: str, hostname: str
    ) -> str:
        """Send Origin header and check for exact reflection in ACAO."""
        origin = f"https://{hostname}"
        try:
            async with sess.get(
                endpoint,
                headers={"Origin": origin, "User-Agent": "ActiveSubEnum/1.0"},
                timeout=aiohttp.ClientTimeout(total=5),
                ssl=False,
                allow_redirects=False,
            ) as resp:
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                # CRITICAL: must EXACTLY match, not wildcard
                if acao == origin:
                    return hostname
        except Exception:
            pass
        return None

    async def _run_async(
        self, endpoints: List[str], hostnames: List[str], results
    ) -> Set[str]:
        """Async CORS probe across all endpoints × hostnames."""
        found: Set[str] = set()
        conn = aiohttp.TCPConnector(limit=80, ssl=False)
        async with aiohttp.ClientSession(connector=conn) as sess:
            tasks = [
                self._probe(sess, ep, h)
                for ep in endpoints
                for h in hostnames
            ]
            # Process in batches to avoid overwhelming
            batch_size = 200
            for i in range(0, len(tasks), batch_size):
                batch_results = await asyncio.gather(
                    *tasks[i:i + batch_size], return_exceptions=True
                )
                for r in batch_results:
                    if r and isinstance(r, str):
                        from core.resolver import resolve_a, ResolverPool
                        from core.config import DEFAULT_RESOLVERS
                        ips = resolve_a(
                            r,
                            ResolverPool(self.cfg.resolvers, self.cfg.timeout)
                        ) or ["[cors-only]"]
                        await results.add(r, ips, "cors-reflection")
                        found.add(r)
        return found

    def run(self, cfg, pool, wc, results, **kwargs) -> Set[str]:
        from rich.console import Console
        console = Console()

        self.cfg = cfg
        console.print(f"\n[bold blue][09][/bold blue] CORS Origin Reflection Mining")

        known: Set[str] = kwargs.get("known", set())
        wordlist: List[str] = kwargs.get("wordlist", [])

        # Build endpoints to probe
        endpoints = []
        for sub in list(known)[:8]:
            endpoints += [f"https://{sub}/", f"https://{sub}/api/v1/"]
        if cfg.api_endpoint:
            endpoints.append(cfg.api_endpoint)
        if not endpoints:
            endpoints = [
                f"https://www.{cfg.domain}/",
                f"https://api.{cfg.domain}/",
            ]

        hostnames = [f"{w}.{cfg.domain}" for w in wordlist[:150]]
        console.print(
            f"  [dim]→ {len(endpoints)} endpoints × {len(hostnames)} origins[/dim]"
        )

        found = asyncio.run(self._run_async(endpoints, hostnames, results))
        console.print(f"  [dim]→ {len(found)} CORS-trusted origins[/dim]")
        return found