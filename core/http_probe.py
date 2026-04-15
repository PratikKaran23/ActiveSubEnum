"""
core/http_probe.py — HTTP Probe Phase (Part 10, Q7)

After all enumeration techniques complete, probe each discovered subdomain
via HTTP/HTTPS and tag them by response status.

Tags:
  [LIVE-200]   — responding with 200
  [LIVE-30x]   — redirecting (follow and tag final destination)
  [LIVE-401]   — auth required (interesting)
  [LIVE-403]   — forbidden (interesting, try path traversal)
  [LIVE-404]   — not found (may still have interesting paths)
  [LIVE-500]   — server error (very interesting)
  [LIVE-502/503] — bad gateway/service unavailable
  [NO-HTTP]    — DNS resolves but no HTTP/HTTPS response
  [DEAD]       — NXDOMAIN or timeout

Uses aiohttp only — no external tool dependency.
Supports HTTPS with SSL verification disabled (self-signed certs are common).
"""

import asyncio
import random
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

import aiohttp


@dataclass
class HTTPProbeResult:
    """Result of probing a single subdomain."""
    fqdn: str
    status: Optional[str] = None  # e.g. "LIVE-200"
    status_code: int = 0
    final_url: Optional[str] = None  # after redirect
    server: Optional[str] = None
    content_length: int = 0
    title: Optional[str] = None
    technologies: List[str] = field(default_factory=list)


class HTTPProbe:
    """HTTP probe for discovered subdomains.

    Probes both HTTP and HTTPS for each subdomain.
    Uses concurrency control to avoid overwhelming targets.
    """

    def __init__(
        self,
        timeout: int = 5,
        concurrency: int = 50,
        user_agents: Optional[List[str]] = None,
        follow_redirects: bool = False,
    ):
        self.timeout = timeout
        self.concurrency = concurrency
        self.user_agents = user_agents or [
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        ]
        self.follow_redirects = follow_redirects

    def _random_ua(self) -> str:
        return random.choice(self.user_agents)

    async def _probe_one(
        self, sess: aiohttp.ClientSession, fqdn: str
    ) -> HTTPProbeResult:
        """Probe a single subdomain over HTTP and HTTPS."""
        result = HTTPProbeResult(fqdn=fqdn)

        for scheme in ("https", "http"):
            url = f"{scheme}://{fqdn}/"
            try:
                async with sess.get(
                    url,
                    headers={"User-Agent": self._random_ua()},
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False,
                    allow_redirects=False,  # Don't follow redirects — tag them
                ) as resp:
                    result.status_code = resp.status
                    result.server = resp.headers.get("Server", "")
                    result.content_length = int(resp.headers.get("Content-Length", 0))

                    # Tag by status code
                    if resp.status == 200:
                        result.status = "LIVE-200"
                    elif 300 <= resp.status < 400:
                        result.status = f"LIVE-{resp.status}"
                        result.final_url = str(resp.headers.get("Location", ""))
                    elif resp.status == 401:
                        result.status = "LIVE-401"
                    elif resp.status == 403:
                        result.status = "LIVE-403"
                    elif resp.status == 404:
                        result.status = "LIVE-404"
                    elif resp.status == 500:
                        result.status = "LIVE-500"
                    elif resp.status in (502, 503, 504):
                        result.status = f"LIVE-{resp.status}"
                    elif resp.status >= 400:
                        result.status = f"LIVE-{resp.status}"

                    # Try to extract page title
                    try:
                        body = await resp.read()
                        if b"<title" in body.lower():
                            import re
                            title_match = re.search(
                                rb"<title[^>]*>([^<]+)</title>", body, re.IGNORECASE
                            )
                            if title_match:
                                result.title = title_match.group(1).decode(
                                    "utf-8", errors="ignore"
                                ).strip()
                    except Exception:
                        pass

                    # Detect technologies from headers
                    technologies = self._detect_technologies(resp.headers, result.server)
                    result.technologies.extend(technologies)

                    if result.status:
                        break  # Got a response, stop probing
            except asyncio.TimeoutError:
                continue
            except aiohttp.ClientConnectorError:
                continue
            except Exception:
                continue

        if not result.status:
            result.status = "NO-HTTP"
        return result

    def _detect_technologies(self, headers: dict, server: str) -> List[str]:
        """Guess technology stack from HTTP headers."""
        techs = []
        header_str = str(headers).lower()
        if "nginx" in server.lower():
            techs.append("nginx")
        if "apache" in server.lower():
            techs.append("apache")
        if "cloudflare" in header_str:
            techs.append("cloudflare")
        if "aws" in header_str or "amazon" in header_str:
            techs.append("aws")
        if "x-powered-by" in headers:
            techs.append(headers["x-powered-by"])
        if "x-aspnet-version" in headers:
            techs.append("aspnet")
        return techs

    async def probe_all(self, fqdns: Set[str]) -> Dict[str, HTTPProbeResult]:
        """Probe all subdomains concurrently. Returns {fqdn: result}."""
        results: Dict[str, HTTPProbeResult] = {}

        # Skip dead subdomains (NXDOMAIN or empty IPs)
        live_fqdns = [f for f in fqdns if f and not f.startswith("[")]

        if not live_fqdns:
            return results

        conn = aiohttp.TCPConnector(
            limit=self.concurrency,
            ssl=False,
            ttl_dns_cache=300,
        )

        async with aiohttp.ClientSession(connector=conn) as sess:
            # Process in batches to respect concurrency
            for i in range(0, len(live_fqdns), self.concurrency):
                batch = live_fqdns[i:i + self.concurrency]
                tasks = [self._probe_one(sess, fqdn) for fqdn in batch]
                batch_results = await asyncio.gather(
                    *tasks, return_exceptions=True
                )
                for r in batch_results:
                    if isinstance(r, HTTPProbeResult):
                        results[r.fqdn] = r

        return results

    def probe_all_sync(self, fqdns: Set[str]) -> Dict[str, HTTPProbeResult]:
        """Synchronous wrapper for probe_all."""
        try:
            asyncio.get_event_loop()
        except RuntimeError:
            asyncio.set_event_loop(asyncio.new_event_loop())
        return asyncio.run(self.probe_all(fqdns))


def update_results_with_probe(
    results: "ResultCollector", probe_results: Dict[str, HTTPProbeResult]
) -> Dict[str, int]:
    """Update ResultCollector with HTTP probe results.

    Returns http_stats: {status: count} for the hunter debrief.
    """
    http_stats: Dict[str, int] = {}
    for fqdn, probe_result in probe_results.items():
        status = probe_result.status or "NO-HTTP"
        http_stats[status] = http_stats.get(status, 0) + 1
        # Update the subdomain result
        try:
            loop = __import__("asyncio").get_event_loop()
        except RuntimeError:
            loop = __import__("asyncio").new_event_loop()
            __import__("asyncio").set_event_loop(loop)
        # Use sync lock since we may be in a sync context
        from .results import SubdomainResult
        if hasattr(results, "found") and fqdn in results.found:
            results.found[fqdn].http_status = status
            results.found[fqdn].confirmed = status.startswith("LIVE-")
    return http_stats