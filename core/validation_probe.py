"""
core/validation_probe.py — HTTP Probe via IP + Host Header

Probes subdomains by connecting DIRECTLY to their resolved IP address
and sending the Host header — bypassing DNS resolution entirely.

This is critical for validation because:
  1. ISP DNS intercept (Airtel rpz.) returns wrong IPs for unknown subdomains
  2. Many CDN subdomains only resolve when DNS wildcard is active
  3. Port scan already found which IPs are live — just probe them directly

Uses IP + Host: header pattern that the previous httpx approach confirmed works.
Thread-safe asyncio throughout.
"""

import asyncio
import re
import ssl
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import aiohttp


WAF_PATTERNS = {
    "cf-ray": "Cloudflare",
    "cf-cache-status": "Cloudflare",
    "x-check-cacheable": "Akamai",
    "x-akamai-": "Akamai",
    "x-amzn-trace-id": "AWS-WAF",
    "x-sucuri-id": "Sucuri",
    "x-sucuri-cache": "Sucuri",
    "x-iinfo": "Incapsula",
    "x-fastly-request-id": "Fastly",
    "server": None,  # handled separately
}


@dataclass
class ProbeResult:
    """Result of a single HTTP probe via IP + Host header."""
    status_code: int = 0
    status_tag: str = "NO-HTTP"     # LIVE-200, LIVE-301, LIVE-401, etc.
    final_url: Optional[str] = None
    title: Optional[str] = None
    server: Optional[str] = None
    content_length: int = 0
    waf_detected: Optional[str] = None
    redirect_count: int = 0
    redirect_chain: List[str] = None

    def __post_init__(self):
        if self.redirect_chain is None:
            self.redirect_chain = []

    @property
    def headers(self) -> Dict[str, str]:
        """Compatibility accessor."""
        return {}


class ValidatorHTTPProbe:
    """HTTP probe that connects to IP directly with Host header.

    Bypasses DNS resolution — uses pre-resolved IP addresses from enumeration.

    Args:
        timeout: connection timeout per request (seconds)
        concurrency: max concurrent probes
        follow_redirects: follow up to 3 redirects
    """

    def __init__(
        self,
        timeout: int = 5,
        concurrency: int = 100,
        follow_redirects: bool = False,
    ):
        self.timeout = timeout
        self.concurrency = concurrency
        self.follow_redirects = follow_redirects
        self._semaphore: asyncio.Semaphore | None = None

    def _get_semaphore(self) -> asyncio.Semaphore:
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.concurrency)
        return self._semaphore

    async def _fetch(
        self,
        ip: str,
        port: int,
        hostname: str,
        path: str = "/",
        follow_redirects: bool = False,
        redirect_count: int = 0,
        chain: Tuple[str, ...] = (),
    ) -> ProbeResult:
        """Single HTTP request via IP + Host header.

        Args:
            ip: resolved IP address to connect to
            port: TCP port (80 or 443)
            hostname: value for Host header
            path: URL path
            follow_redirects: whether to follow redirects
            redirect_count: current redirect depth
            chain: tuple of URLs already visited
        """
        sem = self._get_semaphore()

        scheme = "https" if port in (443, 8443, 9443, 4443) else "http"
        url = f"{scheme}://{ip}:{port}{path}"

        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        connector = aiohttp.TCPConnector(
            ssl=ssl_ctx,
            limit=self.concurrency,
            ttl_dns_cache=300,
            use_dns_cache=True,
        )

        async with sem:
            try:
                async with aiohttp.ClientSession(connector=connector) as sess:
                    async with sess.get(
                        url,
                        headers={"Host": hostname},
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        ssl=False,
                        allow_redirects=False,  # We handle redirects manually
                    ) as resp:
                        status = resp.status
                        headers = dict(resp.headers)
                        content_length = int(headers.get("Content-Length", 0))

                        # Detect WAF
                        waf = self._detect_waf(headers, resp.headers.get("Server", ""))

                        # Read body for title
                        title = ""
                        body = b""
                        try:
                            body = await asyncio.wait_for(
                                resp.read(),
                                timeout=3.0,
                            )
                            content_length = len(body)
                            if b"<title" in body.lower():
                                m = re.search(
                                    rb"<title[^>]*>([^<]+)</title>",
                                    body,
                                    re.IGNORECASE,
                                )
                                if m:
                                    title = m.group(1).decode("utf-8", errors="ignore").strip()
                        except asyncio.TimeoutError:
                            pass

                        result = ProbeResult(
                            status_code=status,
                            server=resp.headers.get("Server", ""),
                            title=title,
                            content_length=content_length,
                            waf_detected=waf,
                            redirect_count=redirect_count,
                            redirect_chain=list(chain),
                        )

                        # Tag status
                        if status == 200:
                            result.status_tag = "LIVE-200"
                        elif 300 <= status < 400:
                            result.status_tag = f"LIVE-{status}"
                            loc = headers.get("Location", headers.get("location", ""))
                            if loc:
                                result.final_url = loc
                        elif status == 401:
                            result.status_tag = "LIVE-401"
                        elif status == 403:
                            result.status_tag = "LIVE-403"
                        elif status == 404:
                            result.status_tag = "LIVE-404"
                        elif status == 500:
                            result.status_tag = "LIVE-500"
                        elif status in (502, 503, 504):
                            result.status_tag = f"LIVE-{status}"
                        elif status >= 400:
                            result.status_tag = f"LIVE-{status}"
                        else:
                            result.status_tag = "NO-HTTP"

                        # Follow redirect (up to 3 hops)
                        if follow_redirects and redirect_count < 3 and 300 <= status < 400:
                            loc = headers.get("Location", "")
                            if loc:
                                # Parse redirect URL
                                if loc.startswith("http://") or loc.startswith("https://"):
                                    redirect_url = loc
                                else:
                                    redirect_url = f"{scheme}://{hostname}{loc}"
                                new_chain = chain + (url,)
                                # Recursively fetch redirect
                                return await self._fetch(
                                    ip, port, hostname, "/" + loc.lstrip("/"),
                                    follow_redirects=True,
                                    redirect_count=redirect_count + 1,
                                    chain=new_chain,
                                )

                        return result

            except asyncio.TimeoutError:
                return ProbeResult(status_tag="NO-HTTP")
            except aiohttp.ClientConnectorError:
                return ProbeResult(status_tag="NO-HTTP")
            except OSError:
                return ProbeResult(status_tag="NO-HTTP")
            except Exception:
                return ProbeResult(status_tag="NO-HTTP")

    def _detect_waf(self, headers: Dict[str, str], server_header: str) -> Optional[str]:
        """Detect WAF from response headers."""
        hdr_lower = {k.lower(): v for k, v in headers.items()}
        for hdr_key, waf_name in WAF_PATTERNS.items():
            if hdr_key == "server":
                continue  # handled separately
            if any(hdr_key.lower() in k for k in hdr_lower):
                return waf_name

        # Server header check
        srv = server_header.lower()
        if "cloudflare" in srv:
            return "Cloudflare"
        elif "akamai" in srv:
            return "Akamai"
        elif "sucuri" in srv:
            return "Sucuri"
        elif "incapsula" in srv:
            return "Incapsula"

        return None

    async def probe_one(self, ip: str, port: int, hostname: str) -> ProbeResult:
        """Probe a single subdomain via IP + Host header.

        Tries HTTPS first (port 443), then HTTP (port 80).
        Returns first successful response.
        """
        result = ProbeResult()

        # Try HTTPS first if port is 443
        if port == 443:
            result = await self._fetch(ip, 443, hostname, "/", self.follow_redirects)
            if result.status_tag != "NO-HTTP":
                return result

        # Try HTTP
        http_port = 80 if port != 443 else 80
        result = await self._fetch(ip, http_port, hostname, "/", self.follow_redirects)
        if result.status_tag != "NO-HTTP":
            return result

        # Try HTTPS explicitly
        if port != 443:
            result = await self._fetch(ip, 443, hostname, "/", self.follow_redirects)
            if result.status_tag != "NO-HTTP":
                return result

        return result

    async def probe_batch(
        self,
        targets: List[Tuple[str, str, int]],
    ) -> Dict[Tuple[str, str], ProbeResult]:
        """Probe multiple (ip, hostname, port) targets concurrently.

        Args:
            targets: list of (ip, hostname, port) tuples

        Returns:
            dict mapping (ip, hostname) → ProbeResult
        """
        tasks = [
            self.probe_one(ip, port, hostname)
            for ip, hostname, port in targets
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        output = {}
        for (ip, hostname, _), result in zip(targets, results):
            if isinstance(result, ProbeResult):
                output[(ip, hostname)] = result
            else:
                output[(ip, hostname)] = ProbeResult()

        return output

    def probe_batch_sync(
        self,
        targets: List[Tuple[str, str, int]],
    ) -> Dict[Tuple[str, str], ProbeResult]:
        """Synchronous wrapper for probe_batch."""
        try:
            asyncio.get_running_loop()
            loop = asyncio.new_event_loop()
            return loop.run_until_complete(self.probe_batch(targets))
        except RuntimeError:
            return asyncio.run(self.probe_batch(targets))
