"""
core/content_fingerprint.py — CDN Wildcard Detection via Content Comparison (Part 12)

Uses HTTP content fingerprinting to detect CDN wildcard responses.
A CDN serving generic content for ANY hostname on an IP (not just valid subdomains)
is identified by:
  1. Fast check (Stage 4a): single HTTP request with random Host header → generic 200/301
  2. Full fingerprint (Stage 4b): compare subdomain content vs baseline random content

Comparison logic:
  - Hash (MD5) of first 4096 bytes, status code, page title
  - If hash SAME AND status SAME AND title SAME → same generic CDN page → discard
  - If content length within 5% AND title SAME → same page → discard
  - Any of: different status, different title, >20% size diff → unique → keep

Supports both normal and fast modes. Fast mode skips content hash comparison.
Thread-safe: asyncio primitives throughout.
"""

import asyncio
import hashlib
import random
import re
import ssl
import string
from typing import Dict, Optional, Tuple

import aiohttp


class ContentFingerprint:
    """Content fingerprinting for CDN wildcard detection.

    Args:
        timeout: HTTP request timeout in seconds (default 5)
        concurrency: max concurrent requests (default 100)
    """

    def __init__(self, timeout: int = 5, concurrency: int = 100):
        self.timeout = timeout
        self.concurrency = concurrency
        self._semaphore = asyncio.Semaphore(concurrency)

    def _random_label(self, length: int = 16) -> str:
        """Generate a random lowercase label (for probe hostnames)."""
        return "".join(random.choices(string.ascii_lowercase, k=length))

    # ── Low-level HTTP fetch ────────────────────────────────────────────────────

    async def _fetch(
        self,
        ip: str,
        port: int,
        hostname: str,
        path: str = "/",
    ) -> Dict:
        """Make a single HTTP(S) request with explicit Host header.

        Returns fingerprint dict:
          {hash, status, title, content_length, server, body}
        """
        sem = self._semaphore
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        scheme = "https" if port in (443, 8443, 9443, 4443) else "http"
        url = f"{scheme}://{ip}:{port}{path}"

        async with sem:
            try:
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(
                        ssl=ssl_ctx,
                        limit=self.concurrency,
                        ttl_dns_cache=300,
                    )
                ) as sess:
                    async with sess.get(
                        url,
                        headers={"Host": hostname},
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        ssl=False,
                        allow_redirects=False,
                    ) as resp:
                        body = await resp.read()
                        body_lower = body.lower()
                        title = ""
                        if b"<title" in body_lower:
                            m = re.search(
                                rb"<title[^>]*>([^<]+)</title>",
                                body,
                                re.IGNORECASE,
                            )
                            if m:
                                title = m.group(1).decode("utf-8", errors="ignore").strip()

                        content_hash = hashlib.md5(body[:4096]).hexdigest()
                        return {
                            "hash": content_hash,
                            "status": resp.status,
                            "title": title,
                            "content_length": len(body),
                            "server": resp.headers.get("Server", ""),
                            "body": body,
                        }
            except Exception:
                return {
                    "hash": "",
                    "status": 0,
                    "title": "",
                    "content_length": 0,
                    "server": "",
                    "body": b"",
                }

    # ── Fast CDN check (Stage 4a) ─────────────────────────────────────────────

    async def fast_cdn_check(
        self,
        ip: str,
        port: int,
        domain: str,
    ) -> bool:
        """Fast CDN wildcard check: single probe with random hostname.

        Makes ONE HTTP request to ip:port with Host: random16.{domain}.
        If we get HTTP 200/301 with body > 0 → CDN wildcard → return True.
        If we get 404/403/error → specific content → return False.

        This runs for EVERY IP even in --fast-validate mode.

        Returns True if CDN wildcard pattern detected, False otherwise.
        """
        random_host = f"{self._random_label(16)}.{domain}"
        result = await self._fetch(ip, port, random_host)

        status = result["status"]
        content_len = result["content_length"]

        # CDN serving ANY hostname: 200 or 301 with non-empty body
        if status in (200, 301) and content_len > 0:
            return True
        # Specific content: 404, 403, or error → not a wildcard
        return False

    # ── Full fingerprint methods (Stage 4b) ─────────────────────────────────

    async def get_fingerprint(
        self,
        ip: str,
        port: int,
        hostname: str,
    ) -> Dict:
        """Get content fingerprint for a specific subdomain.

        Returns fingerprint dict for the hostname's actual content.
        """
        return await self._fetch(ip, port, hostname)

    async def get_baseline(
        self,
        ip: str,
        port: int,
        domain: str,
    ) -> Dict:
        """Get baseline fingerprint using a random nonsense hostname.

        This represents the generic CDN response when an unknown subdomain
        is requested — not the specific content for a real subdomain.
        """
        random_host = f"{self._random_label(24)}.{domain}"
        return await self._fetch(ip, port, random_host)

    async def check_uniqueness(
        self,
        ip: str,
        port: int,
        hostname: str,
        baseline: Dict,
    ) -> Tuple[bool, Dict]:
        """Compare hostname's content against the baseline CDN response.

        Returns (is_unique, hostname_fingerprint):
          - True  = content is unique for this hostname → KEEP
          - False = content matches generic CDN baseline → DISCARD

        Comparison rules:
          1. Hash SAME AND status SAME AND title SAME → discard (exact match)
          2. Content length within 5% AND title SAME → discard (same page)
          3. Any of: different status, different title, >20% size diff → keep
        """
        fp = await self._fetch(ip, port, hostname)

        # Quick "same" check: same hash means same content
        if fp["hash"] == baseline["hash"] and fp["status"] == baseline["status"]:
            return False, fp

        # Title-only check
        if fp["title"] and fp["title"] == baseline["title"]:
            # Same title — check content length
            fp_len = fp["content_length"]
            base_len = baseline["content_length"]
            if base_len > 0:
                ratio = abs(fp_len - base_len) / base_len
                if ratio <= 0.05:
                    return False, fp  # Within 5% → same page

        # Size-based check
        if baseline["content_length"] > 0:
            ratio = abs(fp["content_length"] - baseline["content_length"]) / baseline["content_length"]
            if ratio > 0.20:
                return True, fp  # >20% size diff → definitely unique

        # Default: treat as unique if we can't prove it's the same
        return True, fp

    # ── Batch processing ───────────────────────────────────────────────────────

    async def fast_check_ips(
        self,
        ip_port_map: Dict[str, int],
        domain: str,
    ) -> Dict[str, bool]:
        """Run fast CDN check for multiple IPs concurrently.

        Args:
            ip_port_map: {ip: port_to_check} — typically port 80 or 443
            domain: the target domain

        Returns:
            {ip: is_cdn_wildcard} — True means discard (CDN wildcard),
                                    False means keep (specific content)
        """
        tasks = [
            self.fast_cdn_check(ip, port, domain)
            for ip, port in ip_port_map.items()
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        output = {}
        for ip, result in zip(ip_port_map.keys(), results):
            if isinstance(result, Exception):
                output[ip] = False  # On error, don't discard
            else:
                output[ip] = result

        return output

    # ── Sync wrappers ─────────────────────────────────────────────────────────

    def fast_cdn_check_sync(
        self,
        ip: str,
        port: int,
        domain: str,
    ) -> bool:
        """Synchronous wrapper for fast_cdn_check."""
        try:
            asyncio.get_running_loop()
            return asyncio.run(self.fast_cdn_check(ip, port, domain))
        except RuntimeError:
            return asyncio.run(self.fast_cdn_check(ip, port, domain))

    def fast_check_ips_sync(
        self,
        ip_port_map: Dict[str, int],
        domain: str,
    ) -> Dict[str, bool]:
        """Synchronous wrapper for fast_check_ips."""
        try:
            asyncio.get_running_loop()
            return asyncio.run(self.fast_check_ips(ip_port_map, domain))
        except RuntimeError:
            return asyncio.run(self.fast_check_ips(ip_port_map, domain))
