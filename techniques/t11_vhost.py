"""
techniques/t11_vhost.py — VHost Fuzzing

TECHNIQUE: Virtual Host Fuzzing
TECHNIQUE_ID: t11
STEALTH: LOW — HTTP requests to IP addresses with Host header manipulation
HUNTER NOTE: VHost fuzzing finds subdomains that don't exist in DNS by
  probing IPs directly with Host headers. The same IP often hosts many vhosts
  (especially on shared hosting, CDNs, load balancers). This finds internal
  tools, dev environments, and staging servers that are accessible by IP.
  Baseline must use a definitely-invalid hostname, not empty Host header.

References:
  - https://www.yeswehack.com/learn-bug-bounty/subdomain-enumeration
  - ffuf vhost mode: ffuf -w wordlist.txt -H 'Host: FUZZ.target.com' -u http://IP/
"""

import asyncio
import random
from typing import List, Set

import aiohttp

from .base import BaseTechnique


class VHostTechnique(BaseTechnique):
    name = "VHost Fuzzing"
    aliases = ["vhost", "virtual-host", "host-header-fuzz", "vhost-scan", "11"]
    description = "Host header fuzzing against known IPs to find DNS-invisible virtual hosts"
    stealth_level = "low"
    technique_id = "t11"

    async def _baseline(
        self, sess: aiohttp.ClientSession, url: str
    ) -> tuple:
        """Establish baseline response with invalid hostname."""
        junk = f"nonexistent-{random.randint(10000, 99999)}.{self.cfg.domain}"
        try:
            async with sess.get(
                url,
                headers={"Host": junk},
                timeout=aiohttp.ClientTimeout(total=5),
                ssl=False,
                allow_redirects=False,
            ) as r:
                body = await r.read()
                return r.status, len(body)
        except Exception:
            return 0, 0

    async def _probe(
        self, sess: aiohttp.ClientSession, url: str,
        hostname: str, b_status: int, b_len: int
    ) -> str:
        """Probe with hostname and diff against baseline."""
        try:
            async with sess.get(
                url,
                headers={"Host": hostname, "User-Agent": "ActiveSubEnum/1.0"},
                timeout=aiohttp.ClientTimeout(total=5),
                ssl=False,
                allow_redirects=False,
            ) as r:
                body = await r.read()
                diff_len = abs(len(body) - b_len)
                if diff_len > 200 or r.status != b_status:
                    if r.status not in (400,):
                        return hostname
        except Exception:
            pass
        return None

    async def _fuzz_ip(
        self, ip: str, port: int, words: List[str]
    ) -> Set[str]:
        """Fuzz all words against one IP:port."""
        found: Set[str] = set()
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{ip}:{port}/"
        conn = aiohttp.TCPConnector(limit=60, ssl=False)
        async with aiohttp.ClientSession(connector=conn) as sess:
            b_status, b_len = await self._baseline(sess, url)
            if b_status == 0:
                return found
            tasks = [
                self._probe(sess, url, f"{w}.{self.cfg.domain}", b_status, b_len)
                for w in words
            ]
            batch_size = 60
            for i in range(0, len(tasks), batch_size):
                batch_results = await asyncio.gather(
                    *tasks[i:i + batch_size], return_exceptions=True
                )
                for r in batch_results:
                    if r and isinstance(r, str):
                        tag = f"vhost@{ip}:{port}"
                        self.results.add_sync(r, [f"[{tag}]"], "vhost-fuzz")
                        found.add(r)
        return found

    def run(self, cfg, pool, wc, results, **kwargs) -> Set[str]:
        from core.resolver import resolve_a
        from rich.console import Console
        console = Console()

        self.cfg = cfg
        self.results = results
        console.print(f"\n[bold blue][11][/bold blue] VHost Fuzzing")

        known: Set[str] = kwargs.get("known", set())
        wordlist: List[str] = kwargs.get("wordlist", [])
        max_words = getattr(cfg, "vhost_max_words", 400)
        max_ips = getattr(cfg, "vhost_max_ips", 5)

        # Resolve target IPs from known subdomains
        target_ips: Set[str] = set()
        for sub in list(known)[:5]:
            ips = resolve_a(sub, pool)
            if ips:
                target_ips.update(ips)
        main_ips = resolve_a(cfg.domain, pool)
        if main_ips:
            target_ips.update(main_ips)

        if not target_ips:
            console.print("  [dim]→ No target IPs for vhost fuzzing[/dim]")
            return set()

        console.print(
            f"  [dim]→ {len(target_ips)} IPs × {len(cfg.ports)} ports × "
            f"{min(len(wordlist), max_words)} words[/dim]"
        )

        found: Set[str] = set()
        words = wordlist[:max_words]
        for ip in list(target_ips)[:max_ips]:
            for port in cfg.ports:
                new = asyncio.run(self._fuzz_ip(ip, port, words))
                found.update(new)

        console.print(f"  [dim]→ {len(found)} vhosts discovered[/dim]")
        return found