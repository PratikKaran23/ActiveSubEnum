"""
techniques/t07_tlssni.py — TLS SNI Probing

TECHNIQUE: TLS SNI Probing
TECHNIQUE_ID: t07
STEALTH: LOW — makes TCP connections to IP ranges, potentially logged
HUNTER NOTE: TLS SNI bypasses DNS entirely. It finds split-horizon DNS setups
  where the same IP serves different vhosts that aren't in public DNS.
  Requires --ip-ranges (get from BGP/ASN data: bgp.he.net).
  This is the ONLY technique that finds subdomains that don't exist in DNS.

References:
  - Our earlier conversation
  - masscan + custom TLS probe pattern
  - Key: ssl.CERT_NONE + check_hostname=False
"""

import ipaddress
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set, Tuple

from .base import BaseTechnique


class TLSSNITechnique(BaseTechnique):
    name = "TLS SNI Probing"
    aliases = ["sni-probe", "tls-probe", "sni-scan", "ip-range-scan", "tlssni", "07"]
    description = "TLS ClientHello with SNI hostname probe against IP ranges — finds DNS-invisible vhosts"
    stealth_level = "low"
    technique_id = "t07"

    def _probe(self, ip: str, hostname: str, port: int = 443) -> bool:
        """Send TLS ClientHello with SNI. Check if cert matches domain."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as tls:
                    cert = tls.getpeercert()
                    if not cert:
                        return False
                    san = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
                    cn_list = [
                        v for ent in cert.get("subject", [])
                        for k, v in [ent] if k == "commonName"
                    ]
                    all_names = san + cn_list
                    return any(self.cfg.domain in n for n in all_names)
        except Exception:
            return False

    def _expand_range(self, ip_range: str) -> List[str]:
        """Expand IP range to individual hosts (capped at 512)."""
        try:
            net = ipaddress.ip_network(ip_range, strict=False)
            return [str(h) for h in list(net.hosts())[:512]]
        except Exception:
            return [ip_range]

    def _scan_ip(self, ip: str, hostnames: List[str]) -> List[Tuple[str, str]]:
        """Scan all hostnames against a single IP."""
        hits = []
        for h in hostnames:
            if self._probe(ip, h):
                hits.append((h, ip))
        return hits

    def run(self, cfg, pool, wc, results, **kwargs) -> Set[str]:
        from rich.console import Console
        console = Console()

        self.cfg = cfg
        console.print(f"\n[bold blue][07][/bold blue] TLS SNI Probing")

        found: Set[str] = set()
        if not cfg.ip_ranges:
            console.print("  [dim]→ No --ip-ranges provided. Skipping.[/dim]")
            return found

        all_ips: List[str] = []
        for r in cfg.ip_ranges:
            all_ips.extend(self._expand_range(r))

        hostnames = [f"{w}.{cfg.domain}" for w in kwargs.get("wordlist", [])[:300]]
        console.print(
            f"  [dim]→ {len(all_ips)} IPs × {len(hostnames)} hostnames[/dim]"
        )

        with ThreadPoolExecutor(max_workers=50) as ex:
            fs = {ex.submit(self._scan_ip, ip, hostnames): ip for ip in all_ips}
            for f in as_completed(fs):
                for hostname, ip in f.result():
                    results.add_sync(hostname, [ip], "tls-sni")
                    found.add(hostname)

        console.print(f"  [dim]→ {len(found)} SNI-confirmed subdomains[/dim]")
        return found