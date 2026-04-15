"""
core/port_scanner.py — Async TCP Port Scanner (Part 12)

Fast async TCP connect scan using asyncio.open_connection with a semaphore
for concurrency control. Scans a list of IPs against common port sets and
returns open ports per IP.

Port sets:
  WEB_PORTS     — HTTP/HTTPS and common web admin ports
  MAIL_PORTS    — SMTP, IMAP, POP3
  OTHER_PORTS   — SSH, FTP, databases, monitoring tools
  ALL_PORTS    — union of all three sets

Uses asyncio.Semaphore to cap concurrent connections. Stops early when
connection succeeds (no need to scan remaining ports on same IP).

Thread-safe: uses asyncio primitives throughout. No locks needed.
"""

import asyncio
import socket
from typing import Dict, List


# ── Port definitions ────────────────────────────────────────────────────────────

WEB_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 4443, 9443]
MAIL_PORTS = [25, 587, 465, 993, 995, 110, 143]
OTHER_PORTS = [22, 21, 3306, 5432, 6379, 27017, 9200, 5601]
ALL_PORTS = WEB_PORTS + MAIL_PORTS + OTHER_PORTS

# Quick scan = just web ports (for fast validation)
QUICK_PORTS = [80, 443, 8080, 8443]


class PortScanner:
    """Async TCP port scanner.

    Args:
        concurrency: max concurrent connection attempts (default 500)
        timeout: connection timeout in seconds (default 2.0)
    """

    def __init__(self, concurrency: int = 500, timeout: float = 2.0):
        self.concurrency = concurrency
        self.timeout = timeout
        self._semaphore: asyncio.Semaphore | None = None

    def _get_semaphore(self) -> asyncio.Semaphore:
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.concurrency)
        return self._semaphore

    async def _scan_port(self, ip: str, port: int) -> int | None:
        """Attempt a single TCP connection to ip:port.

        Returns port number if open, None if closed/timeout.
        """
        sem = self._get_semaphore()
        async with sem:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=self.timeout,
                )
                writer.close()
                await writer.wait_closed()
                return port
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError,
                    ConnectionResetError, BrokenPipeError):
                return None

    async def scan_host(
        self,
        ip: str,
        ports: List[int] | None = None,
    ) -> List[int]:
        """Scan all ports on a single IP concurrently.

        Args:
            ip: IPv4 address to scan
            ports: list of ports to test (default ALL_PORTS)

        Returns:
            List of open port numbers, sorted ascending.
        """
        if ports is None:
            ports = ALL_PORTS

        tasks = [self._scan_port(ip, port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        open_ports = []
        for port, result in zip(ports, results):
            if result is not None and not isinstance(result, Exception):
                open_ports.append(port)

        return sorted(open_ports)

    async def _scan_one_ip(self, ip: str, ports: List[int]) -> tuple[str, List[int]]:
        """Worker coroutine for a single IP. Returns (ip, open_ports)."""
        open_ports = await self.scan_host(ip, ports)
        return ip, open_ports

    async def scan_all_async(
        self,
        ip_list: List[str],
        ports: List[int] | None = None,
    ) -> Dict[str, List[int]]:
        """Scan multiple IPs concurrently.

        Args:
            ip_list: list of IPv4 addresses to scan
            ports: list of ports per IP (default ALL_PORTS)

        Returns:
            Dict mapping ip -> [open_port_numbers]. Only IPs with at least
            one open port are included.
        """
        if ports is None:
            ports = ALL_PORTS

        deduped = list(dict.fromkeys(ip_list))  # preserve order, remove dupes

        tasks = [self._scan_one_ip(ip, ports) for ip in deduped]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        output: Dict[str, List[int]] = {}
        for item in results:
            if isinstance(item, tuple) and len(item) == 2:
                ip, open_ports = item
                if open_ports:
                    output[ip] = open_ports

        return output

    def scan_all(
        self,
        ip_list: List[str],
        ports: List[int] | None = None,
    ) -> Dict[str, List[int]]:
        """Synchronous wrapper — runs scan_all_async in a new event loop.

        Args:
            ip_list: list of IPv4 addresses to scan
            ports: list of ports per IP (default ALL_PORTS)

        Returns:
            Dict mapping ip -> [open_port_numbers].
        """
        try:
            loop = asyncio.get_running_loop()
            # Already in async context — can't nest loops, use run_in_executor
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(
                    asyncio.run, self.scan_all_async(ip_list, ports)
                )
                return future.result()
        except RuntimeError:
            # No running loop — safe to use asyncio.run
            return asyncio.run(self.scan_all_async(ip_list, ports))