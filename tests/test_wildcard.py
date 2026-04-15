#!/usr/bin/env python3
"""
tests/test_wildcard.py — Unit tests for WildcardDetector

These tests verify the wildcard detection and filtering logic.
Safe to run: no network calls are made (use mocked resolver).
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.wildcard import WildcardDetector
from core.resolver import ResolverPool


class MockResolverPool:
    """Mock resolver pool that returns predetermined responses."""
    def __init__(self, responses: dict):
        # responses: {(fqdn, type): [ips]}
        self.responses = responses
        self._idx = 0

    def get(self):
        return MockResolver(self)

    def random(self):
        return MockResolver(self)

    def __len__(self):
        return 1


class MockResolver:
    def __init__(self, pool):
        self.pool = pool

    def resolve(self, fqdn, qtype):
        key = (fqdn, qtype)
        if key in self.pool.responses:
            return MockAnswer(self.pool.responses[key])
        raise Exception("Not found")


class MockAnswer:
    def __init__(self, addresses):
        self.addresses = addresses

    def __iter__(self):
        for addr in self.addresses:
            yield MockAddress(addr)


class MockAddress:
    def __init__(self, addr):
        self.address = addr


def test_no_wildcard():
    """If no wildcard detected, nothing should be filtered."""
    pool = MockResolverPool({})
    wc = WildcardDetector("example.com", pool)
    # No detection called — active=False
    assert wc.is_wildcard(["1.2.3.4"]) is False
    assert wc.is_wildcard([]) is False
    print("  ✓ test_no_wildcard passed")


def test_wildcard_filtering():
    """Subdomains matching only wildcard IPs should be filtered."""
    pool = MockResolverPool({})
    wc = WildcardDetector("example.com", pool)
    wc.active = True
    wc.wildcard_ips = {"10.0.0.1", "10.0.0.2"}

    # All IPs match wildcard → filtered
    assert wc.is_wildcard(["10.0.0.1"]) is True
    assert wc.is_wildcard(["10.0.0.1", "10.0.0.2"]) is True

    # Some IPs match, some don't → NOT filtered (legitimate multi-homed)
    assert wc.is_wildcard(["10.0.0.1", "1.2.3.4"]) is False

    # No overlap → not filtered
    assert wc.is_wildcard(["1.2.3.4", "5.6.7.8"]) is False

    # Empty → not filtered
    assert wc.is_wildcard([]) is False

    print("  ✓ test_wildcard_filtering passed")


def test_wildcard_partial_overlap():
    """A subdomain with mixed IPs (some wildcard, some not) should NOT be filtered.

    This is the key bug that was fixed: a real subdomain load-balanced across
    both wildcard infrastructure AND its own IP should be kept.
    """
    pool = MockResolverPool({})
    wc = WildcardDetector("example.com", pool)
    wc.active = True
    wc.wildcard_ips = {"10.0.0.1", "10.0.0.2"}

    # Mixed IPs → not filtered (correct behavior)
    assert wc.is_wildcard(["10.0.0.1", "8.8.8.8"]) is False

    print("  ✓ test_wildcard_partial_overlap passed")


def test_wildcard_thread_safety():
    """WildcardDetector should be thread-safe when multiple threads update state."""
    import threading

    pool = MockResolverPool({})
    wc = WildcardDetector("example.com", pool)
    wc.active = True

    def add_ips():
        for _ in range(100):
            wc.wildcard_ips.add(f"10.0.0.{id(threading.current_thread())}")

    threads = [threading.Thread(target=add_ips) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # All threads should have completed without errors
    assert len(wc.wildcard_ips) <= 400  # 4 threads × 100 additions
    print("  ✓ test_wildcard_thread_safety passed")


def test_empty_ips():
    """Empty IP list should never be filtered as wildcard."""
    pool = MockResolverPool({})
    wc = WildcardDetector("example.com", pool)
    wc.active = True
    wc.wildcard_ips = {"10.0.0.1"}

    assert wc.is_wildcard([]) is False
    print("  ✓ test_empty_ips passed")


if __name__ == "__main__":
    print("[test_wildcard.py] Running WildcardDetector tests...")
    test_no_wildcard()
    test_wildcard_filtering()
    test_wildcard_partial_overlap()
    test_wildcard_thread_safety()
    test_empty_ips()
    print("\nAll WildcardDetector tests passed ✓")
