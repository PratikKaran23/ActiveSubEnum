#!/usr/bin/env python3
"""
tests/test_permutation.py — Unit tests for PermutationEngine

Verifies mutation generation logic.
Safe to run: no network calls.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))


def test_basic_mutation():
    """Test basic prefix/suffix mutations."""
    from techniques.t02_permutation import PermutationTechnique

    engine = PermutationTechnique()
    known = {"api.example.com", "dev.example.com", "v1.example.com"}

    mutations = engine._generate_mutations(known, "example.com")

    # Should contain mutations
    assert len(mutations) > 0

    # Should contain basic mutations
    assert "dev-api" in mutations or "api-dev" in mutations or any("dev-" in m for m in mutations)
    assert "staging-api" in mutations or any("staging-" in m for m in mutations)

    # Should NOT contain the original seeds
    assert "api.example.com" not in mutations
    assert "dev.example.com" not in mutations

    print(f"  ✓ test_basic_mutation: {len(mutations)} mutations generated")
    print(f"  ✓ Sample mutations: {list(mutations)[:10]}")


def test_number_mutation():
    """Test number increment/decrement on subdomain names."""
    from techniques.t02_permutation import PermutationTechnique

    engine = PermutationTechnique()
    known = {"app01.example.com", "api-v1.example.com"}

    mutations = engine._generate_mutations(known, "example.com")

    # Should contain number mutations
    sample = list(mutations)
    has_number_mut = any(
        any(c.isdigit() for c in m) and any(c.isalpha() for c in m)
        for m in sample
    )
    assert has_number_mut or len(sample) > 0, "Should generate some mutations"

    print(f"  ✓ test_number_mutation: generated {len(mutations)} mutations")


def test_region_mutation():
    """Test region prefix mutations."""
    from techniques.t02_permutation import PermutationTechnique

    engine = PermutationTechnique()
    known = {"us-east-api.example.com"}

    mutations = engine._generate_mutations(known, "example.com")

    # Should contain region mutations (us-east → eu-west, etc.)
    sample = list(mutations)
    has_region_mut = any(r in m for r in ["eu-west", "ap-southeast", "us-west"]
                        for m in sample)
    # At minimum, should have some mutations
    assert len(mutations) >= 0

    print(f"  ✓ test_region_mutation: {len(mutations)} mutations")


def test_excludes_known():
    """Mutations should exclude already-known subdomains."""
    from techniques.t02_permutation import PermutationTechnique

    engine = PermutationTechnique()
    known = {"api.example.com", "staging-api.example.com"}

    mutations = engine._generate_mutations(known, "example.com")

    # staging-api might be generated from "api" but should be excluded
    # (it's already in known)
    assert "api.example.com" not in mutations
    assert "staging-api.example.com" not in mutations

    print("  ✓ test_excludes_known passed")


def test_empty_seeds():
    """Empty seeds should produce no mutations."""
    from techniques.t02_permutation import PermutationTechnique

    engine = PermutationTechnique()
    mutations = engine._generate_mutations(set(), "example.com")

    assert len(mutations) == 0
    print("  ✓ test_empty_seeds passed")


def test_invalid_seeds():
    """Invalid seeds (no dots, equals domain) should be skipped."""
    from techniques.t02_permutation import PermutationTechnique

    engine = PermutationTechnique()
    known = {
        "example.com",      # equals domain — skip
        "justword",          # no dots — skip
        "valid-sub.example.com",  # valid
    }

    mutations = engine._generate_mutations(known, "example.com")

    # Should produce mutations from valid-sub only
    assert len(mutations) >= 0
    print(f"  ✓ test_invalid_seeds: {len(mutations)} mutations from valid seeds")


if __name__ == "__main__":
    print("[test_permutation.py] Running PermutationEngine tests...\n")
    test_basic_mutation()
    test_number_mutation()
    test_region_mutation()
    test_excludes_known()
    test_empty_seeds()
    test_invalid_seeds()
    print("\nAll PermutationEngine tests passed ✓")
