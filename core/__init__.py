"""
core/ — Core modules for ActiveSubEnum v1.0

This package contains the foundational components extracted from activesubenum.py
plus additional pro-hunter features. All techniques and workflows import from here.

Modules:
  config     — Configuration dataclass and CLI argument handling
  resolver   — ResolverPool and DNS resolution helpers
  results    — ResultCollector for thread-safe result accumulation
  wildcard   — WildcardDetector for filtering wildcard subdomains
  output     — save_results, print_summary, print_banner, hunter_debrief
  http_probe — HTTP probe phase for tagging subdomains by response status
  scoring    — Subdomain interestingness scorer (0-100)
  saturation — Discovery rate saturation detector
  rate_limiter — Token-bucket rate limiter (global + per-resolver)

If the parent package (activesubenum.py) runs standalone without the full
package installed, it falls back to its own inline classes. The core/ module
is for when running through workflows/ or importing techniques/.
"""

__all__ = [
    "Config",
    "ResolverPool",
    "ResultCollector",
    "WildcardDetector",
    "load_wordlist",
    "load_resolvers",
    "save_results",
    "print_summary",
    "print_banner",
    "hunter_debrief",
    "HUNTER_USER_AGENTS",
    "HTTPProbe",
    "SubdomainScorer",
    "SaturationDetector",
    "RateLimiter",
    "DEFAULT_RESOLVERS",
    "BUILTIN_WORDLIST",
]