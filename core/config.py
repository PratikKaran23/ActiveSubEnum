"""
core/config.py — Configuration dataclass for ActiveSubEnum v1.0

Holds all scan parameters in a single immutable-ish dataclass.
Used by both the standalone activesubenum.py and the techniques/ modules.
"""

from dataclasses import dataclass, field
from typing import List


DEFAULT_RESOLVERS = [
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
    "9.9.9.9", "149.112.112.112", "208.67.222.222",
    "208.67.220.220", "64.6.64.6", "64.6.65.6",
]


@dataclass
class Config:
    """All scan configuration in one place.

    Part 1:    Added dry_run, vhost_max_words, vhost_max_ips
    Part 7:    Added output_format, skip_http_probe, rate_limit,
               sort_by, opsec_mode, refresh_resolvers, resume,
               skip_clean, permutation_wordlist, annotate, http_timeout
    Part 10:   Added user_agents rotation for opsec mode
    """
    domain: str
    wordlist_path: str = ""
    resolvers: List[str] = field(default_factory=lambda: list(DEFAULT_RESOLVERS))
    threads: int = 100
    timeout: int = 3
    techniques: List[str] = field(default_factory=list)
    ip_ranges: List[str] = field(default_factory=list)
    output: str = ""
    depth: int = 2
    api_endpoint: str = ""
    verbose: bool = False
    ports: List[int] = field(default_factory=lambda: [80, 443, 8080, 8443])

    # Part 1: dry-run mode
    dry_run: bool = False

    # Part 1: configurable vhost limits
    vhost_max_words: int = 400
    vhost_max_ips: int = 5

    # Part 7: output format
    output_format: str = "auto"  # auto, json, txt, csv, md
    skip_http_probe: bool = False
    rate_limit: int = 0  # queries per second per resolver; 0 = unlimited

    # Part 7: sort output
    sort_by: str = "score"  # score (default), alpha, ip, technique

    # Part 7: opsec mode
    opsec_mode: bool = False

    # Part 8: resolver refresh
    refresh_resolvers: bool = False
    resolvers_file: str = ""

    # Part 7: resume capability
    resume: bool = False
    resume_file: str = ""

    # Part 7: wordlist cleaning
    skip_clean: bool = False

    # Part 7: permutation wordlist
    permutation_wordlist: str = ""

    # Part 7: annotate mode
    annotate: bool = False

    # Part 7: HTTP probe
    http_timeout: int = 5

    # Part 7: resolver health check
    resolver_health_check: bool = True

    # Part 10: saturation detection
    saturation_threshold: float = 0.1  # subs/min below which we warn

    # Part 10: notes storage
    notes: dict = field(default_factory=dict)  # subdomain -> note string