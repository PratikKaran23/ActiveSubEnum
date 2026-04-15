"""
techniques/t02_permutation.py — Permutation Engine

TECHNIQUE: Permutation / Mutation Engine
TECHNIQUE_ID: t02
STEALTH: MEDIUM
HUNTER NOTE: Permutation finds subdomains that no wordlist can — because
  they're mutations of names YOU already found. If you found api-v1, permutation
  tries api-v2, v3, v4. If you found us-east-api, it tries eu-west-api.
  Must run AFTER brute force (needs seeds). Run it twice — once after brute,
  once after recursive. Feed it the altdns wordlist for best results.

References:
  - https://www.yeswehack.com/learn-bug-bounty/subdomain-enumeration-expand-attack-surface
  - gotator tool by Trickest
  - altdns wordlist: https://github.com/infosec-au/altdns
"""

import re
from typing import List, Set

from .base import BaseTechnique

PERMUTATION_PREFIXES = [
    "dev", "staging", "stage", "prod", "test", "qa", "uat",
    "api", "v1", "v2", "v3", "old", "new", "beta", "alpha",
    "internal", "corp", "admin", "secure", "backup", "bak",
    "eu", "us", "uk", "ap", "sg", "de", "fr", "au", "in", "jp",
    "east", "west", "north", "south", "central",
    "01", "02", "03", "1", "2", "3", "2024", "2025",
    "pre", "post", "mobile", "web", "app", "service", "client",
]

PERMUTATION_SEPARATORS = ["-", ".", ""]


class PermutationTechnique(BaseTechnique):
    name = "Permutation Engine"
    aliases = ["mutation", "permutation", "alteration", "perm", "02"]
    description = "Generate mutations from known subdomains using prefixes, suffixes, and number patterns"
    stealth_level = "medium"
    technique_id = "t02"

    def _generate_mutations(self, known: Set[str], domain: str,
                            prefixes=None, separators=None) -> Set[str]:
        """Generate permutations from known subdomain seeds."""
        mutations: Set[str] = set()
        prefixes = prefixes or PERMUTATION_PREFIXES
        separators = separators or PERMUTATION_SEPARATORS

        for sub in known:
            # Strip domain from subdomain (first occurrence)
            part = sub.replace(f".{domain}", "")
            # Skip if nothing was stripped (sub == domain) or invalid
            if not part or part == domain:
                continue

            # Basic mutations: prefix + sep + part
            for pfx in prefixes:
                for sep in separators:
                    mutations.add(f"{pfx}{sep}{part}")
                    mutations.add(f"{part}{sep}{pfx}")

            # Number mutations: api-v1 → api-v2, api-v01 → api-v02
            for num_match in re.finditer(r"\d+", part):
                num = num_match.group()
                for delta in [-1, 1, 2]:
                    new = str(int(num) + delta)
                    if int(new) >= 0:
                        new_part = part.replace(num, new, 1)
                        mutations.add(new_part)
                        for pfx in ["v", ""]:
                            mutations.add(f"{pfx}{new_part}")

            # Region mapping mutations
            region_map = {
                "us": ["eu", "uk", "ap", "sg", "de", "fr", "au", "in", "jp", "me"],
                "eu": ["us", "uk", "ap", "sg", "de", "fr", "au", "in", "jp", "me"],
                "east": ["west", "north", "south", "central"],
                "west": ["east", "north", "south", "central"],
                "us-east": ["us-west", "eu-west", "eu-central", "ap-southeast", "ap-northeast"],
                "us-west": ["us-east", "eu-west", "eu-central", "ap-southeast", "ap-northeast"],
            }
            for region, alternatives in region_map.items():
                if region in part:
                    for alt in alternatives:
                        for sep in ["-", "."]:
                            mutations.add(part.replace(region, alt))
                            mutations.add(part.replace(region, f"{region}{sep}{alt}"))

        # Remove already-known subdomains
        known_full = known  # original input set
        return {m for m in mutations if f"{m}.{domain}" not in known_full}

    def run(self, cfg, pool, wc, results, **kwargs) -> Set[str]:
        from rich.console import Console

        self.cfg = cfg
        self.pool = pool
        self.wc = wc
        self.results = results
        console = Console()

        known = kwargs.get("known", set())
        if not known:
            console.print(
                f"\n[bold blue][02][/bold blue] Permutation Engine — no seeds yet, skipping"
            )
            return set()

        mutations = self._generate_mutations(known, cfg.domain,
                                              prefixes=kwargs.get("prefixes"),
                                              separators=kwargs.get("separators"))
        console.print(
            f"\n[bold blue][02][/bold blue] Permutation Engine — "
            f"[cyan]{len(mutations):,}[/cyan] mutations from {len(known)} seeds"
        )

        if not mutations:
            return set()

        # Delegate to brute force for resolution
        from .t01_bruteforce import BruteForceTechnique
        bf = BruteForceTechnique()
        return bf.run(cfg, pool, wc, results, wordlist=list(mutations), label="02")