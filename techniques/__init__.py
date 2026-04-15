"""
techniques/__init__.py — Technique Registry and Auto-Discovery

This module provides:
  TECHNIQUE_REGISTRY — Metadata about all available techniques
  TECHNIQUE_CLASSES  — Mapping of technique IDs to their class implementations
  get_technique()     — Retrieve a technique class by name or alias
  list_techniques()   — List all available techniques

Adding a new technique:
  1. Create techniques/tXX_name.py with your implementation
  2. Import it in this file
  3. Add its entry to TECHNIQUE_REGISTRY
  4. Add it to TECHNIQUE_CLASSES
  5. Run: python3 tools/check_technique_overlap.py --name "..." (Part 9)
  6. Add to ALL_TECHNIQUES in activesubenum.py if it should run by default
"""

from typing import Dict, Optional, Type

# ─── Registry: metadata for each technique ────────────────────────────────────

TECHNIQUE_REGISTRY = {
    "t01": {
        "name": "DNS Brute Force",
        "aliases": ["bruteforce", "dns-brute", "wordlist-brute", "brute", "01"],
        "dns_methods": ["A", "CNAME"],
        "interaction": "direct-dns",
        "data_source": "wordlist",
        "key_logic": "resolve_a(word.domain) for word in wordlist",
        "stealth_level": "medium",
        "references": [
            "https://sidxparab.gitbook.io/subdomain-enumeration-guide",
            "https://medium.com/@rajeshsahan507/subdomain-enumeration-like-a-pro",
        ],
    },
    "t02": {
        "name": "Permutation Engine",
        "aliases": ["mutation", "permutation", "alteration", "perm", "02"],
        "dns_methods": ["A", "CNAME"],
        "interaction": "direct-dns",
        "data_source": "existing-subdomains",
        "key_logic": "mutate known subs with prefix/suffix/number patterns",
        "stealth_level": "medium",
        "references": [
            "https://www.yeswehack.com/learn-bug-bounty/subdomain-enumeration-expand-attack-surface",
            "gotator tool, mksub by trickest",
        ],
    },
    "t03": {
        "name": "Zone Transfer",
        "aliases": ["axfr", "ixfr", "zonetransfer", "zone-transfer", "zone", "03"],
        "dns_methods": ["AXFR", "IXFR"],
        "interaction": "direct-dns-authoritative",
        "data_source": "nameserver",
        "key_logic": "dns.zone.from_xfr() against each NS IP",
        "stealth_level": "low",
        "references": [
            "https://0xffsec.com/handbook/information-gathering/subdomain-enumeration/",
        ],
    },
    "t04": {
        "name": "DNSSEC NSEC Walking",
        "aliases": ["nsec-walk", "nsec3", "dnssec-walk", "zone-walk", "nsec", "04"],
        "dns_methods": ["NSEC", "NSEC3", "RRSIG"],
        "interaction": "direct-dns-dnssec",
        "data_source": "dnssec-chain",
        "key_logic": "follow NSEC next-name chain until wrap-around",
        "stealth_level": "medium",
        "references": ["ldns-walk, nsec3map tool"],
    },
    "t05": {
        "name": "DNS Cache Snooping",
        "aliases": ["cache-snoop", "cache-probe", "non-recursive-query", "cachesnoop", "05"],
        "dns_methods": ["A"],
        "interaction": "indirect-resolver",
        "data_source": "resolver-cache",
        "key_logic": "clear RD bit, check if resolver has cached answer",
        "stealth_level": "high",
        "references": ["less-known technique — RD bit must be cleared"],
    },
    "t06": {
        "name": "IPv6 AAAA Enumeration",
        "aliases": ["aaaa", "ipv6-brute", "ipv6-enum", "ipv6", "06"],
        "dns_methods": ["AAAA"],
        "interaction": "direct-dns",
        "data_source": "wordlist",
        "key_logic": "resolve_aaaa(word.domain) for word in wordlist",
        "stealth_level": "medium",
        "references": ["shubhamrooter.medium.com deep subdomain methodology"],
    },
    "t07": {
        "name": "TLS SNI Probing",
        "aliases": ["sni-probe", "tls-probe", "sni-scan", "ip-range-scan", "tlssni", "07"],
        "dns_methods": [],
        "interaction": "direct-tls-ip",
        "data_source": "ip-ranges",
        "key_logic": "TLS ClientHello with SNI, check cert SANs for domain match",
        "stealth_level": "low",
        "references": ["less-known technique — bypass DNS entirely"],
    },
    "t08": {
        "name": "CAA Record Pivoting",
        "aliases": ["caa", "caa-pivot", "caa-probe", "08"],
        "dns_methods": ["CAA", "A"],
        "interaction": "direct-dns",
        "data_source": "wordlist",
        "key_logic": "NoAnswer != NXDOMAIN — confirms existence without A record",
        "stealth_level": "high",
        "references": [
            "less-known technique — DNS confirmation via absence of CAA record",
            "NoAnswer means the name EXISTS in DNS but has no CAA record",
        ],
    },
    "t09": {
        "name": "CORS Origin Reflection",
        "aliases": ["cors", "cors-mining", "cors-reflection", "origin-probe", "09"],
        "dns_methods": [],
        "interaction": "direct-http",
        "data_source": "wordlist + live-endpoints",
        "key_logic": "send Origin: https://word.domain, check ACAO header reflection",
        "stealth_level": "medium",
        "references": ["less-known technique — HTTP-layer subdomain discovery"],
    },
    "t10": {
        "name": "DNS CHAOS Class",
        "aliases": ["chaos", "chaos-txt", "version-bind", "dns-chaos", "10"],
        "dns_methods": ["TXT/CHAOS"],
        "interaction": "direct-dns-chaos-class",
        "data_source": "nameserver",
        "key_logic": "query rdclass=CHAOS for version.bind, hostname.bind",
        "stealth_level": "high",
        "references": ["dig CHAOS TXT version.bind — zero noise recon"],
    },
    "t11": {
        "name": "VHost Fuzzing",
        "aliases": ["vhost", "virtual-host", "host-header-fuzz", "vhost-scan", "11"],
        "dns_methods": [],
        "interaction": "direct-http",
        "data_source": "wordlist + live-ips",
        "key_logic": "Host: word.domain header fuzzing, diff baseline response",
        "stealth_level": "low",
        "references": [
            "https://www.yeswehack.com/learn-bug-bounty/subdomain-enumeration",
            "ffuf vhost mode (-H 'Host: FUZZ.domain.com')",
        ],
    },
    "t12": {
        "name": "Recursive Enumeration",
        "aliases": ["recursive", "sub-subdomain", "deep-brute", "recursive-brute", "12"],
        "dns_methods": ["A"],
        "interaction": "direct-dns",
        "data_source": "existing-subdomains",
        "key_logic": "use found subs as new roots, brute force beneath them",
        "stealth_level": "medium",
        "references": ["shubhamrooter.medium.com, our earlier conversation"],
    },
    "t13": {
        "name": "SPF/TXT Record Mining",
        "aliases": ["spf-mine", "txt-mine", "spf-walk", "spf", "13"],
        "dns_methods": ["TXT", "MX"],
        "interaction": "direct-dns",
        "data_source": "txt-records",
        "key_logic": "parse SPF include: a: mx: directives, extract hostnames",
        "stealth_level": "high",
        "references": [
            "less-known technique — SPF records leak internal hostnames",
            "SPF include: directive reveals third-party mail services",
        ],
    },
    "t14": {
        "name": "DKIM Selector Bruteforce",
        "aliases": ["dkim", "dkim-selector", "domainkey", "14"],
        "dns_methods": ["TXT", "CNAME"],
        "interaction": "direct-dns",
        "data_source": "selector-wordlist",
        "key_logic": "query {selector}._domainkey.{domain} TXT records",
        "stealth_level": "high",
        "references": [
            "less-known technique — reveals mail vendor stack",
            "DKIM selectors: google, sendgrid, amazonses, mailgun",
        ],
    },
    "t15": {
        "name": "SPF Include Chain Walker",
        "aliases": ["spf-chain", "spf-recursive", "spf-tree", "15"],
        "dns_methods": ["TXT"],
        "interaction": "direct-dns",
        "data_source": "spf-includes",
        "key_logic": "recursively follow include: directives across domains",
        "stealth_level": "high",
        "references": [
            "less-known technique — third-party mail service discovery",
            "SPF includes reveal SPF configurations of 3rd party vendors",
        ],
    },
}

# ─── Import all technique classes ──────────────────────────────────────────────

try:
    from .base import BaseTechnique
    from .t01_bruteforce import BruteForceTechnique
    from .t02_permutation import PermutationTechnique
    from .t03_zonetransfer import ZoneTransferTechnique
    from .t04_nsec import NSECTechnique
    from .t05_cachesnoop import CacheSnoopTechnique
    from .t06_ipv6 import IPv6Technique
    from .t07_tlssni import TLSSNITechnique
    from .t08_caa import CAATechnique
    from .t09_cors import CORSTechnique
    from .t10_chaos import CHAOSTechnique
    from .t11_vhost import VHostTechnique
    from .t12_recursive import RecursiveTechnique
    from .t13_TEMPLATE import TemplateTechnique
    from .t14_dkim import DKIMTechnique
    from .t15_spf_chain import SPFChainTechnique

    TECHNIQUE_CLASSES: Dict[str, Type[BaseTechnique]] = {
        "t01": BruteForceTechnique,
        "t02": PermutationTechnique,
        "t03": ZoneTransferTechnique,
        "t04": NSECTechnique,
        "t05": CacheSnoopTechnique,
        "t06": IPv6Technique,
        "t07": TLSSNITechnique,
        "t08": CAATechnique,
        "t09": CORSTechnique,
        "t10": CHAOSTechnique,
        "t11": VHostTechnique,
        "t12": RecursiveTechnique,
        "t13": TemplateTechnique,
        "t14": DKIMTechnique,
        "t15": SPFChainTechnique,
    }

    TECHNIQUE_INSTANCES: Dict[str, BaseTechnique] = {}

except ImportError as e:
    # Graceful degradation — techniques not available
    TECHNIQUE_CLASSES: Dict = {}
    TECHNIQUE_INSTANCES: Dict = {}


# ─── Lookup helpers ───────────────────────────────────────────────────────────

def get_technique(name_or_alias: str) -> Optional[Type["BaseTechnique"]]:
    """Look up a technique class by name or any of its aliases."""
    norm = name_or_alias.lower().strip().replace(" ", "-").replace("_", "-")
    # Check exact match with registry
    for tid, entry in TECHNIQUE_REGISTRY.items():
        if tid.lower() == norm:
            return TECHNIQUE_CLASSES.get(tid)
        if norm in entry["aliases"]:
            return TECHNIQUE_CLASSES.get(tid)
    # Check instance aliases
    for tid, inst in TECHNIQUE_INSTANCES.items():
        if inst.name.lower() == norm:
            return TECHNIQUE_CLASSES.get(tid)
        if norm in inst.aliases:
            return TECHNIQUE_CLASSES.get(tid)
    return None


def list_techniques() -> Dict[str, Dict]:
    """Return all technique metadata."""
    return TECHNIQUE_REGISTRY


__all__ = [
    "TECHNIQUE_REGISTRY",
    "TECHNIQUE_CLASSES",
    "TECHNIQUE_INSTANCES",
    "get_technique",
    "list_techniques",
    "BaseTechnique",
]