# ActiveSubEnum v1.0
### Active Subdomain Enumeration — Beyond the Standard Playbook

A single-tool active subdomain enumeration framework combining
12 active techniques + a 7-stage false positive elimination pipeline.

**Proven result:** tube8.com — 14,675 raw DNS results → 7 confirmed
real targets (99.95% false positive elimination).

---

## Why This Tool Exists

Most subdomain enumeration tools stop at DNS resolution.
They dump everything that resolves and leave the hunter
to figure out what's real. On large targets with CDN wildcards,
that means 14,000+ results where 14,000 are noise.

This tool adds a post-enumeration validation pipeline that:
- Eliminates CDN wildcard catch-alls
- Removes ISP DNS intercept results
- Port-scans to confirm real services
- Checks content uniqueness (not just DNS resolution)
- Validates TLS certificates
- Classifies by ASN ownership
- Scores by interestingness

---

## Install

```bash
git clone https://github.com/YOUR_USERNAME/ActiveSubEnum.git
cd ActiveSubEnum
pip install -r requirements.txt
```

---

## Quick Start

```bash
# Deep scan — standard profile (works on any connection)
python3 activesubenum.py \
  -d target.com \
  -w wordlists/external/jhaddix-all.txt \
  --techniques all \
  --profile normal \
  --refresh-resolvers \
  --fast-validate \
  -o results/target.com-deep.json \
  --validate-output results/target.com/

# Home broadband / shared VPS — light profile
python3 activesubenum.py -d target.com -w wordlist.txt --profile light --techniques all

# Dedicated server — fast profile
python3 activesubenum.py -d target.com -w wordlist.txt --profile fast --techniques all

# Pro hunter — maximum throughput
python3 activesubenum.py -d target.com -w wordlist.txt --profile hunter --techniques all --include-heavy

# Resume interrupted scan
python3 activesubenum.py -d target.com -w wordlist.txt --resume

# Validate existing results only
python3 activesubenum.py --validate-only --input results.json -d target.com
```

---

## Passive Intelligence (Phase 0 — Always Runs First)

crt.sh CT logs run automatically on every scan, at no cost.
ArgosDNS is available when you provide an export file or API key.

### Option A — ArgosDNS Export File (BEST — zero API requests)
1. Go to argosdns.io → Subdomain Search → search your target
2. Click Export → Download the file
3. Pass it to the tool:

```bash
python3 activesubenum.py \
  -d target.com \
  --passive-list target_export.txt \
  --profile normal \
  --fast-validate \
  -o results/target.json \
  --validate-output results/target/
```

### Option B — ArgosDNS API (costs requests — use sparingly)
```bash
python3 activesubenum.py \
  -d target.com \
  --argos-key YOUR_KEY \
  --argos-max-requests 5 \
  --profile normal \
  --fast-validate \
  -o results/target.json
```

### Option C — crt.sh only (always free, always runs)
```bash
python3 activesubenum.py \
  -d target.com \
  --profile normal \
  --fast-validate \
  -o results/target.json
```

---

## Connection Profiles

| Profile  | Threads | Rate   | Jitter | Best For |
|----------|---------|--------|--------|----------|
| `--profile light`  | 20  | 100 q/s | 200ms | Home broadband, shared VPS |
| `--profile normal` | 50 | 300 q/s | 100ms | Good VPS (default) |
| `--profile fast`   | 100| 600 q/s | 50ms  | Dedicated server |
| `--profile hunter` | 200| 1000 q/s| 0ms   | High-end datacenter VPS |

By default (`--techniques all`) runs **light + medium techniques only** (DNS-based).
Heavy HTTP techniques (vhost/cors/tlssni) are skipped to reduce network load.
Add `--include-heavy` or `--techniques all+heavy` to enable them.

---

## 12 Active Techniques

| # | Technique | What It Finds |
|---|-----------|---------------|
| 01 | DNS Brute Force | Standard resolution with wildcard filtering |
| 02 | Permutation Engine | Mutations from discovered subdomains |
| 03 | Zone Transfer | AXFR/IXFR against all nameservers |
| 04 | NSEC Walking | Provably complete enumeration via DNSSEC chain |
| 05 | Cache Snooping | Actively used subdomains via non-recursive queries |
| 06 | IPv6 AAAA | IPv6-only services (missed by 95% of hunters) |
| 07 | TLS SNI Probing | Services with no DNS entry found via IP ranges |
| 08 | CAA Pivoting | Subdomain existence confirmed without A records |
| 09 | CORS Reflection | HTTP-layer trust mining via Origin headers |
| 10 | DNS CHAOS | Version/hostname leaks from nameservers |
| 11 | VHost Fuzzing | Virtual hosts invisible to DNS |
| 12 | Recursive Enum | Sub-subdomains from discovered seeds |

---

## 7-Stage Validation Pipeline

```
Raw DNS results
      ↓
[1] Wildcard elimination    — removes CDN catch-alls
      ↓
[2] Sinkhole/ISP filter     — removes 0.0.0.0 + ISP intercepts
      ↓
[3] Port scan               — confirms real service running
      ↓
[4] Content uniqueness      — removes generic CDN pages
      ↓
[5] TLS validation          — flags expired/self-signed certs
      ↓
[6] HTTP intelligence       — WAF detection, headers, status
      ↓
[7] ASN classification      — OWNED-INFRA vs CDN vs THIRD-PARTY
      ↓
Confirmed real targets
```

---

## Output Files

| File | Contents |
|------|----------|
| `*.CONFIRMED-REAL.txt` | Passed all 7 validation stages |
| `*.HIGH-PRIORITY.txt` | Score >= 60 — hunt these first |
| `*.OWNED-INFRA.txt` | On target's own ASN/netblock |
| `*.NO-WAF.txt` | Live, no WAF detected |
| `*.TAKEOVER-CANDIDATES.txt` | Dangling CNAME / unclaimed services |
| `*.EXPIRED-TLS.txt` | Forgotten services with expired certs |
| `*.DEAD-DNS.txt` | DNS resolves but no open ports |
| `*.CDN-WILDCARD.txt` | Filtered CDN noise (for reference) |
| `*.FULL-REPORT.json` | Everything with full metadata |

---

## Wordlists

Download the recommended wordlists:

```bash
python3 tools/wordlist_manager.py download --tier 1
```

This fetches:
- **jhaddix-all.txt** (~2M words) — Jason Haddix's gold standard
- **assetnote-subdomains** (~9M words) — statistically derived from real internet data
- **trickest-inventory** (~6M words) — from real bug bounty program recon

---

## CLI Flags

```
-d, --domain          Target domain (required)
-w, --wordlist        Path to wordlist
-t, --threads         Thread count (default: 100)
--timeout             DNS timeout in seconds (default: 3)
--techniques          Comma-separated or 'all'
--depth               Recursive enumeration depth (default: 2)
--max-rate            Max queries per second (default: 300)
--jitter              Random delay per query in ms (default: 100)
--profile             Connection preset: light/normal/fast/hunter
--include-heavy       Include HTTP techniques (vhost/cors/tlssni) with --techniques all
--ip-ranges           IP ranges for TLS SNI probing
--refresh-resolvers   Force fresh resolver fetch
--resume              Resume from checkpoint
--skip-validate       Skip validation pipeline
--fast-validate       Skip content fingerprinting (faster)
--validate-only       Run validation on existing JSON
--input               Input JSON for --validate-only
--validate-output     Output directory for validation files
-o, --output          Output file (.json or .txt)
```

---

## Legal

For authorized security testing only.
Always obtain written permission before scanning any domain.

---

## Credits

Wordlists by: Jason Haddix, Assetnote, Trickest, Daniel Miessler,
six2dez, n0kovo, and the bug bounty community.