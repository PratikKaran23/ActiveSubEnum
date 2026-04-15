# Credits and Acknowledgments

This tool uses community wordlists built by researchers who spent years doing real
reconnaissance on bug bounty programs. Their work makes this tool possible.

---

## Wordlist Authors

### Jason Haddix (@jhaddix)
- **Source:** `all.txt` — https://gist.github.com/jhaddix
- **Use:** `jhaddix-all` in wordlist manager
- Jason compiled this list from multiple sources and years of real bug bounty recon.
  It is the de facto standard for subdomain enumeration wordlists.

### Assetnote (Shubham Shah + team)
- **Sources:**
  - `best-dns-wordlist.txt` — https://wordlists.assetnote.io
  - `2m-subdomains.txt`
  - `commonspeak2` — https://github.com/assetnote/commonspeak2-wordlists
- **Use:** `assetnote-manual`, `assetnote-2m`, `commonspeak2`
- Assetnote builds wordlists from real internet data — statistically derived from
  subdomains they observed across millions of domains.

### Daniel Miessler (@danielmiessler) + SecLists Community
- **Source:** https://github.com/danielmiessler/SecLists
- **Use:** `seclists-dns-jhaddix`, `seclists-subdomains-top1m`, `seclists-top5k`
- SecLists is the community's comprehensive security testing wordlist repository.
  The DNS section is widely used across the industry.

### Trickest (trickest.io)
- **Source:** https://github.com/trickest/inventory
- **Use:** `trickest-inventory`
- Built from continuous recon across HackerOne and Bugcrowd programs.
  Contains actual subdomains seen on real bug bounty targets.

### six2dez (@six2dez)
- **Source:** OneListForAll — https://github.com/six2dez/OneListForAll
- **Use:** `six2dez-onelistforall`
- Built by a top-ranked Bugcrowd hunter from years of actual recon experience,
  not just internet crawl data.

### n0kovo (@n0kovo)
- **Source:** https://github.com/n0kovo/n0kovo_subdomains
- **Use:** `n0kovo-subdomains`
- Community-compiled, cleaned, and deduplicated subdomain wordlist.

### infosec-au (altdns project)
- **Source:** https://github.com/infosec-au/altdns
- **Use:** `altdns-words` (permutation engine source only)
- Originally designed for subdomain permutation, these words are the prefixes
  and suffixes that appear in real subdomain mutations.

### RSnake / McAfee (fierce tool)
- **Source:** Part of SecLists
- **Use:** `seclists-fierce`
- Classic Fierce tool wordlist — small but time-tested.

### bitquark
- **Source:** Part of SecLists
- **Use:** `seclists-bitquark`
- Statistically ranked by actual frequency of occurrence on the internet.

---

## Legal Notes

- These wordlists are **community resources** maintained by their respective authors.
- This tool does not claim ownership of any wordlist.
- If you publish research or writeups using findings from this tool,
  **credit the original wordlist authors** where applicable.
- All wordlists are used under their respective licenses (MIT, Apache 2.0, etc.)
  as specified by their original repositories.

---

## Special Thanks

- **Jason Haddix** — for pioneering modern subdomain enumeration methodology
- **Assetnote** — for open-sourcing their statistically-derived wordlists
- **Trickest** — for continuous community recon data sharing
- **The Bug Bounty Community** — for collectively building and maintaining
  the recon methodology that makes tools like this possible
