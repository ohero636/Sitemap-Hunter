# NeroHunt Sitemap Hunter

A Python script designed for professional-grade sitemap reconnaissance. It utilizes a four-tier escalation architecture combined with automatic path traversal to maximize discovery while minimizing its forensic footprint.

Wrapped in a Nix shell to guarantee reproducible dependency isolation.

## Core Features

### 1. The Escalation Architecture

1.  **Tier 1: Standard Probes (Active, Low Noise)**
    *   Parses `robots.txt` for explicit `Sitemap:` directives.
    *   Checks the most common root locations (`/sitemap.xml`, `/sitemap_index.xml`).
2.  **Tier 2: Wayback Analytics (Passive OSINT, Zero Noise)**
    *   Queries the Wayback Machine CDX API (`http://web.archive.org/cdx/search/cdx`) for historical sitemap paths associated with the domain.
    *   Actively verifies if found historical paths are still "live" on the target server.
    *   *Executes exactly once per domain.*
3.  **Tier 3: Homepage/Index Heuristics (Active, Low Noise)**
    *   Scrapes raw HTML for explicit metadata links (`<link rel="sitemap" ...>`) or hardcoded anchor tags pointing to sitemap-like structures.
4.  **Tier 4: Aggressive Fuzzing (Active, High Noise)**
    *   *Only executed if Tiers 1-3 fail for the current path.*
    *   Unleashes a highly concurrent, asynchronous dictionary attack to brute-force the sitemap location.

### 2. Upward Path Traversal

If you supply a deep URL route (e.g., `https://ld.iobit.com/de/giveaway/`), the tool automatically deconstructs the path into a traversal vector:
1.  `https://ld.iobit.com/de/giveaway/`
2.  `https://ld.iobit.com/de/`
3.  `https://ld.iobit.com/`

It executes the escalation tiers (1, 3, and 4) *in sequence at every depth level*, working its way upwards to the root domain until a sitemap is discovered or the domain is exhausted.

### 3. Wordlist Defaults & Resiliency

*   **Auto-Loaded Taxonomy**: The script ships with `sitemaps_wordlist.txt`, a heavily researched taxonomy containing 90+ advanced sitemap routes (covering Nuxt/Next.js API routes, WordPress plugins, E-Commerce platforms, and localized endpoints). This list is loaded **automatically** for Tier 4 if you don't override it. 
*   **SSL Bypass**: Standard intelligence gathering fails against targets with expired, self-signed, or otherwise defective SSL certificates. This tool forcefully disables SSL certificate verification (`verify=False` in `requests`, custom `TCPConnector` in `aiohttp`) and suppresses the resulting `urllib3` spam.
*   **Wildcard 404 Filtering**: A naive script will flag a 200 OK as a hit, completely failing against SPAs or misconfigured servers that return 200 OK for *all* nonexistent routes. This script actively inspects the response payload for XML sitemap signatures (`<?xml`, `<urlset`, `<sitemapindex`) to filter false positives.
*   **CDX Rate Limiting Mitigation**: The Wayback Machine CDX API frequently returns HTTP 429 (Too Many Requests). The script is configured with a hard 10-second timeout and elegant failure handling; if you are throttled, it seamlessly moves to the active tiers without crashing.

## Usage

### 1. Enter the Environment
Ensure you have the Nix package manager installed.
```bash
nix-shell
```

### 2. Execute the Hunt

**Standard Execution (Uses built-in 90+ path taxonomy)**
```bash
python sitemap_hunter.py example.com
```

**Deep Path Target (Triggers Traversal Engine)**
```bash
python sitemap_hunter.py https://ld.iobit.com/de/giveaway/
```

**Custom Payload (Overrides default taxonomy)**
```bash
python sitemap_hunter.py example.com -w /path/to/custom/massive_wordlist.txt
```
