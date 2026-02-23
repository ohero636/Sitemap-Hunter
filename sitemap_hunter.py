#!/usr/bin/env python3
"""
sitemap_hunter.py
Multi-tiered sitemap reconnaissance tool.
Escalates from passive OSINT to active dictionary fuzzing to minimize forensic footprint.
"""
import sys
import asyncio
import argparse
import logging
from urllib.parse import urlparse, urljoin
from pathlib import Path

# Third-party
import requests
import aiohttp
from bs4 import BeautifulSoup

# Suppress SSL validation warnings for defective targets
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

class SitemapHunter:
    def __init__(self, target_url: str, wordlist_path: str = None):
        self.original_url = self._normalize_url(target_url)
        parsed = urlparse(self.original_url)
        self.scheme_netloc = f"{parsed.scheme}://{parsed.netloc}"
        self.domain = parsed.netloc
        
        # Build traversal paths (e.g., /de/giveaway/ -> /de/ -> /)
        self.paths = self._build_traversal_paths(parsed.path)
        
        self.wordlist_path = wordlist_path
        self.sitemaps = set()
        
        # Hardcoded fallback dictionary if all passive methods fail and no external wordlist is provided
        self.fallback_dictionary = [
            "/sitemap.xml", "/sitemap_index.xml", "/sitemap.txt", "/sitemap.xml.gz", 
            "/sitemaps.xml", "/sitemap/sitemap.xml", "/sitemap/index.xml", 
            "/post-sitemap.xml", "/page-sitemap.xml", "/category-sitemap.xml", 
            "/server-sitemap.xml"
        ]

    @staticmethod
    def _normalize_url(url: str) -> str:
        """Forces HTTPS if omitted."""
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "https://" + url
        
        # We don't strip the path here anymore, we preserve it for traversal
        return url

    @staticmethod
    def _build_traversal_paths(path: str) -> list[str]:
        """Splits a path like /a/b/c/ into ['/a/b/c/', '/a/b/', '/a/', '/']"""
        segments = [s for s in path.split('/') if s]
        paths = []
        for i in range(len(segments), 0, -1):
            paths.append('/' + '/'.join(segments[:i]) + '/')
        paths.append('/')
        # Return unique paths preserving order (deepest to root)
        seen = set()
        return [p for p in paths if not (p in seen or seen.add(p))]

    def _verify_sitemap_payload(self, url: str, content: str) -> bool:
        """Naively validates that the HTTP 200 actually contains XML sitemap signatures (filters wildcards)."""
        content_lower = content.lower()
        if "<?xml" in content_lower or "<urlset" in content_lower or "<sitemapindex" in content_lower:
            self.sitemaps.add(url)
            return True
        return False

    def tier1_standard_probe(self, base_url: str) -> bool:
        """
        Active, precise check of robots.txt and standard roots per directory level.
        """
        logging.info(f"\n--- Tier 1: Standard Probes (Active) on {base_url} ---")
        robots_url = urljoin(base_url, "robots.txt")
        
        try:
            logging.info(f"[*] Parsing {robots_url}...")
            # verify=False is critical: many targets have busted certs but valid data.
            res = requests.get(robots_url, timeout=10, verify=False)
            if res.status_code == 200:
                for line in res.text.splitlines():
                    if line.lower().startswith("sitemap:"):
                        sitemap_path = line.split(":", 1)[1].strip()
                        self.sitemaps.add(sitemap_path)
                        logging.info(f"[+] Found via robots.txt: {sitemap_path}")
            else:
                logging.info("[-] robots.txt unavailable or HTTP non-200.")
        except requests.RequestException as e:
            logging.error(f"[-] robots.txt request failed: {e}")

        # Quick check of top 2 roots if robots.txt is empty
        if not self.sitemaps:
            logging.info(f"[*] Checking standard roots on {base_url}...")
            # Ensure we don't duplicate slashes during urljoin
            for root in ["sitemap.xml", "sitemap_index.xml"]:
                target = urljoin(base_url, root)
                try:
                    res = requests.get(target, timeout=10, verify=False)
                    if res.status_code == 200 and self._verify_sitemap_payload(target, res.text):
                         logging.info(f"[+] Found active root sitemap: {target}")
                except requests.RequestException:
                    pass

        return len(self.sitemaps) > 0

    def tier2_passive_osint(self) -> bool:
        """
        Queries Wayback Machine CDX API to find historical sitemaps without touching the target.
        """
        logging.info("\n--- Tier 2: Wayback CDX API Analytics (Passive OSINT) ---")
        # Querying the entire domain for MIME types typical of sitemaps or URLs containing the word
        cdx_url = f"http://web.archive.org/cdx/search/cdx?url={self.domain}/*&filter=mimetype:text/xml&collapse=urlkey&output=json&limit=1000"
        
        try:
            logging.info(f"[*] Querying CDX API for {self.domain} (Timeout: 10s)...")
            res = requests.get(cdx_url, timeout=10)
            
            if res.status_code == 200:
                data = res.json()
                if len(data) > 1: # Index 0 is just headers
                    logging.info(f"[*] Parsing {len(data)-1} historical XML records...")
                    for row in data[1:]:
                        # row format: [urlkey, timestamp, original, mimetype, statuscode, digest, length]
                        original_url = row[2]
                        if "sitemap" in original_url.lower():
                            logging.info(f"[+] Found historical route via CDX: {original_url}")
                            # Add and actively verify it still exists
                            try:
                                v_res = requests.get(original_url, timeout=5, verify=False)
                                if v_res.status_code == 200 and self._verify_sitemap_payload(original_url, v_res.text):
                                    logging.info(f"    -> [VERIFIED] Route is still active.")
                            except requests.RequestException:
                                logging.info(f"    -> [DEAD] Route no longer active on host.")
            else:
                logging.info(f"[-] CDX API returned non-200 status: {res.status_code}")
                
        except requests.exceptions.Timeout:
            logging.warning("[-] CDX API request timed out. Moving to next tier.")
        except Exception as e:
            logging.error(f"[-] CDX API failure: {e}")

        return len(self.sitemaps) > 0

    def tier3_homepage_scrape(self, base_url: str) -> bool:
        """
        Active, low-noise fetch of the specific path to scrape HTML for explicit links.
        """
        logging.info(f"\n--- Tier 3: HTML Heuristics (Active, Low Noise) on {base_url} ---")
        try:
            logging.info(f"[*] Scraping {base_url} HTML...")
            res = requests.get(base_url, timeout=10, verify=False)
            if res.status_code == 200:
                soup = BeautifulSoup(res.text, "html.parser")
                
                # Check <link rel="sitemap" ...>
                for link in soup.find_all("link", rel="sitemap"):
                     href = link.get("href")
                     if href:
                         target = urljoin(base_url, href)
                         logging.info(f"[+] Found embedded metadata link: {target}")
                         self.sitemaps.add(target)
                         
                # Check raw anchor text hrefs
                for a in soup.find_all("a", href=True):
                    href = a.get("href")
                    if "sitemap.xml" in href.lower():
                        target = urljoin(base_url, href)
                        logging.info(f"[+] Found embedded anchor: {target}")
                        self.sitemaps.add(target)
                        
        except requests.RequestException as e:
            logging.error(f"[-] HTML scrape failed: {e}")

        return len(self.sitemaps) > 0

    async def _dictionary_worker(self, session: aiohttp.ClientSession, url: str):
        """Async worker to fetch and validate single URL."""
        try:
            async with session.get(url, allow_redirects=True, timeout=10) as response:
                if response.status == 200:
                    text = await response.text()
                    if self._verify_sitemap_payload(url, text):
                        logging.info(f"[+] Fuzz hit: {url}")
        except Exception as e:
            logging.debug(f"Failed to fetch {url}: {e}")

    async def _fuzz_target(self, base_url: str, wordlist: list[str]):
        """Asynchronous fuzzing engine."""
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(
            connector=connector,
            headers={"User-Agent": "Mozilla/5.0 SitemapHunter/2.0"}
        ) as session:
            # Strip leading slash from wordlist paths so urljoin appends them to the depth root
            tasks = [
                self._dictionary_worker(session, urljoin(base_url, path.lstrip('/'))) 
                for path in wordlist
            ]
            await asyncio.gather(*tasks)

    def tier4_aggressive_fuzz(self, base_url: str):
        """
        Active, high-noise asynchronous dictionary attack per directory level. Final fallback.
        """
        logging.info(f"\n--- Tier 4: Aggressive Fuzzing (Active, High Noise) on {base_url} ---")
        wordlist = self.fallback_dictionary
        
        # Resolve script directory to find the default wordlist
        script_dir = Path(__file__).parent
        default_wordlist = script_dir / "sitemaps_wordlist.txt"

        # Load external dictionary if provided
        if self.wordlist_path:
            path = Path(self.wordlist_path)
            if path.is_file():
                with path.open("r") as f:
                    custom_list = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                    if custom_list:
                        wordlist = custom_list
                        logging.info(f"[*] Loaded {len(wordlist)} paths from custom dictionary: {self.wordlist_path}")
            else:
                logging.warning(f"[!] Custom wordlist {self.wordlist_path} not found. Attempting default built-in file.")
                self.wordlist_path = None
        
        # Load local sitemaps_wordlist.txt if no custom flag or custom missing
        if not self.wordlist_path:
             if default_wordlist.is_file():
                 with default_wordlist.open("r") as f:
                     local_list = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                     if local_list:
                         wordlist = local_list
                         logging.info(f"[*] Auto-loaded {len(wordlist)} paths from local dictionary: {default_wordlist.name}")
             else:
                 logging.warning("[!] Local sitemaps_wordlist.txt missing. Falling back to 11 hardcoded baseline paths.")

        logging.info(f"[*] Splashing {len(wordlist)} routes concurrently...")
        asyncio.run(self._fuzz_target(base_url, wordlist))

    def hunt(self):
        """Orchestrates the escalation tiers across path depths."""
        logging.info(f"Initiating hunt for target: {self.original_url}")
        logging.info(f"Traversal Path Vector: {' -> '.join(self.paths)}")
        
        # Tier 2 (CDX API) is domain-wide. Execute once.
        if self.tier2_passive_osint():
            return self._report(success=True)

        for path in self.paths:
            current_base = urljoin(self.scheme_netloc, path)
            logging.info(f"\n\n=========================================")
            logging.info(f"[*] Executing target depth: {current_base}")
            logging.info(f"=========================================")
            
            if self.tier1_standard_probe(current_base):
                return self._report(success=True)
                
            if self.tier3_homepage_scrape(current_base):
                return self._report(success=True)
                
            self.tier4_aggressive_fuzz(current_base)
            
            if self.sitemaps:
                return self._report(success=True)
                
            logging.info(f"[-] Depth {current_base} exhausted. Traversing upwards...")

        return self._report(success=len(self.sitemaps) > 0)

    def _report(self, success: bool):
        if success:
            print("\n=========================================")
            print("[+] Confirmed Sitemaps:")
            for sm in self.sitemaps:
                print(f"  - {sm}")
            print("=========================================")
            sys.exit(0)
        else:
            print("\n[-] Sitemaps not exposed. Targets are deeply obfuscated or unutilized.")
            sys.exit(1)

class SmartParser(argparse.ArgumentParser):
    def error(self, message):
        print(f"\n[!] CLI ERROR: {message}")
        print("[?] Did you consume the target URL with the wordlist flag?")
        print("    If you use '-w', you MUST provide the path to the wordlist immediately after it.")
        print("\n[+] PROPER USAGE:")
        print("    Standard: python sitemap_hunter.py example.com")
        print("    Advanced: python sitemap_hunter.py example.com -w /path/to/wordlist.txt\n")
        sys.exit(2)

def main():
    parser = SmartParser(description="Multi-tiered Sitemap Reconnaissance.")
    parser.add_argument("url", help="Target URL (e.g., example.com)")
    parser.add_argument("-w", "--wordlist", help="Path to custom sitemap dictionary (e.g., SecLists). Strongly recommended.")
    
    # Catch cases where no arguments are passed at all
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
        
    args = parser.parse_args()

    hunter = SitemapHunter(args.url, args.wordlist)
    hunter.hunt()

if __name__ == "__main__":
    main()
