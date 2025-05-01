#!/usr/bin/env python3
"""
Google Dorking and Typosquatting Scanner
A security tool module for identifying potential security exposures through Google dork queries
and detecting typosquatted domains that might be used for phishing.
"""

import requests
import time
import re
import random
import argparse
import json
import sys
import string
from urllib.parse import quote_plus
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
from tqdm import tqdm

# User-Agent rotation to avoid blocking
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0"
]

class GoogleDorker:
    def __init__(self, domain, proxy=None, delay=2, max_results=30):
        self.domain = domain
        self.proxy = proxy
        self.delay = delay
        self.max_results = max_results
        self.results = []
        
    def get_random_user_agent(self):
        return random.choice(USER_AGENTS)
    
    def search(self, dork):
        """Execute a Google dork search"""
        query = f"{dork} site:{self.domain}"
        encoded_query = quote_plus(query)
        url = f"https://www.google.com/search?q={encoded_query}&num=100"
        
        headers = {
            "User-Agent": self.get_random_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml",
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": "https://www.google.com/"
        }
        
        proxies = {}
        if self.proxy:
            proxies = {
                "http": self.proxy,
                "https": self.proxy
            }
        
        try:
            response = requests.get(url, headers=headers, proxies=proxies, timeout=10)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'html.parser')
            search_results = soup.find_all('div', class_='g')
            
            dork_results = []
            for result in search_results[:self.max_results]:
                link_element = result.find('a')
                if link_element and 'href' in link_element.attrs:
                    href = link_element['href']
                    if href.startswith('/url?q='):
                        href = href.split('/url?q=')[1].split('&')[0]
                    title_element = result.find('h3')
                    title = title_element.text if title_element else "No title"
                    dork_results.append({
                        "title": title,
                        "url": href,
                        "dork": dork
                    })
            
            return dork_results
            
        except requests.exceptions.RequestException as e:
            print(f"Error performing dork search '{dork}': {e}")
            return []
    
    def run_dorks(self, dorks):
        """Run multiple Google dork queries"""
        for dork in tqdm(dorks, desc="Running Google dorks"):
            results = self.search(dork)
            if results:
                self.results.extend(results)
            time.sleep(self.delay)  # Delay between requests to avoid blocking
        
        return self.results


class TypoSquatter:
    def __init__(self, domain, tld_list=None, check_dns=True, threads=10):
        self.domain = domain
        self.base_name, self.original_tld = self._split_domain(domain)
        self.tld_list = tld_list or ['.com', '.net', '.org', '.io', '.co', '.info', '.biz']
        self.check_dns = check_dns
        self.threads = threads
        self.variations = []
        self.active_domains = []
    
    def _split_domain(self, domain):
        """Split domain into base name and TLD"""
        parts = domain.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[:-1]), f".{parts[-1]}"
        return domain, ""
    
    def generate_typos(self):
        """Generate typosquatting domain variations"""
        name = self.base_name
        variations = []
        
        # 1. Character omission (dropping a letter)
        for i in range(len(name)):
            variations.append(name[:i] + name[i+1:] + self.original_tld)
        
        # 2. Character replacement (wrong key hit)
        for i in range(len(name)):
            for c in "abcdefghijklmnopqrstuvwxyz":
                if c != name[i]:
                    variations.append(name[:i] + c + name[i+1:] + self.original_tld)
        
        # 3. Character insertion (extra letter)
        for i in range(len(name) + 1):
            for c in "abcdefghijklmnopqrstuvwxyz":
                variations.append(name[:i] + c + name[i:] + self.original_tld)
        
        # 4. Adjacent character swapping
        for i in range(len(name) - 1):
            variations.append(name[:i] + name[i+1] + name[i] + name[i+2:] + self.original_tld)
        
        # 5. Double letter typing (doubling a letter)
        for i in range(len(name)):
            variations.append(name[:i] + name[i] + name[i:] + self.original_tld)
        
        # 6. TLD Variation
        for tld in self.tld_list:
            if tld != self.original_tld:
                variations.append(name + tld)
        
        # 7. Homoglyphs (similar looking characters)
        homoglyphs = {
            'a': ['4', '@'],
            'e': ['3'],
            'i': ['1', '!'],
            'l': ['1', 'i'],
            'o': ['0'],
            's': ['5', '$'],
            't': ['7'],
            'g': ['q', '9'],
            'z': ['2']
        }
        
        for i in range(len(name)):
            if name[i].lower() in homoglyphs:
                for replacement in homoglyphs[name[i].lower()]:
                    variations.append(name[:i] + replacement + name[i+1:] + self.original_tld)
        
        # Remove duplicates and original domain
        self.variations = list(set(variations))
        if self.domain in self.variations:
            self.variations.remove(self.domain)
        
        return self.variations
    
    def check_domain_availability(self, domain):
        """Check if domain exists by performing DNS lookup"""
        try:
            import socket
            socket.gethostbyname(domain)
            return {"domain": domain, "status": "Registered", "risk": "High"}
        except socket.gaierror:
            return {"domain": domain, "status": "Available", "risk": "Low"}
    
    def scan(self):
        """Scan for typosquatted domains"""
        self.generate_typos()
        results = []
        
        if self.check_dns:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                results = list(tqdm(
                    executor.map(self.check_domain_availability, self.variations),
                    total=len(self.variations),
                    desc="Checking domain availability"
                ))
            
            # Filter for registered domains
            self.active_domains = [r for r in results if r["status"] == "Registered"]
            return self.active_domains
        else:
            return [{"domain": d, "status": "Unknown", "risk": "Unknown"} for d in self.variations]


# Common Google dorks for security assessment
SECURITY_DORKS = [
    "intext:password filetype:txt",
    "intitle:\"Index of\" password",
    "inurl:config filetype:php",
    "filetype:log username password",
    "inurl:wp-content/uploads/",
    "intitle:\"Apache HTTP Server Test Page\"",
    "intext:\"sql syntax near\" filetype:php",
    "ext:sql intext:username password",
    "inurl:login.php",
    "filetype:env \"DB_PASSWORD\"",
    "ext:xml intext:password",
    "intext:\"powered by\" intext:\"admin password\"",
    "filetype:xls inurl:\"email.xls\"",
    "intitle:\"phpMyAdmin\" intext:\"Welcome to phpMyAdmin\"",
    "inurl:admin inurl:backup intitle:index.of",
    "filetype:bak inurl:wp-config",
    "intitle:\"Index of\" wp-admin",
    "inurl:/proc/self/environ",
    "filetype:inc php",
    "inurl:error_log filetype:log"
]

def save_results(results, output_file):
    """Save scan results to a JSON file"""
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=4)
    print(f"Results saved to {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Google Dorking and Typosquatting Scanner")
    parser.add_argument("-d", "--domain", required=True, help="Target domain to scan")
    parser.add_argument("-o", "--output", default="security_scan_results.json", help="Output JSON file")
    parser.add_argument("-p", "--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--delay", type=int, default=3, help="Delay between requests in seconds")
    parser.add_argument("--max-results", type=int, default=30, help="Maximum results per dork")
    parser.add_argument("--no-dorks", action="store_true", help="Skip Google dorking")
    parser.add_argument("--no-typo", action="store_true", help="Skip typosquatting checks")
    parser.add_argument("--no-dns", action="store_true", help="Skip DNS verification for typosquatting")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads for DNS checks")
    parser.add_argument("--tlds", help="Comma-separated list of TLDs to check")
    parser.add_argument("--custom-dorks", help="File with custom Google dorks, one per line")
    
    args = parser.parse_args()
    
    all_results = {
        "target_domain": args.domain,
        "scan_date": time.strftime("%Y-%m-%d %H:%M:%S"),
        "google_dork_results": [],
        "typosquatting_results": []
    }
    
    # Run Google dorking
    if not args.no_dorks:
        print(f"Starting Google dorking for domain: {args.domain}")
        dorks = SECURITY_DORKS
        
        # Load custom dorks if provided
        if args.custom_dorks:
            try:
                with open(args.custom_dorks, 'r') as f:
                    custom_dorks = [line.strip() for line in f if line.strip()]
                    dorks.extend(custom_dorks)
                    print(f"Loaded {len(custom_dorks)} custom dorks")
            except Exception as e:
                print(f"Error loading custom dorks: {e}")
        
        dorker = GoogleDorker(
            domain=args.domain,
            proxy=args.proxy,
            delay=args.delay,
            max_results=args.max_results
        )
        
        dork_results = dorker.run_dorks(dorks)
        all_results["google_dork_results"] = dork_results
        print(f"Google dorking completed. Found {len(dork_results)} results")
    
    # Run typosquatting scan
    if not args.no_typo:
        print(f"Starting typosquatting scan for domain: {args.domain}")
        tld_list = args.tlds.split(',') if args.tlds else None
        
        typosquatter = TypoSquatter(
            domain=args.domain,
            tld_list=tld_list,
            check_dns=not args.no_dns,
            threads=args.threads
        )
        
        typo_results = typosquatter.scan()
        all_results["typosquatting_results"] = typo_results
        print(f"Typosquatting scan completed. Found {len(typo_results)} potential typosquatted domains")
    
    # Save results
    save_results(all_results, args.output)
    
    # Print summary
    print("\nScan Summary:")
    print(f"- Target Domain: {args.domain}")
    if not args.no_dorks:
        print(f"- Google Dork Results: {len(all_results['google_dork_results'])}")
    if not args.no_typo:
        print(f"- Potential Typosquatted Domains: {len(all_results['typosquatting_results'])}")
    print(f"- Full results saved to: {args.output}")

if __name__ == "__main__":
    main()
