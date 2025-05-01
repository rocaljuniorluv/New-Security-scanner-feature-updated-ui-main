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
import json
import sys
import string
from urllib.parse import quote_plus
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
from tqdm import tqdm
import socket
from typing import List, Dict, Any, Optional

# User-Agent rotation to avoid blocking
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0"
]

class GoogleDorker:
    def __init__(self, domain: str, proxy: Optional[str] = None, delay: int = 2, max_results: int = 30):
        self.domain = domain
        self.proxy = proxy
        self.delay = delay
        self.max_results = max_results
        self.results = []
        
    def get_random_user_agent(self) -> str:
        return random.choice(USER_AGENTS)
    
    def search(self, dork: str) -> List[Dict[str, str]]:
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
    
    def run_dorks(self, dorks: List[str]) -> List[Dict[str, str]]:
        """Run multiple Google dork queries"""
        for dork in tqdm(dorks, desc="Running Google dorks"):
            results = self.search(dork)
            if results:
                self.results.extend(results)
            time.sleep(self.delay)  # Delay between requests to avoid blocking
        
        return self.results


class TypoSquatter:
    def __init__(self, domain: str, tld_list: Optional[List[str]] = None, check_dns: bool = True, threads: int = 10):
        self.domain = domain
        self.base_name, self.original_tld = self._split_domain(domain)
        self.tld_list = tld_list or ['.com', '.net', '.org', '.io', '.co', '.info', '.biz']
        self.check_dns = check_dns
        self.threads = threads
        self.variations = []
        self.active_domains = []
    
    def _split_domain(self, domain: str) -> tuple:
        """Split domain into base name and TLD"""
        parts = domain.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[:-1]), f".{parts[-1]}"
        return domain, ""
    
    def generate_typos(self) -> List[str]:
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
    
    def check_domain_availability(self, domain: str) -> Dict[str, str]:
        """Check if domain exists by performing DNS lookup"""
        try:
            socket.gethostbyname(domain)
            return {"domain": domain, "status": "Registered", "risk": "High"}
        except socket.gaierror:
            return {"domain": domain, "status": "Available", "risk": "Low"}
    
    def scan(self) -> List[Dict[str, str]]:
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