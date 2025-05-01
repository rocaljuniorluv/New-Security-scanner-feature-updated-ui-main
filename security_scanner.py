#!/usr/bin/env python3
import os
import dns.resolver
import requests
import socket
import whois
import subprocess
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from typing import List, Dict, Any
import asyncio
from dotenv import load_dotenv
import ssl
from concurrent.futures import ThreadPoolExecutor
import sqlite3
from pathlib import Path
import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from fpdf import FPDF
import tempfile
import logging
import json
import urllib3
import time
from Wappalyzer import Wappalyzer, WebPage
from google_dorking import GoogleDorker, TypoSquatter, SECURITY_DORKS
from traceback_api import TracebackAPI

load_dotenv()
# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(title="Security Scanner API")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Set up templates
templates = Jinja2Templates(directory="templates")

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

class ScanRequest(BaseModel):
    target: Optional[str] = None
    email: Optional[str] = None
    profile: str = "standard"
    scan_subdomains: Optional[bool] = False # Add field for subdomain scan flag
    slack_channel: Optional[str] = None

class ScanResults(BaseModel):
    target: str  # Add the missing target field
    results: Dict[str, Any]

class SecurityScanner:
    def __init__(self, target: str = None, email: str = None, profile: str = "standard"):
        
        self.target = target
        self.email = email
        self.profile = profile
        self.console = Console()
        
        # Initialize AI recommendation system
        self.init_ai_recommendations()
        
        # Configure requests session with proper SSL verification
        self.session = requests.Session()
        self.session.verify = True  # Enable SSL verification
        self.session.headers.update({
            'User-Agent': 'Security Scanner/1.0',
            'Accept': 'application/json'
        })
        
        # Suppress SSL verification warnings
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # Validate required API keys
        required_keys = ['SHODAN_API_KEY', 'ABUSEIPDB_API_KEY']
        missing_keys = [key for key in required_keys if not os.getenv(key)]
        if missing_keys:
            raise ValueError(f"Missing required API keys: {', '.join(missing_keys)}")

        # Load Sublist3r path during initialization
        self.sublist3r_path = os.getenv('SUBLIST3R_PATH')
        if not self.sublist3r_path:
            self.console.print("[yellow]Warning: SUBLIST3R_PATH not found in .env file. Subdomain discovery via Sublist3r will be skipped.[/yellow]")
        elif not os.path.exists(self.sublist3r_path):
             self.console.print(f"[red]Error: SUBLIST3R_PATH ('{self.sublist3r_path}') specified in .env does not exist. Sublist3r will fail.[/red]")
            
        # Load Amass path during initialization
        self.amass_path = os.getenv('AMASS_PATH')
        if not self.amass_path:
            self.console.print("[yellow]Warning: AMASS_PATH not found in .env file. Subdomain discovery via Amass will be skipped.[/yellow]")
        elif not os.path.exists(self.amass_path):
             self.console.print(f"[red]Error: AMASS_PATH ('{self.amass_path}') specified in .env does not exist. Amass will fail.[/red]")
        
        # Load Findomain path during initialization
        self.findomain_path = os.getenv('FINDOMAIN_PATH')
        if not self.findomain_path:
            self.console.print("[yellow]Warning: FINDOMAIN_PATH not found in .env file. Subdomain discovery via Findomain will be skipped.[/yellow]")
        elif not os.path.exists(self.findomain_path):
             self.console.print(f"[red]Error: FINDOMAIN_PATH ('{self.findomain_path}') specified in .env does not exist. Findomain will fail.[/red]")
             
        self.results = {
            'network_security': {},
            'dns_health': {},
            'subdomain_discovery': {}, # Add this line
            'email_security': {},
            'http_security': {}, # Added
            'technology_detection': {}, # Add this line
            'application_security': {},
            'vulnerability_assessment': {},
            'ip_reputation': {},
            'ssl_tls_security': {},
            'api_security': {},
            'container_security': {},
            'database_security': {},
            'patching_status': {},
            'compliance': {},
            'asset_inventory': {},
            'real_time_monitoring': {},
            'historical_data': {},
            'vulnerability_metrics': {},
            'risk_analysis': {},
            'remediation_tracking': {},
            'cloud_security': {},
            'google_dorking': {},
            'typosquatting': {}
        }
        
        # Initialize database for historical data
        self.init_database()
        
        # Initialize scan profiles with optimized settings
        self.scan_profiles = {
            'quick': {
                'vuln_scan': False,
                'compliance': False,
                'timeout': 30,  # 30 seconds timeout
                'tasks': [
                    'network_security',
                    'dns_health',
                    'ssl_tls_security'
                ]
            },
            'standard': {
                'vuln_scan': True,
                'compliance': True,
                'timeout': 120,  # Use comprehensive timeout
                'tasks': [
                    'network_security',
                    'dns_health',
                    'ssl_tls_security',
                    'http_security',
                    'technology_detection', # Add this line
                    'vulnerability_assessment',
                    'ip_reputation',
                    'subdomain_discovery', # Add this line
                    'email_security',
                    'api_security',
                    'container_security',
                    'database_security',
                    'patching_status',
                    'compliance',
                    'asset_inventory',
                    'cloud_security'
                ]
            }
        }
        # --- Wappalyzer Instance ---
        # Initialize Wappalyzer once per instance
        try:
            self.wappalyzer = Wappalyzer.latest()
        except Exception as e:
            self.console.print(f"[red]Failed to initialize Wappalyzer: {e}[/red]")
            self.wappalyzer = None

        self.traceback_api = None
        try:
            self.traceback_api = TracebackAPI()
        except ValueError as e:
            print(f"Warning: {e}")

    def init_ai_recommendations(self):
        """Initialize the AI recommendation system"""
        try:
            from langchain.chat_models import ChatOpenAI
            from langchain.prompts import PromptTemplate
            from langchain.chains import LLMChain
            from dotenv import load_dotenv
            
            # Load environment variables
            load_dotenv()
            openai_api_key = os.getenv("OPENAI_API_KEY")
            
            if not openai_api_key:
                self.console.print("[yellow]Warning: OPENAI_API_KEY not found. AI recommendations will be disabled.[/yellow]")
                self.ai_enabled = False
                return
            
            # Initialize LLM
            self.llm = ChatOpenAI(model="gpt-3.5-turbo", temperature=0)
            
            # Create prompt template for security recommendations
            self.recommendation_prompt = PromptTemplate(
                input_variables=["issue", "context"],
                template="""You are an expert cybersecurity consultant. Analyze the following security issue and provide detailed recommendations.

                Issue: {issue}
                Context: {context}

                Provide recommendations in the following format:
                ---- Recommendation ----
                Impact: [Brief description of potential impact]
                Priority: [High/Medium/Low]
                Steps:
                1. [First step to address the issue]
                2. [Second step]
                3. [Additional steps if needed]
                
                Additional Context: [Any relevant security best practices or standards]
                ---- End ----
                
                Keep the response concise but comprehensive."""
            )
            
            self.recommendation_chain = LLMChain(llm=self.llm, prompt=self.recommendation_prompt)
            self.ai_enabled = True
            
        except Exception as e:
            self.console.print(f"[red]Error initializing AI recommendations: {str(e)}[/red]")
            self.ai_enabled = False

    async def get_ai_recommendation(self, issue: str, context: str = "") -> Dict:
        """Get AI-powered recommendations for a security issue"""
        if not self.ai_enabled:
            return {
                "status": "disabled",
                "recommendation": "AI recommendations are not available"
            }
        
        try:
            result = await self.recommendation_chain.arun({
                "issue": issue,
                "context": context
            })
            
            return {
                "status": "success",
                "recommendation": result
            }
            
        except Exception as e:
            logger.error(f"AI recommendation error: {str(e)}")
            return {
                "status": "error",
                "recommendation": f"Failed to generate recommendation: {str(e)}"
            }

    def init_database(self):
        """Initialize SQLite database for historical data"""
        db_path = Path('security_scanner.db')
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        
        # Create tables for historical data
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                scan_date DATETIME,
                scan_type TEXT,
                findings TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                vuln_type TEXT,
                description TEXT,
                severity TEXT,
                exploitability TEXT,
                impact TEXT,
                discovery_date DATETIME,
                remediation_date DATETIME,
                status TEXT,
                risk_score INTEGER,
                remediation_notes TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                asset_type TEXT,
                details TEXT,
                discovery_date DATETIME
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS remediation_tracking (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vuln_id INTEGER,
                action_taken TEXT,
                action_date DATETIME,
                action_by TEXT,
                status TEXT,
                notes TEXT,
                FOREIGN KEY (vuln_id) REFERENCES vulnerabilities (id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date DATETIME,
                metric_type TEXT,
                value REAL,
                target TEXT
            )
        ''')
        
        conn.commit()
        conn.close()

    async def assess_network_security(self) -> None:
        """Perform passive network security assessment"""
        if not self.target:
            return
            
        self.console.print(f"[bold blue]Starting passive network security assessment...[/bold blue]")
        
        network_info = {
            'ip_info': {},
            'dns_info': {},
            'whois_info': {},
            'passive_port_info': {},
            'passive_service_info': {},
            'network_issues': [] # Added to store issues like non-standard ports
            # 'nmap_scan': {} # Keep commented out or remove entirely
        }
        
        try:
            # Get IP information using IP-API
            try:
                ip_info = socket.gethostbyname(self.target)
                network_info['ip_info']['ip'] = ip_info
                
                # Get ASN information using IP-API
                response = requests.get(f'http://ip-api.com/json/{ip_info}', timeout=5)
                if response.status_code == 200:
                    asn_info = response.json()
                    network_info['ip_info'].update({
                        'asn': asn_info.get('as'),
                        'isp': asn_info.get('isp'),
                        'country': asn_info.get('country'),
                        'city': asn_info.get('city'),
                        'region': asn_info.get('region'),
                        'timezone': asn_info.get('timezone')
                    })
            except Exception as e:
                network_info['ip_info']['error'] = str(e)
            
            # Get DNS information using Cloudflare DNS
            try:
                dns_records = {}
                record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CAA']
                
                for record_type in record_types:
                    try:
                        records = dns.resolver.resolve(self.target, record_type)
                        dns_records[record_type] = [str(r) for r in records]
                    except:
                        dns_records[record_type] = []
                
                network_info['dns_info'] = dns_records
            except Exception as e:
                network_info['dns_info']['error'] = str(e)
            
            # Get WHOIS information
            try:
                whois_info = whois.whois(self.target)
                network_info['whois_info'] = {
                    'registrar': whois_info.registrar,
                    'creation_date': str(whois_info.creation_date),
                    'expiration_date': str(whois_info.expiration_date)
                }
            except Exception as e:
                network_info['whois_info']['error'] = str(e)
            
            # Get passive port and service information from Shodan
            try:
                shodan_api_key = os.getenv('SHODAN_API_KEY')
                if shodan_api_key:
                    response = requests.get(
                        f'https://api.shodan.io/shodan/host/{ip_info}?key={shodan_api_key}',
                        timeout=10
                    )
                    if response.status_code == 200:
                        shodan_data = response.json()
                        open_ports = shodan_data.get('ports', [])
                        network_info['passive_port_info'] = {
                            'ports': open_ports
                            # Removed services from here, use 'data' key below
                        }
                        
                        # Flag non-standard ports
                        for port in open_ports:
                            if port not in [80, 443]:
                                network_info['network_issues'].append(f"Non-standard port open: {port}")

                        # Extract detailed service info
                        service_details = []
                        raw_services = shodan_data.get('data', [])
                        for service_item in raw_services:
                             service_details.append({
                                 'port': service_item.get('port'),
                                 'transport': service_item.get('transport', 'tcp'), # Default to tcp
                                 'service_name': service_item.get('_shodan', {}).get('module', 'unknown'), # Get service name
                                 'product': service_item.get('product', None), # Get product if available
                                 'version': service_item.get('version', None) # Get version if available
                             })
                        network_info['passive_service_info']['shodan'] = {
                            'services': service_details
                        }
            except Exception as e:
                self.console.print(f"[yellow]Warning: Shodan API error: {str(e)}[/yellow]")
            
            # Perform nmap scan only for comprehensive profile
            # if self.profile == "comprehensive":
            #     try:
            #         scanner = AttackSurfaceScanner(self.target)
            #         scanner.port_scan("1-1024")  # Scan common ports
            #         network_info['nmap_scan'] = {
            #             'ports': scanner.results['ports'],
            #             'services': scanner.results['services']
            #         }
            #     except Exception as e:
            #         network_info['nmap_scan']['error'] = str(e)
            
        except Exception as e:
            self.console.print(f"[yellow]Warning: Network security assessment error: {str(e)}[/yellow]")
            
        self.results['network_security'] = network_info

    async def assess_dns_health(self) -> None:
        """Perform DNS health assessment"""
        if not self.target:
            self.results['dns_health'] = {
                'error': 'No target specified',
                'security_records': {},
                'issues': ['No target specified for DNS assessment']
            }
            return
            
        self.console.print(f"[bold blue]Starting DNS health assessment for {self.target}...[/bold blue]")
        
        dns_health = {
            'security_records': {},
            'issues': [],
            'summary': {}
        }
        
        try:
            # Initialize DNS resolver with common DNS servers
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '8.8.4.4']  # Google DNS
            resolver.timeout = 5
            resolver.lifetime = 5
            
            # Check for security records
            dns_records = {}
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CAA']
            
            for record_type in record_types:
                try:
                    records = resolver.resolve(self.target, record_type)
                    dns_records[record_type] = [str(r) for r in records]
                    self.console.print(f"[green]Found {record_type} records for {self.target}[/green]")
                except dns.resolver.NoAnswer:
                    dns_records[record_type] = []
                    self.console.print(f"[yellow]No {record_type} records found for {self.target}[/yellow]")
                except dns.resolver.NXDOMAIN:
                    dns_records[record_type] = []
                    self.console.print(f"[red]Domain {self.target} does not exist[/red]")
                except dns.resolver.Timeout:
                    dns_records[record_type] = []
                    self.console.print(f"[yellow]Timeout while querying {record_type} records for {self.target}[/yellow]")
                except Exception as e:
                    dns_records[record_type] = []
                    self.console.print(f"[yellow]Error querying {record_type} records: {str(e)}[/yellow]")
            
            dns_health['security_records'] = dns_records
            
            # Check for security issues
            issues = []
            summary = {
                'total_records': 0,
                'missing_critical': [],
                'missing_recommended': [],
                'found_records': []
            }
            
            # Check A/AAAA records
            if not dns_records.get('A') and not dns_records.get('AAAA'):
                issues.append('Critical: Missing both A and AAAA records')
                summary['missing_critical'].append('A/AAAA')
            else:
                summary['found_records'].extend(['A' if dns_records.get('A') else None, 'AAAA' if dns_records.get('AAAA') else None])
                summary['total_records'] += len(dns_records.get('A', [])) + len(dns_records.get('AAAA', []))
            
            # Check MX records
            if not dns_records.get('MX'):
                issues.append('Warning: Missing MX records')
                summary['missing_recommended'].append('MX')
            else:
                summary['found_records'].append('MX')
                summary['total_records'] += len(dns_records.get('MX', []))
            
            # Check NS records
            if not dns_records.get('NS'):
                issues.append('Critical: Missing NS records')
                summary['missing_critical'].append('NS')
            else:
                summary['found_records'].append('NS')
                summary['total_records'] += len(dns_records.get('NS', []))
            
            # Check TXT records for security
            txt_records = dns_records.get('TXT', [])
            has_spf = any('v=spf1' in record for record in txt_records)
            has_dmarc = any('v=DMARC1' in record for record in txt_records)
            has_dkim = any('v=DKIM1' in record for record in txt_records)
            
            if not has_spf:
                issues.append('Warning: Missing SPF record')
                summary['missing_recommended'].append('SPF')
            if not has_dmarc:
                issues.append('Warning: Missing DMARC record')
                summary['missing_recommended'].append('DMARC')
            if not has_dkim:
                issues.append('Warning: Missing DKIM record')
                summary['missing_recommended'].append('DKIM')
            
            if txt_records:
                summary['found_records'].append('TXT')
                summary['total_records'] += len(txt_records)
            
            # Check SOA record
            if not dns_records.get('SOA'):
                issues.append('Warning: Missing SOA record')
                summary['missing_recommended'].append('SOA')
            else:
                summary['found_records'].append('SOA')
                summary['total_records'] += len(dns_records.get('SOA', []))
            
            # Check CAA record
            if not dns_records.get('CAA'):
                issues.append('Info: Missing CAA record')
                summary['missing_recommended'].append('CAA')
            else:
                summary['found_records'].append('CAA')
                summary['total_records'] += len(dns_records.get('CAA', []))
            
            # Clean up found records list
            summary['found_records'] = [r for r in summary['found_records'] if r is not None]
            
            dns_health['issues'] = issues
            dns_health['summary'] = summary
            
            self.results['dns_health'] = dns_health
            
        except Exception as e:
            error_msg = f"DNS health assessment error: {str(e)}"
            self.console.print(f"[red]{error_msg}[/red]")
            self.results['dns_health'] = {
                'error': error_msg,
                'security_records': {},
                'issues': ['DNS assessment failed'],
                'summary': {
                    'total_records': 0,
                    'missing_critical': [],
                    'missing_recommended': [],
                    'found_records': []
                }
            }

    async def assess_http_security(self) -> None:
        """Perform HTTP security assessment using Sucuri SiteCheck API via curl"""
        print("--- Entering assess_http_security ---") # Basic print
        if not self.target:
            print("--- assess_http_security: No target ---") # Basic print
            self.results['http_security'] = {'error': 'No target specified'}
            return
            
        self.console.print(f"[bold blue]Starting HTTP security assessment for {self.target}...[/bold blue]")
        # Removed Sucuri check, focusing on manual checks now
        http_info = {
            'status': 'pending',
            'headers': {},
            # 'observatory_scan': {}, # Removed Observatory
            'malware_scan': {'status': 'Check not performed'}, # Placeholder
            'security_hardening': {},
            'waf': 'Unknown/None', # Added WAF detection placeholder
            'warnings': [],
            'error': None
        }
        
        # --- Get Basic Headers --- 
        target_url = f"https://{self.target}" # Define target_url earlier
        try:
            print(f"--- assess_http_security: Getting headers from {target_url} ---")
            response = self.session.get(target_url, timeout=15, verify=True, allow_redirects=True)
            response.raise_for_status() # Check for HTTP errors
            http_info['headers'] = dict(response.headers)
            print(f"--- assess_http_security: Got headers successfully ---")
        except requests.exceptions.SSLError:
            try:
                 print(f"--- assess_http_security: Retrying getting headers from {target_url} without verify ---")
                 response = self.session.get(target_url, timeout=15, verify=False, allow_redirects=True)
                 response.raise_for_status()
                 http_info['headers'] = dict(response.headers)
                 http_info['warnings'].append("SSL certificate verification failed when fetching headers.")
                 print(f"--- assess_http_security: Got headers successfully (insecure) ---")
            except Exception as e:
                 err_msg = f"Failed to get headers (insecure retry): {e}"
                 print(f"--- assess_http_security: Exception - {err_msg} ---")
                 http_info['error'] = err_msg
                 http_info['status'] = 'error'
                 self.results['http_security'] = http_info
                 return 
        except requests.exceptions.RequestException as e:
            err_msg = f"Failed to get headers: {e}"
            print(f"--- assess_http_security: Exception - {err_msg} ---")
            http_info['error'] = err_msg
            http_info['status'] = 'error'
            self.results['http_security'] = http_info
            return 

        # --- Basic Header Checks (Example: Add more as needed) ---
        headers = http_info['headers']
        if not headers.get('Strict-Transport-Security'):
            http_info['warnings'].append("Missing Strict-Transport-Security (HSTS) header.")
        if headers.get('X-Frame-Options', '').upper() not in ['DENY', 'SAMEORIGIN']:
             http_info['warnings'].append("X-Frame-Options header missing or not set to DENY/SAMEORIGIN.")
        if headers.get('X-Content-Type-Options', '').lower() != 'nosniff':
             http_info['warnings'].append("X-Content-Type-Options header missing or not set to 'nosniff'.")
        # Add more checks here (e.g., CSP presence/basics, Referrer-Policy, Permissions-Policy)

        # --- WAF/CDN Detection (Example using headers) ---
        # This is a very basic heuristic and may not be accurate
        server_header = headers.get('Server', '').lower()
        via_header = headers.get('Via', '').lower()
        if 'cloudflare' in server_header or 'cloudflare' in via_header:
            http_info['waf'] = 'Cloudflare'
        elif 'sucuri' in server_header or 'sucuri' in via_header:
            http_info['waf'] = 'Sucuri'
        elif 'incapsula' in server_header or 'incapsula' in via_header:
            http_info['waf'] = 'Incapsula'
        elif 'aws' in server_header or 'cloudfront' in server_header:
             http_info['waf'] = 'AWS CloudFront/WAF'
        # Add other common WAF/CDN identifiers

        # --- Mozilla Observatory Scan --- 
        # --- REMOVED OBSERVATORY LOGIC ---

        # --- Consolidate Status & Results --- 
        # Determine overall status based on header fetch success and warnings
        if http_info['error']:
            http_info['status'] = 'error'
        elif http_info['warnings']:
            http_info['status'] = 'warning' # Set to warning if there are issues found
        else:
            http_info['status'] = 'success'
        
        # Ensure warnings are unique
        http_info['warnings'] = list(set(http_info['warnings']))

        print("--- Exiting assess_http_security ---")
        self.results['http_security'] = http_info
        # Log the final http_info structure for debugging
        # self.console.print(f"HTTP Security results (post-removal): {json.dumps(http_info, indent=2, default=str)}")

    async def assess_vulnerability_assessment(self) -> None:
        """Perform vulnerability assessment with risk analysis"""
        if not self.target:
            return
            
        self.console.print(f"[bold blue]Starting vulnerability assessment...[/bold blue]")
        
        vulnerability_info = {
            'common_vulnerabilities': [],
            'security_issues': [],
            'risk_analysis': {},
            'remediation_priorities': [],
            'metrics': {}
        }
        
        try:
            # Check for common vulnerabilities
            vulnerabilities = []
            target_url_base = f"https://{self.target}"
            self.console.print(f"Checking for vulnerabilities on {target_url_base}")

            # --- XSS Checks --- #
            xss_payloads = [
                '<script>alert(1)</script>',
                '"><script>alert(2)</script>',
                '"><img src=x onerror=alert(3)>'
            ]
            self.console.print(f"Running {len(xss_payloads)} XSS checks...")
            xss_found = False # Flag to avoid duplicate entries for same payload type
            for payload in xss_payloads:
                if xss_found: break # Move to next type if found
                test_url = f"{target_url_base}/?q={payload}" # Test URL parameter
                search_url = f"{target_url_base}/search.aspx?txtSearch={payload}" # Test search functionality
                urls_to_test = [test_url, search_url]
                ssl_verification_status = 'Success'

                for url in urls_to_test:
                    if xss_found: break
                    try:
                        # Initial attempt with SSL verification
                        response = requests.get(url, verify=True, timeout=10)
                        # Use regex to find script tags or onerror handlers more reliably
                        # Replaced regex with simple string checks to avoid syntax errors
                        response_text = response.text # Store raw text
                        # ** Refined Check: Look for exact payload reflection **
                        if payload in response_text:
                            self.console.print(f"    [yellow]* Potential XSS Found (Payload Reflected) in {url} for payload: {payload[:20]}... *[/yellow]")
                            vulnerabilities.append({
                                'type': 'XSS',
                                'payload': payload,
                                'location': url,
                                'severity': 'High',
                                'exploitability': 'Easy',
                                'impact': 'Data theft, session hijacking',
                                'risk_score': self.calculate_risk_score('XSS', 'High', 'Easy', 'Data theft, session hijacking'),
                                'ssl_verification': ssl_verification_status
                            })
                            xss_found = True
                            break # Stop checking this payload type
                    except requests.exceptions.SSLError:
                        ssl_verification_status = 'Failed'
                        try:
                            # Retry without SSL verification
                            response = requests.get(url, verify=False, timeout=10)
                            # Replaced regex with simple string checks to avoid syntax errors
                            response_text = response.text # Store raw text
                            # ** Refined Check: Look for exact payload reflection **
                            if payload in response_text:
                                self.console.print(f"    [yellow]* Potential XSS Found (Payload Reflected/insecure) in {url} for payload: {payload[:20]}... *[/yellow]")
                                vulnerabilities.append({
                                    'type': 'XSS',
                                    'payload': payload,
                                    'location': url,
                                    'severity': 'High',
                                    'exploitability': 'Easy',
                                    'impact': 'Data theft, session hijacking',
                                    'risk_score': self.calculate_risk_score('XSS', 'High', 'Easy', 'Data theft, session hijacking'),
                                    'ssl_verification': ssl_verification_status
                                })
                                xss_found = True
                                break # Stop checking this payload type
                        except Exception as inner_e:
                            self.console.print(f"[yellow]XSS check failed (insecure retry) for {url}: {inner_e}[/yellow]")
                    except requests.exceptions.RequestException as req_e: # Catch timeouts, connection errors etc.
                        self.console.print(f"[yellow]XSS check failed for {url}: {req_e}[/yellow]")
                    except Exception as e: # Catch other unexpected errors
                        self.console.print(f"[red]Unexpected error during XSS check for {url}: {e}[/red]")
            self.console.print(f"XSS checks completed.")

            # --- SQL Injection Checks --- #
            # Payloads targeting different SQL injection types
            sql_payloads = [
                # Boolean-based
                {'payload': "' OR '1'='1", 'location': 'url_param', 'param': 'id'},
                {'payload': "1' OR '1'='1", 'location': 'url_param', 'param': 'id'},
                {'payload': "admin'--", 'location': 'login_uid', 'param': 'uid'}, # Comment based for username
                {'payload': "admin' #", 'location': 'login_uid', 'param': 'uid'},
                {'payload': "admin' or 1=1--", 'location': 'login_uid', 'param': 'uid'},
                # Try injecting password field too
                {'payload': "' OR '1'='1", 'location': 'login_passw', 'param': 'passw'},
                # Union-based (less likely to work on login directly, but try generic param)
                {'payload': "1 UNION SELECT NULL--", 'location': 'url_param', 'param': 'id'}
            ]
            # Specific indicators of successful SQLi, especially for testfire.net
            sqli_success_indicators = [
                "login failed",
                "welcome back", # More general success indicator on testfire
                "you have logged in successfully",
                "invalid syntax",
                "unclosed quotation mark",
                "odbc driver does not support", # testfire specific error
                "microsoft ole db provider for sql server",
                "syntax error", # Add general syntax error
                "sql server error" # Another potential error message
            ]
            sqli_found = False # Flag to avoid duplicates for similar payload types
            self.console.print(f"Running {len(sql_payloads)} SQLi checks...")

            for item in sql_payloads:
                if sqli_found: break # Limit findings for now to avoid overwhelming results
                payload = item['payload']
                location_type = item['location']
                param_name = item['param']
                ssl_verification_status = 'Success'
                test_executed = False

                if location_type == 'url_param':
                    test_url = f"{target_url_base}/?{param_name}={payload}"
                    try:
                        test_executed = True
                        response = requests.get(test_url, verify=True, timeout=10, allow_redirects=True)
                        response_text_lower = response.text.lower()
                        if any(indicator in response_text_lower for indicator in sqli_success_indicators):
                            self.console.print(f"    [red]* Potential SQLi (URL Param: {param_name}) Found for payload: {payload[:20]}... *[/red]")
                            vulnerabilities.append({
                                'type': 'SQL Injection',
                                'payload': payload,
                                'location': f'URL Parameter ({param_name})',
                                'severity': 'Critical',
                                'exploitability': 'Easy',
                                'impact': 'Data breach, unauthorized access',
                                'risk_score': self.calculate_risk_score('SQL Injection', 'Critical', 'Easy', 'Data breach, unauthorized access'),
                                'ssl_verification': ssl_verification_status
                            })
                            sqli_found = True
                    except requests.exceptions.SSLError:
                        ssl_verification_status = 'Failed'
                        try:
                            response = requests.get(test_url, verify=False, timeout=10, allow_redirects=True)
                            response_text_lower = response.text.lower()
                            if any(indicator in response_text_lower for indicator in sqli_success_indicators):
                                self.console.print(f"    [red]* Potential SQLi (URL Param: {param_name}/insecure) Found for payload: {payload[:20]}... *[/red]")
                                vulnerabilities.append({
                                    'type': 'SQL Injection',
                                    'payload': payload,
                                    'location': f'URL Parameter ({param_name})',
                                    'severity': 'Critical',
                                    'exploitability': 'Easy',
                                    'impact': 'Data breach, unauthorized access',
                                    'risk_score': self.calculate_risk_score('SQL Injection', 'Critical', 'Easy', 'Data breach, unauthorized access'),
                                    'ssl_verification': ssl_verification_status
                                })
                                sqli_found = True
                        except Exception as inner_e:
                             self.console.print(f"[yellow]SQLi check (URL Param/insecure retry) failed for {test_url}: {inner_e}[/yellow]")
                    except requests.exceptions.RequestException as req_e:
                        self.console.print(f"[yellow]SQLi check (URL Param) failed for {test_url}: {req_e}[/yellow]")
                    except Exception as e:
                        self.console.print(f"[red]Unexpected error during SQLi check (URL Param) for {test_url}: {e}[/red]")

                elif location_type in ['login_uid', 'login_passw']:
                    login_url = f"{target_url_base}/login.aspx"
                    # Construct login data based on which field is being injected
                    login_data = {
                        'uid': payload if location_type == 'login_uid' else 'testuser', # Inject uid or use placeholder
                        'passw': payload if location_type == 'login_passw' else 'password' # Inject passw or use placeholder
                    }
                    try:
                        test_executed = True
                        response = requests.post(login_url, data=login_data, verify=True, timeout=10, allow_redirects=True)
                        response_text_lower = response.text.lower()
                        if any(indicator in response_text_lower for indicator in sqli_success_indicators):
                            self.console.print(f"    [red]* Potential SQLi (Login Form: {param_name}) Found for payload: {payload[:20]}... *[/red]")
                            vulnerabilities.append({
                                'type': 'SQL Injection',
                                'payload': payload,
                                'location': f'Login Form ({param_name})',
                                'severity': 'Critical',
                                'exploitability': 'Easy',
                                'impact': 'Data breach, unauthorized access',
                                'risk_score': self.calculate_risk_score('SQL Injection', 'Critical', 'Easy', 'Data breach, unauthorized access'),
                                'ssl_verification': ssl_verification_status
                            })
                            sqli_found = True
                    except requests.exceptions.SSLError:
                        ssl_verification_status = 'Failed'
                        try:
                            response = requests.post(login_url, data=login_data, verify=False, timeout=10, allow_redirects=True)
                            response_text_lower = response.text.lower()
                            if any(indicator in response_text_lower for indicator in sqli_success_indicators):
                                 self.console.print(f"    [red]* Potential SQLi (Login Form: {param_name}/insecure) Found for payload: {payload[:20]}... *[/red]")
                                 vulnerabilities.append({
                                     'type': 'SQL Injection',
                                     'payload': payload,
                                     'location': f'Login Form ({param_name})',
                                     'severity': 'Critical',
                                     'exploitability': 'Easy',
                                     'impact': 'Data breach, unauthorized access',
                                     'risk_score': self.calculate_risk_score('SQL Injection', 'Critical', 'Easy', 'Data breach, unauthorized access'),
                                     'ssl_verification': ssl_verification_status
                                 })
                                 sqli_found = True
                        except Exception as inner_e:
                            self.console.print(f"[yellow]SQLi check (Login Form/insecure retry) failed for {login_url}: {inner_e}[/yellow]")
                    except requests.exceptions.RequestException as req_e:
                        self.console.print(f"[yellow]SQLi check (Login Form) failed for {login_url}: {req_e}[/yellow]")
                    except Exception as e:
                        self.console.print(f"[red]Unexpected error during SQLi check (Login Form) for {login_url}: {e}[/red]")

            self.console.print(f"SQLi checks completed.")

            # Assign collected vulnerabilities
            vulnerability_info['common_vulnerabilities'] = vulnerabilities
            self.console.print(f"Found {len(vulnerabilities)} potential common vulnerabilities.")

            # Add SSL verification issues if any were flagged during checks
            if any(vuln.get('ssl_verification') == 'Failed' for vuln in vulnerabilities):
                if 'SSL certificate verification failed during vuln scan' not in vulnerability_info['security_issues']:
                     vulnerability_info['security_issues'].append('SSL certificate verification failed during vuln scan')

            # Perform risk analysis (ensure functions don't raise exceptions that stop the flow)
            try:
                 vulnerability_info['risk_analysis'] = {
                    'total_vulnerabilities': len(vulnerabilities),
                    'severity_distribution': self.calculate_severity_distribution(vulnerabilities),
                    'exploitability_distribution': self.calculate_exploitability_distribution(vulnerabilities),
                    'impact_analysis': self.analyze_impact(vulnerabilities),
                    'risk_trends': self.analyze_risk_trends()
                 }
                 self.console.print("Risk analysis completed.")
            except Exception as risk_e:
                 self.console.print(f"[red]Error during risk analysis calculation: {risk_e}[/red]")
                 vulnerability_info['risk_analysis'] = {'error': f'Risk analysis failed: {risk_e}'}

            # Prioritize remediation
            try:
                vulnerability_info['remediation_priorities'] = self.prioritize_remediation(vulnerabilities)
                self.console.print("Remediation prioritization completed.")
            except Exception as prio_e:
                self.console.print(f"[red]Error during remediation prioritization: {prio_e}[/red]")
                vulnerability_info['remediation_priorities'] = [{'error': f'Prioritization failed: {prio_e}'}]

            # Calculate metrics
            try:
                vulnerability_info['metrics'] = self.calculate_vulnerability_metrics(vulnerabilities)
                self.console.print("Vulnerability metrics calculation completed.")
            except Exception as metrics_e:
                 self.console.print(f"[red]Error during vulnerability metrics calculation: {metrics_e}[/red]")
                 vulnerability_info['metrics'] = {'error': f'Metrics calculation failed: {metrics_e}'}

        except Exception as e:
            # Catch-all for unexpected errors in the main vulnerability assessment block
            self.console.print(f"[red]Unexpected error in Vulnerability assessment: {str(e)}[/red]")
            logger.exception("Unexpected Vulnerability Assessment Error")
            vulnerability_info['error'] = f"Unexpected assessment error: {str(e)}"
            if 'Assessment failed unexpectedly' not in vulnerability_info['security_issues']:
                 vulnerability_info['security_issues'].append('Assessment failed unexpectedly')

        # Assign results and log
        self.results['vulnerability_assessment'] = vulnerability_info
        self.console.print(f"Vulnerability assessment results: {json.dumps(vulnerability_info, indent=2, default=str)}")

    def calculate_risk_score(self, vuln_type: str, severity: str, exploitability: str, impact: str) -> int:
        """Calculate risk score for a vulnerability"""
        score = 0
        
        # Severity scoring
        severity_scores = {
            'Critical': 10,
            'High': 7,
            'Medium': 4,
            'Low': 1
        }
        score += severity_scores.get(severity, 0)
        
        # Exploitability scoring
        exploitability_scores = {
            'Easy': 5,
            'Moderate': 3,
            'Difficult': 1
        }
        score += exploitability_scores.get(exploitability, 0)
        
        # Impact scoring
        if 'data breach' in impact.lower():
            score += 5
        if 'unauthorized access' in impact.lower():
            score += 4
        if 'data theft' in impact.lower():
            score += 3
        if 'session hijacking' in impact.lower():
            score += 2
            
        return min(score, 20)  # Cap at 20

    def calculate_severity_distribution(self, vulnerabilities: List[Dict]) -> Dict:
        """Calculate distribution of vulnerability severities"""
        distribution = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Unknown')
            if severity in distribution:
                distribution[severity] += 1
                
        return distribution

    def calculate_exploitability_distribution(self, vulnerabilities: List[Dict]) -> Dict:
        """Calculate distribution of vulnerability exploitability"""
        distribution = {
            'Easy': 0,
            'Moderate': 0,
            'Difficult': 0
        }
        
        for vuln in vulnerabilities:
            exploitability = vuln.get('exploitability', 'Unknown')
            if exploitability in distribution:
                distribution[exploitability] += 1
                
        return distribution

    def analyze_impact(self, vulnerabilities: List[Dict]) -> Dict:
        """Analyze potential impact of vulnerabilities"""
        impact_analysis = {
            'data_breach_risk': 0,
            'unauthorized_access_risk': 0,
            'data_theft_risk': 0,
            'session_hijacking_risk': 0,
            'service_disruption_risk': 0
        }
        
        for vuln in vulnerabilities:
            impact = vuln.get('impact', '').lower()
            if 'data breach' in impact:
                impact_analysis['data_breach_risk'] += 1
            if 'unauthorized access' in impact:
                impact_analysis['unauthorized_access_risk'] += 1
            if 'data theft' in impact:
                impact_analysis['data_theft_risk'] += 1
            if 'session hijacking' in impact:
                impact_analysis['session_hijacking_risk'] += 1
            if 'service disruption' in impact:
                impact_analysis['service_disruption_risk'] += 1
                
        return impact_analysis

    def analyze_risk_trends(self) -> Dict:
        """Analyze vulnerability risk trends over time"""
        try:
            conn = sqlite3.connect('security_scanner.db')
            cursor = conn.cursor()
            
            # Get historical vulnerability data
            cursor.execute('''
                SELECT discovery_date, severity, risk_score
                FROM vulnerabilities
                WHERE target = ?
                ORDER BY discovery_date DESC
                LIMIT 30
            ''', (self.target,))
            
            historical_data = cursor.fetchall()
            
            trends = {
                'severity_trend': [],
                'risk_score_trend': [],
                'vulnerability_count_trend': []
            }
            
            for date, severity, risk_score in historical_data:
                trends['severity_trend'].append({
                    'date': date,
                    'severity': severity
                })
                trends['risk_score_trend'].append({
                    'date': date,
                    'risk_score': risk_score
                })
                
            conn.close()
            return trends
            
        except Exception as e:
            self.console.print(f"[yellow]Warning: Risk trend analysis error: {str(e)}[/yellow]")
            return {}

    def prioritize_remediation(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Prioritize vulnerabilities for remediation"""
        # Sort vulnerabilities by risk score
        sorted_vulns = sorted(vulnerabilities, key=lambda x: x.get('risk_score', 0), reverse=True)
        
        priorities = []
        for vuln in sorted_vulns:
            priority = {
                'vulnerability': vuln,
                'priority_level': self.determine_priority_level(vuln),
                'recommended_timeline': self.determine_remediation_timeline(vuln),
                'responsible_team': self.determine_responsible_team(vuln)
            }
            priorities.append(priority)
            
        return priorities

    def determine_priority_level(self, vuln: Dict) -> str:
        """Determine priority level for remediation"""
        risk_score = vuln.get('risk_score', 0)
        
        if risk_score >= 15:
            return 'Critical'
        elif risk_score >= 10:
            return 'High'
        elif risk_score >= 5:
            return 'Medium'
        else:
            return 'Low'

    def determine_remediation_timeline(self, vuln: Dict) -> str:
        """Determine recommended remediation timeline"""
        priority = self.determine_priority_level(vuln)
        
        timelines = {
            'Critical': '24 hours',
            'High': '72 hours',
            'Medium': '1 week',
            'Low': '1 month'
        }
        
        return timelines.get(priority, '1 month')

    def determine_responsible_team(self, vuln: Dict) -> str:
        """Determine team for remediation recommendation"""
        vuln_type = vuln.get('type', '').lower()
        
        if 'xss' in vuln_type or 'injection' in vuln_type:
            return 'Application Development'
        elif 'ssl' in vuln_type or 'certificate' in vuln_type:
            return 'Infrastructure'
        elif 'access' in vuln_type or 'authentication' in vuln_type:
            return 'Security'
        else:
            return 'IT Operations'

    def calculate_vulnerability_metrics(self, vulnerabilities: List[Dict]) -> Dict:
        """Calculate vulnerability metrics"""
        metrics = {
            'total_vulnerabilities': len(vulnerabilities),
            'critical_vulnerabilities': len([v for v in vulnerabilities if v.get('severity') == 'Critical']),
            'high_vulnerabilities': len([v for v in vulnerabilities if v.get('severity') == 'High']),
            'medium_vulnerabilities': len([v for v in vulnerabilities if v.get('severity') == 'Medium']),
            'low_vulnerabilities': len([v for v in vulnerabilities if v.get('severity') == 'Low']),
            'average_risk_score': sum(v.get('risk_score', 0) for v in vulnerabilities) / len(vulnerabilities) if vulnerabilities else 0,
            'mttd': self.calculate_mttd(),
            'mttr': self.calculate_mttr()
        }
        
        return metrics

    def calculate_mttd(self) -> float:
        """Calculate Mean Time to Detect (MTTD)"""
        try:
            conn = sqlite3.connect('security_scanner.db')
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT AVG(JULIANDAY(remediation_date) - JULIANDAY(discovery_date))
                FROM vulnerabilities
                WHERE target = ? AND remediation_date IS NOT NULL
            ''', (self.target,))
            
            mttd = cursor.fetchone()[0] or 0
            conn.close()
            
            return mttd
            
        except Exception as e:
            self.console.print(f"[yellow]Warning: MTTD calculation error: {str(e)}[/yellow]")
            return 0

    def calculate_mttr(self) -> float:
        """Calculate Mean Time to Remediate (MTTR)"""
        try:
            conn = sqlite3.connect('security_scanner.db')
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT AVG(JULIANDAY(remediation_date) - JULIANDAY(discovery_date))
                FROM vulnerabilities
                WHERE target = ? AND status = 'Remediated'
            ''', (self.target,))
            
            mttr = cursor.fetchone()[0] or 0
            conn.close()
            
            return mttr
            
        except Exception as e:
            self.console.print(f"[yellow]Warning: MTTR calculation error: {str(e)}[/yellow]")
            return 0

    def generate_remediation_report(self) -> str:
        """Generate a detailed remediation report"""
        report = f"""
Vulnerability Remediation Report
===============================
Target: {self.target}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Executive Summary
----------------
Total Vulnerabilities: {self.results['vulnerability_assessment']['metrics']['total_vulnerabilities']}
Critical Vulnerabilities: {self.results['vulnerability_assessment']['metrics']['critical_vulnerabilities']}
High Vulnerabilities: {self.results['vulnerability_assessment']['metrics']['high_vulnerabilities']}
Average Risk Score: {self.results['vulnerability_assessment']['metrics']['average_risk_score']:.2f}

Risk Analysis
------------
Severity Distribution:
{self.format_distribution(self.results['vulnerability_assessment']['risk_analysis']['severity_distribution'])}

Exploitability Distribution:
{self.format_distribution(self.results['vulnerability_assessment']['risk_analysis']['exploitability_distribution'])}

Impact Analysis:
{self.format_impact_analysis(self.results['vulnerability_assessment']['risk_analysis']['impact_analysis'])}

Performance Metrics
-----------------
Mean Time to Detect (MTTD): {self.results['vulnerability_assessment']['metrics']['mttd']:.2f} days
Mean Time to Remediate (MTTR): {self.results['vulnerability_assessment']['metrics']['mttr']:.2f} days

Remediation Priorities
--------------------
"""
        
        for priority in self.results['vulnerability_assessment']['remediation_priorities']:
            report += f"""
Vulnerability: {priority['vulnerability']['type']}
Priority Level: {priority['priority_level']}
Timeline: {priority['recommended_timeline']}
Recommended Team: {priority['responsible_team']}
Risk Score: {priority['vulnerability']['risk_score']}
Impact: {priority['vulnerability']['impact']}
"""
            
        return report

    def calculate_asset_sensitivity(self, assets: List[Dict]) -> str:
        """Calculate sensitivity level for a group of assets"""
        sensitivity_score = 0
        
        for asset in assets:
            # Check for sensitive data
            if any(sensitive in str(asset).lower() for sensitive in ['password', 'key', 'secret', 'personal', 'private']):
                sensitivity_score += 3
                
            # Check for regulated data
            if any(regulated in str(asset).lower() for regulated in ['hipaa', 'pci', 'gdpr', 'compliance']):
                sensitivity_score += 2
                
            # Check for customer data
            if 'customer' in str(asset).lower() or 'user' in str(asset).lower():
                sensitivity_score += 2
                
        if sensitivity_score >= 5:
            return 'High'
        elif sensitivity_score >= 3:
            return 'Medium'
        else:
            return 'Low'

    def calculate_business_impact(self, assets: List[Dict]) -> str:
        """Calculate business impact level for a group of assets"""
        impact_score = 0
        
        for asset in assets:
            # Check for revenue impact
            if 'payment' in str(asset).lower() or 'sales' in str(asset).lower():
                impact_score += 3
                
            # Check for customer impact
            if 'customer' in str(asset).lower() or 'user' in str(asset).lower():
                impact_score += 2
                
            # Check for operational impact
            if 'operation' in str(asset).lower() or 'service' in str(asset).lower():
                impact_score += 2
                
        if impact_score >= 5:
            return 'High'
        elif impact_score >= 3:
            return 'Medium'
        else:
            return 'Low'

    def map_asset_relationships(self, assets: List[Dict]) -> Dict:
        """Map relationships between assets"""
        relationships = {}
        
        for asset in assets:
            asset_name = asset.get('name', 'Unknown')
            relationships[asset_name] = {
                'dependencies': [],
                'connected_to': [],
                'depends_on': []
            }
            
            # Map dependencies based on asset type
            if asset['type'] == 'Web Application':
                relationships[asset_name]['dependencies'].extend([
                    {'type': 'Database Service', 'name': 'Database'},
                    {'type': 'Email Service', 'name': 'Email System'}
                ])
                
            elif asset['type'] == 'Email Service':
                relationships[asset_name]['dependencies'].extend([
                    {'type': 'DNS Service', 'name': 'DNS'},
                    {'type': 'Security Service', 'name': 'Security Gateway'}
                ])
                
        return relationships

    def assign_asset_owners(self, assets: List[Dict]) -> Dict:
        """Assign ownership recommendations for assets"""
        owners = {}
        
        for asset in assets:
            asset_name = asset.get('name', 'Unknown')
            owners[asset_name] = {
                'recommended_owner': 'System Administrator',
                'department': 'IT'
            }
            
            if asset['type'] in ['Web Application', 'Email Service']:
                owners[asset_name]['recommended_owner'] = 'Application Owner'
                owners[asset_name]['department'] = 'Development'
                
        return owners

    def update_asset_status(self, assets: List[Dict]) -> Dict:
        """Update status of assets based on various factors"""
        status = {}
        
        for asset in assets:
            asset_name = asset.get('name', 'Unknown')
            status[asset_name] = {
                'operational_status': 'Active',
                'last_scan': datetime.now().isoformat(),
                'health_status': 'Healthy',
                'maintenance_status': 'None'
            }
            
            # Update status based on issues
            if any(issue in str(asset).lower() for issue in ['error', 'failed', 'down']):
                status[asset_name]['health_status'] = 'Unhealthy'
                
        return status

    async def run_scan(self, scan_subdomains: bool = False) -> Dict[str, Any]:
        """Run the complete security scan"""
        try:
            print(f"Starting security scan for {self.target}...")
            
            # Initialize results dictionary
            self.results = {
                'target': self.target,
                'scan_date': datetime.now().isoformat(),
                'profile': self.profile,
                'network_security': {},
                'dns_health': {},
                'subdomain_discovery': {},
                'http_security': {},
                'technology_detection': {},
                'vulnerability_assessment': {},
                'ip_reputation': {},
                'ssl_tls_security': {},
                'google_dorking': {},
                'typosquatting': {},
                'subdomain_results': {}
            }

            # Run basic checks first
            await self.assess_network_security()
            await self.assess_dns_health()
            await self.assess_ssl_tls_security()
            await self.assess_http_security()
            await self.assess_vulnerability_assessment()
            await self.assess_technology_detection()
            
            # Run Google dorking and typosquatting checks
            await self.assess_google_dorking()
            await self.assess_typosquatting()
            
            # Run subdomain discovery if enabled
            if scan_subdomains:
                await self.assess_subdomain_discovery()
            
            # Store results
            self.store_results()
            
            # Calculate overall risk
            self.calculate_overall_risk()
            
            # Return results in the structure expected by frontend
            return {
                'results': self.results,  # Frontend expects results under 'results' key
                'scan_subdomains_requested': scan_subdomains  # Keep the flag
            }

        except Exception as e:
             # Added detailed logging
            self.console.print(f"[bold red]Critical Error during run_scan execution: {str(e)}[/bold red]")
            logger.exception("Exception during scan execution:") # Log full traceback
                
            return {
                'status': 'error',
                'message': f'Scan failed: {str(e)}',
                'results': self.results # Still returns potentially empty/partial results
            }

    def calculate_overall_risk(self) -> None:
        """Calculate overall risk score based on findings"""
        risk_score = 0
        total_issues = 0
        critical_issues = 0
        
        # Weight factors for different severity levels
        severity_weights = {
            'Critical': 10,
            'High': 7,
            'Medium': 4,
            'Low': 1
        }
        
        # Calculate risk score from all assessment results
        for category, results in self.results.items():
            if isinstance(results, dict):
                # Check for issues in each category
                if 'issues' in results:
                    for issue in results['issues']:
                        total_issues += 1
                        if isinstance(issue, dict) and 'severity' in issue:
                            severity = issue['severity']
                            if severity in severity_weights:
                                risk_score += severity_weights[severity]
                                if severity in ['Critical', 'High']:
                                    critical_issues += 1
                
                # Check for vulnerabilities
                if 'common_vulnerabilities' in results:
                    for vuln in results['common_vulnerabilities']:
                        total_issues += 1
                        if 'severity' in vuln:
                            severity = vuln['severity']
                            if severity in severity_weights:
                                risk_score += severity_weights[severity]
                                if severity in ['Critical', 'High']:
                                    critical_issues += 1
        
        # Normalize risk score (0-100)
        max_possible_score = total_issues * 10  # Assuming all issues are critical
        normalized_score = (risk_score / max_possible_score) * 100 if max_possible_score > 0 else 0
        
        # Add risk metrics to results
        self.results['risk_metrics'] = {
            'total_issues': total_issues,
            'critical_issues': critical_issues,
            'risk_score': round(normalized_score, 2),
            'risk_level': self.get_risk_level(normalized_score)
        }

    def get_risk_level(self, score: float) -> str:
        """Convert risk score to risk level"""
        if score >= 80:
            return 'Critical'
        elif score >= 60:
            return 'High'
        elif score >= 40:
            return 'Medium'
        elif score >= 20:
            return 'Low'
        else:
            return 'Very Low'

    def generate_report(self) -> str:
        """Generate a comprehensive security report"""
        report = f"""
Security Assessment Report
=========================
Target: {self.target}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Executive Summary
----------------
Total Vulnerabilities: {self.results['vulnerability_assessment']['metrics']['total_vulnerabilities']}
Critical Vulnerabilities: {self.results['vulnerability_assessment']['metrics']['critical_vulnerabilities']}
High Vulnerabilities: {self.results['vulnerability_assessment']['metrics']['high_vulnerabilities']}
Average Risk Score: {self.results['vulnerability_assessment']['metrics']['average_risk_score']:.2f}

Risk Analysis
------------
Severity Distribution:
{self.format_distribution(self.results['vulnerability_assessment']['risk_analysis']['severity_distribution'])}

Exploitability Distribution:
{self.format_distribution(self.results['vulnerability_assessment']['risk_analysis']['exploitability_distribution'])}

Impact Analysis:
{self.format_impact_analysis(self.results['vulnerability_assessment']['risk_analysis']['impact_analysis'])}

Performance Metrics
-----------------
Mean Time to Detect (MTTD): {self.results['vulnerability_assessment']['metrics']['mttd']:.2f} days
Mean Time to Remediate (MTTR): {self.results['vulnerability_assessment']['metrics']['mttr']:.2f} days

Remediation Priorities
--------------------
"""
        
        for priority in self.results['vulnerability_assessment']['remediation_priorities']:
            report += f"""
Vulnerability: {priority['vulnerability']['type']}
Priority Level: {priority['priority_level']}
Timeline: {priority['recommended_timeline']}
Recommended Team: {priority['responsible_team']}
Risk Score: {priority['vulnerability']['risk_score']}
Impact: {priority['vulnerability']['impact']}
"""
            
        return report

    async def send_slack_report(self, channel: str) -> None:
        """Send the assessment report to Slack"""
        if not self.slack_client:
            self.console.print("[yellow]Skipping Slack report - no Slack token configured[/yellow]")
            return
            
        try:
            # Create a formatted message for Slack
            message = f"""
*Security Assessment Report for {self.target}*
Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

*Network Security*
• IP Information: {self.results['network_security'].get('ip_info', {})}
• DNS Records: {self.results['network_security'].get('dns_info', {})}
• WHOIS Information: {self.results['network_security'].get('whois_info', {})}
• Open Ports: {len(self.results['network_security'].get('port_scan', {}).get('open_ports', []))}
• Services: {len(self.results['network_security'].get('port_scan', {}).get('services', []))}

*Email Security*
• Validation: {self.results['email_security'].get('validation', {})}
• Domain Security: {self.results['email_security'].get('domain_security', {})}
• Server Configuration: {self.results['email_security'].get('server_config', {})}
• Security Headers: {self.results['email_security'].get('security_headers', {})}
• Authentication: {self.results['email_security'].get('authentication', {})}
• Reputation: {self.results['email_security'].get('reputation', {})}
• Best Practices: {self.results['email_security'].get('best_practices', {})}
• Phishing Risk Score: {self.results['email_security'].get('phishing_risk', {}).get('score', 0)}
• Phishing Risk Factors: {', '.join(self.results['email_security'].get('phishing_risk', {}).get('factors', []))}

*DNS Health*
• Security Records: {self.results['dns_health'].get('security_records', {})}
• Issues: {', '.join(self.results['dns_health'].get('issues', [])) if self.results['dns_health'].get('issues', []) else 'None'}

*HTTP Security*
• Security Headers: {', '.join(self.results['http_security'].get('security_headers', {}).keys())}
• Issues: {', '.join(self.results['http_security'].get('issues', [])) if self.results['http_security'].get('issues', []) else 'None'}

*Vulnerability Assessment*
• Common Vulnerabilities: {len(self.results['vulnerability_assessment'].get('common_vulnerabilities', []))}
• Security Issues: {len(self.results['vulnerability_assessment'].get('security_issues', []))}

*IP Reputation*
• IP Information: {self.results['ip_reputation'].get('ip_info', {})}
• Reputation Data: {self.results['ip_reputation'].get('reputation_data', {})}

*SSL/TLS Security*
• Certificate Information: {self.results['ssl_tls_security'].get('certificate_info', {})}
• Security Issues: {', '.join(self.results['ssl_tls_security'].get('security_issues', [])) if self.results['ssl_tls_security'].get('security_issues', []) else 'None'}

*API Security*
• Issues Found: {len(self.results['api_security'].get('issues', []))}
• Issues: {', '.join(self.results['api_security'].get('issues', [])) if self.results['api_security'].get('issues', []) else 'None'}

*Container Security*
• Issues Found: {len(self.results['container_security'].get('issues', []))}
• Issues: {', '.join(self.results['container_security'].get('issues', [])) if self.results['container_security'].get('issues', []) else 'None'}

*Database Security*
• Issues Found: {len(self.results['database_security'].get('issues', []))}
• Issues: {', '.join(self.results['database_security'].get('issues', [])) if self.results['database_security'].get('issues', []) else 'None'}

*Patching Status*
• Server Information: {self.results['patching_status'].get('server_info', {})}
• Security Headers: {', '.join(self.results['patching_status'].get('security_headers', {}).keys())}
• Issues: {', '.join(self.results['patching_status'].get('issues', [])) if self.results['patching_status'].get('issues', []) else 'None'}

*Compliance*
• Standards: {', '.join(self.results['compliance'].get('standards', {}).keys())}
• Findings: {len(self.results['compliance'].get('findings', []))}

*Asset Inventory*
• Asset Types: {', '.join(self.results['asset_inventory'].get('asset_types', {}).keys())}
• Risk Levels: {self.results['asset_inventory'].get('risk_levels', {})}
"""
            
            # Send the message to Slack
            self.slack_client.chat_postMessage(
                channel=channel,
                text=message,
                parse='mrkdwn'
            )
        except SlackApiError as e:
            self.console.print(f"[red]Error sending Slack message: {str(e)}[/red]")

    def format_distribution(self, distribution: Dict) -> str:
        """Format distribution data for report"""
        return "\n".join(f"{k}: {v}" for k, v in distribution.items())

    def format_impact_analysis(self, impact: Dict) -> str:
        """Format impact analysis data for report"""
        return "\n".join(f"{k.replace('_', ' ').title()}: {v}" for k, v in impact.items())

    async def assess_ip_reputation(self) -> None:
        """Assess IP reputation using external services like AbuseIPDB."""
        print("--- Starting assess_ip_reputation ---")
        # Initialize ip_info_dict with default error state
        ip_info_dict = {'ip_info': {}, 'reputation_data': {}, 'error': 'Initialization error'}
        # Initialize reputation_data here to ensure it exists even if IP resolution fails
        reputation_data = {"abuseipdb": {"status": "Not Checked", "error": None}}

        try:
            # --- Get IP Address ---
            ip_info_dict = {'ip_info': {}, 'reputation_data': {}, 'error': 'IP resolution failed'}
            print(f"--- assess_ip_reputation: Resolving IP for {self.target} ---")
            resolved_ip = socket.gethostbyname(self.target)
            # Update dict only if resolution succeeds
            ip_info_dict["ip_info"] = {"ip_address": resolved_ip, "hostname": "Hostname lookup disabled"}
            # ip_info_dict["ip_info"]["hostname"] = socket.gethostbyaddr(resolved_ip)[0] # Hostname lookup disabled
            ip_info_dict['error'] = None # Clear error if IP resolved
            print(f"--- assess_ip_reputation: Got IP: {resolved_ip} ---")

            # --- AbuseIPDB Reputation Check --- 
            reputation_data = {
                 "abuseipdb": { "status": "Not Checked", "error": None },
                 # Keep placeholders for others for now
                 "virustotal": {"status": "clean (placeholder)"},
                 "spamhaus": {"status": "clean (placeholder)"}
            }

            # Only proceed if IP resolution was successful
            if resolved_ip:
                try:
                    abuseipdb_key = os.getenv('ABUSEIPDB_API_KEY')
                    if not abuseipdb_key:
                        reputation_data["abuseipdb"]['error'] = "API Key not configured."
                        reputation_data["abuseipdb"]['status'] = "Configuration Error"
                        raise ValueError("AbuseIPDB API Key not found in environment.")
                    
                    print(f"--- assess_ip_reputation: Checking IP {resolved_ip} with AbuseIPDB ---")
                    url = 'https://api.abuseipdb.com/api/v2/check'
                    headers = {
                        'Accept': 'application/json',
                        'Key': abuseipdb_key
                    }
                    params = {
                        'ipAddress': resolved_ip,
                        'maxAgeInDays': '90' # Check reports within the last 90 days
                        # 'verbose': 'true' # Add if more details are needed later
                    }

                    response = self.session.get(url, headers=headers, params=params, timeout=15)
                    response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

                    api_result = response.json()

                    # Check if the 'data' key exists
                    if 'data' in api_result:
                        abuse_data = api_result['data']
                        reputation_data["abuseipdb"] = {
                            "status": "Checked",
                            "ipAddress": abuse_data.get("ipAddress"),
                            "isPublic": abuse_data.get("isPublic"),
                            "ipVersion": abuse_data.get("ipVersion"),
                            "isWhitelisted": abuse_data.get("isWhitelisted"),
                            "abuseConfidenceScore": abuse_data.get("abuseConfidenceScore"),
                            "countryCode": abuse_data.get("countryCode"),
                            "usageType": abuse_data.get("usageType"),
                            "isp": abuse_data.get("isp"),
                            "domain": abuse_data.get("domain"),
                            "totalReports": abuse_data.get("totalReports"),
                            "lastReportedAt": abuse_data.get("lastReportedAt"),
                            "error": None # Explicitly set error to None on success
                        }
                    elif 'errors' in api_result: # Handle API-level errors reported by AbuseIPDB
                         error_detail = api_result['errors'][0]['detail']
                         reputation_data["abuseipdb"]['error'] = f"AbuseIPDB API Error: {error_detail}"
                         reputation_data["abuseipdb"]['status'] = "API Error"
                         print(f"--- assess_ip_reputation: AbuseIPDB API Error: {error_detail} ---")
                    else:
                         # Handle unexpected response structure
                         reputation_data["abuseipdb"]['error'] = "Unexpected response structure from AbuseIPDB."
                         reputation_data["abuseipdb"]['status'] = "Response Error"
                         print("--- assess_ip_reputation: Unexpected AbuseIPDB response structure ---")

                except requests.exceptions.Timeout:
                    err = "Timeout connecting to AbuseIPDB API."
                    print(f"--- assess_ip_reputation: Exception - {err} ---")
                    reputation_data["abuseipdb"]['error'] = err
                    reputation_data["abuseipdb"]['status'] = "Error"
                except requests.exceptions.RequestException as e:
                    err = f"Error connecting to AbuseIPDB API: {e}"
                    print(f"--- assess_ip_reputation: Exception - {err} ---")
                    reputation_data["abuseipdb"]['error'] = err
                    reputation_data["abuseipdb"]['status'] = "Error"
                except ValueError as e: # Catch missing API key error
                     err = str(e)
                     print(f"--- assess_ip_reputation: Exception - {err} ---")
                     # Error already set in this case
                     # Status already set above
                     pass # API Key error is handled
                except Exception as e:
                     err = f"Unexpected error during AbuseIPDB check: {e}"
                     print(f"--- assess_ip_reputation: Exception - {err} ---")
                     reputation_data["abuseipdb"]['error'] = err
                     reputation_data["abuseipdb"]['status'] = "Error"
            else: # This else corresponds to `if resolved_ip:`
                 print("--- assess_ip_reputation: Skipping AbuseIPDB check due to failed IP resolution ---")
                 reputation_data["abuseipdb"]['error'] = "Skipped (IP resolution failed)"
                 reputation_data["abuseipdb"]['status'] = "Skipped"
            # End of the `if resolved_ip:` block

            ip_info_dict['reputation_data'] = reputation_data
            # --- End AbuseIPDB Check ---

        except socket.gaierror as e: # Handle IP resolution failure
            err = f"Could not resolve IP address for {self.target}: {e}"
            print(f"--- assess_ip_reputation: Exception - {err} ---")
            # Error was potentially set during initialization, update for specificity
            ip_info_dict['error'] = err 
            # Keep reputation_data as 'Not Checked' but reflect skip reason
            reputation_data["abuseipdb"]['status'] = "Skipped"
            reputation_data["abuseipdb"]['error'] = "Skipped (IP resolution failed)"
            ip_info_dict['reputation_data'] = reputation_data # Ensure reputation data reflects skip
        except Exception as e: # Catch other unexpected errors in the main try block
             err = f"Unexpected error in assess_ip_reputation for {self.target}: {e}"
             print(f"--- assess_ip_reputation: Major Exception - {err} ---")
             logger.exception("Unexpected IP Reputation Error")
             ip_info_dict['error'] = err
             # Ensure reputation data reflects the error state
             reputation_data["abuseipdb"]['status'] = "Error"
             reputation_data["abuseipdb"]['error'] = "Unexpected error during assessment."
             ip_info_dict['reputation_data'] = reputation_data

        # --- FINAL PART (Assign results regardless of errors) ---
        self.results['ip_reputation'] = ip_info_dict
        print(f"--- Exiting assess_ip_reputation with final data: {json.dumps(ip_info_dict, default=str)} ---")

    async def assess_ssl_tls_security(self) -> None:
        """Perform SSL/TLS security assessment"""
        if not self.target:
            return
            
        self.console.print(f"[bold blue]Starting SSL/TLS security assessment...[/bold blue]")
        
        ssl_info = {
            'certificate_info': {},
            'security_issues': []
        }
        
        try:
            # Get certificate information
            try:
                context = ssl.create_default_context()
                with socket.create_connection((self.target, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                        cert = ssock.getpeercert()
                        # Parse the date string into a datetime object
                        expiry_date_str = cert['notAfter']
                        # Standard format: 'Month Day HH:MM:SS YYYY Timezone'
                        expiry_datetime = datetime.strptime(expiry_date_str, '%b %d %H:%M:%S %Y %Z')
                        # Convert expiry_datetime to offset-naive for comparison if needed, or make now() offset-aware
                        # Assuming datetime.now() is naive for simplicity here, adjust if server uses timezone-aware datetimes
                        is_expired = expiry_datetime.replace(tzinfo=None) < datetime.now()

                        ssl_info['certificate_info'] = {
                            'issuer': dict(x[0] for x in cert['issuer']),
                            'subject': dict(x[0] for x in cert['subject']),
                            'valid_from': cert['notBefore'],
                            'valid_to': expiry_date_str, # Keep original string format for display
                            'expiry_datetime_obj': expiry_datetime, # Store the datetime object if needed elsewhere
                            'is_expired': is_expired # Use the calculated boolean
                        }
            except ssl.SSLCertVerificationError as e:
                # Handle specific cert verification errors
                ssl_info['certificate_info']['error'] = f"Certificate Verification Error: {e.reason}"
                ssl_info['security_issues'].append('SSL certificate verification failed')
            except socket.timeout:
                 ssl_info['certificate_info']['error'] = "Connection timed out during SSL/TLS check."
                 ssl_info['security_issues'].append('SSL/TLS check timed out')
            except ConnectionRefusedError:
                 ssl_info['certificate_info']['error'] = "Connection refused on port 443."
                 ssl_info['security_issues'].append('Connection refused on port 443')
            except Exception as e:
                # General exception handling
                error_message = f"SSL/TLS assessment failed: {str(e)}"
                ssl_info['certificate_info']['error'] = error_message
                ssl_info['security_issues'].append('SSL/TLS assessment failed')
                self.console.print(f"[yellow]Warning: {error_message}[/yellow]")

            # Check for other security issues based on the cert info we got (if any)
            cert_data = ssl_info['certificate_info']
            if 'is_expired' in cert_data and cert_data['is_expired']:
                # Check if already added before adding again
                if 'SSL/TLS certificate expired' not in ssl_info['security_issues']:
                    ssl_info['security_issues'].append('SSL/TLS certificate expired')

            # Ensure the 'security_issues' list is populated even if cert fetching failed partially
            # (Redundant if already added in except blocks, but safe)
            if 'error' in cert_data and 'SSL/TLS assessment failed' not in ssl_info['security_issues'] and 'SSL certificate verification failed' not in ssl_info['security_issues']:
                 ssl_info['security_issues'].append('SSL/TLS assessment failed due to error')

            # Clean up potential duplicate error messages in issues list
            ssl_info['security_issues'] = list(set(ssl_info['security_issues']))

        except Exception as e:
            # Catch-all for unexpected errors *outside* the cert fetching block
            self.console.print(f"[yellow]Warning: Unexpected error in SSL/TLS security assessment: {str(e)}[/yellow]")
            ssl_info['error'] = f"Unexpected assessment error: {str(e)}"
            if 'SSL/TLS assessment failed' not in ssl_info['security_issues']:
                 ssl_info['security_issues'].append('SSL/TLS assessment failed')

        self.results['ssl_tls_security'] = ssl_info

    async def assess_api_security(self) -> None:
        """Assess API security"""
        try:
            self.console.print("Starting API security assessment...")
            
            # Test API endpoints
            endpoints = [
                f"https://{self.target}/api/v1/health",
                f"https://{self.target}/api/v1/status",
                f"https://{self.target}/api/v1/info",
                f"https://{self.target}/api/v1/users",
                f"https://{self.target}/api/v1/auth"
            ]
            
            api_results = {
                'endpoints': [],
                'security_headers': {},
                'authentication': {},
                'rate_limiting': {},
                'input_validation': {}
            }
            
            for endpoint in endpoints:
                try:
                    # Test with different HTTP methods
                    methods = ['GET', 'POST', 'PUT', 'DELETE']
                    endpoint_results = {
                        'url': endpoint,
                        'methods': {}
                    }
                    
                    for method in methods:
                        try:
                            response = self.session.request(
                                method=method,
                                url=endpoint,
                                timeout=10,
                                verify=True
                            )
                            
                            endpoint_results['methods'][method] = {
                                'status_code': response.status_code,
                                'headers': dict(response.headers),
                                'security_headers': {
                                    'X-Frame-Options': response.headers.get('X-Frame-Options', 'Not Set'),
                                    'X-Content-Type-Options': response.headers.get('X-Content-Type-Options', 'Not Set'),
                                    'Strict-Transport-Security': response.headers.get('Strict-Transport-Security', 'Not Set'),
                                    'Content-Security-Policy': response.headers.get('Content-Security-Policy', 'Not Set')
                                }
                            }
                        except requests.exceptions.RequestException as e:
                            endpoint_results['methods'][method] = {
                                'error': str(e)
                            }
                    
                    api_results['endpoints'].append(endpoint_results)
                    
                except Exception as e:
                    api_results['endpoints'].append({
                        'url': endpoint,
                        'error': str(e)
                    })
            
            # Analyze security headers
            security_headers = {}
            for endpoint in api_results['endpoints']:
                if 'methods' in endpoint:
                    for method, data in endpoint['methods'].items():
                        if 'security_headers' in data:
                            for header, value in data['security_headers'].items():
                                if header not in security_headers:
                                    security_headers[header] = []
                                if value not in security_headers[header]:
                                    security_headers[header].append(value)
            
            api_results['security_headers'] = security_headers
            
            # Store results
            self.results['api_security'] = api_results
            
        except Exception as e:
            logger.error(f"API security assessment error: {str(e)}")
            self.results['api_security'] = {'error': str(e)}

    async def assess_container_security(self) -> None:
        """Perform container security assessment"""
        if not self.target:
            return
            
        self.console.print(f"[bold blue]Starting container security assessment...[/bold blue]")
        
        container_info = {
            'image_scan': {},
            'runtime_scan': {},
            'config_scan': {},
            'issues': []
        }
        
        try:
            # Check for container-related headers and configurations
            try:
                response = requests.get(f"https://{self.target}", verify=False, timeout=5)
                headers = response.headers
                
                # Check for container-related headers
                container_headers = {
                    k: v for k, v in headers.items()
                    if k.lower() in [
                        'x-container-id',
                        'x-container-name',
                        'x-docker-container',
                        'x-kubernetes-pod',
                        'x-kubernetes-namespace'
                    ]
                }
                
                container_info['runtime_scan'] = {
                    'headers_found': bool(container_headers),
                    'container_headers': container_headers,
                    'server_type': headers.get('Server', 'Unknown')
                }
            except:
                pass
            
            # Check for container configuration issues
            config_issues = []
            
            # Check for exposed sensitive data in environment
            if any(sensitive in str(os.getenv('DOCKER_IMAGE', '')).lower() for sensitive in ['password', 'key', 'secret']):
                config_issues.append('Exposed sensitive data in container environment')
            
            # Check for privileged mode
            if os.getenv('DOCKER_PRIVILEGED', 'false').lower() == 'true':
                config_issues.append('Container running in privileged mode')
            
            # Check for exposed ports
            exposed_ports = os.getenv('DOCKER_EXPOSED_PORTS', '')
            if exposed_ports:
                config_issues.append(f'Container exposing ports: {exposed_ports}')
            
            container_info['config_scan'] = {
                'issues': config_issues,
                'privileged_mode': os.getenv('DOCKER_PRIVILEGED', 'false').lower() == 'true',
                'exposed_ports': exposed_ports.split(',') if exposed_ports else []
            }
            
            # Check for image security
            image_info = {
                'base_image': os.getenv('DOCKER_BASE_IMAGE', 'Unknown'),
                'image_size': os.getenv('DOCKER_IMAGE_SIZE', 'Unknown'),
                'layers': os.getenv('DOCKER_LAYERS', 'Unknown'),
                'vulnerabilities': []
            }
            
            # Check for common vulnerable base images
            vulnerable_bases = ['alpine:3.1', 'ubuntu:14.04', 'debian:7']
            if image_info['base_image'] in vulnerable_bases:
                image_info['vulnerabilities'].append(f'Using vulnerable base image: {image_info["base_image"]}')
            
            container_info['image_scan'] = image_info
            
            # Combine all issues
            container_info['issues'] = (
                config_issues +
                image_info['vulnerabilities'] +
                (['Container runtime information exposed'] if container_info['runtime_scan']['headers_found'] else [])
            )
            
        except Exception as e:
            self.console.print(f"[yellow]Warning: Container security assessment error: {str(e)}[/yellow]")
            
        self.results['container_security'] = container_info

    async def assess_database_security(self) -> None:
        """Perform database security assessment"""
        if not self.target:
            return
            
        self.console.print(f"[bold blue]Starting database security assessment...[/bold blue]")
        
        db_info = {
            'config_scan': {},
            'access_scan': {},
            'backup_scan': {},
            'encryption_scan': {},
            'audit_scan': {},
            'issues': []
        }
        
        try:
            # Check for database configuration issues
            config_issues = []
            
            # Check for exposed sensitive data in environment
            if any(sensitive in str(os.getenv('DATABASE_URL', '')).lower() for sensitive in ['password', 'key', 'secret']):
                config_issues.append('Exposed sensitive data in database configuration')
            
            # Check for default credentials
            default_creds = [
                ('root', 'root'),
                ('admin', 'admin'),
                ('postgres', 'postgres'),
                ('mysql', 'mysql')
            ]
            for user, passwd in default_creds:
                if user in str(os.getenv('DATABASE_URL', '')).lower() and passwd in str(os.getenv('DATABASE_URL', '')).lower():
                    config_issues.append(f'Using default credentials: {user}/{passwd}')
            
            db_info['config_scan'] = {
                'issues': config_issues,
                'has_encryption': 'ssl=true' in str(os.getenv('DATABASE_URL', '')).lower(),
                'has_connection_pooling': 'pool_size' in str(os.getenv('DATABASE_URL', '')).lower()
            }
            
            # Check for access control issues
            access_issues = []
            
            # Check for public access
            if 'public' in str(os.getenv('DATABASE_URL', '')).lower():
                access_issues.append('Database potentially accessible from public network')
            
            # Check for weak authentication
            if 'auth=scram-sha-256' not in str(os.getenv('DATABASE_URL', '')).lower():
                access_issues.append('Using weak authentication method')
            
            db_info['access_scan'] = {
                'issues': access_issues,
                'has_public_access': 'public' in str(os.getenv('DATABASE_URL', '')).lower(),
                'has_strong_auth': 'auth=scram-sha-256' in str(os.getenv('DATABASE_URL', '')).lower()
            }
            
            # Check for backup configuration
            backup_issues = []
            
            # Check for backup schedule
            if not os.getenv('DB_BACKUP_SCHEDULE'):
                backup_issues.append('No backup schedule configured')
            
            # Check for backup retention
            if not os.getenv('DB_BACKUP_RETENTION'):
                backup_issues.append('No backup retention policy configured')
            
            db_info['backup_scan'] = {
                'issues': backup_issues,
                'has_backup_schedule': bool(os.getenv('DB_BACKUP_SCHEDULE')),
                'has_backup_retention': bool(os.getenv('DB_BACKUP_RETENTION'))
            }

            # Check for encryption
            encryption_issues = []
            
            # Check for TLS/SSL
            if 'ssl=true' not in str(os.getenv('DATABASE_URL', '')).lower():
                encryption_issues.append('TLS/SSL not enabled for database connections')
            
            # Check for data-at-rest encryption
            if not os.getenv('DB_ENCRYPTION_ENABLED'):
                encryption_issues.append('Data-at-rest encryption not configured')
            
            db_info['encryption_scan'] = {
                'issues': encryption_issues,
                'has_tls': 'ssl=true' in str(os.getenv('DATABASE_URL', '')).lower(),
                'has_data_at_rest_encryption': bool(os.getenv('DB_ENCRYPTION_ENABLED'))
            }

            # Check for audit logging
            audit_issues = []
            
            # Check for audit logging configuration
            if not os.getenv('DB_AUDIT_ENABLED'):
                audit_issues.append('Database audit logging not enabled')
            
            # Check for audit retention
            if not os.getenv('DB_AUDIT_RETENTION'):
                audit_issues.append('No audit log retention policy configured')
            
            db_info['audit_scan'] = {
                'issues': audit_issues,
                'has_audit_logging': bool(os.getenv('DB_AUDIT_ENABLED')),
                'has_audit_retention': bool(os.getenv('DB_AUDIT_RETENTION'))
            }
            
            # Combine all issues
            db_info['issues'] = (
                config_issues +
                access_issues +
                backup_issues +
                encryption_issues +
                audit_issues
            )
            
        except Exception as e:
            self.console.print(f"[yellow]Warning: Database security assessment error: {str(e)}[/yellow]")
            
        self.results['database_security'] = db_info

    async def assess_patching_status(self) -> None:
        """Perform passive patching status assessment"""
        if not self.target:
            return
            
        self.console.print(f"[bold blue]Starting passive patching status assessment...[/bold blue]")
        
        patch_info = {
            'server_info': {},
            'security_headers': {},
            'issues': []
        }
        
        try:
            # Get server information
            try:
                response = requests.get(f'https://{self.target}', timeout=5, verify=False)
                patch_info['server_info'] = {
                    'server': response.headers.get('Server', 'Unknown'),
                    'powered_by': response.headers.get('X-Powered-By', 'Unknown')
                }
            except Exception as e:
                patch_info['server_info']['error'] = str(e)
            
            # Check for security issues based on server information
            issues = []
            server_info = patch_info['server_info']
            
            # Check for outdated server versions based on known patterns
            if 'apache' in server_info.get('server', '').lower(): # Added .get()
                version = server_info['server'].split('/')[-1]
                if version and version < '2.4.0': # This comparison might need refinement
                    issues.append('Outdated Apache version detected')
                    
            if 'nginx' in server_info.get('server', '').lower(): # Added .get()
                version = server_info['server'].split('/')[-1]
                if version and version < '1.14.0': # This comparison might need refinement
                    issues.append('Outdated Nginx version detected')
                    
            patch_info['issues'] = issues
            
        except Exception as e:
            self.console.print(f"[yellow]Warning: Patching status assessment error: {str(e)}[/yellow]")
            
        self.results['patching_status'] = patch_info

    async def assess_compliance(self) -> None:
        """Assess compliance with security standards"""
        self.console.print(f"[bold blue]Starting compliance assessment...[/bold blue]")
        
        compliance_info = {
            'standards': {},
            'findings': [],
            'recommendations': []
        }
        
        try:
            # Check for PCI DSS compliance
            pci_findings = await self.check_pci_compliance()
            compliance_info['standards']['PCI DSS'] = pci_findings
            
            # Check for HIPAA compliance
            hipaa_findings = await self.check_hipaa_compliance()
            compliance_info['standards']['HIPAA'] = hipaa_findings
            
            # Check for GDPR compliance
            gdpr_findings = await self.check_gdpr_compliance()
            compliance_info['standards']['GDPR'] = gdpr_findings

            # Check for ISO 27001 compliance
            iso_findings = await self.check_iso27001_compliance()
            compliance_info['standards']['ISO 27001'] = iso_findings

            # Check for SOC 2 compliance
            soc_findings = await self.check_soc2_compliance()
            compliance_info['standards']['SOC 2'] = soc_findings
            
        except Exception as e:
            self.console.print(f"[yellow]Warning: Compliance assessment error: {str(e)}[/yellow]")
            
        self.results['compliance'] = compliance_info

    async def check_pci_compliance(self) -> Dict:
        """Check PCI DSS compliance requirements"""
        findings = {
            'requirements': {},
            'status': 'Compliant', # Assume compliant initially
            'issues': []
        }
        
        try:
            # Check for SSL/TLS
            if not self.results.get('ssl_tls_security', {}).get('certificate_info'):
                findings['issues'].append('SSL/TLS not properly configured')
                findings['status'] = 'Non-Compliant'
                
            # Check for security headers
            headers = self.results.get('http_security', {}).get('headers', {}) # Changed source
            required_headers = [
                'Strict-Transport-Security',
                'X-Frame-Options',
                'X-Content-Type-Options'
                # 'X-XSS-Protection' is deprecated/often harmful
            ]
            
            for header in required_headers:
                if header not in headers or headers[header] in ['Not Set', 'Disabled', '']:
                    findings['issues'].append(f'Missing/insecure required security header: {header}')
                    findings['status'] = 'Non-Compliant'
                    
            # Check for detected vulnerabilities
            if self.results.get('vulnerability_assessment', {}).get('common_vulnerabilities'):
                findings['issues'].append('Potential vulnerabilities detected (review assessment)')
                findings['status'] = 'Non-Compliant'
                
        except Exception as e:
            findings['issues'].append(f'Error checking PCI compliance: {str(e)}')
            findings['status'] = 'Error'
            
        return findings

    async def check_hipaa_compliance(self) -> Dict:
        """Check HIPAA compliance requirements"""
        findings = {
            'requirements': {},
            'status': 'Compliant', # Assume compliant initially
            'issues': []
        }
        
        try:
            # Check for encryption (TLS)
            if not self.results.get('ssl_tls_security', {}).get('certificate_info'):
                findings['issues'].append('Encryption (SSL/TLS) not properly configured')
                findings['status'] = 'Non-Compliant'
                
            # Check for access controls (inferred from vulnerabilities)
            if self.results.get('vulnerability_assessment', {}).get('common_vulnerabilities'):
                 # Filter for access control related issues if possible (e.g., SQLi, Auth issues)
                if any(v.get('type') == 'SQL Injection' for v in self.results['vulnerability_assessment']['common_vulnerabilities']):
                    findings['issues'].append('Potential access control issues detected (review vulnerabilities)')
                    findings['status'] = 'Non-Compliant'
                
            # Check for audit logging (Placeholder - hard to verify passively)
            # if not self.results.get('http_security', {}).get('headers', {}).get('X-Audit-Log'):
            #     findings['issues'].append('Audit logging not verified (passive check)')
                
        except Exception as e:
            findings['issues'].append(f'Error checking HIPAA compliance: {str(e)}')
            findings['status'] = 'Error'
            
        return findings

    async def check_gdpr_compliance(self) -> Dict:
        """Check GDPR compliance requirements"""
        findings = {
            'requirements': {},
            'status': 'Compliant', # Assume compliant initially
            'issues': []
        }
        
        try:
            # Check for data protection (TLS)
            if not self.results.get('ssl_tls_security', {}).get('certificate_info'):
                findings['issues'].append('Data protection (SSL/TLS) measures not properly configured')
                findings['status'] = 'Non-Compliant'
                
            # Check for privacy headers (basic check)
            headers = self.results.get('http_security', {}).get('headers', {})
            # if 'Privacy-Policy' not in headers: # This header is not standard
            #     findings['issues'].append('Privacy policy header not found (manual verification needed)')
            if 'Content-Security-Policy' not in headers or headers['Content-Security-Policy'] in ['Not Set', '']:
                 findings['issues'].append('Content-Security-Policy missing or weak (potential privacy impact)')
                 findings['status'] = 'Non-Compliant'
                 
            # Check for data minimization (inferred from vulnerabilities)
            # if self.results.get('vulnerability_assessment', {}).get('common_vulnerabilities'):
            #     findings['issues'].append('Potential data minimization issues (review vulnerabilities)')
            #     findings['status'] = 'Non-Compliant'
                
        except Exception as e:
            findings['issues'].append(f'Error checking GDPR compliance: {str(e)}')
            findings['status'] = 'Error'
            
        return findings

    async def check_iso27001_compliance(self) -> Dict:
        """Check ISO 27001 compliance requirements"""
        findings = {
            'requirements': {},
            'status': 'Compliant', # Assume compliant initially
            'issues': []
        }
        
        try:
            # Check for information security policy
            if not self.results.get('http_security', {}).get('headers', {}).get('X-Security-Policy'):
                findings['issues'].append('Information security policy not documented')
                findings['status'] = 'Non-Compliant'
                
            # Check for access control
            if self.results.get('vulnerability_assessment', {}).get('common_vulnerabilities'):
                if any(v.get('type') in ['SQL Injection', 'Authentication Bypass'] for v in self.results['vulnerability_assessment']['common_vulnerabilities']):
                    findings['issues'].append('Access control issues detected')
                    findings['status'] = 'Non-Compliant'
                
            # Check for cryptography
            if not self.results.get('ssl_tls_security', {}).get('certificate_info'):
                findings['issues'].append('Cryptography controls not properly implemented')
                findings['status'] = 'Non-Compliant'
                
            # Check for operations security
            if not self.results.get('database_security', {}).get('backup_scan', {}).get('has_backup_schedule'):
                findings['issues'].append('Operations security controls (backups) not implemented')
                findings['status'] = 'Non-Compliant'
                
        except Exception as e:
            findings['issues'].append(f'Error checking ISO 27001 compliance: {str(e)}')
            findings['status'] = 'Error'
            
        return findings

    async def check_soc2_compliance(self) -> Dict:
        """Check SOC 2 compliance requirements"""
        findings = {
            'requirements': {},
            'status': 'Compliant', # Assume compliant initially
            'issues': []
        }
        
        try:
            # Check for security (common criteria)
            if not self.results.get('ssl_tls_security', {}).get('certificate_info'):
                findings['issues'].append('Security controls not properly implemented')
                findings['status'] = 'Non-Compliant'
                
            # Check for availability
            if not self.results.get('database_security', {}).get('backup_scan', {}).get('has_backup_schedule'):
                findings['issues'].append('Availability controls (backups) not implemented')
                findings['status'] = 'Non-Compliant'
                
            # Check for processing integrity
            if self.results.get('vulnerability_assessment', {}).get('common_vulnerabilities'):
                if any(v.get('type') in ['SQL Injection', 'Data Validation'] for v in self.results['vulnerability_assessment']['common_vulnerabilities']):
                    findings['issues'].append('Processing integrity issues detected')
                    findings['status'] = 'Non-Compliant'
                
            # Check for confidentiality
            if not self.results.get('database_security', {}).get('encryption_scan', {}).get('has_tls'):
                findings['issues'].append('Confidentiality controls (encryption) not implemented')
                findings['status'] = 'Non-Compliant'
                
            # Check for privacy
            if not self.results.get('http_security', {}).get('headers', {}).get('Content-Security-Policy'):
                findings['issues'].append('Privacy controls not properly implemented')
                findings['status'] = 'Non-Compliant'
                
        except Exception as e:
            findings['issues'].append(f'Error checking SOC 2 compliance: {str(e)}')
            findings['status'] = 'Error'
            
        return findings

    async def assess_asset_inventory(self) -> None:
        """Manage and track discovered assets"""
        self.console.print(f"[bold blue]Starting asset management...[/bold blue]")
        
        asset_info = {
            'discovered_assets': [],
            'asset_types': {},
            'risk_levels': {},
            'criticality': {},
            'sensitivity': {},
            'business_impact': {},
            'asset_relationships': {},
            'asset_owners': {},
            'asset_status': {}
        }
        
        try:
            # Collect assets from various assessments
            assets = []
            
            # Network assets (using detailed service info)
            network_sec = self.results.get('network_security', {})
            if network_sec.get('passive_service_info', {}).get('shodan', {}).get('services'):
                for service in network_sec['passive_service_info']['shodan']['services']:
                    assets.append({
                        'type': 'Network Service',
                        'name': service.get('service_name', 'Unknown'),
                        'port': service.get('port', 'Unknown'),
                        'version': service.get('version', None), # Keep None if not found
                        'product': service.get('product', None), # Keep None if not found
                        'transport': service.get('transport', 'tcp'),
                        'status': 'Active'
                    })
            elif network_sec.get('passive_port_info', {}).get('ports'): # Fallback to just ports
                 for port in network_sec['passive_port_info']['ports']:
                      assets.append({
                        'type': 'Network Port',
                        'name': f'Port {port}',
                        'port': port,
                        'status': 'Open'
                    }) 
                    
            # Web assets (main target)
            if self.target:
                assets.append({
                    'type': 'Web Application',
                    'name': self.target,
                    # 'headers': self.results.get('http_security', {}).get('headers', {}), # Maybe too verbose
                    'status': 'Active'
                })
                
            # Cloud assets (Placeholder - needs actual implementation)
            # if self.results.get('cloud_security', {}).get('issues'):
            #     for issue in self.results['cloud_security']['issues']:
            #         assets.append({
            #             'type': 'Cloud Service',
            #             'name': issue.get('service', 'Unknown'),
            #             'issue': issue.get('description', 'Unknown'),
            #             'status': 'Active'
            #         })
                    
            # Email assets (If email provided)
            if self.email and self.results.get('email_security'):
                email_domain = self.email.split('@')[1]
                assets.append({
                    'type': 'Email Domain',
                    'name': email_domain,
                    'status': 'Active'
                })
            
            asset_info['discovered_assets'] = assets # Store the list
                    
            # Categorize assets
            for asset in assets:
                asset_type = asset['type']
                if asset_type not in asset_info['asset_types']:
                    asset_info['asset_types'][asset_type] = 0
                asset_info['asset_types'][asset_type] += 1 # Just count types for now
                
            # Calculate risk levels and criticality (simplified)
            # These calculations are very basic and need more context
            # for asset_type, asset_list in asset_info['asset_types'].items():
            #     risk_level = self.calculate_asset_risk(asset_list)
            #     criticality = self.calculate_asset_criticality(asset_list)
            #     sensitivity = self.calculate_asset_sensitivity(asset_list)
            #     business_impact = self.calculate_business_impact(asset_list)
                
            #     asset_info['risk_levels'][asset_type] = risk_level
            #     asset_info['criticality'][asset_type] = criticality
            #     asset_info['sensitivity'][asset_type] = sensitivity
            #     asset_info['business_impact'][asset_type] = business_impact
                
            # Map asset relationships (Placeholder)
            # asset_info['asset_relationships'] = self.map_asset_relationships(assets)
            
            # Assign asset owners (Placeholder)
            # asset_info['asset_owners'] = self.assign_asset_owners(assets)
            
            # Update asset status (Placeholder)
            # asset_info['asset_status'] = self.update_asset_status(assets)
                
        except Exception as e:
            self.console.print(f"[yellow]Warning: Asset management error: {str(e)}[/yellow]")
            asset_info['error'] = f"Asset management assessment failed: {str(e)}"

        self.console.print(f"Asset inventory results: {json.dumps(asset_info, indent=2, default=str)}")
        self.results['asset_inventory'] = asset_info

    def calculate_asset_risk(self, assets: List[Dict]) -> str:
        """Calculate risk level for a group of assets"""
        risk_score = 0
        
        for asset in assets:
            # Check for vulnerabilities
            if any(vuln in str(asset).lower() for vuln in ['vulnerability', 'exposed', 'weak']):
                risk_score += 3
                
            # Check for sensitive information
            if any(info in str(asset).lower() for info in ['password', 'key', 'secret']):
                risk_score += 2
                
            # Check for outdated versions
            if 'version' in asset and asset['version'] and isinstance(asset['version'], str) and 'old' in asset['version'].lower():
                 risk_score += 1
                
        if risk_score >= 5:
            return 'High'
        elif risk_score >= 3:
            return 'Medium'
        else:
            return 'Low'

    def calculate_asset_criticality(self, assets: List[Dict]) -> str:
        """Calculate criticality level for a group of assets"""
        criticality_score = 0
        
        for asset in assets:
            asset_type = asset.get('type', '')
            # Check for critical services
            if asset_type in ['Web Application', 'Email Domain', 'Database Service']: # Added Email Domain
                criticality_score += 3
                
            # Check for production systems (heuristic)
            if 'prod' in str(asset).lower() or 'production' in str(asset).lower():
                criticality_score += 2
                
            # Check for customer-facing services (heuristic)
            # Correcting the missing parenthesis again
            if asset_type == 'Web Application' or ('customer' in str(asset).lower() or 'client' in str(asset).lower()): 
                criticality_score += 2
                
            # Check for financial services (heuristic)
            if 'payment' in str(asset).lower() or 'financial' in str(asset).lower():
                criticality_score += 3
                
        if criticality_score >= 8:
            return 'Critical'
        elif criticality_score >= 5:
            return 'High'
        elif criticality_score >= 3:
            return 'Medium'
        else:
            return 'Low'
            
    async def assess_email_security(self) -> None:
        """Assess email security for the provided email address"""
        if not self.email:
            self.results['email_security'] = {'status': 'skipped', 'message': 'No email provided'}
            return
            
        self.console.print(f"[bold blue]Starting email security assessment for {self.email}...[/bold blue]")
        
        email_info = {
            'validation': {},
            'domain_security': {},
            'server_config': {},
            'authentication': {'status': 'See Domain Security'},
            'reputation': {},
            'best_practices': {},
            'phishing_risk': {},
            'email_harvesting': {},  # Add email harvesting section
            'issues': [],
            'ai_recommendations': []  # Add AI recommendations section
        }
        
        try:
            # Validate email format
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, self.email):
                email_info['validation']['format'] = 'Invalid'
                email_info['issues'].append("Invalid email format")
                self.results['email_security'] = email_info
                return # Stop assessment if format is invalid
            else:
                email_info['validation']['format'] = 'Valid'
                
            # Extract domain
            domain = self.email.split('@')[1]
            email_info['domain'] = domain
            
            # Perform email harvesting
            harvest_results = await self.harvest_emails(domain)
            email_info['email_harvesting'] = harvest_results
            
            # Add harvesting results to issues if any emails were found
            if harvest_results['status'] == 'success' and harvest_results['total_emails'] > 0:
                email_info['issues'].append(f"Found {harvest_results['total_emails']} associated email addresses")
            
            # Initialize DNS resolver
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '8.8.4.4']
            resolver.timeout = 5
            resolver.lifetime = 5
                
            # --- Check domain security (DNS Records) --- 
            domain_sec = email_info['domain_security']
            try:
                # Check MX records
                mx_records = resolver.resolve(domain, 'MX')
                domain_sec['mx_records'] = sorted([str(x.exchange).rstrip('.') for x in mx_records])
            except Exception as e:
                 domain_sec['mx_records'] = None
                 email_info['issues'].append(f"MX record query failed: {e}")
                
            # Check SPF record
            try:
                spf_records = resolver.resolve(domain, 'TXT')
                domain_sec['spf'] = 'Not found'
                for record in spf_records:
                    txt_str = str(record).strip('"')
                    if txt_str.startswith('v=spf1'):
                        domain_sec['spf'] = txt_str
                        break
                if domain_sec['spf'] == 'Not found':
                     email_info['issues'].append('SPF record missing or invalid')
            except Exception as e:
                domain_sec['spf'] = f'Query failed: {e}'
                email_info['issues'].append(f"SPF record query failed: {e}")
                    
            # Check DMARC record
            try:
                dmarc_records = resolver.resolve(f'_dmarc.{domain}', 'TXT')
                domain_sec['dmarc'] = 'Not found'
                for record in dmarc_records:
                    txt_str = str(record).strip('"')
                    if txt_str.startswith('v=DMARC1'):
                        domain_sec['dmarc'] = txt_str
                        break
                if domain_sec['dmarc'] == 'Not found':
                     email_info['issues'].append('DMARC record missing or invalid')
            except Exception as e:
                domain_sec['dmarc'] = f'Query failed: {e}'
                email_info['issues'].append(f"DMARC record query failed: {e}")
                    
            # Check DKIM record (common selector 'default')
            # Note: DKIM selectors can vary, this is a basic check
            dkim_selector = 'default' # Common default
            try:
                dkim_records = resolver.resolve(f'{dkim_selector}._domainkey.{domain}', 'TXT')
                domain_sec['dkim'] = 'Not found'
                for record in dkim_records:
                    txt_str = str(record).strip('"')
                    if txt_str.startswith('v=DKIM1'):
                        domain_sec['dkim'] = f'Found ({dkim_selector}): {txt_str[:50]}...' # Show partial record
                        break
                # Don't issue warning for DKIM as it's common to use other selectors
                # if domain_sec['dkim'] == 'Not found':
                #      email_info['issues'].append('DKIM record missing for default selector') 
            except Exception:
                # Don't treat query failure as a major issue here, could be selector
                domain_sec['dkim'] = f'Not found for selector: {dkim_selector}'
                # email_info['issues'].append(f"DKIM record query failed for default selector: {e}")
            # --- End Domain Security Checks --- 
                    
            # --- Check email server configuration (Passive/Placeholder) --- 
            # Active checks like SMTP connection are often blocked/unreliable
            # Infer from DNS where possible
            server_conf = email_info['server_config']
            server_conf['status'] = 'Passive check only'
            if domain_sec.get('mx_records'):
                 server_conf['primary_mx'] = domain_sec['mx_records'][0]
            else:
                 server_conf['primary_mx'] = 'Unknown (No MX Records)'
            # Can't reliably check STARTTLS/Auth passively
            server_conf['starttls_check'] = 'Requires active connection (Not performed)'
            server_conf['auth_check'] = 'Requires active connection (Not performed)'
            # --- End Server Config --- 
                    
            # --- Check email server reputation (Placeholder/Needs API) --- 
            reputation = email_info['reputation']
            reputation['status'] = 'Check not implemented'
            # try:
            #     # Example: Use VirusTotal API to check IP reputation of primary MX
            #     if server_conf['primary_mx'] != 'Unknown (No MX Records)':
            #         mx_ip = socket.gethostbyname(server_conf['primary_mx'])
            #         vt_api_key = os.getenv('VIRUSTOTAL_API_KEY')
            #         if vt_api_key:
            #             response = requests.get(
            #                 f'https://www.virustotal.com/vtapi/v2/ip-address/report',
            #                 params={'apikey': vt_api_key, 'ip': mx_ip},
            #                 timeout=10
            #             )
            #             if response.status_code == 200:
            #                 reputation['virustotal'] = response.json().get('detected_urls', [])
            #             else:
            #                  reputation['virustotal_error'] = f'API Error {response.status_code}'
            #         else:
            #             reputation['virustotal_status'] = 'API Key missing'
            # except Exception as e:
            #     reputation['error'] = str(e)
            # --- End Reputation Check --- 
                    
            # Check email security best practices based on DNS
            best_practices = []
            if domain_sec.get('spf') == 'Not found' or 'Query failed' in domain_sec.get('spf', ''):
                best_practices.append('SPF record missing or invalid')
            if domain_sec.get('dmarc') == 'Not found' or 'Query failed' in domain_sec.get('dmarc', ''):
                best_practices.append('DMARC record missing or invalid')
            # if domain_sec.get('dkim','').startswith('Not found'): # Less critical
            #     best_practices.append('DKIM record not found for default selector')
                
            email_info['best_practices']['summary'] = best_practices if best_practices else ['Basic DNS records (SPF/DMARC) seem present']
            email_info['best_practices']['issues_count'] = len(best_practices)
                
            # Assess phishing risk based on DNS records
            phishing_risk = {
                'score': 0, # Lower score = better
                'factors': [],
                'level': 'Low'
            }
            if domain_sec.get('spf') == 'Not found' or 'Query failed' in domain_sec.get('spf', ''):
                phishing_risk['score'] += 2
                phishing_risk['factors'].append('Missing/Invalid SPF')
            if domain_sec.get('dmarc') == 'Not found' or 'Query failed' in domain_sec.get('dmarc', ''):
                phishing_risk['score'] += 2
                phishing_risk['factors'].append('Missing/Invalid DMARC')
            # DKIM adds less risk if missing compared to SPF/DMARC
            # if domain_sec.get('dkim','').startswith('Not found'):
            #     phishing_risk['score'] += 1
            #     phishing_risk['factors'].append('Missing DKIM (default selector)')
                
            if phishing_risk['score'] >= 4:
                phishing_risk['level'] = 'High'
            elif phishing_risk['score'] >= 2:
                 phishing_risk['level'] = 'Medium'
                    
            email_info['phishing_risk'] = phishing_risk
                
            # After identifying issues, get AI recommendations
            for issue in email_info['issues']:
                recommendation = await self.get_ai_recommendation(
                    issue=issue,
                    context=f"Email security assessment for {self.email}"
                )
                if recommendation['status'] == 'success':
                    email_info['ai_recommendations'].append({
                        'issue': issue,
                        'recommendation': recommendation['recommendation']
                    })
                
        except Exception as e:
            error_msg = f"Email security assessment error: {str(e)}"
            self.console.print(f"[red]{error_msg}[/red]")
            logger.exception("Email Assessment Error")
            email_info['error'] = error_msg
            email_info['issues'].append("Assessment failed due to unexpected error")
            
        self.results['email_security'] = email_info

    async def assess_cloud_security(self) -> None:
        """Perform cloud security assessment (currently skipped)"""
        # if not self.target:
        #     return
            
        self.console.print(f"[yellow]Cloud security assessment skipped (requires specific credentials/config).[/yellow]")
        
        cloud_info = {
            'status': 'skipped',
            'message': 'Cloud security assessment skipped - requires cloud provider credentials and configuration.'
        }
            
        self.results['cloud_security'] = cloud_info

    def store_results(self):
        """Store scan results in memory (Placeholder)"""
        # This function currently does nothing significant.
        # Future implementation could store to DB or file.
        try:
            # For now, just keep results in memory
            return True
        except Exception as e:
            logger.error(f"Error storing results: {str(e)}")
            return False

    async def assess_application_security(self) -> None:
        """Perform basic application security assessment (Placeholder)"""
        # This is a very basic placeholder and needs significant enhancement
        # for real application security testing (e.g., using SAST/DAST tools)
        if not self.target:
            return
            
        self.console.print(f"[bold blue]Starting basic application security assessment...[/bold blue]")
        
        app_info = {
            # 'web_scan': {}, # Covered by http_security
            # 'api_scan': {}, # Covered by api_security
            # 'vulnerability_scan': {}, # Covered by vulnerability_assessment
            'security_headers': {},
            # 'authentication': {}, # Hard to assess passively
            # 'authorization': {},
            # 'input_validation': {},
            # 'output_encoding': {},
            # 'session_management': {},
            # 'error_handling': {},
            # 'logging': {},
            # 'crypto': {},
            'issues': [],
            'status': 'Basic Check Done'
        }
        
        try:
            # Reuse HTTP security header check if available
            if self.results.get('http_security', {}).get('headers'):
                 app_info['security_headers'] = self.results['http_security']['headers']
                 # Check for common missing headers
                 required_headers = [
                    'Strict-Transport-Security',
                    'X-Content-Type-Options',
                    'X-Frame-Options',
                    'Content-Security-Policy' # CSP is complex, just checking presence
                 ]
                 for header in required_headers:
                     if header not in app_info['security_headers'] or app_info['security_headers'][header] == 'Not Set':
                         app_info['issues'].append(f'Missing or unset security header: {header}')
            else:
                 app_info['issues'].append('Could not check security headers (HTTP assessment failed or not run)')

            # Link to vulnerability assessment
            if self.results.get('vulnerability_assessment', {}).get('common_vulnerabilities'):
                 app_info['issues'].append('Potential vulnerabilities found (see Vulnerability Assessment section)')
                 
        except Exception as e:
            self.console.print(f"[yellow]Warning: Application security assessment error: {str(e)}[/yellow]")
            app_info['error'] = str(e)
            app_info['status'] = 'Error'
            
        self.results['application_security'] = app_info

    async def assess_real_time_monitoring(self) -> None:
        """Perform real-time security monitoring (Placeholder)"""
        # This requires integration with actual monitoring systems (e.g., SIEM, IDS/IPS)
        # if not self.target:
        #     return
            
        self.console.print(f"[yellow]Real-time monitoring skipped (requires integration with monitoring tools).[/yellow]")
        
        monitoring_info = {
            # 'active_connections': [],
            # 'traffic_analysis': {},
            # 'threat_detection': {},
            # 'anomaly_detection': {},
            # 'incident_response': {},
            # 'alerts': []
            'status': 'skipped',
            'message': 'Real-time monitoring requires integration with monitoring tools.'
        }
            
        self.results['real_time_monitoring'] = monitoring_info

    async def assess_vulnerability_metrics(self) -> None:
        """Calculate and analyze vulnerability metrics (Placeholder/Uses Vuln Assessment)"""
        # This primarily relies on the vulnerability assessment results
        if not self.target:
            return
            
        self.console.print(f"[bold blue]Calculating vulnerability metrics...[/bold blue]")
        
        metrics_info = {
            'vulnerability_counts': {},
            'severity_distribution': {},
            # 'trend_analysis': {}, # Requires historical data
            'risk_scores': {},
            'remediation_metrics': {}
        }
        
        try:
            # Get vulnerability counts & severity distribution from vulnerability_assessment
            vuln_assessment = self.results.get('vulnerability_assessment', {})
            vulnerabilities = vuln_assessment.get('common_vulnerabilities', [])
            
            metrics_info['vulnerability_counts'] = {
                'total': len(vulnerabilities),
                'critical': len([v for v in vulnerabilities if v.get('severity') == 'Critical']),
                'high': len([v for v in vulnerabilities if v.get('severity') == 'High']),
                'medium': len([v for v in vulnerabilities if v.get('severity') == 'Medium']),
                'low': len([v for v in vulnerabilities if v.get('severity') == 'Low'])
            }
            
            metrics_info['severity_distribution'] = vuln_assessment.get('risk_analysis', {}).get('severity_distribution', {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0})
            
            # Calculate risk scores
            metrics_info['risk_scores'] = {
                'average_risk_score': vuln_assessment.get('metrics', {}).get('average_risk_score', 0)
                # Add more risk score calculations if needed
            }
            
            # Calculate remediation metrics (uses DB methods)
            metrics_info['remediation_metrics'] = {
                'mttd': self.calculate_mttd(),  # Mean Time to Detect
                'mttr': self.calculate_mttr(),  # Mean Time to Remediate
                # 'remediation_rate': 0, # Requires more data
                # 'backlog_size': 0 # Requires more data
            }
                    
        except Exception as e:
            self.console.print(f"[yellow]Warning: Vulnerability metrics calculation error: {str(e)}[/yellow]")
            metrics_info['error'] = str(e)
            
        self.results['vulnerability_metrics'] = metrics_info

    async def assess_risk_analysis(self) -> None:
        """Perform comprehensive risk analysis (Placeholder/Uses other results)"""
        # This combines information from multiple assessments
        if not self.target:
            return
            
        self.console.print(f"[bold blue]Starting risk analysis...[/bold blue]")
        
        risk_info = {
            # 'threat_analysis': {}, # Requires external threat intel
            'vulnerability_impact': {},
            'asset_risk': {},
            'business_impact': {},
            # 'risk_mitigation': {}, # Covered by vuln assessment remediation
            # 'risk_trends': {} # Requires historical data
            'status': 'Basic Analysis Done'
        }
        
        try:
            vuln_assessment = self.results.get('vulnerability_assessment', {})
            asset_inventory = self.results.get('asset_inventory', {})
            
            # Vulnerability impact analysis (simplified)
            risk_info['vulnerability_impact'] = vuln_assessment.get('risk_analysis', {}).get('impact_analysis', {})
            
            # Asset risk assessment (Placeholder - needs better calculation)
            # risk_info['asset_risk'] = asset_inventory.get('risk_levels', {})

            # Business impact analysis (Placeholder - needs better calculation)
            # risk_info['business_impact'] = asset_inventory.get('business_impact', {})
                       
        except Exception as e:
            self.console.print(f"[yellow]Warning: Risk analysis error: {str(e)}[/yellow]")
            risk_info['error'] = str(e)
            risk_info['status'] = 'Error'
            
        self.results['risk_analysis'] = risk_info

    async def assess_remediation_tracking(self) -> None:
        """Track and manage vulnerability remediation (Placeholder/DB Query)"""
        # Relies heavily on the database state
        if not self.target:
            return
            
        self.console.print(f"[bold blue]Starting remediation tracking...[/bold blue]")
        
        remediation_info = {
            'open_issues': [],
            'in_progress': [],
            'resolved_recently': [], # Renamed from resolved
            'metrics': {},
            # 'timelines': {}, # Static info, not part of tracking state
            # 'assignments': {} # Requires system integration
            'status': 'DB Queried'
        }
        
        try:
            # Get remediation data from database
            conn = sqlite3.connect('security_scanner.db')
            cursor = conn.cursor()
            
            # Get open issues (excluding Remediated)
            cursor.execute('''
                SELECT id, vuln_type, severity, discovery_date, status
                FROM vulnerabilities
                WHERE target = ? AND status != 'Remediated'
                ORDER BY severity DESC
            ''', (self.target,))
            open_issues = cursor.fetchall()
            remediation_info['open_issues'] = [
                {'id': i[0], 'type': i[1], 'severity': i[2], 'date': i[3], 'status': i[4]} 
                for i in open_issues
            ]
                
            # Get in-progress issues
            cursor.execute('''
                SELECT id, vuln_type, severity, discovery_date
                FROM vulnerabilities
                WHERE target = ? AND status = 'In Progress'
                ORDER BY severity DESC
            ''', (self.target,))
            in_progress = cursor.fetchall()
            remediation_info['in_progress'] = [
                {'id': i[0], 'type': i[1], 'severity': i[2], 'date': i[3]}
                for i in in_progress
            ]
                
            # Get recently resolved issues
            cursor.execute('''
                SELECT id, vuln_type, severity, discovery_date, remediation_date
                FROM vulnerabilities
                WHERE target = ? AND status = 'Remediated'
                ORDER BY remediation_date DESC
                LIMIT 10
            ''', (self.target,))
            resolved = cursor.fetchall()
            remediation_info['resolved_recently'] = [
                 {'id': i[0], 'type': i[1], 'severity': i[2], 'discovered': i[3], 'remediated': i[4]}
                 for i in resolved
            ]
                
            # Calculate metrics
            cursor.execute('''
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN status = 'Remediated' THEN 1 ELSE 0 END) as resolved_count
                    -- AVG(JULIANDAY(remediation_date) - JULIANDAY(discovery_date)) as avg_time -- Use MTTR method
                FROM vulnerabilities
                WHERE target = ?
            ''', (self.target,))
            metrics_db = cursor.fetchone()
            total_db_issues = metrics_db[0] or 0
            resolved_db_issues = metrics_db[1] or 0
            
            remediation_info['metrics'] = {
                'total_tracked_issues': total_db_issues,
                'resolved_tracked_issues': resolved_db_issues,
                'resolution_rate_tracked': (resolved_db_issues / total_db_issues * 100) if total_db_issues else 0,
                'mttr_tracked': self.calculate_mttr() # Use existing MTTR method
            }
                
            conn.close()
                
        except Exception as e:
            remediation_info['metrics'] = {'error': str(e)}
            remediation_info['status'] = 'Error'
            self.console.print(f"[red]Error querying remediation DB: {e}[/red]")
                        
        self.results['remediation_tracking'] = remediation_info

    async def assess_subdomain_discovery(self, run_findomain: bool = False) -> None:
        """Discover subdomains using crt.sh and optionally Findomain.""" # Updated docstring
        if not self.target:
            self.results['subdomain_discovery'] = {'error': 'No target specified', 'status': 'error', 'subdomains': []}
            print("--- assess_subdomain_discovery: No target ---")
            return

        self.console.print(f"[bold blue]Starting subdomain discovery for {self.target}...[/bold blue]")
        subdomain_info = {
            'subdomains': set(), # Use a set for automatic deduplication
            'status': 'pending',
            'error': None,
            'sources_used': []
        }

        # --- Method 1: crt.sh ---
        try:
            url = f"https://crt.sh/?q=%.{self.target}&output=json"
            print(f"--- assess_subdomain_discovery: Querying crt.sh: {url} ---")
            response = self.session.get(url, timeout=45, verify=True)
            response.raise_for_status()
            print(f"--- assess_subdomain_discovery (crt.sh): Got status code {response.status_code} ---")
            subdomain_info['sources_used'].append('crt.sh')

            if response.text:
                try:
                    discovered_subs_crtsh = set()
                    raw_data = response.text.strip()
                    json_objects = [line for line in raw_data.split('\n') if line.strip()]
                    print(f"--- assess_subdomain_discovery (crt.sh): Received {len(json_objects)} JSON lines ---")

                    if not json_objects:
                         print("--- assess_subdomain_discovery (crt.sh): Warning - Received empty/non-JSON response ---")
                    else:
                        for json_line in json_objects:
                            try:
                                entry = json.loads(json_line)
                                if not isinstance(entry, dict): continue

                                name_value = entry.get('name_value', '')
                                common_name = entry.get('common_name', '')
                                names_to_check = set()
                                if name_value: names_to_check.update(name_value.split('\n'))
                                if common_name: names_to_check.add(common_name)

                                for name in names_to_check:
                                    clean_name = name.strip().lower()
                                    if clean_name.startswith('*.'): clean_name = clean_name[2:]
                                    if clean_name.endswith(f".{self.target}") and clean_name != self.target:
                                        discovered_subs_crtsh.add(clean_name)

                            except json.JSONDecodeError:
                                print(f"--- assess_subdomain_discovery (crt.sh): Warning - Skipping invalid JSON line: {json_line[:100]}... ---")
                                continue
                        subdomain_info['subdomains'].update(discovered_subs_crtsh)
                        print(f"--- assess_subdomain_discovery (crt.sh): Found {len(discovered_subs_crtsh)} subdomains ---")

                except Exception as e:
                     err_msg = f"Error processing crt.sh data: {e}"
                     print(f"--- assess_subdomain_discovery (crt.sh): Exception - {err_msg} ---")
                     if not subdomain_info['error']: subdomain_info['error'] = f"crt.sh processing error: {e}; "
                     # Continue to Findomain if possible
            else:
                 print("--- assess_subdomain_discovery (crt.sh): Received empty response ---")

        except requests.exceptions.RequestException as e:
            err_msg = f"Error querying crt.sh for {self.target}: {e}"
            print(f"--- assess_subdomain_discovery (crt.sh): RequestException - {err_msg} ---")
            if not subdomain_info['error']: subdomain_info['error'] = f"crt.sh query error: {e}; "
            # Continue to Findomain
        except Exception as e:
            err_msg = f"Unexpected error during crt.sh query: {e}"
            print(f"--- assess_subdomain_discovery (crt.sh): Exception - {err_msg} ---")
            if not subdomain_info['error']: subdomain_info['error'] = f"crt.sh unexpected error: {e}; "
            # Continue to Findomain

        # --- Method 2: Findomain - Run Conditionally --- 
        # We run Findomain if run_findomain is True, assuming this flag means "run external tools"
        if run_findomain: 
            self.console.print("[bold cyan]Running Findomain scan as requested...[/bold cyan]")
            findomain_path = self.findomain_path
            findomain_output_file = None

            if not findomain_path:
                print("--- assess_subdomain_discovery (Findomain): Skipping - FINDOMAIN_PATH not configured in .env ---")
                subdomain_info['error'] = (subdomain_info['error'] or "") + "Findomain skipped (path not configured); "
                subdomain_info['sources_used'].append('Findomain (Skipped)')
            elif not os.path.exists(findomain_path):
                print(f"--- assess_subdomain_discovery (Findomain): Skipping - Path '{findomain_path}' does not exist ---")
                subdomain_info['error'] = (subdomain_info['error'] or "") + f"Findomain skipped (path '{findomain_path}' not found); "
                subdomain_info['sources_used'].append('Findomain (Skipped - Path Invalid)')
            else:
                try:
                    print(f"--- assess_subdomain_discovery: Running Findomain for {self.target} using path: {findomain_path} ---")
                    # Create a temporary file for Findomain output
                    with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.txt') as tmp_file:
                        findomain_output_file = tmp_file.name

                    # Findomain command, outputting to file
                    # Use --output flag for file output
                    cmd = [
                        findomain_path,
                        '--target', self.target,
                        '--output', findomain_output_file
                        # Add other desired findomain flags here if needed (e.g., --threads)
                    ]

                    print(f"--- Findomain Command: {' '.join(cmd)} ---")
                    # Findomain can be fast, but give it reasonable time
                    process = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=300, # 5 minutes timeout for Findomain
                        check=False,
                    )

                    subdomain_info['sources_used'].append('Findomain')
                    discovered_subs_findomain = set()

                    # Findomain usually exits 0 even if no subs found, check output file
                    print(f"--- assess_subdomain_discovery (Findomain): Process finished (Return Code: {process.returncode}). Reading {findomain_output_file} ---")
                    # Findomain stderr might contain progress or errors
                    if process.stderr:
                         print(f"--- Findomain STDERR: {process.stderr[-1000:]} ---") # Show last 1000 chars
                        
                    try:
                        with open(findomain_output_file, 'r') as f:
                            for line in f:
                                # Findomain output is typically just the subdomain
                                subdomain = line.strip().lower()
                                if subdomain and subdomain.endswith(f".{self.target}") and subdomain != self.target:
                                    discovered_subs_findomain.add(subdomain)
                    except FileNotFoundError:
                         print(f"--- assess_subdomain_discovery (Findomain): Error - Output file not found: {findomain_output_file} ---")
                         if not subdomain_info['error']: subdomain_info['error'] = "Findomain output file missing; "
                    except Exception as read_e:
                         print(f"--- assess_subdomain_discovery (Findomain): Error reading output file: {read_e} ---")
                         if not subdomain_info['error']: subdomain_info['error'] = f"Findomain output read error: {read_e}; "
                    
                    # Handle non-zero exit code as an error
                    if process.returncode != 0:
                        print(f"--- assess_subdomain_discovery (Findomain): Process Error (Return Code: {process.returncode}) ---")
                        if not subdomain_info['error'] or "Findomain" not in subdomain_info['error']:
                             subdomain_info['error'] = f"Findomain execution failed (code {process.returncode}); Check console/tool install; "

                    subdomain_info['subdomains'].update(discovered_subs_findomain)
                    print(f"--- assess_subdomain_discovery (Findomain): Found {len(discovered_subs_findomain)} subdomains ---")

                except subprocess.TimeoutExpired:
                     err_msg = "Findomain timed out after 300 seconds."
                     print(f"--- assess_subdomain_discovery (Findomain): Timeout - {err_msg} ---")
                     logger.warning(err_msg)
                     if not subdomain_info['error']: subdomain_info['error'] = "Subdomain discovery tool timed out (Findomain)."
                except Exception as e:
                     err_msg = f"Unexpected error running Findomain: {e}"
                     print(f"--- assess_subdomain_discovery (Findomain): Exception - {err_msg} ---")
                     logger.exception("Findomain Subprocess Error")
                     if not subdomain_info['error']: subdomain_info['error'] = "Subdomain discovery tool encountered an unexpected error (Findomain). Check logs."
                finally:
                     # Clean up temp file if it exists
                     if findomain_output_file and os.path.exists(findomain_output_file):
                         try:
                             os.remove(findomain_output_file)
                         except OSError as rm_e:
                             print(f"--- assess_subdomain_discovery (Findomain): Warning - Could not remove temp file {findomain_output_file}: {rm_e} ---")
        else:
             # If run_findomain is False, skip Findomain
             print("--- assess_subdomain_discovery (Findomain): Skipping - External tool scans not requested ---")
             if 'Findomain (Skipped)' not in subdomain_info['sources_used']:
                  subdomain_info['sources_used'].append('Findomain (Skipped - Not Requested)')

        # --- Finalize ---
        final_subdomains = sorted(list(subdomain_info['subdomains']))
        subdomain_info['subdomains'] = final_subdomains

        # Determine final status based on errors and whether any source worked
        if not subdomain_info['sources_used']:
             subdomain_info['status'] = 'error'
             subdomain_info['error'] = "Failed to run any subdomain discovery method." + (f" Last error: {subdomain_info['error'].strip().rstrip(';')}" if subdomain_info['error'] else "")
        elif subdomain_info['error']:
             subdomain_info['status'] = 'error' # Mark as error if any step failed but some source might have run
             subdomain_info['error'] = subdomain_info['error'].strip().rstrip(';') # Clean up error string
        else:
             subdomain_info['status'] = 'success'


        self.results['subdomain_discovery'] = subdomain_info
        print(f"--- Exiting assess_subdomain_discovery with {len(final_subdomains)} unique subdomains from {subdomain_info['sources_used']}. Status: {subdomain_info['status']}. Error: {subdomain_info['error']} ---")

    async def assess_technology_detection(self) -> None:
        """Detect web technologies using Wappalyzer."""
        if not self.target:
            self.results['technology_detection'] = {'error': 'No target specified', 'status': 'error', 'technologies': {}}
            print("--- assess_technology_detection: No target ---")
            return

        if not self.wappalyzer:
            self.results['technology_detection'] = {'error': 'Wappalyzer not initialized', 'status': 'error', 'technologies': {}}
            print("--- assess_technology_detection: Wappalyzer not initialized ---")
            return

        self.console.print(f"[bold blue]Starting technology detection for {self.target}...[/bold blue]")
        tech_info = {
            'technologies': {},
            'status': 'pending',
            'error': None,
            'ssl_verification_status': 'Unknown'
        }
        target_url = f"https://{self.target}"
        webpage = None

        try:
            # Attempt with SSL verification first
            print(f"--- assess_technology_detection: Fetching {target_url} (verify=True) ---")
            # Use the shared requests session for consistency and user-agent
            response = self.session.get(target_url, timeout=15, verify=True, allow_redirects=True)
            response.raise_for_status() # Check for HTTP errors
            webpage = WebPage(response.url, response.text, response.headers)
            print(f"--- assess_technology_detection: Fetched successfully (verify=True) ---")
            tech_info['ssl_verification_status'] = 'Success'

        except requests.exceptions.SSLError as ssl_err:
            print(f"--- assess_technology_detection: SSL Error for {target_url}: {ssl_err}. Retrying without verification. ---")
            tech_info['ssl_verification_status'] = 'Failed'
            try:
                print(f"--- assess_technology_detection: Retrying fetch for {target_url} (verify=False) ---")
                response = self.session.get(target_url, timeout=15, verify=False, allow_redirects=True)
                response.raise_for_status()
                webpage = WebPage(response.url, response.text, response.headers)
                print(f"--- assess_technology_detection: Fetched successfully (verify=False) ---")
                # SSL verification still failed, but fetch worked
            except Exception as retry_err:
                err_msg = f"Failed to fetch {target_url} even without SSL verify: {retry_err}"
                print(f"--- assess_technology_detection: Exception - {err_msg} ---")
                tech_info['error'] = err_msg
                tech_info['status'] = 'error'
                # Stop here if fetch fails completely
                self.results['technology_detection'] = tech_info
                return

        except requests.exceptions.RequestException as req_err:
            err_msg = f"Failed to fetch {target_url}: {req_err}"
            print(f"--- assess_technology_detection: Exception - {err_msg} ---")
            tech_info['error'] = err_msg
            tech_info['status'] = 'error'
            # Stop here if fetch fails completely
            self.results['technology_detection'] = tech_info
            return

        except Exception as e:
            err_msg = f"Unexpected error fetching {target_url}: {e}"
            print(f"--- assess_technology_detection: Exception - {err_msg} ---")
            logger.exception("Technology Detection Fetch Error")
            tech_info['error'] = err_msg
            tech_info['status'] = 'error'
            # Stop here if fetch fails completely
            self.results['technology_detection'] = tech_info
            return

        # --- Analyze if webpage was fetched --- 
        if webpage:
            try:
                print("--- assess_technology_detection: Analyzing webpage with Wappalyzer ---")
                detected_tech = self.wappalyzer.analyze(webpage)
                # Wappalyzer returns tech name -> {versions: [], categories: []}
                # Convert to a simpler format for JSON/frontend if needed
                tech_info['technologies'] = detected_tech 
                print(f"--- assess_technology_detection: Detected {len(detected_tech)} technologies ---")
                tech_info['status'] = 'success'
            except Exception as analyze_e:
                err_msg = f"Error analyzing webpage with Wappalyzer: {analyze_e}"
                print(f"--- assess_technology_detection: Exception - {err_msg} ---")
                logger.exception("Wappalyzer Analysis Error")
                tech_info['error'] = err_msg
                tech_info['status'] = 'error'
        else:
             # This case should theoretically be caught by earlier returns, but as a fallback:
             if not tech_info['error']:
                  tech_info['error'] = "Webpage could not be fetched for analysis."
             tech_info['status'] = 'error'

        self.results['technology_detection'] = tech_info
        print(f"--- Exiting assess_technology_detection with status: {tech_info['status']}. Error: {tech_info['error']} ---")

    async def harvest_emails(self, domain: str) -> Dict:
        """Harvest email addresses associated with a domain using EmailHarvester"""
        try:
            from EmailHarvester import EmailHarvester
            harvester = EmailHarvester(
                userAgent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                proxy=None
            )
            
            # Initialize results dictionary
            harvest_results = {
                'status': 'success',
                'emails': [],
                'sources': {},
                'error': None
            }
            
            # Get all available plugins
            plugins = harvester.get_plugins()
            
            # Harvest emails from each search engine
            for engine_name, plugin in plugins.items():
                try:
                    emails = plugin['search'](domain, limit=100)
                    if emails:
                        harvest_results['emails'].extend(emails)
                        harvest_results['sources'][engine_name] = len(emails)
                except Exception as e:
                    logger.warning(f"Failed to harvest emails from {engine_name}: {str(e)}")
                    continue
            
            # Remove duplicates
            harvest_results['emails'] = list(set(harvest_results['emails']))
            harvest_results['total_emails'] = len(harvest_results['emails'])
            
            return harvest_results
            
        except Exception as e:
            logger.error(f"Email harvesting error: {str(e)}")
            return {
                'status': 'error',
                'emails': [],
                'sources': {},
                'error': str(e)
            }

    async def assess_google_dorking(self) -> None:
        """Assess potential security exposures through Google dorking"""
        try:
            print(f"Starting Google dorking assessment for {self.target}...")
            dorker = GoogleDorker(domain=self.target)
            dork_results = dorker.run_dorks(SECURITY_DORKS)
            
            self.results['google_dorking'] = {
                'status': 'completed',
                'findings': dork_results,
                'total_findings': len(dork_results),
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            print(f"Error during Google dorking assessment: {e}")
            self.results['google_dorking'] = {
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    async def assess_typosquatting(self) -> None:
        """Assess potential typosquatting domains"""
        try:
            print(f"Starting typosquatting assessment for {self.target}...")
            typosquatter = TypoSquatter(domain=self.target)
            typo_results = typosquatter.scan()
            
            self.results['typosquatting'] = {
                'status': 'completed',
                'findings': typo_results,
                'total_findings': len(typo_results),
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            print(f"Error during typosquatting assessment: {e}")
            self.results['typosquatting'] = {
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    async def run_scan(self, scan_subdomains: bool = False) -> Dict[str, Any]:
        """Run the complete security scan"""
        try:
            print(f"Starting security scan for {self.target}...")
            
            # Initialize results dictionary
            self.results = {
                'target': self.target,
                'scan_date': datetime.now().isoformat(),
                'profile': self.profile,
                'network_security': {},
                'dns_health': {},
                'subdomain_discovery': {},
                'http_security': {},
                'technology_detection': {},
                'vulnerability_assessment': {},
                'ip_reputation': {},
                'ssl_tls_security': {},
                'google_dorking': {},
                'typosquatting': {},
                'subdomain_results': {}
            }
            
            # Run all assessments
            await asyncio.gather(
                self.assess_network_security(),
                self.assess_dns_health(),
                self.assess_http_security(),
                self.assess_vulnerability_assessment(),
                self.assess_ip_reputation(),
                self.assess_ssl_tls_security(),
                self.assess_api_security(),
                self.assess_container_security(),
                self.assess_database_security(),
                self.assess_patching_status(),
                self.assess_compliance(),
                self.assess_asset_inventory(),
                self.assess_email_security(),
                self.assess_cloud_security(),
                self.assess_application_security(),
                self.assess_real_time_monitoring(),
                self.assess_vulnerability_metrics(),
                self.assess_risk_analysis(),
                self.assess_remediation_tracking(),
                self.assess_google_dorking(),  # Add Google dorking assessment
                self.assess_typosquatting(),   # Add typosquatting assessment
                self.assess_subdomain_discovery(run_findomain=scan_subdomains),
                self.assess_technology_detection()
            )
            
            # Calculate overall risk
            self.calculate_overall_risk()
            
            # Store results
            self.store_results()
            
            return self.results
            
        except Exception as e:
            print(f"Error during security scan: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }

    async def assess_data_leaks(self) -> Dict:
        """
        Assess potential data leaks using Traceback API
        Returns a dictionary with status and findings
        """
        try:
            if not hasattr(self, 'traceback_api'):
                return {
                    "status": "skipped",
                    "message": "Traceback API not configured",
                    "findings": []
                }
            
            results = await self.traceback_api.perform_all_lookups(
                query=self.target,
                email=self.email
            )
            
            # Format findings for the scanner output
            formatted_findings = []
            if results.get('status') == 'success':
                for key, value in results.get('findings', {}).items():
                    if isinstance(value, dict) and 'error' not in value:
                        formatted_findings.append({
                            'type': value.get('type', 'unknown'),
                            'severity': 'medium',  # Default severity
                            'description': f"Found {value.get('count', 0)} potential leaks in {key}",
                            'details': value.get('results', [])
                        })
            
            return {
                "status": "success",
                "message": "Data leak assessment completed",
                "findings": formatted_findings
            }
            
        except Exception as e:
            # Log the error but don't let it affect the scanner
            print(f"Warning: Data leak assessment failed: {str(e)}")
            return {
                "status": "skipped",
                "message": "Data leak assessment skipped due to API issues",
                "findings": []
            }

    def analyze_results(self, results):
        """Generate a summary of the scan results without using AI"""
        try:
            # Count vulnerabilities by severity
            severity_counts = {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
            
            # Count vulnerabilities in each category
            for category, data in results.items():
                if isinstance(data, dict) and 'findings' in data:
                    for finding in data['findings']:
                        if 'severity' in finding:
                            severity = finding['severity'].lower()
                            if severity in severity_counts:
                                severity_counts[severity] += 1

            # Generate a simple summary
            summary = "Scan Summary:\n"
            summary += f"Target: {self.target}\n"
            summary += f"Profile: {self.profile}\n\n"
            
            summary += "Vulnerability Counts:\n"
            for severity, count in severity_counts.items():
                if count > 0:
                    summary += f"- {severity.capitalize()}: {count}\n"
            
            summary += "\nRecommendations:\n"
            if severity_counts['critical'] > 0 or severity_counts['high'] > 0:
                summary += "- Immediate attention required for critical and high severity issues\n"
            if severity_counts['medium'] > 0:
                summary += "- Address medium severity issues in the next maintenance window\n"
            if severity_counts['low'] > 0 or severity_counts['info'] > 0:
                summary += "- Review low and informational findings for potential improvements\n"
            
            return summary
            
        except Exception as e:
            print(f"Error generating summary: {str(e)}")
            return "Unable to generate summary due to an error."

@app.get("/health")
async def health_check():
    """API endpoint to check service health"""
    return {"status": "ok"}

# API endpoints
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    logger.info("Root path / requested") # Add log message
    try:
        template_response = templates.TemplateResponse("index.html", {"request": request})
        logger.info(f"TemplateResponse object created: {template_response}") # Add log message
        return template_response
    except Exception as e:
        logger.error(f"Error creating TemplateResponse for index.html: {e}", exc_info=True) # Log exception
        raise HTTPException(status_code=500, detail=f"Internal server error loading template: {e}")

@app.post("/scan")
async def run_security_scan(scan_request: ScanRequest):
    scanner = SecurityScanner(target=scan_request.target, email=scan_request.email, profile=scan_request.profile)
    # Pass the scan_subdomains flag to the run_scan method
    results_package = await scanner.run_scan(scan_subdomains=scan_request.scan_subdomains)
    # Return the results in the format expected by the frontend
    return {
        "results": results_package,
        "scan_subdomains_requested": scan_request.scan_subdomains
    }

# --- Added PDF Download Endpoint --- 
class ReportRequest(BaseModel):
    target: str
    results: Dict[str, Any]

class PDF(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, 'Security Scan Report', 0, 1, 'C')
        self.ln(10)

    def chapter_title(self, title):
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, title, 0, 1, 'L')
        self.ln(4)

    def chapter_body(self, body):
        self.set_font('Arial', '', 10)
        # Use multi_cell for potentially long text
        # Replace non-standard characters that FPDF might not support
        safe_body = body.encode('latin-1', 'replace').decode('latin-1')
        self.multi_cell(0, 5, safe_body)
        self.ln()

    def add_section(self, title, data):
        if not data: # Skip empty sections
            return
            
        self.add_page()
        self.chapter_title(title)
        
        # Basic formatting for dictionary data
        body_text = ""
        if isinstance(data, dict):
            for key, value in data.items():
                 # Simple representation, might need refinement for nested dicts/lists
                 body_text += f"{key.replace('_', ' ').title()}: {str(value)}\n"
        elif isinstance(data, list):
             body_text = "\n".join(map(str, data))
        else:
             body_text = str(data)
             
        self.chapter_body(body_text or "No data available for this section.")

@app.post("/download-report")
async def download_report(report_request: ReportRequest):
    try:
        pdf = PDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(0, 10, f"Report for: {report_request.target}", 0, 1, 'C')
        pdf.ln(10)

        # --- Iterate through results and add sections --- 
        # This part needs refinement to handle the structure correctly
        # For now, just add a few key sections as an example
        results_data = report_request.results

        pdf.add_section("Network Security", results_data.get('network_security'))
        pdf.add_section("DNS Health", results_data.get('dns_health'))
        pdf.add_section("SSL/TLS Security", results_data.get('ssl_tls_security'))
        pdf.add_section("HTTP Security", results_data.get('http_security'))
        pdf.add_section("Technology Detection", results_data.get('technology_detection'))
        pdf.add_section("Subdomain Discovery", results_data.get('subdomain_discovery'))
        pdf.add_section("Vulnerability Assessment", results_data.get('vulnerability_assessment'))
        # TODO: Add handling for subdomain_results dictionary

        # --- Generate PDF File --- 
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmpfile:
            pdf_output_path = tmpfile.name
            pdf.output(pdf_output_path, "F")

        # Create filename
        safe_target = re.sub(r'[^a-zA-Z0-9_.-]', '_', report_request.target)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"SecurityReport_{safe_target}_{timestamp}.pdf"

        return FileResponse(
            path=pdf_output_path, 
            media_type='application/pdf', 
            filename=filename,
            background=BackgroundTasks([lambda: os.remove(pdf_output_path)]) # Clean up temp file
        )

    except Exception as e:
        logger.error(f"Error generating PDF report: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to generate PDF report: {e}")


if __name__ == "__main__": # Fixed: Added colon
    import uvicorn # type: ignore
    uvicorn.run(app, host="0.0.0.0", port=8000)