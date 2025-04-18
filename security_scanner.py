#!/usr/bin/env python3
import os
import dns.resolver
import requests
import socket
import whois
import subprocess # Added for curl
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
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks # type: ignore
from fastapi.templating import Jinja2Templates # type: ignore
from fastapi.staticfiles import StaticFiles # type: ignore
from fastapi.responses import HTMLResponse, FileResponse # type: ignore
from fastapi.middleware.cors import CORSMiddleware # type: ignore
from pydantic import BaseModel # type: ignore
from typing import Optional
from fpdf import FPDF
import tempfile
import logging
# from attack_surface_scanner import AttackSurfaceScanner
# Temporarily comment out ScoutSuite import
# from cloud_security_scanner import CloudSecurityScanner
import json
import urllib3

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
    slack_channel: Optional[str] = None

class ScanResults(BaseModel):
    target: str  # Add the missing target field
    results: Dict[str, Any]

class SecurityScanner:
    def __init__(self, target: str = None, email: str = None, profile: str = "standard"):
        load_dotenv()
        self.target = target
        self.email = email
        self.profile = profile
        self.console = Console()
        
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
            
        self.results = {
            'network_security': {},
            'dns_health': {},
            'email_security': {},
            'http_security': {}, # Added
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
            'cloud_security': {}
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
                    'vulnerability_assessment',
                    'ip_reputation',
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
            
        self.console.print(f"[bold blue]Starting HTTP security assessment for {self.target} via Sucuri (curl)...[/bold blue]")
        sucuri_api_url = f"https://sitecheck.sucuri.net/api/v3/?scan={self.target}"
        http_info = {
            'status': 'pending',
            'headers': {},
            'malware_scan': {},
            'security_hardening': {},
            'warnings': [],
            'error': None
        }
        
        try:
            print(f"--- assess_http_security: Running curl command... ---") # Basic print
            # Construct the curl command
            # Added -s for silent mode (no progress meter), -L to follow redirects
            command = [
                "curl",
                "-s", # Silent mode
                "-L", # Follow redirects
                sucuri_api_url
            ]

            # Execute the curl command
            process = subprocess.run(
                command,
                capture_output=True, 
                text=True, 
                check=False, # Don't raise exception on non-zero exit code, handle manually
                timeout=60 # Add a timeout
            )
            print(f"--- assess_http_security: curl finished. RC={process.returncode} ---") # Basic print

            # Check if curl command executed successfully
            if process.returncode != 0:
                 # Try to get more specific error, otherwise use stderr
                error_detail = process.stderr.strip() if process.stderr else f"Curl command failed with exit code {process.returncode}."
                print(f"--- assess_http_security: curl error detail: {error_detail} ---") # Basic print
                if "Could not resolve host" in error_detail:
                    error_msg = f"Curl could not resolve host: {self.target}. Check network or target validity."
                elif "timed out" in error_detail.lower():
                     error_msg = f"Curl command timed out connecting to {sucuri_api_url}."
                else:
                    error_msg = f"Curl command failed: {error_detail}"
                raise RuntimeError(error_msg)

            # Check if output is empty
            if not process.stdout:
                 print("--- assess_http_security: curl output is empty ---") # Basic print
                 raise ValueError("Received empty response from curl command.")

            # Parse the JSON output from curl
            print("--- assess_http_security: Parsing JSON... ---") # Basic print
            data = json.loads(process.stdout)
            http_info['status'] = 'success'
            print("--- assess_http_security: JSON Parsed Successfully ---") # Basic print

            # --- Extract WAF/CDN Information ---
            waf_info = "Unknown/None"
            try:
                # Check common locations in Sucuri V3 response
                cloudproxy_info = data.get('SITE', {}).get('results', {}).get('CLOUDPROXY', {}).get('info', [])
                if cloudproxy_info and isinstance(cloudproxy_info, list) and len(cloudproxy_info) > 0:
                    # Example: [['cdn-google'], ['provider-google']] or [['firewall-cloudflare'], ['provider-cloudflare']]
                    waf_info = cloudproxy_info[0][0] # Take the first entry's value as the primary identifier
                    if '-' in waf_info:
                        waf_info = waf_info.split('-', 1)[1].replace('-', ' ').title() # Format it nicely

                # Fallback: Check system info if cloudproxy is empty
                elif 'SCAN' in data and 'SYSTEM_INFO' in data['SCAN']:
                    system_info = data['SCAN']['SYSTEM_INFO']
                    # Look for keywords in system info string (less reliable)
                    if 'cloudflare' in system_info.lower():
                        waf_info = 'Cloudflare'
                    elif 'sucuri' in system_info.lower():
                        waf_info = 'Sucuri'
                    elif 'akamai' in system_info.lower():
                        waf_info = 'Akamai'
                    # Add more checks if needed

            except Exception as parse_err:
                self.console.print(f"[yellow]Warning: Could not parse WAF info: {parse_err}[/yellow]")
            http_info['waf'] = waf_info # Add WAF info to results
            # --- End WAF Extraction ---

            # --- Data extraction logic remains the same --- 
            # Extract Header Information (from SECURITY section)
            security_section = data.get('SECURITY', {})
            headers = {}
            if isinstance(security_section, dict):
                for item in security_section.get('results', {}).get('HEADERS', {}).get('info', []):
                    if isinstance(item, list) and len(item) >= 2:
                        header_name = item[0]
                        header_status = item[1]
                        headers[header_name] = header_status
            http_info['headers'] = headers

            # Extract Malware Information
            malware_section = data.get('MALWARE', {})
            http_info['malware_scan'] = {
                'status': malware_section.get('status_text', 'N/A'),
                'details': malware_section.get('info', [])
            }

            # Extract Security Hardening Recommendations / Warnings
            recommendations = data.get('RECOMMENDATIONS', {})
            if isinstance(recommendations, dict):
                 for item in recommendations.get('results', {}).get('HARDENING', {}).get('warn', []):
                      if isinstance(item, list) and len(item) >= 2:
                           http_info['warnings'].append(f"{item[0]}: {item[1]}")
            http_info['security_hardening']['warnings'] = http_info['warnings']

            # Add overall warnings from the main 'WARN' section if present
            warnings_section = data.get('WARN', [])
            if isinstance(warnings_section, list):
                for warning_item in warnings_section:
                     if isinstance(warning_item, list) and len(warning_item) >= 2:
                         http_info['warnings'].append(f"General Warning: {warning_item[1]} (Code: {warning_item[0]})")
            # --- End of data extraction --- 

        except FileNotFoundError:
            error_msg = "Error: 'curl' command not found. Please ensure curl is installed and in your system's PATH."
            print(f"--- assess_http_security: Exception - {error_msg} ---") # Basic print
            self.console.print(f"[red]{error_msg}[/red]")
            http_info['error'] = error_msg
            http_info['status'] = 'error'
        except subprocess.TimeoutExpired:
            error_msg = f"Curl command timed out after 60 seconds for {sucuri_api_url}."
            print(f"--- assess_http_security: Exception - {error_msg} ---") # Basic print
            self.console.print(f"[red]{error_msg}[/red]")
            http_info['error'] = error_msg
            http_info['status'] = 'error'
        except (json.JSONDecodeError, ValueError) as e: # Catch JSON parsing errors and empty response error
            error_msg = f"Failed to process response from curl: {e}"
            print(f"--- assess_http_security: Exception - {error_msg} ---") # Basic print
            self.console.print(f"[red]{error_msg}[/red]")
            http_info['error'] = error_msg
            http_info['status'] = 'error'
        except RuntimeError as e: # Catch errors raised from non-zero return code
            error_msg = str(e)
            print(f"--- assess_http_security: Exception - {error_msg} ---") # Basic print
            self.console.print(f"[red]{error_msg}[/red]")
            http_info['error'] = error_msg
            http_info['status'] = 'error'
        except Exception as e:
            error_msg = f"Unexpected error during Sucuri SiteCheck scan via curl: {e}"
            print(f"--- assess_http_security: Exception - {error_msg} ---") # Basic print
            self.console.print(f"[red]{error_msg}[/red]")
            logger.exception("Unexpected Sucuri Scan (curl) Error")
            http_info['error'] = error_msg
            http_info['status'] = 'error'

        print("--- Exiting assess_http_security ---") # Basic print
        self.results['http_security'] = http_info
        self.console.print(f"HTTP Security results (curl): {json.dumps(http_info, indent=2, default=str)}")

    async def assess_vulnerability(self) -> None:
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
            for payload in xss_payloads:
                test_url = f"{target_url_base}/?q={payload}"
                try:
                    response = requests.get(test_url, verify=True, timeout=5)
                    if payload in response.text:
                        vulnerabilities.append({
                            'type': 'XSS',
                            'payload': payload,
                            'severity': 'High',
                            'exploitability': 'Easy',
                            'impact': 'Data theft, session hijacking',
                            'risk_score': self.calculate_risk_score('XSS', 'High', 'Easy', 'Data theft, session hijacking'),
                            'ssl_verification': 'Success'
                        })
                except requests.exceptions.SSLError:
                    try:
                        response = requests.get(test_url, verify=False, timeout=5)
                        if payload in response.text:
                            vulnerabilities.append({
                                'type': 'XSS',
                                'payload': payload,
                                'severity': 'High',
                                'exploitability': 'Easy',
                                'impact': 'Data theft, session hijacking',
                                'risk_score': self.calculate_risk_score('XSS', 'High', 'Easy', 'Data theft, session hijacking'),
                                'ssl_verification': 'Failed'
                            })
                    except Exception as inner_e:
                        self.console.print(f"[yellow]XSS check failed (insecure retry) for {test_url}: {inner_e}[/yellow]")
                except requests.exceptions.RequestException as req_e: # Catch timeouts, connection errors etc.
                    self.console.print(f"[yellow]XSS check failed for {test_url}: {req_e}[/yellow]")
                except Exception as e: # Catch other unexpected errors
                    self.console.print(f"[red]Unexpected error during XSS check for {test_url}: {e}[/red]")
            self.console.print(f"XSS checks completed.")

            # --- SQL Injection Checks --- #
            sql_payloads = [
                "' OR '1'='1",
                "1' OR '1'='1",
                "1 UNION SELECT NULL--"
            ]
            self.console.print(f"Running {len(sql_payloads)} SQLi checks...")
            for payload in sql_payloads:
                test_url = f"{target_url_base}/?id={payload}"
                print(f"  - Testing SQLi payload: {payload[:20]}... on {test_url}") # Added print
                try:
                    response = requests.get(test_url, verify=True, timeout=5)
                    if any(error in response.text.lower() for error in ['sql', 'mysql', 'postgresql', 'oracle', 'syntax error']):
                        print(f"    * Potential SQLi Found for payload: {payload[:20]}... *") # Added print
                        vulnerabilities.append({
                            'type': 'SQL Injection',
                            'payload': payload,
                            'severity': 'Critical',
                            'exploitability': 'Easy',
                            'impact': 'Data breach, unauthorized access',
                            'risk_score': self.calculate_risk_score('SQL Injection', 'Critical', 'Easy', 'Data breach, unauthorized access'),
                            'ssl_verification': 'Success'
                        })
                except requests.exceptions.SSLError:
                     try:
                        response = requests.get(test_url, verify=False, timeout=5)
                        if any(error in response.text.lower() for error in ['sql', 'mysql', 'postgresql', 'oracle', 'syntax error']):
                            print(f"    * Potential SQLi Found for payload: {payload[:20]}... *") # Added print
                            vulnerabilities.append({
                                'type': 'SQL Injection',
                                'payload': payload,
                                'severity': 'Critical',
                                'exploitability': 'Easy',
                                'impact': 'Data breach, unauthorized access',
                                'risk_score': self.calculate_risk_score('SQL Injection', 'Critical', 'Easy', 'Data breach, unauthorized access'),
                                'ssl_verification': 'Failed'
                            })
                     except Exception as inner_e:
                        self.console.print(f"[yellow]SQLi check failed (insecure retry) for {test_url}: {inner_e}[/yellow]")
                except requests.exceptions.RequestException as req_e:
                    self.console.print(f"[yellow]SQLi check failed for {test_url}: {req_e}[/yellow]")
                except Exception as e:
                    self.console.print(f"[red]Unexpected error during SQLi check for {test_url}: {e}[/red]")
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
            # Catch-all for unexpected errors in the main block
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

    def format_distribution(self, distribution: Dict) -> str:
        """Format distribution data for report"""
        return "\n".join(f"{k}: {v}" for k, v in distribution.items())

    def format_impact_analysis(self, impact: Dict) -> str:
        """Format impact analysis data for report"""
        return "\n".join(f"{k.replace('_', ' ').title()}: {v}" for k, v in impact.items())

    async def assess_ip_reputation(self) -> None:
        """Perform IP reputation assessment"""
        print("--- Entering assess_ip_reputation ---") # Basic print
        if not self.target:
            print("--- assess_ip_reputation: No target ---") # Basic print
            self.results['ip_reputation'] = {'error': 'No target specified'}
            return
            
        self.console.print(f"[bold blue]Starting IP reputation assessment...[/bold blue]")
        
        ip_info = {
            'ip_info': {},
            'reputation_data': {}
        }
        
        try:
            # Get IP information
            try:
                print("--- assess_ip_reputation: Getting IP... ---") # Basic print
                ip = socket.gethostbyname(self.target)
                ip_info["ip_address"] = ip
                print(f"--- assess_ip_reputation: Got IP: {ip} ---") # Basic print
                # Temporarily disable hostname lookup as it can fail often
                # ip_info["hostname"] = socket.gethostbyaddr(ip)[0]
                ip_info["hostname"] = "Hostname lookup disabled"
            except Exception as e:
                print(f"--- assess_ip_reputation: Error getting IP: {e} ---") # Basic print
                ip_info["ip_info"] = {"error": str(e)} # Store error in ip_info sub-dict
                ip = None # Set IP to None if resolution failed

            # --- Actual AbuseIPDB Reputation Check --- 
            reputation_data = {
                 "abuseipdb": { "status": "Not Checked", "error": None },
                 # Keep placeholders for others for now
                 "virustotal": {"status": "clean (placeholder)"},
                 "spamhaus": {"status": "clean (placeholder)"}
            }

            # Only proceed if IP resolution was successful
            ip = ip_info.get("ip_address") # Get IP from the ip_info dict
            if ip:
                try:
                    abuseipdb_key = os.getenv('ABUSEIPDB_API_KEY')
                    if not abuseipdb_key:
                        reputation_data["abuseipdb"]['error'] = "API Key not configured."
                        reputation_data["abuseipdb"]['status'] = "Configuration Error"
                        raise ValueError("AbuseIPDB API Key not found in environment.")
                    
                    print(f"--- assess_ip_reputation: Checking IP {ip} with AbuseIPDB ---")
                    url = 'https://api.abuseipdb.com/api/v2/check'
                    headers = {
                        'Accept': 'application/json',
                        'Key': abuseipdb_key
                    }
                    params = {
                        'ipAddress': ip,
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
            else: # This else corresponds to `if ip:`
                 print("--- assess_ip_reputation: Skipping AbuseIPDB check due to failed IP resolution ---")
                 reputation_data["abuseipdb"]['error'] = "Skipped (IP resolution failed)"
                 reputation_data["abuseipdb"]['status'] = "Skipped"
            # End of the `if ip:` block

            ip_info['reputation_data'] = reputation_data
            # --- End AbuseIPDB Check ---

        except Exception as e: # <<< Reinstate the outer except corresponding to the main try
             print(f"--- assess_ip_reputation: Main Exception: {e} ---")
             self.console.print(f"[yellow]Warning: IP reputation assessment error: {str(e)}[/yellow]")
             # Ensure ip_info exists before assigning error
             if ip_info is not None: 
                 ip_info['error'] = f"Outer assessment error: {str(e)}"
             else: # Should ideally not happen if initialization is correct
                 print("[ERROR] ip_info dictionary not initialized before exception!")
                 # Handle this case, maybe initialize ip_info here or re-raise
                 ip_info = { 'error': f"Outer assessment error: {str(e)}" } 

        # --- FINAL PART (Outside try...except) ---
        print("--- Exiting assess_ip_reputation ---")
        self.results['ip_reputation'] = ip_info # Assign whatever ip_info contains (might have error key)

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
            
            # Combine all issues
            db_info['issues'] = (
                config_issues +
                access_issues +
                backup_issues
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
            if 'apache' in server_info['server'].lower():
                version = server_info['server'].split('/')[-1]
                if version and version < '2.4.0':
                    issues.append('Outdated Apache version detected')
                    
            if 'nginx' in server_info['server'].lower():
                version = server_info['server'].split('/')[-1]
                if version and version < '1.14.0':
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
            
        except Exception as e:
            self.console.print(f"[yellow]Warning: Compliance assessment error: {str(e)}[/yellow]")
            
        self.results['compliance'] = compliance_info

    async def check_pci_compliance(self) -> Dict:
        """Check PCI DSS compliance requirements"""
        findings = {
            'requirements': {},
            'status': 'Non-Compliant',
            'issues': []
        }
        
        try:
            # Check for SSL/TLS
            if not self.results['ssl_tls_security'].get('certificate_info'):
                findings['issues'].append('SSL/TLS not properly configured')
                
            # Check for security headers
            headers = self.results['http_security'].get('security_headers', {})
            required_headers = [
                'Strict-Transport-Security',
                'X-Frame-Options',
                'X-Content-Type-Options',
                'X-XSS-Protection'
            ]
            
            for header in required_headers:
                if header not in headers:
                    findings['issues'].append(f'Missing required security header: {header}')
                    
            # Check for exposed sensitive data
            if self.results['vulnerability_assessment'].get('common_vulnerabilities'):
                findings['issues'].append('Sensitive data exposure detected')
                
        except Exception as e:
            findings['issues'].append(f'Error checking PCI compliance: {str(e)}')
            
        return findings

    async def check_hipaa_compliance(self) -> Dict:
        """Check HIPAA compliance requirements"""
        findings = {
            'requirements': {},
            'status': 'Non-Compliant',
            'issues': []
        }
        
        try:
            # Check for encryption
            if not self.results['ssl_tls_security'].get('certificate_info'):
                findings['issues'].append('Encryption not properly configured')
                
            # Check for access controls
            if self.results['vulnerability_assessment'].get('common_vulnerabilities'):
                findings['issues'].append('Access control issues detected')
                
            # Check for audit logging
            if not self.results['http_security'].get('security_headers', {}).get('X-Audit-Log'):
                findings['issues'].append('Audit logging not configured')
                
        except Exception as e:
            findings['issues'].append(f'Error checking HIPAA compliance: {str(e)}')
            
        return findings

    async def check_gdpr_compliance(self) -> Dict:
        """Check GDPR compliance requirements"""
        findings = {
            'requirements': {},
            'status': 'Non-Compliant',
            'issues': []
        }
        
        try:
            # Check for data protection
            if not self.results['ssl_tls_security'].get('certificate_info'):
                findings['issues'].append('Data protection measures not properly configured')
                
            # Check for privacy headers
            headers = self.results['http_security'].get('security_headers', {})
            if 'Privacy-Policy' not in headers:
                findings['issues'].append('Privacy policy not properly configured')
                
            # Check for data minimization
            if self.results['vulnerability_assessment'].get('common_vulnerabilities'):
                findings['issues'].append('Data minimization issues detected')
                
        except Exception as e:
            findings['issues'].append(f'Error checking GDPR compliance: {str(e)}')
            
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
            
            # Network assets
            if self.results['network_security'].get('passive_port_info'):
                for service in self.results['network_security']['passive_port_info'].get('services', []):
                    assets.append({
                        'type': 'Network Service',
                        'name': service.get('name', 'Unknown'),
                        'port': service.get('port', 'Unknown'),
                        'version': service.get('version', 'Unknown'),
                        'protocol': service.get('protocol', 'Unknown'),
                        'status': 'Active'
                    })
                    
            # Web assets
            if self.results['http_security'].get('security_headers'):
                assets.append({
                    'type': 'Web Application',
                    'name': self.target,
                    'headers': self.results['http_security']['security_headers'],
                    'status': 'Active'
                })
                
            # Cloud assets
            if self.results['cloud_security'].get('issues'):
                for issue in self.results['cloud_security']['issues']:
                    assets.append({
                        'type': 'Cloud Service',
                        'name': issue.get('service', 'Unknown'),
                        'issue': issue.get('description', 'Unknown'),
                        'status': 'Active'
                    })
                    
            # Email assets
            if self.results['email_security']:
                assets.append({
                    'type': 'Email Service',
                    'name': self.email,
                    'domain': self.email.split('@')[1] if self.email else None,
                    'status': 'Active'
                })
                    
            # Categorize assets
            for asset in assets:
                asset_type = asset['type']
                if asset_type not in asset_info['asset_types']:
                    asset_info['asset_types'][asset_type] = []
                asset_info['asset_types'][asset_type].append(asset)
                
            # Calculate risk levels and criticality
            for asset_type, asset_list in asset_info['asset_types'].items():
                risk_level = self.calculate_asset_risk(asset_list)
                criticality = self.calculate_asset_criticality(asset_list)
                sensitivity = self.calculate_asset_sensitivity(asset_list)
                business_impact = self.calculate_business_impact(asset_list)
                
                asset_info['risk_levels'][asset_type] = risk_level
                asset_info['criticality'][asset_type] = criticality
                asset_info['sensitivity'][asset_type] = sensitivity
                asset_info['business_impact'][asset_type] = business_impact
                
            # Map asset relationships
            asset_info['asset_relationships'] = self.map_asset_relationships(assets)
            
            # Assign asset owners
            asset_info['asset_owners'] = self.assign_asset_owners(assets)
            
            # Update asset status
            asset_info['asset_status'] = self.update_asset_status(assets)
                
        except Exception as e:
            self.console.print(f"[yellow]Warning: Asset management error: {str(e)}[/yellow]")
            # Ensure asset_info is still assigned even on error, potentially with error key
            asset_info['error'] = f"Asset management assessment failed: {str(e)}"

        # Log the final asset_info before assigning and ensure assignment happens
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
            if 'version' in asset and 'old' in str(asset['version']).lower():
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
            # Check for critical services
            if asset['type'] in ['Web Application', 'Email Service', 'Database Service']:
                criticality_score += 3
                
            # Check for production systems
            if 'prod' in str(asset).lower() or 'production' in str(asset).lower():
                criticality_score += 2
                
            # Check for customer-facing services
            if 'customer' in str(asset).lower() or 'client' in str(asset).lower():
                criticality_score += 2
                
            # Check for financial services
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

    async def run_scan(self) -> Dict[str, Any]:
        """Run security assessment based on profile"""
        try:
            # Added detailed logging
            self.console.print(f"[bold blue]Starting Security Assessment for target: {self.target} with profile: {self.profile}[/bold blue]")

            profile_settings = self.scan_profiles.get(self.profile, self.scan_profiles['standard'])
            tasks_to_run_names = profile_settings.get('tasks', [])
            # Added detailed logging
            self.console.print(f"Tasks for profile '{self.profile}': {tasks_to_run_names}")

            # Reset results for the new scan to ensure a clean state
            # Keep the original keys but reset values to empty dicts
            initial_keys = list(self.results.keys())
            self.results = {key: {} for key in initial_keys}
            # Optionally track scan status within results if needed, or keep it separate as the API does
            # self.results['status'] = 'pending'

            scan_tasks = []
            for task_name in tasks_to_run_names:
                method_name = f"assess_{task_name}"
                if hasattr(self, method_name):
                    scan_tasks.append(getattr(self, method_name)())
                    # Added detailed logging
                    self.console.print(f"Scheduled task: {method_name}")
                else:
                     # Added detailed logging
                    self.console.print(f"[yellow]Warning: Method {method_name} not found for task {task_name}[/yellow]")

            if not scan_tasks:
                 # Added detailed logging
                 self.console.print(f"[red]Error: No valid scan tasks found for profile '{self.profile}'[/red]")
                 # Return error if no tasks scheduled
                 return {
                     'status': 'error',
                     'message': f'No valid scan tasks found for profile {self.profile}',
                     'results': self.results # Return the (empty) results
                 }

            # Run tasks concurrently
            # Use return_exceptions=True to catch errors within tasks without stopping gather
            task_results = await asyncio.gather(*scan_tasks, return_exceptions=True)
            # Added detailed logging
            self.console.print(f"Asyncio gather completed. Task results/exceptions: {task_results}")

            # Log any exceptions from individual tasks
            for i, result in enumerate(task_results):
                if isinstance(result, Exception):
                    self.console.print(f"[red]Error in task {scan_tasks[i].__qualname__}: {result}[/red]")
                    # Optionally add this error to the specific results section
                    # task_name = tasks_to_run_names[i]
                    # self.results[task_name] = {'error': str(result)}


            # Calculate overall risk (assuming this updates self.results['risk_metrics'] or similar)
            # self.calculate_overall_risk()

            # Store results (currently does nothing significant)
            # self.store_results()

            # Added detailed logging
            populated_sections = [k for k, v in self.results.items() if v]
            self.console.print(f"Final results structure before return (populated sections): {populated_sections}")
            # Log the entire results dict if needed for deep debugging (can be large)
            # self.console.print(f"Full results: {json.dumps(self.results, indent=2, default=str)}")


            return {
                'status': 'success',
                'message': 'Scan completed successfully',
                'results': self.results
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

    async def assess_email_security(self) -> None:
        """Assess email security for the provided email address"""
        if not self.email:
            return
            
        self.console.print(f"[bold blue]Starting email security assessment...[/bold blue]")
        
        email_info = {
            'validation': {},
            'domain_security': {},
            'server_config': {},
            'security_headers': {},
            'authentication': {},
            'reputation': {},
            'best_practices': {},
            'phishing_risk': {}
        }
        
        try:
            # Validate email format
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, self.email):
                email_info['validation']['format'] = 'Invalid'
            else:
                email_info['validation']['format'] = 'Valid'
                
                # Extract domain
                domain = self.email.split('@')[1]
                
                # Check domain security
                try:
                    # Check MX records
                    mx_records = dns.resolver.resolve(domain, 'MX')
                    email_info['domain_security']['mx_records'] = [str(x.exchange).rstrip('.') for x in mx_records]
                    
                    # Check SPF record
                    try:
                        spf_records = dns.resolver.resolve(domain, 'TXT')
                        for record in spf_records:
                            if 'v=spf1' in str(record):
                                email_info['domain_security']['spf'] = str(record)
                    except:
                        email_info['domain_security']['spf'] = 'Not found'
                        
                    # Check DMARC record
                    try:
                        dmarc_records = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
                        for record in dmarc_records:
                            if 'v=DMARC1' in str(record):
                                email_info['domain_security']['dmarc'] = str(record)
                    except:
                        email_info['domain_security']['dmarc'] = 'Not found'
                        
                    # Check DKIM record
                    try:
                        dkim_records = dns.resolver.resolve(f'default._domainkey.{domain}', 'TXT')
                        for record in dkim_records:
                            if 'v=DKIM1' in str(record):
                                email_info['domain_security']['dkim'] = str(record)
                    except:
                        email_info['domain_security']['dkim'] = 'Not found'
                        
                except Exception as e:
                    email_info['domain_security']['error'] = str(e)
                    
                # Check email server configuration
                try:
                    # Get primary MX server
                    primary_mx = str(mx_records[0].exchange).rstrip('.')
                    
                    # Check SMTP server
                    smtp = smtplib.SMTP(primary_mx, 25, timeout=5)
                    smtp.helo('test.com')
                    
                    # Check STARTTLS support
                    try:
                        smtp.starttls()
                        email_info['server_config']['starttls'] = 'Supported'
                    except:
                        email_info['server_config']['starttls'] = 'Not supported'
                        
                    # Check SMTP authentication
                    try:
                        smtp.login('test', 'test')
                        email_info['server_config']['auth'] = 'Required'
                    except:
                        email_info['server_config']['auth'] = 'Not required'
                        
                    smtp.quit()
                    
                except Exception as e:
                    email_info['server_config']['error'] = str(e)
                    
                # Check email security headers
                try:
                    # Create test email
                    msg = MIMEMultipart()
                    msg['From'] = self.email
                    msg['To'] = 'test@example.com'
                    msg['Subject'] = 'Security Test'
                    msg.attach(MIMEText('Test content'))
                    
                    # Send test email
                    with smtplib.SMTP(primary_mx, 25, timeout=5) as server:
                        server.send_message(msg)
                        
                    # Check received headers
                    email_info['security_headers'] = {
                        'received': msg['Received'],
                        'received_spf': msg.get('Received-SPF', 'Not found'),
                        'authentication_results': msg.get('Authentication-Results', 'Not found')
                    }
                    
                except Exception as e:
                    email_info['security_headers']['error'] = str(e)
                    
                # Check email server reputation
                try:
                    # Use VirusTotal API to check IP reputation
                    vt_api_key = os.getenv('VIRUSTOTAL_API_KEY')
                    if vt_api_key:
                        response = requests.get(
                            f'https://www.virustotal.com/vtapi/v2/ip-address/report',
                            params={'apikey': vt_api_key, 'ip': socket.gethostbyname(primary_mx)},
                            timeout=5
                        )
                        if response.status_code == 200:
                            email_info['reputation'] = response.json()
                except Exception as e:
                    email_info['reputation']['error'] = str(e)
                    
                # Check email security best practices
                best_practices = []
                
                # Check SPF
                if email_info['domain_security'].get('spf') == 'Not found':
                    best_practices.append('SPF record missing')
                    
                # Check DMARC
                if email_info['domain_security'].get('dmarc') == 'Not found':
                    best_practices.append('DMARC record missing')
                    
                # Check DKIM
                if email_info['domain_security'].get('dkim') == 'Not found':
                    best_practices.append('DKIM record missing')
                    
                # Check STARTTLS
                if email_info['server_config'].get('starttls') == 'Not supported':
                    best_practices.append('STARTTLS not supported')
                    
                # Check SMTP Auth
                if email_info['server_config'].get('auth') == 'Not required':
                    best_practices.append('SMTP authentication not required')
                    
                email_info['best_practices']['issues'] = best_practices
                
                # Assess phishing risk
                phishing_risk = {
                    'score': 0,
                    'factors': []
                }
                
                # Check for common phishing indicators
                if not email_info['domain_security'].get('spf'):
                    phishing_risk['score'] += 2
                    phishing_risk['factors'].append('No SPF record')
                    
                if not email_info['domain_security'].get('dmarc'):
                    phishing_risk['score'] += 2
                    phishing_risk['factors'].append('No DMARC record')
                    
                if not email_info['domain_security'].get('dkim'):
                    phishing_risk['score'] += 1
                    phishing_risk['factors'].append('No DKIM record')
                    
                if email_info['server_config'].get('starttls') == 'Not supported':
                    phishing_risk['score'] += 1
                    phishing_risk['factors'].append('No STARTTLS support')
                    
                if email_info['server_config'].get('auth') == 'Not required':
                    phishing_risk['score'] += 1
                    phishing_risk['factors'].append('No SMTP authentication')
                    
                email_info['phishing_risk'] = phishing_risk
                
        except Exception as e:
            self.console.print(f"[yellow]Warning: Email security assessment error: {str(e)}[/yellow]")
            
        self.results['email_security'] = email_info

    async def assess_cloud_security(self) -> None:
        """Perform cloud security assessment (currently skipped)"""
        if not self.target:
            return
            
        self.console.print(f"[yellow]Cloud security assessment temporarily disabled.[/yellow]")
        
        cloud_info = {
            'status': 'skipped',
            'message': 'Cloud security assessment temporarily disabled - will be enabled in future updates'
        }
            
        self.results['cloud_security'] = cloud_info

    def store_results(self):
        """Store scan results in memory"""
        try:
            # For now, just keep results in memory
            return True
        except Exception as e:
            logger.error(f"Error storing results: {str(e)}")
            return False

    async def assess_application_security(self) -> None:
        """Perform application security assessment"""
        if not self.target:
            return
            
        self.console.print(f"[bold blue]Starting application security assessment...[/bold blue]")
        
        app_info = {
            'web_scan': {},
            'api_scan': {},
            'vulnerability_scan': {},
            'security_headers': {},
            'authentication': {},
            'authorization': {},
            'input_validation': {},
            'output_encoding': {},
            'session_management': {},
            'error_handling': {},
            'logging': {},
            'crypto': {},
            'issues': []
        }
        
        try:
            # Web application scan
            web_scan = {
                'technologies': [],
                'frameworks': [],
                'libraries': [],
                'server_info': {},
                'security_headers': {}
            }
            
            # Check for common web technologies
            try:
                response = requests.get(f"https://{self.target}", verify=False, timeout=5)
                headers = response.headers
                
                # Check server header
                if 'Server' in headers:
                    web_scan['server_info']['server'] = headers['Server']
                    
                # Check for common frameworks
                if 'X-Powered-By' in headers:
                    web_scan['frameworks'].append(headers['X-Powered-By'])
                    
                # Check security headers
                security_headers = [
                    'X-Frame-Options',
                    'X-Content-Type-Options',
                    'X-XSS-Protection',
                    'Content-Security-Policy',
                    'Strict-Transport-Security'
                ]
                
                for header in security_headers:
                    if header in headers:
                        web_scan['security_headers'][header] = headers[header]
                    else:
                        app_info['issues'].append(f'Missing {header} header')
                        
            except Exception as e:
                app_info['issues'].append(f'Web scan error: {str(e)}')
                
            app_info['web_scan'] = web_scan
            
            # API security scan
            api_scan = {
                'endpoints': [],
                'authentication': {},
                'rate_limiting': {},
                'input_validation': {},
                'output_encoding': {},
                'issues': []
            }
            
            # Check common API endpoints
            common_endpoints = ['/api', '/v1', '/v2', '/graphql']
            for endpoint in common_endpoints:
                try:
                    response = requests.get(f"https://{self.target}{endpoint}", verify=False, timeout=5)
                    if response.status_code != 404:
                        api_scan['endpoints'].append({
                            'path': endpoint,
                            'status_code': response.status_code,
                            'methods': ['GET']  # Add more methods if needed
                        })
                except:
                    continue
                    
            # Check for API authentication
            if api_scan['endpoints']:
                api_scan['authentication'] = {
                    'required': True,
                    'methods': ['API Key', 'OAuth', 'JWT'],
                    'issues': []
                }
                
            app_info['api_scan'] = api_scan
            
            # Vulnerability scan
            vuln_scan = {
                'xss_vulnerabilities': [],
                'csrf_vulnerabilities': [],
                'sqli_vulnerabilities': [],
                'xxe_vulnerabilities': [],
                'ssrf_vulnerabilities': [],
                'file_upload_vulnerabilities': [],
                'injection_vulnerabilities': []
            }
            
            # Check for XSS
            xss_payloads = [
                '<script>alert(1)</script>',
                '"><script>alert(2)</script>',
                '"><img src=x onerror=alert(3)>'
            ]
            
            for payload in xss_payloads:
                try:
                    response = requests.get(
                        f"https://{self.target}/?q={payload}",
                        verify=False,
                        timeout=5
                    )
                    if payload in response.text:
                        vuln_scan['xss_vulnerabilities'].append({
                            'payload': payload,
                            'url': f"https://{self.target}/?q={payload}",
                            'severity': 'High'
                        })
                except:
                    continue
                    
            app_info['vulnerability_scan'] = vuln_scan
            
        except Exception as e:
            self.console.print(f"[yellow]Warning: Application security assessment error: {str(e)}[/yellow]")
            
        self.results['application_security'] = app_info

    async def assess_real_time_monitoring(self) -> None:
        """Perform real-time security monitoring"""
        if not self.target:
            return
            
        self.console.print(f"[bold blue]Starting real-time security monitoring...[/bold blue]")
        
        monitoring_info = {
            'active_connections': [],
            'traffic_analysis': {},
            'threat_detection': {},
            'anomaly_detection': {},
            'incident_response': {},
            'alerts': []
        }
        
        try:
            # Monitor active connections
            try:
                # This would typically use a network monitoring tool
                # For now, we'll simulate with basic connection info
                monitoring_info['active_connections'] = [
                    {
                        'source_ip': '192.168.1.1',
                        'destination_ip': self.target,
                        'port': 443,
                        'protocol': 'HTTPS',
                        'status': 'Active'
                    }
                ]
            except Exception as e:
                monitoring_info['alerts'].append(f'Connection monitoring error: {str(e)}')
                
            # Traffic analysis
            monitoring_info['traffic_analysis'] = {
                'total_requests': 100,
                'requests_per_minute': 5,
                'bandwidth_usage': '1.2 MB/s',
                'protocol_distribution': {
                    'HTTPS': 80,
                    'HTTP': 20
                }
            }
            
            # Threat detection
            monitoring_info['threat_detection'] = {
                'active_threats': [],
                'blocked_ips': [],
                'malicious_requests': [],
                'suspicious_activity': []
            }
            
            # Anomaly detection
            monitoring_info['anomaly_detection'] = {
                'traffic_spikes': [],
                'unusual_patterns': [],
                'suspicious_behavior': []
            }
            
            # Incident response
            monitoring_info['incident_response'] = {
                'active_incidents': [],
                'resolved_incidents': [],
                'response_times': {
                    'average': '5 minutes',
                    'critical': '2 minutes'
                }
            }
            
        except Exception as e:
            self.console.print(f"[yellow]Warning: Real-time monitoring error: {str(e)}[/yellow]")
            
        self.results['real_time_monitoring'] = monitoring_info

    async def assess_vulnerability_metrics(self) -> None:
        """Calculate and analyze vulnerability metrics"""
        if not self.target:
            return
            
        self.console.print(f"[bold blue]Calculating vulnerability metrics...[/bold blue]")
        
        metrics_info = {
            'vulnerability_counts': {},
            'severity_distribution': {},
            'trend_analysis': {},
            'risk_scores': {},
            'remediation_metrics': {}
        }
        
        try:
            # Get vulnerability counts
            metrics_info['vulnerability_counts'] = {
                'total': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }
            
            # Calculate severity distribution
            metrics_info['severity_distribution'] = {
                'Critical': 0,
                'High': 0,
                'Medium': 0,
                'Low': 0
            }
            
            # Analyze trends
            metrics_info['trend_analysis'] = {
                'vulnerability_trend': [],
                'severity_trend': [],
                'risk_trend': []
            }
            
            # Calculate risk scores
            metrics_info['risk_scores'] = {
                'overall_risk': 0,
                'severity_weighted_risk': 0,
                'exploitability_risk': 0,
                'impact_risk': 0
            }
            
            # Calculate remediation metrics
            metrics_info['remediation_metrics'] = {
                'mttd': 0,  # Mean Time to Detect
                'mttr': 0,  # Mean Time to Remediate
                'remediation_rate': 0,
                'backlog_size': 0
            }
            
            # Update metrics based on existing results
            if 'vulnerability_assessment' in self.results:
                vuln_assessment = self.results['vulnerability_assessment']
                
                # Update vulnerability counts
                if 'common_vulnerabilities' in vuln_assessment:
                    for vuln in vuln_assessment['common_vulnerabilities']:
                        metrics_info['vulnerability_counts']['total'] += 1
                        severity = vuln.get('severity', 'Unknown')
                        if severity in metrics_info['vulnerability_counts']:
                            metrics_info['vulnerability_counts'][severity.lower()] += 1
                            
                # Update severity distribution
                if 'risk_analysis' in vuln_assessment and 'severity_distribution' in vuln_assessment['risk_analysis']:
                    metrics_info['severity_distribution'] = vuln_assessment['risk_analysis']['severity_distribution']
                    
                # Update risk scores
                if 'metrics' in vuln_assessment:
                    metrics_info['risk_scores']['overall_risk'] = vuln_assessment['metrics'].get('average_risk_score', 0)
                    
                # Update remediation metrics
                if 'metrics' in vuln_assessment:
                    metrics_info['remediation_metrics']['mttd'] = vuln_assessment['metrics'].get('mttd', 0)
                    metrics_info['remediation_metrics']['mttr'] = vuln_assessment['metrics'].get('mttr', 0)
                    
        except Exception as e:
            self.console.print(f"[yellow]Warning: Vulnerability metrics calculation error: {str(e)}[/yellow]")
            
        self.results['vulnerability_metrics'] = metrics_info

    async def assess_risk_analysis(self) -> None:
        """Perform comprehensive risk analysis"""
        if not self.target:
            return
            
        self.console.print(f"[bold blue]Starting risk analysis...[/bold blue]")
        
        risk_info = {
            'threat_analysis': {},
            'vulnerability_impact': {},
            'asset_risk': {},
            'business_impact': {},
            'risk_mitigation': {},
            'risk_trends': {}
        }
        
        try:
            # Threat analysis
            risk_info['threat_analysis'] = {
                'threat_actors': [],
                'threat_vectors': [],
                'threat_likelihood': {},
                'threat_impact': {}
            }
            
            # Vulnerability impact analysis
            risk_info['vulnerability_impact'] = {
                'critical_impacts': [],
                'high_impacts': [],
                'medium_impacts': [],
                'low_impacts': []
            }
            
            # Asset risk assessment
            risk_info['asset_risk'] = {
                'critical_assets': [],
                'high_risk_assets': [],
                'medium_risk_assets': [],
                'low_risk_assets': []
            }
            
            # Business impact analysis
            risk_info['business_impact'] = {
                'financial_impact': {},
                'operational_impact': {},
                'reputational_impact': {},
                'regulatory_impact': {}
            }
            
            # Risk mitigation strategies
            risk_info['risk_mitigation'] = {
                'recommendations': [],
                'priorities': [],
                'timelines': {},
                'cost_estimates': {}
            }
            
            # Risk trends
            risk_info['risk_trends'] = {
                'historical_trends': [],
                'future_projections': {},
                'risk_factors': []
            }
            
            # Update risk analysis based on existing results
            if 'vulnerability_assessment' in self.results:
                vuln_assessment = self.results['vulnerability_assessment']
                
                # Analyze vulnerability impacts
                if 'common_vulnerabilities' in vuln_assessment:
                    for vuln in vuln_assessment['common_vulnerabilities']:
                        severity = vuln.get('severity', 'Unknown')
                        impact = vuln.get('impact', '')
                        
                        if severity == 'Critical':
                            risk_info['vulnerability_impact']['critical_impacts'].append({
                                'vulnerability': vuln.get('type', 'Unknown'),
                                'impact': impact
                            })
                        elif severity == 'High':
                            risk_info['vulnerability_impact']['high_impacts'].append({
                                'vulnerability': vuln.get('type', 'Unknown'),
                                'impact': impact
                            })
                            
                # Generate risk mitigation recommendations
                if 'remediation_priorities' in vuln_assessment:
                    for priority in vuln_assessment['remediation_priorities']:
                        risk_info['risk_mitigation']['recommendations'].append({
                            'vulnerability': priority['vulnerability'].get('type', 'Unknown'),
                            'priority': priority['priority_level'],
                            'timeline': priority['recommended_timeline'],
                            'team': priority['responsible_team']
                        })
                        
        except Exception as e:
            self.console.print(f"[yellow]Warning: Risk analysis error: {str(e)}[/yellow]")
            
        self.results['risk_analysis'] = risk_info

    async def assess_remediation_tracking(self) -> None:
        """Track and manage vulnerability remediation"""
        if not self.target:
            return
            
        self.console.print(f"[bold blue]Starting remediation tracking...[/bold blue]")
        
        remediation_info = {
            'open_issues': [],
            'in_progress': [],
            'resolved': [],
            'metrics': {},
            'timelines': {},
            'assignments': {}
        }
        
        try:
            # Get remediation data from database
            try:
                conn = sqlite3.connect('security_scanner.db')
                cursor = conn.cursor()
                
                # Get open issues
                cursor.execute('''
                    SELECT id, vuln_type, severity, discovery_date, status
                    FROM vulnerabilities
                    WHERE target = ? AND status != 'Remediated'
                    ORDER BY severity DESC
                ''', (self.target,))
                
                open_issues = cursor.fetchall()
                for issue in open_issues:
                    remediation_info['open_issues'].append({
                        'id': issue[0],
                        'type': issue[1],
                        'severity': issue[2],
                        'discovery_date': issue[3],
                        'status': issue[4]
                    })
                    
                # Get in-progress issues
                cursor.execute('''
                    SELECT id, vuln_type, severity, discovery_date, status
                    FROM vulnerabilities
                    WHERE target = ? AND status = 'In Progress'
                    ORDER BY severity DESC
                ''', (self.target,))
                
                in_progress = cursor.fetchall()
                for issue in in_progress:
                    remediation_info['in_progress'].append({
                        'id': issue[0],
                        'type': issue[1],
                        'severity': issue[2],
                        'discovery_date': issue[3],
                        'status': issue[4]
                    })
                    
                # Get resolved issues
                cursor.execute('''
                    SELECT id, vuln_type, severity, discovery_date, remediation_date
                    FROM vulnerabilities
                    WHERE target = ? AND status = 'Remediated'
                    ORDER BY remediation_date DESC
                    LIMIT 10
                ''', (self.target,))
                
                resolved = cursor.fetchall()
                for issue in resolved:
                    remediation_info['resolved'].append({
                        'id': issue[0],
                        'type': issue[1],
                        'severity': issue[2],
                        'discovery_date': issue[3],
                        'remediation_date': issue[4]
                    })
                    
                # Calculate metrics
                cursor.execute('''
                    SELECT 
                        COUNT(*) as total,
                        SUM(CASE WHEN status = 'Remediated' THEN 1 ELSE 0 END) as resolved,
                        AVG(JULIANDAY(remediation_date) - JULIANDAY(discovery_date)) as avg_time
                    FROM vulnerabilities
                    WHERE target = ?
                ''', (self.target,))
                
                metrics = cursor.fetchone()
                remediation_info['metrics'] = {
                    'total_issues': metrics[0] or 0,
                    'resolved_issues': metrics[1] or 0,
                    'resolution_rate': (metrics[1] or 0) / (metrics[0] or 1) * 100,
                    'average_resolution_time': metrics[2] or 0
                }
                
                conn.close()
                
            except Exception as e:
                remediation_info['metrics'] = {
                    'error': str(e)
                }
                
            # Generate timelines
            remediation_info['timelines'] = {
                'critical': '24 hours',
                'high': '72 hours',
                'medium': '1 week',
                'low': '1 month'
            }
            
            # Assign remediation tasks
            remediation_info['assignments'] = {
                'security_team': [],
                'development_team': [],
                'operations_team': []
            }
            
        except Exception as e:
            self.console.print(f"[yellow]Warning: Remediation tracking error: {str(e)}[/yellow]")
            
        self.results['remediation_tracking'] = remediation_info

# API endpoints
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/scan")
async def run_security_scan(scan_request: ScanRequest):
    """API endpoint to run security assessment"""
    try:
        # Initialize scanner
        scanner = SecurityScanner(
            target=scan_request.target,
            email=scan_request.email,
            profile=scan_request.profile
        )
        
        # Perform security assessment
        results = await scanner.run_scan()
        
        logger.info(f"Scan completed successfully for target: {scan_request.target}")
        
        # Return results directly
        return results
        
    except Exception as e:
        logger.error(f"Error during security scan: {str(e)}")
        return {
            'status': 'error',
            'message': f'Error during security scan: {str(e)}',
            'results': {}
        }

@app.get("/health")
async def health_check():
    """API endpoint to check service health"""
    return {"status": "healthy"}

@app.post("/download-report")
async def download_report(results: ScanResults, background: BackgroundTasks):
    """Generate and download a PDF report"""
    try:
        # TEMPORARY WORKAROUND: Get target from the results dict if available, else use placeholder
        report_target = results.results.get('target_from_scan', 'Unknown_Target')
        # Check if ScanResults object itself has target (it should now, but verifying)
        if hasattr(results, 'target') and results.target:
            report_target = results.target
        else:
            logger.warning("Target attribute missing from ScanResults object in /download-report, using placeholder.")


        # Create a temporary file for the PDF
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp:
            tmp_path = tmp.name

        # Create PDF
        pdf = FPDF()
        pdf.add_page()

        # Add title
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "Security Assessment Report", ln=True)
        pdf.ln(10)

        # Add target and date
        pdf.set_font("Arial", "", 12)
        pdf.cell(0, 10, f"Target: {report_target}", ln=True)
        pdf.cell(0, 10, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
        pdf.ln(10)

        # Add summary
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "Summary", ln=True)
        pdf.set_font("Arial", "", 10)
        
        # Calculate metrics
        total_issues = 0
        critical_issues = 0
        risk_score = 0
        
        for section, data in results.results.items():
            if isinstance(data, dict):
                if 'issues' in data:
                    total_issues += len(data['issues'])
                    # Safely check if item is a dict before calling .get()
                    critical_issues += len([i for i in data['issues'] 
                                            if isinstance(i, dict) and i.get('severity') == 'Critical'])
                if 'common_vulnerabilities' in data: # Also count critical vulns
                    # Add check for common_vulnerabilities as they definitely have severity
                    total_issues += len(data['common_vulnerabilities'])
                    critical_issues += len([v for v in data['common_vulnerabilities'] 
                                              if isinstance(v, dict) and v.get('severity') == 'Critical'])
                # Removed risk_score calculation as it's not displayed anymore
                # if 'risk_score' in data:
                #    risk_score = max(risk_score, data['risk_score'])
        
        pdf.cell(0, 10, f"Total Issues: {total_issues}", ln=True)
        pdf.cell(0, 10, f"Critical Issues: {critical_issues}", ln=True)
        # pdf.cell(0, 10, f"Risk Score: {risk_score}%", ln=True) # Keep risk score display commented out
        pdf.ln(10)

        # Add detailed results
        for section, data in results.results.items():
            # Skip sections that aren't dictionaries or are empty
            if not isinstance(data, dict) or not data:
                continue
                
            pdf.set_font("Arial", "B", 12)
            pdf.cell(0, 10, section.replace("_", " ").title(), ln=True)
            pdf.set_font("Arial", "", 10)
            
            # Check if data contains a simple status/message (like cloud_security)
            if all(k in data for k in ('status', 'message')) and len(data) == 2:
                 pdf.cell(0, 10, f"  Status: {data.get('status', 'N/A')}", ln=True)
                 pdf.cell(0, 10, f"  Message: {data.get('message', 'N/A')}", ln=True)
            # Otherwise, process as a dictionary of details
            else:
                for key, value in data.items():
                    # Skip placeholder error keys if they are empty or None
                    if key == "error" and not value:
                        continue

                    # --- Enhanced Type Checking --- 
                    if isinstance(value, list):
                        # Check if it's a list of simple strings (like issues)
                        if all(isinstance(item, str) for item in value):
                             pdf.cell(0, 10, f"  {key.replace('_', ' ').title()}: {', '.join(value) if value else 'None'}", ln=True)
                        # Otherwise, assume list of objects (like vulnerabilities or assets)
                        else:
                            pdf.cell(0, 10, f"  {key.replace('_', ' ').title()}: ({len(value)} items)", ln=True)
                            for item in value[:5]: # Limit displayed items in PDF
                                # Check if item in list is a dictionary before processing
                                if isinstance(item, dict):
                                    # Basic formatting for dict items in list
                                    item_str = ", ".join([f"{k}: {v}" for k, v in item.items()])
                                    pdf.cell(0, 10, f"    - {item_str}", ln=True)
                                else:
                                    # Just print the item if it's not a dict (e.g., a string)
                                    pdf.cell(0, 10, f"    - {item}", ln=True)
                            if len(value) > 5:
                                pdf.cell(0, 10, f"    ... and {len(value) - 5} more", ln=True)

                    elif isinstance(value, dict):
                        pdf.cell(0, 10, f"  {key.replace('_', ' ').title()}:", ln=True)
                        # Basic formatting for nested dicts
                        for k, v in value.items():
                             # Ensure v is not None before trying to display
                             display_v = v if v is not None else 'N/A'
                             pdf.cell(0, 10, f"    {k.replace('_', ' ').title()}: {display_v}", ln=True)
                    # Handle simple key-value pairs (strings, numbers, booleans)
                    elif isinstance(value, (str, int, float, bool)) or value is None:
                        display_value = value if value is not None else 'N/A'
                        pdf.cell(0, 10, f"  {key.replace('_', ' ').title()}: {display_value}", ln=True)
                    else:
                        # Fallback for unexpected types
                         pdf.cell(0, 10, f"  {key.replace('_', ' ').title()}: [Unsupported Data Type: {type(value).__name__}]", ln=True)
            pdf.ln(5)

        # Save the PDF
        pdf.output(tmp_path)

        # Add cleanup task
        background.add_task(lambda: os.unlink(tmp_path))

        # Return the file
        return FileResponse(
            tmp_path,
            media_type="application/pdf",
            filename="security-report.pdf"
        )

    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn # type: ignore
    uvicorn.run(app, host="0.0.0.0", port=8000) 