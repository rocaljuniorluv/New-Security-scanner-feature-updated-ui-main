import requests
import json
import urllib3
import warnings
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import print as rprint
from datetime import datetime
import time

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore', category=urllib3.exceptions.InsecureRequestWarning)

# Initialize Rich console
console = Console()

def run_scan():
    """Run a security scan with detailed output"""
    url = "http://127.0.0.1:3000/scan"
    
    # Enhanced scan profile with all modules enabled
    scan_data = {
        "target": "digissllc.com",
        "profile": "comprehensive",
        "modules": {
            "network_security": {
                "enabled": True,
                "timeout": 120,
                "options": {
                    "port_scan": True,
                    "service_detection": True,
                    "os_detection": True,
                    "vulnerability_scan": True
                }
            },
            "dns_health": {
                "enabled": True,
                "timeout": 60,
                "options": {
                    "check_all_records": True,
                    "dnssec_check": True,
                    "spf_check": True,
                    "dmarc_check": True
                }
            },
            "email_security": {
                "enabled": True,
                "timeout": 60,
                "options": {
                    "spf_check": True,
                    "dkim_check": True,
                    "dmarc_check": True,
                    "mx_check": True
                }
            },
            "endpoint_security": {
                "enabled": True,
                "timeout": 120,
                "options": {
                    "port_scan": True,
                    "service_detection": True,
                    "vulnerability_scan": True
                }
            },
            "application_security": {
                "enabled": True,
                "timeout": 120,
                "options": {
                    "web_scan": True,
                    "api_scan": True,
                    "vulnerability_scan": True
                }
            },
            "vulnerability_assessment": {
                "enabled": True,
                "timeout": 180,
                "options": {
                    "cve_check": True,
                    "misconfig_check": True,
                    "weak_crypto_check": True
                }
            },
            "ip_reputation": {
                "enabled": True,
                "timeout": 60,
                "options": {
                    "blacklist_check": True,
                    "malware_check": True,
                    "spam_check": True
                }
            },
            "ssl_tls_security": {
                "enabled": True,
                "timeout": 60,
                "options": {
                    "cert_check": True,
                    "protocol_check": True,
                    "cipher_check": True
                }
            },
            "api_security": {
                "enabled": True,
                "timeout": 120,
                "options": {
                    "endpoint_scan": True,
                    "auth_check": True,
                    "rate_limit_check": True
                }
            },
            "container_security": {
                "enabled": True,
                "timeout": 120,
                "options": {
                    "image_scan": True,
                    "runtime_scan": True,
                    "config_check": True
                }
            },
            "database_security": {
                "enabled": True,
                "timeout": 120,
                "options": {
                    "config_check": True,
                    "access_check": True,
                    "backup_check": True
                }
            },
            "patching_status": {
                "enabled": True,
                "timeout": 60,
                "options": {
                    "os_update_check": True,
                    "app_update_check": True,
                    "security_patch_check": True
                }
            }
        }
    }

    # Create progress display
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        # Add main task
        main_task = progress.add_task("[cyan]Running Security Scan...", total=None)
        
        try:
            # Send scan request
            console.print("\n[bold cyan]Sending scan request to server...[/bold cyan]")
            start_time = time.time()
            
            response = requests.post(url, json=scan_data, verify=False)
            end_time = time.time()
            
            # Update progress
            progress.update(main_task, completed=True)
            
            # Print results
            console.print(f"\n[bold green]Scan completed in {end_time - start_time:.2f} seconds[/bold green]")
            console.print(f"\n[bold]Status Code:[/bold] {response.status_code}\n")
            
            if response.status_code == 200:
                results = response.json()
                
                # Create detailed results table
                table = Table(title="Detailed Scan Results", show_header=True, header_style="bold magenta")
                table.add_column("Module", style="cyan")
                table.add_column("Status", style="green")
                table.add_column("Details", style="yellow")
                
                # Add overall status
                table.add_row(
                    "STATUS",
                    f"[green]{results.get('status', 'unknown')}[/green]",
                    json.dumps(results.get('status', 'unknown'), indent=2)
                )
                
                table.add_row(
                    "MESSAGE",
                    f"[green]{results.get('message', 'unknown')}[/green]",
                    json.dumps(results.get('message', 'unknown'), indent=2)
                )
                
                # Add results for each module
                for module, data in results.get('results', {}).items():
                    if isinstance(data, dict):
                        # Extract status and details
                        if 'status' in data:
                            status = data['status']
                            details = data.get('data', {})
                        else:
                            status = "completed" if data else "error"
                            details = data
                        
                        # Format details for display
                        details_str = ""
                        if details:
                            # Extract key information
                            summary = {}
                            if 'issues' in details:
                                summary['issues'] = details['issues']
                            if 'security_issues' in details:
                                summary['security_issues'] = details['security_issues']
                            if 'endpoints' in details:
                                summary['endpoints'] = details['endpoints']
                            if 'security_headers' in details:
                                summary['security_headers'] = details['security_headers']
                            if 'ip_info' in details:
                                summary['ip_info'] = details['ip_info']
                            if 'dns_info' in details:
                                summary['dns_info'] = details['dns_info']
                            if 'whois_info' in details:
                                summary['whois_info'] = details['whois_info']
                            if 'certificate_info' in details:
                                summary['certificate_info'] = details['certificate_info']
                            if 'validation' in details:
                                summary['validation'] = details['validation']
                            if 'domain_security' in details:
                                summary['domain_security'] = details['domain_security']
                            if 'server_config' in details:
                                summary['server_config'] = details['server_config']
                            if 'authentication' in details:
                                summary['authentication'] = details['authentication']
                            if 'reputation' in details:
                                summary['reputation'] = details['reputation']
                            if 'best_practices' in details:
                                summary['best_practices'] = details['best_practices']
                            if 'phishing_risk' in details:
                                summary['phishing_risk'] = details['phishing_risk']
                            
                            details_str = json.dumps(summary, indent=2)
                            if len(details_str) > 200:
                                details_str = details_str[:197] + "..."
                        else:
                            details_str = "{}"
                    else:
                        status = "completed"
                        details = data
                        details_str = json.dumps(details, indent=2)
                        if len(details_str) > 200:
                            details_str = details_str[:197] + "..."
                    
                    table.add_row(
                        module.upper(),
                        f"[{'green' if status == 'completed' else 'red'}]{status}[/{'green' if status == 'completed' else 'red'}]",
                        details_str
                    )
                
                console.print(table)
                
                # Print summary
                console.print("\n[bold]Summary:[/bold]")
                total_modules = len(results.get('results', {}))
                console.print(f"Total Modules: {total_modules}")
                completed = sum(1 for data in results.get('results', {}).values() if isinstance(data, dict) and data.get("status") == "completed")
                console.print(f"Completed Successfully: {completed}")
                errors = sum(1 for data in results.get('results', {}).values() if isinstance(data, dict) and data.get("status") == "error")
                console.print(f"Errors: {errors}")
                
            else:
                console.print(f"[bold red]Error:[/bold red] {response.text}")
                
        except Exception as e:
            console.print(f"[bold red]Error running scan:[/bold red] {str(e)}")
            progress.update(main_task, completed=True)

def test_security_scanner():
    url = "http://127.0.0.1:8000/scan"
    payload = {
        "target": "digissllc.com",
        "profile": "standard"
    }
    
    try:
        console.print(Panel.fit(
            "Security Scanner\nRunning comprehensive security assessment...",
            title="Security Scanner"
        ))
        
        console.print("Sending scan request to server...\n")
        response = requests.post(url, json=payload)
        
        if response.status_code == 200:
            results = response.json()
            
            # Create a table for scan results
            table = Table(title="Detailed Scan Results")
            table.add_column("Module", style="cyan")
            table.add_column("Status", style="green")
            table.add_column("Details", style="yellow")
            
            # Add results to table
            for module, data in results.items():
                if isinstance(data, dict):
                    status = data.get('status', 'unknown')
                    details = json.dumps(data.get('details', {}))
                    table.add_row(module, status, details)
            
            console.print(table)
            
            # Print summary
            console.print("\nSummary:")
            console.print(f"Total Modules: {len(results)}")
            completed = sum(1 for data in results.values() if isinstance(data, dict) and data.get('status') == 'completed')
            errors = sum(1 for data in results.values() if isinstance(data, dict) and data.get('status') == 'error')
            console.print(f"Completed Successfully: {completed}")
            console.print(f"Errors: {errors}")
        else:
            console.print(f"[red]Error: Server returned status code {response.status_code}[/red]")
            console.print(response.text)
            
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

if __name__ == "__main__":
    test_security_scanner()