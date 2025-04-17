import requests
import json
from rich.console import Console
from rich.table import Table
import urllib3
import time

# Disable SSL verification warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()

def run_scan_profile(profile):
    """Run a scan with the specified profile"""
    console.print(f"\n[bold blue]Starting Security Scanner Test - {profile.upper()} Profile[/bold blue]")
    
    # Configure session with proper SSL verification
    session = requests.Session()
    session.verify = True
    session.headers.update({
        'User-Agent': 'Security Scanner Test/1.0',
        'Accept': 'application/json'
    })
    
    try:
        # Send scan request
        console.print(f"[cyan]Sending scan request with {profile} profile...[/cyan]")
        start_time = time.time()
        
        response = session.post(
            "http://127.0.0.1:8000/scan",
            json={
                "target": "digissllc.com",
                "profile": profile
            },
            timeout=300  # Increased timeout for comprehensive scans
        )
        
        end_time = time.time()
        scan_duration = end_time - start_time
        
        if response.status_code == 200:
            results = response.json()
            
            console.print(f"[bold green]Scan completed in {scan_duration:.2f} seconds[/bold green]")
            
            # Create results table
            table = Table(title=f"Security Scan Results - {profile.upper()} Profile")
            table.add_column("Module", style="cyan")
            table.add_column("Status", style="green")
            table.add_column("Details", style="yellow")
            
            # Add results to table
            for module, data in results.items():
                status = "Success" if 'error' not in data else "Error"
                details = str(data.get('error', 'Completed')) if 'error' in data else "Completed"
                table.add_row(module, status, details)
            
            console.print(table)
            
            # Print summary
            console.print(f"\n[bold green]Scan Summary - {profile.upper()} Profile:[/bold green]")
            console.print(f"Total Modules: {len(results)}")
            console.print(f"Completed Successfully: {sum(1 for data in results.values() if 'error' not in data)}")
            console.print(f"Errors: {sum(1 for data in results.values() if 'error' in data)}")
            
            return True
            
        else:
            console.print(f"[bold red]Error:[/bold red] Server returned status code {response.status_code}")
            console.print(response.text)
            return False
            
    except requests.exceptions.RequestException as e:
        console.print(f"[bold red]Error:[/bold red] Failed to connect to server: {str(e)}")
        return False
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        return False

def test_all_profiles():
    """Test all three scan profiles"""
    profiles = ["quick", "standard", "comprehensive"]
    results = {}
    
    for profile in profiles:
        console.print(f"\n[bold cyan]===== Testing {profile.upper()} Profile =====[/bold cyan]")
        result = run_scan_profile(profile)
        results[profile] = result
        
    # Print overall summary
    console.print("\n[bold blue]========= OVERALL TEST SUMMARY ==========[/bold blue]")
    for profile, success in results.items():
        status = "[green]SUCCESS[/green]" if success else "[red]FAILED[/red]"
        console.print(f"{profile.upper()} Profile: {status}")

if __name__ == "__main__":
    test_all_profiles() 