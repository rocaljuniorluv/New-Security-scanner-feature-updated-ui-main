#!/usr/bin/env python3
import os
import asyncio
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from dotenv import load_dotenv
from rich.console import Console
import json
import aiohttp
from typing import Dict, Any

class SecurityScannerBot:
    def __init__(self):
        load_dotenv()
        self.console = Console()
        self.slack_token = os.getenv('SLACK_BOT_TOKEN')
        self.api_url = os.getenv('API_URL', 'http://localhost:8000')
        
        if not self.slack_token:
            raise ValueError("SLACK_BOT_TOKEN not found in environment variables")
            
        self.client = WebClient(token=self.slack_token)
        
    async def handle_command(self, command: str, channel: str, user: str) -> None:
        """Handle incoming Slack commands"""
        try:
            # Parse command
            parts = command.split()
            if not parts:
                await self.send_message(channel, "Please provide a command. Available commands:\n- scan <target> [email]\n- help")
                return
                
            cmd = parts[0].lower()
            
            if cmd == 'help':
                await self.show_help(channel)
            elif cmd == 'scan':
                await self.handle_scan(parts[1:], channel, user)
            else:
                await self.send_message(channel, f"Unknown command: {cmd}. Type 'help' for available commands.")
                
        except Exception as e:
            self.console.print(f"[red]Error handling command: {str(e)}[/red]")
            await self.send_message(channel, f"Error processing command: {str(e)}")
            
    async def handle_scan(self, args: list, channel: str, user: str) -> None:
        """Handle scan command"""
        if not args:
            await self.send_message(channel, "Please provide a target to scan. Usage: scan <target> [email]")
            return
            
        target = args[0]
        email = args[1] if len(args) > 1 else None
        
        # Send initial message
        await self.send_message(channel, f"Starting security scan for {target}...")
        
        try:
            # Call security scanner API
            async with aiohttp.ClientSession() as session:
                payload = {
                    "target": target,
                    "email": email,
                    "profile": "comprehensive"
                }
                
                async with session.post(f"{self.api_url}/scan", json=payload) as response:
                    if response.status == 200:
                        results = await response.json()
                        await self.send_scan_results(channel, results)
                    else:
                        error_text = await response.text()
                        await self.send_message(channel, f"Error during scan: {error_text}")
                        
        except Exception as e:
            self.console.print(f"[red]Error during scan: {str(e)}[/red]")
            await self.send_message(channel, f"Error during scan: {str(e)}")
            
    async def send_scan_results(self, channel: str, results: Dict[str, Any]) -> None:
        """Format and send scan results to Slack"""
        try:
            # Create a formatted message
            message = f"""
*Security Scan Results*

*Network Security*
• IP Information: {results.get('network_security', {}).get('ip_info', {})}
• DNS Records: {results.get('network_security', {}).get('dns_info', {})}
• WHOIS Information: {results.get('network_security', {}).get('whois_info', {})}

*Email Security*
• Validation: {results.get('email_security', {}).get('validation', {})}
• Domain Security: {results.get('email_security', {}).get('domain_security', {})}
• Phishing Risk Score: {results.get('email_security', {}).get('phishing_risk', {}).get('score', 0)}

*Endpoint Security*
• Security Headers: {', '.join(results.get('endpoint_security', {}).get('security_headers', {}).keys())}
• Issues: {', '.join(results.get('endpoint_security', {}).get('issues', [])) if results.get('endpoint_security', {}).get('issues', []) else 'None'}

*SSL/TLS Security*
• Certificate Information: {results.get('ssl_tls_security', {}).get('certificate_info', {})}
• Security Issues: {', '.join(results.get('ssl_tls_security', {}).get('security_issues', [])) if results.get('ssl_tls_security', {}).get('security_issues', []) else 'None'}

*Asset Inventory*
• Asset Types: {', '.join(results.get('asset_inventory', {}).get('asset_types', {}).keys())}
• Risk Levels: {results.get('asset_inventory', {}).get('risk_levels', {})}
"""
            
            # Send the message to Slack
            await self.send_message(channel, message)
            
        except Exception as e:
            self.console.print(f"[red]Error sending scan results: {str(e)}[/red]")
            await self.send_message(channel, f"Error formatting scan results: {str(e)}")
            
    async def show_help(self, channel: str) -> None:
        """Show help message with available commands"""
        help_message = """
*Security Scanner Bot Commands*

*scan <target> [email]*
• Initiates a security scan for the specified target
• Optional email parameter for email security assessment
• Example: scan example.com test@example.com

*help*
• Shows this help message

*Note:* All scans are performed using passive reconnaissance techniques.
"""
        await self.send_message(channel, help_message)
        
    async def send_message(self, channel: str, message: str) -> None:
        """Send a message to a Slack channel"""
        try:
            await self.client.chat_postMessage(
                channel=channel,
                text=message,
                parse='mrkdwn'
            )
        except SlackApiError as e:
            self.console.print(f"[red]Error sending message to Slack: {str(e)}[/red]")
            
    async def start(self) -> None:
        """Start the Slack bot"""
        self.console.print("[bold blue]Starting Security Scanner Bot...[/bold blue]")
        
        try:
            # Test the connection
            await self.client.auth_test()
            self.console.print("[green]Successfully connected to Slack[/green]")
            
            # Keep the bot running
            while True:
                await asyncio.sleep(1)
                
        except Exception as e:
            self.console.print(f"[red]Error starting bot: {str(e)}[/red]")
            
if __name__ == "__main__":
    bot = SecurityScannerBot()
    asyncio.run(bot.start()) 