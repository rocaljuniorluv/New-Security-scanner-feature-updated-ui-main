#!/usr/bin/env python3
"""
Test script for Google Dorking and Typosquatting functionality
"""

import asyncio
from security_scanner import SecurityScanner
from google_dorking import GoogleDorker, TypoSquatter, SECURITY_DORKS
import os
from dotenv import load_dotenv

async def test_google_dorking():
    # Load environment variables
    load_dotenv()
    
    # Initialize scanner
    scanner = SecurityScanner(
        target="example.com",
        profile="standard"
    )
    
    print("\n=== Testing Google Dorking ===")
    try:
        # Initialize GoogleDorker
        dorker = GoogleDorker(domain="example.com")
        
        # Test individual dork
        print("\nTesting single dork search...")
        results = dorker.search("intext:password filetype:txt")
        print(f"Found {len(results)} results")
        for result in results:
            print(f"- {result['title']}: {result['url']}")
        
        # Test multiple dorks
        print("\nTesting multiple dorks...")
        all_results = dorker.run_dorks(SECURITY_DORKS[:3])  # Test first 3 dorks
        print(f"Total findings: {len(all_results)}")
        
    except Exception as e:
        print(f"Error during Google dorking test: {e}")

async def test_typosquatting():
    print("\n=== Testing Typosquatting ===")
    try:
        # Initialize TypoSquatter
        squatter = TypoSquatter(domain="example.com")
        
        # Generate typos
        print("\nGenerating typosquatting variations...")
        variations = squatter.generate_typos()
        print(f"Generated {len(variations)} variations")
        
        # Test domain availability check
        print("\nTesting domain availability check...")
        results = squatter.scan()
        print(f"Found {len(results)} registered domains")
        for result in results:
            print(f"- {result['domain']}: {result['status']} (Risk: {result['risk']})")
        
    except Exception as e:
        print(f"Error during typosquatting test: {e}")

async def test_integration():
    print("\n=== Testing Integration with SecurityScanner ===")
    try:
        scanner = SecurityScanner(
            target="example.com",
            profile="standard"
        )
        
        # Test Google dorking assessment
        print("\nTesting Google dorking assessment...")
        await scanner.assess_google_dorking()
        if hasattr(scanner, 'results') and 'google_dorking' in scanner.results:
            print(f"Google dorking results: {len(scanner.results['google_dorking'].get('findings', []))} findings")
        
        # Test typosquatting assessment
        print("\nTesting typosquatting assessment...")
        await scanner.assess_typosquatting()
        if hasattr(scanner, 'results') and 'typosquatting' in scanner.results:
            print(f"Typosquatting results: {len(scanner.results['typosquatting'].get('findings', []))} findings")
        
    except Exception as e:
        print(f"Error during integration test: {e}")

async def main():
    await test_google_dorking()
    await test_typosquatting()
    await test_integration()

if __name__ == "__main__":
    asyncio.run(main()) 