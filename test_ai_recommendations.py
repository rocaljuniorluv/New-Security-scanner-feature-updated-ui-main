import asyncio
from security_scanner import SecurityScanner
import os
from dotenv import load_dotenv

async def test_ai_recommendations():
    # Load environment variables
    load_dotenv()
    
    # Check if OpenAI API key is set
    if not os.getenv("OPENAI_API_KEY"):
        print("Error: OPENAI_API_KEY not found in environment variables")
        return
    
    # Initialize scanner
    scanner = SecurityScanner(
        target="example.com",
        email="test@example.com",
        profile="standard"
    )
    
    # Test AI recommendation generation
    print("\nTesting AI recommendation generation...")
    recommendation = await scanner.get_ai_recommendation(
        issue="Missing SPF record",
        context="Email security assessment for test@example.com"
    )
    
    print("\nAI Recommendation Result:")
    print(f"Status: {recommendation['status']}")
    print(f"Recommendation: {recommendation['recommendation']}")
    
    # Test AI recommendations for different issues
    print("\nTesting AI recommendations for various security issues...")
    issues = [
        "Weak SSL/TLS configuration",
        "Missing security headers",
        "Outdated software version",
        "Open port 22 (SSH)",
        "Missing DMARC record"
    ]
    
    for issue in issues:
        print(f"\nTesting issue: {issue}")
        recommendation = await scanner.get_ai_recommendation(
            issue=issue,
            context="General security assessment"
        )
        print(f"Status: {recommendation['status']}")
        print(f"Recommendation: {recommendation['recommendation']}")

if __name__ == "__main__":
    asyncio.run(test_ai_recommendations()) 