import asyncio
from security_scanner import SecurityScanner
from dotenv import load_dotenv
import os

async def test_traceback_integration():
    # Load environment variables
    load_dotenv()
    
    # Check if API key is present
    if not os.getenv('TRACEBACK_API_KEY'):
        print("Error: TRACEBACK_API_KEY not found in environment variables")
        return
    
    # Initialize scanner
    scanner = SecurityScanner(
        target="example.com",
        email="test@example.com",
        profile="standard"
    )
    
    print("Testing data leak assessment...")
    try:
        results = await scanner.traceback_api.perform_all_lookups(
            query="example.com",
            email="test@example.com"
        )
        
        print(f"\nData leak assessment completed with status: {results['status']}")
        print(f"Message: {results['message']}")
        
        print("\nFindings:")
        for key, value in results['findings'].items():
            print(f"\n{key}:")
            if 'error' in value:
                print(f"Error: {value['error']}")
            else:
                print(f"Status: {value.get('status', 'unknown')}")
                print(f"Type: {value.get('type', 'unknown')}")
                print(f"Query: {value.get('query', 'unknown')}")
                print(f"Count: {value.get('count', 0)} results")
                if value.get('results'):
                    print("Results:")
                    for result in value['results'][:3]:  # Show first 3 results
                        print(f"  - {result}")
                    if len(value['results']) > 3:
                        print(f"  ... and {len(value['results']) - 3} more results")
    except Exception as e:
        print(f"Error during data leak assessment: {str(e)}")

if __name__ == "__main__":
    asyncio.run(test_traceback_integration()) 