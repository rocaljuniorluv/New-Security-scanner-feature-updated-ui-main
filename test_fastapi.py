from fastapi.testclient import TestClient
from security_scanner import app
import json

client = TestClient(app)

def test_scan():
    response = client.post(
        "/scan",
        json={
            "target": "digissllc.com",
            "profile": "quick"
        }
    )
    print("Status Code:", response.status_code)
    print("Response:", json.dumps(response.json(), indent=2))

if __name__ == "__main__":
    test_scan() 