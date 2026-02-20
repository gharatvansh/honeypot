from fastapi.testclient import TestClient
from src.main import app
import json

client = TestClient(app)

def test_json_response():
    print("=" * 60)
    print("TESTING API JSON RESPONSE FORMAT")
    print("=" * 60)
    
    response = client.post(
        "/api/honeypot",
        json={
            "sessionId": "test-session-123", 
            "message": {
                "text": "URGENT: Your SBI account has been compromised. Share OTP immediately.",
                "sender": "scammer"
            }
        },
        headers={"x-api-key": "honeypot-secret-key-2024"} # Default from main.py
    )
    
    print(f"Status Code: {response.status_code}")
    content_type = response.headers.get('content-type', '')
    print(f"Content-Type: {content_type}")
    
    if "application/json" in content_type:
        print("[PASS] Content-Type specifies application/json")
    else:
        print("[FAIL] Content-Type is not application/json")
        
    try:
        data = response.json()
        print("[PASS] Response body is valid, parsable JSON!")
        
        # Verify required fields from the PDF
        expected_fields = ["status", "reply"]
        all_present = True
        for field in expected_fields:
            if field in data or (field == "reply" and any(k in data for k in ["reply", "message", "text"])):
                print(f"[PASS] Found required response field: {field}")
            else:
                print(f"[FAIL] Missing required response field: {field}")
                all_present = False
                
        if all_present:
            print("\nAPI Response Structure Check: PERFECT [PASS]")
        else:
            print("\nAPI Response Structure Check: FAILED [FAIL]")
            
    except Exception as e:
        print(f"[FAIL] Failed to parse response as JSON: {e}")
        print(f"Raw response text: {response.text}")

if __name__ == "__main__":
    test_json_response()
