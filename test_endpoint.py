"""Test the honeypot endpoint with various body formats."""
import json
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)
headers = {"X-API-Key": "honeypot-secret-key-2024"}

print("="*60)
print("Testing /api/honeypot endpoint with various body formats")
print("="*60)

# Test 1: Empty body
print("\nTest 1 - Empty body:")
r = client.post("/api/honeypot", headers=headers)
print(f"  Status: {r.status_code}")
print(f"  Success: {r.json().get('success', 'N/A')}")

# Test 2: JSON with message
print("\nTest 2 - JSON with message:")
r = client.post("/api/honeypot", headers=headers, json={"message": "Hello test"})
print(f"  Status: {r.status_code}")
print(f"  Success: {r.json().get('success', 'N/A')}")

# Test 3: Plain string as body
print("\nTest 3 - Plain string:")
r = client.post("/api/honeypot", headers=headers, content="Hello test")
print(f"  Status: {r.status_code}")
print(f"  Success: {r.json().get('success', 'N/A')}")

# Test 4: Empty JSON object
print("\nTest 4 - Empty JSON object:")
r = client.post("/api/honeypot", headers=headers, json={})
print(f"  Status: {r.status_code}")
print(f"  Success: {r.json().get('success', 'N/A')}")

# Test 5: JSON string (not object)
print("\nTest 5 - JSON string (not object):")
r = client.post(
    "/api/honeypot", 
    headers={"X-API-Key": "honeypot-secret-key-2024", "Content-Type": "application/json"},
    content='"test message"'
)
print(f"  Status: {r.status_code}")
print(f"  Success: {r.json().get('success', 'N/A')}")

# Test 6: Array body
print("\nTest 6 - JSON array:")
r = client.post(
    "/api/honeypot",
    headers={"X-API-Key": "honeypot-secret-key-2024", "Content-Type": "application/json"},
    content='["message 1", "message 2"]'
)
print(f"  Status: {r.status_code}")
print(f"  Success: {r.json().get('success', 'N/A')}")

# Test 7: Nested message object
print("\nTest 7 - Nested message object:")
r = client.post(
    "/api/honeypot",
    headers=headers,
    json={"message": {"text": "nested text", "content": "nested content"}}
)
print(f"  Status: {r.status_code}")
print(f"  Success: {r.json().get('success', 'N/A')}")

# Test 8: Number as message
print("\nTest 8 - Number as message:")
r = client.post(
    "/api/honeypot",
    headers=headers,
    json={"message": 12345}
)
print(f"  Status: {r.status_code}")
print(f"  Success: {r.json().get('success', 'N/A')}")

# Test 9: Null message
print("\nTest 9 - Null message:")
r = client.post(
    "/api/honeypot",
    headers=headers,
    json={"message": None}
)
print(f"  Status: {r.status_code}")
print(f"  Success: {r.json().get('success', 'N/A')}")

# Test 10: Boolean as message
print("\nTest 10 - Boolean as message:")
r = client.post(
    "/api/honeypot",
    headers=headers,
    json={"message": True}
)
print(f"  Status: {r.status_code}")
print(f"  Success: {r.json().get('success', 'N/A')}")

print("\n" + "="*60)
print("All tests completed")
print("="*60)
