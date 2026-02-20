"""Test the honeypot endpoint with the structured request format."""
import json
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)
headers = {"X-API-Key": "honeypot-secret-key-2024"}

print("Testing structured request format")
print("=" * 60)

# Test 1: New format - first message
print("\nTest 1 - New format (first message):")
r = client.post("/api/honeypot", headers=headers, json={
    "sessionId": "test-session-123",
    "message": {
        "sender": "scammer",
        "text": "Your bank account will be blocked today. Verify immediately.",
        "timestamp": 1770005528731
    },
    "conversationHistory": [],
    "metadata": {
        "channel": "SMS",
        "language": "English",
        "locale": "IN"
    }
})
resp = r.json()
print(f"  Status: {r.status_code}")
print(f"  Success: {resp.get('success')}")
print(f"  SessionId: {resp.get('sessionId')}")
print(f"  Scam Detected: {resp.get('scam_detected')}")
print(f"  Response: {resp.get('message', '')[:50]}...")

# Test 2: New format - follow-up message
print("\nTest 2 - New format (follow-up message):")
r = client.post("/api/honeypot", headers=headers, json={
    "sessionId": "test-session-123",
    "message": {
        "sender": "scammer",
        "text": "Share your UPI ID to avoid account suspension.",
        "timestamp": 1770005528732
    },
    "conversationHistory": [
        {
            "sender": "scammer",
            "text": "Your bank account will be blocked today. Verify immediately.",
            "timestamp": 1770005528731
        },
        {
            "sender": "user",
            "text": "Why will my account be blocked?",
            "timestamp": 1770005528731
        }
    ],
    "metadata": {
        "channel": "SMS",
        "language": "English",
        "locale": "IN"
    }
})
resp = r.json()
print(f"  Status: {r.status_code}")
print(f"  Success: {resp.get('success')}")
print(f"  SessionId: {resp.get('sessionId')}")
print(f"  Scam Detected: {resp.get('scam_detected')}")
print(f"  Response: {resp.get('message', '')[:50]}...")

# Test 3: New format without metadata
print("\nTest 3 - New format (without metadata):")
r = client.post("/api/honeypot", headers=headers, json={
    "sessionId": "test-session-456",
    "message": {
        "sender": "scammer",
        "text": "Click this link to verify: http://fakepaypal.com/verify",
        "timestamp": 1770005528731
    },
    "conversationHistory": []
})
resp = r.json()
print(f"  Status: {r.status_code}")
print(f"  Success: {resp.get('success')}")
print(f"  Phishing Links: {resp.get('extracted_intelligence', {}).get('phishing_links')}")

print("\n" + "=" * 60)
print("All new format tests completed!")
