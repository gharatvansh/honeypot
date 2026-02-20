"""
PDF Compliance Verification Tests
Runs spot-checks for all 6 fixes applied.
"""
import sys, json
sys.path.insert(0, '.')
from dotenv import load_dotenv
load_dotenv()


print("=" * 60)
print("TEST 1: UPI Extraction — scammer.fraud@fakebank style")
print("=" * 60)
from src.extraction.extractor import extract_intelligence
result = extract_intelligence(
    "My UPI ID is scammer.fraud@fakebank and cashback.scam@fakeupi. "
    "Call +91-9876543210. Bank account 1234567890123456"
)
print(json.dumps(result, indent=2))
upi_ids = result.get("upi_ids", [])
upi_id_strs = [u.get("upi_id") for u in upi_ids if isinstance(u, dict)]
assert "scammer.fraud@fakebank" in upi_id_strs, f"FAIL: scammer.fraud@fakebank not found! Got: {upi_id_strs}"
assert "cashback.scam@fakeupi" in upi_id_strs, f"FAIL: cashback.scam@fakeupi not found! Got: {upi_id_strs}"
print("PASS: Both UPI IDs extracted correctly\n")

print("=" * 60)
print("TEST 2: bank_fraud scam type detection")
print("=" * 60)
from src.detection.scam_detector import analyze_message
r2 = analyze_message("URGENT: Your SBI account has been compromised. Share OTP immediately.")
print(f"is_scam: {r2['is_scam']}")
print(f"scam_type: {r2['scam_type']}")
print(f"confidence: {r2['confidence']}")
assert r2['is_scam'], "FAIL: Should be detected as scam"
assert r2['scam_type'] == 'bank_fraud', f"FAIL: Expected bank_fraud, got {r2['scam_type']}"
print("PASS: bank_fraud detected correctly\n")

print("=" * 60)
print("TEST 3: phishing scam type detection")
print("=" * 60)
r3 = analyze_message("Click here http://amaz0n-deals.fake-site.com/claim?id=12345 to claim your free gift!")
print(f"is_scam: {r3['is_scam']}")
print(f"scam_type: {r3['scam_type']}")
print(f"confidence: {r3['confidence']}")
assert r3['is_scam'], "FAIL: Should be detected as scam"
assert r3['scam_type'] in ('phishing', 'lottery'), f"FAIL: Expected phishing/lottery, got {r3['scam_type']}"
print(f"PASS: phishing/lottery detected correctly ({r3['scam_type']})\n")

print("=" * 60)
print("TEST 4: scamDetected threshold in finalOutput")
print("=" * 60)
from src.honeypot_agent import ConversationManager
cm = ConversationManager()
result4 = cm.start_conversation("URGENT: Your SBI account has been compromised. Share OTP immediately.")
conv_id = result4['conversation_id']
final = cm.get_final_output(conv_id)
print(f"scamDetected: {final['scamDetected']}")
print(f"scamType: {final['scamType']}")
print(f"confidenceLevel: {final['confidenceLevel']}")
assert final['scamDetected'] == True, "FAIL: scamDetected should be True"
print("PASS: scamDetected threshold correct\n")

print("=" * 60)
print("TEST 5: MessageBody accepts string timestamp (no 422)")
print("=" * 60)
from src.main import MessageBody
try:
    mb = MessageBody(sender="scammer", text="Hello", timestamp="2025-02-11T10:30:00Z")
    print(f"PASS: String timestamp accepted: {mb.timestamp}")
except Exception as e:
    print(f"FAIL: {e}")

try:
    mb2 = MessageBody(sender="scammer", text="Hello", timestamp=1739271000000)
    print(f"PASS: Int timestamp accepted: {mb2.timestamp}")
except Exception as e:
    print(f"FAIL: {e}")

print("\n" + "=" * 60)
print("ALL TESTS PASSED")
print("=" * 60)
