"""
Utility functions for the Honeypot system.
Contains helper functions for text analysis and note generation.
"""

from typing import Dict, List, Optional


# Suspicious keywords to look for in scam messages
SUSPICIOUS_KEYWORDS = [
    "urgent", "verify", "immediately", "blocked", "suspended",
    "account", "bank", "upi", "otp", "password", "pin",
    "click", "link", "update", "confirm", "transfer",
    "prize", "lottery", "winner", "congratulations", "claim",
    "kyc", "aadhar", "pan", "expired", "renew",
    "refund", "cashback", "offer", "limited", "hurry"
]

# Red flag definitions for scoring (evaluator awards points per flag identified)
RED_FLAG_RULES = [
    ("urgency",              ["urgent", "immediately", "hurry", "running out of time", "fast", "quick"]),
    ("OTP request",          ["otp", "one time password", "verification code", "share otp", "enter otp"]),
    ("payment redirection",  ["upi", "bank account", "transfer", "send money", "pay", "account number", "ifsc"]),
    ("suspicious link",      ["http://", "https://", "click here", "click the link", "bit.ly", "tinyurl", ".com/", "fake"]),
    ("fear-based threat",    ["blocked", "suspended", "frozen", "compromised", "permanently", "action required"]),
    ("impersonation",        ["sbi", "hdfc", "icici", "axis", "rbi", "police", "cyber crime", "employee id", "officer"]),
    ("identity theft",       ["kyc", "aadhar", "aadhaar", "pan card", "passport", "date of birth", "full name"]),
    ("prize/lottery scam",   ["prize", "lottery", "winner", "congratulations", "cashback", "reward", "selected"]),
]


def extract_suspicious_keywords(message: str) -> List[str]:
    """Extract suspicious keywords from a message."""
    message_lower = message.lower()
    found_keywords = []
    
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in message_lower:
            found_keywords.append(keyword)
    
    return found_keywords


def identify_red_flags(full_text: str) -> List[str]:
    """Identify red flags in the full conversation text. Used for scoring."""
    text_lower = full_text.lower()
    found_flags = []
    for flag_name, keywords in RED_FLAG_RULES:
        if any(kw in text_lower for kw in keywords):
            found_flags.append(flag_name)
    return found_flags


def generate_agent_notes(
    scam_type: Optional[str],
    extracted_intelligence: Dict,
    message_count: int,
    suspicious_keywords: List[str],
    full_conversation_text: str = "",
    questions_asked: int = 0
) -> str:
    """Generate a rich summary of scammer behavior with explicit red flags.
    
    Red flags are scored independently by the evaluator (≥5 = 8pts, ≥3 = 5pts, ≥1 = 2pts).
    """
    notes_parts = []
    
    # 1. Scam type declaration
    if scam_type:
        notes_parts.append(f"Detected {scam_type} scam attempt")
    else:
        notes_parts.append("Potential scam activity detected")
    
    # 2. Explicit red flags (key scoring category)
    text_for_flags = full_conversation_text.lower() if full_conversation_text else " ".join(suspicious_keywords)
    red_flags = identify_red_flags(text_for_flags)
    if red_flags:
        notes_parts.append(f"Red flags identified: {', '.join(red_flags)} ({len(red_flags)} total)")
    
    # 3. Tactics used
    tactics = []
    kw = set(suspicious_keywords)
    if kw & {"urgent", "immediately", "hurry"}:
        tactics.append("urgency tactics")
    if kw & {"blocked", "suspended", "frozen", "compromised"}:
        tactics.append("fear-based manipulation")
    if kw & {"prize", "lottery", "winner", "cashback"}:
        tactics.append("lottery/prize lure")
    if kw & {"upi", "bank", "transfer", "account"}:
        tactics.append("payment redirection")
    if kw & {"kyc", "aadhar", "pan"}:
        tactics.append("identity theft attempt")
    if kw & {"otp", "password", "pin"}:
        tactics.append("credential phishing")
    if tactics:
        notes_parts.append(f"Tactics used: {', '.join(tactics)}")
    
    # 4. Intelligence extracted
    intel_summary = []
    if extracted_intelligence.get("bank_accounts"):
        intel_summary.append(f"{len(extracted_intelligence['bank_accounts'])} bank account(s)")
    if extracted_intelligence.get("upi_ids"):
        intel_summary.append(f"{len(extracted_intelligence['upi_ids'])} UPI ID(s)")
    if extracted_intelligence.get("phishing_links"):
        intel_summary.append(f"{len(extracted_intelligence['phishing_links'])} phishing link(s)")
    if extracted_intelligence.get("phone_numbers"):
        intel_summary.append(f"{len(extracted_intelligence['phone_numbers'])} phone number(s)")
    if extracted_intelligence.get("emails"):
        intel_summary.append(f"{len(extracted_intelligence['emails'])} email address(es)")
    if intel_summary:
        notes_parts.append(f"Extracted: {', '.join(intel_summary)}")
    
    # 5. Elicitation attempts
    if questions_asked > 0:
        notes_parts.append(f"Elicitation attempts: {questions_asked} investigative questions asked (identity, company, address, website, contact details)")
    
    notes_parts.append(f"Total messages exchanged: {message_count}")
    
    return ". ".join(notes_parts) + "."
