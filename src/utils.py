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


def extract_suspicious_keywords(message: str) -> List[str]:
    """Extract suspicious keywords from a message."""
    message_lower = message.lower()
    found_keywords = []
    
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in message_lower:
            found_keywords.append(keyword)
    
    return found_keywords


def generate_agent_notes(
    scam_type: Optional[str],
    extracted_intelligence: Dict,
    message_count: int,
    suspicious_keywords: List[str]
) -> str:
    """Generate a summary of scammer behavior for the agent notes."""
    notes_parts = []
    
    if scam_type:
        notes_parts.append(f"Detected {scam_type} scam attempt")
    else:
        notes_parts.append("Potential scam activity detected")
    
    # Add tactics used
    tactics = []
    if "urgent" in suspicious_keywords or "immediately" in suspicious_keywords:
        tactics.append("urgency tactics")
    if "blocked" in suspicious_keywords or "suspended" in suspicious_keywords:
        tactics.append("fear-based manipulation")
    if "prize" in suspicious_keywords or "lottery" in suspicious_keywords or "winner" in suspicious_keywords:
        tactics.append("lottery/prize scam")
    if "upi" in suspicious_keywords or "bank" in suspicious_keywords:
        tactics.append("payment redirection")
    if "kyc" in suspicious_keywords or "aadhar" in suspicious_keywords:
        tactics.append("identity theft attempt")
    
    if tactics:
        notes_parts.append(f"Used {', '.join(tactics)}")
    
    # Add intelligence summary
    intel_summary = []
    if extracted_intelligence.get("bank_accounts"):
        intel_summary.append(f"{len(extracted_intelligence['bank_accounts'])} bank account(s)")
    if extracted_intelligence.get("upi_ids"):
        intel_summary.append(f"{len(extracted_intelligence['upi_ids'])} UPI ID(s)")
    if extracted_intelligence.get("phishing_links"):
        intel_summary.append(f"{len(extracted_intelligence['phishing_links'])} phishing link(s)")
    if extracted_intelligence.get("phone_numbers"):
        intel_summary.append(f"{len(extracted_intelligence['phone_numbers'])} phone number(s)")
    
    if intel_summary:
        notes_parts.append(f"Extracted: {', '.join(intel_summary)}")
    
    notes_parts.append(f"Total messages exchanged: {message_count}")
    
    return ". ".join(notes_parts) + "."
