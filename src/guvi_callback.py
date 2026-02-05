"""
GUVI Callback Module
Sends final extracted intelligence to GUVI evaluation endpoint.
"""

import os
import httpx
from typing import Dict, List, Optional
import logging

# GUVI evaluation endpoint
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

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


def format_intelligence_for_callback(extracted_intelligence: Dict, suspicious_keywords: List[str]) -> Dict:
    """Format the extracted intelligence for the GUVI callback."""
    # Extract just the account numbers/IDs as simple lists
    bank_accounts = []
    for acc in extracted_intelligence.get("bank_accounts", []):
        if isinstance(acc, dict):
            bank_accounts.append(acc.get("account_number", str(acc)))
        else:
            bank_accounts.append(str(acc))
    
    upi_ids = []
    for upi in extracted_intelligence.get("upi_ids", []):
        if isinstance(upi, dict):
            upi_ids.append(upi.get("upi_id", str(upi)))
        else:
            upi_ids.append(str(upi))
    
    phishing_links = []
    for link in extracted_intelligence.get("phishing_links", []):
        if isinstance(link, dict):
            phishing_links.append(link.get("url", str(link)))
        else:
            phishing_links.append(str(link))
    
    phone_numbers = []
    for phone in extracted_intelligence.get("phone_numbers", []):
        phone_numbers.append(str(phone))
    
    return {
        "bankAccounts": bank_accounts,
        "upiIds": upi_ids,
        "phishingLinks": phishing_links,
        "phoneNumbers": phone_numbers,
        "suspiciousKeywords": suspicious_keywords
    }


async def send_final_result_callback(
    session_id: str,
    scam_detected: bool,
    total_messages: int,
    extracted_intelligence: Dict,
    suspicious_keywords: List[str],
    agent_notes: str
) -> Dict:
    """
    Send the final extracted intelligence to GUVI evaluation endpoint.
    
    This is MANDATORY for evaluation.
    """
    # Format the payload according to GUVI specification
    payload = {
        "sessionId": session_id,
        "scamDetected": scam_detected,
        "totalMessagesExchanged": total_messages,
        "extractedIntelligence": format_intelligence_for_callback(
            extracted_intelligence, suspicious_keywords
        ),
        "agentNotes": agent_notes
    }
    
    print(f"[GUVI CALLBACK] Sending final result for session {session_id}")
    print(f"[GUVI CALLBACK] Payload: {payload}")
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                GUVI_CALLBACK_URL,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=5.0
            )
            
            result = {
                "success": response.status_code in [200, 201, 202],
                "status_code": response.status_code,
                "response": response.text[:500] if response.text else ""
            }
            
            print(f"[GUVI CALLBACK] Response: {result}")
            return result
            
    except httpx.HTTPError as e:
        error_msg = f"HTTP error: {str(e)}"
        print(f"[GUVI CALLBACK] Error: {error_msg}")
        return {"success": False, "error": error_msg}
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        print(f"[GUVI CALLBACK] Error: {error_msg}")
        return {"success": False, "error": error_msg}


def send_final_result_callback_sync(
    session_id: str,
    scam_detected: bool,
    total_messages: int,
    extracted_intelligence: Dict,
    suspicious_keywords: List[str],
    agent_notes: str
) -> Dict:
    """
    Synchronous version of send_final_result_callback.
    """
    import requests
    
    payload = {
        "sessionId": session_id,
        "scamDetected": scam_detected,
        "totalMessagesExchanged": total_messages,
        "extractedIntelligence": format_intelligence_for_callback(
            extracted_intelligence, suspicious_keywords
        ),
        "agentNotes": agent_notes
    }
    
    print(f"[GUVI CALLBACK] Sending final result for session {session_id}")
    print(f"[GUVI CALLBACK] Payload: {payload}")
    
    try:
        response = requests.post(
            GUVI_CALLBACK_URL,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=5
        )
        
        result = {
            "success": response.status_code in [200, 201, 202],
            "status_code": response.status_code,
            "response": response.text[:500] if response.text else ""
        }
        
        print(f"[GUVI CALLBACK] Response: {result}")
        return result
        
    except Exception as e:
        error_msg = f"Error: {str(e)}"
        print(f"[GUVI CALLBACK] Error: {error_msg}")
        return {"success": False, "error": error_msg}
