"""
Scam Detection Patterns Library
Contains keywords, regex patterns, and behavioral indicators for detecting various scam types.
"""

import re
from typing import List, Dict

# Scam type definitions
SCAM_TYPES = {
    "lottery": {
        "keywords": [
            "congratulations", "winner", "won", "lottery", "prize", "lucky draw",
            "jackpot", "claim", "reward", "selected", "lakh", "crore", "million",
            "billion", "cash prize", "gift", "free money"
        ],
        "patterns": [
            r"won\s*(?:rs\.?|₹|inr)?\s*[\d,\.]+\s*(?:lakh|crore|lac)?",
            r"prize\s*(?:of|worth)?\s*(?:rs\.?|₹|inr)?\s*[\d,\.]+",
            r"claim\s*(?:your)?\s*(?:prize|reward|gift)",
        ],
        "weight": 1.0
    },
    "upi_fraud": {
        "keywords": [
            "upi", "paytm", "phonepe", "gpay", "google pay", "bhim", "send money",
            "transfer", "pay now", "payment link", "collect request", "upi id",
            "verify account", "receive money", "cashback"
        ],
        "patterns": [
            r"[a-zA-Z0-9._-]+@[a-zA-Z]+",  # UPI ID pattern
            r"upi://pay\?",
            r"send\s*(?:rs\.?|₹)?\s*\d+\s*(?:to)?\s*(?:receive|get)",
        ],
        "weight": 1.2
    },
    "job_scam": {
        "keywords": [
            "work from home", "earn money", "part time", "full time", "hiring",
            "job offer", "salary", "income", "per day", "per month", "weekly",
            "no experience", "easy money", "guaranteed income", "registration fee"
        ],
        "patterns": [
            r"earn\s*(?:rs\.?|₹)?\s*[\d,]+\s*(?:per|/)\s*(?:day|week|month)",
            r"(?:salary|income)\s*(?:of|:)?\s*(?:rs\.?|₹)?\s*[\d,]+",
            r"registration\s*fee",
        ],
        "weight": 0.9
    },
    "kyc_fraud": {
        "keywords": [
            "kyc", "verification", "account blocked", "suspended", "update",
            "expire", "verify", "bank account", "pan card", "aadhaar", "aadhar",
            "document", "urgent", "immediately", "within 24 hours", "link below"
        ],
        "patterns": [
            r"(?:account|card)\s*(?:will be|is)\s*(?:blocked|suspended|closed)",
            r"(?:update|verify)\s*(?:your)?\s*kyc",
            r"(?:pan|aadhaar|aadhar)\s*(?:card|number|details)",
        ],
        "weight": 1.1
    },
    "romance_scam": {
        "keywords": [
            "love", "dear", "darling", "sweetheart", "beautiful", "handsome",
            "lonely", "relationship", "marriage", "meet", "video call", "gift",
            "customs", "shipping", "stuck", "help me", "send money", "western union"
        ],
        "patterns": [
            r"(?:send|need)\s*(?:me)?\s*(?:money|funds|help)",
            r"(?:stuck|stranded)\s*(?:at|in)\s*(?:airport|customs)",
            r"(?:love|miss)\s*you\s*(?:so much)?",
        ],
        "weight": 0.8
    },
    "tech_support": {
        "keywords": [
            "virus", "malware", "hacked", "compromised", "security alert",
            "microsoft", "windows", "apple", "remote access", "teamviewer",
            "anydesk", "call now", "toll free", "tech support"
        ],
        "patterns": [
            r"(?:your)?\s*(?:computer|system|device)\s*(?:is|has been)\s*(?:infected|hacked|compromised)",
            r"call\s*(?:us|now|immediately)\s*(?:at|on)?\s*[\d-]+",
        ],
        "weight": 1.0
    },
    "social_engineering": {
        "keywords": [
            "issue", "flagged", "restriction", "restricted", "verify", "verification",
            "confirm", "confirmation", "account", "suspicious", "unusual activity",
            "security", "access", "blocked", "suspended", "hold", "freeze",
            "action required", "attention", "important", "notification", "alert",
            "tried reaching", "couldn't reach", "didn't receive", "no response",
            "available", "earliest", "proceed", "process"
        ],
        "patterns": [
            r"issue\s*(?:flagged|detected|found|reported)",
            r"(?:restriction|block|suspend)\s*(?:will|doesn't|won't)\s*proceed",
            r"verify\s*(?:at\s*the\s*earliest|immediately|now|asap)",
            r"(?:tried|couldn't|didn't)\s*(?:reaching|reach|contact|receive)",
            r"(?:your)?\s*account\s*(?:has been|is|will be)",
            r"(?:let me know|confirm|reply)\s*(?:once|when|if)\s*(?:you're|you are)\s*available",
        ],
        "weight": 1.0
    }
}

# Urgency indicators that increase scam confidence
URGENCY_INDICATORS = [
    "urgent", "immediately", "now", "today", "hurry", "limited time",
    "act fast", "don't delay", "expire", "last chance", "final notice",
    "within 24 hours", "within 48 hours", "asap", "right now",
    "at the earliest", "as soon as possible", "time sensitive", "action required",
    "respond immediately", "before it's too late", "don't ignore", "must verify",
    "without delay", "promptly", "restriction", "will be blocked", "will proceed"
]

# Sensitive data request indicators
SENSITIVE_DATA_REQUESTS = [
    "bank account", "account number", "ifsc", "credit card", "debit card",
    "cvv", "otp", "password", "pin", "upi pin", "aadhaar", "aadhar",
    "pan card", "passport", "social security"
]


def get_scam_patterns() -> Dict:
    """Return all scam patterns."""
    return SCAM_TYPES


def get_urgency_indicators() -> List[str]:
    """Return urgency indicator keywords."""
    return URGENCY_INDICATORS


def get_sensitive_data_requests() -> List[str]:
    """Return sensitive data request keywords."""
    return SENSITIVE_DATA_REQUESTS
