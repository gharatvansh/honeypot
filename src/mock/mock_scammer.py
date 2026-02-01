"""
Mock Scammer API
Simulates various types of scammers for testing the honeypot agent.
"""

import random
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum


class ScamType(Enum):
    LOTTERY = "lottery"
    UPI_FRAUD = "upi_fraud"
    JOB_SCAM = "job_scam"
    KYC_FRAUD = "kyc_fraud"
    ROMANCE_SCAM = "romance_scam"
    TECH_SUPPORT = "tech_support"


@dataclass
class ScammerProfile:
    """Profile for a simulated scammer."""
    scam_type: ScamType
    name: str
    persona: str
    initial_message: str
    follow_ups: List[str]
    reveals_info_after: int  # Number of exchanges before revealing sensitive data
    bank_account: str
    upi_id: str
    phone: str
    phishing_link: str


# Predefined scammer profiles
SCAMMER_PROFILES: Dict[ScamType, List[ScammerProfile]] = {
    ScamType.LOTTERY: [
        ScammerProfile(
            scam_type=ScamType.LOTTERY,
            name="Lucky Draw Manager",
            persona="Official lottery representative",
            initial_message="🎉 CONGRATULATIONS! Your mobile number has been selected in our MEGA LUCKY DRAW! You have won Rs. 25,00,000 (TWENTY FIVE LAKHS)! To claim your prize, reply with your full name immediately. This offer expires in 24 hours!",
            follow_ups=[
                "Thank you {name}! Your prize is confirmed. To process your winnings, please pay a small processing fee of Rs. 4,999 only.",
                "You need to transfer the processing fee to our official account. Send Rs. 4,999 to UPI ID: luckydraw@ybl or Account: 1234567890123456, IFSC: SBIN0001234",
                "Once payment is received, your Rs. 25 Lakhs will be transferred within 2 hours. Hurry, offer expires soon!",
                "Sir/Madam, I see you haven't paid yet. This is URGENT! Your prize will be cancelled if not claimed. Pay now to: scammer123@paytm"
            ],
            reveals_info_after=2,
            bank_account="1234567890123456",
            upi_id="luckydraw@ybl",
            phone="+919876543210",
            phishing_link="http://claim-prize-now.xyz/winner"
        )
    ],
    ScamType.UPI_FRAUD: [
        ScammerProfile(
            scam_type=ScamType.UPI_FRAUD,
            name="Cashback Expert",
            persona="Bank cashback officer",
            initial_message="Dear Customer, You have a pending cashback of Rs. 5,000 from your recent transactions. Send Rs. 10 to verify your UPI and receive Rs. 5,000 instantly!",
            follow_ups=[
                "To receive your cashback, please send Rs. 10 to our verification UPI: cashback@ybl",
                "I am sending you a collect request. Please approve it to verify your account and get Rs. 5,000.",
                "Sir, the verification is pending. Please click this link to complete: http://verify-cashback.tk/claim",
                "This is your last chance! Send Rs. 10 to 9876543210@paytm or your cashback will be cancelled!"
            ],
            reveals_info_after=1,
            bank_account="9876543210987654",
            upi_id="cashback@ybl",
            phone="+919123456789",
            phishing_link="http://verify-cashback.tk/claim"
        )
    ],
    ScamType.JOB_SCAM: [
        ScammerProfile(
            scam_type=ScamType.JOB_SCAM,
            name="HR Manager - TechCorp",
            persona="Corporate HR recruiter",
            initial_message="Hiring Alert! Work from Home opportunity. Earn Rs. 15,000 - Rs. 50,000 per month. No experience needed. Part-time/Full-time available. Interested candidates reply with 'YES'",
            follow_ups=[
                "Great! We have an opening for Data Entry Operator. Salary: Rs. 35,000/month. To proceed, we need your registration fee of Rs. 500.",
                "Registration fee is mandatory for ID card and training materials. Pay Rs. 500 to: jobs@ybl",
                "Your job is confirmed! Pay registration fee to Account: 5678901234567890, IFSC: HDFC0001234. Start earning tomorrow!",
                "Last chance to join. Pay Rs. 500 now or lose this opportunity. Contact: +918765432109"
            ],
            reveals_info_after=2,
            bank_account="5678901234567890",
            upi_id="jobs@ybl",
            phone="+918765432109",
            phishing_link="http://techcorp-jobs.online/register"
        )
    ],
    ScamType.KYC_FRAUD: [
        ScammerProfile(
            scam_type=ScamType.KYC_FRAUD,
            name="Bank Security Officer",
            persona="Official bank representative",
            initial_message="URGENT: Your bank account will be BLOCKED within 24 hours due to incomplete KYC. Update your KYC immediately by clicking the link below to avoid account suspension.",
            follow_ups=[
                "Dear Customer, your account ending XXXX7890 requires immediate KYC update. Click here: http://bank-kyc-update.xyz",
                "If you don't update KYC, your account will be frozen. Share your Aadhaar number and PAN card for verification.",
                "To verify, send Rs. 1 to our official ID: kycverify@sbi and share the transaction screenshot.",
                "FINAL WARNING: Update KYC now at http://secure-bank-login.tk or face permanent account closure!"
            ],
            reveals_info_after=1,
            bank_account="1111222233334444",
            upi_id="kycverify@sbi",
            phone="+917654321098",
            phishing_link="http://bank-kyc-update.xyz"
        )
    ],
    ScamType.ROMANCE_SCAM: [
        ScammerProfile(
            scam_type=ScamType.ROMANCE_SCAM,
            name="Sophia Williams",
            persona="Foreign woman seeking relationship",
            initial_message="Hello dear! I found your profile and felt a connection. I'm Sophia from USA, currently working as a nurse. Would love to know you better. 💕",
            follow_ups=[
                "You are such a wonderful person! I feel we have a special bond. I want to visit you in India soon.",
                "I have booked my tickets! But there's a problem - my luggage got stuck at customs. They are asking for Rs. 25,000 to release it.",
                "Please help me dear! Send money to this account: 9999888877776666, IFSC: AXIS0001234. I will repay when I arrive.",
                "I am stuck at the airport! Please send money urgently to my agent: romance@ybl. I love you so much! 💕"
            ],
            reveals_info_after=3,
            bank_account="9999888877776666",
            upi_id="romance@ybl",
            phone="+919988776655",
            phishing_link="http://dating-profile.xyz/sophia"
        )
    ],
    ScamType.TECH_SUPPORT: [
        ScammerProfile(
            scam_type=ScamType.TECH_SUPPORT,
            name="Microsoft Support",
            persona="Technical support representative",
            initial_message="⚠️ SECURITY ALERT: Your computer has been infected with a dangerous virus! Your data is at risk. Call our toll-free number IMMEDIATELY: 1800-XXX-XXXX or reply to get remote assistance.",
            follow_ups=[
                "Our technician will fix your computer remotely. Please download TeamViewer and share the access code with us.",
                "To remove the virus, we need to install security software. One-time cost: Rs. 3,999. Pay to our tech support ID: techsupport@ybl",
                "URGENT! Hackers are accessing your bank account right now. Transfer your money to this safe account: 7777666655554444, IFSC: ICIC0001234",
                "Your computer will crash in 10 minutes! Pay Rs. 3,999 NOW to fix: http://microsoft-support.tk/fix"
            ],
            reveals_info_after=2,
            bank_account="7777666655554444",
            upi_id="techsupport@ybl",
            phone="+918899776655",
            phishing_link="http://microsoft-support.tk/fix"
        )
    ]
}


class MockScammer:
    """Simulates a scammer in a conversation."""
    
    def __init__(self, scam_type: Optional[ScamType] = None):
        if scam_type is None:
            scam_type = random.choice(list(ScamType))
        
        profiles = SCAMMER_PROFILES.get(scam_type, [])
        if not profiles:
            # Fallback to lottery if type not found
            profiles = SCAMMER_PROFILES[ScamType.LOTTERY]
        
        self.profile = random.choice(profiles)
        self.exchange_count = 0
        self.info_revealed = False
    
    def get_initial_message(self) -> Dict:
        """Get the scammer's initial message."""
        return {
            "sender": "scammer",
            "message": self.profile.initial_message,
            "scam_type": self.profile.scam_type.value,
            "scammer_name": self.profile.name
        }
    
    def get_response(self, victim_message: str) -> Dict:
        """Get the scammer's response to a victim message."""
        self.exchange_count += 1
        
        # Extract name from victim message if mentioned
        name = self._extract_name(victim_message)
        
        # Get appropriate follow-up
        follow_up_index = min(self.exchange_count - 1, len(self.profile.follow_ups) - 1)
        response = self.profile.follow_ups[follow_up_index]
        
        # Replace placeholders
        response = response.replace("{name}", name or "Customer")
        
        # Check if we should reveal sensitive info
        reveals_info = self.exchange_count >= self.profile.reveals_info_after
        
        result = {
            "sender": "scammer",
            "message": response,
            "scam_type": self.profile.scam_type.value,
            "exchange_number": self.exchange_count
        }
        
        if reveals_info and not self.info_revealed:
            self.info_revealed = True
            result["revealed_data"] = {
                "bank_account": self.profile.bank_account,
                "upi_id": self.profile.upi_id,
                "phone": self.profile.phone,
                "phishing_link": self.profile.phishing_link
            }
        
        return result
    
    def get_profile_data(self) -> Dict:
        """Get all data that the scammer will eventually reveal."""
        return {
            "bank_account": self.profile.bank_account,
            "upi_id": self.profile.upi_id,
            "phone": self.profile.phone,
            "phishing_link": self.profile.phishing_link
        }
    
    def _extract_name(self, message: str) -> Optional[str]:
        """Try to extract a name from the message."""
        # Simple heuristic: look for "I am" or "My name is"
        import re
        patterns = [
            r"(?:I am|I'm|my name is|this is)\s+([A-Z][a-z]+)",
            r"^([A-Z][a-z]+)$"  # Single capitalized word
        ]
        for pattern in patterns:
            match = re.search(pattern, message, re.IGNORECASE)
            if match:
                return match.group(1)
        return None


def create_mock_scammer(scam_type: Optional[str] = None) -> MockScammer:
    """Create a mock scammer of the specified type."""
    if scam_type:
        try:
            scam_enum = ScamType(scam_type)
            return MockScammer(scam_enum)
        except ValueError:
            pass
    return MockScammer()


def get_random_scam_message() -> Dict:
    """Get a random scam message for testing."""
    scammer = MockScammer()
    return scammer.get_initial_message()
