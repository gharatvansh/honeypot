"""
Intelligence Extractor Module
Extracts bank accounts, UPI IDs, and phishing links from conversation messages.
"""

import re
from typing import Dict, List, Optional
from dataclasses import dataclass, field, asdict


@dataclass
class BankAccount:
    """Represents an extracted bank account."""
    account_number: str
    ifsc_code: Optional[str] = None
    bank_name: Optional[str] = None
    holder_name: Optional[str] = None


@dataclass
class UPIInfo:
    """Represents an extracted UPI ID or link."""
    upi_id: Optional[str] = None
    upi_link: Optional[str] = None
    provider: Optional[str] = None


@dataclass
class PhishingLink:
    """Represents an extracted phishing link."""
    url: str
    risk_level: str = "medium"
    reason: str = ""


@dataclass
class ExtractedIntelligence:
    """Container for all extracted intelligence."""
    bank_accounts: List[BankAccount] = field(default_factory=list)
    upi_ids: List[UPIInfo] = field(default_factory=list)
    phishing_links: List[PhishingLink] = field(default_factory=list)
    raw_phone_numbers: List[str] = field(default_factory=list)
    raw_emails: List[str] = field(default_factory=list)
    case_ids: List[str] = field(default_factory=list)
    policy_numbers: List[str] = field(default_factory=list)
    order_numbers: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization (snake_case)."""
        return {
            "bank_accounts": [asdict(acc) for acc in self.bank_accounts],
            "upi_ids": [asdict(upi) for upi in self.upi_ids],
            "phishing_links": [asdict(link) for link in self.phishing_links],
            "phone_numbers": self.raw_phone_numbers,
            "emails": self.raw_emails,
            "case_ids": self.case_ids,
            "policy_numbers": self.policy_numbers,
            "order_numbers": self.order_numbers
        }
    
    def to_camel_dict(self) -> Dict:
        """Convert to dictionary with camelCase keys for evaluation system."""
        return {
            "phoneNumbers": self.raw_phone_numbers,
            "bankAccounts": [acc.account_number for acc in self.bank_accounts],
            "upiIds": [upi.upi_id for upi in self.upi_ids if upi.upi_id],
            "phishingLinks": [link.url for link in self.phishing_links],
            "emailAddresses": self.raw_emails,
            "caseIds": self.case_ids,
            "policyNumbers": self.policy_numbers,
            "orderNumbers": self.order_numbers
        }
    
    def has_intelligence(self) -> bool:
        """Check if any intelligence was extracted."""
        return bool(
            self.bank_accounts or 
            self.upi_ids or 
            self.phishing_links or
            self.raw_phone_numbers or
            self.raw_emails or
            self.case_ids or
            self.policy_numbers or
            self.order_numbers
        )


class IntelligenceExtractor:
    """Extracts sensitive information from messages."""
    
    # Indian bank account patterns
    # 11-18 digits: real Indian accounts are min 11 digits (SBI=11, HDFC=14, etc.)
    # 10-digit numbers are always phone numbers, not account numbers
    ACCOUNT_PATTERN = r'\b\d{11,18}\b'
    
    # IFSC code pattern (4 letter bank code + 0 + 6 alphanumeric)
    IFSC_PATTERN = r'\b[A-Z]{4}0[A-Z0-9]{6}\b'
    
    # UPI ID pattern (username@bankhandle)
    UPI_ID_PATTERN = r'\b[a-zA-Z0-9._-]+@[a-zA-Z]{2,}\b'
    
    # UPI link pattern
    UPI_LINK_PATTERN = r'upi://pay\?[^\s]+'
    
    # URL pattern
    URL_PATTERN = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+'
    
    # Phone number pattern (Indian and international)
    PHONE_PATTERN = r'(?:\+91[-\s]?)?\b[6-9]\d{9}\b|\+\d{1,3}[-\s]?\d{4,14}'
    
    # Email pattern
    EMAIL_PATTERN = r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
    
    # Case/Reference ID pattern
    CASE_ID_PATTERN = r'\b(?:case|ref|reference|ticket|complaint|FIR)[-\s#:]*([A-Z0-9]{4,20})\b'
    
    # Policy number pattern
    POLICY_NUMBER_PATTERN = r'\b(?:policy|insurance)[-\s#:]*([A-Z0-9]{4,20})\b'
    
    # Order number pattern
    ORDER_NUMBER_PATTERN = r'\b(?:order|tracking|shipment|AWB)[-\s#:]*([A-Z0-9]{4,20})\b'
    
    # Known UPI providers
    UPI_PROVIDERS = {
        'ybl': 'PhonePe', 'ibl': 'PhonePe', 'axl': 'PhonePe',
        'okhdfcbank': 'Google Pay', 'okicici': 'Google Pay', 'oksbi': 'Google Pay',
        'paytm': 'Paytm', 'ptyes': 'Paytm', 'pthdfc': 'Paytm',
        'upi': 'BHIM', 'sbi': 'SBI', 'icici': 'ICICI', 
        'hdfc': 'HDFC', 'axis': 'Axis Bank', 'kotak': 'Kotak'
    }
    
    # Suspicious domain patterns
    SUSPICIOUS_DOMAINS = [
        r'bit\.ly', r'tinyurl', r'goo\.gl', r't\.co', r'short\.link',
        r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+',  # IP addresses
        r'.*-.*-.*\..*',  # Multiple hyphens (common in phishing)
        r'.*login.*\..*(?!\.gov|\.bank)',  # Login in domain
        r'.*verify.*\..*',  # Verify in domain
        r'.*secure.*\..*(?!\.gov|\.bank)',  # Secure (ironically)
        r'.*update.*\..*',  # Update in domain
        r'.*account.*\..*(?!\.gov|\.bank)',  # Account in domain
    ]
    
    # Known legitimate domains to exclude
    LEGITIMATE_DOMAINS = [
        'google.com', 'facebook.com', 'twitter.com', 'instagram.com',
        'linkedin.com', 'youtube.com', 'amazon.com', 'flipkart.com',
        'paytm.com', 'phonepe.com', 'gpay.com', 'sbi.co.in', 
        'hdfcbank.com', 'icicibank.com', 'axisbank.com', 'rbi.org.in'
    ]
    
    def __init__(self):
        self.extracted = ExtractedIntelligence()
    
    def extract_all(self, message: str) -> ExtractedIntelligence:
        """Extract all intelligence from a message."""
        result = ExtractedIntelligence()
        
        # Extract bank accounts
        result.bank_accounts = self._extract_bank_accounts(message)
        
        # Extract UPI information
        result.upi_ids = self._extract_upi_info(message)
        
        # Extract phishing links
        result.phishing_links = self._extract_phishing_links(message)
        
        # Extract phone numbers
        result.raw_phone_numbers = self._extract_phone_numbers(message)
        
        # Extract emails
        result.raw_emails = self._extract_emails(message)
        
        # Extract case/reference IDs
        result.case_ids = self._extract_case_ids(message)
        
        # Extract policy numbers
        result.policy_numbers = self._extract_policy_numbers(message)
        
        # Extract order numbers
        result.order_numbers = self._extract_order_numbers(message)
        
        return result
    
    def _extract_bank_accounts(self, message: str) -> List[BankAccount]:
        """Extract bank account numbers and IFSC codes."""
        accounts = []

        # Find account numbers (11-18 digits)
        account_numbers = re.findall(self.ACCOUNT_PATTERN, message)

        # Find phone numbers to exclude (10-digit Indian mobiles)
        phone_numbers = re.findall(r'\b[6-9]\d{9}\b', message)
        phone_set = set(phone_numbers)

        # Find IFSC codes
        ifsc_codes = re.findall(self.IFSC_PATTERN, message.upper())

        ifsc_idx = 0
        seen = set()
        for acc_num in account_numbers:
            # Skip numbers that are just phone numbers
            if acc_num in phone_set or acc_num in seen:
                continue
            seen.add(acc_num)
            ifsc = ifsc_codes[ifsc_idx] if ifsc_idx < len(ifsc_codes) else None
            bank_name = self._get_bank_from_ifsc(ifsc) if ifsc else None
            if ifsc:
                ifsc_idx += 1

            accounts.append(BankAccount(
                account_number=acc_num,
                ifsc_code=ifsc,
                bank_name=bank_name
            ))

        return accounts
    
    # Standard email TLDs — if a handle ends in these it's likely a real email, not UPI
    STANDARD_EMAIL_TLDS = {
        'com', 'org', 'net', 'edu', 'gov', 'io', 'co', 'in', 'uk',
        'info', 'biz', 'me', 'app', 'dev', 'ai', 'tech', 'online',
        'store', 'site', 'web', 'mail', 'email'
    }

    def _extract_upi_info(self, message: str) -> List[UPIInfo]:
        """Extract UPI IDs and links."""
        upi_list = []
        seen = set()

        # Find UPI IDs — widen to catch any x@domain where domain ≤20 chars
        # and doesn't look like a standard email domain
        upi_ids = re.findall(self.UPI_ID_PATTERN, message.lower())
        for upi_id in upi_ids:
            if upi_id in seen:
                continue
            parts = upi_id.split('@')
            if len(parts) != 2:
                continue
            handle = parts[1]

            # Accept if it's a known UPI provider
            if handle in self.UPI_PROVIDERS:
                provider = self.UPI_PROVIDERS[handle]
                upi_list.append(UPIInfo(upi_id=upi_id, provider=provider))
                seen.add(upi_id)
                continue

            # Accept short handles (≤5 chars) — typical UPI shortcodes
            if len(handle) <= 5:
                upi_list.append(UPIInfo(upi_id=upi_id, provider="Unknown"))
                seen.add(upi_id)
                continue

            # Accept if handle doesn't end with a standard email TLD
            # e.g. @fakebank, @fraudupi, @fakedep — these are UPI, not email
            # Real emails end in .com, .org, .net, etc. (domain has a dot+TLD)
            if '.' not in handle:
                # No dot at all → definitely a UPI handle (e.g. @fakebank)
                upi_list.append(UPIInfo(upi_id=upi_id, provider="Unknown"))
                seen.add(upi_id)
                continue

            # Has a dot — check if the TLD is a standard email TLD
            tld = handle.split('.')[-1]
            if tld not in self.STANDARD_EMAIL_TLDS and len(handle) <= 20:
                # Non-standard TLD with short domain → likely UPI
                upi_list.append(UPIInfo(upi_id=upi_id, provider="Unknown"))
                seen.add(upi_id)

        # Find UPI links
        upi_links = re.findall(self.UPI_LINK_PATTERN, message)
        for link in upi_links:
            upi_list.append(UPIInfo(upi_link=link))

        return upi_list
    
    def _extract_phishing_links(self, message: str) -> List[PhishingLink]:
        """Extract and analyze URLs for phishing indicators."""
        phishing_links = []
        
        urls = re.findall(self.URL_PATTERN, message)
        
        for url in urls:
            # Skip legitimate domains
            if any(legit in url.lower() for legit in self.LEGITIMATE_DOMAINS):
                continue
            
            risk_level, reason = self._analyze_url(url)
            
            if risk_level != "safe":
                phishing_links.append(PhishingLink(
                    url=url,
                    risk_level=risk_level,
                    reason=reason
                ))
        
        return phishing_links
    
    def _analyze_url(self, url: str) -> tuple:
        """Analyze a URL for phishing indicators."""
        url_lower = url.lower()
        
        # Check for suspicious patterns
        for pattern in self.SUSPICIOUS_DOMAINS:
            if re.search(pattern, url_lower):
                return "high", f"Matches suspicious pattern: {pattern}"
        
        # Check for URL shorteners
        shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'short.link']
        for shortener in shorteners:
            if shortener in url_lower:
                return "high", "URL shortener detected"
        
        # Check for IP address URLs
        if re.search(r'\d+\.\d+\.\d+\.\d+', url):
            return "high", "IP address in URL"
        
        # Check for suspicious keywords
        suspicious_words = ['login', 'verify', 'secure', 'update', 'account', 'bank']
        for word in suspicious_words:
            if word in url_lower:
                return "medium", f"Suspicious keyword: {word}"
        
        return "low", "Unknown domain"
    
    def _extract_phone_numbers(self, message: str) -> List[str]:
        """Extract phone numbers."""
        return list(set(re.findall(self.PHONE_PATTERN, message)))
    
    def _extract_emails(self, message: str) -> List[str]:
        """Extract email addresses."""
        emails = re.findall(self.EMAIL_PATTERN, message)
        # Filter out UPI IDs that look like emails
        return [e for e in emails if not any(
            prov in e.lower() for prov in self.UPI_PROVIDERS.keys()
        )]
    
    def _extract_case_ids(self, message: str) -> List[str]:
        """Extract case/reference IDs."""
        matches = re.findall(self.CASE_ID_PATTERN, message, re.IGNORECASE)
        return list(set(matches))
    
    def _extract_policy_numbers(self, message: str) -> List[str]:
        """Extract policy numbers."""
        matches = re.findall(self.POLICY_NUMBER_PATTERN, message, re.IGNORECASE)
        return list(set(matches))
    
    def _extract_order_numbers(self, message: str) -> List[str]:
        """Extract order numbers."""
        matches = re.findall(self.ORDER_NUMBER_PATTERN, message, re.IGNORECASE)
        return list(set(matches))
    
    def _get_bank_from_ifsc(self, ifsc: str) -> Optional[str]:
        """Get bank name from IFSC code prefix."""
        bank_codes = {
            'SBIN': 'State Bank of India',
            'HDFC': 'HDFC Bank',
            'ICIC': 'ICICI Bank',
            'AXIS': 'Axis Bank',
            'PUNB': 'Punjab National Bank',
            'BARB': 'Bank of Baroda',
            'CNRB': 'Canara Bank',
            'UBIN': 'Union Bank of India',
            'KKBK': 'Kotak Mahindra Bank',
            'IDFB': 'IDFC First Bank',
            'YESB': 'Yes Bank',
            'INDB': 'IndusInd Bank'
        }
        if ifsc and len(ifsc) >= 4:
            return bank_codes.get(ifsc[:4], None)
        return None


# Create default instance
extractor = IntelligenceExtractor()


def extract_intelligence(message: str) -> Dict:
    """Convenience function to extract intelligence from a message."""
    result = extractor.extract_all(message)
    return result.to_dict()


def extract_intelligence_camel(message: str) -> Dict:
    """Extract intelligence with camelCase keys for evaluation system."""
    result = extractor.extract_all(message)
    return result.to_camel_dict()
