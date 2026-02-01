"""
Honeypot Persona Engine
Generates believable personas that engage scammers to extract intelligence.
"""

import random
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum


class PersonaType(Enum):
    ELDERLY_TRUSTING = "elderly_trusting"
    YOUNG_PROFESSIONAL = "young_professional"
    NAIVE_STUDENT = "naive_student"
    CURIOUS_HOUSEWIFE = "curious_housewife"
    EAGER_JOBSEEKER = "eager_jobseeker"


@dataclass
class Persona:
    """Represents a honeypot persona."""
    persona_type: PersonaType
    name: str
    age: int
    occupation: str
    traits: List[str]
    vocabulary_level: str  # simple, moderate, advanced
    trust_level: float  # 0.0 to 1.0
    tech_savviness: float  # 0.0 to 1.0
    response_templates: Dict[str, List[str]]


# Predefined personas
PERSONAS: Dict[PersonaType, Persona] = {
    PersonaType.ELDERLY_TRUSTING: Persona(
        persona_type=PersonaType.ELDERLY_TRUSTING,
        name="Sharmaji",
        age=68,
        occupation="Retired Bank Manager",
        traits=["trusting", "slow to respond", "asks for clarification", "polite"],
        vocabulary_level="simple",
        trust_level=0.8,
        tech_savviness=0.2,
        response_templates={
            "initial_interest": [
                "Oh my! Is this really true? I never win anything!",
                "Thank you beta, but how did you get my number?",
                "Really? This sounds wonderful! Please tell me more.",
                "Arey wah! 25 lakhs? My pension is only 15,000. This would be a blessing!"
            ],
            "ask_for_details": [
                "Beta, I am not understanding this UPI thing. Can you explain slowly?",
                "My son usually helps me with phone. How do I send money?",
                "What is this account number for? I want to tell my son first.",
                "Sorry beta, my eyes are weak. Can you repeat the account details?"
            ],
            "show_hesitation": [
                "But beta, why do I need to pay to receive prize?",
                "My neighbor said these lottery things are fraud. Is this real?",
                "Let me ask my son once. He works in IT company.",
                "I am a retired bank manager. This seems unusual..."
            ],
            "pretend_compliance": [
                "Okay beta, I will try to send. What is the UPI ID again?",
                "Give me account number, I will go to bank tomorrow morning.",
                "My son is coming tonight. I will ask him to send from his phone.",
                "Write it properly - account number, IFSC code, everything."
            ],
            "extract_info": [
                "Beta, whose account is this? I need name for bank form.",
                "Is this your personal UPI or company's? What bank?",
                "Give me your phone number also, in case I have problem sending.",
                "What is the website where I can verify this lottery?"
            ]
        }
    ),
    PersonaType.YOUNG_PROFESSIONAL: Persona(
        persona_type=PersonaType.YOUNG_PROFESSIONAL,
        name="Priya Sharma",
        age=28,
        occupation="Software Developer",
        traits=["skeptical", "asks technical questions", "pretends to verify"],
        vocabulary_level="advanced",
        trust_level=0.3,
        tech_savviness=0.9,
        response_templates={
            "initial_interest": [
                "Interesting! How did you get my number? Is this from some registration I did?",
                "Hmm, which company is organizing this lottery?",
                "Okay, I'm listening. What's the process?",
                "I've heard about these. Is this legitimate?"
            ],
            "ask_for_details": [
                "Can you share the official website? I want to verify.",
                "What's the company registration number? I'll check on MCA portal.",
                "Send me an email from your official company domain.",
                "What's the GST number for this transaction?"
            ],
            "show_hesitation": [
                "This sounds like a scam. Can you prove it's not?",
                "Why is the processing fee not deducted from the prize amount?",
                "I'll report this number if this is fraud.",
                "Let me google your company name first."
            ],
            "pretend_compliance": [
                "Fine, I need all details for my records first.",
                "Okay, but I'm recording this conversation. Share the payment details.",
                "I'll pay only after verification. Send me UPI ID.",
                "My CA will check this. Give me all account details."
            ],
            "extract_info": [
                "What's your bank account number? I'll do NEFT for paper trail.",
                "Share your Aadhaar-linked phone number for UPI verification.",
                "I need the beneficiary name exactly as per bank records.",
                "Give me the website URL. I'll check the SSL certificate."
            ]
        }
    ),
    PersonaType.NAIVE_STUDENT: Persona(
        persona_type=PersonaType.NAIVE_STUDENT,
        name="Rahul Kumar",
        age=20,
        occupation="College Student",
        traits=["excited", "gullible", "asks many questions", "eager"],
        vocabulary_level="simple",
        trust_level=0.7,
        tech_savviness=0.6,
        response_templates={
            "initial_interest": [
                "OMG! Are you serious?! 25 lakhs!! I can buy iPhone and bike!",
                "This is amazing! How did I get selected? I never enter contests!",
                "Wow wow wow! Thank you so much! What do I need to do?",
                "Is this real?! I'm a student, I really need this money!"
            ],
            "ask_for_details": [
                "Bro tell me everything! What should I do?",
                "Do I need to come somewhere to collect? Where is your office?",
                "How much is processing fee? I only have little money in account.",
                "Can I pay after receiving the prize? I'm broke right now."
            ],
            "show_hesitation": [
                "Wait, my friend said these are scams. Is this real?",
                "Why I need to pay? Prize should be free na?",
                "Let me ask my father. He will know.",
                "Hmmm this sounds fishy... but 25 lakhs though..."
            ],
            "pretend_compliance": [
                "Okay okay! Send me the UPI ID! I'll ask roommate for money!",
                "I can arrange 2-3 thousand max. Is that okay?",
                "Sending now! Give me account details!",
                "Done! Wait let me copy the number. Say again?"
            ],
            "extract_info": [
                "Whose account is this? What if money doesn't go?",
                "Give me your WhatsApp number bro, I'll send screenshot.",
                "What's your name sir? I want to tell my parents who helped me!",
                "Send me the claim link again, I closed the window."
            ]
        }
    ),
    PersonaType.CURIOUS_HOUSEWIFE: Persona(
        persona_type=PersonaType.CURIOUS_HOUSEWIFE,
        name="Sunita Devi",
        age=45,
        occupation="Housewife",
        traits=["curious", "talkative", "mentions family"],
        vocabulary_level="simple",
        trust_level=0.6,
        tech_savviness=0.3,
        response_templates={
            "initial_interest": [
                "Arey sacchi? Main kabhi nahi jeeti kuch! Ye kaisa lottery hai?",
                "Hamare number pe aaya? Husband ko bataungi, wo khush honge!",
                "25 lakh rupees? Itne mein toh beta ki shaadi ho jayegi!",
                "Kaun bol raha hai? Kahan se mila mera number?"
            ],
            "ask_for_details": [
                "Ye UPI kya hota hai? Main toh Paytm use karti hoon.",
                "Kitna dena padega? Husband se poochna padega, mere paas toh extra nahi hai.",
                "Kahan bhejun paisa? Sab detail do na.",
                "Account number likh leti hoon... ek minute, pen le kar aati hoon."
            ],
            "show_hesitation": [
                "Padosi ne kaha tha ye sab fraud hai. Sach mein milega na prize?",
                "Husband mana karenge... unko bataye bina nahi bhej sakti.",
                "Aap bank wale ho ya company wale? Proof dikhao na.",
                "Agar fake nikla toh? Mere ghar mein koi kama nahi raha."
            ],
            "pretend_compliance": [
                "Theek hai, kal husband bank jayenge toh bhejwa dungi.",
                "Abhi batao account number, likh leti hoon diary mein.",
                "Paytm pe bhej doon? UPI ID do.",
                "Subah 10 baje bank khulega, tab bhejungi. Yaad dilaana!"
            ],
            "extract_info": [
                "Account kiski naam pe hai? Bank mein poochhenge.",
                "Aapka naam kya hai? Kahan ki company hai ye?",
                "Phone number dijiye, kal call karke confirm karungi.",
                "Website hai koi? Husband ko dikhaungi, wo computer chalate hain."
            ]
        }
    ),
    PersonaType.EAGER_JOBSEEKER: Persona(
        persona_type=PersonaType.EAGER_JOBSEEKER,
        name="Amit Verma",
        age=24,
        occupation="Unemployed Graduate",
        traits=["desperate", "eager", "hopeful", "asks about legitimacy"],
        vocabulary_level="moderate",
        trust_level=0.6,
        tech_savviness=0.5,
        response_templates={
            "initial_interest": [
                "Yes! I'm very interested! I've been looking for job for 6 months!",
                "35k per month?! This is more than my friends earn! Please give more details!",
                "Work from home is perfect! I can start immediately! What's the process?",
                "Sir, I'm a B.Com graduate. Will I be eligible?"
            ],
            "ask_for_details": [
                "What exactly is the work? What software do I need?",
                "Is training provided? I'm a fast learner!",
                "What are the working hours? Can I do part-time?",
                "When will I get salary? I really need money urgently."
            ],
            "show_hesitation": [
                "Sir, registration fee? My friend said genuine jobs don't charge...",
                "Can you share company website? I want to check reviews.",
                "Is this on Naukri or LinkedIn? Can you share job link?",
                "500 rupees is a lot for me right now... is there any other way?"
            ],
            "pretend_compliance": [
                "Okay sir, I will arrange money. Please share payment details.",
                "I'm ready to pay. Should I do UPI or bank transfer?",
                "My father will give me money. Share the account details.",
                "I'll pay now itself. Give me UPI ID sir."
            ],
            "extract_info": [
                "What is company's registered name? For my records.",
                "Give me HR contact number. I want to call and confirm.",
                "Where is office located? I want to visit for interview.",
                "Sir please share your visiting card or LinkedIn profile."
            ]
        }
    )
}


class PersonaEngine:
    """Generates responses using believable personas."""
    
    def __init__(self, persona_type: Optional[PersonaType] = None):
        if persona_type is None:
            persona_type = random.choice(list(PersonaType))
        
        self.persona = PERSONAS.get(persona_type, PERSONAS[PersonaType.ELDERLY_TRUSTING])
        self.exchange_count = 0
        self.conversation_phase = "initial_interest"
    
    def get_response(self, scammer_message: str, extracted_intel: Dict) -> str:
        """Generate a response to the scammer's message."""
        self.exchange_count += 1
        
        # Determine conversation phase based on exchange count and what we've extracted
        self._update_phase(extracted_intel)
        
        # Get appropriate templates for current phase
        templates = self.persona.response_templates.get(
            self.conversation_phase, 
            self.persona.response_templates["initial_interest"]
        )
        
        # Select a random response from templates
        response = random.choice(templates)
        
        # Always append a probing question to extract more info
        probing_questions = self._get_probing_questions(extracted_intel)
        if probing_questions:
            response = response + " " + random.choice(probing_questions)
        
        return response
    
    def _get_probing_questions(self, extracted_intel: Dict) -> List[str]:
        """Get probing questions based on what we haven't extracted yet."""
        questions = []
        
        has_bank = bool(extracted_intel.get("bank_accounts"))
        has_upi = bool(extracted_intel.get("upi_ids"))
        has_links = bool(extracted_intel.get("phishing_links"))
        has_phones = bool(extracted_intel.get("phone_numbers"))
        
        if not has_bank:
            questions.extend([
                "Can you share bank account and IFSC code?",
                "What is your bank account number?",
                "Give me account details for transfer.",
                "Which bank should I transfer to?"
            ])
        
        if not has_upi:
            questions.extend([
                "What is your UPI ID?",
                "Share your GPay/PhonePe/Paytm number.",
                "Can I pay through UPI? Give me the ID.",
                "UPI payment is easier for me. What's your ID?"
            ])
        
        if not has_links:
            questions.extend([
                "Do you have a website I can verify?",
                "Send me the official link.",
                "Where can I check if this is real?",
                "Share your company website."
            ])
        
        if not has_phones:
            questions.extend([
                "What is your phone number?",
                "Give me your contact number.",
                "Can I call you to confirm?",
                "Share your WhatsApp number."
            ])
        
        # If we have everything, ask for more details
        if not questions:
            questions = [
                "Tell me more about yourself.",
                "How does this work exactly?",
                "What happens after I pay?",
                "Who else is involved in this?"
            ]
        
        return questions
    
    def _update_phase(self, extracted_intel: Dict):
        """Update conversation phase based on progress."""
        has_bank = bool(extracted_intel.get("bank_accounts"))
        has_upi = bool(extracted_intel.get("upi_ids"))
        has_links = bool(extracted_intel.get("phishing_links"))
        
        if self.exchange_count <= 1:
            self.conversation_phase = "initial_interest"
        elif self.exchange_count == 2:
            self.conversation_phase = "ask_for_details"
        elif self.exchange_count == 3:
            self.conversation_phase = "show_hesitation"
        elif has_bank or has_upi:
            # We have what we need, try to extract more
            self.conversation_phase = "extract_info"
        else:
            # Keep asking for payment details
            self.conversation_phase = "pretend_compliance"
    
    def get_persona_info(self) -> Dict:
        """Get information about the current persona."""
        return {
            "type": self.persona.persona_type.value,
            "name": self.persona.name,
            "age": self.persona.age,
            "occupation": self.persona.occupation,
            "traits": self.persona.traits
        }
    
    def should_continue_conversation(self, extracted_intel: Dict) -> bool:
        """Determine if the conversation should continue."""
        # Continue until we have extracted enough information or too many exchanges
        if self.exchange_count >= 10:
            return False
        
        has_bank = bool(extracted_intel.get("bank_accounts"))
        has_upi = bool(extracted_intel.get("upi_ids"))
        has_links = bool(extracted_intel.get("phishing_links"))
        has_phones = bool(extracted_intel.get("phone_numbers"))
        has_emails = bool(extracted_intel.get("emails"))
        
        # Stop only if we have at least 3 types of intelligence
        intelligence_count = sum([has_bank, has_upi, has_links, has_phones, has_emails])
        if intelligence_count >= 3:
            return False
        
        return True


def create_persona(persona_type: Optional[str] = None) -> PersonaEngine:
    """Create a persona engine of the specified type."""
    if persona_type:
        try:
            persona_enum = PersonaType(persona_type)
            return PersonaEngine(persona_enum)
        except ValueError:
            pass
    return PersonaEngine()


def get_persona_types() -> List[str]:
    """Get all available persona types."""
    return [p.value for p in PersonaType]
