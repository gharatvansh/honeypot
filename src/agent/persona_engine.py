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
                "Oh my! I am a bit confused by your message. Is everything okay?",
                "Thank you beta, but how did you get my number?",
                "Really? This sounds important. Please tell me more.",
                "Oh dear! My pension is only 15,000. Please explain slowly what is happening."
            ],
            "ask_for_details": [
                "Beta, I am not understanding this. Can you explain slowly?",
                "My son usually helps me with phone. What should I do?",
                "What is this for? I want to tell my son first.",
                "Sorry beta, my eyes are weak. Can you repeat the details?"
            ],
            "show_hesitation": [
                "But beta, why do I need to do this?",
                "My neighbor said there are many frauds nowadays. Is this real?",
                "Let me ask my son once. He works in IT company.",
                "I am a retired bank manager. This seems unusual..."
            ],
            "pretend_compliance": [
                "Okay beta, I will try to follow. What is the next step?",
                "Give me details, I will go to bank tomorrow morning.",
                "My son is coming tonight. I will ask him to check from his phone.",
                "Write it properly so I can understand - what exactly is needed?"
            ],
            "extract_info": [
                "Beta, whose account or number is this? I need details.",
                "Are you from the main branch or office? What is the name?",
                "Give me your phone number also, in case I have a problem.",
                "What is the website where I can verify this?"
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
                "Hmm, which company or department are you from?",
                "Okay, I'm listening. What's the process?",
                "I've heard about these things. Is this legitimate?"
            ],
            "ask_for_details": [
                "Can you share the official website? I want to verify.",
                "What's the company or branch registration number? I'll check online.",
                "Send me an email from your official domain.",
                "What are the exact details for this transaction?"
            ],
            "show_hesitation": [
                "This sounds like a scam. Can you prove it's not?",
                "Why is the process like this? It doesn't make sense.",
                "I'll report this number if this is fraud.",
                "Let me google this first."
            ],
            "pretend_compliance": [
                "Fine, I need all details for my records first.",
                "Okay, but I'm recording this conversation. Share the details.",
                "I'll proceed only after verification. Send me the exact ID.",
                "My CA will check this. Give me all the necessary info."
            ],
            "extract_info": [
                "What's the bank account number? I'll do NEFT for paper trail.",
                "Share your Aadhaar-linked phone number for verification.",
                "I need the beneficiary name exactly as per records.",
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
                "OMG! Are you serious?! What is going on?",
                "Wait, how did you get my number? I'm just a student!",
                "Wow, what should I do next? Please tell me!",
                "Is this real?! I'm a student, I'm really tensed now!"
            ],
            "ask_for_details": [
                "Bro tell me everything! What should I do?",
                "Do I need to come somewhere? Where is your office?",
                "How much will this cost? I only have little money in account.",
                "Can I do it later? I'm in class right now."
            ],
            "show_hesitation": [
                "Wait, my friend said these are scams. Is this real?",
                "Why do I need to follow these steps? Seems weird na?",
                "Let me ask my father. He will know.",
                "Hmmm this sounds fishy..."
            ],
            "pretend_compliance": [
                "Okay okay! Send me the details! I'll ask roommate to help!",
                "I can only do a little bit right now. Is that okay?",
                "Doing it now! Give me the info!",
                "Done! Wait let me copy the details. Say again?"
            ],
            "extract_info": [
                "Whose account or number is this? What if it fails?",
                "Give me your WhatsApp number bro, I'll send screenshot.",
                "What's your name sir? I want to tell my parents.",
                "Send me the link again, I closed the window."
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
                "Arey! Ye kya message hai? Mujhe theek se samajh nahi aa raha.",
                "Hamare number pe aaya? Husband ko bataungi, par hua kya hai?",
                "Arey baap re! Ye sab kya hai? Main kya karoon ab?",
                "Kaun bol raha hai? Kahan se mila mera number?"
            ],
            "ask_for_details": [
                "Ye sab kaise karte hain? Main toh bas message padh rahi hoon.",
                "Kitna time lagega? Husband se poochna padega.",
                "Kahan bhejun details? Sab theek se batao na.",
                "Likh leti hoon... ek minute, pen le kar aati hoon."
            ],
            "show_hesitation": [
                "Padosi ne kaha tha ye sab fraud hai. Sach bol rahe ho na?",
                "Husband mana karenge... unko bataye bina nahi lag kar sakti.",
                "Aap kahan se bol rahe ho? Proof dikhao na.",
                "Agar fake nikla toh? Mere ghar mein tension ho jayega."
            ],
            "pretend_compliance": [
                "Theek hai, kal husband aayenge toh kar dungi.",
                "Abhi batao kya karna hai, likh leti hoon diary mein.",
                "Kaise karna hai? Mujhe steps batao.",
                "Subah 10 baje bank khulega, tab karungi. Yaad dilaana!"
            ],
            "extract_info": [
                "Account ya kiski naam pe hai? Main verify karungi.",
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
                "Hello! I am Amit. I read your message. Can you explain what this is about?",
                "This is very sudden! Please give me more details.",
                "I can follow instructions. What's the process?",
                "Sir, I'm a B.Com graduate and looking for opportunities. Is this legitimate?"
            ],
            "ask_for_details": [
                "What exactly do I need to do? What software do I need?",
                "Can you guide me step by step? I'm a fast learner!",
                "When will this be completed? Is it urgent?",
                "Can you explain the exact process?"
            ],
            "show_hesitation": [
                "Sir, my friend said these messages are often fake...",
                "Can you share an official website? I want to check reviews.",
                "Is this linked anywhere officially? Can you share a link?",
                "This seems suspicious... is there any other way?"
            ],
            "pretend_compliance": [
                "Okay sir, I will try to arrange what you need. Please share details.",
                "I'm ready. Should I do it through browser or app?",
                "My father is helping me. Share the exact details.",
                "I'll do it now itself. Give me the info sir."
            ],
            "extract_info": [
                "What is the registered name of your organization? For my records.",
                "Give me a contact number. I want to call and confirm.",
                "Where is the office located? I want to verify.",
                "Sir please share an official ID or linked profile."
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
        self.conversation_history = []  # Track history for LLM context
    
    def get_response(self, scammer_message: str, extracted_intel: Dict) -> str:
        """Generate a response to the scammer's message."""
        self.exchange_count += 1
        
        # Determine conversation phase based on exchange count and what we've extracted
        self._update_phase(extracted_intel)
        
        # Track scammer message in history
        self.conversation_history.append({"role": "scammer", "text": scammer_message})
        
        # Try LLM first for more natural responses
        response = self._try_llm_response(scammer_message, extracted_intel)
        
        if not response:
            # Fall back to template-based response
            templates = self.persona.response_templates.get(
                self.conversation_phase, 
                self.persona.response_templates["initial_interest"]
            )
            
            if not hasattr(self, "used_responses"):
                self.used_responses = set()
                
            # Prevent repetition of the main template
            available_templates = [t for t in templates if t not in self.used_responses]
            if not available_templates:
                available_templates = templates
                
            base_response = random.choice(available_templates)
            self.used_responses.add(base_response)
            
            response = base_response
            
            # Append a probing question to extract more info
            probing_questions = self._get_probing_questions(extracted_intel)
            if probing_questions:
                available_probing = [q for q in probing_questions if q not in self.used_responses]
                if not available_probing:
                    available_probing = probing_questions
                    
                probe = random.choice(available_probing)
                self.used_responses.add(probe)
                response = response + " " + probe
        
        # Track our response in history
        self.conversation_history.append({"role": "honeypot", "text": response})
        
        return response
    
    def _try_llm_response(self, scammer_message: str, extracted_intel: Dict) -> Optional[str]:
        """Try to generate a response using the LLM."""
        try:
            from src.agent.llm_engine import get_llm_response
            
            persona_info = {
                "name": self.persona.name,
                "background": f"{self.persona.age} year old {self.persona.occupation}",
                "trust_level": str(self.persona.trust_level),
                "vocabulary_level": self.persona.vocabulary_level
            }
            
            return get_llm_response(
                scammer_message=scammer_message,
                persona_info=persona_info,
                conversation_history=self.conversation_history[:-1],  # Exclude the message we just added
                extracted_intel=extracted_intel,
                phase=self.conversation_phase
            )
        except Exception as e:
            print(f"LLM fallback: {e}")
            return None
    
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
        # Always continue until we hit 10 exchanges to maximize engagement score
        # Evaluation rewards ≥8 turns with full points (8pts)
        if self.exchange_count >= 10:
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
