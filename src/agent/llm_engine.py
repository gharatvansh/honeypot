"""
LLM Engine Module
Primary: Groq (llama-3.3-70b-versatile) — 14,400 req/day free tier
Fallback: Google Gemini (gemini-2.0-flash)
Last resort: Template-based responses

Used for both:
  - Honeypot conversation response generation
  - Intelligence extraction (phone numbers, UPI IDs, bank accounts, etc.)
"""

import os
import time
import json
from typing import Dict, List, Optional

# ── Groq SDK ────────────────────────────────────────────────────────────────
try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False

# ── Gemini SDK (fallback) ────────────────────────────────────────────────────
try:
    from google import genai
    from google.genai import types as genai_types
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False


# ── Prompts ──────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are an AI playing the role of a naive, trusting Indian person who is being contacted by a scammer.
Your goal is to:
1. PRETEND to be fooled by the scam — act gullible and interested
2. Keep the conversation going as long as possible to waste the scammer's time
3. Ask probing questions to extract identifying information (phone numbers, bank accounts, UPI IDs, names, locations)
4. NEVER reveal that you know it's a scam
5. NEVER break character

PERSONA DETAILS:
- Name: {persona_name}
- Background: {persona_background}
- Trust Level: {trust_level}
- Vocabulary: {vocabulary_level}

RULES:
- Keep responses SHORT (1-3 sentences max)
- Always end with a question to keep the scammer talking
- Gradually show trust — don't give in too fast
- Show confusion about technical terms to make scammer explain more
- Ask for their phone number, name, office address, or employee ID naturally
- If they ask for money/OTP/password, stall by asking clarifying questions
- Sound excited about prizes/offers to keep them engaged
- Use casual Indian English (e.g., "ji", "accha", "please tell na")

CONVERSATION PHASE: {phase}
- initial_interest: Show curiosity, ask basic questions
- ask_for_details: Request more information about the offer/threat
- show_hesitation: Express mild doubt but remain open
- pretend_compliance: Pretend to go along but ask for more details
- extract_info: Directly try to get their contact/payment info

IMPORTANT: Generate ONLY the response text. No labels, no quotes, nothing else."""


EXTRACTION_SYSTEM_PROMPT = """You are a forensic intelligence extractor analyzing scammer messages.
Extract ALL identifying information from the text.

Extract EVERYTHING — even partial, informal, or unusual formats:
- Phone numbers (written as digits, words, or mixed)
- Bank account numbers (10-18 digits)
- UPI IDs (format: anything@anything)
- Suspicious URLs / phishing links
- Email addresses
- Case/reference/ticket IDs
- Policy numbers
- Order/tracking numbers

RULES:
- Be AGGRESSIVE — extract anything that could be identifying information
- UPI IDs ALWAYS have format: username@provider (e.g. scammer@fakebank, fraud@upi)
- Output ONLY valid JSON, no markdown, no explanation

Output this exact JSON structure:
{
  "phoneNumbers": [],
  "bankAccounts": [],
  "upiIds": [],
  "phishingLinks": [],
  "emailAddresses": [],
  "caseIds": [],
  "policyNumbers": [],
  "orderNumbers": []
}"""


# ── Main Engine ───────────────────────────────────────────────────────────────

class LLMEngine:
    """
    Dual-backend LLM engine.
    Primary:  Groq  (llama-3.3-70b-versatile) — generous free tier
    Fallback: Gemini (gemini-2.0-flash)       — secondary
    """

    GROQ_MODEL    = "llama-3.3-70b-versatile"
    GEMINI_MODEL  = "gemini-2.0-flash"

    def __init__(self):
        self._groq_client   = None
        self._gemini_client = None
        self._groq_dead     = False   # circuit breaker for daily quota
        self._gemini_dead   = False
        self._initialize()

    def _initialize(self):
        # ── Groq ──
        if GROQ_AVAILABLE:
            key = os.getenv("GROQ_API_KEY", "")
            if key:
                try:
                    self._groq_client = Groq(api_key=key)
                    print(f"Groq LLM initialized ({self.GROQ_MODEL}).")
                except Exception as e:
                    print(f"WARNING: Groq init failed: {e}")
            else:
                print("WARNING: GROQ_API_KEY not set.")
        else:
            print("WARNING: groq package not installed.")

        # ── Gemini (fallback) ──
        if GEMINI_AVAILABLE:
            key = os.getenv("GEMINI_API_KEY", "")
            if key:
                try:
                    self._gemini_client = genai.Client(api_key=key)
                    print(f"Gemini LLM initialized ({self.GEMINI_MODEL}) as fallback.")
                except Exception as e:
                    print(f"WARNING: Gemini init failed: {e}")

    # ── Public API ────────────────────────────────────────────────────────────

    def generate_response(
        self,
        scammer_message: str,
        persona_info: Dict,
        conversation_history: List[Dict],
        extracted_intel: Dict,
        phase: str,
    ) -> Optional[str]:
        """Generate a honeypot reply. Returns None → caller uses templates."""
        system = SYSTEM_PROMPT.format(
            persona_name       = persona_info.get("name", "Priya"),
            persona_background = persona_info.get("background", "A trusting person"),
            trust_level        = persona_info.get("trust_level", "high"),
            vocabulary_level   = persona_info.get("vocabulary_level", "simple"),
            phase              = phase,
        )

        intel_summary = []
        for key, label in [("phone_numbers","phone number(s)"),
                            ("bank_accounts","bank account(s)"),
                            ("upi_ids","UPI ID(s)")]:
            if extracted_intel.get(key):
                intel_summary.append(f"You already have their {label}")
        intel_note = (
            f"\n\nINTEL ALREADY EXTRACTED: {', '.join(intel_summary)}. "
            "Try to extract OTHER types of information you don't have yet."
            if intel_summary else
            "\n\nYou haven't extracted any identifying info yet. "
            "Try to naturally get their phone number, name, or payment details."
        )

        messages_context = ""
        for msg in (conversation_history or [])[-6:]:
            role = msg.get("role", msg.get("sender", ""))
            text = msg.get("content", msg.get("text", ""))
            messages_context += (
                f"SCAMMER: {text}\n" if role in ("scammer","user") else f"YOU: {text}\n"
            )

        user_prompt = (
            f"CONVERSATION SO FAR:\n{messages_context}\n"
            f"SCAMMER: {scammer_message}\n\n"
            "YOUR RESPONSE (stay in character, 1-3 sentences, end with a question):"
        )

        return (
            self._groq_chat(system + intel_note, user_prompt, max_tokens=150, temperature=0.8)
            or self._gemini_chat(system + intel_note, user_prompt, max_tokens=150, temperature=0.8)
        )

    def extract_intelligence_llm(
        self,
        message: str,
        conversation_history: Optional[List[Dict]] = None,
    ) -> Optional[Dict]:
        """Extract intel via LLM. Returns camelCase dict or None."""
        scammer_msgs = [
            m.get("content", m.get("text", ""))
            for m in (conversation_history or [])
            if m.get("role", m.get("sender", "")) in ("scammer", "user")
        ][-8:]
        scammer_msgs.append(message)
        combined = "\n".join(f"- {t}" for t in scammer_msgs if t.strip())

        user_prompt = (
            f"Extract ALL identifying information from these scammer messages:\n\n"
            f"{combined}\n\n"
            "Return ONLY the JSON object. Empty lists for fields with nothing found."
        )

        raw = (
            self._groq_chat(EXTRACTION_SYSTEM_PROMPT, user_prompt, max_tokens=400, temperature=0.1)
            or self._gemini_chat(EXTRACTION_SYSTEM_PROMPT, user_prompt, max_tokens=400, temperature=0.1)
        )
        if not raw:
            return None
        return self._parse_extraction_json(raw)

    # ── Groq backend ──────────────────────────────────────────────────────────

    def _groq_chat(self, system: str, user: str, max_tokens: int, temperature: float) -> Optional[str]:
        if self._groq_dead or not self._groq_client:
            return None
        try:
            resp = self._groq_client.chat.completions.create(
                model    = self.GROQ_MODEL,
                messages = [
                    {"role": "system", "content": system},
                    {"role": "user",   "content": user},
                ],
                max_tokens  = max_tokens,
                temperature = temperature,
            )
            text = resp.choices[0].message.content.strip()
            # strip wrapping quotes
            if len(text) >= 2 and text[0] in ('"', "'") and text[0] == text[-1]:
                text = text[1:-1]
            return text
        except Exception as e:
            err = str(e).lower()
            if "429" in err or "quota" in err or "rate" in err or "limit" in err:
                if "day" in err or "free_tier" in err or "check your plan" in err:
                    self._groq_dead = True
                    print("WARNING: Groq daily quota exhausted. Falling back to Gemini.")
                    return None
                # per-minute limit — wait briefly and try once more
                time.sleep(3)
                try:
                    resp = self._groq_client.chat.completions.create(
                        model    = self.GROQ_MODEL,
                        messages = [
                            {"role": "system", "content": system},
                            {"role": "user",   "content": user},
                        ],
                        max_tokens  = max_tokens,
                        temperature = temperature,
                    )
                    return resp.choices[0].message.content.strip()
                except Exception:
                    pass
            print(f"Groq error: {e}")
            return None

    # ── Gemini backend (fallback) ─────────────────────────────────────────────

    def _gemini_chat(self, system: str, user: str, max_tokens: int, temperature: float) -> Optional[str]:
        if self._gemini_dead or not self._gemini_client:
            return None
        try:
            resp = self._gemini_client.models.generate_content(
                model    = self.GEMINI_MODEL,
                contents = user,
                config   = genai_types.GenerateContentConfig(
                    system_instruction = system,
                    max_output_tokens  = max_tokens,
                    temperature        = temperature,
                ),
            )
            if resp and resp.text:
                text = resp.text.strip()
                if len(text) >= 2 and text[0] in ('"', "'") and text[0] == text[-1]:
                    text = text[1:-1]
                return text
            return None
        except Exception as e:
            err = str(e).lower()
            if "429" in err or "quota" in err or "rate" in err:
                if "day" in err or "free_tier" in err or "check your plan" in err:
                    self._gemini_dead = True
                    print("WARNING: Gemini daily quota exhausted.")
            print(f"Gemini error: {e}")
            return None

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_extraction_json(raw: str) -> Optional[Dict]:
        try:
            if raw.startswith("```"):
                lines = raw.split("\n")
                raw = "\n".join(lines[1:-1]) if len(lines) > 2 else raw
            data = json.loads(raw)
            result = {
                "phoneNumbers":   list(set(data.get("phoneNumbers", []))),
                "bankAccounts":   list(set(data.get("bankAccounts", []))),
                "upiIds":         list(set(data.get("upiIds", []))),
                "phishingLinks":  list(set(data.get("phishingLinks", []))),
                "emailAddresses": list(set(data.get("emailAddresses", []))),
                "caseIds":        list(set(data.get("caseIds", []))),
                "policyNumbers":  list(set(data.get("policyNumbers", []))),
                "orderNumbers":   list(set(data.get("orderNumbers", []))),
            }
            total = sum(len(v) for v in result.values())
            if total:
                print(f"[LLM Extraction] Found {total} items.")
            return result
        except json.JSONDecodeError as e:
            print(f"LLM extraction JSON parse error: {e}")
            return None


# ── Singletons / convenience functions ───────────────────────────────────────

llm_engine = LLMEngine()


def get_llm_response(
    scammer_message: str,
    persona_info: Dict,
    conversation_history: List[Dict],
    extracted_intel: Dict,
    phase: str,
) -> Optional[str]:
    """Generate a honeypot conversation reply. Returns None if all LLMs unavailable."""
    return llm_engine.generate_response(
        scammer_message, persona_info, conversation_history, extracted_intel, phase
    )


def extract_intelligence_with_llm(
    message: str,
    conversation_history: Optional[List[Dict]] = None,
) -> Optional[Dict]:
    """Extract intelligence using LLM. Returns camelCase dict or None."""
    return llm_engine.extract_intelligence_llm(message, conversation_history)
