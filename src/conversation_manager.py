"""
Conversation Manager
Manages honeypot conversation state and orchestrates detection, response, and extraction.
"""

import uuid
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, field, asdict

from src.detection import analyze_message
from src.extraction import extract_intelligence
from src.agent import PersonaEngine, create_persona
from src.mock import MockScammer, create_mock_scammer


@dataclass
class Message:
    """A single message in the conversation."""
    sender: str  # "scammer" or "honeypot"
    content: str
    timestamp: str
    extracted_intel: Optional[Dict] = None


@dataclass
class Conversation:
    """Represents a complete honeypot conversation."""
    conversation_id: str
    started_at: str
    scam_type: Optional[str] = None
    persona_type: Optional[str] = None
    messages: List[Message] = field(default_factory=list)
    aggregated_intelligence: Dict = field(default_factory=dict)
    is_active: bool = True
    scam_confidence: float = 0.0
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "conversation_id": self.conversation_id,
            "started_at": self.started_at,
            "scam_type": self.scam_type,
            "persona_type": self.persona_type,
            "messages": [
                {
                    "sender": m.sender,
                    "content": m.content,
                    "timestamp": m.timestamp,
                    "extracted_intel": m.extracted_intel
                }
                for m in self.messages
            ],
            "aggregated_intelligence": self.aggregated_intelligence,
            "is_active": self.is_active,
            "scam_confidence": self.scam_confidence,
            "message_count": len(self.messages)
        }


class ConversationManager:
    """Manages all honeypot conversations."""
    
    def __init__(self):
        self.conversations: Dict[str, Conversation] = {}
        self.personas: Dict[str, PersonaEngine] = {}
        self.scammers: Dict[str, MockScammer] = {}
    
    def start_conversation(
        self, 
        initial_message: str,
        persona_type: Optional[str] = None
    ) -> Dict:
        """
        Start a new honeypot conversation.
        
        Args:
            initial_message: The scammer's initial message
            persona_type: Optional persona type for the honeypot
            
        Returns:
            Dictionary with conversation info and honeypot response
        """
        # Create conversation
        conv_id = str(uuid.uuid4())
        now = datetime.utcnow().isoformat() + "Z"
        
        conversation = Conversation(
            conversation_id=conv_id,
            started_at=now
        )
        
        # Analyze the message
        analysis = analyze_message(initial_message)
        conversation.scam_type = analysis.get("scam_type")
        conversation.scam_confidence = analysis.get("confidence", 0)
        
        # Extract intelligence from initial message
        intel = extract_intelligence(initial_message)
        
        # Create message record
        scammer_msg = Message(
            sender="scammer",
            content=initial_message,
            timestamp=now,
            extracted_intel=intel
        )
        conversation.messages.append(scammer_msg)
        
        # Aggregate intelligence
        self._aggregate_intelligence(conversation, intel)
        
        # Create persona for this conversation
        persona = create_persona(persona_type)
        conversation.persona_type = persona.get_persona_info()["type"]
        self.personas[conv_id] = persona
        
        # Generate honeypot response
        honeypot_response = persona.get_response(initial_message, conversation.aggregated_intelligence)
        
        honeypot_msg = Message(
            sender="honeypot",
            content=honeypot_response,
            timestamp=datetime.utcnow().isoformat() + "Z"
        )
        conversation.messages.append(honeypot_msg)
        
        # Store conversation
        self.conversations[conv_id] = conversation
        
        return {
            "conversation_id": conv_id,
            "scam_analysis": analysis,
            "extracted_intelligence": intel,
            "honeypot_response": honeypot_response,
            "persona": persona.get_persona_info(),
            "should_continue": analysis.get("is_scam", False)
        }
    
    def continue_conversation(
        self, 
        conversation_id: str, 
        scammer_message: str
    ) -> Dict:
        """
        Continue an existing conversation with a new scammer message.
        
        Args:
            conversation_id: The conversation ID
            scammer_message: The scammer's new message
            
        Returns:
            Dictionary with response and extraction results
        """
        conversation = self.conversations.get(conversation_id)
        if not conversation:
            return {"error": "Conversation not found"}
        
        if not conversation.is_active:
            return {"error": "Conversation has ended"}
        
        now = datetime.utcnow().isoformat() + "Z"
        
        # Extract intelligence from new message
        intel = extract_intelligence(scammer_message)
        
        # Create message record
        scammer_msg = Message(
            sender="scammer",
            content=scammer_message,
            timestamp=now,
            extracted_intel=intel
        )
        conversation.messages.append(scammer_msg)
        
        # Aggregate intelligence
        self._aggregate_intelligence(conversation, intel)
        
        # Get persona and generate response
        persona = self.personas.get(conversation_id)
        if not persona:
            persona = create_persona()
            self.personas[conversation_id] = persona
        
        honeypot_response = persona.get_response(
            scammer_message, 
            conversation.aggregated_intelligence
        )
        
        honeypot_msg = Message(
            sender="honeypot",
            content=honeypot_response,
            timestamp=datetime.utcnow().isoformat() + "Z"
        )
        conversation.messages.append(honeypot_msg)
        
        # Check if conversation should continue
        should_continue = persona.should_continue_conversation(
            conversation.aggregated_intelligence
        )
        
        if not should_continue:
            conversation.is_active = False
        
        return {
            "conversation_id": conversation_id,
            "extracted_intelligence": intel,
            "honeypot_response": honeypot_response,
            "should_continue": should_continue,
            "aggregated_intelligence": conversation.aggregated_intelligence,
            "message_count": len(conversation.messages)
        }
    
    def simulate_full_conversation(
        self, 
        scam_type: Optional[str] = None,
        persona_type: Optional[str] = None
    ) -> Dict:
        """
        Simulate a full conversation with mock scammer.
        
        Args:
            scam_type: Type of scam to simulate
            persona_type: Type of persona to use
            
        Returns:
            Complete conversation with all extracted intelligence
        """
        # Create mock scammer
        scammer = create_mock_scammer(scam_type)
        
        # Get initial message
        initial = scammer.get_initial_message()
        
        # Start conversation
        result = self.start_conversation(
            initial["message"],
            persona_type
        )
        
        conv_id = result["conversation_id"]
        self.scammers[conv_id] = scammer
        
        # Continue conversation until done
        max_exchanges = 6
        exchanges = 0
        
        while result.get("should_continue", False) and exchanges < max_exchanges:
            # Get honeypot response
            honeypot_msg = result.get("honeypot_response", "Tell me more")
            
            # Get scammer's reply
            scammer_reply = scammer.get_response(honeypot_msg)
            
            # Continue conversation
            result = self.continue_conversation(conv_id, scammer_reply["message"])
            exchanges += 1
        
        # Get final conversation state
        conversation = self.conversations.get(conv_id)
        
        return {
            "conversation": conversation.to_dict() if conversation else None,
            "total_exchanges": exchanges,
            "scammer_profile": scammer.get_profile_data()
        }
    
    def get_conversation(self, conversation_id: str) -> Optional[Dict]:
        """Get a conversation by ID."""
        conversation = self.conversations.get(conversation_id)
        return conversation.to_dict() if conversation else None
    
    def get_all_conversations(self) -> List[Dict]:
        """Get all conversations."""
        return [c.to_dict() for c in self.conversations.values()]
    
    def get_all_intelligence(self) -> Dict:
        """Get aggregated intelligence from all conversations."""
        all_intel = {
            "bank_accounts": [],
            "upi_ids": [],
            "phishing_links": [],
            "phone_numbers": [],
            "emails": []
        }
        
        for conversation in self.conversations.values():
            intel = conversation.aggregated_intelligence
            for key in all_intel:
                if key in intel:
                    all_intel[key].extend(intel[key])
        
        # Remove duplicates
        for key in all_intel:
            if key in ["bank_accounts", "upi_ids", "phishing_links"]:
                # For dicts, dedupe by converting to string and back
                seen = set()
                unique = []
                for item in all_intel[key]:
                    item_str = str(item)
                    if item_str not in seen:
                        seen.add(item_str)
                        unique.append(item)
                all_intel[key] = unique
            else:
                all_intel[key] = list(set(all_intel[key]))
        
        return all_intel
    
    def _aggregate_intelligence(self, conversation: Conversation, intel: Dict):
        """Aggregate extracted intelligence into conversation."""
        agg = conversation.aggregated_intelligence
        
        for key in ["bank_accounts", "upi_ids", "phishing_links", "phone_numbers", "emails"]:
            if key not in agg:
                agg[key] = []
            if key in intel:
                agg[key].extend(intel[key])


# Create default instance
conversation_manager = ConversationManager()
