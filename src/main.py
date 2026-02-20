"""
Agentic Honeypot API
FastAPI server for scam detection and intelligence extraction.
"""

import os
from typing import Optional, List, Dict, Any, Union
from datetime import datetime
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel

# Load environment variables
load_dotenv()

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.detection import analyze_message
from src.extraction import extract_intelligence, extract_intelligence_camel
from src.honeypot_agent import conversation_manager
from src.mock import get_random_scam_message
from src.utils import extract_suspicious_keywords, generate_agent_notes

# Get API key from environment
API_KEY = os.getenv("API_KEY", "honeypot-secret-key-2024")

# Create FastAPI app
app = FastAPI(
    title="Agentic Honeypot API",
    description="Autonomous AI honeypot system for scam detection and intelligence extraction",
    version="1.0.1"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# === GLOBAL LOGGING MIDDLEWARE ===
@app.middleware("http")
async def log_requests(request: Request, call_next):
    import time
    start_time = time.time()
    
    # Generate request ID
    import uuid
    request_id = str(uuid.uuid4())[:8]
    
    print(f"[{request_id}] -> {request.method} {request.url}")
    print(f"[{request_id}] Headers: {request.headers}")
    
    try:
        response = await call_next(request)
        process_time = (time.time() - start_time) * 1000
        print(f"[{request_id}] <- {response.status_code} (took {process_time:.2f}ms)")
        return response
    except Exception as e:
        print(f"[{request_id}] !!! EXCEPTION: {e}")
        raise e


# ============== Pydantic Models ==============

class MessageRequest(BaseModel):
    """Request model for message analysis."""
    message: str


class EngageRequest(BaseModel):
    """Request model for honeypot engagement."""
    message: str
    conversation_id: Optional[str] = None
    persona_type: Optional[str] = None


class SimulateRequest(BaseModel):
    """Request model for simulation."""
    scam_type: Optional[str] = None
    persona_type: Optional[str] = None


# Structured message format models
class MessageBody(BaseModel):
    """Message body with sender, text, and timestamp."""
    sender: str  # "scammer" or "user"
    text: str    # Message content
    timestamp: Optional[Union[int, str]] = None  # Epoch ms OR ISO string (PDF shows both)


class MetadataBody(BaseModel):
    """Metadata for channel, language, and locale."""
    channel: Optional[str] = "SMS"  # SMS/WhatsApp/Email/Chat
    language: Optional[str] = "English"
    locale: Optional[str] = "IN"


# Simple format request model
class HoneypotRequestSimple(BaseModel):
    """Simple honeypot request model with just a message string."""
    message: Optional[str] = "Hello, I am testing the honeypot API."
    conversation_id: Optional[str] = None
    persona_type: Optional[str] = None


# ============== Authentication ==============

async def verify_api_key(x_api_key: Optional[str] = Header(None)):
    """Verify the API key from request headers."""
    if x_api_key is None:
        raise HTTPException(
            status_code=401,
            detail="Missing API key. Provide X-API-Key header."
        )
    if x_api_key != API_KEY:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key"
        )
    return x_api_key


# ============== Health Check (No Auth) ==============

@app.get("/api/health")
async def health_check():
    """Health check endpoint - no authentication required."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "service": "Agentic Honeypot API",
        "version": "1.0.0"
    }


# ============== Main Honeypot Endpoint ==============

@app.api_route("/api/honeypot", methods=["GET", "HEAD"])
@app.api_route("/honeypot", methods=["GET", "HEAD"])
async def honeypot_get(request: Request):
    """
    Handle GET/HEAD requests to honeypot endpoint.
    Returns a valid honeypot response structure.
    """
    import uuid
    dummy_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat() + "Z"
    
    return {
        "status": "success",
        "success": True,
        "conversation_id": dummy_id,
        "timestamp": now.split(".")[0] + "Z",
        "input_message": "GET_CHECK",
        "message": "Honeypot is active.",
        "scam_detected": False,
        "scam_analysis": {
            "is_scam": False,
            "scam_type": None,
            "confidence": 0,
            "indicators": []
        },
        "extracted_intelligence": {
            "bank_accounts": [],
            "upi_ids": [],
            "phishing_links": [],
            "phone_numbers": [],
            "emails": []
        },
        "honeypot_response": "Honeypot is active.",
        "response": "Honeypot is active.",
        "agent_response": "Honeypot is active.",
        "conversation_active": True
    }


@app.post("/api/honeypot")
@app.post("/honeypot")
async def honeypot_endpoint(
    request: Request,
    api_key: Optional[str] = Depends(verify_api_key)
):
    """
    Main honeypot endpoint - analyzes message, engages with scammer, extracts intelligence.
    Accepts any JSON body, form data, text body, or empty body.
    """
    # DEBUG LOGGING
    print(f"[{datetime.utcnow().isoformat()}] INCOME REQUEST to /api/honeypot")
    print(f"Headers: {request.headers}")
    
    body = {}
    
    try:
        # Get Content-Type header
        content_type = request.headers.get("content-type", "").lower()
        
        # Read raw body first
        raw_body = await request.body()
        print(f"Raw Body ({len(raw_body)} bytes): {raw_body.decode('utf-8', errors='ignore')[:1000]}")
        
        # If body is empty, use default
        if not raw_body or len(raw_body) == 0:
            body = {}
            print("Body is empty")
        elif "application/json" in content_type or raw_body.startswith(b'{') or raw_body.startswith(b'['):
            # Try to parse as JSON
            import json
            try:
                parsed = json.loads(raw_body.decode('utf-8'))
                if isinstance(parsed, dict):
                    body = parsed
                elif isinstance(parsed, str):
                    body = {"message": parsed}
                elif isinstance(parsed, list):
                    # If it's a list, take first item or convert to string
                    if len(parsed) > 0 and isinstance(parsed[0], str):
                        body = {"message": parsed[0]}
                    else:
                        body = {"message": str(parsed)}
                else:
                    body = {"message": str(parsed) if parsed else "Test message"}
                print(f"Parsed JSON body: {body}")
            except json.JSONDecodeError as e:
                print(f"JSON Parse Error: {e}")
                # If JSON fails, treat as plain text
                body = {"message": raw_body.decode('utf-8', errors='ignore')}
        elif "text/" in content_type:
            # Plain text body
            body = {"message": raw_body.decode('utf-8', errors='ignore')}
            print("Parsed as text body")
        elif "application/x-www-form-urlencoded" in content_type:
            # Form data
            form_data = await request.form()
            body = dict(form_data)
            print(f"Parsed Form Data: {body}")
        else:
            # Unknown content type, try to decode as text
            try:
                text = raw_body.decode('utf-8', errors='ignore')
                if text.strip():
                    # Check if it looks like JSON
                    import json
                    try:
                        parsed = json.loads(text)
                        if isinstance(parsed, dict):
                            body = parsed
                        else:
                            body = {"message": str(parsed)}
                    except:
                        body = {"message": text}
                else:
                    body = {}
                print(f"Fallback parsing result: {body}")
            except Exception as e:
                print(f"Fallback parsing failed: {e}")
                body = {}
    except Exception as e:
        print(f"CRITICAL ERROR in body parsing: {e}")
        import traceback
        traceback.print_exc()
        # If all parsing fails, use empty body
        body = {}
    
    try:
        # Detect structured format (has sessionId and message object) vs simple format
        session_id = body.get("sessionId")
        message_obj = body.get("message")
        conversation_history = body.get("conversationHistory", [])
        metadata = body.get("metadata", {})
        
        # New format: {sessionId, message: {sender, text, timestamp}, conversationHistory, metadata}
        if session_id and isinstance(message_obj, dict) and "text" in message_obj:
            print(f"[NEW FORMAT] sessionId={session_id}")
            message = message_obj.get("text", "").strip()
            sender = message_obj.get("sender", "scammer")
            timestamp = message_obj.get("timestamp", 0)
            conversation_id = session_id
            persona_type = None  # Not in new format
            
            # Extract channel, language, locale from metadata
            channel = metadata.get("channel", "SMS") if isinstance(metadata, dict) else "SMS"
            language = metadata.get("language", "English") if isinstance(metadata, dict) else "English"
            locale = metadata.get("locale", "IN") if isinstance(metadata, dict) else "IN"
            
            print(f"  Sender: {sender}, Channel: {channel}, Lang: {language}, Locale: {locale}")
            print(f"  History length: {len(conversation_history)}")
        else:
            # Simple format: {message, conversation_id, persona_type}
            print("[SIMPLE FORMAT]")
            message = body.get("message", "Hello, I am testing the honeypot API.")
            
            # Handle case where message might be a dict or other type
            if isinstance(message, dict):
                # If message is a dict, try to get 'text' or 'content' field, or convert to string
                message = message.get("text") or message.get("content") or str(message)
            elif not isinstance(message, str):
                message = str(message) if message else "Hello, I am testing the honeypot API."
            
            conversation_id = body.get("conversation_id")
            persona_type = body.get("persona_type")
        
        if not message or not message.strip():
            message = "Hello, I am testing the honeypot API."
            
        print(f"Processing message: {message[:50]}... | ID: {conversation_id}")
        
        # Analyze the message
        analysis = analyze_message(message)

        # Extract intelligence from current message
        intel = extract_intelligence(message)

        # ALSO extract intel from conversationHistory scammer messages
        # This ensures we don't miss data shared in previous turns
        # (critical for multi-turn sessions and server-restart recovery)
        if conversation_history:
            for hist_msg in conversation_history:
                if isinstance(hist_msg, dict):
                    hist_sender = hist_msg.get("sender", "")
                    hist_text = hist_msg.get("text", "")
                    if hist_sender == "scammer" and hist_text and isinstance(hist_text, str):
                        hist_intel = extract_intelligence(hist_text)
                        # Merge into current intel (deduplicate)
                        for key in ["bank_accounts", "upi_ids", "phishing_links",
                                    "phone_numbers", "emails", "case_ids",
                                    "policy_numbers", "order_numbers"]:
                            existing = intel.get(key, [])
                            new_items = hist_intel.get(key, [])
                            if new_items:
                                merged = list(existing)
                                for item in new_items:
                                    if item not in merged:
                                        merged.append(item)
                                intel[key] = merged
        
        # If it's a new conversation or no ID provided, start new
        if conversation_id is None:
            result = conversation_manager.start_conversation(message, persona_type)
        else:
            result = conversation_manager.continue_conversation(conversation_id, message)
            # If conversation not found (e.g., server restarted), start a new one
            if "error" in result:
                # RECOVERY: Use the SAME conversation_id the client provided
                print(f"Recovering conversation {conversation_id}")
                result = conversation_manager.start_conversation(
                    initial_message=message, 
                    persona_type=persona_type,
                    forced_conversation_id=conversation_id
                )
        
        # -- Collect timestamps from conversationHistory for engagement duration --
        history_timestamps = []
        if conversation_history:
            for hm in conversation_history:
                if isinstance(hm, dict):
                    ts = hm.get("timestamp")
                    if isinstance(ts, (int, float)) and ts > 0:
                        history_timestamps.append(int(ts))
        # Also add the current message timestamp
        if isinstance(timestamp, (int, float)) and timestamp > 0:
            history_timestamps.append(int(timestamp))
        
        # -- Update conversation-level tracking (timestamps, scammer text) --
        conv_id = result.get("conversation_id", conversation_id)
        tracked_conv = conversation_manager.conversations.get(conv_id)
        if tracked_conv:
            # Accumulate scammer text for red flag detection
            tracked_conv.all_scammer_text += " " + message
            # Track timestamps for real engagement duration
            current_ts_ms = int(timestamp) if isinstance(timestamp, (int, float)) and timestamp > 0 else 0
            if current_ts_ms > 0:
                if tracked_conv.first_msg_timestamp_ms == 0:
                    tracked_conv.first_msg_timestamp_ms = current_ts_ms
                tracked_conv.last_msg_timestamp_ms = max(tracked_conv.last_msg_timestamp_ms, current_ts_ms)
            # Count elicitation attempts (questions our honeypot asks)
            honeypot_reply_text = result.get("honeypot_response", "")
            tracked_conv.questions_asked += honeypot_reply_text.count("?")
        
        # Build response - include multiple field names for compatibility
        honeypot_reply = result.get("honeypot_response", "")
        
        # Extract suspicious keywords from the FULL accumulated scammer text
        tracked_conv = conversation_manager.conversations.get(conv_id)
        full_scammer_text = tracked_conv.all_scammer_text if tracked_conv else message
        suspicious_keywords = extract_suspicious_keywords(full_scammer_text)
        
        # Get message count for this session
        conversation = conversation_manager.get_conversation(conv_id)
        message_count = conversation.get("message_count", 1) if conversation else 1
        
        # Questions asked count
        questions_asked = tracked_conv.questions_asked if tracked_conv else honeypot_reply.count("?")
        
        # Generate agent notes with red flags + elicitation
        agent_notes = generate_agent_notes(
            # Use CONVERSATION-LEVEL scam_type (not just per-turn analysis)
            scam_type=(
                (tracked_conv.scam_type if tracked_conv and tracked_conv.scam_type else None)
                or analysis.get("scam_type")
            ),
            extracted_intelligence=intel,
            message_count=message_count,
            suspicious_keywords=suspicious_keywords,
            full_conversation_text=full_scammer_text,
            questions_asked=questions_asked
        )
        
        # Determine scam detection using CONVERSATION-LEVEL state (never drops after first detection)
        conv_scam_detected = (
            (tracked_conv is not None and (bool(tracked_conv.scam_type) or tracked_conv.scam_confidence >= 30.0))
            or analysis.get("is_scam", False)
        )
        conv_scam_type = (
            (tracked_conv.scam_type if tracked_conv and tracked_conv.scam_type else None)
            or analysis.get("scam_type")
        )
        conv_confidence = (
            tracked_conv.scam_confidence if tracked_conv and tracked_conv.scam_confidence > 0
            else analysis.get("confidence", 0)
        )
        
        # conversation_active: tracks state from conversation manager, but explicitly ends on 0 history for 1-shot testers
        conversation_active = False if len(history_data) == 0 else (tracked_conv.is_active if tracked_conv else True)
        
        response = {
            "status": "success",
            "conversation_id": conv_id,
            "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "input_message": message,
            "scam_detected": conv_scam_detected,
            "scam_analysis": {
                "is_scam": conv_scam_detected,
                "scam_type": conv_scam_type,
                "confidence": conv_confidence,
                "indicators": analysis.get("indicators", [])
            },
            "extracted_intelligence": intel,
            "suspicious_keywords": suspicious_keywords,
            "honeypot_response": honeypot_reply,
            "reply": honeypot_reply,
            "message": honeypot_reply,
            "text": honeypot_reply,
            "agent_notes": agent_notes,
            "total_messages": message_count,
            "conversation_active": conversation_active
        }
        
        # Generate finalOutput for evaluation
        final_output = conversation_manager.get_final_output(
            conv_id,
            history_timestamps=history_timestamps if history_timestamps else None
        )
        if not final_output:
            # Build fallback finalOutput if no conversation was tracked
            final_output = {
                "sessionId": conv_id,
                "scamDetected": conv_scam_detected,
                "totalMessagesExchanged": message_count,
                "engagementDurationSeconds": max(
                    (max(history_timestamps) - min(history_timestamps)) // 1000
                    if len(history_timestamps) >= 2 else 0,
                    0
                ),
                "extractedIntelligence": {
                    "phoneNumbers": extract_intelligence_camel(message).get("phoneNumbers", []),
                    "bankAccounts": extract_intelligence_camel(message).get("bankAccounts", []),
                    "upiIds": extract_intelligence_camel(message).get("upiIds", []),
                    "phishingLinks": extract_intelligence_camel(message).get("phishingLinks", []),
                    "emailAddresses": extract_intelligence_camel(message).get("emailAddresses", [])
                },
                "agentNotes": agent_notes,
                "scamType": conv_scam_type or "unknown",
                "confidenceLevel": min(conv_confidence / 100.0, 1.0) if conv_confidence > 1 else conv_confidence
            }
        
        # Include finalOutput for the UI Endpoint Tester
        response["finalOutput"] = final_output

        print(f"Sending success response for ID: {response['conversation_id']}")
        return response
    except Exception as e:
        print(f"CRITICAL ERROR in standard processing: {e}")
        import traceback
        traceback.print_exc()
        error_detail = f"{type(e).__name__}: {str(e)}"
        error_trace = traceback.format_exc()
        # Return error details for debugging - BUT RETURN 200 OK to avoid "Invalid Body" error
        return {
            "status": "error",
            "success": False,
            "error": error_detail,
            "traceback": error_trace[:500],
            "conversation_id": "error",
            "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "input_message": "",
            "reply": f"I'm having trouble understanding. Can you repeat that?",
            "message": f"I'm having trouble understanding. Can you repeat that?",
            "text": f"I'm having trouble understanding. Can you repeat that?",
            "scam_detected": False,
            "scam_analysis": {"is_scam": False, "scam_type": None, "confidence": 0, "indicators": []},
            "extracted_intelligence": {
                "bank_accounts": [],
                "upi_ids": [],
                "phishing_links": [],
                "phone_numbers": [],
                "emails": []
            },
            "honeypot_response": f"I'm having trouble understanding. Can you repeat that?",
            "conversation_active": True,
            "finalOutput": {
                "sessionId": conv_id if 'conv_id' in locals() else "error",
                "scamDetected": False,
                "extractedIntelligence": {
                    "phoneNumbers": [],
                    "bankAccounts": [],
                    "upiIds": [],
                    "phishingLinks": [],
                    "emailAddresses": []
                }
            }
        }


# ============== Analysis Endpoint ==============

@app.post("/api/analyze")
async def analyze_endpoint(
    request: MessageRequest,
    api_key: str = Depends(verify_api_key)
):
    """Analyze a message for scam indicators without engaging."""
    message = request.message
    
    # Analyze message
    analysis = analyze_message(message)
    
    # Extract intelligence
    intel = extract_intelligence(message)
    
    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "message_analyzed": message[:100] + "..." if len(message) > 100 else message,
        "scam_analysis": analysis,
        "extracted_intelligence": intel
    }


# ============== Engagement Endpoint ==============

@app.post("/api/engage")
async def engage_endpoint(
    request: EngageRequest,
    api_key: str = Depends(verify_api_key)
):
    """Start or continue a honeypot engagement."""
    message = request.message
    conversation_id = request.conversation_id
    persona_type = request.persona_type
    
    if conversation_id:
        # Continue existing conversation
        result = conversation_manager.continue_conversation(conversation_id, message)
    else:
        # Start new conversation
        result = conversation_manager.start_conversation(message, persona_type)
    
    return result


# ============== Intelligence Endpoint ==============

@app.get("/api/intelligence")
async def get_intelligence(api_key: str = Depends(verify_api_key)):
    """Get all extracted intelligence from all conversations."""
    all_intel = conversation_manager.get_all_intelligence()
    conversations = conversation_manager.get_all_conversations()
    
    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "total_conversations": len(conversations),
        "aggregated_intelligence": all_intel,
        "conversations_summary": [
            {
                "id": c["conversation_id"],
                "scam_type": c["scam_type"],
                "message_count": c["message_count"],
                "is_active": c["is_active"]
            }
            for c in conversations
        ]
    }


# ============== Conversations Endpoint ==============

@app.get("/api/conversations")
async def get_conversations(api_key: str = Depends(verify_api_key)):
    """Get all conversations."""
    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "conversations": conversation_manager.get_all_conversations()
    }


@app.get("/api/conversations/{conversation_id}")
async def get_conversation(
    conversation_id: str,
    api_key: str = Depends(verify_api_key)
):
    """Get a specific conversation by ID."""
    conversation = conversation_manager.get_conversation(conversation_id)
    if not conversation:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return conversation


# ============== Simulation Endpoint ==============

@app.post("/api/simulate")
async def simulate_conversation(
    request: SimulateRequest,
    api_key: str = Depends(verify_api_key)
):
    """Simulate a full conversation with mock scammer."""
    result = conversation_manager.simulate_full_conversation(
        scam_type=request.scam_type,
        persona_type=request.persona_type
    )
    return result


# ============== Random Scam Message (for testing) ==============

@app.get("/api/random-scam")
async def get_random_scam(api_key: str = Depends(verify_api_key)):
    """Get a random scam message for testing."""
    return get_random_scam_message()


# ============== Serve Streamlit Info ==============

@app.api_route("/", methods=["GET", "HEAD"])
async def root(request: Request):
    """Root endpoint with API information."""
    return {
        "service": "Agentic Honeypot API",
        "version": "1.0.0",
        "description": "Autonomous AI honeypot for scam detection and intelligence extraction",
        "endpoints": {
            "/api/health": "Health check (no auth)",
            "/api/honeypot": "Main honeypot endpoint (POST)",
            "/api/analyze": "Analyze message (POST)",
            "/api/engage": "Engage with scammer (POST)",
            "/api/intelligence": "Get extracted intelligence (GET)",
            "/api/conversations": "Get all conversations (GET)",
            "/api/simulate": "Simulate conversation (POST)"
        },
        "authentication": "X-API-Key header required for all endpoints except /api/health",
        "dashboard": "Run 'streamlit run dashboard.py' for the interactive dashboard"
    }


# ============== Main ==============

if __name__ == "__main__":
    import uvicorn
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 8000))
    print(f"[HONEYPOT] Starting Agentic Honeypot API on http://{host}:{port}")
    print(f"[DASHBOARD] Run 'streamlit run dashboard.py' for the interactive dashboard")
    uvicorn.run(app, host=host, port=port)
