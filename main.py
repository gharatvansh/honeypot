"""
Agentic Honeypot API
FastAPI server for scam detection and intelligence extraction.
"""

import os
from typing import Optional
from datetime import datetime
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel

# Load environment variables
load_dotenv()

# Import our modules
from src.detection import analyze_message
from src.extraction import extract_intelligence
from src.conversation_manager import conversation_manager
from src.mock import get_random_scam_message

# Get API key from environment
API_KEY = os.getenv("API_KEY", "honeypot-secret-key-2024")

# Create FastAPI app
app = FastAPI(
    title="Agentic Honeypot API",
    description="Autonomous AI honeypot system for scam detection and intelligence extraction",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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


class HoneypotRequest(BaseModel):
    """Main honeypot request model."""
    message: str
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

@app.post("/api/honeypot")
async def honeypot_endpoint(
    request: HoneypotRequest,
    api_key: str = Depends(verify_api_key)
):
    """
    Main honeypot endpoint - analyzes message, engages with scammer, extracts intelligence.
    
    This is the primary endpoint for the evaluation tester.
    """
    message = request.message
    conversation_id = request.conversation_id
    persona_type = request.persona_type
    
    # Analyze the message
    analysis = analyze_message(message)
    
    # Extract intelligence
    intel = extract_intelligence(message)
    
    # If it's a new conversation or no ID provided, start new
    if conversation_id is None:
        result = conversation_manager.start_conversation(message, persona_type)
    else:
        result = conversation_manager.continue_conversation(conversation_id, message)
    
    # Build response
    response = {
        "conversation_id": result.get("conversation_id", conversation_id),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "scam_analysis": {
            "is_scam": analysis.get("is_scam", False),
            "scam_type": analysis.get("scam_type"),
            "confidence": analysis.get("confidence", 0),
            "indicators": analysis.get("indicators", [])
        },
        "extracted_intelligence": intel,
        "honeypot_response": result.get("honeypot_response", ""),
        "conversation_active": result.get("should_continue", False)
    }
    
    return response


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

@app.get("/")
async def root():
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
