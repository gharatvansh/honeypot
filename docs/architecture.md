# System Architecture

## Overview
The Honeypot API is designed to simulate a vulnerable target to attract and engage scammers. The system consists of three main components engineered to maximize engagement time while covertly extracting actionable intelligence.

## 1. Fast API Server (main.py)
Acts as the external facing interface for the system.
- **Entry point:** `/api/honeypot` (or `/honeypot`)
- **Authentication:** Middleware validates `x-api-key` header.
- **State Management:** Uses an in-memory `ConversationManager` to maintain session continuity between stateless HTTP POST requests. 

## 2. Honeypot Agent (honeypot_agent.py)
Orchestrates the core logic per conversation.
- **Initialization:** Parses the incoming `sessionId` and starts a tracked `Conversation` object.
- **Message Pipeline:**
  1. `analyze_message()` calculates scam indicators.
  2. `extract_intelligence()` runs RegEx for immediate PII capture.
  3. `extract_intelligence_with_llm()` acts as a semantic fallback for obfuscated data.
  4. `PersonaEngine` generates the honeypot's actual reply.

## 3. Persona Engine (persona_engine.py)
Responsible for believable human-like interaction to waste the scammer's time.
- **Dual LLM Architecture:** 
  - **Primary:** `llama-3.3-70b-versatile` (via Groq) for high-speed, high-quality responses.
  - **Fallback:** `gemini-2.0-flash` (via Google) kicks in instantly if Groq hits rate limits or latency spikes.
  - **Hard-Fallback:** Local deterministic templates if APIs completely fail.
- **Phased Engagement:** The engine shifts from `initial_interest` -> `ask_for_details` -> `show_hesitation` -> `extract_info` dynamically based on the current `exchange_count`.
- **Probing Layer:** Specifically checks the `aggregated_intelligence` dictionary to identify what data (Bank, UPI, Link, Phone) is missing, and appends a structured probing question to elicit it.
