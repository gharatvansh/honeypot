# 🍯 Honeypot API

## Description

An autonomous AI honeypot system that detects scam attempts, engages scammers using believable personas to waste their time, and extracts intelligence (phone numbers, bank accounts, UPI IDs, phishing links, emails, case IDs) from conversations. The system is designed to keep scammers engaged for as long as possible while covertly gathering identifying information.

## Tech Stack

- **Language/Framework**: Python 3.x / FastAPI
- **Key Libraries**: Pydantic, uvicorn, python-dotenv, google-genai
- **LLM**: Google Gemini (`gemini-2.0-flash`) — used for natural honeypot conversation generation with template fallback
- **AI/ML**: Rule-based pattern matching + NLP-based scam detection engine with 8 scam type classifiers (bank_fraud, phishing, upi_fraud, lottery, kyc_fraud, job_scam, romance_scam, tech_support)
- **Personas**: 5 believable persona templates (elderly, professional, student, housewife, jobseeker) with LLM-backed context-aware response generation

## Setup Instructions

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-username/honeypot.git
   cd honeypot
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set environment variables**
   ```bash
   cp .env.example .env
   # Edit .env and set your API_KEY value
   ```

4. **Run the application**
   ```bash
   python main.py
   ```
   API will be available at `http://localhost:8000`

## API Endpoint

- **URL**: `https://your-deployed-url.com/honeypot` (or `/api/honeypot`)
- **Method**: POST
- **Authentication**: `x-api-key` header

### Request Format

```json
{
  "sessionId": "uuid-v4-string",
  "message": {
    "sender": "scammer",
    "text": "URGENT: Your account has been compromised...",
    "timestamp": "2025-02-11T10:30:00Z"
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

### Response Format

```json
{
  "status": "success",
  "reply": "Oh my! Is this really true? Can you tell me more about this?",
  "finalOutput": {
    "sessionId": "uuid",
    "scamDetected": true,
    "totalMessagesExchanged": 6,
    "engagementDurationSeconds": 120,
    "extractedIntelligence": {
      "phoneNumbers": ["+91-9876543210"],
      "bankAccounts": ["1234567890123456"],
      "upiIds": ["scammer@fakebank"],
      "phishingLinks": [],
      "emailAddresses": []
    },
    "agentNotes": "Detected bank_fraud scam attempt. Extracted: 1 phone number(s), 1 bank account(s).",
    "scamType": "bank_fraud",
    "confidenceLevel": 0.92
  }
}
```

## Approach

### How We Detect Scams
- **Pattern matching**: 6 scam type classifiers (lottery, UPI fraud, job scam, KYC fraud, romance scam, tech support) using keyword analysis and urgency/pressure indicators
- **Confidence scoring**: Multi-factor analysis combining keyword density, urgency tactics, and behavioral patterns

### How We Extract Intelligence
- **Regex-based extraction**: Phone numbers (Indian & international formats), bank account numbers, IFSC codes, UPI IDs, phishing URLs, email addresses, case/reference IDs, policy numbers, order numbers
- **URL analysis**: Suspicious domain detection, URL shortener flagging, phishing pattern matching
- **Aggregation**: All intelligence is deduplicated and aggregated across conversation turns

### How We Maintain Engagement
- **5 distinct personas**: Each with unique personality, vocabulary level, trust level, and response templates
- **Strategic conversation phases**: Initial interest → Ask for details → Show hesitation → Pretend compliance → Extract info
- **Probing questions**: Automatically generates targeted questions based on what intelligence hasn't been extracted yet
- **10-turn engagement**: Designed to keep scammers talking for maximum turns to extract all possible intelligence

## Project Structure

```
honeypot/
├── main.py                 # FastAPI server with /honeypot and /api/honeypot endpoints
├── dashboard.py            # Streamlit dashboard (optional)
├── requirements.txt        # Python dependencies
├── .env.example            # Environment variables template
└── src/
    ├── detection/          # Scam detection module
    │   ├── patterns.py     # Scam patterns library (6 types)
    │   └── scam_detector.py
    ├── extraction/         # Intelligence extraction
    │   └── extractor.py    # Bank, UPI, phishing, phone, email extraction
    ├── agent/              # Honeypot personas
    │   └── persona_engine.py  # 5 persona types with response templates
    ├── mock/               # Mock scammer API for testing
    │   └── mock_scammer.py
    └── conversation_manager.py  # Session state, timing, and finalOutput generation
```

## License

MIT
