# 🍯 Agentic Honeypot System

Autonomous AI honeypot system for scam detection and intelligence extraction.

## Features

- **Scam Detection**: Detects 6 types of scams (lottery, UPI fraud, job scam, KYC fraud, romance scam, tech support)
- **Fake Personas**: 5 believable personas that engage scammers strategically
- **Intelligence Extraction**: Extracts bank accounts, UPI IDs, phishing links, phone numbers
- **Mock Scammer API**: Simulates realistic scam conversations for testing
- **API Authentication**: Secured with X-API-Key header
- **Streamlit Dashboard**: Interactive UI for analysis and monitoring

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure Environment
```bash
# Copy example and edit
cp .env.example .env
# Edit .env to set your API_KEY
```

### 3. Start the API Server
```bash
python main.py
```
API will be available at `http://localhost:8000`

### 4. Start the Dashboard (Optional)
```bash
streamlit run dashboard.py
```
Dashboard will open at `http://localhost:8501`

## API Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/health` | GET | ❌ | Health check |
| `/api/honeypot` | POST | ✅ | Main endpoint - analyze & engage |
| `/api/analyze` | POST | ✅ | Analyze message for scam indicators |
| `/api/engage` | POST | ✅ | Start/continue honeypot engagement |
| `/api/intelligence` | GET | ✅ | Get all extracted intelligence |
| `/api/conversations` | GET | ✅ | Get conversation history |
| `/api/simulate` | POST | ✅ | Run mock scammer simulation |

## Authentication

All endpoints (except `/api/health`) require the `X-API-Key` header:

```bash
curl -X POST http://localhost:8000/api/honeypot \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"message": "Congratulations! You won 10 lakhs!"}'
```

## Example Response

```json
{
  "conversation_id": "uuid",
  "timestamp": "2024-01-30T12:00:00Z",
  "scam_analysis": {
    "is_scam": true,
    "scam_type": "lottery",
    "confidence": 92.5,
    "indicators": ["lottery_patterns", "urgency_tactics"]
  },
  "extracted_intelligence": {
    "bank_accounts": [],
    "upi_ids": [],
    "phishing_links": [],
    "phone_numbers": [],
    "emails": []
  },
  "honeypot_response": "Oh my! Is this really true? I never win anything!"
}
```

## Project Structure

```
honeypot/
├── main.py                 # FastAPI server
├── dashboard.py            # Streamlit dashboard
├── requirements.txt
├── .env
└── src/
    ├── detection/          # Scam detection module
    │   ├── patterns.py     # Scam patterns library
    │   └── scam_detector.py
    ├── extraction/         # Intelligence extraction
    │   └── extractor.py    # Bank, UPI, phishing extraction
    ├── agent/              # Honeypot personas
    │   └── persona_engine.py
    ├── mock/               # Mock scammer API
    │   └── mock_scammer.py
    └── conversation_manager.py
```

## License

MIT
