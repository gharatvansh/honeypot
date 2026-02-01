"""
Agentic Honeypot Dashboard
Streamlit-based interactive dashboard for the honeypot system.
"""

import streamlit as st
import requests
import json
from datetime import datetime

# Configuration
API_BASE_URL = "http://localhost:8000"
DEFAULT_API_KEY = "honeypot-secret-key-2024"

# Page config
st.set_page_config(
    page_title=" Agentic Honeypot",
    page_icon="",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for dark theme and styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        background: linear-gradient(90deg, #FF6B6B, #4ECDC4);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-align: center;
        margin-bottom: 1rem;
    }
    .stat-card {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        border-radius: 10px;
        padding: 1rem;
        border: 1px solid #4ECDC4;
    }
    .scam-indicator {
        color: #FF6B6B;
        font-weight: bold;
    }
    .safe-indicator {
        color: #4ECDC4;
        font-weight: bold;
    }
    .message-scammer {
        background-color: #3d1a1a;
        border-left: 4px solid #FF6B6B;
        padding: 10px;
        margin: 5px 0;
        border-radius: 5px;
    }
    .message-honeypot {
        background-color: #1a3d3d;
        border-left: 4px solid #4ECDC4;
        padding: 10px;
        margin: 5px 0;
        border-radius: 5px;
    }
    .intel-card {
        background: linear-gradient(135deg, #2d1b4e 0%, #1a1a2e 100%);
        border-radius: 10px;
        padding: 1rem;
        border: 1px solid #9B59B6;
        margin: 0.5rem 0;
    }
</style>
""", unsafe_allow_html=True)


def make_api_request(endpoint, method="GET", data=None, api_key=None):
    """Make an API request to the honeypot server."""
    if api_key is None:
        api_key = st.session_state.get("api_key", DEFAULT_API_KEY)
    
    headers = {
        "X-API-Key": api_key,
        "Content-Type": "application/json"
    }
    
    url = f"{API_BASE_URL}{endpoint}"
    
    try:
        if method == "GET":
            response = requests.get(url, headers=headers, timeout=10)
        elif method == "POST":
            response = requests.post(url, headers=headers, json=data, timeout=10)
        
        response.raise_for_status()
        return response.json()
    except requests.exceptions.ConnectionError:
        return {"error": "Cannot connect to API server. Make sure the server is running."}
    except requests.exceptions.HTTPError as e:
        return {"error": f"HTTP Error: {e.response.status_code} - {e.response.text}"}
    except Exception as e:
        return {"error": str(e)}


def display_scam_analysis(analysis):
    """Display scam analysis results."""
    is_scam = analysis.get("is_scam", False)
    confidence = analysis.get("confidence", 0)
    scam_type = analysis.get("scam_type", "Unknown")
    indicators = analysis.get("indicators", [])
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if is_scam:
            st.markdown("###  Scam Detected")
            st.markdown(f'<p class="scam-indicator">This message appears to be a SCAM</p>', unsafe_allow_html=True)
        else:
            st.markdown("###  No Scam Detected")
            st.markdown(f'<p class="safe-indicator">Message appears safe</p>', unsafe_allow_html=True)
    
    with col2:
        st.metric("Confidence", f"{confidence:.1f}%")
    
    with col3:
        if scam_type:
            st.metric("Scam Type", scam_type.replace("_", " ").title())
    
    if indicators:
        st.markdown("**Indicators Found:**")
        for ind in indicators:
            st.markdown(f"- {ind.replace('_', ' ').title()}")


def display_intelligence(intel):
    """Display extracted intelligence."""
    st.markdown("### 🔍 Extracted Intelligence")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Bank Accounts
        bank_accounts = intel.get("bank_accounts", [])
        if bank_accounts:
            st.markdown("####  Bank Accounts")
            for acc in bank_accounts:
                if isinstance(acc, dict):
                    st.markdown(f"""
                    <div class="intel-card">
                    <strong>Account:</strong> {acc.get('account_number', 'N/A')}<br>
                    <strong>IFSC:</strong> {acc.get('ifsc_code', 'N/A')}<br>
                    <strong>Bank:</strong> {acc.get('bank_name', 'N/A')}
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.code(str(acc))
        
        # Phone Numbers
        phones = intel.get("phone_numbers", [])
        if phones:
            st.markdown("#### 📱 Phone Numbers")
            for phone in phones:
                st.code(phone)
    
    with col2:
        # UPI IDs
        upi_ids = intel.get("upi_ids", [])
        if upi_ids:
            st.markdown("####  UPI IDs")
            for upi in upi_ids:
                if isinstance(upi, dict):
                    upi_id = upi.get('upi_id') or upi.get('upi_link', 'N/A')
                    provider = upi.get('provider', 'Unknown')
                    st.markdown(f"""
                    <div class="intel-card">
                    <strong>UPI:</strong> {upi_id}<br>
                    <strong>Provider:</strong> {provider}
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.code(str(upi))
        
        # Phishing Links
        links = intel.get("phishing_links", [])
        if links:
            st.markdown("####  Phishing Links")
            for link in links:
                if isinstance(link, dict):
                    st.markdown(f"""
                    <div class="intel-card">
                    <strong>URL:</strong> {link.get('url', 'N/A')}<br>
                    <strong>Risk:</strong> {link.get('risk_level', 'Unknown')}<br>
                    <strong>Reason:</strong> {link.get('reason', 'N/A')}
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.code(str(link))


def display_conversation(conversation):
    """Display a conversation."""
    messages = conversation.get("messages", [])
    
    for msg in messages:
        sender = msg.get("sender", "unknown")
        content = msg.get("content", "")
        
        if sender == "scammer":
            st.markdown(f"""
            <div class="message-scammer">
            <strong> Scammer:</strong><br>{content}
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class="message-honeypot">
            <strong> Honeypot:</strong><br>{content}
            </div>
            """, unsafe_allow_html=True)


def main():
    """Main dashboard function."""
    
    # Header
    st.markdown('<p class="main-header"> Agentic Honeypot Dashboard</p>', unsafe_allow_html=True)
    st.markdown("---")
    
    # Sidebar
    with st.sidebar:
        st.markdown("##  Configuration")
        
        api_key = st.text_input(
            "API Key",
            value=DEFAULT_API_KEY,
            type="password",
            help="Enter your API key for authentication"
        )
        st.session_state["api_key"] = api_key
        
        st.markdown("---")
        
        # Health check
        if st.button(" Check API Status"):
            result = make_api_request("/api/health")
            if "error" in result:
                st.error(result["error"])
            else:
                st.success(f" API is healthy - {result.get('service', 'Unknown')}")
        
        st.markdown("---")
        st.markdown("### 📊 Quick Stats")
        
        # Get intelligence summary
        intel_result = make_api_request("/api/intelligence")
        if "error" not in intel_result:
            total_convs = intel_result.get("total_conversations", 0)
            agg_intel = intel_result.get("aggregated_intelligence", {})
            
            st.metric("Total Conversations", total_convs)
            st.metric("Bank Accounts", len(agg_intel.get("bank_accounts", [])))
            st.metric("UPI IDs", len(agg_intel.get("upi_ids", [])))
            st.metric("Phishing Links", len(agg_intel.get("phishing_links", [])))
    
    # Main content tabs
    tab1, tab2, tab3, tab4 = st.tabs([
        "🔍 Analyze Message",
        "🎮 Run Simulation",
        "💬 Conversations",
        "📋 Intelligence Report"
    ])
    
    # Tab 1: Analyze Message
    with tab1:
        st.markdown("### Analyze a Suspicious Message")
        st.markdown("Enter a message to analyze for scam indicators and extract intelligence.")
        
        message = st.text_area(
            "Message to Analyze",
            height=150,
            placeholder="Paste the suspicious message here..."
        )
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("🔍 Analyze Only", use_container_width=True):
                if message:
                    with st.spinner("Analyzing..."):
                        result = make_api_request("/api/analyze", "POST", {"message": message})
                    
                    if "error" in result:
                        st.error(result["error"])
                    else:
                        display_scam_analysis(result.get("scam_analysis", {}))
                        st.markdown("---")
                        display_intelligence(result.get("extracted_intelligence", {}))
                else:
                    st.warning("Please enter a message to analyze")
        
        with col2:
            persona_type = st.selectbox(
                "Honeypot Persona",
                ["elderly_trusting", "young_professional", "naive_student", "curious_housewife", "eager_jobseeker"]
            )
            
            if st.button("🍯 Engage Honeypot", use_container_width=True):
                if message:
                    with st.spinner("Engaging..."):
                        result = make_api_request("/api/honeypot", "POST", {
                            "message": message,
                            "persona_type": persona_type
                        })
                    
                    if "error" in result:
                        st.error(result["error"])
                    else:
                        st.success(f"Conversation started: {result.get('conversation_id', 'N/A')}")
                        display_scam_analysis(result.get("scam_analysis", {}))
                        
                        st.markdown("### 🍯 Honeypot Response")
                        st.info(result.get("honeypot_response", "No response"))
                        
                        st.markdown("---")
                        display_intelligence(result.get("extracted_intelligence", {}))
                else:
                    st.warning("Please enter a message to engage")
    
    # Tab 2: Run Simulation
    with tab2:
        st.markdown("### Simulate Full Scam Conversation")
        st.markdown("Run an automated simulation with a mock scammer to test the honeypot.")
        
        col1, col2 = st.columns(2)
        
        with col1:
            scam_type = st.selectbox(
                "Scam Type",
                ["lottery", "upi_fraud", "job_scam", "kyc_fraud", "romance_scam", "tech_support"],
                help="Select the type of scam to simulate"
            )
        
        with col2:
            sim_persona = st.selectbox(
                "Honeypot Persona",
                ["elderly_trusting", "young_professional", "naive_student", "curious_housewife", "eager_jobseeker"],
                key="sim_persona"
            )
        
        if st.button("🎮 Start Simulation", use_container_width=True):
            with st.spinner("Running simulation..."):
                result = make_api_request("/api/simulate", "POST", {
                    "scam_type": scam_type,
                    "persona_type": sim_persona
                })
            
            if "error" in result:
                st.error(result["error"])
            else:
                conversation = result.get("conversation", {})
                
                st.success(f"Simulation complete! {result.get('total_exchanges', 0)} exchanges")
                
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    st.markdown("### 💬 Conversation")
                    display_conversation(conversation)
                
                with col2:
                    st.markdown("### 🔍 Extracted Intelligence")
                    display_intelligence(conversation.get("aggregated_intelligence", {}))
                    
                    st.markdown("### 🦹 Scammer's Actual Data")
                    scammer_data = result.get("scammer_profile", {})
                    st.json(scammer_data)
    
    # Tab 3: Conversations
    with tab3:
        st.markdown("### Conversation History")
        
        if st.button("🔄 Refresh Conversations"):
            st.rerun()
        
        result = make_api_request("/api/conversations")
        
        if "error" in result:
            st.error(result["error"])
        else:
            conversations = result.get("conversations", [])
            
            if not conversations:
                st.info("No conversations yet. Start a simulation or engage with a scammer message.")
            else:
                for conv in conversations:
                    scam_type = conv.get('scam_type') or 'Unknown'
                    with st.expander(
                        f"📝 {scam_type.replace('_', ' ').title()} - "
                        f"{conv.get('message_count', 0)} messages - "
                        f"{'🟢 Active' if conv.get('is_active') else '🔴 Ended'}"
                    ):
                        st.json(conv)
    
    # Tab 4: Intelligence Report
    with tab4:
        st.markdown("### Aggregated Intelligence Report")
        
        if st.button("🔄 Refresh Intelligence"):
            st.rerun()
        
        result = make_api_request("/api/intelligence")
        
        if "error" in result:
            st.error(result["error"])
        else:
            st.markdown(f"**Total Conversations Analyzed:** {result.get('total_conversations', 0)}")
            
            display_intelligence(result.get("aggregated_intelligence", {}))
            
            st.markdown("### 📥 Export Data")
            if st.button("Download JSON Report"):
                st.download_button(
                    label="📥 Download Intelligence Report",
                    data=json.dumps(result, indent=2),
                    file_name=f"honeypot_intelligence_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )


if __name__ == "__main__":
    main()
