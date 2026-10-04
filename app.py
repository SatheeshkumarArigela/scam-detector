"""
Web app for the AI Scam Detector (Streamlit).
Needs scam_detector_gemini.py in the same folder.
"""

import os

import streamlit as st
from google import genai

from scam_detector_gemini import analyze_message

st.set_page_config(page_title="AI Scam Detector", page_icon="🛡️")
st.title("🛡️ AI Scam Detector")
st.caption("Paste a suspicious SMS or email. Please use sample or made-up messages only.")


@st.cache_resource
def get_client():
    """Read the API key from Streamlit secrets (online) or environment (local)."""
    key = None
    try:
        key = st.secrets["GEMINI_API_KEY"]
    except Exception:
        key = os.getenv("GEMINI_API_KEY")
    if not key:
        return None
    return genai.Client(api_key=key)


client = get_client()
if client is None:
    st.error("API key not found. Add GEMINI_API_KEY in the app's Secrets settings.")
    st.stop()

channel = st.selectbox("Message type", ["SMS", "Email"])
text = st.text_area("Message to check", height=150,
                    placeholder="e.g. Your account will be blocked today. Verify now: http://bit.ly/abc")

if st.button("Check message", type="primary"):
    if not text.strip():
        st.warning("Please paste a message first.")
    else:
        with st.spinner("Analyzing..."):
            try:
                result = analyze_message(client, text.strip(), channel, retries=2)
            except Exception as e:
                st.error(f"Something went wrong: {e}")
                st.stop()

        verdict = result["verdict"]
        if verdict == "SCAM":
            st.error(f"🚨 SCAM  (risk {result['risk_score']}/100)")
        elif verdict == "SUSPICIOUS":
            st.warning(f"⚠️ SUSPICIOUS  (risk {result['risk_score']}/100)")
        else:
            st.success(f"✅ SAFE  (risk {result['risk_score']}/100)")

        st.progress(result["risk_score"] / 100)
        st.write(f"**Type:** {result['scam_type']}")
        st.write(f"**Intent:** {result['intent']}")

        if result["fraud_patterns"]:
            st.write("**Patterns found:** " + ", ".join(result["fraud_patterns"]))
        if result["red_flags"]:
            st.write("**Red flags:**")
            for flag in result["red_flags"]:
                st.write(f"- {flag}")

        st.info(f"**In simple terms:** {result['explanation']}")
        st.write(f"**What to do:** {result['recommended_action']}")
