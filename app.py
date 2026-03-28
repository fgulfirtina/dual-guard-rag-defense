import streamlit as st
import os
import hashlib
from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI
from layer1_detector import InjectionDetector
from rag_module import ingest_pdf_securely, retrieve_context

# ==========================================
# INITIALIZATION & CONFIGURATION
# ==========================================
load_dotenv()
llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0)
detector = InjectionDetector()

st.set_page_config(page_title="DualGuard-RAG Defense System", page_icon="🛡️", layout="wide")
st.title("🛡️ DualGuard-RAG: Two-Tier Defense Architecture")
st.markdown(
    "A resilient RAG pipeline featuring **Tier 1 (DistilBERT)** for query inspection and "
    "**Tier 2 (LLaMA-3)** for pre-ingestion database sanitization. Powered by a Gemini backend "
    "to prevent cross-model injection vulnerabilities."
)

# ==========================================
# SIDEBAR: SETTINGS ONLY
# ==========================================
with st.sidebar:
    st.header("⚙️ Defense Settings")
    
    security_mode = st.radio(
        "Tier 2 Strictness Level",
        [
            "Standard (Balanced)", 
            "Academic (Preserves Tech Examples)", 
            "Paranoid (Strips all threats)"
        ],
        help="Determines how aggressively LLaMA-3 sanitizes the text during upload."
    )
    
    st.divider()
    
    threat_action = st.radio(
        "Document Threat Handling",
        [
            "Sanitize & Ingest (Slower, Auto-Remediation)", 
            "Block & Reject (Fast, Zero-Trust)"
        ],
        help="Choose whether to clean infected documents or instantly reject them."
    )

# ==========================================
# MAIN INTERFACE: UPLOAD & STERILIZE
# ==========================================
st.header("📄 1. Knowledge Base Initialization")
uploaded = st.file_uploader("Upload a PDF to sterilize and index", type="pdf")

if uploaded:
    file_bytes = uploaded.getvalue()
    file_hash = hashlib.md5(file_bytes).hexdigest()
    
    if "processed_file_hash" not in st.session_state or st.session_state.processed_file_hash != file_hash:
        
        temp_dir = "temp_uploads"
        os.makedirs(temp_dir, exist_ok=True)
        path = os.path.join(temp_dir, uploaded.name)
        
        with open(path, "wb") as f:
            f.write(file_bytes)
            
        st.info(f"Initiating Pre-Ingestion Pipeline ({threat_action})...")
        
        success, message, logs = ingest_pdf_securely(path, security_mode, threat_action)
        
        if success:
            st.session_state.processed_file_hash = file_hash
            st.session_state.sanitization_logs = logs 
            st.success(f"✅ {message}")
        else:
            st.error(f"🚨 {message}")
            
    else:
        st.success("✅ PDF is already processed and ready for questions.")
        
    if st.session_state.get("sanitization_logs"):
        with st.expander("🛡️ Tier 2 Sanitization Audit Logs (Action Taken)", expanded=True):
            st.warning("LLaMA-3 detected and removed the following threats from the document:")
            for log in st.session_state.sanitization_logs:
                st.markdown(f"- {log}")

st.divider()

# ==========================================
# MAIN INTERFACE: QUERY PROCESSING
# ==========================================
st.header("💬 2. System Query")
col1, col2 = st.columns([2, 1])

with col1:
    user_input = st.text_area("Your question", height=120, placeholder="Ask something about the sterilized document...")

if st.button("Submit", type="primary") and user_input:

    if "processed_file_hash" not in st.session_state:
        st.warning("⚠️ Please upload and successfully process a PDF first.")
    else:
        with st.status("Processing Security Pipeline...", expanded=True) as status:

            # ---------------------------------------------------------
            # Layer 1: Query Inspection
            # ---------------------------------------------------------
            st.write("🔍 Layer 1: Inspecting user query for malicious intent...")
            report = detector.analyze(user_input)
            
            if report["is_bad"]:
                status.update(label="Blocked by Guardrails", state="error")
                st.error(f"🚫 Input blocked by Layer 1 ({report['reason']}). Confidence: {report['confidence']:.2%}")
            else:
                st.success(f"✅ Layer 1 passed. Malicious confidence: {report['confidence']:.2%}")

                # ---------------------------------------------------------
                # RAG Retrieval
                # ---------------------------------------------------------
                st.write("📚 Retrieving pre-sanitized context from vector store...")
                safe_context = retrieve_context(user_input)
                
                with st.expander("View Sterile Retrieved Context"):
                    st.text(safe_context)

                # ---------------------------------------------------------
                # Backend Execution (Gemini 2.5 Flash)
                # ---------------------------------------------------------
                st.write("🤖 Sending clean context to Gemini...")
                
                final_prompt = (
                    "You are a helpful assistant. Answer only based on the provided context.\n\n"
                    f"Context:\n{safe_context}\n\n"
                    f"Question: {user_input}"
                )
                
                # Wrap the Gemini call in a try-except block
                try:
                    response = llm.invoke(final_prompt)
                    answer = response.content
                    
                    status.update(label="Pipeline Completed Successfully", state="complete")
                    st.subheader("Response")
                    st.write(answer)
                    
                except Exception as e:
                    # Convert the error to a string to check if it's a safety block
                    error_msg = str(e).lower()
                    
                    if "safety" in error_msg or "blocked" in error_msg or "finish_reason" in error_msg:
                        status.update(label="Blocked by Backend AI", state="error")
                        st.error("🚨 Detected Security Breach: The backend AI refused to process this request due to its internal safety filters.")
                    else:
                        # Catch any other API errors (like internet disconnection)
                        status.update(label="Execution Error", state="error")
                        st.error(f"⚠️ An unexpected API error occurred: {e}")