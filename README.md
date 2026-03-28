# DualGuard-RAG: Two-Tier Defense Architecture

An advanced, secure Retrieval-Augmented Generation (RAG) system designed to mitigate Indirect Prompt Injections and malicious payloads in document-processing pipelines. 

DualGuard-RAG employs a **Zero-Trust Pre-Ingestion Architecture**, meaning documents are aggressively scanned and sterilized *before* they ever enter the vector database, preventing cross-model vulnerabilities and safeguarding the backend LLM.

## The Dual-Layer Architecture

This system uses a **Dual LLM Strategy** to prevent systemic bypasses. By using different model architectures for defense (DistilBERT & Meta's LLaMA-3) and execution (Google's Gemini), the system eliminates single points of failure.

### Layer 1: High-Speed Detection (Fast Path)
* **What it does:** Scans incoming document chunks for prompt injections, jailbreaks, and data exfiltration commands.
* **Technology:** A custom-trained DistilBERT model paired with Regex heuristics.
* **Check out the Model Training Repository:** [🔗](https://github.com/fgulfirtina/llm-security-prompt-injection-detection) - *This repository contains the dataset, training scripts, and evaluation metrics for the Layer 1 model.*

### Layer 2: Deep Context Sanitization (Slow Path)
* **What it does:** If the system is set to "Auto-Remediation", it uses an 8-billion parameter local model to rewrite and sterilize infected document chunks while preserving academic/factual integrity.
* **Technology:** LLaMA-3 (via Ollama) enforcing strict JSON-formatted structured outputs.

## Key Features

* **Dynamic Threat Handling:** Administrators can toggle between *Block & Reject* (fast, strict blocking) and *Sanitize & Ingest* (slower, auto-remediation).
* **Pre-Ingestion Sterilization:** The vector database (`ChromaDB`) only stores 100% clean data, drastically reducing query latency during the chat phase.
* **Cryptographic File Tracking:** Uses MD5 hashing to track document state, preventing redundant processing and automatically wiping the database when new content is detected.
* **Persistent Audit Logs:** A UI expander that permanently logs exactly which malicious commands were removed by Layer 2 during ingestion.

## Installation & Setup

### Prerequisites
1. **Python 3.9+**
2. **Ollama:** Must be installed and running locally with the `llama3` model pulled (`ollama run llama3`).
3. **Google Gemini API Key:** Required for the backend execution engine.

### Quick Start

1. Clone the repository:
   ```bash
   git clone https://github.com/fgulfirtina/dual-guard-rag-defense.git
   cd dual-guard-rag-defense
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Create a .env file in the root directory and add your Google API key:
   ```bash
   GOOGLE_API_KEY=your_gemini_api_key_here
   ```

4. Run the application:
   ```bash
   streamlit run app.py
   ```

## Usage

1. Open the Streamlit interface in your browser.
2. Select your desired Tier 2 Strictness Level and Threat Handling strategy from the sidebar.
3. Upload a PDF. The system will process it based on your security settings.
4. If malicious content is found and sanitized, review the Tier 2 Sanitization Audit Logs on the main screen.
5. Query the sterilized document using the chat interface.

## Screenshots

• File upload & sanitization:

<img width="1919" height="848" alt="Ekran görüntüsü 2026-03-28 190036" src="https://github.com/user-attachments/assets/a60aacb9-ea2d-4e0e-8e92-22e4a39a0b8e" />

---

• Prompt injection detection:

<img width="1919" height="845" alt="Ekran görüntüsü 2026-03-28 190141" src="https://github.com/user-attachments/assets/d81ca0ba-6024-4fc9-aa6e-e24ac8fb6125" />

## Security Considerations

This project was developed as a proof-of-concept for securing LLM architectures.
The Heterogeneous (LLaMA + Gemini) approach specifically targets the mitigation of adversarial inputs that attempt to exploit shared model vulnerabilities.

## Author

Fatmagül Fırtına — Computer Engineering Student at Dokuz Eylul University
