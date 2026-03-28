import os
import shutil
import streamlit as st
from langchain_community.document_loaders import PyPDFLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_chroma import Chroma
from langchain_community.embeddings import HuggingFaceEmbeddings

from layer2_sanitizer import sanitize_context
from layer1_detector import InjectionDetector

CHROMA_PATH = "vector_store"
embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")

def ingest_pdf_securely(file_path: str, security_mode: str, threat_action: str):
    """
    Tier 2 Pre-Ingestion Pipeline with dynamic Threat Handling.
    Returns: (bool, str) -> (Success status, Message)
    """
    # ==========================================
    # 0. AUTO-WIPE (Chroma Native Reset)
    # ==========================================
    # ChromaDB is cleaned each time a PDF is uploaded
    if os.path.exists(CHROMA_PATH):
        try:
            db = Chroma(persist_directory=CHROMA_PATH, embedding_function=embeddings)
            db.delete_collection()
        except Exception as e:
            print(f"An error occured when deleting previous vector database: {e}")

    loader = PyPDFLoader(file_path)
    docs = loader.load()
        
    # 1. Split into chunks
    splitter = RecursiveCharacterTextSplitter(chunk_size=1500, chunk_overlap=200)
    raw_chunks = splitter.split_documents(docs)
    
    # 2. Initialize the fast Tier-1 Scanner for document inspection
    doc_scanner = InjectionDetector()
    
    clean_chunks = []
    sanitization_logs = []
    
    progress_text = "Processing document chunks. Please wait..."
    my_bar = st.progress(0, text=progress_text)
    
    total_chunks = len(raw_chunks)
    for i, chunk in enumerate(raw_chunks):
        
        if "Block" in threat_action:
            # ==========================================
            # FAST PATH (Tier 1 Scan Only)
            # ==========================================
            scan_report = doc_scanner.analyze(chunk.page_content)
            
            if scan_report["is_bad"]:
                my_bar.empty()
                
                return False, f"Upload Rejected! Malicious content found. (Reason: {scan_report['reason']})", []
            else:
                clean_chunks.append(chunk)
                
        else:
            # ==========================================
            # SLOW PATH (Tier 2 LLaMA-3 Sanitization)
            # ==========================================
            safe_text, action_report = sanitize_context(chunk.page_content, mode=security_mode)
            
            if action_report and "clean" not in action_report.lower():
                sanitization_logs.append(f"**Chunk {i+1}:** {action_report}")
                
            chunk.page_content = safe_text
            clean_chunks.append(chunk)
            
        my_bar.progress((i + 1) / total_chunks, text=f"Processing chunk {i+1} of {total_chunks}")
        
    my_bar.empty()
    
    Chroma.from_documents(clean_chunks, embeddings, persist_directory=CHROMA_PATH)
    
    return True, "PDF sterilized and successfully ingested into the vector store.", sanitization_logs

def retrieve_context(query: str, k: int = 4) -> str:
    """Retrieves the top k most similar chunks and removes duplicates."""
    
    db = Chroma(persist_directory=CHROMA_PATH, embedding_function=embeddings)
    
    # Fetch the top results
    results = db.similarity_search(query, k=6)
    
    # Use a Python list/set logic to remove exact duplicate chunks
    unique_chunks = []
    seen_texts = set()
    
    for doc in results:
        # We strip whitespace to ensure exact matches are caught even if spaces differ slightly
        text = doc.page_content.strip()
        if text not in seen_texts:
            seen_texts.add(text)
            unique_chunks.append(text)
            
        # Stop once we have our desired number of unique chunks
        if len(unique_chunks) == k:
            break
            
    return "\n\n".join(unique_chunks)