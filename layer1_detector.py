import torch
import torch.nn.functional as F
from transformers import DistilBertTokenizer, DistilBertForSequenceClassification
import re
import streamlit as st

# ==========================================
# TIER 1 — SURGICAL REGEX RULES
# ==========================================
# Harmful verbs
_GENERATE = r"(?:writ(?:e|es|ing|ten)|creat(?:e|es|ed|ing)|build(?:s|ing)?|cod(?:e|es|ed|ing)|develop(?:s|ed|ing)?|generat(?:e|es|ed|ing)|produc(?:e|es|ed|ing)|craft(?:s|ed|ing)?|output(?:s|ting)?|giv(?:e|es|ing)\s+me|show(?:s|ing)?\s+me|provid(?:e|es|ed|ing))"
_PERFORM  = r"(?:perform(?:s|ed|ing)?|execut(?:e|es|ed|ing)|inject(?:s|ed|ing)?|conduct(?:s|ed|ing)?|run(?:s|ning)?|launch(?:es|ed|ing)?|carry(?:ing)?\s+out|carried\s+out)"
_BYPASS   = r"(?:bypass(?:es|ed|ing)?|circumvent(?:s|ed|ing)?|disabl(?:e|es|ed|ing)|overrid(?:e|es|ing)|evad(?:e|es|ed|ing)|get(?:s|ting)?\s+around|break(?:s|ing)?)"
_EXFIL    = r"(?:send(?:s|ing)?|transmit(?:s|ting|ted)?|post(?:s|ed|ing)?|upload(?:s|ed|ing)?|exfiltrat(?:e|es|ed|ing)|dump(?:s|ed|ing)?|leak(?:s|ed|ing)?)"

#Specific action verbs
_MANIPULATE = r"(?:manipulat(?:e|es|ed|ing)|modif(?:y|ies|ied|ying)|alter(?:s|ed|ing)?|inject(?:s|ed|ing)?\s+into|tamper(?:s|ed|ing)?\s+with)"
_RECON_VERB = r"(?:discover(?:s|ed|ing)?|scan(?:s|ned|ning)?\s+for|find(?:s|ing)?|enumerat(?:e|es|ed|ing)|search(?:es|ed|ing)?\s+for|list(?:s|ed|ing)?)"

# Harmful objects
_MALWARE  = r"(?:keylog(?:ger|ging)?|hack(?:er|s|ers|ing)?|virus|ransomware|malware|trojan|rootkit|spyware|worm|backdoor|reverse\s+shell|botnet|shellcode|exploit\s+(?:code|script)|payload(?:s)?)"
_ATTACK   = r"(?:sql\s+injection|sqli|xss|cross.site\s+scripting|csrf|ssrf|rce|remote\s+code\s+execution|buffer\s+overflow|privilege\s+escalation|directory\s+traversal|path\s+traversal|command\s+injection)"
_PHISH    = r"(?:phish(?:ing|es|ed)?|fake\s+login\s+page(?:s)?|credential\s+harvest(?:ing)?|account\s+takeover\s+page(?:s)?)"
_EXFOBJ   = r"(?:system\s+prompt(?:s)?|conversation\s+history|context\s+window|internal\s+instruction(?:s)?|prior\s+message(?:s)?)"

# Specific target objects
_DB_QUERY   = r"(?:database\s+)?(?:sql\s+)?quer(?:y|ies)"
_RECON_OBJ  = r"(?:all\s+)?(?:open|active|vulnerable)\s+port(?:s)?"

# Captures variations of "how to", "what should I do to", "steps to", etc.
_TUTORIAL_REQ = r"(?:how\s+to|what\s+.*?\s+do\s+to|steps\s+to|guide\s+(?:on|to|for)|tell\s+me\s+how|ways?\s+to|instructions?\s+(?:on|for))"
    
_HACKING_VERBS = r"(?:hack(?:s|ed|ing|er|ers)?|crack(?:s|ed|ing)?|infiltrat(?:e|es|ed|ing)|compromis(?:e|es|ed|ing)|hijack(?:s|ed|ing)?|ddos)"


TIER1_PATTERNS = [
    # Payload generation: verb + malware/exploit object
    rf"{_GENERATE}.*?{_MALWARE}",
    rf"{_MALWARE}.*?{_GENERATE}",          # reverse order ("keylogger code, write it")

    # Attack execution: verb + attack type
    rf"{_PERFORM}.*?{_ATTACK}",
    rf"{_ATTACK}.*?{_PERFORM}",

    # Phishing / social engineering generation
    rf"{_GENERATE}.*?{_PHISH}",
    rf"{_PHISH}.*?{_GENERATE}",

    # Safety bypass: explicit bypass verb + safety target
    rf"{_BYPASS}.*?(?:safety|restriction(?:s)?|filter(?:s)?|guardrail(?:s)?|polic(?:y|ies)|rule(?:s)?|content\s+polic(?:y|ies)|moderation)",

    # Prompt injection markers (these have no benign interpretation)
    r"ignor(?:e|es|ed|ing)\s+(?:all\s+)?(?:previous|prior|above|your)\s+(?:instruction(?:s)?|rule(?:s)?|guideline(?:s)?|direction(?:s)?|prompt(?:s)?)",
    r"disregard(?:s|ed|ing)?\s+(?:all\s+)?(?:previous|prior|above|your)\s+(?:instruction(?:s)?|rule(?:s)?|guideline(?:s)?|direction(?:s)?)",
    r"forget(?:s|ting)?\s+(?:all\s+)?(?:previous|prior|above|your)\s+(?:instruction(?:s)?|rule(?:s)?|guideline(?:s)?|direction(?:s)?)",
    r"you\s+are\s+now\s+(?:in\s+)?(?:developer|god|unrestricted|jailbreak|dan)\s+mode",
    r"\bdo\s+anything\s+now\b",
    r"\bdeveloper\s+mode\s+enabled\b",
    r"\bjailbreak(?:ed)?\b.*?(?:mode|enabled|activated)",

    # Indirect injection: fetch external instructions
    r"(?:load(?:s|ed|ing)?|read(?:s|ing)?|fetch(?:es|ed|ing)?|retriev(?:e|es|ed|ing)|visit(?:s|ed|ing)?|access(?:es|ed|ing)?)\s+.*?(?:instruction(?:s)?|rule(?:s)?|guideline(?:s)?|command(?:s)?)\s+from\s+(?:http|www\.|this\s+url|the\s+link)",

    # Data exfiltration: send model internals somewhere
    rf"{_EXFIL}.*?{_EXFOBJ}",
    rf"{_EXFOBJ}.*?{_EXFIL}",
    rf"{_EXFIL}.*?(?:your\s+(?:output|response|reply))\s+to\s+(?:http|www\.|this\s+url)",

    # ==========================================
    # ETHICS, SAFETY OVERRIDES & RECON
    # ==========================================
    
    # "Without safety", "do not care about safety" (flexible spacing and phrasing)
    r"(?:without|ignor(?:e|es|ed|ing)|disregard(?:s|ed|ing)?|do(?:es)\s+not\s+care\s+about|do(?:es)n['’]?t\s+care\s+about|remov(?:e|es|ed|ing)|drop(?:s|ping)?).*?(?:any\s+)?(?:safety|security)\s+(?:restriction(?:s)?|filter(?:s)?|rule(?:s)?|guideline(?:s)?|protocol(?:s)?|guardrail(?:s)?)",

    # "Reverse ethics", "ignore core ethics" (catches deep persona manipulations)
    r"(?:revers(?:e|es|ed|ing)|ignor(?:e|es|ed|ing)|disregard(?:s|ed|ing)?|bypass(?:es|ed|ing)?|do\s+not\s+care\s+about|don['’]?t\s+care\s+about|suspend(?:s|ed|ing)?).*?(?:your\s+)?(?:core\s+)?(?:ethics|ethical\s+(?:guideline(?:s)?|rule(?:s)?|filter(?:s)?|protocol(?:s)?|principle(?:s)?))",

    # "Manipulate database query" (stops subtle SQLi logic requests)
    rf"{_MANIPULATE}.*?{_DB_QUERY}",
    rf"{_DB_QUERY}.*?{_MANIPULATE}",

    # "Discover open ports" (stops network reconnaissance scripts like our sci-fi villain)
    rf"{_RECON_VERB}.*?{_RECON_OBJ}",
    rf"{_RECON_OBJ}.*?{_RECON_VERB}",

    # Blocks instructional requests for attacks (e.g., "what i should do to hack")
    # The (?!.*?(?:prevent|stop|secure|protect|defend|patch)) ensures we DO NOT block defensive questions
    rf"{_TUTORIAL_REQ}\s+(?!.*?(?:prevent|stop|secure|protect|defend|patch|fix)).*?{_HACKING_VERBS}\b",
    rf"{_HACKING_VERBS}\s+(?!.*?(?:prevent|stop|secure|protect|defend|patch|fix)).*?{_TUTORIAL_REQ}\b",
]

_COMPILED = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in TIER1_PATTERNS]

# We use cache to prevent streamlit upload the model each time
@st.cache_resource
def get_model(model_path):
    tokenizer = DistilBertTokenizer.from_pretrained(model_path)
    model = DistilBertForSequenceClassification.from_pretrained(model_path)
    model.eval()
    return tokenizer, model

class InjectionDetector:
    def __init__(self, model_path="./distilbert_context_aware_model"):
        self.tokenizer, self.model = get_model(model_path)
        self.block_threshold = 0.65

    def analyze(self, text: str):
        # 1. Surgical Regex Check
        for pat, raw in zip(_COMPILED, TIER1_PATTERNS):
            if pat.search(text):
                return {"is_bad": True, "reason": "Regex pattern matched", "confidence": 1.0}
        
        # 2. DistilBERT Check
        inputs = self.tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
        with torch.no_grad():
            logits = self.model(**inputs).logits
        
        probs = torch.softmax(logits, dim=1)
        malicious_prob = probs[0][1].item()
        
        if malicious_prob > self.block_threshold:
            return {"is_bad": True, "reason": "AI model detected threat", "confidence": malicious_prob}
            
        return {"is_bad": False, "reason": "Clean", "confidence": malicious_prob}