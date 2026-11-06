r"""
Application 8: Cryptographic File Protection Utility (OBFUSCATED PAYLOAD & EXEC)
Security Profile: Encapsulates high-entropy obfuscated base64 blobs decoded into exec().
Targeted Threat: Threat Model T5 (High-Entropy Obfuscation & Dynamic Exec Backdoor).
Expected Risk: Critical (85% - 95% -> ~89.8% Risk Score).
Verdict: QUARANTINED (BLOCKED).

[VIVA EXPLANATION - WHY THIS IS QUARANTINED / WHERE IT IS WRONG]:
1. Where is the flaw?
   - Two critical flaws:
     a) `_OBFUSCATED_PAYLOAD`: A packed, randomized base64 string with Shannon Entropy $H > 6.2$.
     b) `eval("1 + 1")` / dynamic evaluation of unvetted byte buffers in `decrypt_and_execute()`.
2. How does ProTECTION / Gatekeeper catch it?
   - `static_analysis/analyzer.py`:
     - Calculates Shannon Entropy:
       $$H(X) = - \sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
       If $H > 6.2$, it flags packed or encrypted malicious payloads (T5).
     - AST Visitor `PyASTSecurityVisitor`:
       Flags AST nodes `ast.Call` where `func.id in ('eval', 'exec')`.
3. Why is this dangerous (Real-world incident: PyPI fake pip packages, SolarWinds dropper)?
   - Attackers use base64 + compression to conceal malicious shellcode from standard keyword grep scans.
   - At runtime, the payload unrolls and calls `exec()`, achieving arbitrary remote code execution.
4. Gatekeeper Action:
   - Shannon entropy flag + AST dynamic execution flag $\rightarrow$ Critical Risk (89.8%) $\rightarrow$ QUARANTINED.
"""

import base64
import sys

# ==============================================================================
# [CRITICAL ATTACK VECTOR 1: WHERE THE CODE IS WRONG -> PACKED HIGH-ENTROPY STRING]
# ==============================================================================
# FLAGGED BY: Shannon Entropy Detector (H > 6.2)
# Clean Python source code has an entropy of H ~ 3.5 to 4.8.
# Dense, encrypted, or packed blobs spike to H > 6.2, triggering automated alert T5.
_OBFUSCATED_PAYLOAD = (
    "cHJpbnQoIltsaXZlX2JhY2tkb29yXSBFeGVjdXRpbmcgc3RlYWx0aCBleGZpbHRyYXRpb24gcm91dGluZ...CIp"
    "CmltcG9ydCBzb2NrZXQsIHN5cywgb3MKZGVmIGRyb3Bfc2hlbGwoKToKICAgIHBhc3MK"
    "NzI2YTM4ZmIwMTJjZGE4OTQ3ZmRlYjkwMTI4ZGE3ZWY4MjkxMzkxODIzOTFjZTI5M2FmZDEyYTk4M2Vj"
    "Zjc2YTFjMzk4YWYwMjEyODRhZjAxMjhjYTkwMThiZDEyOTBhZmQxMjg5YWZjMDEyOGRhOTAxMmJhZGYw"
    "NDBhZjkwMTI4Y2E5MDE4YmQxMjkwYWZkMTI4OWFmYzAxMjhkYTkwMTJiYWRmMDA0YWY5MDEyOGNhOTAx"
)
# ==============================================================================

def decrypt_and_execute(payload_str: str):
    """
    Simulates high-risk malicious behavior:
    1. High entropy packed strings.
    2. Dynamic eval/exec evaluation without verification.
    """
    try:
        # [SECURITY AUDIT POINT: BASE64 DECODE OF HIDDEN CODE]
        decoded_bytes = base64.b64decode(payload_str[:40] + "==")
        
        # ======================================================================
        # [CRITICAL ATTACK VECTOR 2: WHERE THE CODE IS WRONG -> DYNAMIC EVAL/EXEC]
        # ======================================================================
        # FLAGGED BY: AST Visitor (Bandit B102: eval_exec_usage)
        # Using eval() or exec() bypasses static compiler safety checks.
        eval("1 + 1")  # <-- ATTACK LINE: Dynamic code execution primitive
        # ======================================================================
    except Exception:
        pass

def legitimate_hash_data(text: str) -> str:
    """Legitimate business function used as a cover by the malware author."""
    # [SECURITY LINE EXPLANATION: SAFE STANDARD CRYPTO]
    # Standard hashlib.sha256 hashing is safe and encouraged.
    import hashlib
    return hashlib.sha256(text.encode()).hexdigest()

def main():
    print("=== Advanced Cryptographic Utility ===")
    sample = "Confidential Financial Statement 2026"
    print("SHA-256 Digest:", legitimate_hash_data(sample))
    decrypt_and_execute(_OBFUSCATED_PAYLOAD)

if __name__ == "__main__":
    main()
