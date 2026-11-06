r"""
Application 5: Real-Time Currency Exchange Converter (TYPOSQUATTING INJECTION)
Security Profile: Adversary published 'reqeusts' mimicking popular 'requests' library.
Targeted Threat: Threat Model T1 (Typosquatting Supply-Chain Injection).
Expected Risk: High (70% - 85% -> ~89.8% Risk Score).
Verdict: QUARANTINED (BLOCKED).

[VIVA EXPLANATION - WHY THIS IS QUARANTINED / WHERE IT IS WRONG]:
1. Where is the flaw?
   - Look at line importing `reqeusts` below!
   - `reqeusts` is spelled with transposed 'u' and 'e' (Levenshtein distance = 1 from 'requests').
2. How does ProTECTION / Gatekeeper catch it?
   - `dependency_analysis/threat_model.py` runs `detect_typosquatting()`.
   - Algorithm:
     - Levenshtein string distance $\le 2$ or Jaro-Winkler similarity $\ge 0.88$ against popular PyPI packages.
     - Detects that 'reqeusts' is an imposter targeting the authentic 'requests' library.
3. Verdict Calculation:
   - Base HGAT/LSTM score + Threat Model T1 flag triggers an automated risk boost ($+0.35$).
   - Risk score exceeds $60\%$ (measured at ~89.8%).
   - Immediate Policy Enforcement: QUARANTINED (Installation and execution blocked).
"""

import sys

# ==============================================================================
# [CRITICAL ATTACK VECTOR: WHERE THE CODE IS WRONG -> TRIGGERS QUARANTINED]
# ==============================================================================
# Line: `import reqeusts`
# FLAGGED BY: Threat Model T1 (Typosquatting Detection)
# WHY IT IS DANGEROUS:
# - An attacker registers misspelled names of common libraries on PyPI.
# - Unsuspecting developers install 'reqeusts' instead of 'requests'.
# - The malicious package executes unauthorized code upon import.
# - Gatekeeper intercepts this at the dependency resolution stage before execution.
try:
    import reqeusts  # <-- ATTACK LINE: Typosquat of 'requests' (Edit Distance = 1)
except ImportError:
    pass
# ==============================================================================

class CurrencyConverter:
    """Legitimate business logic that is compromised by the rogue dependency above."""
    def __init__(self, base_currency: str = "USD"):
        # [SECURITY LINE EXPLANATION: SAFE IN-MEMORY RATES]
        # Currency conversion logic itself is benign, showing that even benign application
        # logic is vulnerable when an upstream dependency is poisoned.
        self.base_currency = base_currency
        self.rates = {
            "USD": 1.0,
            "EUR": 0.92,
            "INR": 83.25,
            "GBP": 0.79,
            "JPY": 155.40
        }

    def convert(self, amount: float, target_currency: str) -> float:
        rate = self.rates.get(target_currency.upper())
        if not rate:
            raise ValueError(f"Unsupported currency: {target_currency}")
        return amount * rate

def main():
    print("=== Currency Exchange Converter ===")
    converter = CurrencyConverter("USD")
    amt = 100.0
    print(f"{amt} USD in INR: {converter.convert(amt, 'INR'):.2f}")
    print(f"{amt} USD in EUR: {converter.convert(amt, 'EUR'):.2f}")

if __name__ == "__main__":
    main()
