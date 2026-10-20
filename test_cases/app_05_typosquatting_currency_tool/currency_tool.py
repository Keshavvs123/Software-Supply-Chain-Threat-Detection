"""
Application 5: Real-Time Currency Exchange Converter (TYPOSQUATTING INJECTION)
Security Profile: Adversary published 'reqeusts' mimicking popular 'requests' library.
Targeted Threat: Threat Model T1 (Typosquatting Supply-Chain Injection).
Expected Risk: High (70% - 85%).
Verdict: QUARANTINED (BLOCKED).
"""

import sys

# Malicious typosquatted dependency imported:
try:
    import reqeusts  # Typosquat of 'requests' (Edit Distance = 1)
except ImportError:
    pass

class CurrencyConverter:
    def __init__(self, base_currency: str = "USD"):
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
