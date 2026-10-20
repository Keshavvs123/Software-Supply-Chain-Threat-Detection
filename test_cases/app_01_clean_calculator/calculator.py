"""
Application 1: Scientific & Financial Calculator CLI (CLEAN BASELINE)
Security Profile: 100% Safe, zero external attack surface.
Uses standard library math, decimal, and clean typing.
"""

import math
import sys
from decimal import Decimal, getcontext

getcontext().prec = 10

class ScientificCalculator:
    def __init__(self):
        self.history = []

    def add(self, a: float, b: float) -> float:
        res = float(Decimal(str(a)) + Decimal(str(b)))
        self.history.append(f"{a} + {b} = {res}")
        return res

    def subtract(self, a: float, b: float) -> float:
        res = float(Decimal(str(a)) - Decimal(str(b)))
        self.history.append(f"{a} - {b} = {res}")
        return res

    def multiply(self, a: float, b: float) -> float:
        res = float(Decimal(str(a)) * Decimal(str(b)))
        self.history.append(f"{a} * {b} = {res}")
        return res

    def divide(self, a: float, b: float) -> float:
        if b == 0:
            raise ValueError("Division by zero is undefined.")
        res = float(Decimal(str(a)) / Decimal(str(b)))
        self.history.append(f"{a} / {b} = {res}")
        return res

    def power(self, a: float, b: float) -> float:
        res = math.pow(a, b)
        self.history.append(f"{a} ^ {b} = {res}")
        return res

    def square_root(self, a: float) -> float:
        if a < 0:
            raise ValueError("Cannot calculate square root of negative number.")
        res = math.sqrt(a)
        self.history.append(f"sqrt({a}) = {res}")
        return res

    def compound_interest(self, principal: float, rate: float, time_years: float, n: int = 12) -> float:
        """Calculates compound interest securely without external risky dependencies."""
        amount = principal * math.pow((1 + (rate / (100 * n))), n * time_years)
        self.history.append(f"CI(P={principal}, r={rate}%, t={time_years}y) = {amount:.2f}")
        return amount

def main():
    calc = ScientificCalculator()
    print("=== Secure Scientific Calculator ===")
    print("Testing operations:")
    print("5 + 7 =", calc.add(5, 7))
    print("100 - 45.5 =", calc.subtract(100, 45.5))
    print("12 * 12 =", calc.multiply(12, 12))
    print("144 / 12 =", calc.divide(144, 12))
    print("Compound Interest on $10,000 at 5% over 10 years:", calc.compound_interest(10000, 5, 10))
    print("Calculation History Count:", len(calc.history))

if __name__ == "__main__":
    main()
