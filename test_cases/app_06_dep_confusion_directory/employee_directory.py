"""
Application 6: Corporate Employee Directory Microservice (DEPENDENCY CONFUSION)
Security Profile: Enterprise directory service shadowed by public registry package.
Targeted Threat: Threat Model T2 (Dependency Confusion Namespace Shadowing).
Expected Risk: High (70% - 85% -> ~64.8% Risk Score).
Verdict: QUARANTINED (BLOCKED).

[VIVA EXPLANATION - WHY THIS IS QUARANTINED / WHERE IT IS WRONG]:
1. Where is the flaw?
   - Look at the line importing `corp_internal_auth` below!
   - `corp_internal_auth` represents an internal, proprietary enterprise module (prefixed with `corp_`).
2. How does ProTECTION / Gatekeeper catch it?
   - `dependency_analysis/threat_model.py` runs `detect_dependency_confusion()`.
   - Pattern: Detects internal namespace conventions (`corp_`, `internal_`, `company_`) being fetched from public PyPI registries without scoping or private repository indexes.
3. Why is this dangerous (Real-world incident: Alex Birsan 2021)?
   - Attackers claim names of internal private modules on public PyPI with a higher semantic version (e.g., 99.0.0).
   - Standard package managers (`pip`) prioritize public repositories, inadvertently downloading and executing the attacker's public payload inside the enterprise network.
4. Gatekeeper Action:
   - Threat Model T2 flag triggers quarantine and alerts developers to configure private Artifactory/Nexus indexes.
"""

import sys

# ==============================================================================
# [CRITICAL ATTACK VECTOR: WHERE THE CODE IS WRONG -> TRIGGERS QUARANTINED]
# ==============================================================================
# Line: `import corp_internal_auth`
# FLAGGED BY: Threat Model T2 (Dependency Confusion Detection)
# WHY IT IS DANGEROUS:
# - An external attacker uploads a rogue package named `corp_internal_auth` to public PyPI.
# - The build pipeline downloads the public malicious version instead of the internal company version.
# - Gatekeeper detects the corporate namespace prefix and blocks installation.
try:
    import corp_internal_auth  # <-- ATTACK LINE: Shadows internal private corporate microservice package
except ImportError:
    pass
# ==============================================================================

class EmployeeDirectory:
    def __init__(self):
        # [SECURITY LINE EXPLANATION: IN-MEMORY BENIGN DATA]
        # Represents standard organizational microservice data that would be stolen
        # if the dependency confusion attack succeeded.
        self.employees = [
            {"id": "EMP001", "name": "Alice Smith", "dept": "Engineering", "role": "Senior Architect"},
            {"id": "EMP002", "name": "Bob Jones", "dept": "Product", "role": "Principal PM"},
            {"id": "EMP003", "name": "Charlie Ray", "dept": "Security", "role": "CISO"}
        ]

    def find_by_dept(self, dept: str) -> list:
        # [SECURITY LINE EXPLANATION: CASE-INSENSITIVE SAFE FILTER]
        return [e for e in self.employees if e["dept"].lower() == dept.lower()]

    def authenticate_query(self, user_token: str) -> bool:
        # [SECURITY AUDIT POINT: COMPROMISED AUTH HOOK]
        # In a real environment, `corp_internal_auth` would be invoked here.
        # If shadowed, the attacker gains access to all directory search requests.
        return bool(user_token and len(user_token) >= 8)

def main():
    print("=== Corporate Employee Directory Service ===")
    directory = EmployeeDirectory()
    auth_ok = directory.authenticate_query("AUTH_SECRET_KEY_1234")
    print(f"Directory Authentication Status: {auth_ok}")
    security_team = directory.find_by_dept("Security")
    print("Security Team Members:", security_team)

if __name__ == "__main__":
    main()
