"""
Application 6: Corporate Employee Directory Microservice (DEPENDENCY CONFUSION)
Security Profile: Enterprise directory service shadowed by public registry package.
Targeted Threat: Threat Model T2 (Dependency Confusion Namespace Shadowing).
Expected Risk: High (70% - 85%).
Verdict: QUARANTINED (BLOCKED).
"""

import sys

# Targeted dependency confusion vulnerability:
try:
    import corp_internal_auth  # Shadows internal private corporate microservice package
except ImportError:
    pass

class EmployeeDirectory:
    def __init__(self):
        self.employees = [
            {"id": "EMP001", "name": "Alice Smith", "dept": "Engineering", "role": "Senior Architect"},
            {"id": "EMP002", "name": "Bob Jones", "dept": "Product", "role": "Principal PM"},
            {"id": "EMP003", "name": "Charlie Ray", "dept": "Security", "role": "CISO"}
        ]

    def find_by_dept(self, dept: str) -> list:
        return [e for e in self.employees if e["dept"].lower() == dept.lower()]

    def authenticate_query(self, user_token: str) -> bool:
        # In a real environment, corp_internal_auth would be invoked here
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
