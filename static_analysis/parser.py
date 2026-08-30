import json

def parse_bandit(file_path):
    with open(file_path) as f:
        data = json.load(f)

    issues = data.get("results", [])

    total = len(issues)
    high = sum(1 for i in issues if i["issue_severity"] == "HIGH")
    medium = sum(1 for i in issues if i["issue_severity"] == "MEDIUM")
    low = sum(1 for i in issues if i["issue_severity"] == "LOW")

    return {
        "bandit_total": total,
        "bandit_high": high,
        "bandit_medium": medium,
        "bandit_low": low
    }


def parse_semgrep(file_path):
    with open(file_path) as f:
        data = json.load(f)

    issues = data.get("results", [])

    total = len(issues)

    return {
        "semgrep_total": total
    }