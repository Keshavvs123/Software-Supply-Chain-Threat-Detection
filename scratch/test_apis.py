import urllib.request
import json
import ssl

ssl_context = ssl._create_unverified_context()

def test_pypi():
    url = "https://pypi.org/pypi/requests/json"
    req = urllib.request.Request(url, headers={"User-Agent": "SupplyChainThreatDetector"})
    with urllib.request.urlopen(req, timeout=5, context=ssl_context) as response:
        data = json.loads(response.read().decode())
        info = data.get("info", {})
        releases = data.get("releases", {})
        print("Requests version:", info.get("version"))
        print("Total releases:", len(releases))
        print("Requires dist:", info.get("requires_dist")[:5] if info.get("requires_dist") else None)

def test_osv():
    url = "https://api.osv.dev/v1/query"
    query = {"package": {"name": "requests", "ecosystem": "PyPI"}}
    req = urllib.request.Request(
        url, 
        data=json.dumps(query).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "SupplyChainThreatDetector"}
    )
    with urllib.request.urlopen(req, timeout=5, context=ssl_context) as response:
        data = json.loads(response.read().decode())
        vulns = data.get("vulns", [])
        print("Requests OSV vulnerabilities count:", len(vulns))
        if vulns:
            print("First vuln ID:", vulns[0].get("id"))
            print("First vuln details keys:", list(vulns[0].keys()))

if __name__ == "__main__":
    print("Testing PyPI JSON API...")
    test_pypi()
    print("\nTesting OSV.dev API...")
    test_osv()
