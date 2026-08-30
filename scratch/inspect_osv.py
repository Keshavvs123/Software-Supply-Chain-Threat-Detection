import urllib.request
import json
import ssl

ssl_context = ssl._create_unverified_context()

def inspect_osv():
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
        if vulns:
            v = vulns[0]
            print("ID:", v.get("id"))
            print("Aliases:", v.get("aliases"))
            affected = v.get("affected", [])
            print("Affected length:", len(affected))
            if affected:
                aff = affected[0]
                print("Affected keys:", list(aff.keys()))
                print("Affected package:", aff.get("package"))
                print("Affected ranges:", aff.get("ranges"))
                print("Affected versions sample (first 10):", aff.get("versions", [])[:10])

if __name__ == "__main__":
    inspect_osv()
