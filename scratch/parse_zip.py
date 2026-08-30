import zipfile
import io
import json
import os
import urllib.request
import ssl
from collections import Counter

ssl_context = ssl._create_unverified_context()
ZIP_PATH = os.path.join("outputs", "osv_pypi_all.zip")

def download_if_not_exists():
    if not os.path.exists(ZIP_PATH):
        os.makedirs("outputs", exist_ok=True)
        url = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"
        print("Downloading GCS ZIP...")
        req = urllib.request.Request(url, headers={"User-Agent": "SupplyChainThreatDetector"})
        with urllib.request.urlopen(req, timeout=30, context=ssl_context) as response:
            with open(ZIP_PATH, "wb") as f:
                f.write(response.read())
        print("Downloaded GCS ZIP successfully.")

def parse_zip():
    download_if_not_exists()
    package_vulns = Counter()
    total_vulns = 0
    
    with zipfile.ZipFile(ZIP_PATH) as z:
        namelist = z.namelist()
        print(f"Total entries: {len(namelist)}")
        for filename in namelist:
            if not filename.endswith(".json"):
                continue
            try:
                data = json.loads(z.read(filename).decode("utf-8"))
                affected = data.get("affected", [])
                for aff in affected:
                    pkg = aff.get("package", {})
                    if pkg.get("ecosystem") == "PyPI":
                        pkg_name = pkg.get("name")
                        if pkg_name:
                            package_vulns[pkg_name.lower().replace('_', '-')] += 1
                            total_vulns += 1
            except Exception as e:
                pass
                
    print(f"Total PyPI vulnerability mappings: {total_vulns}")
    print(f"Total unique vulnerable packages: {len(package_vulns)}")
    print("\nTop 20 vulnerable packages and their vuln counts:")
    for name, count in package_vulns.most_common(20):
        print(f"  {name}: {count} vulns")

if __name__ == "__main__":
    parse_zip()
