import zipfile
import json
import os
import urllib.request
import ssl
from collections import Counter, defaultdict

ssl_context = ssl._create_unverified_context()
ZIP_PATH = os.path.join("outputs", "osv_pypi_all.zip")

def analyze_vulnerable_packages():
    if not os.path.exists(ZIP_PATH):
        print("ZIP file not found.")
        return
        
    package_vulns = Counter()
    package_to_cves = defaultdict(set)
    
    with zipfile.ZipFile(ZIP_PATH) as z:
        namelist = z.namelist()
        for filename in namelist:
            if not filename.endswith(".json"):
                continue
            try:
                data = json.loads(z.read(filename).decode("utf-8"))
                affected = data.get("affected", [])
                cve_id = data.get("id")
                aliases = data.get("aliases", [])
                for a in aliases:
                    if a.startswith("CVE-"):
                        cve_id = a
                        break
                for aff in affected:
                    pkg = aff.get("package", {})
                    if pkg.get("ecosystem") == "PyPI":
                        pkg_name = pkg.get("name")
                        if pkg_name:
                            pkg_clean = pkg_name.lower().replace('_', '-')
                            package_vulns[pkg_clean] += 1
                            package_to_cves[pkg_clean].add(cve_id)
            except Exception:
                pass
                
    print("Vulnerable packages parsed.")
    # Print statistics
    sorted_pkgs = [name for name, _ in package_vulns.most_common(200)]
    print(f"Top 50 packages: {sorted_pkgs[:50]}")
    
if __name__ == "__main__":
    analyze_vulnerable_packages()
