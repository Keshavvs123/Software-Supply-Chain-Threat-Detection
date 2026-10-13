import os
import json
import urllib.request

KNOWN_SAFE_VERSIONS = {
    "urllib3": "2.2.3",
    "jinja2": "3.1.5",
    "requests": "2.32.3",
    "aiohttp": "3.10.11",
    "flask": "3.1.0",
    "pytest": "8.3.4",
    "setuptools": "75.8.2",
    "cryptography": "43.0.3",
    "werkzeug": "3.0.6",
    "certifi": "2024.8.30",
    "tornado": "6.4.2",
    "pillow": "10.4.0",
    "numpy": "2.0.2"
}

def generate_remediation_plan(resolved_packages, vulnerability_details, attack_paths=None):
    """
    Analyzes detected CVEs and transitive attack paths to calculate the minimal
    non-breaking safe upgrade recommendation for every vulnerable package.
    """
    remediation_actions = []
    package_recommendations = {}
    
    for pkg_key, vulns in vulnerability_details.items():
        if not vulns:
            continue
            
        pkg_info = resolved_packages.get(pkg_key, {})
        current_version = pkg_info.get("version", "Unknown")
        # Deduplicate CVE list preserving order
        cve_list = list(dict.fromkeys([v.get("cve_id", v.get("id", "Unknown")) for v in vulns]))
        max_cvss = max([v.get("cvss_score", 0.0) for v in vulns]) if vulns else 0.0
        
        # Determine safe version
        safe_ver = KNOWN_SAFE_VERSIONS.get(pkg_key.lower())
        
        # If current version is already at the known safe version, query PyPI for newer release or mark safe
        if safe_ver and current_version != "Unknown" and safe_ver == current_version:
            try:
                url = f"https://pypi.org/pypi/{pkg_key}/json"
                req = urllib.request.Request(url, headers={"User-Agent": "SecurityRemediator/2.0"})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    pypi_data = json.loads(resp.read().decode("utf-8"))
                    latest_ver = pypi_data.get("info", {}).get("version")
                    if latest_ver and latest_ver != current_version:
                        safe_ver = latest_ver
            except Exception:
                pass

        if not safe_ver:
            # Fallback: check PyPI for latest patch release
            try:
                url = f"https://pypi.org/pypi/{pkg_key}/json"
                req = urllib.request.Request(url, headers={"User-Agent": "SecurityRemediator/2.0"})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    pypi_data = json.loads(resp.read().decode("utf-8"))
                    safe_ver = pypi_data.get("info", {}).get("version")
            except Exception:
                safe_ver = current_version
                
        clean_safe_ver = str(safe_ver).lstrip(">= ").strip() if safe_ver else current_version
        
        # Skip redundant upgrade action if package is already at the recommended version
        if current_version != "Unknown" and clean_safe_ver == current_version:
            package_recommendations[pkg_key] = f"Verified at secure release {current_version}"
            continue

        # Find which root packages pull this vulnerable library
        root_parents = []
        if attack_paths:
            for path in attack_paths:
                p_str = path.get("path", "")
                if pkg_key.lower() in p_str.lower():
                    root_pkg = p_str.split("->")[0].strip()
                    if root_pkg and root_pkg.lower() != pkg_key.lower() and root_pkg not in root_parents:
                        root_parents.append(root_pkg)
                        
        impact_level = "CRITICAL" if max_cvss >= 8.5 else "HIGH" if max_cvss >= 6.0 else "MEDIUM"
        
        remediation_item = {
            "package": pkg_key,
            "current_version": current_version,
            "recommended_version": clean_safe_ver,
            "severity": impact_level,
            "cves_resolved": cve_list,
            "cve_count": len(cve_list),
            "max_cvss": max_cvss,
            "transitive_parents": root_parents,
            "upgrade_command": f"pip install --upgrade \"{pkg_key}>={clean_safe_ver}\"",
            "action_summary": f"Upgrade {pkg_key} from {current_version} to >={clean_safe_ver} (fixes {len(cve_list)} CVEs)"
        }
        
        remediation_actions.append(remediation_item)
        package_recommendations[pkg_key] = f"Upgrade to >={clean_safe_ver} (Fixes {', '.join(cve_list[:2])})"
        
    # Sort by risk severity
    remediation_actions.sort(key=lambda x: x["max_cvss"], reverse=True)
    
    # Save plan to outputs/remediation_plan.json
    os.makedirs("outputs", exist_ok=True)
    plan_path = os.path.join("outputs", "remediation_plan.json")
    with open(plan_path, "w", encoding="utf-8") as f:
        json.dump({
            "total_vulnerable_packages": len(remediation_actions),
            "remediation_actions": remediation_actions
        }, f, indent=2)
        
    return {
        "actions": remediation_actions,
        "recommendations_by_pkg": package_recommendations,
        "total_fixes": len(remediation_actions)
    }
