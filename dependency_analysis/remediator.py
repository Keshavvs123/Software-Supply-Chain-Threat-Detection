import os
import json
import urllib.request

def _minimal_fixed_version(vulns, current_version):
    """Smallest version that fixes ALL advisories, taken from the advisories' own "fixed" data.

    For each advisory pick its lowest fixed version above the current one; the answer is the highest of
    those (so one upgrade resolves every advisory). Returns None if the advisories carry no fix data.
    """
    from packaging.version import Version, InvalidVersion
    try:
        cur = Version(str(current_version))
    except InvalidVersion:
        return None
    needed = []
    for v in vulns:
        candidates = []
        for fv in v.get("fixed_versions", []) or []:
            try:
                ver = Version(fv)
            except InvalidVersion:
                continue
            if ver > cur:
                candidates.append(ver)
        if candidates:
            needed.append(min(candidates))
    return str(max(needed)) if needed else None


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
        cve_list = list(dict.fromkeys(v.get("cve_id", v.get("id", "Unknown")) for v in vulns))  # de-duplicated, order kept
        max_cvss = max([v.get("cvss_score", 0.0) for v in vulns]) if vulns else 0.0
        
        # Determine safe version from the advisories themselves (no hard-coded table: those go stale)
        safe_ver = _minimal_fixed_version(vulns, current_version)
        if not safe_ver:
            # No fix data in the advisories: suggest the latest PyPI release if it is newer than the current one
            try:
                url = f"https://pypi.org/pypi/{pkg_key}/json"
                req = urllib.request.Request(url, headers={"User-Agent": "SecurityRemediator/2.0"})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    pypi_data = json.loads(resp.read().decode("utf-8"))
                    safe_ver = pypi_data.get("info", {}).get("version")
            except Exception:
                safe_ver = None

        # Find which root packages pull this vulnerable library
        root_parents = []
        if attack_paths:
            for path in attack_paths:
                p_str = path.get("path", "")
                if pkg_key.lower() in p_str.lower():
                    root_pkg = p_str.split("->")[0].strip()
                    if root_pkg and root_pkg.lower() != pkg_key.lower() and root_pkg not in root_parents:
                        root_parents.append(root_pkg)
                        
        # Never recommend the version that is already installed (or an older one) as a "fix".
        try:
            from packaging.version import Version
            no_newer_fix = (not str(safe_ver).startswith(">=")) and Version(str(safe_ver)) <= Version(str(current_version))
        except Exception:
            no_newer_fix = str(safe_ver) == str(current_version) or str(safe_ver).startswith(">=")
        if no_newer_fix:
            safe_ver = None

        impact_level = "CRITICAL" if max_cvss >= 8.5 else "HIGH" if max_cvss >= 6.0 else "MEDIUM"
        
        remediation_item = {
            "package": pkg_key,
            "current_version": current_version,
            "recommended_version": safe_ver,
            "severity": impact_level,
            "cves_resolved": cve_list,
            "cve_count": len(cve_list),
            "max_cvss": max_cvss,
            "transitive_parents": root_parents,
            "upgrade_command": (f"pip install --upgrade \"{pkg_key}>={safe_ver}\"" if safe_ver else
                                f"# no newer fixed release known for {pkg_key} {current_version}; review advisories manually"),
            "action_summary": (f"Upgrade {pkg_key} from {current_version} to >={safe_ver} (fixes {len(cve_list)} CVEs)" if safe_ver else
                               f"{pkg_key} {current_version} has {len(cve_list)} known CVEs but no newer fixed release was found; review manually")
        }
        
        remediation_actions.append(remediation_item)
        package_recommendations[pkg_key] = (f"Upgrade to >={safe_ver} (Fixes {', '.join(cve_list[:2])})" if safe_ver
                                            else f"No newer fixed release known; review {', '.join(cve_list[:2])}")
        
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