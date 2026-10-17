import os
import sys
import json
import subprocess
import importlib.metadata
import urllib.request
import hashlib
import re
from packaging.requirements import Requirement

def clean_dependency_name(dep_str):
    """
    Cleans requirement string removing environment markers, extras [toml], and version operators.
    E.g. "coverage[toml] (>=7.10.6); os_name == 'nt'" -> "coverage"
    """
    if not dep_str:
        return ""
    # Remove markers after semicolon
    dep = dep_str.split(";")[0].strip()
    # Remove comments
    dep = dep.split("#")[0].strip()
    # Remove parentheses
    dep = dep.split("(")[0].strip()
    # Remove extras [...]
    dep = re.sub(r'\[.*?\]', '', dep).strip()
    # Remove version operators <, >, =, !, ~, ^ and anything after
    dep = re.sub(r'[<>=!~^].*$', '', dep).strip()
    # Split by whitespace to take first token
    dep = dep.split()[0] if dep.split() else ""
    return dep.strip().lower()

def get_package_hashes(pkg_name, version):
    """
    Fetch package hashes (SHA256) from PyPI API.
    """
    try:
        url = f"https://pypi.org/pypi/{pkg_name}/{version}/json"
        with urllib.request.urlopen(url, timeout=3) as response:
            data = json.loads(response.read().decode())
            urls = data.get("urls", [])
            hashes = []
            for u in urls:
                if "digests" in u and "sha256" in u["digests"]:
                    hashes.append({
                        "alg": "SHA-256",
                        "content": u["digests"]["sha256"]
                    })
            return hashes
    except Exception:
        return []

def get_installed_packages():
    """
    Use importlib.metadata to get all installed packages and their details.
    """
    packages = {}
    dists = importlib.metadata.distributions()
    for dist in dists:
        name = dist.metadata["Name"]
        version = dist.metadata["Version"]
        license_info = dist.metadata.get("License", "Unknown")
        maintainer = dist.metadata.get("Maintainer", dist.metadata.get("Author", "Unknown"))
        
        # Extract requires (dependencies)
        requires = dist.requires or []
        deps = []
        for req in requires:
            dep_name = clean_dependency_name(req)
            if dep_name and dep_name != name.lower() and dep_name not in deps:
                deps.append(dep_name)
                
        packages[name.lower()] = {
            "name": name,
            "version": version,
            "license": license_info,
            "maintainer": maintainer,
            "dependencies": deps
        }
    return packages

_pypi_cache = {}

def get_pypi_metadata(pkg_name, requested_version=None):
    """
    Query PyPI JSON API and local archives for non-local (uninstalled) packages to resolve
    their real version, license, maintainer, and requires_dist dependencies.
    """
    clean_name = pkg_name.strip().lower()
    cache_key = f"{clean_name}::{requested_version or ''}"
    if cache_key in _pypi_cache:
        return _pypi_cache[cache_key]
    
    # 1. Try PyPI JSON API
    try:
        if requested_version and requested_version.lower() != "unknown":
            url = f"https://pypi.org/pypi/{clean_name}/{requested_version}/json"
        else:
            url = f"https://pypi.org/pypi/{clean_name}/json"
            
        req = urllib.request.Request(url, headers={"User-Agent": "SupplyChainThreatScanner/2.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            info = data.get("info", {})
            real_ver = info.get("version") or (requested_version if requested_version else "1.0.0")
            license_val = info.get("license") or "Open Source"
            # Trim long license text if it's the entire license file
            if len(license_val) > 40 or "\n" in license_val:
                license_val = "Open Source / Specified in Package"
            author = info.get("author") or info.get("maintainer") or "PyPI Community"
            
            raw_reqs = info.get("requires_dist") or []
            deps = []
            for r in raw_reqs:
                dep_pkg = clean_dependency_name(r)
                if dep_pkg and dep_pkg != clean_name and dep_pkg not in deps:
                    deps.append(dep_pkg)
                    
            res = {
                "name": clean_name,
                "version": real_ver,
                "license": license_val,
                "maintainer": author,
                "dependencies": deps
            }
            _pypi_cache[cache_key] = res
            return res
    except Exception:
        pass
        
    # 2. Fallback: inspect downloaded wheel in outputs/scan_temp
    try:
        import glob
        from email import message_from_string
        meta_candidates = glob.glob(f"outputs/scan_temp/packages/{clean_name}*/*.dist-info/METADATA") + \
                          glob.glob(f"outputs/scan_temp/packages/{clean_name}*/PKG-INFO")
        if meta_candidates:
            with open(meta_candidates[0], "r", encoding="utf-8", errors="ignore") as mf:
                msg = message_from_string(mf.read())
                v = msg.get("Version") or requested_version or "1.0.0"
                lic = msg.get("License") or "Open Source"
                maint = msg.get("Author") or msg.get("Maintainer") or "PyPI Author"
                req_dists = msg.get_all("Requires-Dist", [])
                deps = []
                for r in req_dists:
                    dep_pkg = clean_dependency_name(r)
                    if dep_pkg and dep_pkg != clean_name and dep_pkg not in deps:
                        deps.append(dep_pkg)
                res = {
                    "name": clean_name,
                    "version": v,
                    "license": lic,
                    "maintainer": maint,
                    "dependencies": deps
                }
                _pypi_cache[cache_key] = res
                return res
    except Exception:
        pass
        
    res = {
        "name": clean_name,
        "version": requested_version if requested_version else "1.0.0",
        "license": "Open Source",
        "maintainer": "PyPI Contributor",
        "dependencies": []
    }
    _pypi_cache[cache_key] = res
    return res

def generate_sbom(project_path):
    print("\nGenerating SBOM (CycloneDX and SPDX)...")
    os.makedirs("outputs", exist_ok=True)
    
    # 1. Identify dependencies from requirements.txt or pipdeptree
    requirements_file = os.path.join(project_path, "requirements.txt")
    if not os.path.exists(requirements_file):
        for candidate in [os.path.join("outputs", "last_requirements.txt"), os.path.join("outputs", "scan_temp", "requirements.txt")]:
            if os.path.exists(candidate):
                requirements_file = candidate
                break
    direct_deps = {}
    if os.path.exists(requirements_file):
        with open(requirements_file, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    req_ver = None
                    if "==" in line:
                        parts = line.split("==")
                        pkg = clean_dependency_name(parts[0])
                        req_ver = parts[1].split(";")[0].strip()
                    else:
                        pkg = clean_dependency_name(line)
                    if pkg:
                        direct_deps[pkg] = req_ver
    
    if not direct_deps:
        # Fallback: parse pipdeptree output
        try:
            result = subprocess.run(
                ["pipdeptree", "--json-tree"],
                capture_output=True,
                text=True,
                check=True
            )
            tree_data = json.loads(result.stdout)
            for item in tree_data:
                direct_deps[item["package_name"].lower()] = None
        except Exception:
            pass

    installed = get_installed_packages()
    
    # Resolve dependencies
    dependency_queue = list(direct_deps.keys())
    resolved_packages = {}
    visited = set()
    
    while dependency_queue:
        pkg_key = dependency_queue.pop(0).lower()
        if pkg_key in visited:
            continue
        visited.add(pkg_key)
        
        pkg_info = installed.get(pkg_key)
        if pkg_info:
            resolved_packages[pkg_key] = pkg_info
            for dep in pkg_info["dependencies"]:
                dep_key = dep.lower()
                if dep_key not in visited and dep_key in installed:
                    dependency_queue.append(dep_key)
        else:
            # Not installed locally: resolve from PyPI manifest / wheel archive!
            req_version = direct_deps.get(pkg_key)
            non_local_info = get_pypi_metadata(pkg_key, req_version)
            resolved_packages[pkg_key] = non_local_info
            # For dependencies of non-local packages:
            # If installed on disk, queue them to expand the tree!
            for dep in non_local_info["dependencies"]:
                dep_key = dep.lower()
                if dep_key not in visited:
                    if dep_key in installed:
                        dependency_queue.append(dep_key)
                    elif len(resolved_packages) < 15:
                        # Light resolution for uninstalled direct dependencies
                        resolved_packages[dep_key] = get_pypi_metadata(dep_key)

    # Generate CycloneDX JSON SBOM structure
    cyclonedx = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": "urn:uuid:68e894ba-e35f-4a5f-97cb-251f084ba6f8",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "Python Supply Chain Analyser Target",
                "version": "1.0.0"
            }
        },
        "components": []
    }
    
    for key, pkg in resolved_packages.items():
        hashes = get_package_hashes(pkg["name"], pkg["version"])
        component = {
            "type": "library",
            "name": pkg["name"],
            "version": pkg["version"],
            "purl": f"pkg:pypi/{pkg['name']}@{pkg['version']}",
            "hashes": hashes,
            "licenses": [{"license": {"name": pkg["license"]}}],
            "properties": [
                {"name": "maintainer", "value": pkg["maintainer"]}
            ]
        }
        cyclonedx["components"].append(component)
        
    sbom_json_path = os.path.join("outputs", "sbom.json")
    with open(sbom_json_path, "w", encoding="utf-8") as f:
        json.dump(cyclonedx, f, indent=2)
        
    # Generate SPDX SBOM structure
    spdx_lines = [
        "SPDXVersion: SPDX-2.2",
        "DataLicense: CC0-1.0",
        "SPDXID: SPDXRef-DOCUMENT",
        "DocumentName: Python Supply Chain Analysis Target",
        "DocumentNamespace: http://spdx.org/spdxdocs/python-supply-chain-analysis-document",
        "Creator: Tool: AI Software Supply Chain Threat Detector",
        "Created: 2026-06-11T12:00:00Z",
        ""
    ]
    
    for key, pkg in resolved_packages.items():
        spdx_ref = f"SPDXRef-Package-{pkg['name']}"
        spdx_lines.extend([
            f"PackageName: {pkg['name']}",
            f"SPDXID: {spdx_ref}",
            f"PackageVersion: {pkg['version']}",
            f"PackageDownloadLocation: NOASSERTION",
            f"FilesAnalyzed: false",
            f"PackageLicenseConcluded: {pkg['license']}",
            f"PackageLicenseDeclared: {pkg['license']}",
            f"PackageCopyrightText: NOASSERTION",
            f"PackageSummary: Python library dependencies.",
            ""
        ])
        # Add relationships
        for dep in pkg["dependencies"]:
            dep_key = dep.lower()
            if dep_key in resolved_packages:
                spdx_lines.append(f"Relationship: {spdx_ref} DEPENDS_ON SPDXRef-Package-{resolved_packages[dep_key]['name']}")
        spdx_lines.append("")
        
    sbom_spdx_path = os.path.join("outputs", "sbom.spdx")
    with open(sbom_spdx_path, "w", encoding="utf-8") as f:
        f.write("\n".join(spdx_lines))
        
    print(f"SBOMs generated: {sbom_json_path} and {sbom_spdx_path}")
    return resolved_packages
