import os
import json
import subprocess
import urllib.request
import re
import pandas as pd

# Global CSV vulnerability dataset lookup cache
vulnerability_dataset_cache = {}

def load_vulnerability_dataset_cache(target_dir=None):
    global vulnerability_dataset_cache
    if vulnerability_dataset_cache:
        return
        
    paths_to_check = []
    if target_dir:
        paths_to_check.append(os.path.join(target_dir, "Supply_Chain_Risk_Dataset_v2.xlsx"))
        paths_to_check.append(os.path.join(target_dir, "dataset", "Supply_Chain_Risk_Dataset_v2.xlsx"))
    
    # Defaults
    paths_to_check.extend([
        os.path.join("test_project", "Supply_Chain_Risk_Dataset_v2.xlsx"),
        os.path.join("test_project", "dataset", "Supply_Chain_Risk_Dataset_v2.xlsx"),
        os.path.join("dataset", "Supply_Chain_Risk_Dataset_v2.xlsx"),
        "Supply_Chain_Risk_Dataset_v2.xlsx"
    ])
    
    for path in paths_to_check:
        if os.path.exists(path):
            try:
                # Read from the 'Vulnerabilities' sheet of the Excel dataset
                df_vuln = pd.read_excel(path, sheet_name="Vulnerabilities")
                for _, row in df_vuln.iterrows():
                    cve_id = str(row.get("CVE_ID", "")).strip().upper()
                    if cve_id and cve_id != "NAN":
                        # Handle potential NaN values safely
                        cvss_val = row.get("CVSS_Score", 0.0)
                        cvss_score = float(cvss_val) if pd.notna(cvss_val) else 0.0
                        
                        exp_val = row.get("Exploitability_Score", 0.0)
                        exploitability = float(exp_val) if pd.notna(exp_val) else 0.0
                        
                        pub_val = str(row.get("Published", "None"))
                        published_date = pub_val.split("T")[0] if "T" in pub_val else pub_val
                        
                        severity = str(row.get("Severity", "UNKNOWN"))
                        description = str(row.get("Description", ""))
                        
                        vulnerability_dataset_cache[cve_id] = {
                            "cvss_score": cvss_score,
                            "exploitability": exploitability,
                            "published_date": published_date,
                            "severity": severity,
                            "description": description
                        }
                print(f"Successfully loaded vulnerability dataset from Excel: {path}")
                break
            except Exception as e:
                print(f"Warning: Failed to load Excel dataset {path} due to: {e}")
                pass

def query_osv_vulnerabilities(package_name, version):
    """
    Queries OSV.dev API for package vulnerabilities.
    """
    url = "https://api.osv.dev/v1/query"
    body = {
        "package": {
            "name": package_name,
            "ecosystem": "PyPI"
        },
        "version": version
    }
    
    try:
        req = urllib.request.Request(
            url, 
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            res_data = json.loads(response.read().decode("utf-8"))
            vulns = res_data.get("vulns", [])
            
            parsed_vulns = []
            load_vulnerability_dataset_cache()
            
            for v in vulns:
                vuln_id = v.get("id")
                # Look for CVE aliases
                aliases = v.get("aliases", [])
                cve_id = vuln_id
                for alias in aliases:
                    if alias.startswith("CVE-"):
                        cve_id = alias
                        break
                
                # Check user dataset first
                csv_record = vulnerability_dataset_cache.get(cve_id.upper())
                
                if csv_record:
                    cvss_score = csv_record["cvss_score"]
                    published = csv_record["published_date"]
                    details = csv_record["description"]
                    cwe_list = ["CWE-Unknown"]
                    # Extract CWE from description if present
                    cwe_matches = re.findall(r"CWE-\d+", details)
                    if cwe_matches:
                        cwe_list.extend(cwe_matches)
                    cwe_list = list(set(cwe_list))
                    cvss_vector = csv_record["severity"]
                else:
                    # Parse CVSS score
                    cvss_score = 0.0
                    cvss_vector = ""
                    severities = v.get("severity", [])
                    for sev in severities:
                        if "CVSS" in sev.get("type", ""):
                            cvss_vector = sev.get("score", "")
                            # Parse score from vector or extract if direct
                            score_match = re.search(r"/([0-9.]+)(?:/|$)", cvss_vector)
                            if score_match:
                                try:
                                    cvss_score = float(score_match.group(1))
                                except ValueError:
                                    pass
                            # Or if they just put the score
                            if not cvss_score:
                                try:
                                    # Sometimes score is just the CVSS score string
                                    cvss_score = float(cvss_vector)
                                except ValueError:
                                    pass
                    
                    # Parse CWE mappings
                    cwe_list = []
                    database_specific = v.get("database_specific", {})
                    cwes = database_specific.get("cwe", []) or v.get("database_specific", {}).get("cwes", [])
                    if isinstance(cwes, list):
                        cwe_list = [c for c in cwes if isinstance(c, str)]
                    elif isinstance(cwes, str):
                        cwe_list = [cwes]
                    
                    # Check description/details for CWEs
                    details = v.get("details", "") + " " + v.get("summary", "")
                    cwe_matches = re.findall(r"CWE-\d+", details)
                    if cwe_matches:
                        cwe_list.extend(cwe_matches)
                    cwe_list = list(set(cwe_list))
                    published = v.get("published")
                
                parsed_vulns.append({
                    "id": vuln_id,
                    "cve_id": cve_id,
                    "summary": v.get("summary", "No summary provided"),
                    "cvss_score": cvss_score or 5.0, # Default medium risk if not specified
                    "cvss_vector": cvss_vector,
                    "cwes": cwe_list if cwe_list else ["CWE-Unknown"],
                    "published": v.get("published"),
                    "details": v.get("details", "")
                })
            return parsed_vulns
    except Exception as e:
        print(f"Error querying OSV for {package_name}@{version}: {e}")
        return []

def run_dependency_scan(project_path, resolved_packages=None):
    """
    Scans the dependency list for vulnerabilities using pip-audit and OSV.dev APIs.
    """
    print("\nRunning Dependency Vulnerability Scan...")
    
    # Load vulnerability dataset cache with target project path preference
    load_vulnerability_dataset_cache(project_path)
    
    # Run pip-audit to get quick vulnerabilities
    pip_audit_vulns = {}
    requirements_file = os.path.join(project_path, "requirements.txt")
    if os.path.exists(requirements_file):
        try:
            result = subprocess.run(
                ["pip-audit", "-r", requirements_file, "-f", "json"],
                capture_output=True,
                text=True
            )
            if result.stdout:
                audit_data = json.loads(result.stdout)
                for dep in audit_data.get("dependencies", []):
                    pkg_name = dep.get("name")
                    vulns = dep.get("vulns", [])
                    if vulns:
                        pip_audit_vulns[pkg_name.lower()] = vulns
        except Exception as e:
            print(f"pip-audit warning: {e}")

    # Build/Query vulnerability data for all resolved packages
    if resolved_packages is None:
        # Import dynamically to avoid cyclic dependencies
        from sbom.generator import generate_sbom
        resolved_packages = generate_sbom(project_path)

    vulnerability_database = {}
    vulnerable_packages_count = 0
    total_vulns_count = 0
    
    for key, pkg in resolved_packages.items():
        name = pkg["name"]
        version = pkg["version"]
        
        # 1. Check OSV.dev
        osv_vulns = query_osv_vulnerabilities(name, version)
        
        # 2. Check pip-audit
        audit_vulns = pip_audit_vulns.get(key, [])
        
        # Merge vulnerabilities
        all_vulns = []
        seen_ids = set()
        
        for ov in osv_vulns:
            all_vulns.append(ov)
            seen_ids.add(ov["cve_id"].lower())
            seen_ids.add(ov["id"].lower())
            
        for av in audit_vulns:
            cve_id = av.get("id")
            if cve_id.lower() not in seen_ids:
                all_vulns.append({
                    "id": cve_id,
                    "cve_id": cve_id,
                    "summary": av.get("description", "Vulnerability found by pip-audit"),
                    "cvss_score": 7.5, # Default high if from pip-audit but not in OSV
                    "cvss_vector": "",
                    "cwes": ["CWE-Unknown"],
                    "published": None,
                    "details": av.get("description", "")
                })
                seen_ids.add(cve_id.lower())
                
        if all_vulns:
            vulnerability_database[key] = all_vulns
            vulnerable_packages_count += 1
            total_vulns_count += len(all_vulns)

    # 3. Print the Dependency Tree in the Terminal
    print("\n" + "="*50)
    print("DEPENDENCY RISK TREE (TERMINAL VISUALIZATION)")
    print("="*50)
    
    # Find root nodes (packages not depended on by any other package)
    all_deps = set()
    for key, pkg in resolved_packages.items():
        for dep in pkg["dependencies"]:
            all_deps.add(dep.lower())
            
    root_nodes = [key for key in resolved_packages.keys() if key not in all_deps]
    if not root_nodes:
        # If circular or everything is linked, just print all
        root_nodes = list(resolved_packages.keys())

    def print_tree(node_key, prefix="", is_last=True):
        pkg = resolved_packages.get(node_key)
        if not pkg:
            return
        
        name = pkg["name"]
        version = pkg["version"]
        vulns = vulnerability_database.get(node_key, [])
        
        marker = "└── " if is_last else "├── "
        node_str = f"{prefix}{marker}{name} ({version})"
        
        cve_labels = ""
        max_cvss = 0.0
        if vulns:
            cve_labels = ", ".join([v["cve_id"] for v in vulns])
            max_cvss = max(v["cvss_score"] for v in vulns)
            node_str += f" [VULNERABLE - Max CVSS: {max_cvss} - {cve_labels}]"
        else:
            node_str += " [SECURE]"
            
        try:
            print(node_str)
        except UnicodeEncodeError:
            # Fallback to pure ASCII formatting
            ascii_marker = "\\-- " if is_last else "+-- "
            # Clean up the prefix
            clean_prefix = prefix.replace("└── ", "\\-- ").replace("├── ", "+-- ").replace("│   ", "|   ")
            ascii_node_str = f"{clean_prefix}{ascii_marker}{name} ({version})"
            if vulns:
                ascii_node_str += f" [VULNERABLE - Max CVSS: {max_cvss} - {cve_labels}]"
            else:
                ascii_node_str += " [SECURE]"
            print(ascii_node_str)
        
        new_prefix = prefix + ("    " if is_last else "│   ")
        deps = pkg["dependencies"]
        for i, dep in enumerate(deps):
            dep_key = dep.lower()
            if dep_key in resolved_packages:
                print_tree(dep_key, new_prefix, i == len(deps) - 1)

    for i, root in enumerate(root_nodes):
        print_tree(root, is_last=(i == len(root_nodes)-1))
    print("="*50 + "\n")

    results = {
        "vulnerable_packages": vulnerable_packages_count,
        "total_dependency_vulnerabilities": total_vulns_count,
        "vulnerability_details": vulnerability_database
    }
    
    return results