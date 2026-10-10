import os
import json

def parse_npm_dependencies(project_path):
    """
    Parses Node.js / JavaScript dependencies from package-lock.json or package.json.
    Returns dictionary of resolved packages and dependencies.
    """
    lock_file = os.path.join(project_path, "package-lock.json")
    pkg_file = os.path.join(project_path, "package.json")
    
    resolved_packages = {}
    
    # 1. Check package-lock.json (Lockfile v2/v3 or v1)
    if os.path.exists(lock_file):
        try:
            with open(lock_file, "r", encoding="utf-8") as f:
                lock_data = json.load(f)
                
            # Lockfile v2 / v3 packages mapping
            if "packages" in lock_data:
                for pkg_path, details in lock_data["packages"].items():
                    if not pkg_path:  # root package
                        continue
                    pkg_name = pkg_path.replace("node_modules/", "").strip().lower()
                    ver = details.get("version", "1.0.0")
                    deps = list(details.get("dependencies", {}).keys())
                    resolved_packages[pkg_name] = {
                        "name": pkg_name,
                        "version": ver,
                        "license": details.get("license", "MIT"),
                        "ecosystem": "npm",
                        "dependencies": [d.lower() for d in deps]
                    }
                    
            # Lockfile v1 dependencies mapping
            elif "dependencies" in lock_data:
                for pkg_name, details in lock_data["dependencies"].items():
                    clean_name = pkg_name.strip().lower()
                    ver = details.get("version", "1.0.0")
                    deps = list(details.get("requires", {}).keys())
                    resolved_packages[clean_name] = {
                        "name": clean_name,
                        "version": ver,
                        "license": "MIT",
                        "ecosystem": "npm",
                        "dependencies": [d.lower() for d in deps]
                    }
            print(f"[NPM-PARSER] Successfully parsed {len(resolved_packages)} Node.js packages from {lock_file}")
            return resolved_packages
        except Exception as e:
            print(f"[NPM-PARSER] Warning reading package-lock.json: {e}")
            
    # 2. Fallback to package.json
    if os.path.exists(pkg_file):
        try:
            with open(pkg_file, "r", encoding="utf-8") as f:
                pkg_data = json.load(f)
                
            all_deps = {}
            all_deps.update(pkg_data.get("dependencies", {}))
            all_deps.update(pkg_data.get("devDependencies", {}))
            
            for name, ver in all_deps.items():
                clean_name = name.strip().lower()
                clean_ver = ver.replace("^", "").replace("~", "").replace(">=", "")
                resolved_packages[clean_name] = {
                    "name": clean_name,
                    "version": clean_ver,
                    "license": "MIT",
                    "ecosystem": "npm",
                    "dependencies": []
                }
            print(f"[NPM-PARSER] Parsed {len(resolved_packages)} direct npm packages from {pkg_file}")
            return resolved_packages
        except Exception as e:
            print(f"[NPM-PARSER] Warning reading package.json: {e}")
            
    return resolved_packages
