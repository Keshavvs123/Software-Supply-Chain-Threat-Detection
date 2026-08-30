import os
import ast
import json
import subprocess
import re

class PyASTSecurityVisitor(ast.NodeVisitor):
    def __init__(self):
        self.stats = {
            "command_execution_usage": 0,
            "insecure_deserialization": 0,
            "hardcoded_secrets": 0,
            "weak_cryptography": 0,
            "eval_exec_usage": 0,
            "insecure_permissions": 0,
            "taint_flow_risk": 0
        }
        self.ast_nodes_count = 0
        self.dynamic_imports_count = 0
        self.secrets_pattern = re.compile(
            r"(password|passwd|api_key|apikey|secret|token|private_key|auth_token)", 
            re.IGNORECASE
        )
        self.taint_sources = set()

    def visit_Assign(self, node):
        # Detect potential hardcoded secrets
        for target in node.targets:
            if isinstance(target, ast.Name):
                name = target.id
                if self.secrets_pattern.search(name):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        self.stats["hardcoded_secrets"] += 1
                    elif isinstance(node.value, ast.Str):  # for compatibility with older Python
                        self.stats["hardcoded_secrets"] += 1
                
                # Simple taint-style variable flow helper
                # Track user inputs
                if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name):
                    if node.value.func.id == "input":
                        self.taint_sources.add(name)
        self.generic_visit(node)

    def visit_Call(self, node):
        func_name = ""
        # Get function name
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            # Reconstruct full name if possible (e.g. os.system)
            if isinstance(node.func.value, ast.Name):
                func_name = f"{node.func.value.id}.{func_name}"

        # 1. Command injection / shell execution
        if func_name in ("os.system", "subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output"):
            self.stats["command_execution_usage"] += 1
            # Check for shell=True or direct os.system usage
            is_shell_true = False
            for kw in node.keywords:
                if kw.arg == "shell":
                    if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        is_shell_true = True
                    elif isinstance(kw.value, ast.NameConstant) and kw.value.value is True:
                        is_shell_true = True
            
            if func_name == "os.system" or is_shell_true:
                self.stats["taint_flow_risk"] += 1

            # Simple Taint Flow check: check if any arg comes from input variable
            for arg in node.args:
                if isinstance(arg, ast.Name) and arg.id in self.taint_sources:
                    self.stats["taint_flow_risk"] += 2

        # 2. Insecure deserialization
        if func_name in ("pickle.loads", "pickle.load", "yaml.load"):
            self.stats["insecure_deserialization"] += 1
            # Check if Loader is unsafe in yaml.load
            if func_name == "yaml.load":
                has_safe_loader = False
                for kw in node.keywords:
                    if kw.arg == "Loader":
                        if isinstance(kw.value, ast.Attribute) and kw.value.attr == "SafeLoader":
                            has_safe_loader = True
                if not has_safe_loader:
                    self.stats["taint_flow_risk"] += 1

        # 3. Weak cryptography
        if func_name in ("hashlib.md5", "hashlib.sha1"):
            self.stats["weak_cryptography"] += 1

        # 4. eval / exec
        if func_name in ("eval", "exec"):
            self.stats["eval_exec_usage"] += 1
            # Check if any arg comes from input
            for arg in node.args:
                if isinstance(arg, ast.Name) and arg.id in self.taint_sources:
                    self.stats["taint_flow_risk"] += 2

        # 5. Insecure temporary file
        if func_name == "tempfile.mktemp":
            self.stats["insecure_permissions"] += 1

        # 6. Insecure permissions (chmod)
        if func_name == "os.chmod":
            self.stats["insecure_permissions"] += 1
            if len(node.args) >= 2:
                mode_arg = node.args[1]
                if isinstance(mode_arg, ast.Constant):
                    val = mode_arg.value
                    if isinstance(val, int) and (val & 0o007) > 0: # World writable/readable/executable
                        self.stats["taint_flow_risk"] += 1

        self.generic_visit(node)

    def visit_Attribute(self, node):
        if node.attr in ("import_module", "importlib", "getattr"):
            self.dynamic_imports_count += 1
        self.generic_visit(node)

    def generic_visit(self, node):
        self.ast_nodes_count += 1
        super().generic_visit(node)


import math
import collections

def calculate_shannon_entropy(text):
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    counts = collections.Counter(text)
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def calculate_encoded_string_ratio(text):
    if not text:
        return 0.0
    total_len = len(text)
    if total_len == 0:
        return 0.0
    
    hex_escapes = len(re.findall(r'\\x[0-9a-fA-F]{2}', text)) * 4
    base64_strings = sum(len(x) for x in re.findall(r'[A-Za-z0-9+/]{12,}={0,2}', text))
    
    encoded_len = hex_escapes + base64_strings
    return min(encoded_len / total_len, 1.0)

def run_ast_scan(dir_path):
    visitor = PyASTSecurityVisitor()
    py_files_count = 0
    total_entropy = 0.0
    total_encoded_ratio = 0.0
    
    for root, _, files in os.walk(dir_path):
        if "venv" in root or ".git" in root or "__pycache__" in root:
            continue
        for file in files:
            if file.endswith(".py"):
                py_files_count += 1
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        tree = ast.parse(content, filename=file_path)
                    visitor.visit(tree)
                    total_entropy += calculate_shannon_entropy(content)
                    total_encoded_ratio += calculate_encoded_string_ratio(content)
                except Exception:
                    pass
                    
    avg_entropy = (total_entropy / py_files_count) if py_files_count > 0 else 0.0
    avg_encoded_ratio = (total_encoded_ratio / py_files_count) if py_files_count > 0 else 0.0
    
    res_stats = visitor.stats.copy()
    res_stats["shannon_entropy"] = avg_entropy
    res_stats["encoded_string_ratio"] = avg_encoded_ratio
    res_stats["ast_complexity"] = visitor.ast_nodes_count
    res_stats["dynamic_imports"] = visitor.dynamic_imports_count
    
    return res_stats, py_files_count

def run_bandit_scan(dir_path):
    import tempfile
    fd, temp_json = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        subprocess.run(
            ["bandit", "-r", dir_path, "-f", "json", "-o", temp_json],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        if os.path.exists(temp_json):
            with open(temp_json, "r") as f:
                data = json.load(f)
            issues = data.get("results", [])
            high = sum(1 for i in issues if i.get("issue_severity") == "HIGH")
            medium = sum(1 for i in issues if i.get("issue_severity") == "MEDIUM")
            low = sum(1 for i in issues if i.get("issue_severity") == "LOW")
            return len(issues), high, medium, low
    except Exception:
        pass
    finally:
        if os.path.exists(temp_json):
            os.remove(temp_json)
    return 0, 0, 0, 0

def run_static_analysis(project_path, resolved_packages=None):
    print(f"\nRunning Static Analysis on: {project_path}...\n")
    os.makedirs("outputs", exist_ok=True)
    
    EXCLUDE_HEAVY_PACKAGES = {
        'numpy', 'pandas', 'matplotlib', 'pyarrow', 'scipy', 'notebook', 
        'ipykernel', 'pytest', 'pytest-cov', 'setuptools', 'packaging', 
        'colorama', 'psutil', 'pywin32', 'nest-asyncio'
    }
    
    import importlib.util
    import shutil
    
    # 1. Create a clean scan temp staging directory inside outputs
    scan_temp_dir = os.path.abspath(os.path.join("outputs", "scan_temp"))
    if os.path.exists(scan_temp_dir):
        shutil.rmtree(scan_temp_dir, ignore_errors=True)
    os.makedirs(scan_temp_dir, exist_ok=True)
    
    # Copy project files to scan_temp_dir/first_party
    first_party_dest = os.path.join(scan_temp_dir, "first_party")
    os.makedirs(first_party_dest, exist_ok=True)
    
    for item in os.listdir(project_path):
        s = os.path.join(project_path, item)
        d = os.path.join(first_party_dest, item)
        if os.path.isdir(s):
            if "venv" not in item and ".git" not in item and "__pycache__" not in item and "outputs" not in item:
                try:
                    shutil.copytree(s, d, dirs_exist_ok=True)
                except Exception:
                    pass
        else:
            if item.endswith(".py") or item == "requirements.txt":
                try:
                    shutil.copy2(s, d)
                except Exception:
                    pass

    # Copy or download package source directories to scan_temp_dir/packages/{pkg_name}
    import shutil
    import importlib.util
    import tarfile
    import zipfile
    
    package_paths_map = {} # pkg_dest_lower -> pkg_name_lower
    if resolved_packages:
        for pkg_key, pkg_info in resolved_packages.items():
            pkg_name = pkg_info["name"]
            if pkg_name.lower() in EXCLUDE_HEAVY_PACKAGES:
                continue
            try:
                spec = importlib.util.find_spec(pkg_name.replace("-", "_").lower())
                pkg_path = None
                if spec and spec.submodule_search_locations:
                    pkg_path = spec.submodule_search_locations[0]
                
                pkg_dest = os.path.join(scan_temp_dir, "packages", pkg_name.lower())
                
                # Check if package is installed locally
                if pkg_path and os.path.exists(pkg_path):
                    shutil.copytree(pkg_path, pkg_dest, dirs_exist_ok=True, ignore=shutil.ignore_patterns('*.pyc', '__pycache__', '*.png', '*.jpg', '*.pdf'))
                    package_paths_map[pkg_dest.lower()] = pkg_name.lower()
                    print(f"Copied package {pkg_name} to scan staging: {pkg_dest}")
                else:
                    # Not found locally: Download and extract for pre-install scan!
                    print(f"Package {pkg_name} not found locally. Downloading from PyPI for pre-install scan...")
                    temp_dl = os.path.join(scan_temp_dir, "downloads", pkg_name.lower())
                    os.makedirs(temp_dl, exist_ok=True)
                    
                    version_spec = f"{pkg_name}=={pkg_info['version']}" if pkg_info.get("version") and pkg_info["version"] != "Unknown" else pkg_name
                    import sys
                    subprocess.run(
                        [sys.executable, "-m", "pip", "download", "--no-deps", "-d", temp_dl, version_spec],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                    )
                    
                    # Search and extract archive
                    extracted = False
                    for file in os.listdir(temp_dl):
                        file_path = os.path.join(temp_dl, file)
                        if file.endswith(".tar.gz") or file.endswith(".tgz"):
                            with tarfile.open(file_path, "r:gz") as tar:
                                tar.extractall(path=pkg_dest)
                            extracted = True
                            break
                        elif file.endswith(".whl") or file.endswith(".zip"):
                            with zipfile.ZipFile(file_path, "r") as zip_ref:
                                zip_ref.extractall(path=pkg_dest)
                            extracted = True
                            break
                            
                    if extracted:
                        package_paths_map[pkg_dest.lower()] = pkg_name.lower()
                        print(f"Downloaded and extracted {pkg_name} archive to scan staging: {pkg_dest}")
                    else:
                        print(f"Warning: Could not download/extract PyPI archive for {pkg_name}")
                        
            except Exception as e:
                print(f"Error staging package {pkg_name} for scan: {e}")

    # Helper function to find which package path a file belongs to
    def find_associated_package(file_path):
        if not file_path:
            return None
        file_path_lower = os.path.realpath(file_path).lower()
        for pkg_path, pkg_name in package_paths_map.items():
            if file_path_lower.startswith(pkg_path + os.sep) or file_path_lower == pkg_path:
                return pkg_name
        return None

    # Helper function to restore original path string in JSON files
    def restore_path(temp_path):
        if not temp_path:
            return temp_path
        temp_path_lower = os.path.realpath(temp_path).lower()
        for pkg_dest_lower, pkg_name in package_paths_map.items():
            if temp_path_lower.startswith(pkg_dest_lower + os.sep) or temp_path_lower == pkg_dest_lower:
                try:
                    spec = importlib.util.find_spec(pkg_name.replace("-", "_").lower())
                    if spec and spec.submodule_search_locations:
                        orig_path = os.path.realpath(spec.submodule_search_locations[0])
                        rel_path = os.path.relpath(temp_path, pkg_dest_lower)
                        return os.path.join(orig_path, rel_path)
                except Exception:
                    pass
        first_party_prefix = os.path.join(scan_temp_dir, "first_party").lower()
        if temp_path_lower.startswith(first_party_prefix + os.sep) or temp_path_lower == first_party_prefix:
            rel_path = os.path.relpath(temp_path, first_party_prefix)
            return os.path.join(project_path, rel_path)
        return temp_path

    # Initialize stats for each scanned package
    packages_stats = {}
    for pkg_name in package_paths_map.values():
        packages_stats[pkg_name] = {
            "bandit_issue_count": 0,
            "semgrep_issue_count": 0,
            "critical_findings": 0,
            "command_execution_usage": 0,
            "insecure_deserialization": 0,
            "hardcoded_secrets": 0,
            "weak_cryptography": 0,
            "eval_exec_usage": 0,
            "insecure_permissions": 0,
            "taint_flow_risk": 0,
            "shannon_entropy": 0.0,
            "encoded_string_ratio": 0.0,
            "ast_complexity": 0,
            "dynamic_imports": 0
        }

    # 1. AST scan on first_party project path
    ast_stats, py_files_count = run_ast_scan(first_party_dest)
    
    # Run AST scan on copied package paths
    for pkg_dest_path, pkg_name in package_paths_map.items():
        p_ast, p_files = run_ast_scan(pkg_dest_path)
        stats = packages_stats[pkg_name]
        stats["command_execution_usage"] = p_ast["command_execution_usage"]
        stats["insecure_deserialization"] = p_ast["insecure_deserialization"]
        stats["hardcoded_secrets"] = p_ast["hardcoded_secrets"]
        stats["weak_cryptography"] = p_ast["weak_cryptography"]
        stats["eval_exec_usage"] = p_ast["eval_exec_usage"]
        stats["insecure_permissions"] = p_ast["insecure_permissions"]
        stats["taint_flow_risk"] = p_ast["taint_flow_risk"]
        stats["shannon_entropy"] = p_ast.get("shannon_entropy", 0.0)
        stats["encoded_string_ratio"] = p_ast.get("encoded_string_ratio", 0.0)
        stats["ast_complexity"] = p_ast.get("ast_complexity", 0)
        stats["dynamic_imports"] = p_ast.get("dynamic_imports", 0)

    # 2. Bandit scan (and write to outputs/bandit.json)
    bandit_issue_count = 0
    bandit_high = 0
    bandit_medium = 0
    bandit_low = 0
    cwe_freq = {}
    
    bandit_output = os.path.join("outputs", "bandit.json")
    try:
        # Run bandit on all scan paths staging folder
        cmd = ["bandit", "-r", scan_temp_dir, "-f", "json", "-o", bandit_output]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if os.path.exists(bandit_output):
            with open(bandit_output, "r", encoding="utf-8") as f:
                data = json.load(f)
            issues = data.get("results", [])
            for issue in issues:
                file_path = issue.get("filename", "")
                sev = issue.get("issue_severity", "LOW")
                associated_pkg = find_associated_package(file_path)
                
                if associated_pkg:
                    stats = packages_stats[associated_pkg]
                    stats["bandit_issue_count"] += 1
                    if sev == "HIGH":
                        stats["critical_findings"] += 1
                else:
                    bandit_issue_count += 1
                    if sev == "HIGH":
                        bandit_high += 1
                    elif sev == "MEDIUM":
                        bandit_medium += 1
                    else:
                        bandit_low += 1
                    
                    cwe_meta = issue.get("ref", "")
                    cwe_match = re.search(r"CWE-\d+", cwe_meta)
                    cwe_id = cwe_match.group(0) if cwe_match else "CWE-Unknown"
                    cwe_freq[cwe_id] = cwe_freq.get(cwe_id, 0) + 1
            
            # Restore paths inside bandit.json
            for issue in issues:
                issue["filename"] = restore_path(issue.get("filename", ""))
            with open(bandit_output, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
    except Exception as e:
        print(f"Bandit execution warning/error: {e}")

    # 3. Semgrep scan (and write to outputs/semgrep.json)
    semgrep_issue_count = 0
    semgrep_output = os.path.join("outputs", "semgrep.json")
    try:
        cmd = ["semgrep", "--config=auto", "--json", "--no-git-ignore", scan_temp_dir, "-o", semgrep_output]
        # Inject PYTHONUTF8 environment variable to prevent Cp1252 charmap encode crashes on Windows
        env_vars = os.environ.copy()
        env_vars["PYTHONUTF8"] = "1"
        subprocess.run(cmd, env=env_vars, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if os.path.exists(semgrep_output):
            with open(semgrep_output, "r", encoding="utf-8") as f:
                data = json.load(f)
            results = data.get("results", [])
            for r in results:
                file_path = r.get("path", "")
                associated_pkg = find_associated_package(file_path)
                
                if associated_pkg:
                    stats = packages_stats[associated_pkg]
                    stats["semgrep_issue_count"] += 1
                else:
                    semgrep_issue_count += 1
                    metadata = r.get("extra", {}).get("metadata", {})
                    cwes = metadata.get("cwe", [])
                    if isinstance(cwes, list):
                        for c in cwes:
                            c_match = re.search(r"CWE-\d+", c)
                            if c_match:
                                cwe_freq[c_match.group(0)] = cwe_freq.get(c_match.group(0), 0) + 1
                    elif isinstance(cwes, str):
                        c_match = re.search(r"CWE-\d+", cwes)
                        if c_match:
                            cwe_freq[c_match.group(0)] = cwe_freq.get(c_match.group(0), 0) + 1
            
            # Restore paths inside semgrep.json
            for r in results:
                r["path"] = restore_path(r.get("path", ""))
            with open(semgrep_output, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
    except Exception as e:
        print(f"Semgrep execution warning/error: {e}")

    # Clean up the staging dir
    if os.path.exists(scan_temp_dir):
        shutil.rmtree(scan_temp_dir, ignore_errors=True)

    critical_findings = bandit_high + sum(
        1 for k, v in ast_stats.items() if k in ["command_execution_usage", "insecure_deserialization"] and v > 0
    )
    issue_density = (bandit_issue_count + semgrep_issue_count) / max(py_files_count, 1)

    # Compute critical findings for packages
    for pkg_name, stats in packages_stats.items():
        p_ast_crit = sum(1 for k, v in stats.items() if k in ["command_execution_usage", "insecure_deserialization"] and v > 0)
        stats["critical_findings"] += p_ast_crit
        print(f"Scanned package source: {pkg_name} | Bandit issues: {stats['bandit_issue_count']} | Semgrep issues: {stats['semgrep_issue_count']} | AST issues: {stats['command_execution_usage'] + stats['insecure_deserialization'] + stats['hardcoded_secrets']}")

    project_static_features = {
        "bandit_issue_count": bandit_issue_count,
        "semgrep_issue_count": semgrep_issue_count,
        "critical_findings": critical_findings,
        "command_execution_usage": ast_stats["command_execution_usage"],
        "insecure_deserialization": ast_stats["insecure_deserialization"],
        "hardcoded_secrets": ast_stats["hardcoded_secrets"],
        "weak_cryptography": ast_stats["weak_cryptography"],
        "eval_exec_usage": ast_stats["eval_exec_usage"],
        "insecure_permissions": ast_stats["insecure_permissions"],
        "taint_flow_risk": ast_stats["taint_flow_risk"],
        "shannon_entropy": ast_stats.get("shannon_entropy", 0.0),
        "encoded_string_ratio": ast_stats.get("encoded_string_ratio", 0.0),
        "ast_complexity": ast_stats.get("ast_complexity", 0),
        "dynamic_imports": ast_stats.get("dynamic_imports", 0),
        "issue_density": issue_density,
        "CWE_frequency": cwe_freq,
        "bandit_high": bandit_high,
        "bandit_medium": bandit_medium,
        "bandit_low": bandit_low,
        "packages": packages_stats
    }

    print("Static Analysis Features Generated successfully.")
    return project_static_features