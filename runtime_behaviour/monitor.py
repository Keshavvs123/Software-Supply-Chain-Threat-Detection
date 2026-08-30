import os
import sys
import subprocess
import json
import tempfile

WRAPPER_TEMPLATE = """
import sys
import os
import builtins
import subprocess
import socket
import json

# Metrics dict
telemetry = {{
    "system_call_count": 0,
    "subprocess_count": 0,
    "shell_execution_usage": 0,
    "dynamic_execution_count": 0,
    "suspicious_network_activity": 0,
    "file_access_risk": 0,
    "packages": {{}}
}}

def get_caller_package():
    try:
        # Traverse frames up to identify caller module
        frame = sys._getframe(2)
        while frame:
            module_name = frame.f_globals.get("__name__", "")
            root_package = module_name.split(".")[0]
            if root_package and root_package not in ("__main__", "builtins", "monitor", "runpy", "os", "subprocess", "socket", "sys", "json", "importlib", "ssl"):
                return root_package
            frame = frame.f_back
    except Exception:
        pass
    return None

def log_package_telemetry(pkg_name, metric, val=1):
    if not pkg_name:
        return
    pkg_name = pkg_name.lower()
    pkg_data = telemetry["packages"].setdefault(pkg_name, {{
        "system_call_count": 0,
        "subprocess_count": 0,
        "shell_execution_usage": 0,
        "dynamic_execution_count": 0,
        "suspicious_network_activity": 0,
        "file_access_risk": 0
    }})
    pkg_data[metric] = pkg_data.get(metric, 0) + val

# 1. Patch os.system and other exec tools
orig_os_system = os.system
def patched_os_system(command):
    caller = get_caller_package()
    telemetry["system_call_count"] += 1
    telemetry["shell_execution_usage"] += 1
    log_package_telemetry(caller, "system_call_count")
    log_package_telemetry(caller, "shell_execution_usage")
    return orig_os_system(command)
os.system = patched_os_system

# 2. Patch subprocess.Popen
orig_popen = subprocess.Popen
def patched_popen(*args, **kwargs):
    caller = get_caller_package()
    telemetry["subprocess_count"] += 1
    log_package_telemetry(caller, "subprocess_count")
    shell = kwargs.get("shell", False)
    if shell:
        telemetry["shell_execution_usage"] += 1
        log_package_telemetry(caller, "shell_execution_usage")
    return orig_popen(*args, **kwargs)
subprocess.Popen = patched_popen

# 3. Patch builtins.__import__ for dynamic imports
orig_import = builtins.__import__
def patched_import(name, globals=None, locals=None, fromlist=(), level=0):
    caller = get_caller_package()
    telemetry["dynamic_execution_count"] += 1
    log_package_telemetry(caller, "dynamic_execution_count")
    return orig_import(name, globals, locals, fromlist, level)
builtins.__import__ = patched_import

# 4. Patch open for suspicious file access
orig_open = builtins.open
def patched_open(file, mode='r', *args, **kwargs):
    caller = get_caller_package()
    telemetry["system_call_count"] += 1
    log_package_telemetry(caller, "system_call_count")
    if isinstance(file, str):
        # Check if they are opening sensitive paths or system files
        lower_file = file.lower()
        risk_val = 0
        if "hosts" in lower_file or "passwd" in lower_file or "shadow" in lower_file or "system32" in lower_file or lower_file.endswith(".exe") or lower_file.endswith(".bat") or lower_file.endswith(".sh"):
            risk_val += 2
        if 'w' in mode or 'a' in mode:
            risk_val += 1
        if risk_val > 0:
            telemetry["file_access_risk"] += risk_val
            log_package_telemetry(caller, "file_access_risk", risk_val)
    return orig_open(file, mode, *args, **kwargs)
builtins.open = patched_open

# 5. Patch socket.socket.connect for network activity
orig_connect = socket.socket.connect
def patched_connect(self, address):
    caller = get_caller_package()
    telemetry["suspicious_network_activity"] += 1
    log_package_telemetry(caller, "suspicious_network_activity")
    return orig_connect(self, address)
socket.socket.connect = patched_connect

# Patch eval/exec (via builtins)
orig_eval = builtins.eval
def patched_eval(expression, globals=None, locals=None):
    caller = get_caller_package()
    telemetry["dynamic_execution_count"] += 1
    log_package_telemetry(caller, "dynamic_execution_count")
    return orig_eval(expression, globals, locals)
builtins.eval = patched_eval

orig_exec = builtins.exec
def patched_exec(object, globals=None, locals=None):
    caller = get_caller_package()
    telemetry["dynamic_execution_count"] += 1
    log_package_telemetry(caller, "dynamic_execution_count")
    return orig_exec(object, globals, locals)
builtins.exec = patched_exec

# Load and run the target script
target_script = {target_script_repr}
sys.argv = [target_script]

# Dynamically import packages to trigger initialization telemetry under the sandbox
import_errors = []
for pkg_name in {package_names_repr}:
    try:
        import importlib
        importlib.import_module(pkg_name.replace("-", "_").lower())
    except Exception as e:
        import_errors.append(f"Error importing {{pkg_name}}: {{e}}")

if import_errors:
    try:
        with open("outputs/import_errors.log", "w", encoding="utf-8") as err_f:
            err_f.write("\n".join(import_errors))
    except Exception:
        pass

# Redirect input so it does not block
sys.stdin = open(os.devnull, 'r')

try:
    import runpy
    runpy.run_path(target_script, run_name="__main__")
except Exception as e:
    # We capture execution errors, but we want the telemetry
    pass

# Write telemetry to output file
with open({output_file_repr}, "w", encoding="utf-8") as f:
    json.dump(telemetry, f, indent=2)
"""

def monitor_runtime(script_path, package_names=None, timeout=5):
    """
    Runs the target Python script in a monitored environment using monkeypatching
    to capture runtime features. Returns RuntimeFeatures dictionary.
    """
    print(f"\nMonitoring Runtime Behaviour of: {script_path}...")
    
    os.makedirs("outputs", exist_ok=True)
    telemetry_file = os.path.abspath(os.path.join("outputs", "runtime_telemetry.json"))
    
    # Write the monitoring script wrapper
    fd, wrapper_path = tempfile.mkstemp(suffix=".py", text=True)
    os.close(fd)
    
    try:
        monitoring_code = WRAPPER_TEMPLATE.format(
            target_script_repr=repr(os.path.abspath(script_path)),
            output_file_repr=repr(telemetry_file),
            package_names_repr=repr(package_names or [])
        )
        
        with open(wrapper_path, "w", encoding="utf-8") as f:
            f.write(monitoring_code)
        
        # Run wrapper script
        # We pass a timeout to avoid hangs (e.g. from infinite loops or stdin reads)
        try:
            subprocess.run(
                [sys.executable, wrapper_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout
            )
        except subprocess.TimeoutExpired:
            print("Runtime monitoring script execution timed out (graceful recovery).")
            
        # Parse the output
        if os.path.exists(telemetry_file):
            with open(telemetry_file, "r") as f:
                runtime_features = json.load(f)
                
            def calc_weighted_risk(stats_dict):
                p = float(stats_dict.get("subprocess_count", 0))
                n = float(stats_dict.get("suspicious_network_activity", 0))
                f = float(stats_dict.get("file_access_risk", 0))
                e = float(stats_dict.get("dynamic_execution_count", 0))
                return 0.4 * p + 0.3 * n + 0.2 * f + 0.1 * e

            runtime_features["behavioral_risk"] = calc_weighted_risk(runtime_features)
            for pkg, pkg_stats in runtime_features.get("packages", {}).items():
                pkg_stats["behavioral_risk"] = calc_weighted_risk(pkg_stats)

            print(f"Runtime telemetry successfully captured and saved to: outputs/runtime_telemetry.json")
            pkg_count = len(runtime_features.get("packages", {}))
            print(f" - Captured System Calls: {runtime_features.get('system_call_count', 0)}")
            print(f" - Captured Subprocesses: {runtime_features.get('subprocess_count', 0)}")
            print(f" - Active Monitored Packages: {pkg_count}")
            return runtime_features
            
    except Exception as e:
        print(f"Error during runtime monitoring: {e}")
    finally:
        if os.path.exists(wrapper_path):
            os.remove(wrapper_path)
            
    # Fallback to defaults
    fallback = {
        "system_call_count": 0,
        "subprocess_count": 0,
        "shell_execution_usage": 0,
        "dynamic_execution_count": 0,
        "suspicious_network_activity": 0,
        "file_access_risk": 0
    }
    print("Using default fallback runtime features.")
    return fallback
