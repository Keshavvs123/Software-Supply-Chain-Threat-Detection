import os
import sys

# Force standard output line buffering to flush logs instantly on Windows terminal
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(line_buffering=True)

# Ensure project root is in the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from static_analysis.analyzer import run_static_analysis
from sbom.generator import generate_sbom
from dependency_analysis.dependency_scanner import run_dependency_scan
from runtime_behaviour.monitor import monitor_runtime
from data_pipeline.enricher import verify_and_enrich_package, record_vulnerabilities, log_risk_history
from ml_engine.trainer import train_framework_models
from ml_engine.predictor import run_risk_prediction
from visualization.dashboard import generate_security_dashboard

ASCII_ART = """
================================================================================
 ____  ____   ___ _____ _____ ____ _____ ___ ___  _   _ 
|  _ \\|  _ \\ / _ \\_   _| ____/ ___|_   _|_ _/ _ \\| \\ | |
| |_) | |_) | | | | | | |  _|| |     | |  | | | | |  \\| |
|  __/|  _ <| |_| | | | | |__| |___  | |  | | |_| | |\\  |
|_|   |_| \\_\\\\___/  |_| |_____\\____| |_| |___\\___/|_| \\_|
                                                        
 ____  _   _ ___ _____ _     ____  
/ ___|| | | |_ _| ____| |   |  _ \\ 
\\___ \\| |_| || ||  _| | |   | | | |
 ___) |  _  || || |___| |___| |_| |
|____/|_| |_|___|_________|____/ 

                SOFTWARE SUPPLY-CHAIN THREAT DETECTION ENGINE
================================================================================
"""

import json
import http.server
import socketserver
import webbrowser
import threading
import urllib.parse
import networkx as nx

PORT = 5000
last_requirements_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "outputs", "last_requirements.txt"))

def print_console_summary(predictions, resolved_packages):
    print("\n" + "="*50)
    print("PIPELINE SCAN AND PREDICTION OUTPUT SUMMARY")
    print("="*50)
    print(f"Project Risk Level: {predictions['project_risk_score'] * 100:.1f}%")
    print("Package Risk Breakdown:")
    
    for pkg_name, risk in predictions["package_risks"].items():
        conf = predictions["confidence_scores"].get(pkg_name, 0.9)
        exp = predictions["explanations"].get(pkg_name, {})
        hgat_gnn = exp.get("graph_risk", 0.1)
        lstm_drift = exp.get("temporal_drift", 0.1)
        threat_list = predictions["package_threats"].get(pkg_name, [])
        threat_str = ", ".join([f"{t['id']}:{t['vector']}" for t in threat_list]) if threat_list else "Clean"
        print(f" - {pkg_name:18s} | Risk: {risk * 100:5.1f}% | Confidence: {conf * 100:4.1f}% | HGAT GNN: {hgat_gnn:.3f} | LSTM Drift: {lstm_drift:.3f} | Threats: {threat_str}")

    if predictions["attack_paths"]:
        print("\nCritical Transitive Risk Paths:")
        for idx, path in enumerate(predictions["attack_paths"][:3]):
            print(f" [{idx+1}] Propagated Risk: {path['risk_score']*100:.1f}% | {path['path']}")

    print("\nExplainable AI Saliency Drivers:")
    for pkg_name, exp in predictions["explanations"].items():
        if exp["top_features"]:
            feat_str = ", ".join([f"{f} ({w*100:.0f}%)" for f, w in exp["top_features"]])
            print(f" - {pkg_name:18s} | Drivers: {feat_str}")

    ew = predictions.get("early_warning_metrics", {})
    print("\n==================================================")
    print("           EARLY WARNING PERFORMANCE METRICS")
    print("==================================================")
    print(f" Detection Latency (TTD):             {ew.get('detection_latency_hours', 0.0):.1f} hours")
    print(f" Median Time-To-Detection (TTD):      {ew.get('median_ttd_hours', 0.0):.1f} hours")
    print(f" Intercepted within 24h (TTD@24h):   {ew.get('ttd_at_24h_percent', 100.0):.1f}%")
    print(f" Intercepted within 72h (TTD@72h):   {ew.get('ttd_at_72h_percent', 100.0):.1f}%")
    print(f" Early Detection Rate (EDR):         {ew.get('early_detection_rate_percent', 100.0):.1f}%")
    print("==================================================\n")

def get_transitive_dependencies(pkg_key, resolved_packages, visited=None):
    if visited is None:
        visited = set()
    pkg = resolved_packages.get(pkg_key)
    if not pkg:
        return set()
    for dep in pkg.get("dependencies", []):
        dep_key = dep.lower()
        if dep_key not in visited:
            visited.add(dep_key)
            get_transitive_dependencies(dep_key, resolved_packages, visited)
    return visited

def save_scan_results_csv(predictions, resolved_packages, static_results, output_path="outputs/scan_results.csv"):
    import pandas as pd
    # Load runtime telemetry if available
    runtime_data = {}
    runtime_path = "outputs/runtime_telemetry.json"
    if os.path.exists(runtime_path):
        try:
            with open(runtime_path, "r", encoding="utf-8") as rf:
                runtime_data = json.load(rf).get("packages", {})
        except Exception:
            runtime_data = {}

    scan_rows = []
    for key, pkg in resolved_packages.items():
        name = pkg["name"]
        ver = pkg["version"]
        
        # Dependency resolving
        direct_list = [d.lower() for d in pkg.get("dependencies", []) if d.lower() in resolved_packages]
        direct_count = len(direct_list)
        
        all_transitive = get_transitive_dependencies(key, resolved_packages, set())
        indirect_list = all_transitive - set(direct_list) - {key}
        indirect_count = len(indirect_list)
        total_count = direct_count + indirect_count
        
        final_score = predictions["package_risks"].get(name, 0.1)
        conf = predictions["confidence_scores"].get(name, 0.9)
        exp = predictions["explanations"].get(name, {})
        hgat_gnn = exp.get("graph_risk", 0.1)
        lstm_drift = exp.get("temporal_drift", 0.1)
        pkg_static = static_results.get("packages", {}).get(key.lower(), {})
        pkg_static_issues = pkg_static.get("bandit_issue_count", 0) + pkg_static.get("semgrep_issue_count", 0)
        
        # Extract runtime telemetry events
        pkg_rt = runtime_data.get(name.lower(), {})
        runtime_events = pkg_rt.get("system_call_count", 0) + pkg_rt.get("subprocess_count", 0) + \
                         pkg_rt.get("suspicious_network_activity", 0) + pkg_rt.get("file_access_risk", 0)
        
        if final_score >= 0.85:
            risk_lvl = "Critical"
        elif final_score >= 0.60:
            risk_lvl = "High"
        elif final_score >= 0.35:
            risk_lvl = "Medium"
        else:
            risk_lvl = "Low"
            
        scan_rows.append({
            "Package": name,
            "Version": ver,
            "Direct Dependencies": ",".join(direct_list) if direct_list else "None",
            "Indirect Dependencies": ",".join(sorted(list(indirect_list))) if indirect_list else "None",
            "Direct Dependency Count": direct_count,
            "Indirect Dependency Count": indirect_count,
            "Total Dependency Count": total_count,
            "SAST Issues": pkg_static_issues,
            "Runtime Telemetry Issues": runtime_events,
            "HGAT GNN Risk": hgat_gnn,
            "LSTM Drift Risk": lstm_drift,
            "Composite Risk Score": final_score,
            "Confidence": conf,
            "Risk Level": risk_lvl
        })
    df = pd.DataFrame(scan_rows)
    df.to_csv(output_path, index=False)
    print(f"[GATEKEEPER] Consolidated scan results saved to: {output_path}")

class GatekeeperHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Serve the download CSV report endpoint
        if self.path == "/download_csv":
            csv_path = "outputs/scan_results.csv"
            if os.path.exists(csv_path):
                self.send_response(200)
                self.send_header("Content-Type", "text/csv")
                self.send_header("Content-Disposition", "attachment; filename=scan_results.csv")
                self.end_headers()
                with open(csv_path, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"CSV file not generated yet. Please run a requirements scan first.")
            return

        if self.path == "/list_outputs":
            allowed_files = {
                "ablation_study_results.csv",
                "ablation_table.md",
                "runtime_telemetry.json",
                "sbom.json",
                "scan_results.csv",
                "semgrep.json",
                "early_warning_metrics.png",
                "detection_latency_ttd.png",
                "ablation_metrics_comparison.png",
                "fpr_metrics_comparison.png"
            }
            files_list = []
            if os.path.exists("outputs"):
                for item in os.listdir("outputs"):
                    if item in allowed_files and os.path.isfile(os.path.join("outputs", item)):
                        files_list.append(item)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(files_list).encode('utf-8'))
            return

        if self.path.startswith("/view_output"):
            allowed_files = {
                "ablation_study_results.csv",
                "ablation_table.md",
                "runtime_telemetry.json",
                "sbom.json",
                "scan_results.csv",
                "semgrep.json",
                "early_warning_metrics.png",
                "detection_latency_ttd.png",
                "ablation_metrics_comparison.png",
                "fpr_metrics_comparison.png"
            }
            query_components = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            file_name = query_components.get("file", [None])[0]
            if file_name:
                clean_name = os.path.basename(file_name)
                if clean_name in allowed_files:
                    target_path = os.path.join("outputs", clean_name)
                    if os.path.exists(target_path):
                        self.send_response(200)
                        content_type = "image/png" if clean_name.endswith(".png") else "text/plain; charset=utf-8"
                        self.send_header("Content-Type", content_type)
                        self.end_headers()
                        with open(target_path, "rb") as f:
                            self.wfile.write(f.read())
                        return
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"File not found or access restricted.")
            return

        # Serve the dashboard at root or /dashboard.html
        if self.path == "/" or self.path == "/dashboard.html":
            self.path = "/outputs/dashboard.html"
        return super().do_GET()

    def do_POST(self):
        global last_requirements_path
        if self.path == "/scan_requirements":
            # 1. Parse plain text requirements from body
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length).decode('utf-8')
            
            print("\n" + "="*50)
            print("[GATEKEEPER] RECEIVED REQUIREMENTS FILE UPLOAD")
            print("="*50)
            print(f"Content:\n{post_data}\n---")
            
            # Save file to outputs/scan_temp/requirements.txt for scanner pipeline
            os.makedirs("outputs/scan_temp", exist_ok=True)
            with open(os.path.join("outputs", "scan_temp", "requirements.txt"), "w", encoding="utf-8") as f:
                f.write(post_data)
                
            # Keep a persistent copy at last_requirements_path for the installation step
            with open(last_requirements_path, "w", encoding="utf-8") as f:
                f.write(post_data)
                
            try:
                # 2. Run pre-install pipeline
                print("\n[STEP 1/6] Generating SBOM...")
                res_packages = generate_sbom("outputs/scan_temp")
                
                print("\n[STEP 2/6] Running static code scans...")
                static_res = run_static_analysis("outputs/scan_temp", res_packages)
                
                # Mock telemetry for quarantine scan
                runtime_res = {
                    "system_call_count": 0,
                    "subprocess_count": 0,
                    "shell_execution_usage": 0,
                    "dynamic_execution_count": 0,
                    "suspicious_network_activity": 0,
                    "file_access_risk": 0
                }
                
                print("\n[STEP 3/6] Fetching dependency vulnerability intelligence...")
                dep_res = run_dependency_scan("outputs/scan_temp", res_packages)
                v_details = dep_res["vulnerability_details"]
                
                print("\n[STEP 4/6] Querying maintainer and package metadata databases...")
                package_metadata_map = {}
                for key, pkg in res_packages.items():
                    pkg_profile = verify_and_enrich_package(pkg["name"], pkg["version"])
                    package_metadata_map[key] = pkg_profile
                    if key in v_details:
                        record_vulnerabilities(pkg["name"], v_details[key])
                        
                print("\n[STEP 5/6] Executing HGAT GNN and Temporal LSTM risk propagation...")
                pred_res = run_risk_prediction(
                    res_packages, 
                    v_details, 
                    package_metadata_map, 
                    static_res, 
                    runtime_res
                )
                
                print("\n[STEP 6/6] Categorizing threat vector anomalies T1-T6...")
                from dependency_analysis.threat_model import evaluate_all_threats
                threat_res = evaluate_all_threats(
                    res_packages,
                    package_metadata_map,
                    static_res,
                    runtime_res,
                    pred_res
                )
                pred_res["package_threats"] = threat_res["package_threats"]
                
                # Format graph and predictions for D3
                G = pred_res["graph"]
                nodes_list = [{"id": n, "type": G.nodes[n].get("type", "package")} for n in G.nodes]
                links_list = [{"source": u, "target": v, "relationship": G.edges[u,v].get("relationship", "depends_on")} for u, v in G.edges]
                
                prediction_clean = {
                    "project_risk_score": float(pred_res["project_risk_score"]),
                    "package_risks": {k: float(v) for k, v in pred_res["package_risks"].items()},
                    "confidence_scores": {k: float(v) for k, v in pred_res["confidence_scores"].items()},
                    "radv_scores": {k: float(v) for k, v in pred_res.get("radv_scores", {}).items()},
                    "blast_radius_scores": {k: int(v) for k, v in pred_res.get("blast_radius_scores", {}).items()},
                    "early_warning_metrics": pred_res.get("early_warning_metrics", {}),
                    "package_threats": pred_res.get("package_threats", {}),
                    "attack_paths": pred_res["attack_paths"],
                    "explanations": {}
                }
                
                for pkg, exp in pred_res["explanations"].items():
                    prediction_clean["explanations"][pkg] = {
                        "graph_risk": float(exp["graph_risk"]),
                        "temporal_drift": float(exp["temporal_drift"]),
                        "top_features": [(f, float(w)) for f, w in exp["top_features"]],
                        "top_influencing_nodes": [(n, float(w)) for n, w in exp["top_influencing_nodes"]]
                    }
                
                # Save the comprehensive risk analysis and early warnings to scan_results.csv
                save_scan_results_csv(prediction_clean, res_packages, static_res)

                # Print the comprehensive risk analysis and early warnings to host terminal
                print_console_summary(prediction_clean, res_packages)
                
                response_payload = json.dumps({
                    "predictions": prediction_clean,
                    "graph": {"nodes": nodes_list, "links": links_list}
                })
                
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(response_payload.encode('utf-8'))
                print("\n[GATEKEEPER] Threat analysis complete. Output sent to browser.")
                
            except Exception as e:
                import traceback
                traceback.print_exc()
                print(f"\n[GATEKEEPER] Error during scan pipeline execution: {e}")
                self.send_response(500)
                self.end_headers()
                self.wfile.write(str(e).encode('utf-8'))
                
        elif self.path == "/install":
            print("\n" + "="*50)
            print("[GATEKEEPER] USER APPROVED INSTALLATION")
            print("="*50)
            try:
                import subprocess
                cmd = [sys.executable, "-m", "pip", "install", "-r", last_requirements_path]
                print(f"Running command: {' '.join(cmd)}")
                
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                pip_logs = []
                for line in proc.stdout:
                    log_line = line.strip()
                    print(f" [pip] {log_line}")
                    pip_logs.append(log_line)
                proc.wait()
                
                if proc.returncode == 0:
                    print("\n[GATEKEEPER] Installation successful! Host packages updated.")
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"Success")
                else:
                    error_summary = "\n".join(pip_logs[-4:]) if pip_logs else ""
                    raise Exception(f"pip install failed (code {proc.returncode}):\n{error_summary}")
            except Exception as e:
                print(f"\n[GATEKEEPER] Installation failed: {e}")
                self.send_response(500)
                self.end_headers()
                self.wfile.write(str(e).encode('utf-8'))
                
        elif self.path == "/abort":
            print("\n[GATEKEEPER] User rejected/cancelled the installation scan.")
            if os.path.exists(last_requirements_path):
                os.remove(last_requirements_path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Aborted")

def main():
    print(ASCII_ART)
    os.makedirs("outputs", exist_ok=True)

    # 1. Train models and output training, validation, and test split metrics
    print("Initializing chronological neural network training and validation pipeline...")
    train_framework_models()
        
    # 2. Write empty initial dashboard page to outputs/dashboard.html
    blank_predictions = {
        "project_risk_score": 0.0,
        "package_risks": {},
        "confidence_scores": {},
        "attack_paths": [],
        "explanations": {},
        "graph": nx.DiGraph()
    }
    generate_security_dashboard(blank_predictions, {}, "outputs/dashboard.html")

    # 3. Start local HTTP server
    handler = GatekeeperHandler
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), handler) as httpd:
        print(f"\n[SERVER] Gatekeeper server listening on: http://localhost:{PORT}")
        print("[SERVER] Opening Security Gatekeeper Dashboard in your browser...")
        
        # Open browser in a separate thread to prevent blocking
        threading.Thread(target=lambda: webbrowser.open(f"http://localhost:{PORT}")).start()
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[SERVER] Shutting down Gatekeeper server.")

if __name__ == "__main__":
    main()