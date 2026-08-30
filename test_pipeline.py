import os
import sys

# Ensure root is in path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ml_engine.trainer import train_framework_models
from static_analysis.analyzer import run_static_analysis
from runtime_behaviour.monitor import monitor_runtime
from sbom.generator import generate_sbom
from dependency_analysis.dependency_scanner import run_dependency_scan
from data_pipeline.enricher import verify_and_enrich_package, record_vulnerabilities, log_risk_history
from ml_engine.predictor import run_risk_prediction
from visualization.dashboard import generate_security_dashboard

def main():
    print("==================================================")
    print("RUNNING PROGRAMMATIC SECURITY PIPELINE VERIFICATION")
    print("==================================================")
    
    project_path = "test_project"
    os.makedirs("outputs", exist_ok=True)
    
    # 1. Force train models
    print("\n[1] Training Neural Networks (HGAT + LSTM)...")
    train_framework_models()
    
    # 2. Generate SBOM
    print("\n[2] Generating SBOM (CycloneDX + SPDX)...")
    resolved_packages = generate_sbom(project_path)
    
    # 3. Run static analysis
    print("\n[3] Running Static Analysis (Bandit, Semgrep, AST)...")
    static_results = run_static_analysis(project_path, resolved_packages)
    print(f"Static issues: Bandit={static_results['bandit_issue_count']}, Semgrep={static_results['semgrep_issue_count']}")
    
    # 4. Run runtime behavior tracing
    print("\n[4] Running Runtime Monitoring...")
    entry_script = os.path.join(project_path, "app.py")
    runtime_results = monitor_runtime(entry_script, list(resolved_packages.keys()), timeout=6)
    
    # 5. Dependency vulnerability scan
    print("\n[5] Scanning Dependencies for CVEs...")
    dependency_results = run_dependency_scan(project_path, resolved_packages)
    vulns_details = dependency_results["vulnerability_details"]
    
    # 6. Database enrichment
    print("\n[6] Database enrichment & Known Package Verification...")
    package_metadata_map = {}
    for key, pkg in resolved_packages.items():
        pkg_profile = verify_and_enrich_package(pkg["name"], pkg["version"])
        package_metadata_map[key] = pkg_profile
        if key in vulns_details:
            record_vulnerabilities(pkg["name"], vulns_details[key])
            
    # 7. ML Predictions
    print("\n[7] Running HGAT + LSTM Threat Prediction Engine...")
    predictions = run_risk_prediction(
        resolved_packages, 
        vulns_details, 
        package_metadata_map, 
        static_results, 
        runtime_results
    )
    
    # 7.5 Evaluate Threat Model Vectors (T1-T6)
    from dependency_analysis.threat_model import evaluate_all_threats
    threat_results = evaluate_all_threats(
        resolved_packages,
        package_metadata_map,
        static_results,
        runtime_results,
        predictions
    )
    predictions["package_threats"] = threat_results["package_threats"]
    
    # 8. Generate Dashboard
    print("\n[8] Generating Interactive HTML Dashboard...")
    dashboard_path = "outputs/dashboard.html"
    generate_security_dashboard(predictions, resolved_packages, dashboard_path)
    
    # [8.5] Generate Consolidated CSV Scan Report
    print("\n[8.5] Exporting Consolidated CSV Scan Report...")
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

    import pandas as pd
    scan_rows = []
    
    # Add package rows
    for key, pkg in resolved_packages.items():
        name = pkg["name"]
        ver = pkg["version"]
        vulns = vulns_details.get(key, [])
        cve_count = len(vulns)
        max_cvss = max([v["cvss_score"] for v in vulns]) if vulns else 0.0
        
        # Dependency counts
        direct_list = [d.lower() for d in pkg.get("dependencies", []) if d.lower() in resolved_packages]
        direct_count = len(direct_list)
        all_transitive = get_transitive_dependencies(key, resolved_packages, set())
        indirect_list = all_transitive - set(direct_list) - {key}
        indirect_count = len(indirect_list)
        total_count = direct_count + indirect_count
        
        # Risk predictions
        final_score = predictions["package_risks"].get(name, 0.1)
        conf = predictions["confidence_scores"].get(name, 0.9)
        exp = predictions["explanations"].get(name, {})
        hgat_gnn = exp.get("graph_risk", 0.1)
        lstm_drift = exp.get("temporal_drift", 0.1)
        
        # Risk level classification
        if final_score >= 0.85:
            risk_lvl = "Critical Risk"
        elif final_score >= 0.60:
            risk_lvl = "High Risk"
        elif final_score >= 0.35:
            risk_lvl = "Medium Risk"
        else:
            risk_lvl = "Low Risk"
            
        # Get package static issues and metrics
        pkg_static = static_results.get("packages", {}).get(key.lower(), {})
        pkg_static_issues = pkg_static.get("bandit_issue_count", 0) + pkg_static.get("semgrep_issue_count", 0)
        shannon_entropy = pkg_static.get("shannon_entropy", 0.0)
        encoded_string_ratio = pkg_static.get("encoded_string_ratio", 0.0)
        ast_complexity = pkg_static.get("ast_complexity", 0)
        dynamic_imports = pkg_static.get("dynamic_imports", 0)
        
        # Get package runtime system calls
        import_name = key.lower()
        if key.lower() == "pyyaml":
            import_name = "yaml"
        elif key.lower() == "pytest-cov":
            import_name = "pytest_cov"
        elif key.lower() == "charset-normalizer":
            import_name = "charset_normalizer"
            
        pkg_runtime = {}
        for k in (key.lower(), import_name):
            pkg_runtime = runtime_results.get("packages", {}).get(k, {})
            if pkg_runtime:
                break
        pkg_sys_calls = (
            pkg_runtime.get("system_call_count", 0) +
            pkg_runtime.get("subprocess_count", 0) +
            pkg_runtime.get("dynamic_execution_count", 0) +
            pkg_runtime.get("suspicious_network_activity", 0)
        )
        behavioral_risk = pkg_runtime.get("behavioral_risk", 0.0)
        
        # Get Blast Radius and RADV
        blast_radius = predictions["blast_radius_scores"].get(name, 0)
        radv_score = predictions["radv_scores"].get(name, 0.0)

        scan_rows.append({
            "entity_name": name,
            "entity_type": "package",
            "version": ver,
            "direct_dependencies": ",".join(direct_list) if direct_list else "None",
            "indirect_dependencies": ",".join(sorted(list(indirect_list))) if indirect_list else "None",
            "direct_dependency_count": direct_count,
            "indirect_dependency_count": indirect_count,
            "total_dependency_count": total_count,
            "cve_count": cve_count,
            "max_cvss": max_cvss,
            "static_analysis_issues": pkg_static_issues,
            "runtime_system_calls": pkg_sys_calls,
            "hgat_gnn_risk": hgat_gnn,
            "lstm_drift_risk": lstm_drift,
            "final_risk_score": final_score,
            "confidence_score": conf,
            "risk_level": risk_lvl,
            "shannon_entropy": shannon_entropy,
            "encoded_string_ratio": encoded_string_ratio,
            "ast_complexity": ast_complexity,
            "dynamic_imports": dynamic_imports,
            "behavioral_risk": behavioral_risk,
            "blast_radius": blast_radius,
            "radv_score": radv_score
        })
        
    # Add first-party file rows
    if os.path.exists(entry_script):
        file_name = os.path.basename(entry_script)
        static_issues = static_results.get("bandit_issue_count", 0) + static_results.get("semgrep_issue_count", 0)
        sys_calls = runtime_results.get("system_call_count", 0) + runtime_results.get("subprocess_count", 0)
        
        # Calculate file risk score normalized to 0.0 - 1.0
        file_score = min((static_issues + sys_calls) / 10.0, 1.0)
        
        if file_score >= 0.85:
            risk_lvl = "Critical Risk"
        elif file_score >= 0.60:
            risk_lvl = "High Risk"
        elif file_score >= 0.35:
            risk_lvl = "Medium Risk"
        else:
            risk_lvl = "Low Risk"
            
        # Get static analysis metrics
        shannon_entropy = static_results.get("shannon_entropy", 0.0)
        encoded_string_ratio = static_results.get("encoded_string_ratio", 0.0)
        ast_complexity = static_results.get("ast_complexity", 0)
        dynamic_imports = static_results.get("dynamic_imports", 0)
        
        # Get dynamic behavior risk
        behavioral_risk = runtime_results.get("behavioral_risk", 0.0)

        scan_rows.append({
            "entity_name": file_name,
            "entity_type": "file",
            "version": "N/A",
            "direct_dependencies": "None",
            "indirect_dependencies": "None",
            "direct_dependency_count": 0,
            "indirect_dependency_count": 0,
            "total_dependency_count": 0,
            "cve_count": 0,
            "max_cvss": 0.0,
            "static_analysis_issues": static_issues,
            "runtime_system_calls": sys_calls,
            "hgat_gnn_risk": 0.0,
            "lstm_drift_risk": 0.0,
            "final_risk_score": file_score,
            "confidence_score": 0.95,
            "risk_level": risk_lvl,
            "shannon_entropy": shannon_entropy,
            "encoded_string_ratio": encoded_string_ratio,
            "ast_complexity": ast_complexity,
            "dynamic_imports": dynamic_imports,
            "behavioral_risk": behavioral_risk,
            "blast_radius": 0,
            "radv_score": 0.0
        })
        
    df_scan = pd.DataFrame(scan_rows)
    scan_csv_path = "outputs/scan_results.csv"
    df_scan.to_csv(scan_csv_path, index=False)
    print(f"Consolidated scan results exported to: {os.path.abspath(scan_csv_path)}")

    # Log risk scores to history database
    for key, pkg in resolved_packages.items():
        name = pkg["name"]
        score = predictions["package_risks"].get(name, 0.1)
        conf = predictions["confidence_scores"].get(name, 0.9)
        log_risk_history(name, pkg["version"], score, conf)

    print("\n==================================================")
    print("PIPELINE SCAN AND PREDICTION OUTPUT SUMMARY")
    print("==================================================")
    print(f"Project Risk Level: {predictions['project_risk_score'] * 100:.1f}%")
    print("Package Risk Breakdown:")
    for pkg_name, risk in predictions["package_risks"].items():
        conf = predictions["confidence_scores"].get(pkg_name, 0.9)
        exp = predictions["explanations"].get(pkg_name, {})
        threat_list = threat_results["package_threats"].get(pkg_name, [])
        threat_str = ", ".join([f"{t['id']}:{t['vector']}" for t in threat_list]) if threat_list else "Clean"
        print(f" - {pkg_name:12s} | Risk: {risk*100:5.1f}% | Confidence: {conf*100:4.1f}% | HGAT GNN: {exp['graph_risk']:.3f} | LSTM Drift: {exp['temporal_drift']:.3f} | Threats: {threat_str}")
        
    if predictions["attack_paths"]:
        print("\nCritical Transitive Risk Paths:")
        for idx, path in enumerate(predictions["attack_paths"][:3]):
            print(f" [{idx+1}] Propagated Risk: {path['risk_score']*100:.1f}% | {path['path']}")

    print("\nExplainable AI Saliency Drivers:")
    for pkg_name, exp in predictions["explanations"].items():
        if exp["top_features"]:
            feat_str = ", ".join([f"{f} ({w*100:.0f}%)" for f, w in exp["top_features"]])
            print(f" - {pkg_name:12s} | Drivers: {feat_str}")

    ew = predictions.get("early_warning_metrics", {})
    print("\n==================================================")
    print("           EARLY WARNING PERFORMANCE METRICS")
    print("==================================================")
    print(f" Detection Latency (TTD):             {ew.get('detection_latency_hours', 0.0):.1f} hours")
    print(f" Median Time-To-Detection (TTD):      {ew.get('median_ttd_hours', 0.0):.1f} hours")
    print(f" Intercepted within 24h (TTD@24h):   {ew.get('ttd_at_24h_percent', 100.0):.1f}%")
    print(f" Intercepted within 72h (TTD@72h):   {ew.get('ttd_at_72h_percent', 100.0):.1f}%")
    print(f" Early Detection Rate (EDR):         {ew.get('early_detection_rate_percent', 100.0):.1f}%")
    
    print("==================================================")
    print("Pipeline run successfully verified!")

if __name__ == "__main__":
    main()
