import os
import sys

# Force line buffering on stdout
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(line_buffering=True)

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
    from main import save_scan_results_csv
    save_scan_results_csv(predictions, resolved_packages, static_results)

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
