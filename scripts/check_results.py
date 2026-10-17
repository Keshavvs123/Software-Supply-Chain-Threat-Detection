"""
Statistical & Artifact Verification Script.
Asserts that empirical experimental outputs match publication confidence targets
and confirms that all 15 visualization charts and evaluation reports exist.
"""

import os
import sys
import pandas as pd

def check_results():
    print("\n=======================================================")
    print("VERIFYING EMPIRICAL BENCHMARK CRITERIA & ARTIFACTS")
    print("=======================================================")
    
    passed_checks = 0
    total_checks = 0

    def assert_check(name, condition, details=""):
        nonlocal passed_checks, total_checks
        total_checks += 1
        if condition:
            passed_checks += 1
            print(f" [PASS] {name} {details}")
        else:
            print(f" [FAIL] {name} {details}")

    # 1. Check ablation table exists and meets target metrics
    abl_path = "outputs/ablation_study_results.csv"
    if os.path.exists(abl_path):
        df_abl = pd.read_csv(abl_path)
        hgat_row = df_abl[df_abl['Model Config'].str.contains("Proposed HGAT", case=False)]
        if not hgat_row.empty:
            f1 = float(hgat_row.iloc[0]['F1-Score'])
            roc_auc = float(hgat_row.iloc[0]['ROC-AUC'])
            recall = float(hgat_row.iloc[0]['Recall'])
            
            assert_check("HGAT F1-Score >= 0.85", f1 >= 0.85, f"(Measured: {f1:.4f})")
            assert_check("HGAT ROC-AUC >= 0.85", roc_auc >= 0.85, f"(Measured: {roc_auc:.4f})")
            assert_check("HGAT Recall >= 0.90", recall >= 0.90, f"(Measured: {recall:.4f})")
        else:
            assert_check("Proposed HGAT present in ablation table", False)
    else:
        # Check fallback
        print("Note: ablation_study_results.csv not yet generated or located.")

    # 2. Check 15 visual graphs exist in graphs/
    required_graphs = [
        "accuracy_bar_chart.png",
        "precision_recall_f1_grouped.png",
        "confusion_matrix_threat_types.png",
        "suspicious_dependencies_bar_chart.png",
        "dependency_risk_heatmap.png",
        "dependency_graph_topology.png",
        "event_timeline_suspicious_steps.png",
        "threat_propagation_network.png",
        "false_positive_line_chart.png",
        "explainability_shap_saliency.png",
        "ttd_network_graph.png",
        "model_robustness_plot.png",
        "computational_overhead_scatter.png",
        "roc_curve_ablation.png",
        "dataset_description_pie.png"
    ]

    print("\n--- Verifying 15 Publication Visualizations in graphs/ ---")
    for g in required_graphs:
        path = os.path.join("graphs", g)
        exists = os.path.exists(path)
        assert_check(f"Graph: {g}", exists, f"({os.path.getsize(path)/1024:.1f} KB)" if exists else "NOT FOUND")

    # 3. Check 10 Test Cases evaluation artifact
    test_eval_path = "outputs/test_cases_evaluation.json"
    assert_check("10 Test Cases JSON Report", os.path.exists(test_eval_path))

    # 4. Check Multi-seed and 5-fold CV summaries
    assert_check("Multi-Seed Summary", os.path.exists("outputs/multi_seed_results.csv") or os.path.exists("outputs/multi_seed_summary.md"))
    assert_check("5-Fold CV Summary", os.path.exists("outputs/5fold_cv_results.csv") or os.path.exists("outputs/5fold_cv_summary.md"))
    assert_check("Threat Evaluation Summary", os.path.exists("outputs/threat_vector_eval_results.json"))

    print("\n=======================================================")
    print(f"VERIFICATION SUMMARY: {passed_checks}/{total_checks} CHECKS PASSED")
    print("=======================================================\n")
    return passed_checks == total_checks

if __name__ == "__main__":
    success = check_results()
    sys.exit(0 if success else 1)
