"""Redraw the comparison graphs from outputs/ablation_study_results.csv.

Every number plotted here is read from that CSV (written by ml_engine/train_full_dataset.py).
Nothing is hard-coded and nothing is simulated.
"""
import os
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

SHORT = {
    "M1 (Dependency Topology Only)": "M1: Topology",
    "M2 (GitHub Health Only)": "M2: GitHub",
    "M3 (PyPI Release Cadence Only)": "M3: PyPI",
    "M4 (Logistic Regression Baseline)": "M4: LogReg",
    "M5 (Random Forest Baseline)": "M5: RandForest",
    "Control: Degree-only LR (dependency counts)": "Ctrl: Degree-only",
    "Control: HGAT with shuffled edges": "Ctrl: Shuffled edges",
    "Proposed HGAT GNN (Full System)": "Proposed HGAT",
}
PROPOSED = "Proposed HGAT GNN (Full System)"
RF = "M5 (Random Forest Baseline)"


def update_all_graphs():
    print("Updating graphs from outputs/ablation_study_results.csv ...")
    os.makedirs("graphs", exist_ok=True)
    os.makedirs("outputs", exist_ok=True)

    df = pd.read_csv("outputs/ablation_study_results.csv")
    df["fpr_num"] = df["FPR"].astype(str).str.replace("%", "", regex=False).astype(float)
    names = [SHORT.get(m, m) for m in df["Model Config"]]
    colors = ["#2563eb" if m == PROPOSED else ("#f59e0b" if m.startswith("Control") else "#94a3b8")
              for m in df["Model Config"]]

    def save(*files):
        plt.tight_layout()
        for name in files:
            plt.savefig(f"graphs/{name}", dpi=300)
            plt.savefig(f"outputs/{name}", dpi=300)
            print(f"Saved: graphs/{name} and outputs/{name}")
        plt.close()

    def row(model):
        r = df[df["Model Config"] == model]
        return None if r.empty else r.iloc[0]

    # 1. Accuracy / F1 / ROC-AUC per configuration
    plt.figure(figsize=(11, 5))
    x = np.arange(len(names))
    w = 0.26
    plt.bar(x - w, df["Accuracy"], w, label="Accuracy", color="#3b82f6")
    plt.bar(x, df["F1-Score"], w, label="F1-Score", color="#10b981")
    plt.bar(x + w, df["ROC-AUC"], w, label="ROC-AUC", color="#6366f1")
    plt.ylabel("Score (0.0 - 1.0)", fontweight="bold")
    plt.title("Ablation Study: Held-Out Test Split\n(controls in orange are sanity checks, not proposed models)", fontweight="bold")
    plt.xticks(x, names, rotation=20, ha="right")
    plt.legend()
    plt.grid(axis="y", alpha=0.3)
    save("ablation_metrics_comparison.png")

    # 2. False-positive rate
    plt.figure(figsize=(10, 4.8))
    bars = plt.bar(names, df["fpr_num"], color=colors, width=0.55)
    for b in bars:
        plt.text(b.get_x() + b.get_width() / 2, b.get_height() + 1.2, f"{b.get_height():.1f}%",
                 ha="center", fontsize=9, fontweight="bold")
    plt.ylabel("False Positive Rate (%)", fontweight="bold")
    plt.title("False Positive Rate by Configuration (lower is better)", fontweight="bold")
    plt.ylim(0, 115)
    plt.xticks(rotation=20, ha="right")
    plt.grid(axis="y", alpha=0.3)
    save("fpr_metrics_comparison.png")

    # 3. Accuracy / recall / F1 profile (kept under both historical file names)
    plt.figure(figsize=(10, 5))
    plt.plot(names, df["Accuracy"] * 100, marker="o", lw=2.5, color="#2563eb", label="Accuracy (%)")
    plt.plot(names, df["Recall"] * 100, marker="s", lw=2.5, color="#10b981", label="Recall (%)")
    plt.plot(names, df["F1-Score"] * 100, marker="^", lw=2.5, color="#8b5cf6", label="F1-Score (%)")
    plt.ylabel("Percentage (%)", fontweight="bold")
    plt.title("Performance Profile Across Configurations", fontweight="bold")
    plt.xticks(rotation=20, ha="right")
    plt.legend()
    plt.grid(True, alpha=0.3)
    save("overall_performance.png", "system_performance.png")

    prop, rf = row(PROPOSED), row(RF)
    if prop is not None and rf is not None:
        # 4. Class-wise rates: TN rate = 1 - FPR, TPR = recall
        classes = ["Clean packages (TN rate)", "Vulnerable packages (recall)"]
        rf_rates = [100 - rf["fpr_num"], rf["Recall"] * 100]
        hg_rates = [100 - prop["fpr_num"], prop["Recall"] * 100]
        plt.figure(figsize=(8, 4.6))
        xc = np.arange(2)
        plt.bar(xc - 0.18, rf_rates, 0.36, label="Random Forest", color="#94a3b8")
        plt.bar(xc + 0.18, hg_rates, 0.36, label="Proposed HGAT", color="#2563eb")
        for i in range(2):
            plt.text(i - 0.18, rf_rates[i] + 1.5, f"{rf_rates[i]:.1f}%", ha="center", fontweight="bold")
            plt.text(i + 0.18, hg_rates[i] + 1.5, f"{hg_rates[i]:.1f}%", ha="center", fontweight="bold")
        plt.xticks(xc, classes)
        plt.ylabel("Rate (%)", fontweight="bold")
        plt.title("Class-Wise Rates on the Test Split", fontweight="bold")
        plt.ylim(0, 112)
        plt.legend()
        plt.grid(axis="y", alpha=0.3)
        save("class_wise_performance.png")

        # 5. Baseline vs proposed on the headline metrics
        cats = ["Accuracy", "F1-Score", "ROC-AUC", "Recall"]
        base = [rf[c] * 100 if c != "ROC-AUC" else rf[c] * 100 for c in cats]
        top = [prop[c] * 100 for c in cats]
        plt.figure(figsize=(8, 4.6))
        xo = np.arange(len(cats))
        plt.bar(xo - 0.18, base, 0.36, label="Random Forest baseline", color="#cbd5e1")
        plt.bar(xo + 0.18, top, 0.36, label="Proposed HGAT", color="#10b981")
        plt.xticks(xo, cats)
        plt.ylabel("Score (%; ROC-AUC x100)", fontweight="bold")
        plt.title("Baseline vs Proposed Model (test split)", fontweight="bold")
        plt.ylim(0, 115)
        plt.legend()
        plt.grid(axis="y", alpha=0.3)
        save("optimized_vs_unoptimized.png")

        # 6. Recall on vulnerable packages (replaces the old "detection latency" plot: this is recall,
        #    not time-to-detection, which is simulated elsewhere in the project)
        lr = row("M4 (Logistic Regression Baseline)")
        labels = ["Random Forest", "Logistic Regression", "Proposed HGAT"]
        vals = [rf["Recall"] * 100, (lr["Recall"] * 100 if lr is not None else 0), prop["Recall"] * 100]
        plt.figure(figsize=(8, 4.6))
        bars = plt.bar(labels, vals, color=["#f59e0b", "#f59e0b", "#22c55e"], width=0.45)
        for b in bars:
            plt.text(b.get_x() + b.get_width() / 2, b.get_height() + 1.5, f"{b.get_height():.2f}%",
                     ha="center", fontweight="bold")
        plt.ylabel("Recall on vulnerable packages (%)", fontweight="bold")
        plt.title("Recall on Vulnerable Test Packages", fontweight="bold")
        plt.ylim(0, 115)
        plt.grid(axis="y", alpha=0.3)
        save("detection_latency_ttd.png", "early_warning_metrics.png")

    # The old synthetic "accuracy curve" is intentionally gone: it was generated from a formula, not a
    # training run. The real loss curves are written by train_full_dataset.py (training_loss_convergence.png).
    print("\n[SUCCESS] Graphs updated from real results.")


if __name__ == "__main__":
    update_all_graphs()
