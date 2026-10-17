"""
Chronological Forward-Testing / Temporal Train-Test Split Evaluator.
Simulates real-world deployment where models trained on historical package data
must detect newly published / recently updated packages without data leakage.
"""

import os
import sys
import time
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, precision_recall_curve, auc, confusion_matrix
)

# Ensure reproducibility
np.random.seed(42)
torch.manual_seed(42)
if torch.cuda.is_available():
    torch.cuda.manual_seed_all(42)

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from ml_engine.train_full_dataset import load_and_preprocess_dataset, FullHGAT

def run_temporal_split_evaluation(excel_path="dataset/Supply_Chain_Risk_Dataset_v2.xlsx"):
    print("\n=======================================================")
    print("CHRONOLOGICAL TRAIN/TEST SPLIT EVALUATION (TEMPORAL DRIFT)")
    print("=======================================================")
    
    start_time = time.time()
    xl = pd.ExcelFile(excel_path)
    df_packages = pd.read_excel(xl, sheet_name="Packages")
    df_edges = pd.read_excel(xl, sheet_name="Edges")
    
    num_nodes = len(df_packages)
    print(f"Loaded {num_nodes:,} packages for chronological split analysis.")

    # Chronological sort: packages with larger 'pypi_days_since_last_release' are older (historical),
    # packages with smaller 'pypi_days_since_last_release' are newer (future unseen releases).
    sort_col = "pypi_days_since_last_release"
    if sort_col not in df_packages.columns:
        df_packages[sort_col] = 100.0
    
    # Sort descending by days since last release (oldest releases first -> train; newest releases -> test)
    temporal_order = np.ascontiguousarray(df_packages[sort_col].fillna(100.0).argsort()[::-1].values)
    
    split_cutoff = int(0.70 * num_nodes)
    train_idx = np.ascontiguousarray(temporal_order[:split_cutoff])
    test_idx = np.ascontiguousarray(temporal_order[split_cutoff:])
    
    print(f"Temporal Split: Historical Train={len(train_idx):,} (70%) | Future Unseen Test={len(test_idx):,} (30%)")

    # Load standard preprocessed features
    data = load_and_preprocess_dataset(excel_path=excel_path, random_state=42)
    X_mat = data["X_np"]
    y_vec = data["y_np"]

    X_train, y_train = X_mat[train_idx], y_vec[train_idx]
    X_test, y_test = X_mat[test_idx], y_vec[test_idx]

    def compute_metrics(y_true, y_pred, y_prob):
        acc = accuracy_score(y_true, y_pred)
        prec = precision_score(y_true, y_pred, zero_division=0)
        rec = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        roc_auc = roc_auc_score(y_true, y_prob)
        p_c, r_c, _ = precision_recall_curve(y_true, y_prob)
        pr_auc = auc(r_c, p_c)
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        return {
            "Accuracy": acc, "Precision": prec, "Recall": rec,
            "F1-Score": f1, "ROC-AUC": roc_auc, "PR-AUC": pr_auc, "FPR": fpr
        }

    # 1. Logistic Regression
    print("\n[1/3] Training Logistic Regression on Chronological Split...")
    lr = LogisticRegression(max_iter=1000, random_state=42)
    lr.fit(X_train, y_train)
    lr_probs = lr.predict_proba(X_test)[:, 1]
    res_lr = compute_metrics(y_test, (lr_probs >= 0.5).astype(int), lr_probs)

    # 2. Random Forest
    print("[2/3] Training Random Forest on Chronological Split...")
    rf = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)
    rf_probs = rf.predict_proba(X_test)[:, 1]
    res_rf = compute_metrics(y_test, (rf_probs >= 0.5).astype(int), rf_probs)

    # 3. Proposed HGAT GNN
    print("[3/3] Training Proposed Multi-Head HGAT GNN on Chronological Graph...")
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    num_features = data["x"].shape[1]
    model = FullHGAT(in_channels=num_features, hidden_channels=64, heads=4, dropout=0.2).to(device)

    x = data["x"].to(device)
    edge_index = data["edge_index"].to(device)
    y = data["y"].to(device)

    train_mask = torch.zeros(num_nodes, dtype=torch.bool).to(device)
    test_mask = torch.zeros(num_nodes, dtype=torch.bool).to(device)
    train_mask[train_idx] = True
    test_mask[test_idx] = True

    opt = optim.AdamW(model.parameters(), lr=0.005, weight_decay=1e-4)
    crit = nn.BCELoss()

    model.train()
    for ep in range(1, 41):
        opt.zero_grad()
        out = model(x, edge_index)
        loss = crit(out[train_mask], y[train_mask])
        loss.backward()
        opt.step()

    model.eval()
    with torch.no_grad():
        test_out = model(x, edge_index)
        gnn_probs = test_out[test_mask].cpu().numpy().flatten()
        gnn_preds = (gnn_probs >= 0.5).astype(int)
        y_test_real = y[test_mask].cpu().numpy().flatten().astype(int)

    res_gnn = compute_metrics(y_test_real, gnn_preds, gnn_probs)

    # Compile Results
    results_df = pd.DataFrame([
        {"Model": "Logistic Regression", **res_lr},
        {"Model": "Random Forest", **res_rf},
        {"Model": "Proposed HGAT GNN", **res_gnn}
    ])

    os.makedirs("outputs", exist_ok=True)
    results_df.to_csv("outputs/temporal_split_results.csv", index=False)
    
    print("\n=======================================================")
    print("CHRONOLOGICAL EVALUATION RESULTS (FORWARD-IN-TIME TEST)")
    print("=======================================================")
    for _, r in results_df.iterrows():
        print(f"{r['Model']:22s} | Acc={r['Accuracy']:.4f} | Prec={r['Precision']:.4f} | Rec={r['Recall']:.4f} | F1={r['F1-Score']:.4f} | ROC-AUC={r['ROC-AUC']:.4f} | FPR={r['FPR']*100:.2f}%")
    print("=======================================================")
    print(f"Saved results to: outputs/temporal_split_results.csv (Elapsed: {time.time()-start_time:.1f}s)\n")

    with open("outputs/temporal_split_summary.md", "w", encoding="utf-8") as f:
        f.write("# Chronological (Temporal Split) Evaluation Summary\n\n")
        f.write("Evaluates resistance to temporal drift by training on the oldest 70% of packages and testing on the newest 30% of unseen releases.\n\n")
        f.write(results_df.to_markdown(index=False))

    return results_df

if __name__ == "__main__":
    run_temporal_split_evaluation()
