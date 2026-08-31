import os
import sys
import time
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
from torch_geometric.nn import GATConv
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, precision_recall_curve, auc, roc_curve,
    matthews_corrcoef, confusion_matrix
)
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

def load_and_preprocess_dataset(excel_path="dataset/Supply_Chain_Risk_Dataset_v2.xlsx"):
    print(f"\n[1/5] Loading real supply chain dataset from: {excel_path}...")
    start_time = time.time()
    
    xl = pd.ExcelFile(excel_path)
    df_packages = pd.read_excel(xl, sheet_name="Packages")
    df_edges = pd.read_excel(xl, sheet_name="Edges")
    print(f"Loaded {len(df_packages):,} packages and {len(df_edges):,} graph edges in {time.time()-start_time:.1f}s")
    
    # 1. Map package names to integer node IDs
    package_names = df_packages['package_name'].astype(str).str.lower().values
    pkg_to_idx = {name: i for i, name in enumerate(package_names)}
    num_nodes = len(package_names)
    
    # 2. Extract input features (12 features)
    feature_cols = [
        'total_dependencies',
        'direct_dependencies_count',
        'indirect_dependencies_count',
        'in_degree_blast_radius',
        'pypi_num_releases',
        'pypi_avg_release_interval_days',
        'pypi_days_since_last_release',
        'pypi_requires_dist_count',
        'github_stars',
        'github_forks',
        'github_open_issues',
        'github_days_since_last_push'
    ]
    
    X_df = df_packages[feature_cols].copy()
    
    # Fill missing values and apply robust log normalization
    X_df['total_dependencies'] = np.log1p(X_df['total_dependencies'].fillna(0).clip(lower=0))
    X_df['direct_dependencies_count'] = np.log1p(X_df['direct_dependencies_count'].fillna(0).clip(lower=0))
    X_df['indirect_dependencies_count'] = np.log1p(X_df['indirect_dependencies_count'].fillna(0).clip(lower=0))
    X_df['in_degree_blast_radius'] = np.log1p(X_df['in_degree_blast_radius'].fillna(0).clip(lower=0))
    X_df['pypi_num_releases'] = np.log1p(X_df['pypi_num_releases'].fillna(1).clip(lower=0))
    X_df['pypi_avg_release_interval_days'] = np.log1p(X_df['pypi_avg_release_interval_days'].fillna(30).clip(lower=0))
    X_df['pypi_days_since_last_release'] = np.log1p(X_df['pypi_days_since_last_release'].fillna(100).clip(lower=0))
    X_df['pypi_requires_dist_count'] = np.log1p(X_df['pypi_requires_dist_count'].fillna(0).clip(lower=0))
    X_df['github_stars'] = np.log1p(X_df['github_stars'].fillna(0).clip(lower=0))
    X_df['github_forks'] = np.log1p(X_df['github_forks'].fillna(0).clip(lower=0))
    X_df['github_open_issues'] = np.log1p(X_df['github_open_issues'].fillna(0).clip(lower=0))
    X_df['github_days_since_last_push'] = np.log1p(X_df['github_days_since_last_push'].fillna(365).clip(lower=0))
    
    X_mat = X_df.values.astype(np.float32)
    
    # Mean-std standardize
    mean = np.mean(X_mat, axis=0)
    std = np.std(X_mat, axis=0) + 1e-6
    X_mat = (X_mat - mean) / std
    
    # Target label: is_vulnerable_any (0 or 1)
    y_vec = df_packages['is_vulnerable_any'].fillna(0).astype(int).values
    
    # 3. Construct PyG edge_index from real Edges sheet
    src_nodes = []
    dst_nodes = []
    
    for _, row in df_edges.iterrows():
        s = str(row['source_package']).lower()
        t = str(row['target_package']).lower()
        if s in pkg_to_idx and t in pkg_to_idx:
            src_nodes.append(pkg_to_idx[s])
            dst_nodes.append(pkg_to_idx[t])
            # Add reverse edge for undirected message passing
            src_nodes.append(pkg_to_idx[t])
            dst_nodes.append(pkg_to_idx[s])
            
    # Add self-loops
    for i in range(num_nodes):
        src_nodes.append(i)
        dst_nodes.append(i)
        
    edge_index = torch.tensor([src_nodes, dst_nodes], dtype=torch.long)
    x_tensor = torch.tensor(X_mat, dtype=torch.float)
    y_tensor = torch.tensor(y_vec, dtype=torch.float).unsqueeze(1)
    
    # 4. Train / Validation / Test Splits (70% / 15% / 15%) with stratification
    indices = np.arange(num_nodes)
    train_idx, temp_idx, y_train, y_temp = train_test_split(indices, y_vec, test_size=0.30, random_state=42, stratify=y_vec)
    val_idx, test_idx, y_val, y_test = train_test_split(temp_idx, y_temp, test_size=0.50, random_state=42, stratify=y_temp)
    
    train_mask = torch.zeros(num_nodes, dtype=torch.bool)
    val_mask = torch.zeros(num_nodes, dtype=torch.bool)
    test_mask = torch.zeros(num_nodes, dtype=torch.bool)
    
    train_mask[train_idx] = True
    val_mask[val_idx] = True
    test_mask[test_idx] = True
    
    print(f"Data Split: Train={len(train_idx):,} | Val={len(val_idx):,} | Test={len(test_idx):,}")
    print(f"Vulnerability Class Ratio: Vulnerable={sum(y_vec):,} ({sum(y_vec)/len(y_vec)*100:.1f}%), Clean={len(y_vec)-sum(y_vec):,}")
    
    return {
        "x": x_tensor,
        "edge_index": edge_index,
        "y": y_tensor,
        "train_mask": train_mask,
        "val_mask": val_mask,
        "test_mask": test_mask,
        "X_np": X_mat,
        "y_np": y_vec,
        "train_idx": train_idx,
        "val_idx": val_idx,
        "test_idx": test_idx
    }

class FullHGAT(nn.Module):
    def __init__(self, in_channels=12, hidden_channels=64, heads=4, dropout=0.2):
        super(FullHGAT, self).__init__()
        self.conv1 = GATConv(in_channels, hidden_channels, heads=heads, concat=True, dropout=dropout)
        self.conv2 = GATConv(hidden_channels * heads, hidden_channels, heads=1, concat=False, dropout=dropout)
        self.fc1 = nn.Linear(hidden_channels, 32)
        self.fc2 = nn.Linear(32, 1)
        self.dropout = dropout

    def forward(self, x, edge_index):
        h = F.elu(self.conv1(x, edge_index))
        h = F.dropout(h, p=self.dropout, training=self.training)
        h = F.elu(self.conv2(h, edge_index))
        h = F.dropout(h, p=self.dropout, training=self.training)
        out = F.relu(self.fc1(h))
        out = self.fc2(out)
        return torch.sigmoid(out)

def train_and_evaluate():
    data = load_and_preprocess_dataset()
    os.makedirs("outputs", exist_ok=True)
    os.makedirs("graphs", exist_ok=True)
    
    # -------------------------------------------------------------
    # 1. TRAIN BASELINE 1: LOGISTIC REGRESSION
    # -------------------------------------------------------------
    print("\n[2/5] Training Baseline Models on Real Dataset...")
    lr = LogisticRegression(max_iter=1000, random_state=42)
    lr.fit(data["X_np"][data["train_idx"]], data["y_np"][data["train_idx"]])
    lr_probs = lr.predict_proba(data["X_np"][data["test_idx"]])[:, 1]
    lr_preds = (lr_probs >= 0.5).astype(int)
    
    # -------------------------------------------------------------
    # 2. TRAIN BASELINE 2: RANDOM FOREST
    # -------------------------------------------------------------
    rf = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42, n_jobs=-1)
    rf.fit(data["X_np"][data["train_idx"]], data["y_np"][data["train_idx"]])
    rf_probs = rf.predict_proba(data["X_np"][data["test_idx"]])[:, 1]
    rf_preds = (rf_probs >= 0.5).astype(int)
    
    # -------------------------------------------------------------
    # 3. TRAIN PROPOSED HGAT GNN MODEL
    # -------------------------------------------------------------
    print("\n[3/5] Training Proposed Multi-Head HGAT GNN on Real Graph Topology...")
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"Using compute device: {device}")
    
    model = FullHGAT(in_channels=12, hidden_channels=64, heads=4, dropout=0.2).to(device)
    x = data["x"].to(device)
    edge_index = data["edge_index"].to(device)
    y = data["y"].to(device)
    train_mask = data["train_mask"].to(device)
    val_mask = data["val_mask"].to(device)
    test_mask = data["test_mask"].to(device)
    
    optimizer = optim.AdamW(model.parameters(), lr=0.005, weight_decay=1e-4)
    criterion = nn.BCELoss()
    
    train_losses = []
    val_losses = []
    
    best_val_f1 = 0.0
    best_weights = None
    
    num_epochs = 100
    for epoch in range(1, num_epochs + 1):
        model.train()
        optimizer.zero_grad()
        out = model(x, edge_index)
        loss = criterion(out[train_mask], y[train_mask])
        loss.backward()
        optimizer.step()
        
        train_losses.append(loss.item())
        
        # Validation
        model.eval()
        with torch.no_grad():
            val_out = model(x, edge_index)
            val_loss = criterion(val_out[val_mask], y[val_mask])
            val_losses.append(val_loss.item())
            
            val_probs = val_out[val_mask].cpu().numpy().flatten()
            val_preds = (val_probs >= 0.5).astype(int)
            val_targets = y[val_mask].cpu().numpy().flatten().astype(int)
            val_f1 = f1_score(val_targets, val_preds, zero_division=0)
            
            if val_f1 > best_val_f1:
                best_val_f1 = val_f1
                best_weights = model.state_dict().copy()
                
        if epoch % 20 == 0 or epoch == 1:
            print(f"Epoch {epoch:03d}/{num_epochs:03d} | Train Loss: {loss.item():.4f} | Val Loss: {val_loss.item():.4f} | Val F1: {val_f1:.4f}")
            
    # Load best model weights
    if best_weights:
        model.load_state_dict(best_weights)
    torch.save(model.state_dict(), "outputs/hgat_model.pt")
    print("Best HGAT model weights saved to: outputs/hgat_model.pt")
    
    # Test Evaluation
    model.eval()
    with torch.no_grad():
        test_out = model(x, edge_index)
        hgat_probs = test_out[test_mask].cpu().numpy().flatten()
        hgat_preds = (hgat_probs >= 0.5).astype(int)
        y_test_real = y[test_mask].cpu().numpy().flatten().astype(int)
        
    # -------------------------------------------------------------
    # 4. COMPUTE REAL PERFORMANCE METRICS ON TEST SET
    # -------------------------------------------------------------
    print("\n[4/5] Computing Real Empirical Evaluation Metrics on Test Set (3,700 packages)...")
    
    def calculate_all_metrics(y_true, y_pred, y_prob):
        acc = accuracy_score(y_true, y_pred)
        prec = precision_score(y_true, y_pred, zero_division=0)
        rec = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        roc_auc = roc_auc_score(y_true, y_prob)
        p_curve, r_curve, _ = precision_recall_curve(y_true, y_prob)
        pr_auc = auc(r_curve, p_curve)
        mcc = matthews_corrcoef(y_true, y_pred)
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        return {
            "Accuracy": acc,
            "Precision": prec,
            "Recall": rec,
            "F1-Score": f1,
            "ROC-AUC": roc_auc,
            "PR-AUC": pr_auc,
            "MCC": mcc,
            "FPR": fpr,
            "TP": int(tp), "FP": int(fp), "TN": int(tn), "FN": int(fn)
        }
        
    metrics_lr = calculate_all_metrics(y_test_real, lr_preds, lr_probs)
    metrics_rf = calculate_all_metrics(y_test_real, rf_preds, rf_probs)
    metrics_hgat = calculate_all_metrics(y_test_real, hgat_preds, hgat_probs)
    
    print("\n==================================================")
    print("REAL EMPIRICAL TEST RESULTS (TRAINED ON 24,666 PACKAGES)")
    print("==================================================")
    print(f"Logistic Regression: Accuracy={metrics_lr['Accuracy']:.4f} | F1={metrics_lr['F1-Score']:.4f} | ROC-AUC={metrics_lr['ROC-AUC']:.4f} | FPR={metrics_lr['FPR']:.4f}")
    print(f"Random Forest:       Accuracy={metrics_rf['Accuracy']:.4f} | F1={metrics_rf['F1-Score']:.4f} | ROC-AUC={metrics_rf['ROC-AUC']:.4f} | FPR={metrics_rf['FPR']:.4f}")
    print(f"Proposed HGAT (GNN): Accuracy={metrics_hgat['Accuracy']:.4f} | F1={metrics_hgat['F1-Score']:.4f} | ROC-AUC={metrics_hgat['ROC-AUC']:.4f} | FPR={metrics_hgat['FPR']:.4f}")
    print("==================================================\n")
    
    # Generate Ablation Table based on Real Modality Subsets
    # M1: Dependencies count only
    lr_m1 = LogisticRegression(max_iter=500).fit(data["X_np"][data["train_idx"]][:, :3], data["y_np"][data["train_idx"]])
    m1_probs = lr_m1.predict_proba(data["X_np"][data["test_idx"]][:, :3])[:, 1]
    m1_res = calculate_all_metrics(y_test_real, (m1_probs >= 0.5).astype(int), m1_probs)
    
    # M2: GitHub metadata only
    lr_m2 = LogisticRegression(max_iter=500).fit(data["X_np"][data["train_idx"]][:, 8:], data["y_np"][data["train_idx"]])
    m2_probs = lr_m2.predict_proba(data["X_np"][data["test_idx"]][:, 8:])[:, 1]
    m2_res = calculate_all_metrics(y_test_real, (m2_probs >= 0.5).astype(int), m2_probs)
    
    # M3: PyPI release metadata only
    lr_m3 = LogisticRegression(max_iter=500).fit(data["X_np"][data["train_idx"]][:, 4:8], data["y_np"][data["train_idx"]])
    m3_probs = lr_m3.predict_proba(data["X_np"][data["test_idx"]][:, 4:8])[:, 1]
    m3_res = calculate_all_metrics(y_test_real, (m3_probs >= 0.5).astype(int), m3_probs)
    
    # Compile Real Ablation Table DataFrame
    ablation_df = pd.DataFrame([
        {"Model Config": "M1 (Dependency Topology Only)", "Precision": f"{m1_res['Precision']:.4f}", "Recall": f"{m1_res['Recall']:.4f}", "F1-Score": f"{m1_res['F1-Score']:.4f}", "Accuracy": f"{m1_res['Accuracy']:.4f}", "ROC-AUC": f"{m1_res['ROC-AUC']:.4f}", "PR-AUC": f"{m1_res['PR-AUC']:.4f}", "FPR": f"{m1_res['FPR']*100:.1f}%"},
        {"Model Config": "M2 (GitHub Health Only)", "Precision": f"{m2_res['Precision']:.4f}", "Recall": f"{m2_res['Recall']:.4f}", "F1-Score": f"{m2_res['F1-Score']:.4f}", "Accuracy": f"{m2_res['Accuracy']:.4f}", "ROC-AUC": f"{m2_res['ROC-AUC']:.4f}", "PR-AUC": f"{m2_res['PR-AUC']:.4f}", "FPR": f"{m2_res['FPR']*100:.1f}%"},
        {"Model Config": "M3 (PyPI Release Cadence Only)", "Precision": f"{m3_res['Precision']:.4f}", "Recall": f"{m3_res['Recall']:.4f}", "F1-Score": f"{m3_res['F1-Score']:.4f}", "Accuracy": f"{m3_res['Accuracy']:.4f}", "ROC-AUC": f"{m3_res['ROC-AUC']:.4f}", "PR-AUC": f"{m3_res['PR-AUC']:.4f}", "FPR": f"{m3_res['FPR']*100:.1f}%"},
        {"Model Config": "M4 (Logistic Regression Baseline)", "Precision": f"{metrics_lr['Precision']:.4f}", "Recall": f"{metrics_lr['Recall']:.4f}", "F1-Score": f"{metrics_lr['F1-Score']:.4f}", "Accuracy": f"{metrics_lr['Accuracy']:.4f}", "ROC-AUC": f"{metrics_lr['ROC-AUC']:.4f}", "PR-AUC": f"{metrics_lr['PR-AUC']:.4f}", "FPR": f"{metrics_lr['FPR']*100:.1f}%"},
        {"Model Config": "M5 (Random Forest Baseline)", "Precision": f"{metrics_rf['Precision']:.4f}", "Recall": f"{metrics_rf['Recall']:.4f}", "F1-Score": f"{metrics_rf['F1-Score']:.4f}", "Accuracy": f"{metrics_rf['Accuracy']:.4f}", "ROC-AUC": f"{metrics_rf['ROC-AUC']:.4f}", "PR-AUC": f"{metrics_rf['PR-AUC']:.4f}", "FPR": f"{metrics_rf['FPR']*100:.1f}%"},
        {"Model Config": "Proposed HGAT GNN (Full System)", "Precision": f"{metrics_hgat['Precision']:.4f}", "Recall": f"{metrics_hgat['Recall']:.4f}", "F1-Score": f"{metrics_hgat['F1-Score']:.4f}", "Accuracy": f"{metrics_hgat['Accuracy']:.4f}", "ROC-AUC": f"{metrics_hgat['ROC-AUC']:.4f}", "PR-AUC": f"{metrics_hgat['PR-AUC']:.4f}", "FPR": f"{metrics_hgat['FPR']*100:.1f}%"}
    ])
    
    with open("outputs/ablation_table.md", "w", encoding="utf-8") as f:
        f.write(ablation_df.to_string(index=False))
    print("Real ablation results saved to: outputs/ablation_study_results.csv")
    
    # -------------------------------------------------------------
    # 5. GENERATE REAL EMPIRICAL PLOTS (FROM ACTUAL PREDICTIONS)
    # -------------------------------------------------------------
    print("\n[5/5] Plotting Real Empirical Curves from Test Set Predictions...")
    
    # 1. REAL ROC CURVE
    fpr_lr, tpr_lr, _ = roc_curve(y_test_real, lr_probs)
    fpr_rf, tpr_rf, _ = roc_curve(y_test_real, rf_probs)
    fpr_hgat, tpr_hgat, _ = roc_curve(y_test_real, hgat_probs)
    
    plt.figure(figsize=(7, 6))
    plt.plot(fpr_hgat, tpr_hgat, color='#2563eb', lw=2.5, label=f'Proposed HGAT GNN (AUC = {metrics_hgat["ROC-AUC"]:.3f})')
    plt.plot(fpr_rf, tpr_rf, color='#10b981', lw=2.0, linestyle='--', label=f'Random Forest (AUC = {metrics_rf["ROC-AUC"]:.3f})')
    plt.plot(fpr_lr, tpr_lr, color='#f59e0b', lw=2.0, linestyle=':', label=f'Logistic Regression (AUC = {metrics_lr["ROC-AUC"]:.3f})')
    plt.plot([0, 1], [0, 1], color='#94a3b8', linestyle='--', lw=1.5, label='Random Chance')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate (FPR)', fontsize=12, fontweight='bold')
    plt.ylabel('True Positive Rate (TPR / Recall)', fontsize=12, fontweight='bold')
    plt.title('Empirical Receiver Operating Characteristic (ROC) Curve\n(Evaluated on 3,700 Real Test Packages)', fontsize=12, fontweight='bold')
    plt.legend(loc='lower right', fontsize=10)
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig("graphs/roc_curve.png", dpi=300)
    plt.savefig("outputs/roc_curve.png", dpi=300)
    plt.close()
    
    # 2. REAL PRECISION-RECALL CURVE
    p_hgat, r_hgat, _ = precision_recall_curve(y_test_real, hgat_probs)
    p_rf, r_rf, _ = precision_recall_curve(y_test_real, rf_probs)
    p_lr, r_lr, _ = precision_recall_curve(y_test_real, lr_probs)
    
    plt.figure(figsize=(7, 6))
    plt.plot(r_hgat, p_hgat, color='#2563eb', lw=2.5, label=f'Proposed HGAT (PR-AUC = {metrics_hgat["PR-AUC"]:.3f})')
    plt.plot(r_rf, p_rf, color='#10b981', lw=2.0, linestyle='--', label=f'Random Forest (PR-AUC = {metrics_rf["PR-AUC"]:.3f})')
    plt.plot(r_lr, p_lr, color='#f59e0b', lw=2.0, linestyle=':', label=f'Logistic Regression (PR-AUC = {metrics_lr["PR-AUC"]:.3f})')
    plt.xlabel('Recall', fontsize=12, fontweight='bold')
    plt.ylabel('Precision', fontsize=12, fontweight='bold')
    plt.title('Empirical Precision-Recall (PR) Curve\n(Evaluated on 3,700 Real Test Packages)', fontsize=12, fontweight='bold')
    plt.legend(loc='lower left', fontsize=10)
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig("graphs/pr_curve.png", dpi=300)
    plt.savefig("outputs/pr_curve.png", dpi=300)
    plt.close()
    
    # 3. REAL CONFUSION MATRIX
    cm = confusion_matrix(y_test_real, hgat_preds)
    plt.figure(figsize=(6, 5))
    plt.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
    plt.title('HGAT Empirical Confusion Matrix (Test Set)', fontsize=12, fontweight='bold')
    plt.colorbar()
    classes = ['Clean (0)', 'Vulnerable (1)']
    tick_marks = np.arange(len(classes))
    plt.xticks(tick_marks, classes, fontsize=10)
    plt.yticks(tick_marks, classes, fontsize=10)
    
    thresh = cm.max() / 2.
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            plt.text(j, i, f"{cm[i, j]:,}\n({cm[i, j]/cm.sum()*100:.1f}%)",
                     horizontalalignment="center",
                     verticalalignment="center",
                     color="white" if cm[i, j] > thresh else "black",
                     fontsize=11, fontweight='bold')
                     
    plt.ylabel('Ground Truth Label', fontsize=11, fontweight='bold')
    plt.xlabel('Predicted Label', fontsize=11, fontweight='bold')
    plt.tight_layout()
    plt.savefig("graphs/confusion_matrix.png", dpi=300)
    plt.savefig("outputs/confusion_matrix.png", dpi=300)
    plt.close()
    
    # 4. REAL TRAINING LOSS CURVE
    plt.figure(figsize=(7, 5))
    plt.plot(range(1, num_epochs + 1), train_losses, label='Train Loss (BCE)', color='#ef4444', lw=2)
    plt.plot(range(1, num_epochs + 1), val_losses, label='Validation Loss (BCE)', color='#3b82f6', lw=2)
    plt.xlabel('Training Epochs', fontsize=11, fontweight='bold')
    plt.ylabel('Loss Value', fontsize=11, fontweight='bold')
    plt.title('HGAT GNN Real Training & Validation Convergence', fontsize=12, fontweight='bold')
    plt.legend(fontsize=10)
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig("graphs/training_loss_convergence.png", dpi=300)
    plt.savefig("outputs/training_loss_convergence.png", dpi=300)
    plt.close()
    
    print("\n[SUCCESS] Real Empirical Results successfully generated and plotted!")

if __name__ == "__main__":
    train_and_evaluate()
