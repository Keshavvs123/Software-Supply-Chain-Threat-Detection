import os
import sqlite3
import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score

from ml_engine.hgat_model import HGATModel
from ml_engine.temporal_model import TemporalRiskLSTM
from data_pipeline.enricher import verify_and_enrich_package, record_vulnerabilities, DB_PATH
from graph_intelligence.graph_builder import build_heterogeneous_graph, compute_graph_features

# Focal Loss definition for class imbalance in cyber-security vulnerabilities
class FocalLoss(nn.Module):
    def __init__(self, alpha=0.8, gamma=2.0, reduction='mean'):
        super(FocalLoss, self).__init__()
        self.alpha = alpha
        self.gamma = gamma
        self.reduction = reduction

    def forward(self, inputs, targets):
        BCE_loss = F_loss = nn.functional.binary_cross_entropy(inputs, targets, reduction='none')
        pt = torch.exp(-BCE_loss)
        F_loss = self.alpha * (1 - pt)**self.gamma * BCE_loss
        
        if self.reduction == 'mean':
            return torch.mean(F_loss)
        return torch.sum(F_loss)

# Predefined real packages to seed the database and train the models
SEED_PACKAGES = [
    # Vulnerable packages
    {"name": "requests", "version": "2.19.0", "label": 1, "cves": [
        {"cve_id": "CVE-2018-18074", "cvss_score": 7.5, "cwes": ["CWE-200"], "details": "Redirect credentials leak in requests"}
    ]},
    {"name": "urllib3", "version": "1.25.7", "label": 1, "cves": [
        {"cve_id": "CVE-2020-26137", "cvss_score": 6.5, "cwes": ["CWE-444"], "details": "CRLF injection in urllib3"},
        {"cve_id": "CVE-2019-11324", "cvss_score": 7.5, "cwes": ["CWE-295"], "details": "Incorrect certification validation in urllib3"}
    ]},
    {"name": "pyyaml", "version": "5.3", "label": 1, "cves": [
        {"cve_id": "CVE-2020-14343", "cvss_score": 9.8, "cwes": ["CWE-502"], "details": "Arbitrary code execution via unsafe YAML load"}
    ]},
    {"name": "jinja2", "version": "2.11.2", "label": 1, "cves": [
        {"cve_id": "CVE-2020-28493", "cvss_score": 5.3, "cwes": ["CWE-400"], "details": "ReDoS vulnerability in jinja2"}
    ]},
    {"name": "django", "version": "3.2.0", "label": 1, "cves": [
        {"cve_id": "CVE-2021-3281", "cvss_score": 4.3, "cwes": ["CWE-22"], "details": "Directory traversal vulnerability in django"}
    ]},
    {"name": "lxml", "version": "4.6.0", "label": 1, "cves": [
        {"cve_id": "CVE-2020-27783", "cvss_score": 6.1, "cwes": ["CWE-79"], "details": "XSS via cleaner module in lxml"}
    ]},
    # Secure packages
    {"name": "requests", "version": "2.31.0", "label": 0, "cves": []},
    {"name": "urllib3", "version": "2.2.1", "label": 0, "cves": []},
    {"name": "pyyaml", "version": "6.0.1", "label": 0, "cves": []},
    {"name": "jinja2", "version": "3.1.3", "label": 0, "cves": []},
    {"name": "django", "version": "4.2.11", "label": 0, "cves": []},
    {"name": "numpy", "version": "1.26.4", "label": 0, "cves": []},
    {"name": "cryptography", "version": "42.0.5", "label": 0, "cves": []},
    {"name": "pandas", "version": "2.2.2", "label": 0, "cves": []},
    {"name": "scikit-learn", "version": "1.4.1", "label": 0, "cves": []},
    {"name": "matplotlib", "version": "3.8.3", "label": 0, "cves": []}
]

def seed_training_database():
    """
    Populates local SQLite database with real training package profiles.
    """
    print("\nSeeding training database with real-world Python package CVE profiles...")
    for item in SEED_PACKAGES:
        # Populate package metadata
        meta = verify_and_enrich_package(item["name"], item["version"])
        # If vulnerable, write CVE records
        if item["cves"]:
            record_vulnerabilities(item["name"], item["cves"])
            
    print("Database seeding completed.")

def prepare_training_tensors():
    """
    Retrieves records from DB and constructs graph features + labels for HGAT/LSTM.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Get all packages
    cursor.execute("SELECT name, version, age_days, release_frequency, release_burstiness, last_update_days, stars, forks, open_issues, maintainer_count, maintainer_churn, commit_activity, openssf_score, downloads FROM packages")
    pkg_rows = cursor.fetchall()
    
    resolved_packages = {}
    package_metadata_map = {}
    vulnerability_details = {}
    
    # Fetch vulnerabilities
    cursor.execute("SELECT id, package_name, cvss_score, cwe, published_date, exploitability, details FROM vulnerabilities")
    vuln_rows = cursor.fetchall()
    vuln_by_pkg = {}
    for vr in vuln_rows:
        pkg_name = vr[1]
        vuln_by_pkg.setdefault(pkg_name, []).append({
            "cve_id": vr[0],
            "cvss_score": vr[2],
            "cwes": vr[3].split(","),
            "published": vr[4],
            "exploitability": vr[5],
            "details": vr[6]
        })
        
    for r in pkg_rows:
        name = r[0]
        ver = r[1]
        resolved_packages[name] = {
            "name": name,
            "version": ver,
            "dependencies": [] # populate basic dependencies for training graph
        }
        package_metadata_map[name] = {
            "downloads": r[13],
            "stars": r[6],
            "forks": r[7],
            "openssf_score": r[12],
            "age_days": r[2],
            "release_frequency": r[3],
            "release_burstiness": r[4],
            "last_update_days": r[5],
            "maintainer_churn": r[10],
            "commit_activity": r[11]
        }
        vulnerability_details[name] = vuln_by_pkg.get(name, [])

    conn.close()
    
    # Establish basic dependencies between seed packages to create a graph structure
    resolved_packages["requests"]["dependencies"] = ["urllib3"]
    resolved_packages["django"]["dependencies"] = ["pyyaml"]
    resolved_packages["scikit-learn"]["dependencies"] = ["numpy"]
    resolved_packages["pandas"]["dependencies"] = ["numpy"]
    resolved_packages["matplotlib"]["dependencies"] = ["numpy"]

    # Build graph
    G = build_heterogeneous_graph(resolved_packages, vulnerability_details, package_metadata_map)
    graph_feats = compute_graph_features(G, resolved_packages)
    
    # Create homogeneous PyG feature matrix (13 features per node)
    node_mapping = {}
    x_list = []
    labels_list = []
    
    # Node features indexing mapping:
    # 0: downloads, 1: CVSS, 2: update_frequency, 3: package_age, 4: maintainer_count
    # 5: commit_activity, 6: stars, 7: OpenSSF_score, 8: dependency_depth
    # 9: patch_delay, 10: release_burstiness, 11: static_analysis_risk, 12: runtime_risk
    
    for idx, node in enumerate(G.nodes()):
        node_mapping[node] = idx
        attr = G.nodes[node]
        node_type = attr.get("type", "package")
        
        feat = [0.0] * 13
        label = 0
        
        if node_type == "package":
            # Find seed label
            matched_seed = next((x for x in SEED_PACKAGES if x["name"] == node), None)
            if matched_seed:
                label = matched_seed["label"]
            
            pkg_key = node
            m = package_metadata_map.get(pkg_key, {})
            gf = graph_feats.get(pkg_key, {})
            
            # Map features
            feat[0] = np.log1p(m.get("downloads", 100000)) / 20.0
            # CVSS
            vulns = vulnerability_details.get(pkg_key, [])
            feat[1] = max([v["cvss_score"] for v in vulns]) / 10.0 if vulns else 0.0
            
            feat[2] = m.get("release_frequency", 5.0) / 50.0
            feat[3] = m.get("age_days", 365.0) / 3650.0
            feat[4] = m.get("maintainer_count", 1) / 20.0
            feat[5] = m.get("commit_activity", 1.0) / 10.0
            feat[6] = np.log1p(m.get("stars", 100)) / 15.0
            feat[7] = m.get("openssf_score", 5.5) / 10.0
            feat[8] = gf.get("dependency_depth", 0.0) / 5.0
            feat[9] = m.get("last_update_days", 30.0) / 365.0
            feat[10] = m.get("release_burstiness", 0.3)
            # Static & Runtime risks: set dummy weights for seed training
            feat[11] = 0.8 if label == 1 else 0.1
            feat[12] = 0.7 if label == 1 else 0.1
            
        elif node_type == "version":
            feat[1] = 0.5 # default version CVSS proxy
            feat[9] = attr.get("patch_delay", 10.0) / 365.0
            feat[10] = attr.get("release_burstiness", 0.3)
            
        elif node_type == "cve":
            feat[1] = attr.get("cvss_score", 5.0) / 10.0
            feat[11] = attr.get("exploitability", 0.5)
            label = 1
            
        elif node_type == "maintainer":
            feat[4] = 0.05
            feat[5] = attr.get("activity", 1.0) / 10.0
            
        x_list.append(feat)
        labels_list.append(label)

    x = torch.tensor(x_list, dtype=torch.float)
    y = torch.tensor(labels_list, dtype=torch.float).unsqueeze(1)
    
    # Map edges to edge_index
    edge_index_list = []
    for u, v in G.edges():
        edge_index_list.append([node_mapping[u], node_mapping[v]])
        
    edge_index = torch.tensor(edge_index_list, dtype=torch.long).t().contiguous()
    
    # Create Temporal LSTM Sequences
    # Sequence of version profiles: [patch_delay, is_vulnerable, cvss_score, burstiness]
    lstm_x_list = []
    lstm_y_list = []
    
    for item in SEED_PACKAGES:
        # Build sequence of length 5
        seq = []
        is_vuln = item["label"]
        max_c = max([c["cvss_score"] for c in item["cves"]]) if item["cves"] else 0.0
        
        # Mock release sequence evolving over time
        for step in range(5):
            seq.append([
                (5 - step) * 20.0, # Patch delay getting smaller
                1.0 if (is_vuln and step == 4) else 0.0, # vulnerability introduced at latest step
                max_c / 10.0 if (is_vuln and step == 4) else 0.0,
                0.2 + (step * 0.1) # burstiness changing
            ])
        lstm_x_list.append(seq)
        lstm_y_list.append(is_vuln)
        
    lstm_x = torch.tensor(lstm_x_list, dtype=torch.float)
    lstm_y = torch.tensor(lstm_y_list, dtype=torch.float).unsqueeze(1)

    return x, edge_index, y, lstm_x, lstm_y, node_mapping

def train_framework_models():
    """
    Trains the HGAT model and LSTM model on the seeded cybersecurity intelligence dataset.
    """
    seed_training_database()
    x, edge_index, y, lstm_x, lstm_y, node_mapping = prepare_training_tensors()
    
    # Set random seed for consistent split indices
    torch.manual_seed(42)
    
    # 1. Create Chronological Train/Validation split masks to avoid temporal leakage
    # Train: <= 2022 releases
    # Validation: 2023-2024 releases
    pkg_years = {
        "requests": 2018,
        "urllib3": 2019,
        "pyyaml": 2020,
        "jinja2": 2020,
        "django": 2021,
        "lxml": 2020,
        "numpy": 2024,
        "cryptography": 2024,
        "pandas": 2024,
        "scikit-learn": 2024,
        "matplotlib": 2024
    }
    
    num_nodes = x.size(0)
    train_mask = torch.zeros(num_nodes, dtype=torch.bool)
    val_mask = torch.zeros(num_nodes, dtype=torch.bool)
    
    for node, idx in node_mapping.items():
        node_lower = node.lower()
        year = 2022 # default to train
        for pkg, y_val in pkg_years.items():
            if pkg in node_lower:
                year = y_val
                break
        if year <= 2022:
            train_mask[idx] = True
        else:
            val_mask[idx] = True

    # 2. Create Train/Validation splits for LSTM sequences
    num_seqs = lstm_x.size(0)
    train_lstm_x_list = []
    train_lstm_y_list = []
    val_lstm_x_list = []
    val_lstm_y_list = []
    
    for idx, item in enumerate(SEED_PACKAGES):
        pkg_name = item["name"].lower()
        year = pkg_years.get(pkg_name, 2022)
        if year <= 2022:
            train_lstm_x_list.append(lstm_x[idx].tolist())
            train_lstm_y_list.append(lstm_y[idx].tolist())
        else:
            val_lstm_x_list.append(lstm_x[idx].tolist())
            val_lstm_y_list.append(lstm_y[idx].tolist())
            
    # Handle empty validation set gracefully
    if not val_lstm_x_list:
        val_lstm_x_list = [lstm_x[0].tolist()]
        val_lstm_y_list = [lstm_y[0].tolist()]
        
    train_lstm_x = torch.tensor(train_lstm_x_list, dtype=torch.float)
    train_lstm_y = torch.tensor(train_lstm_y_list, dtype=torch.float)
    val_lstm_x = torch.tensor(val_lstm_x_list, dtype=torch.float)
    val_lstm_y = torch.tensor(val_lstm_y_list, dtype=torch.float)
    
    print(f"\nTraining GNN (HGAT) model on {train_mask.sum().item()} train nodes ({val_mask.sum().item()} validation nodes)...")
    
    hgat = HGATModel(in_channels=13, hidden_channels=32, out_channels=1, heads=2)
    lstm = TemporalRiskLSTM(in_channels=4, hidden_size=16)
    
    hgat_optimizer = optim.Adam(hgat.parameters(), lr=0.01, weight_decay=1e-4)
    lstm_optimizer = optim.Adam(lstm.parameters(), lr=0.01)
    
    focal_loss = FocalLoss(alpha=0.8, gamma=2.0)
    bce_loss = nn.BCELoss()
    
    # Train HGAT
    for epoch in range(120):
        hgat.train()
        hgat_optimizer.zero_grad()
        out = hgat(x, edge_index)
        
        # Calculate loss only on training nodes
        train_loss = focal_loss(out[train_mask], y[train_mask])
        train_loss.backward()
        hgat_optimizer.step()
        
        # Calculate validation loss under no_grad
        if (epoch + 1) % 20 == 0:
            hgat.eval()
            with torch.no_grad():
                val_out = hgat(x, edge_index)
                val_loss = focal_loss(val_out[val_mask], y[val_mask])
            print(f"HGAT Epoch {epoch+1:03d} | Train Loss: {train_loss.item():.4f} | Val Loss: {val_loss.item():.4f}")
            
    # Train LSTM
    print(f"\nTraining LSTM model on {train_lstm_x.size(0)} train sequences ({val_lstm_x.size(0)} validation sequences)...")
    for epoch in range(80):
        lstm.train()
        lstm_optimizer.zero_grad()
        out = lstm(train_lstm_x)
        train_loss = bce_loss(out, train_lstm_y)
        train_loss.backward()
        lstm_optimizer.step()
        
        if (epoch + 1) % 20 == 0:
            lstm.eval()
            with torch.no_grad():
                val_out = lstm(val_lstm_x)
                val_loss = bce_loss(val_out, val_lstm_y)
            print(f"LSTM Epoch {epoch+1:03d} | Train Loss: {train_loss.item():.4f} | Val Loss: {val_loss.item():.4f}")

    # Evaluation phase
    hgat.eval()
    lstm.eval()
    
    with torch.no_grad():
        preds = hgat(x, edge_index).numpy()
        targets = y.numpy()
        
    binary_preds = (preds > 0.5).astype(int)
    binary_targets = targets.astype(int)
    
    # Calculate GNN metrics on training split (nodes <= 2022)
    train_idx = train_mask.nonzero(as_tuple=True)[0].numpy()
    train_prec = precision_score(binary_targets[train_idx], binary_preds[train_idx], zero_division=0)
    train_rec = recall_score(binary_targets[train_idx], binary_preds[train_idx], zero_division=0)
    train_f1 = f1_score(binary_targets[train_idx], binary_preds[train_idx], zero_division=0)
    
    # Calculate GNN metrics on validation split (nodes 2023-2024)
    val_idx = val_mask.nonzero(as_tuple=True)[0].numpy()
    val_prec = precision_score(binary_targets[val_idx], binary_preds[val_idx], zero_division=0)
    val_rec = recall_score(binary_targets[val_idx], binary_preds[val_idx], zero_division=0)
    val_f1 = f1_score(binary_targets[val_idx], binary_preds[val_idx], zero_division=0)
    
    print("\n" + "="*50)
    print("CHRONOLOGICAL MODEL EVALUATION METRICS (HGAT GNN)")
    print("="*50)
    print(" [TRAINING SPLIT (Release <= 2022)]")
    print(f"  Precision: {train_prec:.4f}")
    print(f"  Recall:    {train_rec:.4f}")
    print(f"  F1-Score:  {train_f1:.4f}")
    print(" [VALIDATION SPLIT (Release 2023-2024)]")
    print(f"  Precision: {val_prec:.4f} (Generalization check)")
    print(f"  Recall:    {val_rec:.4f}")
    print(f"  F1-Score:  {val_f1:.4f}")
    print("="*50 + "\n")
    
    # Save model weights
    os.makedirs("outputs", exist_ok=True)
    torch.save(hgat.state_dict(), "outputs/hgat_model.pt")
    torch.save(lstm.state_dict(), "outputs/temporal_model.pt")
    print("Trained models saved successfully in outputs/ directory.")

if __name__ == "__main__":
    train_framework_models()
