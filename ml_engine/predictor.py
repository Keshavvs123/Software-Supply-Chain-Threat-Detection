import os
import torch
import numpy as np
import networkx as nx

from ml_engine.hgat_model import HGATModel
from ml_engine.temporal_model import TemporalRiskLSTM
from graph_intelligence.graph_builder import build_heterogeneous_graph, compute_graph_features, propagate_risks

FEATURE_NAMES = [
    "downloads",
    "CVSS",
    "update_frequency",
    "package_age",
    "maintainer_count",
    "commit_activity",
    "stars",
    "OpenSSF_score",
    "dependency_depth",
    "patch_delay",
    "release_burstiness",
    "static_analysis_risk",
    "runtime_risk"
]

def run_risk_prediction(resolved_packages, vulnerability_details, package_metadata_map, static_results, runtime_results):
    """
    Coordinates HGAT GNN and LSTM Temporal predictions on project dependencies.
    Computes XAI explanations using gradients and GNN attention.
    """
    print("\nRunning AI Supply Chain Threat Prediction Engine...")
    
    # 1. Build Graph and compute topological features
    G = build_heterogeneous_graph(resolved_packages, vulnerability_details, package_metadata_map)
    graph_feats = compute_graph_features(G, resolved_packages)
    risk_prop_results = propagate_risks(G)
    
    # 2. Build HGAT input tensors
    node_mapping = {}
    reverse_node_mapping = {}
    x_list = []
    
    # Extract static/runtime risks to embed
    static_risk = (static_results.get("bandit_issue_count", 0) + static_results.get("semgrep_issue_count", 0)) / 10.0
    runtime_risk = float(runtime_results.get("behavioral_risk", (
        runtime_results.get("subprocess_count", 0) + 
        runtime_results.get("system_call_count", 0) + 
        runtime_results.get("suspicious_network_activity", 0) + 
        runtime_results.get("file_access_risk", 0)
    ) / 10.0))
    
    for idx, node in enumerate(G.nodes()):
        node_mapping[node] = idx
        reverse_node_mapping[idx] = node
        attr = G.nodes[node]
        node_type = attr.get("type", "package")
        
        feat = [0.0] * 13
        
        if node_type == "package":
            pkg_key = node.lower()
            m = package_metadata_map.get(pkg_key, {})
            gf = graph_feats.get(pkg_key, {})
            
            # Map features
            feat[0] = np.log1p(m.get("downloads", 100000)) / 20.0
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
            # Inject SAST + Dynamic DAST
            pkg_static = static_results.get("packages", {}).get(pkg_key, {})
            if pkg_static:
                pkg_static_risk = (pkg_static.get("bandit_issue_count", 0) + pkg_static.get("semgrep_issue_count", 0)) / 10.0
            else:
                pkg_static_risk = 0.0
            feat[11] = min(pkg_static_risk, 1.0)
            
            import_name = pkg_key
            if pkg_key == "pyyaml":
                import_name = "yaml"
            elif pkg_key == "pytest-cov":
                import_name = "pytest_cov"
            elif pkg_key == "charset-normalizer":
                import_name = "charset_normalizer"
            
            pkg_runtime = {}
            for k in (pkg_key, import_name):
                pkg_runtime = runtime_results.get("packages", {}).get(k, {})
                if pkg_runtime:
                    break
            
            if pkg_runtime:
                total_calls = (
                    pkg_runtime.get("subprocess_count", 0) + 
                    pkg_runtime.get("system_call_count", 0) +
                    pkg_runtime.get("dynamic_execution_count", 0) +
                    pkg_runtime.get("suspicious_network_activity", 0) +
                    pkg_runtime.get("file_access_risk", 0)
                )
                pkg_runtime_risk = total_calls / 10.0
            else:
                pkg_runtime_risk = 0.0
            feat[12] = min(pkg_runtime_risk, 1.0)
            
            
        elif node_type == "version":
            feat[1] = 0.4
            feat[9] = attr.get("patch_delay", 10.0) / 365.0
            feat[10] = attr.get("release_burstiness", 0.3)
            
        elif node_type == "cve":
            feat[1] = attr.get("cvss_score", 5.0) / 10.0
            feat[11] = attr.get("exploitability", 0.5)
            
        elif node_type == "maintainer":
            feat[4] = 0.05
            feat[5] = attr.get("activity", 1.0) / 10.0
            
        x_list.append(feat)

    x = torch.tensor(x_list, dtype=torch.float)
    x.requires_grad = True # Enable grad for XAI Integrated Gradients / Saliency maps!
    
    edge_index_list = []
    for u, v in G.edges():
        edge_index_list.append([node_mapping[u], node_mapping[v]])
    
    edge_index = torch.tensor(edge_index_list, dtype=torch.long).t().contiguous()
    
    # 3. Load HGAT and LSTM models
    hgat = HGATModel(in_channels=13, hidden_channels=32, out_channels=1, heads=2)
    lstm = TemporalRiskLSTM(in_channels=4, hidden_size=16)
    
    if os.path.exists("outputs/hgat_model.pt"):
        hgat.load_state_dict(torch.load("outputs/hgat_model.pt"))
    if os.path.exists("outputs/temporal_model.pt"):
        lstm.load_state_dict(torch.load("outputs/temporal_model.pt"))
        
    hgat.eval()
    lstm.eval()
    
    # 4. Predict GraphRisk (HGAT) and extract GNN attention weights
    prob, att_edge_index, att_weights = hgat(x, edge_index, return_attention=True)
    
    # Map attention coefficients
    attention_map = {}
    att_edge_index_np = att_edge_index.numpy()
    att_weights_np = att_weights.detach().mean(dim=1).numpy() # Mean over attention heads
    
    for i in range(att_edge_index_np.shape[1]):
        u_idx, v_idx = att_edge_index_np[0, i], att_edge_index_np[1, i]
        u_node = reverse_node_mapping[u_idx]
        v_node = reverse_node_mapping[v_idx]
        attention_map.setdefault(u_node, {})[v_node] = float(att_weights_np[i])

    # 5. Compute Saliency map (XAI feature gradients) for each package node
    saliency_map = {}
    for pkg_key, pkg in resolved_packages.items():
        name = pkg["name"]
        if name in node_mapping:
            node_idx = node_mapping[name]
            node_prob = prob[node_idx]
            
            # Compute gradients of probability w.r.t inputs
            hgat.zero_grad()
            if x.grad is not None:
                x.grad = None
                
            node_prob.backward(retain_graph=True)
            
            node_grad = x.grad[node_idx].numpy()
            feature_importance = {}
            for f_idx, f_name in enumerate(FEATURE_NAMES):
                feature_importance[f_name] = float(abs(node_grad[f_idx]))
                
            # Normalize importance
            sum_imp = sum(feature_importance.values())
            if sum_imp > 0:
                feature_importance = {k: v / sum_imp for k, v in feature_importance.items()}
                
            saliency_map[name] = feature_importance

    # 6. Predict TemporalDrift (LSTM) for each package
    temporal_drifts = {}
    for key, pkg in resolved_packages.items():
        name = pkg["name"]
        m = package_metadata_map.get(key, {})
        vulns = vulnerability_details.get(key, [])
        max_c = max([v["cvss_score"] for v in vulns]) if vulns else 0.0
        
        # Build dynamic sequence of past states
        seq = []
        for step in range(5):
            seq.append([
                max((m.get("last_update_days", 10.0) + (4 - step) * 15.0), 0.1),
                1.0 if (vulns and step == 4) else 0.0,
                max_c / 10.0 if (vulns and step == 4) else 0.0,
                m.get("release_burstiness", 0.3)
            ])
            
        lstm_input = torch.tensor([seq], dtype=torch.float)
        with torch.no_grad():
            drift_score = lstm(lstm_input).item()
        temporal_drifts[name] = drift_score

    # 7. Synthesize final scores (Risk_t = 0.6 * GraphRisk + 0.4 * TemporalDrift)
    package_risks = {}
    confidence_scores = {}
    explanations = {}
    
    prob_np = prob.detach().numpy()
    
    for key, pkg in resolved_packages.items():
        name = pkg["name"]
        node_idx = node_mapping.get(name)
        
        if node_idx is not None:
            graph_risk = float(prob_np[node_idx][0])
            temporal_drift = temporal_drifts[name]
            
            # Formula:
            composite_risk = 0.6 * graph_risk + 0.4 * temporal_drift
            
            # Confidence score calculation: penalize high entropy predictions (around 0.5)
            # and penalize lack of metadata
            entropy_penalty = 1.0 - (abs(composite_risk - 0.5) * 2.0) # 0 to 1
            metadata_penalty = 0.0
            m = package_metadata_map.get(key, {})
            if m.get("stars") == 100 and m.get("downloads") == 100000: # Defaults indicators
                metadata_penalty = 0.1 # penalize slightly if using mock fallbacks
                
            confidence = 0.95 - (0.15 * entropy_penalty) - (0.10 * metadata_penalty)
            
            # Boost vulnerability risk if static / runtime analysis shows high values
            if static_risk > 0.5 or runtime_risk > 0.5:
                composite_risk = min(composite_risk + 0.15, 1.0)
                
            package_risks[name] = composite_risk
            confidence_scores[name] = confidence
            
            # XAI Explanation compilation
            feat_imp = saliency_map.get(name, {})
            top_features = sorted(feat_imp.items(), key=lambda x: x[1], reverse=True)[:3]
            
            # Neighbors attention weights
            neighbors_att = attention_map.get(name, {})
            top_neighbors = sorted(neighbors_att.items(), key=lambda x: x[1], reverse=True)[:3]
            
            explanations[name] = {
                "top_features": top_features,
                "top_influencing_nodes": top_neighbors,
                "graph_risk": graph_risk,
                "temporal_drift": temporal_drift
            }
        else:
            package_risks[name] = 0.1
            confidence_scores[name] = 0.90
            explanations[name] = {
                "top_features": [],
                "top_influencing_nodes": [],
                "graph_risk": 0.1,
                "temporal_drift": 0.1
            }

    # Project-level overall risk score
    if package_risks:
        project_risk_score = sum(package_risks.values()) / len(package_risks)
        # Apply static analysis penalty
        if static_risk > 0.5:
            project_risk_score = min(project_risk_score + 0.1, 1.0)
    else:
        project_risk_score = 0.1

    # 7.5. Compute RADV and Early Warning metrics
    radv_scores = {}
    blast_radius_scores = {}
    ttd_values = []
    
    for key, pkg in resolved_packages.items():
        name = pkg["name"]
        composite_risk = package_risks.get(name, 0.1)
        gf = graph_feats.get(key, {})
        blast_rad = gf.get("blast_radius", 0)
        
        # RADV calculation
        radv = composite_risk * (np.log10(blast_rad + 10))
        radv_scores[name] = float(radv)
        blast_radius_scores[name] = int(blast_rad)
        
        # Track TTD for simulated threat triggers (composite_risk > 0.40)
        if composite_risk > 0.40:
            ttd = max(1.0, 2.0 + (1.0 - composite_risk) * 48.0)
            ttd_values.append(ttd)

    if ttd_values:
        avg_ttd = np.mean(ttd_values)
        median_ttd = np.median(ttd_values)
        ttd_24h = sum(1 for t in ttd_values if t <= 24.0) / len(ttd_values) * 100.0
        ttd_72h = sum(1 for t in ttd_values if t <= 72.0) / len(ttd_values) * 100.0
        edr = sum(1 for t in ttd_values if t <= 12.0) / len(ttd_values) * 100.0
    else:
        avg_ttd = 0.0
        median_ttd = 0.0
        ttd_24h = 100.0
        ttd_72h = 100.0
        edr = 100.0
        
    early_warning_metrics = {
        "detection_latency_hours": float(avg_ttd),
        "median_ttd_hours": float(median_ttd),
        "ttd_at_24h_percent": float(ttd_24h),
        "ttd_at_72h_percent": float(ttd_72h),
        "early_detection_rate_percent": float(edr)
    }

    return {
        "package_risks": package_risks,
        "project_risk_score": project_risk_score,
        "confidence_scores": confidence_scores,
        "attack_paths": risk_prop_results["attack_paths"],
        "transitive_risks": risk_prop_results["package_risks"],
        "explanations": explanations,
        "graph": G,
        "radv_scores": radv_scores,
        "blast_radius_scores": blast_radius_scores,
        "early_warning_metrics": early_warning_metrics
    }
