# Temporal Multimodal Software Supply-Chain Threat Detection Engine

An AI-driven pre-installation security gatekeeper that intercepts, evaluates, and neutralizes software supply chain threats (typosquatting, dependency confusion, malicious releases, transitive vulnerability cascades, and compromised maintainers) before packages reach developer machines.

The system combines a **Multi-Head Heterogeneous Graph Attention Network (HGAT GNN)** with a **Temporal Long Short-Term Memory (LSTM)** anomaly classifier to evaluate transitive risk propagation and chronologically detect package release drift.

---

## 👥 Project Team & Work Division

* **Keshav (Lead)**: Pre-installation quarantine workflow, Multi-Head HGAT GNN modeling (`ml_engine/hgat_model.py`, `ml_engine/train_full_dataset.py`), Risk Fusion ($0.6\text{ GNN} + 0.4\text{ LSTM}$), RADV scoring, and HTTP Backend Server (`main.py`).
* **Hamsa**: Dependency graph builder (`graph_intelligence/graph_builder.py`), NetworkX topological metrics (Blast Radius, PageRank), and Temporal LSTM anomaly detection (`ml_engine/temporal_model.py`).
* **Moeen (Moen)**: Static code & AST visitor (`PyASTSecurityVisitor`), Shannon Entropy obfuscation detector ($H > 4.5$), and Bandit & Semgrep SAST integration.
* **Tejas**: CycloneDX / SPDX SBOM pipeline (`sbom/generator.py`, `sbom/npm_generator.py`), Local SQLite CVE database (`dependency_analysis/cve_db.py`), Automated Remediation engine (`dependency_analysis/remediator.py`), and Glassmorphic Dashboard (`visualization/dashboard.py`).

---

## 1. System Architecture & Multimodal Pipeline

The framework analyzes software dependencies across 5 complementary security modalities:

1. **Source Code (C)**: AST structural visitor (`eval`, `exec`, `os.system`), Shannon entropy obfuscation analysis ($H > 4.5$), and Bandit/Semgrep static analyzers.
2. **Metadata & Reputation (M)**: Downloads, stars, OpenSSF scorecard, release intervals, and maintainer account churn.
3. **Graph Topology (G)**: 4-Head HGAT GNN modeling transitive dependency trees across 79,741 edges and calculating reachability Blast Radius.
4. **Behavioral Telemetry (B)**: Sandboxed quarantine tracing measuring dynamic function executions, system calls, subprocesses, and unauthorized network/file access.
5. **Temporal Sequence (T)**: LSTM tracking historical release velocity, version cadence anomalies, and sudden burstiness flags.

```
Ingestion (requirements.txt / package-lock.json)
       │
       ▼
Pre-Install Quarantine Staging (CycloneDX & SPDX SBOM)
       │
   ┌───┴───────────────────────────────┐
   ▼                                   ▼
Static AST & Shannon Entropy    Local SQLite CVE Database
   │                                   │
   └───────────────┬───────────────────┘
                   ▼
     NetworkX Dependency Graph (79,741 Edges)
                   │
         ┌─────────┴─────────┐
         ▼                   ▼
Multi-Head HGAT GNN    Temporal LSTM
 (Graph Propagation)   (Release Drift)
         │                   │
         └─────────┬─────────┘
                   ▼
     Composite Risk Fusion (0.6 GNN + 0.4 LSTM)
     + Explainable AI (XAI Saliency Gradients)
                   │
         ┌─────────┴─────────┐
         ▼                   ▼
Interactive Dashboard    Automated Safe Upgrade Solver
(http://localhost:5000)  (outputs/remediation_plan.json)
```

---

## 2. Empirical Benchmark Evaluation (24,666 Real Packages)

The framework was trained and evaluated on **24,666 real-world packages and 79,741 dependency graph edges** from `Supply_Chain_Risk_Dataset_v2.xlsx`, split chronologically using a stratified 70/15/15 partition (17,266 train / 3,700 val / 3,700 held-out test packages).

### 2.1 Ablation Study & Baseline Comparison Table

| Model Configuration | Accuracy | Threat Recall | F1-Score | Precision | ROC-AUC | PR-AUC | False Positive Rate (FPR) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **M1 (Dependency Topology Only)** | 50.57% | 67.87% | 0.5833 | 0.5114 | 0.5034 | 0.5415 | 67.4% |
| **M2 (GitHub Health Only)** | 50.97% | 100.0% | 0.6753 | 0.5097 | 0.5000 | 0.7549 | 100.0% |
| **M3 (PyPI Release Cadence Only)** | 51.03% | 77.62% | 0.6177 | 0.5130 | 0.5061 | 0.5524 | 76.6% |
| **M4 (Logistic Regression Baseline)** | 50.76% | 65.11% | 0.5741 | 0.5134 | 0.5111 | 0.5558 | 64.2% |
| **M5 (Random Forest Baseline)** | 50.86% | 64.16% | 0.5710 | 0.5145 | 0.5089 | 0.5444 | 63.0% |
| **Proposed HGAT GNN (Full System)** | **84.89%** | **97.24%** | **0.8678** | **0.7834** | **0.8617** | **0.8933** | **27.9%** |

*Key Findings*:
* Classical classifiers (Random Forest at $50.86\%$ accuracy) fail to capture deep transitive infections because graph relationships cannot be represented in flat feature matrices.
* The proposed Multi-Head HGAT GNN achieves **$84.89\%$ Accuracy** and **$97.24\%$ Recall**, reducing the False Positive Rate from $63.0\%$ to **$27.9\%$**.

---

## 3. Early Warning & Interception Latency

* **Median Time-To-Detection (TTD)**: **14.6 hours**
* **Interception Rate within 24 Hours (TTD@24h)**: **71.4%**
* **Interception Rate within 72 Hours (TTD@72h)**: **100.0%**
* **Early Detection Rate (EDR)**: **42.9%**

---

## 4. Key Capabilities & Features

### 4.1 ⚡ Local Offline SQLite CVE Database (`outputs/cve_database.sqlite`)
* Pre-indexed local database providing **$< 0.1\text{ ms}$ zero-latency offline lookups** without network dependency.

### 4.2 🛡️ Automated Self-Healing Remediation (`outputs/remediation_plan.json`)
* Generates minimal, non-breaking safe upgrade recipes with 1-click `pip install --upgrade ...` commands for vulnerable transitive dependencies.

### 4.3 🌐 Multi-Ecosystem Support (Python + Node.js)
* Supports both Python (`requirements.txt`, wheels, sdist) and Node.js (`package-lock.json` v1/v2/v3, `package.json`).

### 4.4 ⚙️ GitHub Actions CI/CD Workflow (`.github/workflows/security-gatekeeper.yml`)
* Automated DevSecOps gatekeeper that scans pull requests and blocks builds containing critical supply chain threats.

### 4.5 🧠 Explainable AI (XAI)
* Uses gradient backpropagation and Graph Attention weights to rank the top mathematical drivers behind every risk score.

---

## 5. Setup & Running Instructions

### 5.1 Installation
```bash
pip install torch networkx pandas numpy scikit-learn bandit semgrep requests warcio openpyxl
```

### 5.2 Running the Interactive Web Gatekeeper Dashboard
```bash
python main.py
```
* Starts the server at **`http://localhost:5000/`**.
* Drag and drop `test_project/requirements.txt` to inspect the D3.js dependency graph, attack paths, XAI saliency bars, and remediation cards.

### 5.3 Running the Automated CLI Scan Pipeline
```bash
python test_pipeline.py
```
* Scans target packages end-to-end, displays the ASCII dependency tree with vulnerability tags, and outputs audit CSV reports.

### 5.4 Re-Training the GNN on the Full Dataset
```bash
python ml_engine/train_full_dataset.py
```
* Runs 100 training epochs on 17,266 packages and updates all empirical plots in `graphs/`.

---

## 6. Project Structure

```
├── .github/workflows/
│   └── security-gatekeeper.yml     # Automated CI/CD PR scanning action
├── data_pipeline/
│   └── enricher.py                 # PyPI/GitHub metadata & CVE database logger
├── dataset/
│   └── Supply_Chain_Risk_Dataset_v2.xlsx  # 24,666 real package dataset
├── dependency_analysis/
│   ├── cve_db.py                   # Local SQLite CVE database
│   ├── dependency_scanner.py       # Vulnerability scanner & tree builder
│   ├── remediator.py               # Automated safe version solver
│   └── threat_model.py             # Threat vectors T1-T6 classifier
├── graph_intelligence/
│   └── graph_builder.py            # NetworkX dependency graph & blast radius
├── graphs/                         # 13 Empirical publication plots
├── ml_engine/
│   ├── hgat_model.py               # Multi-Head HGAT PyTorch architecture
│   ├── predictor.py                # Risk Fusion & XAI Saliency engine
│   ├── temporal_model.py           # Temporal LSTM anomaly detector
│   └── train_full_dataset.py       # 100-epoch full dataset training script
├── outputs/
│   ├── ablation_study_results.csv  # Empirical test metrics
│   ├── cve_database.sqlite         # Local offline CVE database
│   ├── hgat_model.pt               # Trained GNN weights
│   ├── remediation_plan.json       # Automated remediation recipes
│   ├── sbom.json                   # CycloneDX v1.4 SBOM
│   ├── sbom.spdx                   # SPDX 2.2 SBOM
│   └── scan_results.csv            # Consolidated security audit CSV
├── runtime_behaviour/
│   └── monitor.py                  # Behavioral execution telemetry tracer
├── sbom/
│   ├── generator.py                # Python SBOM generator & metadata resolver
│   └── npm_generator.py            # Node.js / npm lockfile dependency parser
├── static_analysis/
│   └── analyzer.py                 # AST visitor, Shannon entropy, Bandit & Semgrep
├── visualization/
│   └── dashboard.py                # Interactive Glassmorphic Web Dashboard
├── main.py                         # Live HTTP Server & Gatekeeper orchestrator
└── test_pipeline.py                # Automated end-to-end CLI pipeline
```
