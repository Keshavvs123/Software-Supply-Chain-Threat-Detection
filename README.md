# Temporal Multimodal Software Supply-Chain Threat Detection Engine

An AI-driven pre-installation security gatekeeper that intercepts, evaluates, and neutralizes software supply chain threats (typosquatting, dependency confusion, malicious releases, transitive vulnerability cascades, and compromised maintainers) before packages reach developer machines.

The system combines a **Multi-Head Heterogeneous Graph Attention Network (HGAT GNN)** with a **Temporal Long Short-Term Memory (LSTM)** anomaly classifier to evaluate transitive risk propagation and flag package release drift. (The temporal LSTM is a prototype trained on synthetic release sequences; see Section 3.)

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

The framework was trained and evaluated on **24,666 real-world packages and 79,741 dependency graph edges** from `Supply_Chain_Risk_Dataset_v2.xlsx`, split with a **stratified random** 70/15/15 partition (fixed seed 42; 17,266 train / 3,700 val / 3,700 held-out test packages). The split is **not chronological**: the dataset is a single snapshot with no release dates to split on. The label is `is_vulnerable_any`, i.e. whether a package has any known vulnerability.

### 2.1 Ablation Study & Baseline Comparison Table

*Values below are from the last recorded run (`outputs/ablation_study_results.csv`). Re-run `ml_engine/train_full_dataset.py` and copy the numbers from the regenerated CSV; the CSV is the single source of truth. The re-run also adds two control rows (degree-only baseline and a shuffled-edge GNN) described in 2.3.*

| Model Configuration | Accuracy | Threat Recall | F1-Score | Precision | ROC-AUC | PR-AUC | False Positive Rate (FPR) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **M1 (Dependency Topology Only)** | 50.57% | 67.87% | 0.5833 | 0.5114 | 0.5034 | 0.5415 | 67.4% |
| **M2 (GitHub Health Only)** | 50.97% | 100.0% | 0.6753 | 0.5097 | 0.5000 | 0.7549 | 100.0% |
| **M3 (PyPI Release Cadence Only)** | 51.03% | 77.62% | 0.6177 | 0.5130 | 0.5061 | 0.5524 | 76.6% |
| **M4 (Logistic Regression Baseline)** | 50.76% | 65.11% | 0.5741 | 0.5134 | 0.5111 | 0.5558 | 64.2% |
| **M5 (Random Forest Baseline)** | 50.86% | 64.16% | 0.5710 | 0.5145 | 0.5089 | 0.5444 | 63.0% |
| **Control: Degree-only LR** | 50.54% | 64.85% | 0.5720 | 0.5117 | 0.5082 | 0.5523 | 64.3% |
| **Control: HGAT with shuffled edges** | 83.57% | 96.34% | 0.8567 | 0.7712 | 0.8451 | 0.7768 | 29.7% |
| **Proposed HGAT GNN (Full System)** | **84.46%** | **97.08%** | **0.8643** | **0.7788** | **0.8543** | **0.8497** | **28.7%** |

*Key Findings*:
* The flat-feature baselines score close to chance (about $51\%$ accuracy, ROC-AUC about $0.50$). One reason is that most GitHub/PyPI feature columns are mostly empty in the dataset (see 2.2), so those baselines have little signal to learn from.
* The HGAT GNN reaches **$84.46\%$ accuracy** and **$97.08\%$ recall** on the held-out split, with a **$28.7\%$** false positive rate (Random Forest: $63.0\%$).
* The **shuffled-edge control GNN scores $83.57\%$ accuracy** — only $0.9\%$ below the real GNN. This shows the model is primarily learning structural/degree patterns (e.g. vulnerable packages have fewer dependency edges) rather than pure transitive risk propagation. This is acknowledged as a dataset limitation and does not invalidate the full pipeline's value.
* The gap to the baselines is unusually large. Before claiming it comes from "learning transitive risk", check it against the control rows in 2.3.

### 2.2 Dataset Limitations (read before citing the numbers)

* **Sparse metadata:** the GitHub and PyPI feature columns are 98-100% empty. Missing values are filled with constants, so the "metadata" modality carries very little real information.
* **Class structure differs:** about 91% of vulnerable packages have no dependency edges versus about 72% of safe packages, and safe packages have more dependencies on average (6.5 vs 3.2). A graph model can exploit this structural difference without learning real risk.
* **Label meaning:** `is_vulnerable_any` marks known vulnerabilities; the model predicts that flag, not future compromise.
* **Snapshot data:** there is no release history, so the temporal component cannot be evaluated on this dataset.

### 2.3 Control Experiments

`train_full_dataset.py` also trains (a) a logistic regression on dependency/degree counts only and (b) the same GNN on randomly rewired edges. If either comes close to the full GNN, the reported advantage is largely explained by degree/structure effects rather than meaningful graph propagation. Report both rows alongside the headline result.

---

## 3. Early Warning & Interception Latency (SIMULATED)

Time-To-Detection (TTD) and Early Detection Rate (EDR) shown by the dashboard and CLI are **simulated, not measured**: TTD is derived from the composite risk score with a fixed formula, and the LSTM is trained on synthetic release sequences. They illustrate the intended behaviour only and must not be cited as empirical results. Measuring them needs real, timestamped release/compromise data.

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
# Install Gatekeeper's own dependencies:
pip install -r project_requirements.txt

# Only needed for live NVD lookups (never commit the key):
export NVD_API_KEY=your_key      # Windows: setx NVD_API_KEY your_key
```

> **Note:** `requirements.txt` at the project root is the **demo scan target** — drag it into the
> dashboard to test the scanner. It is not the Gatekeeper's own dependency manifest.

### 5.2 Running the Interactive Web Gatekeeper Dashboard
```bash
python main.py
```
* Starts the server at **`http://localhost:5000/`** (bound to 127.0.0.1 only).
* Security notes: the runtime monitor *executes* the scanned code on your machine, so scan untrusted projects inside a container/VM (or set `GATEKEEPER_DISABLE_RUNTIME=1`). `/install` accepts only plain requirement lines and installs wheels only.
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
* Trains the 12-feature benchmark GNN for 100 epochs on the training split, evaluates on the held-out test split, writes `outputs/ablation_study_results.csv`, `outputs/ablation_table.md`, `outputs/hgat_full_eval.pt` and the plots in `graphs/`.
* Then run `python scripts/update_all_graphs_real.py` to redraw the comparison plots from the CSV.
* **Important:** the scanner (`main.py`) uses a different, 13-feature `HGATModel` whose weights (`outputs/hgat_model.pt`) come from the small seed-data bootstrap in `ml_engine/trainer.py`. It is *not* the benchmarked model, so the benchmark metrics describe `hgat_full_eval.pt` only.

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
│   ├── hgat_model.pt               # Scanner GNN weights (seed bootstrap, 13 features)
│   ├── hgat_full_eval.pt           # Benchmark GNN weights (12 features)
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
├── test_pipeline.py                # Automated end-to-end CLI pipeline
├── requirements.txt                # Demo scan target (drag into dashboard to test)
└── project_requirements.txt        # Gatekeeper's own install dependencies
```
