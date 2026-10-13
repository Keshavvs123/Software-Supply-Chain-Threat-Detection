# Software Supply-Chain Threat Detection Gatekeeper: Comprehensive Project Overview

This document provides a comprehensive technical overview of the Supply Chain Threat Detection Gatekeeper project. It can be used as a project report, reference sheet, or presentation guide.

---

## 1. Executive Summary & Problem Domain

### The Threat Landscape
Modern software development is heavily dependent on open-source package repositories (such as PyPI, npm, and Maven). While these repositories accelerate development velocity, they have become a major vector for supply-chain attacks. Typical attacks include:
* **Typosquatting**: Uploading malicious packages with names close to popular ones (e.g. `reqeusts` vs `requests`).
* **Dependency Confusion**: Exploit internal package namespaces to force public repository fetches instead of private networks.
* **Maintainer Account Hijack**: Compromising developer accounts to push malicious updates containing backdoors or infostealers.

### Core Solution
Rather than running a standard, unmonitored host installation (which executes setup scripts on local machines), this system intercepts installation requests using a **Pre-Install Quarantine Gatekeeper**. 
* Packages are first fetched into a local sandbox quarantine.
* An AI-driven **Multimodal Threat Detection Engine** (GNN + LSTM) evaluates the risk levels.
* Results are displayed in a visual dashboard for administrator approval before host compilation.

---

## 2. Multimodal AI Security Architecture

The framework evaluates dependency threat profiles using **five distinct analysis modalities (C-M-G-B-T)**, fusing their indicators to compute a final risk probability:

### Modality 1: Source Code (C)
* **Static Analysis**: Scans source directories for security flags using **Bandit** and **Semgrep** rulesets.
* **Obfuscation Checking**: Calculates **Shannon Entropy** to identify high-entropy strings (indicative of base64 payloads, encrypted shellcode, or packed binaries).
* **AST Complexity**: Maps Abstract Syntax Tree properties to find nested, suspicious imports and dynamic executions (`eval`, `exec`, `importlib.import_module`).

### Modality 2: Package Metadata (M)
* **Reputation Analytics**: Inspects the package's age, release frequency, total downloads, and maintainer counts.
* **Vulnerability History**: Maps known CVE metadata and OpenSSF security scorecards. Newer packages with abnormally low download rates receive elevated base risk flags.

### Modality 3: Graph Topology (G)
* **Dependency Risk Propagation**: Models transitive package relationships as a heterogeneous directed dependency graph.
* **Heterogeneous Graph Attention Network (HGAT)**: Analyzes target dependencies and propagates risk features from deep transit nodes up to the top-level application boundaries.

### Modality 4: Behavioral Telemetry (B)
* **Sandboxed Quarantine Execution**: Runs the package within a secure virtual sandbox/quarantine container.
* **Syscall Tracing**: Monitors dynamic activities, flagging anomalies such as:
  * Spawning unexpected subprocesses.
  * Attempting to write to system folders (file access risks).
  * Initiating unsolicited outbound socket connections (suspicious network activity).

### Modality 5: Temporal Drift (T)
* **Sequential Release Profiling**: Models the release interval trends over time.
* **Temporal LSTM**: Detects sequence anomalies. A sudden spike in release frequency (burstiness) or publication of a new release after a long dormancy period often signals a hijacked maintainer account.

---

## 3. Operational Workflow

```mermaid
graph TD
    A[requirements.txt Uploaded] --> B[SBOM Generator CycloneDX / SPDX]
    B --> C[Fetch PyPI package source into Sandbox]
    C --> D[Static Code Scans: Bandit, Semgrep, AST]
    C --> E[Vulnerability Lookup: OSV.dev, NVD Cache]
    C --> F[Enrich Package Metadata profiles]
    D --> G[AI Risk Predictor Engine]
    E --> G
    F --> G
    G --> H[Run HGAT GNN & Temporal LSTM models]
    H --> I[Generate Interactive Dashboard]
    I --> J[User Approves or Aborts Installation]
    J -- Approved --> K[pip install on Host machine]
    J -- Aborted --> L[Clean staging directories]
```

---

## 4. Evaluation Performance & Results

To evaluate the system, we performed a systematic **Ablation Study** across baseline configurations M1–M5 and the proposed system on **24,666 real-world packages and 79,741 graph edges** (evaluated on 3,700 held-out test packages):

* **M1–M3 (Unimodal Baselines)**: Relying strictly on flat features (topology-only, GitHub-only, or release cadence-only) caps detection accuracy near random chance (~50.5%–51.0%).
* **M4–M5 (Classical ML Baselines)**: Logistic Regression (50.76% Acc) and Random Forest (50.86% Acc, 64.16% Recall) fail on supply chain cascades because flat tabular vectors cannot represent deep transitive dependency graphs.
* **Proposed System (Multi-Head HGAT GNN + Temporal LSTM Fusion)**:
  * **Test Accuracy**: **84.89%** (vs. 50.86% Random Forest baseline)
  * **Threat Detection Recall**: **97.24%** (intercepting nearly all supply chain threat vectors)
  * **F1-Score**: **0.8678** (86.78%)
  * **Precision**: **78.34%** (0.7834)
  * **ROC-AUC & PR-AUC**: **0.8617 ROC-AUC** and **0.8933 PR-AUC**
  * **False Positive Rate (FPR)**: Dropped from 63.0% (RF) down to **27.9%**
* **Early Warning Capacity & Latency**:
  * **Median Time-To-Detection (TTD)**: **14.6 hours**
  * **Intercepted within 24 Hours (TTD@24h)**: **71.4%**
  * **Intercepted within 72 Hours (TTD@72h)**: **100.0%**
  * **Early Detection Rate (EDR)**: **42.9%**

---

## 5. Directory & Codebase Navigation

When demonstrating or presenting the project codebase:
* **[`main.py`](file:///c:/Users/keshav/OneDrive/Documents/caps_pjct/project/project/main.py)**: The central control hub. Handles HTTP request routes, scans uploaded requirements, triggers the prediction pipelines, and updates the local package installation database.
* **[`dependency_analysis/`](file:///c:/Users/keshav/OneDrive/Documents/caps_pjct/project/project/dependency_analysis/)**: Parses dependencies, matches OSV caches, and prints the ASCII dependency risk tree inside the terminal.
* **[`ml_engine/`](file:///c:/Users/keshav/OneDrive/Documents/caps_pjct/project/project/ml_engine/)**: Holds the neural architectures:
  * [`hgat_model.py`](file:///c:/Users/keshav/OneDrive/Documents/caps_pjct/project/project/ml_engine/hgat_model.py): The PyTorch GNN implementation.
  * [`temporal_model.py`](file:///c:/Users/keshav/OneDrive/Documents/caps_pjct/project/project/ml_engine/temporal_model.py): The LSTM sequence anomaly classifier.
  * [`trainer.py`](file:///c:/Users/keshav/OneDrive/Documents/caps_pjct/project/project/ml_engine/trainer.py): The model training pipeline.
* **[`visualization/dashboard.py`](file:///c:/Users/keshav/OneDrive/Documents/caps_pjct/project/project/visualization/dashboard.py)**: Generates the glassmorphic interactive security monitoring dashboard.
* **[`graphs/`](file:///c:/Users/keshav/OneDrive/Documents/caps_pjct/project/project/graphs)** & **[`outputs/`](file:///c:/Users/keshav/OneDrive/Documents/caps_pjct/project/project/outputs)**: Directory housing model metrics, ROC/PR curves, and ablated early-warning plots.
