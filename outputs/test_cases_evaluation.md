# Comprehensive Supply-Chain Threat Evaluation: 10 Test Cases Report
This report documents the end-to-end detection, neural risk scoring, and gatekeeper verdict across 10 distinct supply-chain attack vectors and clean baselines.
| Case ID | Scenario Name | Target Package | Vector | Composite Risk | Threats Identified | Gatekeeper Verdict | Result |
| :--- | :--- | :--- | :---: | :---: | :--- | :--- | :---: |
| **TC-01** | Typosquatting Supply-Chain Injection | `reqeusts==2.28.1` | T1 | **53.2%** | T1, T6 | ⛔ **QUARANTINED** | MATCHED (PASS) |
| **TC-02** | Dependency Confusion Namespace Shadowing | `internal-auth-token==0.1.0` | T2 | **48.8%** | T2, T6 | ⛔ **QUARANTINED** | MATCHED (PASS) |
| **TC-03** | Malicious Install-Hook Backdoor in setup.py | `setup-cmdclass-backdoor==1.0.0` | T5 | **86.8%** | T5 | ⛔ **QUARANTINED** | MATCHED (PASS) |
| **TC-04** | High-Entropy Obfuscated Payload with Dynamic Exec | `pyobfuscate-payload==1.2.0` | T5 | **87.2%** | T5 | ⛔ **QUARANTINED** | MATCHED (PASS) |
| **TC-05** | Deep Transitive Multi-Hop Attack Path | `innocent-web-wrapper==2.4.0` | T6 | **50.4%** | T6 | ⛔ **QUARANTINED** | MATCHED (PASS) |
| **TC-06** | Compromised Maintainer Account Hijack | `ctx==0.1.2` | T3 | **79.2%** | T3 | ⛔ **QUARANTINED** | MATCHED (PASS) |
| **TC-07** | Malicious Release Cadence Spike & Burst Anomaly | `pytz-ultra==2024.1.9` | T4 | **72.6%** | T1, T4, T6 | ⛔ **QUARANTINED** | MATCHED (PASS) |
| **TC-08** | Altered Artifact / Checksum Digest Discrepancy | `tampered-crypto-tool==1.4.2` | Integrity | **76.0%** | Tamper | ⛔ **QUARANTINED** | MATCHED (PASS) |
| **TC-09** | Unauthorized Dial-Home C2 Exfiltration Telemetry | `dialhome-spyware==0.3.1` | Telemetry | **76.2%** | None | ⛔ **QUARANTINED** | MATCHED (PASS) |
| **TC-10** | Verified Clean Standard Library (Benign Control) | `pydantic==2.8.2` | Benign | **6.8%** | None | ✅ **APPROVED** | MATCHED (PASS) |

---

## Detailed Test Case Audit Logs

### TC-01: Typosquatting Supply-Chain Injection
- **Package**: `reqeusts==2.28.1`
- **Threat Vector**: `T1`
- **Description**: Adversary publishes 'reqeusts' mimicking popular 'requests' library to execute malicious code on developer typos.
- **Neural Predictions**: HGAT GNN Risk = `0.7200`, Temporal LSTM Drift = `0.2500`, Composite Risk = `53.2%` (Confidence: `93.7%`)
- **Checksum Provenance**: `VALID`
- **Gatekeeper Action**: `QUARANTINED (BLOCKED)`
- **Remediation**: Block pip install 'reqeusts'. Quarantine artifact in staging sandbox. Inspect provenance manifest.

### TC-02: Dependency Confusion Namespace Shadowing
- **Package**: `internal-auth-token==0.1.0`
- **Threat Vector**: `T2`
- **Description**: Adversary publishes 'internal-auth-token' on public PyPI shadowing internal private corporate microservice package.
- **Neural Predictions**: HGAT GNN Risk = `0.6800`, Temporal LSTM Drift = `0.2000`, Composite Risk = `48.8%` (Confidence: `93.9%`)
- **Checksum Provenance**: `VALID`
- **Gatekeeper Action**: `QUARANTINED (BLOCKED)`
- **Remediation**: Block pip install 'internal-auth-token'. Quarantine artifact in staging sandbox. Inspect provenance manifest.

### TC-03: Malicious Install-Hook Backdoor in setup.py
- **Package**: `setup-cmdclass-backdoor==1.0.0`
- **Threat Vector**: `T5`
- **Description**: Package overrides build/install cmdclass in setup.py to execute bash shell commands and drop backdoor upon pip installation.
- **Neural Predictions**: HGAT GNN Risk = `0.8800`, Temporal LSTM Drift = `0.3500`, Composite Risk = `86.8%` (Confidence: `90.3%`)
- **Checksum Provenance**: `VALID`
- **Gatekeeper Action**: `QUARANTINED (BLOCKED)`
- **Remediation**: Block pip install 'setup-cmdclass-backdoor'. Quarantine artifact in staging sandbox. Inspect provenance manifest.

### TC-04: High-Entropy Obfuscated Payload with Dynamic Exec
- **Package**: `pyobfuscate-payload==1.2.0`
- **Threat Vector**: `T5`
- **Description**: Source files contain heavily packed multi-layer base64/hex blobs decoded dynamically into eval() and exec().
- **Neural Predictions**: HGAT GNN Risk = `0.9200`, Temporal LSTM Drift = `0.3000`, Composite Risk = `87.2%` (Confidence: `90.3%`)
- **Checksum Provenance**: `VALID`
- **Gatekeeper Action**: `QUARANTINED (BLOCKED)`
- **Remediation**: Block pip install 'pyobfuscate-payload'. Quarantine artifact in staging sandbox. Inspect provenance manifest.

### TC-05: Deep Transitive Multi-Hop Attack Path
- **Package**: `innocent-web-wrapper==2.4.0`
- **Threat Vector**: `T6`
- **Description**: Direct library appears clean with 0 static security issues, but transitively imports deeply nested backdoored dependency 3 hops away.
- **Neural Predictions**: HGAT GNN Risk = `0.7400`, Temporal LSTM Drift = `0.1500`, Composite Risk = `50.4%` (Confidence: `94.0%`)
- **Checksum Provenance**: `VALID`
- **Gatekeeper Action**: `QUARANTINED (BLOCKED)`
- **Remediation**: Block pip install 'innocent-web-wrapper'. Quarantine artifact in staging sandbox. Inspect provenance manifest.

### TC-06: Compromised Maintainer Account Hijack
- **Package**: `ctx==0.1.2`
- **Threat Vector**: `T3`
- **Description**: Legitimate popular package with >500k downloads undergoes maintainer abandonment, rapid maintainer churn, and unauthorized credential takeover.
- **Neural Predictions**: HGAT GNN Risk = `0.7900`, Temporal LSTM Drift = `0.4200`, Composite Risk = `79.2%` (Confidence: `91.1%`)
- **Checksum Provenance**: `VALID`
- **Gatekeeper Action**: `QUARANTINED (BLOCKED)`
- **Remediation**: Block pip install 'ctx'. Quarantine artifact in staging sandbox. Inspect provenance manifest.

### TC-07: Malicious Release Cadence Spike & Burst Anomaly
- **Package**: `pytz-ultra==2024.1.9`
- **Threat Vector**: `T4`
- **Description**: Dormant library suddenly publishes rapid burst releases with interval deviance >3.5 sigma outside historical baseline.
- **Neural Predictions**: HGAT GNN Risk = `0.6500`, Temporal LSTM Drift = `0.8400`, Composite Risk = `72.6%` (Confidence: `91.7%`)
- **Checksum Provenance**: `VALID`
- **Gatekeeper Action**: `QUARANTINED (BLOCKED)`
- **Remediation**: Block pip install 'pytz-ultra'. Quarantine artifact in staging sandbox. Inspect provenance manifest.

### TC-08: Altered Artifact / Checksum Digest Discrepancy
- **Package**: `tampered-crypto-tool==1.4.2`
- **Threat Vector**: `Integrity`
- **Description**: Wheel archive bytecode modified in transit; downloaded file SHA256 does not match CycloneDX SBOM provenance manifest.
- **Neural Predictions**: HGAT GNN Risk = `0.5500`, Temporal LSTM Drift = `0.2000`, Composite Risk = `76.0%` (Confidence: `91.4%`)
- **Checksum Provenance**: `MISMATCH_CORRUPTED (Expected: a1b2c3d4..., Actual: f9e8d7c6...)`
- **Gatekeeper Action**: `QUARANTINED (BLOCKED)`
- **Remediation**: Block pip install 'tampered-crypto-tool'. Quarantine artifact in staging sandbox. Inspect provenance manifest.

### TC-09: Unauthorized Dial-Home C2 Exfiltration Telemetry
- **Package**: `dialhome-spyware==0.3.1`
- **Threat Vector**: `Telemetry`
- **Description**: Package imports socket/urllib to establish unauthorized outbound connection to foreign IP upon package import.
- **Neural Predictions**: HGAT GNN Risk = `0.8200`, Temporal LSTM Drift = `0.3000`, Composite Risk = `76.2%` (Confidence: `91.4%`)
- **Checksum Provenance**: `VALID`
- **Gatekeeper Action**: `QUARANTINED (BLOCKED)`
- **Remediation**: Block pip install 'dialhome-spyware'. Quarantine artifact in staging sandbox. Inspect provenance manifest.

### TC-10: Verified Clean Standard Library (Benign Control)
- **Package**: `pydantic==2.8.2`
- **Threat Vector**: `Benign`
- **Description**: Standard, well-maintained foundational library with high star count, robust commit velocity, and zero security anomalies.
- **Neural Predictions**: HGAT GNN Risk = `0.0800`, Temporal LSTM Drift = `0.0500`, Composite Risk = `6.8%` (Confidence: `89.7%`)
- **Checksum Provenance**: `VALID`
- **Gatekeeper Action**: `APPROVED (CLEAN)`
- **Remediation**: Safe to install. Automated integrity checks and neural anomaly scoring verified clean.

