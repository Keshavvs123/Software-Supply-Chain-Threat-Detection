"""
Centralized Configuration Module for Software Supply-Chain Threat Detection Gatekeeper.
Defines risk fusion weights, threat vector thresholds (T1-T6), HTTP timeouts, and filesystem paths.
"""

import os

# ==============================================================================
# 1. FILESYSTEM PATHS
# ==============================================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, "dataset", "Supply_Chain_Risk_Dataset_v2.xlsx")
OUTPUTS_DIR = os.path.join(BASE_DIR, "outputs")
GRAPHS_DIR = os.path.join(BASE_DIR, "graphs")
SQLITE_DB_PATH = os.path.join(OUTPUTS_DIR, "cyber_intel_db.sqlite")

# ==============================================================================
# 2. RISK FUSION WEIGHTS & PENALTIES
# ==============================================================================
GNN_WEIGHT = 0.60
LSTM_WEIGHT = 0.40
STATIC_PENALTY_BOOST = 0.15
CRITICAL_STATIC_PENALTY_BOOST = 0.30

# Risk classification thresholds
RISK_THRESHOLD_LOW = 0.30
RISK_THRESHOLD_MEDIUM = 0.60
RISK_THRESHOLD_HIGH = 0.80

# ==============================================================================
# 3. THREAT VECTOR THRESHOLDS (T1 - T6)
# ==============================================================================
# T1: Typosquatting
TYPOSQUAT_MAX_DISTANCE = 2
TYPOSQUAT_MIN_NAME_LEN = 4
TYPOSQUAT_CANDIDATE_LIMIT = 250

# T2: Dependency Confusion
INTERNAL_NAMESPACE_PREFIXES = [
    "internal", "corp", "company", "private", "local", "pkg", "core-internal", "sec"
]

# T3: Compromised Maintainer
MAINTAINER_DOWNLOAD_THRESHOLD = 50000
MAINTAINER_CHURN_THRESHOLD = 0.40
MAINTAINER_COMMIT_ACTIVITY_THRESHOLD = 0.30

# T4: Malicious Release Anomaly
RELEASE_BURSTINESS_THRESHOLD = 0.50
RELEASE_ANOMALY_ZSCORE_THRESHOLD = 2.50
CRITICAL_BURSTINESS_THRESHOLD = 0.75

# T5: Obfuscated Payloads
SHANNON_ENTROPY_THRESHOLD = 6.20
ENCODED_STRING_RATIO_THRESHOLD = 0.15
EVAL_EXEC_ENTROPY_THRESHOLD = 5.50

# T6: Transitive Dependency Threat
PROPAGATED_GRAPH_RISK_THRESHOLD = 0.50

# ==============================================================================
# 4. NETWORK & HTTP TIMEOUTS / RETRIES
# ==============================================================================
HTTP_TIMEOUT_SECONDS = 5
HTTP_MAX_RETRIES = 3
HTTP_BACKOFF_FACTOR = 0.5
USER_AGENT = "SupplyChainSecurityScanner/2.0 (Security Quarantine Gatekeeper)"

# ==============================================================================
# 5. ML ENGINE HYPERPARAMETERS
# ==============================================================================
RANDOM_SEEDS = [42, 123, 456, 789, 1011]
DEFAULT_SEED = 42
GNN_EPOCHS = 100
GNN_LEARNING_RATE = 0.005
GNN_WEIGHT_DECAY = 1e-4
GNN_HIDDEN_CHANNELS = 64
GNN_HEADS = 4
GNN_DROPOUT = 0.20
