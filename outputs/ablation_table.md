                     Model Config Precision Recall F1-Score Accuracy ROC-AUC PR-AUC   FPR
    M1 (Dependency Topology Only)    0.5114 0.6787   0.5833   0.5057  0.5034 0.5415 67.4%
          M2 (GitHub Health Only)    0.5100 0.9857   0.6722   0.5100  0.5006 0.7515 98.5%
   M3 (PyPI Release Cadence Only)    0.5099 0.9936   0.6740   0.5100  0.4916 0.5016 99.3%
M4 (Logistic Regression Baseline)    0.5117 0.5223   0.5169   0.5024  0.5052 0.5406 51.8%
      M5 (Random Forest Baseline)    0.5133 0.5027   0.5079   0.5035  0.5004 0.6248 49.6%
  Proposed HGAT GNN (Full System)    0.9951 0.9724   0.9836   0.9835  0.9973 0.9977  0.5%