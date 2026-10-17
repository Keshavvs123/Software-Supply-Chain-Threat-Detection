# Chronological (Temporal Split) Evaluation Summary

Evaluates resistance to temporal drift by training on the oldest 70% of packages and testing on the newest 30% of unseen releases.

| Model               |   Accuracy |   Precision |   Recall |   F1-Score |   ROC-AUC |   PR-AUC |      FPR |
|:--------------------|-----------:|------------:|---------:|-----------:|----------:|---------:|---------:|
| Logistic Regression |   0.603514 |    0.579057 | 0.97398  |   0.726306 |  0.349457 | 0.376148 | 0.831619 |
| Random Forest       |   0.585946 |    0.56671  | 0.991494 |   0.721201 |  0.944389 | 0.968804 | 0.890391 |
| Proposed HGAT GNN   |   0.784865 |    0.731473 | 0.950713 |   0.826806 |  0.943983 | 0.96238  | 0.409932 |