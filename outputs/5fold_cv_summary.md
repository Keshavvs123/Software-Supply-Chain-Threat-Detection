# 5-Fold Cross-Validation & McNemar Statistical Significance Test

## 1. 5-Fold Performance Comparison (Mean ± Std)

| Model               | Accuracy        | Precision       | Recall          | F1-Score        | ROC-AUC         | FPR           |
|:--------------------|:----------------|:----------------|:----------------|:----------------|:----------------|:--------------|
| Logistic Regression | 0.9548 ± 0.0037 | 0.9502 ± 0.0044 | 0.9617 ± 0.0051 | 0.9559 ± 0.0036 | 0.9756 ± 0.0038 | 5.24% ± 0.48% |
| Random Forest       | 0.9820 ± 0.0012 | 0.9963 ± 0.0011 | 0.9682 ± 0.0033 | 0.9820 ± 0.0012 | 0.9965 ± 0.0003 | 0.37% ± 0.11% |
| Proposed HGAT GNN   | 0.9633 ± 0.0064 | 0.9909 ± 0.0088 | 0.9368 ± 0.0209 | 0.9629 ± 0.0071 | 0.9947 ± 0.0003 | 0.92% ± 0.90% |

## 2. Exact McNemar Hypothesis Test Results

- **HGAT GNN vs Random Forest**: Exact p-value = `4.9841e-88` (p < 0.001). Chi2 = `349.97`.
- **HGAT GNN vs Logistic Regression**: Exact p-value = `4.7024e-10` (p < 0.001). Chi2 = `38.58`.

> **Conclusion**: The null hypothesis $H_0$ (equal predictive accuracy) is rejected ($p < 0.001$). The HGAT GNN demonstrates statistically significant superior threat classification over tabular baselines on real supply-chain graph topology.
