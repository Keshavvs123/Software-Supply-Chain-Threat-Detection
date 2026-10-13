
import os
import numpy as np
import pandas as pd

from sklearn.model_selection import StratifiedKFold
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    precision_recall_curve,
    auc,
    matthews_corrcoef,
    confusion_matrix
)

from statsmodels.stats.contingency_tables import mcnemar


# ==========================================================
# 1. CONFIGURATION
# ==========================================================

DATASET_PATH = "dataset/Supply_Chain_Risk_Dataset_v2.xlsx"
SHEET_NAME = "Packages"
TARGET_COLUMN = "is_vulnerable_any"

OUTPUT_DIR = "outputs"
RANDOM_STATE = 42
N_SPLITS = 5

os.makedirs(OUTPUT_DIR, exist_ok=True)


# ==========================================================
# 2. LOAD DATASET
# ==========================================================

print("=" * 70)
print("PYTHON SOFTWARE SUPPLY CHAIN VULNERABILITY ANALYSIS")
print("5-Fold Stratified Cross-Validation")
print("=" * 70)

data = pd.read_excel(
    DATASET_PATH,
    sheet_name=SHEET_NAME
)

print("\nDataset loaded successfully.")
print("Dataset shape:", data.shape)
print("Available columns:", data.columns.tolist())


# ==========================================================
# 3. VALIDATE TARGET LABELS
# ==========================================================

if TARGET_COLUMN not in data.columns:
    raise ValueError(
        f"Target column '{TARGET_COLUMN}' was not found."
    )

data = data.dropna(subset=[TARGET_COLUMN]).copy()

# Accept numeric 0/1 or Boolean target labels.
# Reject unexpected values instead of silently mislabelling them.
if data[TARGET_COLUMN].dtype == bool:
    y = data[TARGET_COLUMN].astype(int)
else:
    y = pd.to_numeric(
        data[TARGET_COLUMN],
        errors="raise"
    )

if not y.isin([0, 1]).all():
    raise ValueError(
        "The target column must contain only 0 and 1."
    )

y = y.astype(int)

print("\nTarget class distribution:")
print(y.value_counts().sort_index().rename(
    index={0: "Non-vulnerable (0)", 1: "Vulnerable (1)"}
))

class_counts = y.value_counts()

if len(class_counts) != 2:
    raise ValueError(
        "Both target classes (0 and 1) must be present."
    )

if class_counts.min() < N_SPLITS:
    raise ValueError(
        f"Each class must contain at least {N_SPLITS} "
        "samples for stratified 5-fold CV."
    )


# ==========================================================
# 4. SELECT FEATURES
# ==========================================================

# Exclude identifiers, descriptive text, target-related counts,
# and fields that may directly reveal vulnerability status.
#
# NOTE:
# max_cvss_score and max_severity_encoded are excluded because
# they are derived from vulnerability records and could leak
# target information.
#
# total_dependencies and dependency counts are retained as
# structural package features.

EXCLUDE_COLUMNS = [
    TARGET_COLUMN,
    "package_name",
    "num_cve_records",
    "num_malicious_records",
    "max_cvss_score",
    "max_severity_encoded",
    "pypi_status",
    "pypi_license",
    "pypi_summary",
    "pypi_first_release",
    "pypi_latest_release",
    "github_url",
    "github_status",
    "github_archived"
]

X = data.drop(
    columns=[
        col for col in EXCLUDE_COLUMNS
        if col in data.columns
    ]
).copy()

# Keep numeric features for this baseline experiment.
X = X.select_dtypes(include=[np.number])

# Remove columns that contain no usable values.
X = X.dropna(axis=1, how="all")

if X.empty:
    raise ValueError(
        "No usable numeric feature columns remain."
    )

# Remove constant features.
X = X.loc[:, X.nunique(dropna=True) > 1]

if X.empty:
    raise ValueError(
        "All selected features are constant or empty."
    )

# Align target and features after filtering.
valid_indices = X.index.intersection(y.index)
X = X.loc[valid_indices].reset_index(drop=True)
y = y.loc[valid_indices].reset_index(drop=True)

print("\nFeatures used:")
for column in X.columns:
    print(" -", column)

print("\nNumber of samples:", len(X))
print("Number of features:", X.shape[1])


# ==========================================================
# 5. DEFINE MODELS
# ==========================================================

models = {
    "Random Forest": make_pipeline(
        SimpleImputer(strategy="median"),
        RandomForestClassifier(
            n_estimators=200,
            class_weight="balanced",
            random_state=RANDOM_STATE,
            n_jobs=-1
        )
    ),

    "Logistic Regression": make_pipeline(
        SimpleImputer(strategy="median"),
        StandardScaler(),
        LogisticRegression(
            max_iter=2000,
            class_weight="balanced",
            random_state=RANDOM_STATE
        )
    )
}


# ==========================================================
# 6. METRIC CALCULATION
# ==========================================================

def calculate_metrics(y_true, y_pred, y_prob):
    """Calculate binary classification evaluation metrics."""

    accuracy = accuracy_score(y_true, y_pred)

    precision = precision_score(
        y_true, y_pred, zero_division=0
    )

    recall = recall_score(
        y_true, y_pred, zero_division=0
    )

    f1 = f1_score(
        y_true, y_pred, zero_division=0
    )

    roc_auc = roc_auc_score(y_true, y_prob)

    precision_curve, recall_curve, _ = (
        precision_recall_curve(y_true, y_prob)
    )

    pr_auc = auc(recall_curve, precision_curve)

    mcc = matthews_corrcoef(y_true, y_pred)

    tn, fp, fn, tp = confusion_matrix(
        y_true,
        y_pred,
        labels=[0, 1]
    ).ravel()

    fpr = (
        fp / (fp + tn)
        if (fp + tn) > 0
        else 0.0
    )

    return {
        "Accuracy": accuracy,
        "Precision": precision,
        "Recall": recall,
        "F1-Score": f1,
        "ROC-AUC": roc_auc,
        "PR-AUC": pr_auc,
        "MCC": mcc,
        "FPR": fpr
    }


# ==========================================================
# 7. STRATIFIED 5-FOLD CROSS-VALIDATION
# ==========================================================

skf = StratifiedKFold(
    n_splits=N_SPLITS,
    shuffle=True,
    random_state=RANDOM_STATE
)

fold_results = []

# Store out-of-fold predictions for paired McNemar comparison.
oof_predictions = {
    model_name: np.full(len(y), -1, dtype=int)
    for model_name in models
}

print("\nStarting 5-fold cross-validation...\n")

for model_name, model in models.items():

    print("-" * 60)
    print("Model:", model_name)
    print("-" * 60)

    for fold, (train_idx, test_idx) in enumerate(
        skf.split(X, y),
        start=1
    ):

        X_train = X.iloc[train_idx]
        X_test = X.iloc[test_idx]

        y_train = y.iloc[train_idx]
        y_test = y.iloc[test_idx]

        # Fit only on training data.
        model.fit(X_train, y_train)

        # Predict labels and vulnerability probabilities.
        y_pred = model.predict(X_test)
        y_prob = model.predict_proba(X_test)[:, 1]

        # Save out-of-fold predictions in original row positions.
        oof_predictions[model_name][test_idx] = y_pred

        metrics = calculate_metrics(
            y_test,
            y_pred,
            y_prob
        )

        fold_results.append({
            "Model Configuration": model_name,
            "Fold": fold,
            **metrics
        })

        print(
            f"Fold {fold} | "
            f"Accuracy: {metrics['Accuracy'] * 100:.2f}% | "
            f"F1: {metrics['F1-Score'] * 100:.2f}% | "
            f"ROC-AUC: {metrics['ROC-AUC'] * 100:.2f}%"
        )


# ==========================================================
# 8. SAVE PER-FOLD RESULTS
# ==========================================================

cv_df = pd.DataFrame(fold_results)

cv_results_path = os.path.join(
    OUTPUT_DIR,
    "cv_5fold_results.csv"
)

cv_df.to_csv(cv_results_path, index=False)

print("\nPer-fold results saved to:")
print(cv_results_path)


# ==========================================================
# 9. CALCULATE MEAN AND STANDARD DEVIATION
# ==========================================================

metric_columns = [
    "Accuracy",
    "Precision",
    "Recall",
    "F1-Score",
    "ROC-AUC",
    "PR-AUC",
    "MCC",
    "FPR"
]

summary_df = (
    cv_df.groupby("Model Configuration")[metric_columns]
    .agg(["mean", "std"])
)

summary_df.columns = [
    f"{metric}_{stat}"
    for metric, stat in summary_df.columns
]

summary_df = summary_df.reset_index()

summary_path = os.path.join(
    OUTPUT_DIR,
    "cv_5fold_summary.csv"
)

summary_df.to_csv(summary_path, index=False)


# ==========================================================
# 10. MCNEMAR'S TEST
# ==========================================================

print("\n" + "=" * 70)
print("MCNEMAR'S TEST")
print("=" * 70)

model_names = list(models.keys())

pred1 = oof_predictions[model_names[0]]
pred2 = oof_predictions[model_names[1]]

if np.any(pred1 < 0) or np.any(pred2 < 0):
    raise RuntimeError(
        "Some samples do not have out-of-fold predictions."
    )

correct1 = pred1 == y.to_numpy()
correct2 = pred2 == y.to_numpy()

# b: first model correct, second model incorrect.
# c: first model incorrect, second model correct.
b = int(np.sum(correct1 & ~correct2))
c = int(np.sum(~correct1 & correct2))

contingency_table = [
    [
        int(np.sum(correct1 & correct2)),
        b
    ],
    [
        c,
        int(np.sum(~correct1 & ~correct2))
    ]
]

mcnemar_result = mcnemar(
    contingency_table,
    exact=True,
    correction=False
)

print(f"Model 1: {model_names[0]}")
print(f"Model 2: {model_names[1]}")
print("Contingency table:", contingency_table)
print(f"Statistic: {mcnemar_result.statistic}")
print(f"P-value: {mcnemar_result.pvalue:.6f}")

mcnemar_df = pd.DataFrame([{
    "Model 1": model_names[0],
    "Model 2": model_names[1],
    "b": b,
    "c": c,
    "McNemar Statistic": mcnemar_result.statistic,
    "McNemar p-value": mcnemar_result.pvalue
}])

mcnemar_path = os.path.join(
    OUTPUT_DIR,
    "mcnemar_results.csv"
)

mcnemar_df.to_csv(mcnemar_path, index=False)


# ==========================================================
# 11. PRINT IEEE-STYLE SUMMARY
# ==========================================================

print("\n" + "=" * 90)
print("5-FOLD CROSS-VALIDATION RESULTS FOR IEEE PAPER")
print("=" * 90)

print(
    f"{'Model Configuration':<25}"
    f"{'Accuracy (%)':<20}"
    f"{'F1-Score (%)':<20}"
    f"{'ROC-AUC (%)':<20}"
)

print("-" * 85)

for _, row in summary_df.iterrows():

    accuracy_mean = row["Accuracy_mean"] * 100
    accuracy_std = row["Accuracy_std"] * 100

    f1_mean = row["F1-Score_mean"] * 100
    f1_std = row["F1-Score_std"] * 100

    auc_mean = row["ROC-AUC_mean"] * 100
    auc_std = row["ROC-AUC_std"] * 100

    print(
        f"{row['Model Configuration']:<25}"
        f"{accuracy_mean:.2f} +/- {accuracy_std:.2f}   "
        f"{f1_mean:.2f} +/- {f1_std:.2f}   "
        f"{auc_mean:.2f} +/- {auc_std:.2f}"
    )

print("\nAll experiments completed.")

print("\nGenerated files:")
print("1.", cv_results_path)
print("2.", summary_path)
print("3.", mcnemar_path)

print(
    "\nNote: Report these results as baseline performance "
    "on the selected dataset. Validate labels, feature provenance, "
    "and possible package-level duplicates before making claims "
    "about generalization to unseen packages."
)
