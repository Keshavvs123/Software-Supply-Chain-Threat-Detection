import re
import math

POPULAR_PYPI_PACKAGES = [
    "requests", "urllib3", "numpy", "pandas", "flask", "django", 
    "cryptography", "jinja2", "scipy", "matplotlib", "boto3", "click", 
    "pydantic", "pytest", "setuptools", "wheel", "pip", "pillow", 
    "pyyaml", "six", "certifi", "idna", "charset-normalizer", 
    "typing-extensions", "packaging", "tqdm", "rsa", "pyasn1", 
    "beautifulsoup4", "virtualenv", "pipenv", "torch", "transformers",
    "scikit-learn", "seaborn", "tornado", "aiohttp", "sqlalchemy"
]

def levenshtein_distance(s1, s2):
    """
    Computes Levenshtein edit distance between two strings.
    """
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]

def evaluate_package_threats(pkg_name, pkg_data, metadata, static_info, runtime_info, exp_info):
    """
    Evaluates a single package against threat vectors T1 to T6.
    Returns a list of detected threat tags with explanations.
    """
    threats = []
    clean_name = pkg_name.lower()

    # ========================================================
    # T1 — Typosquatting
    # ========================================================
    for pop in POPULAR_PYPI_PACKAGES:
        if clean_name != pop:
            dist = levenshtein_distance(clean_name, pop)
            if 0 < dist <= 2 and len(clean_name) >= 4:
                threats.append({
                    "id": "T1",
                    "vector": "Typosquatting",
                    "severity": "HIGH",
                    "detail": f"Package name '{pkg_name}' is suspiciously close to popular library '{pop}' (edit distance={dist})."
                })
                break

    # ========================================================
    # T2 — Dependency Confusion
    # ========================================================
    is_internal_prefix = bool(re.match(r"^(internal|corp|company|private|local|pkg)[-_]", clean_name))
    is_unregistered = metadata.get("stars", 0) <= 0 and metadata.get("downloads", 0) <= 0
    if is_internal_prefix or (is_unregistered and pkg_data.get("version") != "Unknown"):
        threats.append({
            "id": "T2",
            "vector": "Dependency Confusion",
            "severity": "MEDIUM",
            "detail": f"Package '{pkg_name}' matches private/internal namespace patterns or lacks standard public PyPI provenance."
        })

    # ========================================================
    # T3 — Compromised Legitimate Package (Maintainer Risk)
    # ========================================================
    maintainer_churn = metadata.get("maintainer_churn", 0.1)
    commit_activity = metadata.get("commit_activity", 1.0)
    downloads = metadata.get("downloads", 100000)
    if downloads > 50000 and maintainer_churn > 0.4 and commit_activity < 0.3:
        threats.append({
            "id": "T3",
            "vector": "Compromised Maintainer",
            "severity": "HIGH",
            "detail": f"Established package exhibits anomalous maintainer churn ({maintainer_churn:.2f}) combined with dropped commit activity."
        })

    # ========================================================
    # T4 — Malicious Release Anomaly
    # ========================================================
    burstiness = metadata.get("release_burstiness", 0.3)
    last_update = metadata.get("last_update_days", 10.0)
    expected_interval = 365.0 / max(metadata.get("release_frequency", 5.0), 1.0)
    
    # Statistical deviance A_release = |x_t - mu| / (sigma + eps)
    sigma = expected_interval * 0.5 + 1.0
    a_release = abs(last_update - expected_interval) / sigma
    
    if (a_release > 2.5 and burstiness > 0.5) or burstiness > 0.75:
        threats.append({
            "id": "T4",
            "vector": "Malicious Release Anomaly",
            "severity": "MEDIUM",
            "detail": f"Release pattern deviates sharply from historical baseline (A_release={a_release:.2f}, burstiness={burstiness:.2f})."
        })

    # ========================================================
    # T5 — Obfuscated Payload
    # ========================================================
    entropy = static_info.get("shannon_entropy", 0.0)
    encoded_ratio = static_info.get("encoded_string_ratio", 0.0)
    eval_exec = static_info.get("eval_exec_usage", 0)
    
    if entropy > 6.2 or encoded_ratio > 0.15 or (eval_exec > 0 and entropy > 5.5):
        threats.append({
            "id": "T5",
            "vector": "Obfuscated Payload",
            "severity": "CRITICAL",
            "detail": f"Detected high code entropy ({entropy:.2f}) and encoded string constructs ({encoded_ratio*100:.1f}%) suggesting packed or obfuscated payload."
        })

    # ========================================================
    # T6 — Dependency-Based Attack
    # ========================================================
    direct_issues = static_info.get("bandit_issue_count", 0) + static_info.get("semgrep_issue_count", 0)
    graph_risk = exp_info.get("graph_risk", 0.1)
    
    # Clean on surface (0 direct issues), but high propagated graph risk
    if direct_issues == 0 and graph_risk > 0.50:
        threats.append({
            "id": "T6",
            "vector": "Dependency-Based Attack",
            "severity": "HIGH",
            "detail": f"Package surface code appears benign, but introduces high transitive dependency risk ({graph_risk*100:.1f}% propagated graph threat)."
        })

    return threats

def evaluate_all_threats(resolved_packages, package_metadata_map, static_results, runtime_results, predictions):
    """
    Evaluates all packages across the 6 threat models.
    """
    package_threats = {}
    total_threat_vectors_detected = 0

    for key, pkg in resolved_packages.items():
        name = pkg["name"]
        metadata = package_metadata_map.get(key, {})
        static_info = static_results.get("packages", {}).get(key.lower(), {})
        runtime_info = runtime_results.get("packages", {}).get(key.lower(), {})
        exp_info = predictions.get("explanations", {}).get(name, {})

        detected = evaluate_package_threats(name, pkg, metadata, static_info, runtime_info, exp_info)
        package_threats[name] = detected
        total_threat_vectors_detected += len(detected)

    return {
        "package_threats": package_threats,
        "total_threat_count": total_threat_vectors_detected
    }
