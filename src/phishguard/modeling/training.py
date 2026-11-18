from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    precision_recall_curve,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

from phishguard.config import ARTIFACT_DIR, MODEL_CARD_PATH, METRICS_PATH, MODEL_PATH, RANDOM_STATE
from phishguard.data.dataset import DatasetAudit
from phishguard.data.splitting import make_domain_splits
from phishguard.features.url_features import FEATURE_NAMES, extract_features_frame


def _model_definitions(random_state: int) -> dict[str, Pipeline]:
    return {
        "Logistic Regression": Pipeline(
            [
                ("imputer", SimpleImputer(strategy="median")),
                ("scaler", StandardScaler()),
                (
                    "classifier",
                    LogisticRegression(
                        max_iter=1200,
                        class_weight="balanced",
                        solver="liblinear",
                        random_state=random_state,
                    ),
                ),
            ]
        ),
        "Decision Tree": Pipeline(
            [
                ("imputer", SimpleImputer(strategy="median")),
                (
                    "classifier",
                    DecisionTreeClassifier(
                        max_depth=14,
                        min_samples_leaf=4,
                        class_weight="balanced",
                        random_state=random_state,
                    ),
                ),
            ]
        ),
        "Random Forest": Pipeline(
            [
                ("imputer", SimpleImputer(strategy="median")),
                (
                    "classifier",
                    RandomForestClassifier(
                        n_estimators=160,
                        max_depth=18,
                        min_samples_leaf=2,
                        max_features="sqrt",
                        class_weight="balanced_subsample",
                        n_jobs=-1,
                        random_state=random_state,
                    ),
                ),
            ]
        ),
        "Extra Trees": Pipeline(
            [
                ("imputer", SimpleImputer(strategy="median")),
                (
                    "classifier",
                    ExtraTreesClassifier(
                        n_estimators=160,
                        max_depth=18,
                        min_samples_leaf=2,
                        max_features="sqrt",
                        class_weight="balanced",
                        n_jobs=-1,
                        random_state=random_state,
                    ),
                ),
            ]
        ),
    }


def _phishing_probability(model: Pipeline, features: pd.DataFrame) -> np.ndarray:
    classes = list(model.named_steps["classifier"].classes_)
    if 1 not in classes:
        raise RuntimeError("Trained model does not contain the phishing target class (1).")
    class_index = classes.index(1)
    return model.predict_proba(features)[:, class_index]


def _best_f1_threshold(y_true: np.ndarray, probabilities: np.ndarray) -> tuple[float, float]:
    # precision_recall_curve evaluates all score thresholds efficiently in O(n log n).
    precision, recall, thresholds = precision_recall_curve(y_true, probabilities, pos_label=1)
    if len(thresholds) == 0:
        return 0.5, float(f1_score(y_true, probabilities >= 0.5, zero_division=0))
    denominator = precision[:-1] + recall[:-1]
    f1_values = np.divide(
        2 * precision[:-1] * recall[:-1],
        denominator,
        out=np.zeros_like(denominator),
        where=denominator > 0,
    )
    best_index = int(np.nanargmax(f1_values))
    return float(thresholds[best_index]), float(f1_values[best_index])


def _calculate_metrics(y_true: np.ndarray, probabilities: np.ndarray, threshold: float) -> dict:
    predictions = (probabilities >= threshold).astype("int8")
    tn, fp, fn, tp = confusion_matrix(y_true, predictions, labels=[0, 1]).ravel()
    try:
        roc_auc = float(roc_auc_score(y_true, probabilities))
    except ValueError:
        roc_auc = None
    try:
        pr_auc = float(average_precision_score(y_true, probabilities))
    except ValueError:
        pr_auc = None
    return {
        "threshold": float(threshold),
        "accuracy": float(accuracy_score(y_true, predictions)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, predictions)),
        "precision_phishing": float(precision_score(y_true, predictions, pos_label=1, zero_division=0)),
        "recall_phishing": float(recall_score(y_true, predictions, pos_label=1, zero_division=0)),
        "f1_phishing": float(f1_score(y_true, predictions, pos_label=1, zero_division=0)),
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
        "false_positive_rate": float(fp / max(fp + tn, 1)),
        "false_negative_rate": float(fn / max(fn + tp, 1)),
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
        "support": {"legitimate": int(tn + fp), "phishing": int(fn + tp)},
    }


def _curve_points(y_true: np.ndarray, probabilities: np.ndarray, max_points: int = 160) -> dict:
    fpr, tpr, _ = roc_curve(y_true, probabilities)
    precision, recall, _ = precision_recall_curve(y_true, probabilities, pos_label=1)

    def reduce(x: np.ndarray, y: np.ndarray) -> list[list[float]]:
        if len(x) > max_points:
            indices = np.unique(np.linspace(0, len(x) - 1, max_points, dtype=int))
            x, y = x[indices], y[indices]
        return [[float(a), float(b)] for a, b in zip(x, y)]

    return {
        "roc": reduce(fpr, tpr),
        "precision_recall": reduce(recall, precision),
    }


def _feature_importance(model: Pipeline) -> list[dict]:
    estimator = model.named_steps["classifier"]
    if hasattr(estimator, "feature_importances_"):
        values = np.asarray(estimator.feature_importances_, dtype=float)
        method = "tree impurity importance"
    elif hasattr(estimator, "coef_"):
        values = np.abs(np.asarray(estimator.coef_, dtype=float)).ravel()
        method = "absolute standardized coefficient"
    else:
        return []
    total = float(values.sum()) or 1.0
    importance = values / total
    return [
        {"feature": name, "importance": float(value), "method": method}
        for name, value in sorted(zip(FEATURE_NAMES, importance), key=lambda item: item[1], reverse=True)
    ]


def _dataset_fingerprint(urls: list[str], labels: np.ndarray) -> str:
    digest = hashlib.sha256()
    for url, label in zip(urls, labels):
        digest.update(url.encode("utf-8", errors="replace"))
        digest.update(b"\0")
        digest.update(str(int(label)).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def train_compare_models(
    dataset: pd.DataFrame,
    audit: DatasetAudit | dict | None = None,
    artifact_dir: str | Path = ARTIFACT_DIR,
    selected_models: list[str] | None = None,
    random_state: int = RANDOM_STATE,
) -> dict:
    """Train and compare models using registered-domain-separated splits.

    dataset columns: url, target (1=phishing, 0=legitimate), domain_group.
    The threshold is selected on validation only. The test set remains untouched
    until final evaluation for each already-trained model.
    """
    required = {"url", "target", "domain_group"}
    if not required.issubset(dataset.columns):
        raise ValueError(f"Training data must contain columns: {sorted(required)}")
    urls = dataset["url"].astype(str).tolist()
    y = dataset["target"].astype("int8").to_numpy()
    groups = dataset["domain_group"].astype(str).to_numpy()
    if len(dataset) < 100:
        raise ValueError("At least 100 valid URL records are required for a meaningful first experiment.")

    features = extract_features_frame(urls)
    if not np.isfinite(features.to_numpy()).all():
        raise ValueError("Feature extraction produced non-finite values.")
    splits = make_domain_splits(y, groups, random_state=random_state)
    x_train, y_train = features.iloc[splits.train_idx], y[splits.train_idx]
    x_val, y_val = features.iloc[splits.validation_idx], y[splits.validation_idx]
    x_test, y_test = features.iloc[splits.test_idx], y[splits.test_idx]

    definitions = _model_definitions(random_state)
    if selected_models:
        unknown = set(selected_models) - set(definitions)
        if unknown:
            raise ValueError(f"Unknown models selected: {sorted(unknown)}")
        definitions = {name: model for name, model in definitions.items() if name in selected_models}
    if not definitions:
        raise ValueError("Select at least one model to train.")

    results: dict[str, dict] = {}
    trained: dict[str, Pipeline] = {}
    for name, model in definitions.items():
        started = time.perf_counter()
        model.fit(x_train, y_train)
        train_seconds = time.perf_counter() - started
        val_probabilities = _phishing_probability(model, x_val)
        threshold, validation_f1 = _best_f1_threshold(y_val, val_probabilities)
        test_probabilities = _phishing_probability(model, x_test)
        metrics = _calculate_metrics(y_test, test_probabilities, threshold)
        metrics["validation_f1_at_selected_threshold"] = validation_f1
        metrics["training_seconds"] = float(train_seconds)
        metrics["test_rows"] = int(len(y_test))
        metrics["curves"] = _curve_points(y_test, test_probabilities)
        results[name] = metrics
        trained[name] = model

    # Select only on validation F1, never on test metrics.
    selected_name = max(results, key=lambda name: results[name]["validation_f1_at_selected_threshold"])
    selected_model = trained[selected_name]
    selected_threshold = results[selected_name]["threshold"]
    importance = _feature_importance(selected_model)
    selected_test = _calculate_metrics(y_test, _phishing_probability(selected_model, x_test), selected_threshold)

    audit_dict = audit.to_dict() if hasattr(audit, "to_dict") else (audit or {})
    artifact_path = Path(artifact_dir)
    artifact_path.mkdir(parents=True, exist_ok=True)
    bundle = {
        "model": selected_model,
        "model_name": selected_name,
        "threshold": selected_threshold,
        "feature_names": FEATURE_NAMES,
        "target_positive_class": "phishing",
        "target_mapping_internal": {"0": "legitimate", "1": "phishing"},
        "url_only": True,
        "dataset_fingerprint_sha256": _dataset_fingerprint(urls, y),
        "random_state": random_state,
        "split_summary": splits.summary,
        "trained_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    joblib.dump(bundle, artifact_path / "phishguard_model.joblib", compress=3)

    metadata = {
        "project": "PHISHGUARD AI",
        "version": "1.0.0",
        "dataset_name": "PhiUSIIL Phishing URL (Website) or compatible URL/label CSV",
        "label_mapping_source": "UCI PhiUSIIL: 0=phishing, 1=legitimate; normalized internally to 1=phishing, 0=legitimate",
        "feature_scope": "URL string only; no page fetch, HTML, TLS, DNS, WHOIS or reputation lookup",
        "feature_names": FEATURE_NAMES,
        "dataset_audit": audit_dict,
        "dataset_fingerprint_sha256": bundle["dataset_fingerprint_sha256"],
        "random_state": random_state,
        "split_strategy": "StratifiedGroupKFold grouped by registrable domain; 60/20/20 approximate train/validation/test",
        "split_summary": splits.summary,
        "model_selection": "highest phishing-class F1 on validation set",
        "selected_model": selected_name,
        "selected_threshold": selected_threshold,
        "selected_model_test_metrics": selected_test,
        "all_models_test_metrics": results,
        "global_feature_importance": importance,
        "caveats": [
            "Model scores are estimates and may be miscalibrated under distribution shift.",
            "Domain-separated evaluation is more demanding than a random row split, but is not a guarantee of future-campaign performance.",
            "The system analyzes URL strings only and does not visit or verify the target website.",
            "Importance values describe model behaviour, not causal proof that a feature indicates phishing.",
        ],
    }
    (artifact_path / "training_metrics.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    _write_model_card(metadata, artifact_path / "MODEL_CARD.md")
    return metadata


def _write_model_card(metadata: dict, path: Path) -> None:
    metrics = metadata["selected_model_test_metrics"]
    rows = "\n".join(
        f"| {name} | {m['precision_phishing']:.3f} | {m['recall_phishing']:.3f} | {m['f1_phishing']:.3f} | {m['pr_auc'] if m['pr_auc'] is not None else float('nan'):.3f} |"
        for name, m in metadata["all_models_test_metrics"].items()
    )
    content = f"""# PHISHGUARD AI — Model Card\n\n- Selected model: **{metadata['selected_model']}**\n- Decision threshold: **{metadata['selected_threshold']:.4f}** (selected on validation only)\n- Dataset fingerprint (SHA-256): `{metadata['dataset_fingerprint_sha256']}`\n- Random state: `{metadata['random_state']}`\n- Feature scope: {metadata['feature_scope']}\n\n## Test results\n\n| Model | Precision (phishing) | Recall (phishing) | F1 (phishing) | PR-AUC |\n|---|---:|---:|---:|---:|\n{rows}\n\n## Selected-model confusion matrix\n\nRows are true labels `[legitimate, phishing]`, columns are predicted labels `[legitimate, phishing]`.\n\n```json\n{json.dumps(metrics['confusion_matrix'], indent=2)}\n```\n\n## Intended use\n\nEducational and defensive URL triage. It is not a browser protection guarantee, a URL reputation service, or an automated blocking system.\n\n## Limitations\n\n""" + "\n".join(f"- {item}" for item in metadata["caveats"]) + "\n"
    path.write_text(content, encoding="utf-8")


def load_model_bundle(path: str | Path = MODEL_PATH) -> dict | None:
    model_path = Path(path)
    if not model_path.exists():
        return None
    bundle = joblib.load(model_path)
    required = {"model", "model_name", "threshold", "feature_names", "url_only"}
    if not required.issubset(bundle):
        raise ValueError("Model artifact is incomplete or incompatible with this version.")
    if bundle["feature_names"] != FEATURE_NAMES:
        raise ValueError("Saved model feature schema differs from the current extractor.")
    return bundle
