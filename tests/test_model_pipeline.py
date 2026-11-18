import numpy as np
import pandas as pd

from phishguard.data.dataset import prepare_dataset
from phishguard.modeling.training import load_model_bundle, train_compare_models
from phishguard.modeling.prediction import predict_one, predict_many


def _training_frame():
    rows = []
    for domain_index in range(35):
        domain = f"unit{domain_index}.example"
        for idx in range(8):
            phishing = idx < 4
            prefix = "verify-login-account" if phishing else "news-public-info"
            path = "account/secure/confirm" if phishing else "articles/today"
            url = f"https://{prefix}-{idx}.{domain}/{path}?id={idx}"
            rows.append({"URL": url, "label": 0 if phishing else 1})
    return prepare_dataset(pd.DataFrame(rows))


def test_training_saves_reloadable_model_and_predicts(tmp_path):
    dataset, audit = _training_frame()
    metadata = train_compare_models(
        dataset,
        audit=audit,
        artifact_dir=tmp_path,
        selected_models=["Logistic Regression", "Decision Tree", "Random Forest", "Extra Trees"],
        random_state=11,
    )
    assert metadata["selected_model"] in {"Logistic Regression", "Decision Tree", "Random Forest", "Extra Trees"}
    assert set(metadata["all_models_test_metrics"]) == {"Logistic Regression", "Decision Tree", "Random Forest", "Extra Trees"}
    bundle = load_model_bundle(tmp_path / "phishguard_model.joblib")
    assert bundle is not None
    result = predict_one("https://account-verify.example.net/login", bundle)
    assert result["prediction"] in {"Phishing", "Legitimate"}
    assert 0 <= result["phishing_score"] <= 1
    many, errors = predict_many(["https://example.com", "not a valid url with spaces"], bundle)
    assert len(many) == 1
    assert len(errors) == 1
