from __future__ import annotations

import numpy as np
import pandas as pd

from phishguard.features.url_features import extract_features_frame, extract_url_features


def predict_one(url: str, bundle: dict) -> dict:
    features_dict = extract_url_features(url)
    frame = pd.DataFrame([features_dict], columns=bundle["feature_names"])
    model = bundle["model"]
    classes = list(model.named_steps["classifier"].classes_)
    phishing_probability = float(model.predict_proba(frame)[0, classes.index(1)])
    threshold = float(bundle["threshold"])
    predicted_phishing = phishing_probability >= threshold
    if phishing_probability >= 0.80:
        score_band = "High model score"
    elif phishing_probability >= 0.50:
        score_band = "Medium model score"
    else:
        score_band = "Low model score"
    return {
        "url": url,
        "prediction": "Phishing" if predicted_phishing else "Legitimate",
        "score_band": score_band,
        "phishing_score": phishing_probability,
        "decision_threshold": threshold,
        "features": features_dict,
        "model_name": bundle["model_name"],
        "score_note": "Model output score; not a calibrated real-world probability.",
    }


def predict_many(urls: list[str], bundle: dict) -> tuple[pd.DataFrame, pd.DataFrame]:
    valid_urls: list[str] = []
    features: list[dict] = []
    errors: list[dict] = []
    for index, value in enumerate(urls):
        try:
            feature_row = extract_url_features(value)
            valid_urls.append(str(value))
            features.append(feature_row)
        except ValueError as exc:
            errors.append({"row_number": index + 1, "url": str(value), "error": str(exc)})
    if not features:
        return pd.DataFrame(), pd.DataFrame(errors)
    feature_frame = pd.DataFrame(features, columns=bundle["feature_names"])
    model = bundle["model"]
    classes = list(model.named_steps["classifier"].classes_)
    scores = model.predict_proba(feature_frame)[:, classes.index(1)]
    threshold = float(bundle["threshold"])
    results = pd.DataFrame(
        {
            "url": valid_urls,
            "prediction": np.where(scores >= threshold, "Phishing", "Legitimate"),
            "phishing_score": scores,
            "score_band": np.where(scores >= 0.8, "High model score", np.where(scores >= 0.5, "Medium model score", "Low model score")),
        }
    )
    results["model_name"] = bundle["model_name"]
    return results, pd.DataFrame(errors)
