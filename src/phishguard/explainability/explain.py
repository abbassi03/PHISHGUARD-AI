from __future__ import annotations

import pandas as pd

from phishguard.features.url_features import FEATURE_NAMES, extract_url_features

FEATURE_DESCRIPTIONS = {
    "url_length": "Total URL string length",
    "hostname_length": "Hostname length",
    "path_length": "Path length",
    "query_length": "Query-string length",
    "fragment_length": "Fragment length",
    "num_dots": "Number of dots in URL",
    "num_hyphens": "Number of hyphens",
    "num_underscores": "Number of underscores",
    "num_digits": "Number of digits",
    "num_at_symbols": "Number of @ symbols",
    "num_subdomains_estimated": "Estimated subdomain count",
    "has_ip_host": "Hostname is an IP address",
    "uses_https_scheme": "HTTPS scheme declared",
    "has_nonstandard_port": "Explicit non-standard port",
    "num_percent_encodings": "Percent-encoded sequences",
    "num_suspicious_tokens": "Occurrences of terms from the documented token list",
    "url_entropy": "Shannon entropy of URL characters",
    "has_fragment": "URL contains a fragment",
    "num_query_parameters": "Number of query parameters",
    "num_slashes": "Number of slash characters",
    "has_punycode_label": "Hostname contains a punycode label",
    "hostname_digit_ratio": "Digit ratio in hostname",
}


def global_importance_frame(metadata: dict) -> pd.DataFrame:
    rows = metadata.get("global_feature_importance", [])
    if not rows:
        return pd.DataFrame(columns=["feature", "importance", "method", "description"])
    frame = pd.DataFrame(rows)
    frame["description"] = frame["feature"].map(FEATURE_DESCRIPTIONS).fillna(frame["feature"])
    return frame.sort_values("importance", ascending=False).reset_index(drop=True)


def build_feature_context(url: str, metadata: dict | None = None) -> pd.DataFrame:
    values = extract_url_features(url)
    frame = pd.DataFrame(
        [{"feature": name, "value": value, "description": FEATURE_DESCRIPTIONS.get(name, name)}
         for name, value in values.items()]
    )
    if metadata:
        importance = {row["feature"]: row["importance"] for row in metadata.get("global_feature_importance", [])}
        frame["global_model_importance"] = frame["feature"].map(importance).fillna(0.0)
        frame = frame.sort_values("global_model_importance", ascending=False)
    return frame.reset_index(drop=True)


def shap_local_explanation(url: str, bundle: dict):
    """Optional SHAP explanation for tree models; returns None when unavailable."""
    try:
        import shap  # type: ignore
        import numpy as np
        import pandas as pd

        model = bundle["model"]
        classifier = model.named_steps["classifier"]
        if not hasattr(classifier, "feature_importances_"):
            return None
        background = pd.DataFrame([extract_url_features(url)], columns=FEATURE_NAMES)
        explainer = shap.TreeExplainer(classifier)
        transformed = model.named_steps["imputer"].transform(background)
        values = explainer.shap_values(transformed)
        if isinstance(values, list):
            values = values[1] if len(values) > 1 else values[0]
        values = np.asarray(values)
        if values.ndim == 3:
            values = values[0, :, 1]
        elif values.ndim == 2:
            values = values[0]
        return pd.DataFrame(
            {"feature": FEATURE_NAMES, "shap_value": values.astype(float)}
        ).sort_values("shap_value", key=lambda col: col.abs(), ascending=False).reset_index(drop=True)
    except Exception:
        return None
