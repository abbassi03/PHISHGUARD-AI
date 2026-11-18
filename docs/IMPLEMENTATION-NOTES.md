# PHISHGUARD AI v1.0.0 — Implementation notes

This note maps the agreed initial specification to the delivered application and records deliberate boundaries.

## Delivered in v1.0.0

- Streamlit multi-page application with Overview, URL Analyzer, Batch Analysis, Dataset Explorer, ML Laboratory, Explainability, Reports & History, and Methodology.
- URL-only parser and a fixed 22-feature schema shared by training and inference.
- UCI-compatible `URL`/`label` data loader that reads only those two columns, while retaining source-column names for the audit report.
- Source-label normalization: UCI `0 = phishing`, `1 = legitimate`; internal `1 = phishing`, `0 = legitimate`.
- Validation for malformed URLs, missing fields, invalid labels, duplicate URLs and conflicting duplicate labels.
- Registered-domain group separation with `StratifiedGroupKFold`; split intersections are checked.
- Logistic Regression, Decision Tree, Random Forest and Extra Trees candidates.
- Validation-only threshold selection and held-out test evaluation.
- Accuracy, balanced accuracy, phishing precision/recall/F1, PR-AUC, ROC-AUC, false-positive/negative rates and confusion matrix.
- Model artifact, metrics JSON and generated model card.
- Global feature importance, optional SHAP local explanation for supported tree models, CSV exports and HTML experiment report.
- CLI audit/train scripts, EDA notebook, Docker files, GitHub Actions and automated tests.

## Deliberate v1 boundaries

- The original UCI dataset is not bundled. Download it from the official source and keep it in `data/raw/`, which is excluded from Git.
- No pre-trained model is bundled. The first run is feature-extraction-only until the source dataset is audited and a model is trained. This avoids shipping fabricated benchmark results.
- PDF export is not included; CSV and HTML exports are implemented.
- Analysis history is kept in Streamlit session state only; no persistent database is used.
- SHAP is optional and installed separately. Global feature importance remains available without SHAP.
- The UI has no multi-user authentication. Keep it local; do not expose it publicly without an access-control layer.
- The first version does not visit submitted URLs, follow redirects, inspect HTML/TLS/DNS/WHOIS, query reputation services, or block websites.

## Verification performed for this delivery

- Python source compilation.
- Shell-script syntax checks.
- Automated tests for URL parsing/features, dataset and label validation, domain-group split isolation, four-model training/reload, single and batch prediction, and formula-safe CSV exports.
- Notebook schema validation.

The Streamlit package was unavailable in the build environment and package-index access failed, so the UI AppTest is included for GitHub Actions but was skipped in the local build validation. The complete UI must still be launched in the user's environment after `./setup.sh`.
