# PHISHGUARD AI

**URL-only phishing detection research and analysis workspace**  
Master 1 · Cybersecurity & Artificial Intelligence · v1.0.0

PHISHGUARD AI extracts lexical and structural features from a URL string, trains and compares classical machine-learning models, evaluates them using registered-domain-separated splits, and provides a local Streamlit interface for single and batch triage. The application **never visits the submitted URL**.

> **Important:** PHISHGUARD AI is an educational defensive triage aid. A prediction is not proof that a URL is malicious or safe. It is not a browser protection product, a reputation service, or an automatic blocking system.

## Product areas

- **Overview:** experiment status, workflow and evaluation guardrails.
- **URL Analyzer:** parse a URL locally, extract 22 features and score it when a trained model exists.
- **Batch Analysis:** validate and analyze a bounded CSV batch; export predictions and invalid rows.
- **Dataset Explorer:** audit URL/label data, class balance, duplicates, domain groups and URL-only feature distributions.
- **ML Laboratory:** compare Logistic Regression, Decision Tree, Random Forest and Extra Trees.
- **Explainability:** global model importance, feature context and optional local SHAP for supported tree models.
- **Reports & History:** export experiment metadata, HTML report and session-only analysis history.
- **Methodology:** dataset provenance, feature schema, protocol, limitations and safety policy.

## Architecture

```text
PHISHGUARD-AI/
├── app.py
├── pages/
│   ├── 1_URL_Analyzer.py
│   ├── 2_Batch_Analysis.py
│   ├── 3_Dataset_Explorer.py
│   ├── 4_ML_Laboratory.py
│   ├── 5_Explainability.py
│   ├── 6_Reports_History.py
│   └── 7_Methodology.py
├── src/phishguard/
│   ├── config.py
│   ├── data/                 # label audit + domain-grouped splitting
│   ├── features/             # URL-only feature extractor
│   ├── modeling/             # training, threshold selection, prediction
│   ├── explainability/       # global importance + optional SHAP
│   ├── reporting/            # CSV and HTML reports
│   └── ui.py
├── data/
│   ├── raw/                  # local dataset only; ignored by Git
│   └── sample/               # small URL examples; not training data
├── artifacts/                # generated model and metrics; ignored by Git
├── docs/
├── notebooks/                # EDA starter notebook
├── scripts/                  # command-line audit and train helpers
├── tests/
├── .github/workflows/tests.yml
├── setup.sh
├── run.sh
├── requirements.txt
├── requirements-dev.txt
└── pyproject.toml
```

See [Architecture](docs/ARCHITECTURE.md), [Dataset Protocol](docs/DATASET.md) and [Experimental Protocol](docs/EXPERIMENTS.md).

## 1. Requirements

- Python 3.11 or newer (Python 3.13 is a good supported target).
- Linux, macOS or Windows with a virtual environment.
- Internet access only for the first dependency installation and downloading the source dataset. The application does not need network access to inspect submitted URLs.

## 2. Installation on Kali Linux

Extract the archive, open the project folder in VS Code, then run once:

```bash
cd ~/Downloads/PHISHGUARD-AI
chmod +x setup.sh run.sh
./setup.sh
```

The setup script creates `.venv`, installs application/development requirements, installs the local package and runs Python compilation checks. It does not download or fabricate the research dataset.

Start the application:

```bash
./run.sh
```

Open `http://127.0.0.1:8501` in the browser.

To run tests later (with the project environment active):

```bash
source .venv/bin/activate
pytest -q
```

## 3. Get the official dataset

Primary source: [PhiUSIIL Phishing URL (Website) — UCI Machine Learning Repository](https://archive.ics.uci.edu/dataset/967/phiusil+phishing+url+dataset).

1. Download `PhiUSIIL_Phishing_URL_Dataset.csv` from UCI.
2. Copy it to:

   `data/raw/PhiUSIIL_Phishing_URL_Dataset.csv`

3. Open **Dataset Explorer** and inspect the audit.
4. Open **ML Laboratory**, choose candidate models and start training.

The UCI record documents 235,795 instances, including 134,850 legitimate and 100,945 phishing URLs. UCI labels are `0 = phishing` and `1 = legitimate`. The repository page states CC BY 4.0; retain attribution and licence notices when using or redistributing dataset-derived results. The original CSV is **not included** in this repository.

### Critical methodological choice: URL-only features

PhiUSIIL includes features extracted from both the URL and the webpage source. PHISHGUARD AI intentionally reads only the `URL` and `label` columns. It ignores the other source columns and recomputes its own fixed 22-feature schema directly from the URL string. This prevents the model from relying on information that is unavailable in the URL Analyzer.

Internal target encoding:

- `1` = phishing (positive class for evaluation)
- `0` = legitimate

This is normalized from the UCI source convention described above.

## 4. Run dataset audit from the command line

```bash
python scripts/audit_dataset.py data/raw/PhiUSIIL_Phishing_URL_Dataset.csv
```

Optionally export the normalized URL/target/domain table:

```bash
python scripts/audit_dataset.py data/raw/PhiUSIIL_Phishing_URL_Dataset.csv \
  --output data/processed/audited_urls.csv
```

`data/processed/` is local working output and should not be committed unless explicitly reviewed.

## 5. Train from the command line

```bash
python scripts/train_model.py data/raw/PhiUSIIL_Phishing_URL_Dataset.csv \
  --models "Logistic Regression" "Decision Tree" "Random Forest" \
  --seed 42
```

Generated local files:

- `artifacts/phishguard_model.joblib`
- `artifacts/training_metrics.json`
- `artifacts/MODEL_CARD.md`

These artifacts are ignored by Git by default. If publishing a trained model is appropriate, review dataset terms, artifact size and reproducibility metadata first.

## 6. Evaluation protocol

- Dataset audit checks URL/label columns, missing values, invalid URLs, duplicate URLs and conflicting duplicate labels.
- The source dataset is reduced to `URL` and `label` only.
- URL-only features are extracted through one shared function for training and inference.
- `StratifiedGroupKFold` isolates registrable domains across train, validation and test (approximately 60/20/20).
- Candidate models are compared on the same split.
- The decision threshold is selected on validation F1 for the phishing class.
- Model choice is based on validation F1. The held-out test partition is reserved for final evaluation.
- Reports include precision, recall, F1, PR-AUC, ROC-AUC, false-positive rate, false-negative rate and confusion matrix.

The split is domain-aware but not temporal. It does not guarantee generalization to future campaigns or unseen ecosystems.

## 7. Feature schema (22 URL-only features)

`url_length`, `hostname_length`, `path_length`, `query_length`, `fragment_length`, `num_dots`, `num_hyphens`, `num_underscores`, `num_digits`, `num_at_symbols`, `num_subdomains_estimated`, `has_ip_host`, `uses_https_scheme`, `has_nonstandard_port`, `num_percent_encodings`, `num_suspicious_tokens`, `url_entropy`, `has_fragment`, `num_query_parameters`, `num_slashes`, `has_punycode_label`, `hostname_digit_ratio`.

Subdomain and registered-domain grouping use `tldextract` with its bundled Public Suffix List snapshot and no runtime list download. A documented limited offline fallback is provided if the dependency is unavailable.

## 8. Safety and privacy

- Submitted URLs are parsed locally; PHISHGUARD does not send HTTP requests, resolve DNS, inspect TLS, render HTML or execute scripts.
- Batch uploads are limited by file size and row count.
- Only CSV input is supported in the first version.
- Session URL history is stored in Streamlit session state, not a persistent database.
- Do not commit `.env`, raw datasets, model artifacts or confidential URL lists.
- Never use model output as the only basis for an incident or blocking decision.
- `joblib` model artifacts are pickle-based: load only artifacts created by this project or another source you trust. Do not place untrusted model files in `artifacts/`.
- The Streamlit app has no multi-user authentication in v1. Keep it on a trusted local machine; do not expose it publicly without adding access controls and a hardened deployment layer.

## 9. Optional SHAP

The global importance and URL feature context pages work without SHAP. For optional tree-model local explanations:

```bash
python -m pip install -r requirements-explain.txt
```

SHAP output is still a model-behaviour explanation, not causal proof.

## 10. Tests

```bash
pytest -q
```

Tests cover URL parsing and feature stability, label mapping, duplicate handling, domain leakage checks, model training/reload, single prediction and batch invalid-row handling.

## Dataset citation

Prasad, A. & Chandra, S. (2024). *PhiUSIIL Phishing URL (Website) Dataset*. UCI Machine Learning Repository. https://doi.org/10.1016/j.cose.2023.103545. Dataset page: https://archive.ics.uci.edu/dataset/967/phiusil+phishing+url+dataset. Licence: CC BY 4.0 (as stated by UCI).
