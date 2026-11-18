# PHISHGUARD AI — Architecture

## Scope

PHISHGUARD AI v1 is a local, defensive research application that analyzes the URL string only. The submitted destination is never opened. No HTTP, DNS, WHOIS, TLS, JavaScript, HTML or reputation lookup is part of the v1 pipeline.

## Main components

```text
Streamlit UI
  ├── Overview
  ├── URL Analyzer ───────┐
  ├── Batch Analysis ─────┤
  ├── Dataset Explorer    │
  ├── ML Laboratory       │
  ├── Explainability      │
  └── Reports & History   │
                          ▼
                    URL Feature Extractor
                          │
                ordered 22-feature schema
                          │
             ┌────────────┴─────────────┐
             ▼                        ▼
       Dataset Audit             Model Artifact
             │                 (Pipeline + threshold)
             ▼                        │
       Domain Split                  ▼
             │                  URL prediction
             ▼                        │
      Train / Validation / Test       ▼
             │                 Explainable output
             ▼
      Model comparison
             │
      Validation threshold
             │
        Hold-out test
             │
       Metrics / Model Card
```

## Package boundaries

- `src/phishguard/features`: URL normalization and deterministic feature extraction.
- `src/phishguard/data`: source dataset validation, target mapping and domain-grouped splits.
- `src/phishguard/modeling`: model definitions, threshold selection, test evaluation and prediction.
- `src/phishguard/explainability`: global feature importance, feature context and optional SHAP.
- `src/phishguard/reporting`: CSV and HTML report generation.
- `pages/`: Streamlit application pages.

## Target semantics

UCI PhiUSIIL uses `0 = phishing` and `1 = legitimate`. The loader normalizes that to an internal target of `1 = phishing` and `0 = legitimate`, which is the positive class for precision/recall/F1 and threshold selection.

## Persistence

The application stores a trained scikit-learn pipeline and experiment metadata under `artifacts/`. Raw user datasets under `data/raw/` are local-only and ignored by Git. No submitted URLs are written to a persistent database; browser-session history is kept in Streamlit session state only.
