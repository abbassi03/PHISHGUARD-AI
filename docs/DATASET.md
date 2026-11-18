# Dataset protocol

## Primary source

Prasad, A. & Chandra, S. (2024). *PhiUSIIL Phishing URL (Website) Dataset*. UCI Machine Learning Repository. https://archive.ics.uci.edu/dataset/967/phiusil+phishing+url+dataset. DOI: https://doi.org/10.1016/j.cose.2023.103545. License shown by UCI: CC BY 4.0.

The UCI record documents 235,795 instances, 54 features, 134,850 legitimate URLs and 100,945 phishing URLs. The source labels are `0 = phishing` and `1 = legitimate`. The source features include both URL and webpage-source information.

## Strict URL-only policy

The research pipeline requires only `URL` and `label` columns. Every other source column is ignored, including columns derived from page source, page title, favicon, reputation or other page context. PHISHGUARD extracts its own fixed, ordered 22-feature vector from the URL string. This prevents training on features unavailable when the application receives a URL string.

## Local setup

1. Download the official CSV from the UCI dataset page.
2. Place it at `data/raw/PhiUSIIL_Phishing_URL_Dataset.csv`.
3. Do not commit the raw CSV to Git; `data/raw/` is ignored.
4. Run `python scripts/audit_dataset.py data/raw/PhiUSIIL_Phishing_URL_Dataset.csv`.
5. Open Dataset Explorer and inspect the audit before training.

## Audit rules

- Require `URL` and `label` columns.
- Reject labels other than the documented 0/1 values (or supported textual equivalents).
- Reject conflicting labels for an identical URL.
- Remove exact duplicate URLs after checking conflicts.
- Drop missing and invalid URL rows, recording counts.
- Group by registrable domain for train/validation/test isolation.

The `tldextract` dependency uses its bundled Public Suffix List snapshot without fetching updates at runtime. If it is unavailable, the extractor falls back to a documented, limited offline suffix set; for research-quality domain grouping, install the declared dependency.

## Attribution

PhiUSIIL is distributed under CC BY 4.0 according to UCI. Retain the dataset citation and license terms when sharing derived outputs. This repository does not redistribute the original CSV.
