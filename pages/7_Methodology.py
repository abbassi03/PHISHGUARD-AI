from __future__ import annotations

import streamlit as st

from phishguard.config import DATASET_DOI, DATASET_URL
from phishguard.features.url_features import FEATURE_NAMES, SUSPICIOUS_TOKENS
from phishguard.ui import page_header, setup_page

setup_page("Methodology", "📚")
page_header(
    "Methodology, assumptions and limitations.",
    "A transparent reference for the research scope, dataset handling, feature definitions and evaluation protocol.",
    "RESEARCH NOTES",
)

st.subheader("Research question")
st.markdown("To what extent can lexical and structural characteristics extracted from a URL string distinguish phishing URLs from legitimate URLs, without visiting the target website?")

st.subheader("Dataset source")
st.markdown(f"- **Dataset:** PhiUSIIL Phishing URL (Website)\n- **Repository:** [UCI Machine Learning Repository]({DATASET_URL})\n- **Paper DOI:** [https://doi.org/{DATASET_DOI}](https://doi.org/{DATASET_DOI})\n- **Original UCI target:** 0 = phishing, 1 = legitimate\n- **Internal target used here:** 1 = phishing, 0 = legitimate\n- **License:** CC BY 4.0; retain attribution when redistributing dataset-derived content.")
st.warning("The source dataset includes both URL-derived and webpage-source features. PHISHGUARD AI reads only URL and label, then recomputes its own URL-only feature vector. All HTML, title, favicon, reputation and page-content columns are excluded.")

st.subheader("Feature schema")
st.write(f"The current extractor exposes {len(FEATURE_NAMES)} ordered numeric features.")
st.code("\n".join(FEATURE_NAMES), language="text")
st.write("Suspicious tokens are heuristic lexical signals, not a list of forbidden words or proof of malicious intent:")
st.code(", ".join(SUSPICIOUS_TOKENS), language="text")

st.subheader("Evaluation protocol")
st.markdown(
    """
    1. Validate URL and label fields, remove empty/invalid URLs, and audit duplicate/conflicting labels.
    2. Normalize the target so the positive class is phishing.
    3. Extract the same ordered feature schema during training and inference.
    4. Split by registrable domain using `StratifiedGroupKFold` to reduce domain leakage.
    5. Train candidate models on train data, choose a decision threshold on validation F1, and report held-out test metrics.
    6. Report precision, recall, F1, PR-AUC, ROC-AUC, false-positive rate, false-negative rate and confusion matrix.
    """
)

st.subheader("Limitations")
st.markdown(
    """
    - URL lexical features cannot see page content, redirects, TLS state, DNS reputation or live threat intelligence.
    - A legitimate-looking URL may host harmful content; a suspicious-looking URL may be benign.
    - Dataset labels and collection dates introduce bias and temporal drift.
    - Domain-grouped test evaluation is more conservative than random row splitting, but does not prove performance on all future phishing campaigns.
    - Model scores are not guaranteed to be calibrated probabilities.
    - The app is a defensive educational triage aid, not an automated blocking service.
    """
)

st.subheader("Safety and privacy")
st.markdown("The V1 application parses URL strings locally. It does not open submitted URLs, issue HTTP requests, perform DNS lookups, download content or execute code. Do not upload personal or confidential URL lists unless you are authorized to process them.")
