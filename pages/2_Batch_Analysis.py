from __future__ import annotations

import pandas as pd
import streamlit as st

from phishguard.config import MAX_BATCH_ROWS, MAX_UPLOAD_MB
from phishguard.features.url_features import extract_url_features
from phishguard.modeling.prediction import predict_many
from phishguard.reporting.export import dataframe_to_csv
from phishguard.ui import load_current_model, page_header, setup_page

setup_page("Batch Analysis", "📄")
page_header(
    "Batch URL analysis",
    "Import a CSV and analyze many URL strings in one run. No target sites are contacted.",
    "BULK TRIAGE",
)

uploaded = st.file_uploader("Upload CSV", type=["csv"], help=f"Maximum {MAX_UPLOAD_MB} MB and {MAX_BATCH_ROWS:,} rows.")
model = load_current_model()

if uploaded:
    size_mb = len(uploaded.getvalue()) / (1024 * 1024)
    if size_mb > MAX_UPLOAD_MB:
        st.error(f"File is {size_mb:.1f} MB. Maximum allowed size is {MAX_UPLOAD_MB} MB.")
    else:
        try:
            frame = pd.read_csv(uploaded)
            st.caption(f"Loaded {len(frame):,} rows · {len(frame.columns)} columns · {size_mb:.2f} MB")
            if len(frame) > MAX_BATCH_ROWS:
                st.error(f"The file exceeds the {MAX_BATCH_ROWS:,}-row batch limit. Split it into smaller files.")
            elif frame.empty:
                st.warning("The CSV has no rows.")
            else:
                url_column = st.selectbox("Choose the column containing URLs", frame.columns.tolist(), index=frame.columns.tolist().index("URL") if "URL" in frame.columns else 0)
                if st.button("Run batch analysis", type="primary"):
                    values = frame[url_column].astype(str).tolist()
                    if model:
                        with st.spinner("Extracting URL features and running the saved model…"):
                            results, errors = predict_many(values, model)
                        st.session_state["last_batch_results"] = results
                        st.session_state["last_batch_errors"] = errors
                        history = st.session_state.setdefault("analysis_history", [])
                        if not results.empty:
                            history[:0] = results.head(100).to_dict(orient="records")
                    else:
                        rows, errors_list = [], []
                        for index, value in enumerate(values):
                            try:
                                rows.append({"url": value, **extract_url_features(value)})
                            except ValueError as exc:
                                errors_list.append({"row_number": index + 1, "url": value, "error": str(exc)})
                        st.session_state["last_batch_features"] = pd.DataFrame(rows)
                        st.session_state["last_batch_errors"] = pd.DataFrame(errors_list)
                    st.success("Batch processing completed.")
        except Exception as exc:
            st.error(f"Could not read this CSV: {exc}")

results = st.session_state.get("last_batch_results")
features = st.session_state.get("last_batch_features")
errors = st.session_state.get("last_batch_errors")
if results is not None:
    st.subheader("Prediction results")
    st.dataframe(results, use_container_width=True, hide_index=True)
    st.download_button("Download predictions · CSV", dataframe_to_csv(results), "phishguard_batch_predictions.csv", "text/csv")
    a, b, c = st.columns(3)
    a.metric("Analyzed", f"{len(results):,}")
    b.metric("Flagged phishing-like", f"{int((results['prediction'] == 'Phishing').sum()):,}")
    c.metric("Invalid rows", f"{len(errors) if errors is not None else 0:,}")
elif features is not None:
    st.warning("A trained model is not available. Feature extraction only was performed; no classification was produced.")
    st.dataframe(features.head(100), use_container_width=True, hide_index=True)
    st.download_button("Download extracted features · CSV", dataframe_to_csv(features), "phishguard_batch_features.csv", "text/csv")

if errors is not None and not errors.empty:
    with st.expander(f"Invalid rows ({len(errors)})"):
        st.dataframe(errors, use_container_width=True, hide_index=True)
        st.download_button("Download invalid rows", dataframe_to_csv(errors), "phishguard_invalid_urls.csv", "text/csv")

if not model:
    st.info("Train a model in **ML Laboratory** to enable phishing predictions. Without a model, this page only extracts URL features.")
