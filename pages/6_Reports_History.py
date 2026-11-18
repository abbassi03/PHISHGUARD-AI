from __future__ import annotations

import json

import pandas as pd
import streamlit as st

from phishguard.modeling.training import load_model_bundle
from phishguard.reporting.export import build_html_report, dataframe_to_csv
from phishguard.ui import load_metrics, page_header, setup_page

setup_page("Reports & History", "📊")
page_header(
    "Research reports and local analysis history.",
    "Export the current experiment metadata and the URL analyses performed in this browser session.",
    "REPORTING CENTER",
)

history = st.session_state.get("analysis_history", [])
if history:
    history_frame = pd.DataFrame(history)
    st.subheader("Session analysis history")
    st.dataframe(history_frame, use_container_width=True, hide_index=True)
    st.download_button("Download history · CSV", dataframe_to_csv(history_frame), "phishguard_analysis_history.csv", "text/csv")
    if st.button("Clear session history"):
        st.session_state["analysis_history"] = []
        st.rerun()
else:
    st.info("No URL analyses in this browser session yet. Use URL Analyzer or Batch Analysis first.")

metrics = load_metrics()
if metrics:
    st.markdown("---")
    st.subheader("Latest model experiment")
    st.write(f"Selected model: **{metrics.get('selected_model', 'Unknown')}**")
    st.json(metrics.get("selected_model_test_metrics", {}))
    st.download_button("Download experiment metrics · JSON", json.dumps(metrics, indent=2).encode("utf-8"), "phishguard_experiment.json", "application/json")
    bundle = load_model_bundle()
    if bundle:
        sections = {
            "Selected model": f"{bundle['model_name']} with validation-selected threshold {bundle['threshold']:.4f}.",
            "Evaluation": "The final metrics are computed on a domain-separated hold-out test split.",
            "Feature scope": "22 lexical and structural features are extracted from the URL string only. The app does not visit the submitted website.",
            "Limitations": "Model outputs may be wrong or miscalibrated on new campaigns. The score is a triage estimate and not a safety guarantee.",
        }
        html = build_html_report("PHISHGUARD AI — Experiment Report", sections)
        st.download_button("Download HTML experiment report", html, "phishguard_experiment_report.html", "text/html")
else:
    st.info("No experiment report exists until a model has been trained in ML Laboratory.")
