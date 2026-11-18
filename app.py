from __future__ import annotations

import pandas as pd
import plotly.express as px
import streamlit as st

from phishguard.config import MODEL_PATH
from phishguard.ui import load_metrics, metric_card, page_header, setup_page

setup_page("Overview")
page_header(
    "Phishing intelligence, grounded in URL evidence.",
    "A research workspace for URL feature engineering, machine-learning evaluation and explainable defensive triage.",
    "SECURITY ANALYTICS WORKSPACE",
)

metrics = load_metrics()
model_ready = MODEL_PATH.exists() and metrics is not None

a, b, c, d = st.columns(4)
with a:
    metric_card("MODEL STATUS", "Trained" if model_ready else "Not trained", "A local model artifact is available" if model_ready else "Train a model in ML Laboratory")
with b:
    metric_card("FEATURES", "22", "URL-only, reproducible features")
with c:
    metric_card("DATASET", "PhiUSIIL", "UCI source · labels normalized internally")
with d:
    metric_card("ANALYSIS MODE", "Offline", "No target URL requests are made")

st.markdown('<div class="pg-section">Research workflow</div>', unsafe_allow_html=True)
left, right = st.columns([1.25, 1])
with left:
    with st.container(border=True):
        st.subheader("From URL string to an explainable decision")
        steps = pd.DataFrame(
            {
                "Stage": ["URL input", "Feature extraction", "Model inference", "Risk explanation", "Report"],
                "Order": [1, 2, 3, 4, 5],
            }
        )
        fig = px.bar(
            steps,
            x="Order",
            y="Stage",
            orientation="h",
            color="Order",
            color_continuous_scale=["#19a99a", "#6658d3"],
        )
        fig.update_layout(
            height=280,
            showlegend=False,
            coloraxis_showscale=False,
            margin=dict(l=8, r=8, t=10, b=10),
            plot_bgcolor="white",
            paper_bgcolor="white",
        )
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
with right:
    with st.container(border=True):
        st.subheader("Scientific guardrails")
        st.markdown(
            """
            - **URL-only:** no HTTP requests to submitted domains.
            - **Leakage-aware:** model evaluation groups URLs by registrable domain.
            - **Validation threshold:** decision threshold selected on validation, not test.
            - **Transparent labels:** UCI `0 = phishing`, `1 = legitimate`; internal positive class is phishing.
            - **Human review:** scores are estimates, not proof of maliciousness.
            """
        )

st.markdown('<div class="pg-section">Latest experiment</div>', unsafe_allow_html=True)
if model_ready:
    selected = metrics.get("selected_model_test_metrics", {})
    st.success(f"Trained model available: **{metrics.get('selected_model', 'Unknown')}**")
    cols = st.columns(4)
    for col, label, key in zip(
        cols,
        ["F1 · phishing", "Recall · phishing", "Precision · phishing", "PR-AUC"],
        ["f1_phishing", "recall_phishing", "precision_phishing", "pr_auc"],
    ):
        value = selected.get(key)
        col.metric(label, "—" if value is None else f"{value:.3f}")
    split = metrics.get("split_summary", {})
    st.caption(
        f"Domain-separated split · train {split.get('train', {}).get('rows', 0):,} rows · "
        f"validation {split.get('validation', {}).get('rows', 0):,} rows · test {split.get('test', {}).get('rows', 0):,} rows"
    )
else:
    st.info(
        "No trained model found yet. Add the official UCI CSV to `data/raw/` or upload it in Dataset Explorer, "
        "audit it, then train and compare models in ML Laboratory. This workspace does not display fabricated metrics."
    )


active_dataset = st.session_state.get("prepared_dataset")
if active_dataset is not None and not active_dataset.empty:
    st.markdown('<div class="pg-section">Current dataset snapshot</div>', unsafe_allow_html=True)
    dataset_left, dataset_right = st.columns(2)
    with dataset_left:
        class_counts = active_dataset["target"].map({0: "Legitimate", 1: "Phishing"}).value_counts().rename_axis("Class").reset_index(name="Records")
        class_fig = px.pie(
            class_counts,
            names="Class",
            values="Records",
            hole=0.62,
            color="Class",
            color_discrete_map={"Legitimate": "#19a99a", "Phishing": "#e36c83"},
            title="Audited URL class balance",
        )
        class_fig.update_layout(height=330, paper_bgcolor="white", plot_bgcolor="white", legend_title="")
        st.plotly_chart(class_fig, use_container_width=True)
    with dataset_right:
        group_counts = active_dataset.groupby("domain_group").size().sort_values(ascending=False).head(10).reset_index(name="URL records")
        domain_fig = px.bar(
            group_counts.sort_values("URL records"),
            x="URL records",
            y="domain_group",
            orientation="h",
            color="URL records",
            color_continuous_scale=["#b9e6df", "#6658d3"],
            title="Most represented registered domains",
        )
        domain_fig.update_layout(height=330, yaxis_title="", coloraxis_showscale=False, paper_bgcolor="white", plot_bgcolor="white")
        st.plotly_chart(domain_fig, use_container_width=True)
else:
    st.caption("Dataset charts will appear here after a successful audit in Dataset Explorer.")

if model_ready and metrics.get("global_feature_importance"):
    st.markdown('<div class="pg-section">What the selected model uses</div>', unsafe_allow_html=True)
    importance_frame = pd.DataFrame(metrics["global_feature_importance"]).head(10).sort_values("importance")
    importance_fig = px.bar(
        importance_frame,
        x="importance",
        y="feature",
        orientation="h",
        color="importance",
        color_continuous_scale=["#b9e6df", "#6658d3"],
        title="Top global model features",
    )
    importance_fig.update_layout(height=390, yaxis_title="", coloraxis_showscale=False, paper_bgcolor="white", plot_bgcolor="white")
    st.plotly_chart(importance_fig, use_container_width=True)

st.markdown('<div class="pg-section">Workspace navigation</div>', unsafe_allow_html=True)
nav_cols = st.columns(3)
nav_items = [
    ("URL Analyzer", "Inspect URL structure and obtain a model prediction."),
    ("Batch Analysis", "Analyze a CSV of URLs with bounded row counts."),
    ("Dataset Explorer", "Audit labels, duplicates, classes and URL-derived features."),
    ("ML Laboratory", "Train and compare models with grouped evaluation."),
    ("Explainability", "Review global feature importance and optional SHAP output."),
    ("Reports & History", "Export analysis results and experiment reports."),
]
for index, (title, desc) in enumerate(nav_items):
    with nav_cols[index % 3]:
        st.markdown(f"**{title}**")
        st.caption(desc)

st.caption("PHISHGUARD AI v1.0.0 · Academic research prototype · Use only with URLs and datasets you are authorized to analyze.")
