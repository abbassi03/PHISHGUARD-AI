from __future__ import annotations

from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from phishguard.config import DATA_RAW_DIR, MAX_UPLOAD_MB
from phishguard.data.dataset import read_dataset
from phishguard.features.url_features import extract_features_frame
from phishguard.ui import load_local_dataset_into_state, page_header, set_current_dataset, setup_page

setup_page("Dataset Explorer", "🧬")
page_header(
    "Audit the dataset before modeling.",
    "Inspect schema, label balance, duplicates and reproducible URL-only features. Webpage-derived columns are never used.",
    "DATA QUALITY & EXPLORATION",
)

local = load_local_dataset_into_state()
uploaded = st.file_uploader("Upload the official PhiUSIIL CSV or a compatible URL/label CSV", type=["csv"], help=f"Maximum upload size: {MAX_UPLOAD_MB} MB. Required columns: URL and label.")
if uploaded:
    size_mb = len(uploaded.getvalue()) / (1024 * 1024)
    if size_mb > MAX_UPLOAD_MB:
        st.error(f"File is larger than the {MAX_UPLOAD_MB} MB limit.")
    else:
        try:
            with st.spinner("Auditing URL strings, labels, duplicates and domain groups…"):
                dataset, audit = read_dataset(uploaded.getvalue())
            set_current_dataset(dataset, audit.to_dict())
            st.session_state["dataset_file_name"] = uploaded.name
            st.success(f"Dataset audit completed: {len(dataset):,} usable URLs.")
            local = (dataset, audit.to_dict())
        except Exception as exc:
            st.error(f"Dataset validation failed: {exc}")

if local is None:
    local_path = sorted(DATA_RAW_DIR.glob("*.csv")) if DATA_RAW_DIR.exists() else []
    st.info("No dataset loaded. Download the official UCI PhiUSIIL CSV and place it in `data/raw/`, or upload it above.")
    st.markdown("[Open official PhiUSIIL dataset page](https://archive.ics.uci.edu/dataset/967/phiusil+phishing+url+dataset)")
else:
    dataset, audit = local
    source_name = st.session_state.get("dataset_file_name", "Uploaded dataset / local CSV")
    st.caption(f"Source: {source_name} · Internal target encoding: 1 = phishing, 0 = legitimate")
    cols = st.columns(4)
    cols[0].metric("Usable URLs", f"{audit.get('usable_rows', len(dataset)):,}")
    cols[1].metric("Phishing", f"{audit.get('phishing_rows', int((dataset.target == 1).sum())):,}")
    cols[2].metric("Legitimate", f"{audit.get('legitimate_rows', int((dataset.target == 0).sum())):,}")
    cols[3].metric("Unique domains", f"{audit.get('unique_domains', dataset.domain_group.nunique()):,}")

    st.subheader("Dataset quality audit")
    audit_cols = st.columns(4)
    audit_cols[0].metric("Missing rows", f"{audit.get('dropped_missing', 0):,}")
    audit_cols[1].metric("Invalid URLs", f"{audit.get('dropped_invalid_url', 0):,}")
    audit_cols[2].metric("Duplicate URLs removed", f"{audit.get('duplicate_urls_removed', 0):,}")
    audit_cols[3].metric("Input rows", f"{audit.get('input_rows', len(dataset)):,}")

    left, right = st.columns(2)
    with left:
        label_counts = dataset["target"].map({0: "Legitimate", 1: "Phishing"}).value_counts().rename_axis("Class").reset_index(name="Records")
        fig = px.pie(label_counts, names="Class", values="Records", hole=.62, color="Class", color_discrete_map={"Legitimate": "#19a99a", "Phishing": "#e36c83"}, title="Class distribution")
        fig.update_layout(height=340, paper_bgcolor="white", plot_bgcolor="white", legend_title="")
        st.plotly_chart(fig, use_container_width=True)
    with right:
        domain_counts = dataset.groupby("domain_group").size().sort_values(ascending=False).head(12).reset_index(name="URLs")
        fig = px.bar(domain_counts, x="URLs", y="domain_group", orientation="h", title="Top registered domains by URL count", color="URLs", color_continuous_scale=["#b7e8e1", "#6658d3"])
        fig.update_layout(height=340, yaxis_title="Registered domain", coloraxis_showscale=False, paper_bgcolor="white", plot_bgcolor="white")
        st.plotly_chart(fig, use_container_width=True)

    st.subheader("URL-only feature profile")
    sample_size = min(8000, len(dataset))
    sample = dataset.sample(sample_size, random_state=42) if len(dataset) > sample_size else dataset
    with st.spinner(f"Extracting the 22 URL-only features for {len(sample):,} sample rows…"):
        feature_frame = extract_features_frame(sample["url"].tolist())
    feature_frame["class"] = sample["target"].map({0: "Legitimate", 1: "Phishing"}).to_numpy()
    selected_feature = st.selectbox("Feature to inspect", feature_frame.columns.drop("class").tolist(), index=0)
    fig = px.histogram(feature_frame, x=selected_feature, color="class", marginal="box", barmode="overlay", opacity=.72, color_discrete_map={"Legitimate": "#19a99a", "Phishing": "#e36c83"}, title=f"Distribution of {selected_feature}")
    fig.update_layout(height=380, paper_bgcolor="white", plot_bgcolor="white", legend_title="Class")
    st.plotly_chart(fig, use_container_width=True)

    st.subheader("Feature correlation")
    numeric_features = feature_frame.drop(columns=["class"])
    correlation = numeric_features.corr(method="spearman")
    correlation_fig = px.imshow(
        correlation,
        text_auto=".1f",
        aspect="auto",
        color_continuous_scale=["#e39aa8", "#f6f7fb", "#19a99a"],
        color_continuous_midpoint=0,
        zmin=-1,
        zmax=1,
        title="Spearman correlation across URL-only features",
    )
    correlation_fig.update_layout(height=650, paper_bgcolor="white", plot_bgcolor="white")
    st.plotly_chart(correlation_fig, use_container_width=True)

    st.subheader("Validated dataset preview")
    st.dataframe(dataset.head(30), use_container_width=True, hide_index=True)
    st.download_button("Download audited URL/label table · CSV", dataset[["url", "target", "domain_group"]].to_csv(index=False).encode("utf-8-sig"), "phishguard_audited_dataset.csv", "text/csv")

    with st.expander("Audit details and source columns"):
        st.json(audit)
        st.write("Original source columns (only URL and label are retained for modeling):")
        st.write(audit.get("source_columns", []))
