from __future__ import annotations

import json

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from phishguard.config import MAX_UPLOAD_MB
from phishguard.data.dataset import read_dataset
from phishguard.modeling.training import train_compare_models
from phishguard.ui import load_local_dataset_into_state, load_metrics, page_header, set_current_dataset, setup_page

setup_page("ML Laboratory", "🧪")
page_header(
    "Train, compare and validate models.",
    "Use registered-domain-separated train/validation/test splits. Select the model on validation F1; keep test metrics for final reporting.",
    "MACHINE LEARNING LABORATORY",
)

local = load_local_dataset_into_state()
uploaded = st.file_uploader("Upload URL/label CSV", type=["csv"], help=f"Maximum {MAX_UPLOAD_MB} MB. Columns URL and label are required.")
if uploaded:
    size_mb = len(uploaded.getvalue()) / (1024 * 1024)
    if size_mb > MAX_UPLOAD_MB:
        st.error(f"File is larger than the {MAX_UPLOAD_MB} MB limit.")
    else:
        try:
            with st.spinner("Validating labels, URLs and domain groups…"):
                dataset, audit = read_dataset(uploaded.getvalue())
            set_current_dataset(dataset, audit.to_dict())
            st.session_state["dataset_file_name"] = uploaded.name
            local = (dataset, audit.to_dict())
            st.success(f"Dataset ready: {len(dataset):,} valid URL records.")
        except Exception as exc:
            st.error(f"Dataset validation failed: {exc}")

if local is None:
    st.warning("Load a dataset in Dataset Explorer or upload a CSV above before training.")
    st.markdown("Required columns: `URL`, `label`. UCI PhiUSIIL uses 0 = phishing and 1 = legitimate.")
else:
    dataset, audit = local
    st.caption(f"Active dataset: {st.session_state.get('dataset_file_name', 'Local or session dataset')} · {len(dataset):,} rows · {dataset.domain_group.nunique():,} registered domains")
    st.info("The system ignores all precomputed page/HTML features and derives the 22 model inputs from URL strings only.")
    model_options = ["Logistic Regression", "Decision Tree", "Random Forest", "Extra Trees"]
    selected = st.multiselect(
        "Models to compare",
        options=model_options,
        default=["Logistic Regression", "Decision Tree", "Random Forest"],
        help="At least one model is required. More models increase training time.",
    )
    random_state = st.number_input("Random seed", min_value=0, max_value=100000, value=42, step=1)
    if st.button("Train and compare selected models", type="primary", disabled=not selected):
        try:
            with st.spinner("Extracting URL features, splitting by domain, training models and evaluating the hold-out test set…"):
                metrics = train_compare_models(dataset, audit=audit, selected_models=selected, random_state=int(random_state))
            st.session_state["last_training_metrics"] = metrics
            st.success(f"Training completed. Selected on validation F1: {metrics['selected_model']}.")
        except Exception as exc:
            st.error(f"Training could not complete: {exc}")
            st.exception(exc)

metrics = st.session_state.get("last_training_metrics") or load_metrics()
if metrics:
    st.markdown("---")
    selected_name = metrics.get("selected_model", "Unknown")
    st.subheader(f"Selected model · {selected_name}")
    selected_test = metrics.get("selected_model_test_metrics", {})
    kpi = st.columns(4)
    kpi[0].metric("F1 · phishing", f"{selected_test.get('f1_phishing', 0):.3f}")
    kpi[1].metric("Recall · phishing", f"{selected_test.get('recall_phishing', 0):.3f}")
    kpi[2].metric("Precision · phishing", f"{selected_test.get('precision_phishing', 0):.3f}")
    kpi[3].metric("PR-AUC", "—" if selected_test.get("pr_auc") is None else f"{selected_test['pr_auc']:.3f}")

    comparison_rows = []
    for name, result in metrics.get("all_models_test_metrics", {}).items():
        comparison_rows.append({
            "Model": name,
            "Precision": result["precision_phishing"],
            "Recall": result["recall_phishing"],
            "F1": result["f1_phishing"],
            "PR-AUC": result["pr_auc"],
            "ROC-AUC": result["roc_auc"],
            "FPR": result["false_positive_rate"],
            "FNR": result["false_negative_rate"],
            "Training seconds": result["training_seconds"],
        })
    comparison = pd.DataFrame(comparison_rows).sort_values("F1", ascending=False)
    st.subheader("Hold-out test comparison")
    st.dataframe(comparison, use_container_width=True, hide_index=True)
    fig = px.bar(comparison.melt(id_vars="Model", value_vars=["Precision", "Recall", "F1", "PR-AUC"], var_name="Metric", value_name="Score"), x="Model", y="Score", color="Metric", barmode="group", title="Model performance on domain-separated test data", color_discrete_sequence=["#6658d3", "#19a99a", "#e6a23c", "#e36c83"])
    fig.update_layout(height=420, yaxis_range=[0, 1], paper_bgcolor="white", plot_bgcolor="white", legend_title="")
    st.plotly_chart(fig, use_container_width=True)

    st.subheader("Discrimination curves")
    roc_col, pr_col = st.columns(2)
    palette = {"Logistic Regression": "#6658d3", "Decision Tree": "#19a99a", "Random Forest": "#e6a23c", "Extra Trees": "#e36c83"}
    roc_fig = go.Figure()
    pr_fig = go.Figure()
    for name, result in metrics.get("all_models_test_metrics", {}).items():
        points = result.get("curves", {})
        roc_points = points.get("roc", [])
        pr_points = points.get("precision_recall", [])
        if roc_points:
            roc_fig.add_trace(go.Scatter(x=[p[0] for p in roc_points], y=[p[1] for p in roc_points], mode="lines", name=name, line={"color": palette.get(name)}))
        if pr_points:
            pr_fig.add_trace(go.Scatter(x=[p[0] for p in pr_points], y=[p[1] for p in pr_points], mode="lines", name=name, line={"color": palette.get(name)}))
    roc_fig.add_trace(go.Scatter(x=[0, 1], y=[0, 1], mode="lines", name="Random baseline", line={"dash": "dash", "color": "#9aa4b5"}))
    roc_fig.update_layout(title="ROC curve · test split", xaxis_title="False Positive Rate", yaxis_title="True Positive Rate", height=380, yaxis_range=[0, 1], xaxis_range=[0, 1], paper_bgcolor="white", plot_bgcolor="white", legend_title="Model")
    pr_fig.update_layout(title="Precision–Recall curve · test split", xaxis_title="Recall", yaxis_title="Precision", height=380, yaxis_range=[0, 1], xaxis_range=[0, 1], paper_bgcolor="white", plot_bgcolor="white", legend_title="Model")
    with roc_col:
        st.plotly_chart(roc_fig, use_container_width=True)
    with pr_col:
        st.plotly_chart(pr_fig, use_container_width=True)

    st.subheader("Selected model · confusion matrix")
    cm = selected_test.get("confusion_matrix", [[0, 0], [0, 0]])
    cm_fig = go.Figure(data=go.Heatmap(z=cm, x=["Predicted legitimate", "Predicted phishing"], y=["Actual legitimate", "Actual phishing"], colorscale=[[0, "#eff1fb"], [1, "#6658d3"]], showscale=False, text=cm, texttemplate="%{text}"))
    cm_fig.update_layout(height=330, paper_bgcolor="white", plot_bgcolor="white", margin=dict(l=15, r=15, t=20, b=20))
    st.plotly_chart(cm_fig, use_container_width=True)

    st.subheader("Domain-separated split report")
    st.json(metrics.get("split_summary", {}))
    st.caption(f"Decision threshold was selected on validation data only: {metrics.get('selected_threshold', 0):.4f}. Model selection criterion: highest phishing-class validation F1.")
    st.download_button("Download experiment metrics · JSON", json.dumps(metrics, indent=2).encode("utf-8"), "phishguard_training_metrics.json", "application/json")
else:
    st.info("No experiment is stored yet. Load the official dataset, choose your models, then start training.")

with st.expander("Experiment protocol"):
    st.markdown(
        "- Registered domains are kept separate across train, validation and test.\n"
        "- The threshold is selected on validation F1 for the phishing class.\n"
        "- The held-out test set is used only for final evaluation.\n"
        "- Internal target encoding: 1 = phishing, 0 = legitimate.\n"
        "- All URL features are extracted from the URL string. HTML/page-derived UCI columns are excluded."
    )
