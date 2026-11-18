from __future__ import annotations

import plotly.express as px
import streamlit as st

from phishguard.explainability.explain import build_feature_context, global_importance_frame, shap_local_explanation
from phishguard.features.url_features import extract_url_features
from phishguard.modeling.prediction import predict_one
from phishguard.ui import load_current_model, load_metrics, page_header, setup_page

setup_page("Explainability", "🧠")
page_header(
    "Understand the signals behind model behaviour.",
    "Review global feature importance and, when supported by an installed optional package, local SHAP contributions.",
    "EXPLAINABLE AI",
)

bundle = load_current_model()
metrics = load_metrics()
if not bundle or not metrics:
    st.info("Train a model in ML Laboratory before opening the explainability workspace.")
else:
    st.subheader("Global model feature importance")
    importance = global_importance_frame(metrics)
    if importance.empty:
        st.warning("The selected model does not expose native feature importance in this artifact.")
    else:
        chart_data = importance.head(15).sort_values("importance")
        fig = px.bar(chart_data, x="importance", y="feature", orientation="h", color="importance", color_continuous_scale=["#b9e6df", "#6658d3"], title="Top URL-only features")
        fig.update_layout(height=520, yaxis_title="", xaxis_title="Relative importance", coloraxis_showscale=False, paper_bgcolor="white", plot_bgcolor="white")
        st.plotly_chart(fig, use_container_width=True)
        st.caption("Importance describes how this trained model uses features. It is not causal evidence and does not prove a URL is malicious.")
        st.dataframe(importance, use_container_width=True, hide_index=True)

    st.markdown("---")
    st.subheader("Inspect one URL")
    url = st.text_input("URL for feature-level explanation", placeholder="https://example.com/account")
    if st.button("Explain URL", type="primary", disabled=not bool(url.strip())):
        try:
            prediction = predict_one(url, bundle)
            st.session_state["explain_url"] = url
            st.session_state["explain_result"] = prediction
        except ValueError as exc:
            st.error(str(exc))

    if st.session_state.get("explain_result"):
        result = st.session_state["explain_result"]
        a, b, c = st.columns(3)
        a.metric("Model prediction", result["prediction"])
        b.metric("Phishing model score", f"{result['phishing_score']:.1%}")
        c.metric("Model score band", result["score_band"])
        st.markdown("**Optional SHAP local explanation**")
        with st.spinner("Computing local explanation if SHAP is installed…"):
            shap_frame = shap_local_explanation(st.session_state["explain_url"], bundle)
        if shap_frame is not None and not shap_frame.empty:
            shap_frame["direction"] = shap_frame["shap_value"].map(lambda x: "Pushes toward phishing" if x > 0 else "Pushes away from phishing")
            fig = px.bar(shap_frame.head(12).sort_values("shap_value"), x="shap_value", y="feature", orientation="h", color="shap_value", color_continuous_scale=["#19a99a", "#f1bd64", "#e36c83"], title="Local SHAP contribution to the phishing-class output")
            fig.update_layout(height=440, paper_bgcolor="white", plot_bgcolor="white", yaxis_title="", coloraxis_showscale=False)
            st.plotly_chart(fig, use_container_width=True)
            st.dataframe(shap_frame, use_container_width=True, hide_index=True)
        else:
            st.info("SHAP is optional and is not installed, or the selected model does not support this local explainer. The table below shows extracted values alongside global importance; it is context, not a local causal explanation.")
        context = build_feature_context(st.session_state["explain_url"], metrics)
        st.subheader("URL feature context")
        st.dataframe(context, use_container_width=True, hide_index=True)
