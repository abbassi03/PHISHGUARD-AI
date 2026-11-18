from __future__ import annotations

import pandas as pd
import plotly.express as px
import streamlit as st

from phishguard.explainability.explain import FEATURE_DESCRIPTIONS
from phishguard.features.url_features import extract_url_features
from phishguard.modeling.prediction import predict_one
from phishguard.ui import load_current_model, page_header, setup_page

setup_page("URL Analyzer", "🔎")
page_header(
    "Analyze a URL without visiting it.",
    "Extract lexical and structural URL signals locally, then score them with your trained model when available.",
    "SINGLE-URL TRIAGE",
)

url = st.text_input("URL to analyze", placeholder="https://example.com/account/sign-in", help="The application parses the URL string only. It does not open the website or make DNS/HTTP requests.")
model = load_current_model()

if st.button("Analyze URL", type="primary", disabled=not bool(url.strip())):
    try:
        values = extract_url_features(url)
        result = predict_one(url, model) if model else None
        st.session_state["last_url_analysis"] = {"url": url, "features": values, "result": result}
        history = st.session_state.setdefault("analysis_history", [])
        history.insert(0, {
            "url": url,
            "prediction": result["prediction"] if result else "Features only · model not trained",
            "phishing_score": result["phishing_score"] if result else None,
            "score_band": result["score_band"] if result else "Not scored",
        })
        st.success("URL syntax accepted. Feature extraction completed locally.")
    except ValueError as exc:
        st.error(str(exc))

analysis = st.session_state.get("last_url_analysis")
if analysis:
    st.markdown("---")
    if analysis["result"]:
        result = analysis["result"]
        c1, c2, c3 = st.columns(3)
        c1.metric("Model decision", result["prediction"])
        c2.metric("Phishing model score", f"{result['phishing_score']:.1%}")
        c3.metric("Model score band", result["score_band"])
        if result["prediction"] == "Phishing":
            st.error("The model flags this URL as phishing-like. Treat this as a triage signal and verify through trusted security procedures.")
        else:
            st.success("The model classifies this URL as legitimate-like. This is not a guarantee that the destination is safe.")
        st.caption(f"Model: {result['model_name']} · Decision threshold: {result['decision_threshold']:.3f} · {result['score_note']}")
    else:
        st.warning("No trained model is available yet. The URL was parsed and its URL-only features were extracted, but no phishing classification was produced.")

    st.subheader("Extracted URL features")
    feature_frame = pd.DataFrame(
        [{"Feature": name.replace("_", " ").title(), "Value": value, "Description": FEATURE_DESCRIPTIONS.get(name, name)}
         for name, value in analysis["features"].items()]
    )
    st.dataframe(feature_frame, hide_index=True, use_container_width=True)
    st.download_button(
        "Download feature vector · CSV",
        feature_frame.to_csv(index=False).encode("utf-8-sig"),
        file_name="phishguard_url_features.csv",
        mime="text/csv",
    )

st.markdown("---")
with st.expander("How this analysis works"):
    st.markdown(
        "1. The input is normalized and parsed with Python URL utilities.\n"
        "2. Twenty-two numeric features are extracted from the URL string.\n"
        "3. If a trained artifact exists, the saved model and validation-selected threshold are applied.\n"
        "4. The destination website is never visited. HTTPS, URL length or suspicious words are signals, not proof."
    )
