from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import streamlit as st

from phishguard.config import DATA_RAW_DIR, METRICS_PATH, MODEL_PATH
from phishguard.modeling.training import load_model_bundle

CSS = """
<style>
:root { --pg-navy:#17233f; --pg-indigo:#6658d3; --pg-teal:#19a99a; --pg-muted:#71809a; }
.stApp { background: radial-gradient(circle at 94% 1%, rgba(102,88,211,.075), transparent 25%), #f5f7fc; }
[data-testid="stSidebar"] { background: linear-gradient(180deg,#17233f 0%,#202e50 100%); }
[data-testid="stSidebar"] * { color: #eef2ff !important; }
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p { color:#d5def3 !important; }
.pg-brand { display:flex; align-items:center; gap:12px; padding:8px 0 22px; }
.pg-logo { width:42px;height:42px;display:flex;align-items:center;justify-content:center;border-radius:14px;background:linear-gradient(135deg,#6658d3,#19a99a);font-size:22px;box-shadow:0 8px 20px #0002; }
.pg-brand-title { font-size:18px;font-weight:800;letter-spacing:.04em;color:white; }
.pg-brand-sub { font-size:11px;color:#b9c7e6; }
.pg-hero { padding:26px 28px; border-radius:22px; background:linear-gradient(115deg,#17233f 0%,#293b68 60%,#6658d3 100%);color:white;margin-bottom:18px;box-shadow:0 12px 28px rgba(23,35,63,.14); }
.pg-hero h1 { color:white;font-size:30px;line-height:1.15;margin:0 0 8px; }
.pg-hero p { color:#dbe5ff;margin:0;font-size:14px; }
.pg-eyebrow { text-transform:uppercase;letter-spacing:.14em;font-size:10px;font-weight:800;color:#5fd5c3;margin-bottom:8px; }
.pg-card { background:#fff;border:1px solid #e7ebf4;border-radius:17px;padding:17px 18px;box-shadow:0 6px 22px rgba(25,40,75,.045);min-height:112px; }
.pg-card-label { color:#77839a;font-size:12px;font-weight:650;margin-bottom:9px; }
.pg-card-value { color:#17233f;font-size:27px;font-weight:800;line-height:1.05; }
.pg-card-note { color:#8792a7;font-size:11px;margin-top:8px; }
.pg-section { color:#17233f;font-size:18px;font-weight:800;margin:18px 0 10px; }
.pg-panel { background:#fff;border:1px solid #e7ebf4;border-radius:17px;padding:18px 20px; }
.pg-pill { display:inline-block;border-radius:999px;padding:5px 10px;font-size:11px;font-weight:700;background:#eeecff;color:#584bc0; }
div[data-testid="stMetric"] {background:#fff;border:1px solid #e7ebf4;padding:14px 16px;border-radius:15px;box-shadow:0 5px 18px rgba(25,40,75,.04);}
div[data-testid="stMetricLabel"] p { color:#72809a;font-weight:650; }
div[data-testid="stMetricValue"] { color:#17233f; }
.stButton>button { border-radius:11px;border:0;background:linear-gradient(90deg,#6658d3,#5145bd);color:white;font-weight:700;padding:.55rem 1rem; }
.stButton>button:hover { color:white;border:0;filter:brightness(1.06); }
.stDownloadButton>button { border-radius:10px; }
[data-testid="stDataFrame"] { border:1px solid #e7ebf4;border-radius:12px;overflow:hidden; }
hr { border-color:#e6eaf3; }
footer { visibility:hidden; }
</style>
"""


def setup_page(title: str, icon: str = "🛡️") -> None:
    st.set_page_config(page_title=f"{title} · PHISHGUARD AI", page_icon=icon, layout="wide")
    st.markdown(CSS, unsafe_allow_html=True)
    with st.sidebar:
        st.markdown(
            '<div class="pg-brand"><div class="pg-logo">🛡️</div><div><div class="pg-brand-title">PHISHGUARD AI</div><div class="pg-brand-sub">URL Threat Intelligence Lab</div></div></div>',
            unsafe_allow_html=True,
        )
        st.caption("MASTER 1 · CYBERSECURITY & AI")
        st.markdown("---")
        model_ready = MODEL_PATH.exists()
        st.markdown(f"**Model status:** {'🟢 Trained' if model_ready else '🟠 Not trained'}")
        dataset = get_current_dataset()
        st.markdown(f"**Dataset:** {'🟢 Loaded' if dataset is not None else '🟠 Not loaded'}")
        st.markdown("---")
        st.caption("Defensive research tool · URL-only analysis")


def page_header(title: str, subtitle: str, eyebrow: str = "PHISHGUARD AI") -> None:
    st.markdown(
        f'<div class="pg-hero"><div class="pg-eyebrow">{eyebrow}</div><h1>{title}</h1><p>{subtitle}</p></div>',
        unsafe_allow_html=True,
    )


def metric_card(label: str, value: str, note: str = "") -> None:
    st.markdown(
        f'<div class="pg-card"><div class="pg-card-label">{label}</div><div class="pg-card-value">{value}</div><div class="pg-card-note">{note}</div></div>',
        unsafe_allow_html=True,
    )


def load_metrics() -> dict | None:
    if not METRICS_PATH.exists():
        return None
    try:
        return json.loads(METRICS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def load_current_model() -> dict | None:
    try:
        return load_model_bundle()
    except Exception as exc:
        st.error(f"Model artifact could not be loaded: {exc}")
        return None


def get_current_dataset() -> pd.DataFrame | None:
    return st.session_state.get("prepared_dataset")


def set_current_dataset(dataset: pd.DataFrame, audit: dict) -> None:
    st.session_state["prepared_dataset"] = dataset
    st.session_state["dataset_audit"] = audit


def find_local_dataset() -> Path | None:
    DATA_RAW_DIR.mkdir(parents=True, exist_ok=True)
    candidates = sorted(DATA_RAW_DIR.glob("*.csv"))
    return candidates[0] if candidates else None


def load_local_dataset_into_state() -> tuple[pd.DataFrame, dict] | None:
    current = get_current_dataset()
    if current is not None:
        return current, st.session_state.get("dataset_audit", {})
    path = find_local_dataset()
    if path is None:
        return None
    try:
        from phishguard.data.dataset import read_dataset

        dataset, audit = read_dataset(path)
        set_current_dataset(dataset, audit.to_dict())
        st.session_state["dataset_file_name"] = path.name
        return dataset, audit.to_dict()
    except Exception as exc:
        st.error(f"Could not load {path.name}: {exc}")
        return None


def load_model_metrics_pair() -> tuple[dict | None, dict | None]:
    return load_current_model(), load_metrics()
