from __future__ import annotations

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_RAW_DIR = PROJECT_ROOT / "data" / "raw"
DATA_SAMPLE_DIR = PROJECT_ROOT / "data" / "sample"
ARTIFACT_DIR = Path(os.getenv("PHISHGUARD_ARTIFACT_DIR", PROJECT_ROOT / "artifacts"))
REPORT_DIR = PROJECT_ROOT / "reports"
MODEL_PATH = ARTIFACT_DIR / "phishguard_model.joblib"
METRICS_PATH = ARTIFACT_DIR / "training_metrics.json"
MODEL_CARD_PATH = ARTIFACT_DIR / "MODEL_CARD.md"
MAX_BATCH_ROWS = int(os.getenv("PHISHGUARD_MAX_BATCH_ROWS", "5000"))
MAX_UPLOAD_MB = int(os.getenv("PHISHGUARD_MAX_UPLOAD_MB", "70"))
RANDOM_STATE = 42

DATASET_NAME = "PhiUSIIL Phishing URL (Website)"
DATASET_URL = "https://archive.ics.uci.edu/dataset/967/phiusil+phishing+url+dataset"
DATASET_DOI = "10.1016/j.cose.2023.103545"
