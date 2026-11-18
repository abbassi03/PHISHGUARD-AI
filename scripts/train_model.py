#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from phishguard.data.dataset import read_dataset  # noqa: E402
from phishguard.modeling.training import train_compare_models  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Train PHISHGUARD AI using a domain-separated protocol.")
    parser.add_argument("dataset", type=Path, help="Source CSV with URL and label columns.")
    parser.add_argument("--models", nargs="+", default=["Logistic Regression", "Decision Tree", "Random Forest"], choices=["Logistic Regression", "Decision Tree", "Random Forest", "Extra Trees"])
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    dataset, audit = read_dataset(args.dataset)
    metrics = train_compare_models(dataset, audit=audit, selected_models=args.models, random_state=args.seed)
    print(f"Selected model (validation F1): {metrics['selected_model']}")
    print(f"Test F1 (phishing): {metrics['selected_model_test_metrics']['f1_phishing']:.4f}")
    print(f"Artifacts saved under: {PROJECT_ROOT / 'artifacts'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
