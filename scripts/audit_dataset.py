#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from phishguard.data.dataset import read_dataset  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit a URL/label CSV without using page-derived features.")
    parser.add_argument("dataset", type=Path, help="Path to the source CSV (must contain URL and label columns).")
    parser.add_argument("--output", type=Path, help="Optional path for audited URL/target/domain CSV.")
    args = parser.parse_args()
    dataset, audit = read_dataset(args.dataset)
    print(json.dumps(audit.to_dict(), indent=2))
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        dataset.to_csv(args.output, index=False)
        print(f"\nAudited dataset written to: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
