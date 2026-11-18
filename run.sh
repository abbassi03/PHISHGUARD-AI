#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"
if [[ ! -d .venv ]]; then
  echo "Virtual environment not found. Run ./setup.sh once first."
  exit 1
fi
# shellcheck disable=SC1091
source .venv/bin/activate
exec streamlit run app.py
