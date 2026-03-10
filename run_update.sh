#!/usr/bin/env bash
set -euo pipefail

# หา path ของ script ตัวนี้
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# virtualenv อยู่ใน project
VENV_DIR="$SCRIPT_DIR/.venv"
PYTHON_BIN="$VENV_DIR/bin/python"

# เข้า directory project
cd "$SCRIPT_DIR"

# เช็คว่า venv มีไหม
if [ ! -x "$PYTHON_BIN" ]; then
  echo "Python virtualenv not found at $PYTHON_BIN"
  echo "Create it with:"
  echo "  python3 -m venv .venv"
  echo "  source .venv/bin/activate"
  echo "  pip install -r requirements.txt"
  exit 1
fi

# รัน script
"$PYTHON_BIN" fetch_feeds.py --verbose