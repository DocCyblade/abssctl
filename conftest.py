"""Pytest bootstrap to ensure local sources are importable."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
src_path = str(SRC)
if SRC.exists() and src_path not in sys.path:
    sys.path.insert(0, src_path)
