"""Ensure the local `src` directory stays on sys.path for ad-hoc runners."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"

src_path = str(SRC)
if SRC.is_dir() and src_path not in sys.path:
    sys.path.insert(0, src_path)
