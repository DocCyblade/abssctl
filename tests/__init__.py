"""Test package marker to enable relative imports in tooling like mutmut."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
src_path = str(SRC)
if SRC.exists() and src_path not in sys.path:
    sys.path.insert(0, src_path)
