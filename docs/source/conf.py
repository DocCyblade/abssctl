"""Sphinx configuration for abssctl documentation."""
from __future__ import annotations

import pathlib
import sys
from datetime import UTC, datetime

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

project = "abssctl"
author = "Ken Robinson"
copyright = f"{datetime.now(UTC):%Y}, Ken Robinson"

release = "0.1.0a0"
version = release

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.todo",
    "sphinx.ext.autosectionlabel",
]

autodoc_default_options = {
    "members": True,
    "undoc-members": False,
    "show-inheritance": False,
}

templates_path = ["_templates"]
exclude_patterns: list[str] = ["_build", "Thumbs.db", ".DS_Store"]

html_theme = "sphinx_rtd_theme"
html_static_path = ["_static"]
html_css_files = getattr(globals(), "html_css_files", [])
html_css_files += ["wrap.css"]

napoleon_google_docstring = False
napoleon_numpy_docstring = True
napoleon_use_param = True
napoleon_use_rtype = False

# Make TODO entries visible while the project is in flux.
todo_include_todos = True
