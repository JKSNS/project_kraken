"""Shared sys.path setup for unit tests.

Adds the repo's src/ to sys.path so package imports work
without setting PYTHONPATH explicitly.
"""

from __future__ import annotations

import sys
from pathlib import Path

_THIS_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _THIS_DIR.parent.parent  # project_kraken/
_SRC = _PROJECT_ROOT / "src"

if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
