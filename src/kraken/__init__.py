"""KRAKEN: Autonomous Reverse Engineering CTF Solver."""

# Force HuggingFace / sentence-transformers fully offline BEFORE any import
# touches the library.  The embedding model (~90 MB) is cached in
# ~/.cache/huggingface/ after the first explicit download.  After that,
# every subsequent load is 100 % local -- no HTTP requests at all.
import os as _os

_os.environ.setdefault("HF_HUB_OFFLINE", "1")
_os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
_os.environ.setdefault("HF_DATASETS_OFFLINE", "1")
_os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
_os.environ.setdefault("DO_NOT_TRACK", "1")

del _os

__version__ = "1.0.0"
