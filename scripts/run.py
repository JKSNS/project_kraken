#!/usr/bin/env python3
"""CLI entry point for KRAKEN solver."""

import sys
from pathlib import Path

# Add src to path for development
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from kraken.orchestrator import main

if __name__ == "__main__":
    exit(main())
