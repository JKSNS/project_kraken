#!/usr/bin/env python3
"""Calibration discipline (audit gap F).

Runs the holdout scorer, compares precision@K against the last committed
baseline (data/precision_baseline.json). Exits non-zero if precision drops
more than the allowed threshold -- preventing methodology weight changes
from silently degrading recall.

Usage:
  python3 scripts/precision_regression.py            # check vs baseline
  python3 scripts/precision_regression.py --update   # re-write baseline (after intentional improvement)
  python3 scripts/precision_regression.py --threshold 0.05  # allow 5% drop

Wire as a pre-commit hook:
  ln -sf ../../scripts/precision_regression.py .git/hooks/pre-commit
  chmod +x .git/hooks/pre-commit
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOLDOUT_SCORE = REPO / "benchmarks" / "dossier" / "holdout" / "score.py"
SUMMARY = REPO / "benchmarks" / "dossier" / "holdout" / "summary.json"
BASELINE = REPO / "data" / "precision_baseline.json"


def _run_scorer() -> dict:
    if not HOLDOUT_SCORE.exists():
        print(f"missing: {HOLDOUT_SCORE}", file=sys.stderr)
        sys.exit(2)
    r = subprocess.run(
        ["python3", str(HOLDOUT_SCORE), "--top-k", "5"],
        capture_output=True,
        text=True,
        timeout=600,
        env={**__import__("os").environ, "PYTHONPATH": str(REPO / "src")},
    )
    if r.returncode != 0:
        print("scorer failed:", r.stderr[:1000], file=sys.stderr)
        sys.exit(2)
    if not SUMMARY.exists():
        print(f"scorer did not write: {SUMMARY}", file=sys.stderr)
        sys.exit(2)
    return json.loads(SUMMARY.read_text())


def main() -> int:
    p = argparse.ArgumentParser(prog="precision_regression")
    p.add_argument(
        "--update", action="store_true", help="Replace baseline with current measurement (intentional improvement)"
    )
    p.add_argument("--threshold", type=float, default=0.10, help="Maximum allowed precision drop (default 0.10 = 10%%)")
    args = p.parse_args()

    current = _run_scorer()
    BASELINE.parent.mkdir(parents=True, exist_ok=True)

    if args.update or not BASELINE.exists():
        BASELINE.write_text(json.dumps(current, indent=2) + "\n")
        action = "updated" if args.update else "initialized"
        print(f"[precision_regression] baseline {action}: {current}")
        return 0

    baseline = json.loads(BASELINE.read_text())
    base_p = baseline.get("sink_call_precision_at_k", 0.0)
    cur_p = current.get("sink_call_precision_at_k", 0.0)
    delta = cur_p - base_p

    print("[precision_regression]")
    print(f"  baseline precision@{baseline.get('top_k', '?')}: {base_p:.3f}")
    print(f"  current  precision@{current.get('top_k', '?')}: {cur_p:.3f}")
    print(f"  delta:   {delta:+.3f}")

    if delta < -args.threshold:
        print(f"  REGRESSION: drop {-delta:.3f} exceeds threshold {args.threshold:.3f}", file=sys.stderr)
        print("  Either fix the regression or run with --update to acknowledge.", file=sys.stderr)
        return 1
    if delta > 0:
        print("  Improvement. Consider running with --update to bake in the new floor.")
    else:
        print("  No regression beyond threshold.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
