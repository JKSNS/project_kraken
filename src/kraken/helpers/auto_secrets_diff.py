#!/usr/bin/env python3
"""auto_secrets_diff -- find byte ranges that differ across sibling firmware builds.

When a target ships multiple build variants (eCTF: dev/tech1/tech2 HSMs;
signed-firmware engagements: per-customer images), the bytes that vary
across builds are by construction the personalisation blob -- keys, salts,
PINs, group secrets. Locating that range is the first step in any
secrets-extraction primitive.

Usage:
    python3 auto_secrets_diff.py <bin1> <bin2> [<bin3> ...] [--json] [--out PATH]

Outputs structured JSON when --json or --out is set; human summary otherwise.

Output schema (matches docs/kraken_research_mode_synthesis.md):
{
  "variants": [paths...],
  "diff_runs": [
    {"start_offset": 0xXX, "end_offset": 0xYY, "size": N,
     "interpretation": "size-pattern heuristic"}
  ],
  "total_diff_bytes": N,
  "total_compared_bytes": N,
  "blob_bounds": {"min_offset": 0xXX, "max_offset": 0xYY}
}

Designed to be opportunistic -- runs on any pair of binaries and produces
a degraded-but-useful output if the inputs are mismatched in size.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

SIZE_HINTS = {
    16: "16 bytes -- likely AES-128 key / salt / IV",
    20: "20 bytes -- likely SHA-1 hash",
    24: "24 bytes -- likely AES-192 key / Curve25519 component",
    32: "32 bytes -- likely AES-256 key / SHA-256 / HMAC key / Ed25519 public",
    48: "48 bytes -- likely SHA-384 / Ed25519 (pub+sig prefix)",
    64: "64 bytes -- likely Ed25519 signature / SHA-512 / RSA prime",
    128: "128 bytes -- likely RSA-1024 modulus",
    256: "256 bytes -- likely RSA-2048 modulus",
}


def _size_hint(size: int) -> str:
    return SIZE_HINTS.get(size, f"{size} bytes -- unknown")


def diff_pair(a: bytes, b: bytes) -> list[int]:
    """Return offsets where a and b differ. Compares up to min(len)."""
    n = min(len(a), len(b))
    return [i for i in range(n) if a[i] != b[i]]


def diff_many(blobs: list[bytes]) -> list[int]:
    """Return offsets where any pair of blobs differs."""
    if len(blobs) < 2:
        return []
    n = min(len(b) for b in blobs)
    out = []
    for i in range(n):
        first = blobs[0][i]
        if any(b[i] != first for b in blobs[1:]):
            out.append(i)
    return out


def detect_outlier(blobs: list[bytes], paths: list[Path]) -> int | None:
    """Identify a variant whose pairwise diffs are substantially larger
    than the median pairwise diff (e.g. debug build vs release builds).

    Returns the index of the outlier variant, or None if no clear outlier.
    """
    if len(blobs) < 3:
        return None
    n_pairs = []
    for i in range(len(blobs)):
        sizes = [len(diff_pair(blobs[i], blobs[j])) for j in range(len(blobs)) if j != i]
        n_pairs.append(sum(sizes) / len(sizes))
    sorted_pairs = sorted(n_pairs)
    if sorted_pairs[0] == 0:
        return None
    # Use the smallest pairwise-avg as baseline (the most "central" variant)
    # rather than median: with 4 variants and 1 outlier, the median is
    # already inflated by the outlier's pulls on the other 3.
    baseline = sorted_pairs[0]
    for idx, avg in enumerate(n_pairs):
        if avg > baseline * 2.0:  # 2x baseline = clear outlier
            return idx
    return None


def collapse_runs(diffs: list[int]) -> list[tuple[int, int]]:
    """Collapse consecutive diff offsets into (start, end_inclusive) runs.

    Tolerates gaps of up to 2 bytes -- typical compiler alignment padding."""
    if not diffs:
        return []
    runs = []
    s = diffs[0]
    p = diffs[0]
    GAP_TOLERANCE = 2
    for d in diffs[1:]:
        if d - p <= GAP_TOLERANCE:
            p = d
        else:
            runs.append((s, p))
            s = d
            p = d
    runs.append((s, p))
    return runs


def find_primary_cluster(runs: list[tuple[int, int]], min_run_size: int = 8) -> tuple[int, int] | None:
    """Find the contiguous span containing all "substantive" diff runs.

    Filters out single-byte diffs (typical of debug-build noise from
    embedded __FILE__/__LINE__ macros) and returns (start, end) of the
    densest cluster of runs whose individual size >= min_run_size.

    Heuristic: take all substantive runs, find the largest gap between
    consecutive ones, split there, and return the larger half. Repeat
    until no gap > 0x1000 between adjacent runs in the chosen cluster.
    """
    substantive = [r for r in runs if (r[1] - r[0] + 1) >= min_run_size]
    if not substantive:
        return None

    # Cluster: greedy split on biggest gap until all gaps < threshold
    cluster = substantive
    GAP_THRESHOLD = 0x1000
    while len(cluster) > 1:
        gaps = [(cluster[i + 1][0] - cluster[i][1], i) for i in range(len(cluster) - 1)]
        biggest_gap, idx = max(gaps)
        if biggest_gap < GAP_THRESHOLD:
            break
        left = cluster[: idx + 1]
        right = cluster[idx + 1 :]
        # Pick the cluster with more total bytes
        left_bytes = sum(r[1] - r[0] + 1 for r in left)
        right_bytes = sum(r[1] - r[0] + 1 for r in right)
        cluster = left if left_bytes >= right_bytes else right

    return (cluster[0][0], cluster[-1][1])


def analyze(paths: list[Path], exclude_outliers: bool = True) -> dict[str, Any]:
    blobs: list[bytes] = []
    sizes = []
    for p in paths:
        data = p.read_bytes()
        blobs.append(data)
        sizes.append(len(data))

    if len(set(sizes)) > 1:
        warning = (
            f"size mismatch across variants: {dict(zip([str(p) for p in paths], sizes))} "
            f"-- comparing first {min(sizes)} bytes only"
        )
    else:
        warning = None

    excluded_outlier = None
    if exclude_outliers:
        idx = detect_outlier(blobs, paths)
        if idx is not None:
            excluded_outlier = {
                "path": str(paths[idx]),
                "reason": "pairwise diffs >3x median (likely debug build)",
            }
            blobs = [b for i, b in enumerate(blobs) if i != idx]
            paths = [p for i, p in enumerate(paths) if i != idx]
            sizes = [s for i, s in enumerate(sizes) if i != idx]

    diffs = diff_many(blobs)
    runs = collapse_runs(diffs)
    primary = find_primary_cluster(runs)

    diff_runs = []
    for start, end in runs:
        size = end - start + 1
        diff_runs.append(
            {
                "start_offset": start,
                "start_offset_hex": f"0x{start:x}",
                "end_offset": end,
                "end_offset_hex": f"0x{end:x}",
                "size": size,
                "interpretation": _size_hint(size),
            }
        )

    blob_bounds = None
    if runs:
        blob_bounds = {
            "min_offset": runs[0][0],
            "min_offset_hex": f"0x{runs[0][0]:x}",
            "max_offset": runs[-1][1],
            "max_offset_hex": f"0x{runs[-1][1]:x}",
        }

    primary_cluster = None
    if primary:
        cluster_runs = [r for r in runs if r[0] >= primary[0] and r[1] <= primary[1]]
        cluster_diff_bytes = sum(r[1] - r[0] + 1 for r in cluster_runs)
        primary_cluster = {
            "start_offset": primary[0],
            "start_offset_hex": f"0x{primary[0]:x}",
            "end_offset": primary[1],
            "end_offset_hex": f"0x{primary[1]:x}",
            "span_bytes": primary[1] - primary[0] + 1,
            "diff_bytes_in_cluster": cluster_diff_bytes,
            "run_count": len(cluster_runs),
            "note": ("densest cluster of substantive (>=8 byte) diff runs -- likely the personalisation/secrets blob"),
        }

    out = {
        "variants": [str(p) for p in paths],
        "compared_bytes": min(sizes) if sizes else 0,
        "total_diff_bytes": len(diffs),
        "diff_runs": diff_runs,
        "blob_bounds": blob_bounds,
        "primary_cluster": primary_cluster,
        "excluded_outlier": excluded_outlier,
    }
    if warning:
        out["warning"] = warning
    return out


def _print_human(result: dict[str, Any]) -> None:
    print(f"variants: {result['variants']}")
    print(
        f"compared {result['compared_bytes']} bytes; "
        f"{result['total_diff_bytes']} differ in "
        f"{len(result['diff_runs'])} runs"
    )
    if "warning" in result:
        print(f"WARN: {result['warning']}")
    if result["blob_bounds"]:
        bb = result["blob_bounds"]
        print(f"secrets-blob bounds: {bb['min_offset_hex']} – {bb['max_offset_hex']}")
    if result.get("primary_cluster"):
        pc = result["primary_cluster"]
        print(
            f"primary cluster: {pc['start_offset_hex']}–{pc['end_offset_hex']} "
            f"({pc['span_bytes']} B span, {pc['diff_bytes_in_cluster']} diff bytes "
            f"across {pc['run_count']} runs)"
        )
    for r in result["diff_runs"]:
        print(f"  run {r['start_offset_hex']}–{r['end_offset_hex']} ({r['size']} B) -- {r['interpretation']}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("variants", nargs="+", type=Path, help="2+ sibling binaries to diff")
    p.add_argument("--json", action="store_true", help="emit JSON to stdout")
    p.add_argument("--out", type=Path, help="write JSON to this path (implies --json)")
    p.add_argument(
        "--include-all",
        action="store_true",
        help="don't exclude debug-build outlier variants (default: auto-exclude)",
    )
    args = p.parse_args(argv)

    if len(args.variants) < 2:
        p.error("need at least 2 variants")

    for path in args.variants:
        if not path.is_file():
            print(f"[-] not a file: {path}", file=sys.stderr)
            return 1

    result = analyze(args.variants, exclude_outliers=not args.include_all)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2))
        print(f"wrote {args.out}")
    elif args.json:
        json.dump(result, sys.stdout, indent=2)
        print()
    else:
        _print_human(result)

    return 0


if __name__ == "__main__":
    sys.exit(main())
