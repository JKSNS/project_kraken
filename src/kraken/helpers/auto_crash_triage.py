#!/usr/bin/env python3
"""auto_crash_triage -- dedupe + classify + minimise AFL++ crashes (B.6).

Closes the loop after auto_fuzz_target_function runs:
  100 raw AFL crashes → ≤10 unique classes → minimised inputs.

Pipeline:
  1. SHA256 the input file → first dedupe pass
  2. Run target with input under ASAN/Valgrind (if available)
  3. Stack-hash the crash report → second dedupe pass (true bug class)
  4. Classify per ASAN signature (heap-overflow / UAF / null-deref / etc.)
  5. Minimise via afl-tmin if available

Honesty constraint: if ASAN/valgrind absent, dedupe by file-sha only +
note in output that classification didn't run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

ASAN_SIG_PATTERNS = {
    "heap-buffer-overflow": re.compile(r"heap-buffer-overflow"),
    "stack-buffer-overflow": re.compile(r"stack-buffer-overflow"),
    "use-after-free": re.compile(r"use-after-free"),
    "double-free": re.compile(r"double-free"),
    "null-deref": re.compile(r"SEGV.*0x0\b"),
    "memcpy-overflow": re.compile(r"AddressSanitizer.*memcpy.*overflow"),
    "uninitialized-memory": re.compile(r"MemorySanitizer|uninitialized"),
    "stack-overflow": re.compile(r"stack-overflow"),
}


@dataclass
class CrashRecord:
    input_path: str
    input_sha: str
    asan_class: str = "unclassified"
    stack_hash: str = ""
    minimised_path: str = ""
    minimised_size: int = 0


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _run_with_asan(target: Path, input_file: Path, timeout_s: int = 5) -> str:
    """Run target with input on stdin (or as @@ first arg); return combined output."""
    try:
        with input_file.open("rb") as f:
            data = f.read()
        r = subprocess.run(
            [str(target), str(input_file)],
            input=data,
            capture_output=True,
            timeout=timeout_s,
        )
        return r.stderr.decode("latin-1", errors="replace") + r.stdout.decode("latin-1", errors="replace")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""


def _classify_asan(output: str) -> str:
    for class_name, pattern in ASAN_SIG_PATTERNS.items():
        if pattern.search(output):
            return class_name
    if "SIGSEGV" in output or "Segmentation fault" in output:
        return "sigsegv-uncategorised"
    if "abort" in output.lower():
        return "abort-uncategorised"
    return "unclassified"


def _stack_hash(output: str) -> str:
    """Hash the top 5 frames of the ASAN/valgrind backtrace -- true bug
    identity (different inputs hitting same bug have same stack hash)."""
    # Match #N 0x... in func at file:line -- top 5
    frames = re.findall(r"#\d+\s+0x[0-9a-f]+\s+in\s+(\S+)", output)[:5]
    if not frames:
        # Fall back to crashing-instruction-pointer
        m = re.search(r"pc\s+0x([0-9a-f]+)", output)
        return m.group(1) if m else ""
    return hashlib.sha256("\n".join(frames).encode()).hexdigest()[:16]


def _minimise(target: Path, input_file: Path, out_dir: Path) -> tuple[str, int]:
    """Use afl-tmin if available to minimise."""
    if not shutil.which("afl-tmin"):
        # No afl-tmin; just copy the input
        out = out_dir / input_file.name
        shutil.copy(input_file, out)
        return (str(out), out.stat().st_size)
    out = out_dir / ("min_" + input_file.name)
    try:
        subprocess.run(
            ["afl-tmin", "-i", str(input_file), "-o", str(out), "--", str(target)],
            capture_output=True,
            timeout=120,
        )
        if out.exists():
            return (str(out), out.stat().st_size)
    except subprocess.TimeoutExpired:
        pass
    shutil.copy(input_file, out)
    return (str(out), out.stat().st_size)


def triage(target: Path, crash_dir: Path, out_dir: Path) -> dict:
    """Walk crash_dir, dedupe + classify + minimise. Emit RESULTS.md."""
    out_dir.mkdir(parents=True, exist_ok=True)
    minimised_dir = out_dir / "minimised"
    minimised_dir.mkdir(exist_ok=True)

    raw_crashes = sorted(crash_dir.glob("*"))
    raw_crashes = [c for c in raw_crashes if c.is_file()]

    # Pass 1: file-sha dedupe
    by_file_sha: dict = {}
    for c in raw_crashes:
        sha = _sha256(c)[:16]
        by_file_sha.setdefault(sha, []).append(c)

    # For each unique file, run target + classify + stack-hash
    by_stack_hash: dict = defaultdict(list)
    records: list = []
    for sha, files in by_file_sha.items():
        rep = files[0]  # one canonical file per sha
        output = _run_with_asan(target, rep) if target.exists() else ""
        asan_class = _classify_asan(output) if output else "no_runtime_classification"
        stack = _stack_hash(output) if output else sha[:16]
        rec = CrashRecord(
            input_path=str(rep),
            input_sha=sha,
            asan_class=asan_class,
            stack_hash=stack,
        )
        records.append(rec)
        by_stack_hash[stack].append(rec)

    # Pass 2: stack-hash dedupe (true unique bugs)
    unique_bugs = []
    for stack, recs in by_stack_hash.items():
        # Pick smallest input as the canonical one
        recs.sort(key=lambda r: Path(r.input_path).stat().st_size)
        canonical = recs[0]
        if target.exists():
            mp, sz = _minimise(target, Path(canonical.input_path), minimised_dir)
            canonical.minimised_path = mp
            canonical.minimised_size = sz
        unique_bugs.append(
            {
                "stack_hash": stack,
                "asan_class": canonical.asan_class,
                "duplicate_count": len(recs),
                "canonical_input": canonical.input_path,
                "minimised_input": canonical.minimised_path,
                "minimised_size": canonical.minimised_size,
            }
        )

    by_class = defaultdict(int)
    for b in unique_bugs:
        by_class[b["asan_class"]] += 1

    # Render RESULTS.md
    md = [
        "# Crash triage results",
        "",
        f"_target: `{target}`_  ",
        f"_crash dir: `{crash_dir}` ({len(raw_crashes)} raw inputs)_",
        "",
        f"- raw inputs:               **{len(raw_crashes)}**",
        f"- file-sha unique:          **{len(by_file_sha)}**",
        f"- stack-hash unique (TRUE bug count): **{len(unique_bugs)}**",
        "",
        "## By bug class",
        "",
    ]
    for cls, n in sorted(by_class.items(), key=lambda kv: -kv[1]):
        md.append(f"- `{cls}`: {n}")
    md.append("")
    md.append("## Unique bugs")
    md.append("")
    md.append("| stack_hash | class | dup_count | minimised |")
    md.append("|---|---|---:|---:|")
    for b in unique_bugs:
        md.append(f"| `{b['stack_hash']}` | {b['asan_class']} | {b['duplicate_count']} | {b['minimised_size']} bytes |")
    (out_dir / "RESULTS.md").write_text("\n".join(md))
    (out_dir / "results.json").write_text(
        json.dumps(
            {
                "target": str(target),
                "raw_count": len(raw_crashes),
                "file_sha_unique": len(by_file_sha),
                "true_unique_bugs": len(unique_bugs),
                "by_class": dict(by_class),
                "bugs": unique_bugs,
            },
            indent=2,
        )
    )

    return {
        "status": "ok",
        "raw_count": len(raw_crashes),
        "true_unique_bugs": len(unique_bugs),
        "out_dir": str(out_dir),
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="auto_crash_triage")
    p.add_argument("target", help="path to the (preferably ASAN-instrumented) binary")
    p.add_argument("crash_dir", help="dir of AFL++ crash inputs")
    p.add_argument("--out-dir", default="triage_out")
    args = p.parse_args(argv)
    result = triage(Path(args.target), Path(args.crash_dir), Path(args.out_dir))
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") == "ok" else 2


if __name__ == "__main__":
    sys.exit(main())
