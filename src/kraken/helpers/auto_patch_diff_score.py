#!/usr/bin/env python3
"""auto_patch_diff_score -- score a winning patch against the upstream fix.

For OSV-ingested CVEs we capture `upstream_fix.diff` during ingest. After
auto_patch_synth produces a winner, this helper compares the two diffs
to surface "did kraken converge on the canonical fix?" as a real metric
(not just "tests passed").

Three signals:
  1. file overlap        -- same files touched?
  2. line-level overlap  -- Jaccard similarity on changed-line content
                            (after stripping leading +/-, whitespace,
                            and obvious noise)
  3. function overlap    -- same C/Rust/Python function bodies modified?

A winning patch with high upstream similarity is strong evidence the
helper is producing real fixes, not stubs that happen to silence the
test.

Usage:
    python3 auto_patch_diff_score.py --winner patch.json \\
        --upstream upstream_fix.diff [--out score.json]

    python3 auto_patch_diff_score.py --cve-dir ./cve/CVE-2018-25032

Output schema:
{
  "cve": "<id>",
  "winner_diff_lines": N,
  "upstream_diff_lines": N,
  "files_overlap":   {"jaccard": 0..1, "winner_only": [...], "upstream_only": [...]},
  "line_overlap":    {"jaccard": 0..1, "shared_lines": N, "winner_unique": N, "upstream_unique": N},
  "function_overlap":{"jaccard": 0..1, "shared_fns": [...], "winner_only_fns": [...], "upstream_only_fns": [...]},
  "summary": {
    "convergence":  0..1,        # weighted average of the three Jaccards
    "verdict": "canonical|partial|divergent|unrelated"
  }
}
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

# ── diff parsing ──────────────────────────────────────────────────────


def _parse_diff(diff_text: str) -> dict[str, Any]:
    """Walk a unified diff. Return:
    files: {path: {added: [str], removed: [str]}}
    function_contexts: list of nearest function-name hints from `@@ ... @@`
    """
    out: dict[str, dict[str, list[str]]] = {}
    function_contexts: list[str] = []
    current_file: str | None = None
    for line in diff_text.splitlines():
        if line.startswith("--- a/") or line.startswith("--- "):
            continue
        if line.startswith("+++ b/"):
            current_file = line[6:].strip()
            out.setdefault(current_file, {"added": [], "removed": []})
        elif line.startswith("+++ "):
            current_file = line[4:].strip()
            if current_file == "/dev/null":
                current_file = None
            else:
                out.setdefault(current_file, {"added": [], "removed": []})
        elif line.startswith("@@"):
            # `@@ -1,2 +3,4 @@ functionName(args)`
            after = line.split("@@", 2)
            if len(after) >= 3:
                ctx = after[2].strip()
                if ctx:
                    function_contexts.append(ctx)
        elif line.startswith("+") and not line.startswith("+++") and current_file:
            out[current_file]["added"].append(line[1:])
        elif line.startswith("-") and not line.startswith("---") and current_file:
            out[current_file]["removed"].append(line[1:])
    return {"files": out, "function_contexts": function_contexts}


def _normalize_line(line: str) -> str:
    """Strip whitespace + comments + obvious volatility."""
    line = line.strip()
    # Strip C/Rust/JS line comments
    line = re.sub(r"//.*$", "", line)
    # Strip C block-comment fragments
    line = re.sub(r"/\*.*?\*/", "", line)
    # Strip Python comments (if any)
    line = re.sub(r"\s+#.*$", "", line)
    # Collapse internal whitespace
    line = re.sub(r"\s+", " ", line)
    return line.strip()


def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 1.0
    return len(a & b) / max(1, len(a | b))


def _extract_function_names(contexts: list[str]) -> set[str]:
    """Pull function-ish identifiers from `@@ ... @@` context hints."""
    out: set[str] = set()
    for ctx in contexts:
        # Look for `\w+\s*\(` -- typical function call/decl shape
        m = re.search(r"\b([a-zA-Z_]\w{1,128})\s*\(", ctx)
        if m:
            out.add(m.group(1))
        else:
            # Maybe a Python def?
            m = re.search(r"\bdef\s+([a-zA-Z_]\w+)", ctx)
            if m:
                out.add(m.group(1))
    return out


# ── scoring ───────────────────────────────────────────────────────────


def score(winner_diff: str, upstream_diff: str) -> dict[str, Any]:
    w = _parse_diff(winner_diff)
    u = _parse_diff(upstream_diff)

    # Files overlap
    w_files = set(w["files"].keys())
    u_files = set(u["files"].keys())
    files_jaccard = _jaccard(w_files, u_files)

    # Line-level overlap (across all touched files; ignore leading slash
    # diffs to compare just content)
    w_lines: set[str] = set()
    u_lines: set[str] = set()
    for f, content in w["files"].items():
        for ln in content["added"] + content["removed"]:
            n = _normalize_line(ln)
            if n:
                w_lines.add(n)
    for f, content in u["files"].items():
        for ln in content["added"] + content["removed"]:
            n = _normalize_line(ln)
            if n:
                u_lines.add(n)
    line_jaccard = _jaccard(w_lines, u_lines)

    # Function-name overlap (from @@ headers)
    w_fns = _extract_function_names(w["function_contexts"])
    u_fns = _extract_function_names(u["function_contexts"])
    fn_jaccard = _jaccard(w_fns, u_fns)

    # Composite convergence: weight files most (must touch same code), then
    # functions, then line content
    convergence = (0.4 * files_jaccard) + (0.3 * fn_jaccard) + (0.3 * line_jaccard)

    if convergence >= 0.75:
        verdict = "canonical"
    elif convergence >= 0.45:
        verdict = "partial"
    elif convergence >= 0.15:
        verdict = "divergent"
    else:
        verdict = "unrelated"

    return {
        "winner_diff_lines": sum(len(c["added"]) + len(c["removed"]) for c in w["files"].values()),
        "upstream_diff_lines": sum(len(c["added"]) + len(c["removed"]) for c in u["files"].values()),
        "files_overlap": {
            "jaccard": round(files_jaccard, 3),
            "shared": sorted(w_files & u_files),
            "winner_only": sorted(w_files - u_files),
            "upstream_only": sorted(u_files - w_files),
        },
        "line_overlap": {
            "jaccard": round(line_jaccard, 3),
            "shared_lines": len(w_lines & u_lines),
            "winner_unique": len(w_lines - u_lines),
            "upstream_unique": len(u_lines - w_lines),
        },
        "function_overlap": {
            "jaccard": round(fn_jaccard, 3),
            "shared_fns": sorted(w_fns & u_fns),
            "winner_only_fns": sorted(w_fns - u_fns),
            "upstream_only_fns": sorted(u_fns - w_fns),
        },
        "summary": {
            "convergence": round(convergence, 3),
            "verdict": verdict,
        },
    }


# ── CLI ───────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--cve-dir", type=Path, help="convenience: load patch.json + upstream_fix.diff from this dir")
    p.add_argument("--winner", type=Path, help="patch.json from auto_patch_synth")
    p.add_argument("--upstream", type=Path, help="upstream_fix.diff (from auto_cve_ingest)")
    p.add_argument("--out", type=Path)
    args = p.parse_args(argv)

    winner_diff = None
    upstream_diff = None
    cve_id = None

    if args.cve_dir:
        cve_id = args.cve_dir.name
        patch_json = args.cve_dir / "patch.json"
        if not patch_json.is_file():
            print(f"[-] no patch.json in {args.cve_dir}", file=sys.stderr)
            return 1
        d = json.loads(patch_json.read_text())
        if not d.get("winner"):
            print(f"[-] no winner in {patch_json}", file=sys.stderr)
            return 1
        winner_diff = d["winner"]["diff"]
        upstream_path = args.cve_dir / "upstream_fix.diff"
        if upstream_path.is_file():
            upstream_diff = upstream_path.read_text()
        else:
            print(f"[-] no upstream_fix.diff in {args.cve_dir} (only auto-ingested CVEs have one)", file=sys.stderr)
            return 1
    else:
        if not args.winner or not args.upstream:
            p.error("provide --cve-dir, or both --winner and --upstream")
        winner_diff = (
            json.loads(args.winner.read_text())["winner"]["diff"]
            if args.winner.suffix == ".json"
            else args.winner.read_text()
        )
        upstream_diff = args.upstream.read_text()

    result = score(winner_diff, upstream_diff)
    if cve_id:
        result["cve"] = cve_id

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2))
        print(f"wrote {args.out}")
    else:
        print(json.dumps(result, indent=2))

    s = result["summary"]
    print(f"\nverdict: {s['verdict']} (convergence={s['convergence']})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
