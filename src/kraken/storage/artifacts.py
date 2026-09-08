"""Artifact emitter -- comprehensive post-solve artifact bundle generation.

Produces a self-contained, auditable artifact bundle per challenge that enables:
1. Engineers to jump into an unfinished solution with full context
2. Complete audit trail for realized solutions, start to finish
3. Machine-readable outputs for tooling integration (Ghidra, IDE, CI)

Artifact bundle structure:
    {workspace}/
    ├── summary.json              # Flag, timing, cost, strategies, outcome
    ├── challenge_meta.json       # Name, category, arch, protections, checksec
    ├── tool_cascade_log.jsonl    # Every tool invocation + result
    ├── knowledge_graph.json      # Functions, vulns, data flows (machine-readable)
    ├── reproduce.sh              # Standalone re-run script (no Kraken deps)
    ├── attempt_diff.md           # What changed between solve attempts
    ├── artifacts_manifest.json   # Index of everything in this bundle
    ├── decompiled/               # One .c file per function (IDE-friendly)
    │   ├── main.c
    │   └── check_password.c
    ├── analysis/
    │   ├── call_graph.json       # Function → callees
    │   ├── symbols.json          # Symbol table
    │   ├── xrefs.json            # Cross-references
    │   └── strings.json          # Filtered strings of interest
    ├── ghidra/
    │   └── kraken_import.py      # Ghidra headless script to import annotations
    ├── solve_ledger.md           # Existing narrative log
    └── solve_attempts/           # Existing scripts + output
"""
from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import stat
import time
from pathlib import Path
from typing import Any

from kraken.storage.artifact_store import ArtifactStore, get_artifact
from kraken.logging.structured import get_logger

log = get_logger(__name__)

# ── Flag redaction ──────────────────────────────────────────────────────────

_FLAG_LIKE = re.compile(r"\b[A-Za-z0-9_\-]{1,32}\{[^\n\r}]{1,220}\}")


def _redact(text: str) -> str:
    """Redact flag-like tokens from text."""
    return _FLAG_LIKE.sub("<REDACTED>", text or "")


# ── Safe JSON serialization ────────────────────────────────────────────────

def _safe(data: Any, max_str: int = 10000) -> Any:
    """Make data JSON-serializable, truncating large strings."""
    if isinstance(data, dict):
        return {k: _safe(v, max_str) for k, v in data.items()}
    if isinstance(data, (list, tuple)):
        return [_safe(item, max_str) for item in data]
    if isinstance(data, str) and len(data) > max_str:
        return data[:max_str] + f"... [{len(data)} chars]"
    if isinstance(data, bytes):
        return data.hex()[:200]
    if isinstance(data, (int, float, bool, type(None))):
        return data
    return str(data)[:max_str]


def _write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, default=str, ensure_ascii=False) + "\n")


def _sanitize_filename(name: str) -> str:
    """Convert a function name like 'main@0x401000' to a safe filename."""
    return re.sub(r'[^\w\-.]', '_', name)


# ── Core emitter ────────────────────────────────────────────────────────────

def emit_artifacts(state: dict, solve_result: dict, workspace: str | None = None) -> Path:
    """Emit the full artifact bundle for a completed challenge solve.

    Args:
        state: Final KrakenState dict (full graph state after solve).
        solve_result: Summary dict returned by orchestrator.solve().
        workspace: Override workspace path. Defaults to state["solve_workspace"].

    Returns:
        Path to the workspace directory containing all artifacts.
    """
    ws = Path(workspace or state.get("solve_workspace", "."))
    ws.mkdir(parents=True, exist_ok=True)

    manifest_entries: list[dict] = []

    def _track(path: Path, description: str, category: str) -> None:
        rel = str(path.relative_to(ws))
        size = path.stat().st_size if path.exists() else 0
        manifest_entries.append({
            "path": rel,
            "description": description,
            "category": category,
            "size_bytes": size,
        })

    # 1. summary.json
    summary_path = ws / "summary.json"
    _emit_summary(state, solve_result, summary_path)
    _track(summary_path, "Solve outcome: flag, timing, cost, strategies", "metadata")

    # 2. challenge_meta.json
    meta_path = ws / "challenge_meta.json"
    _emit_challenge_meta(state, meta_path)
    _track(meta_path, "Challenge metadata: name, category, arch, protections", "metadata")

    # 3. tool_cascade_log.jsonl
    cascade_path = ws / "tool_cascade_log.jsonl"
    _emit_tool_cascade_log(state, cascade_path)
    _track(cascade_path, "Tool invocation log (one JSON line per tool)", "execution")

    # 4. decompiled/*.c
    decomp_dir = ws / "decompiled"
    count = _emit_decompiled_sources(state, decomp_dir)
    if count > 0:
        _track(decomp_dir, f"{count} decompiled C source files", "analysis")

    # 5. analysis/*.json
    analysis_dir = ws / "analysis"
    _emit_analysis_artifacts(state, analysis_dir)
    for f in sorted(analysis_dir.glob("*.json")) if analysis_dir.exists() else []:
        _track(f, f"Analysis: {f.stem}", "analysis")

    # 6. knowledge_graph.json
    kg_path = ws / "knowledge_graph.json"
    _emit_knowledge_graph(state, kg_path)
    if kg_path.exists():
        _track(kg_path, "Knowledge graph: functions, calls, vulns, data flows", "analysis")

    # 7. ghidra/kraken_import.py
    ghidra_dir = ws / "ghidra"
    _emit_ghidra_import_script(state, ghidra_dir)
    ghidra_script = ghidra_dir / "kraken_import.py"
    if ghidra_script.exists():
        _track(ghidra_script, "Ghidra headless import script for Kraken annotations", "tooling")

    # 8. reproduce.sh
    repro_path = ws / "reproduce.sh"
    _emit_reproduce_script(state, solve_result, repro_path)
    if repro_path.exists():
        _track(repro_path, "Standalone reproduce script (no Kraken dependency)", "execution")

    # 9. attempt_diff.md
    diff_path = ws / "attempt_diff.md"
    _emit_attempt_diff(state, ws, diff_path)
    if diff_path.exists():
        _track(diff_path, "Diff view of solve attempt iterations", "execution")

    # 10. artifacts_manifest.json (always last)
    manifest_path = ws / "artifacts_manifest.json"
    manifest = {
        "challenge_id": state.get("challenge_id", "unknown"),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "solved": solve_result.get("solved", False),
        "artifact_count": len(manifest_entries),
        "artifacts": manifest_entries,
    }
    _write_json(manifest_path, manifest)

    log.info("artifacts_emitted",
             challenge=state.get("challenge_id", "?"),
             artifact_count=len(manifest_entries),
             workspace=str(ws))

    return ws


# ── Individual emitters ─────────────────────────────────────────────────────

def _emit_summary(state: dict, solve_result: dict, path: Path) -> None:
    """Emit summary.json -- the quick-glance outcome file."""
    summary = {
        "challenge_id": state.get("challenge_id", ""),
        "solved": solve_result.get("solved", False),
        "flag": solve_result.get("flag", ""),
        "duration_seconds": solve_result.get("duration_seconds", 0),
        "cost_usd": solve_result.get("cost_usd", 0),
        "iterations": solve_result.get("steps", 0),
        "challenge_type": state.get("challenge_type", ""),
        "secondary_types": state.get("secondary_types", []),
        "strategy_hypothesis": state.get("strategy_hypothesis", ""),
        "strategies_tried": solve_result.get("strategies_tried", []),
        "solve_path": solve_result.get("solve_path", []),
        "node_timings": solve_result.get("node_timings", []),
        "error_log": [
            {"node": e.get("node", "?"), "error": e.get("error", "")[:500]}
            for e in state.get("error_log", [])
        ],
        "rejected_flags": state.get("rejected_flags", []),
        "failure_diagnosis": state.get("failure_diagnosis", ""),
        "script_findings": state.get("script_findings", []),
        "racing_attempted": state.get("racing_attempted", False),
    }
    _write_json(path, summary)


def _emit_challenge_meta(state: dict, path: Path) -> None:
    """Emit challenge_meta.json -- reproducibility context."""
    binary_info = state.get("binary_info", {})
    remote_info = state.get("remote_info", {})
    challenge_files = state.get("challenge_files", {})

    meta = {
        "challenge_id": state.get("challenge_id", ""),
        "challenge_path": state.get("challenge_path", ""),
        "challenge_dir": state.get("challenge_dir", ""),
        "description": state.get("challenge_description", ""),
        "category": state.get("category", ""),
        "flag_format": state.get("flag_format", ""),
        "binary_info": {
            "file_type": binary_info.get("file_type", ""),
            "architecture": binary_info.get("architecture", ""),
            "endianness": binary_info.get("endianness", ""),
            "bit_width": binary_info.get("bit_width", ""),
            "checksec": binary_info.get("checksec", {}),
            "checksec_pwntools": binary_info.get("checksec_pwntools", {}),
            "sections": binary_info.get("sections", []),
            "entropy": binary_info.get("entropy", ""),
            "corruption_detected": binary_info.get("corruption_detected", False),
            "anti_debug": binary_info.get("anti_debug", False),
            "stripped": binary_info.get("stripped", False),
        },
        "remote_info": remote_info,
        "challenge_files": {
            name: {
                "type": info.get("type", ""),
                "size": info.get("size", 0),
            }
            for name, info in challenge_files.items()
        } if isinstance(challenge_files, dict) else {},
    }
    _write_json(path, meta)


def _emit_tool_cascade_log(state: dict, path: Path) -> None:
    """Emit tool_cascade_log.jsonl -- one JSON line per tool invocation."""
    cascade = state.get("tool_cascade_results", [])
    if not cascade:
        return
    with open(path, "w") as f:
        for i, result in enumerate(cascade):
            entry = {
                "sequence": i + 1,
                "tool": result.get("tool", "?"),
                "success": result.get("success", False),
                "exit_code": result.get("exit_code", None),
                "flag_found": bool(result.get("flag", "")),
                "flag": result.get("flag", ""),
                "duration_s": result.get("duration_s", None),
                "stdout_preview": _redact((result.get("stdout", "") or "")[:1000]),
                "stderr_preview": _redact((result.get("stderr", "") or "")[:500]),
                "error": result.get("error", ""),
                "script_path": result.get("script_path", ""),
            }
            f.write(json.dumps(entry, default=str) + "\n")


def _emit_decompiled_sources(state: dict, decomp_dir: Path) -> int:
    """Emit individual .c files for each decompiled function."""
    # Try artifact store first, then inline state
    functions = get_artifact(state, "decompiled_functions", "decompiled_functions_handle")
    if not functions or not isinstance(functions, dict):
        return 0

    decomp_dir.mkdir(parents=True, exist_ok=True)
    annotations = state.get("function_annotations", {})
    count = 0

    for func_name, code in functions.items():
        if not code or not isinstance(code, str):
            continue
        safe_name = _sanitize_filename(func_name)
        file_path = decomp_dir / f"{safe_name}.c"

        # Add header comment with annotation if available
        header = f"/* Function: {func_name}\n"
        annotation = annotations.get(func_name, "")
        if annotation:
            header += f" * Description: {annotation}\n"
        header += f" * Decompiled by Kraken (Ghidra backend)\n */\n\n"

        file_path.write_text(header + code, encoding="utf-8")
        count += 1

    # Write an index file
    if count > 0:
        index_lines = [f"# Decompiled Functions ({count} total)\n"]
        for func_name in sorted(functions.keys()):
            safe_name = _sanitize_filename(func_name)
            annotation = annotations.get(func_name, "")
            desc = f" -- {annotation}" if annotation else ""
            index_lines.append(f"- [{func_name}]({safe_name}.c){desc}")
        (decomp_dir / "INDEX.md").write_text("\n".join(index_lines) + "\n")

    return count


def _emit_analysis_artifacts(state: dict, analysis_dir: Path) -> None:
    """Emit analysis/*.json -- call graph, symbols, xrefs, strings."""
    analysis_dir.mkdir(parents=True, exist_ok=True)
    written = False

    # Call graph
    call_graph = state.get("call_graph", {})
    if call_graph:
        _write_json(analysis_dir / "call_graph.json", call_graph)
        written = True

    # Symbols
    symbols = state.get("symbols", {})
    if symbols:
        _write_json(analysis_dir / "symbols.json", symbols)
        written = True

    # Cross-references
    xrefs = state.get("xrefs", {})
    if xrefs:
        _write_json(analysis_dir / "xrefs.json", xrefs)
        written = True

    # Strings of interest
    strings = state.get("strings_of_interest", [])
    if strings:
        _write_json(analysis_dir / "strings.json", {
            "count": len(strings),
            "strings": strings,
        })
        written = True

    # Angr results
    angr = get_artifact(state, "angr_results", "angr_results_handle")
    if angr:
        _write_json(analysis_dir / "angr_results.json", _safe(angr))
        written = True

    # Z3 results
    z3 = state.get("z3_results", {})
    if z3:
        _write_json(analysis_dir / "z3_results.json", _safe(z3))
        written = True

    # Dynamic traces
    traces = get_artifact(state, "dynamic_traces", "dynamic_traces_handle")
    if traces:
        _write_json(analysis_dir / "dynamic_traces.json", _safe(traces))
        written = True

    # Memory dumps
    memory = state.get("memory_dumps", {})
    if memory:
        _write_json(analysis_dir / "memory_dumps.json", _safe(memory))
        written = True

    # Extracted params
    params = state.get("extracted_params", {})
    if params:
        _write_json(analysis_dir / "extracted_params.json", params)
        written = True

    # Clean up if nothing was written
    if not written:
        try:
            analysis_dir.rmdir()
        except OSError:
            pass


def _emit_knowledge_graph(state: dict, path: Path) -> None:
    """Emit knowledge_graph.json -- machine-readable relationship graph.

    Nodes: functions, strings, vulnerabilities, parameters
    Edges: calls, references, exploits, data_flow
    """
    functions = get_artifact(state, "decompiled_functions", "decompiled_functions_handle")
    call_graph = state.get("call_graph", {})
    xrefs = state.get("xrefs", {})
    annotations = state.get("function_annotations", {})
    strings = state.get("strings_of_interest", [])
    params = state.get("extracted_params", {})
    binary_info = state.get("binary_info", {})

    if not functions and not call_graph and not strings:
        return  # Nothing to graph

    nodes: list[dict] = []
    edges: list[dict] = []
    node_ids: set[str] = set()

    def _add_node(nid: str, ntype: str, label: str, **props: Any) -> None:
        if nid not in node_ids:
            node_ids.add(nid)
            node = {"id": nid, "type": ntype, "label": label}
            node.update(props)
            nodes.append(node)

    # Function nodes
    if isinstance(functions, dict):
        for func_name, code in functions.items():
            annotation = annotations.get(func_name, "")
            code_len = len(code) if isinstance(code, str) else 0
            _add_node(
                f"func:{func_name}", "function", func_name,
                annotation=annotation,
                code_length=code_len,
            )

    # Call graph edges
    if isinstance(call_graph, dict):
        for caller, callees in call_graph.items():
            _add_node(f"func:{caller}", "function", caller)
            if isinstance(callees, list):
                for callee in callees:
                    _add_node(f"func:{callee}", "function", callee)
                    edges.append({
                        "source": f"func:{caller}",
                        "target": f"func:{callee}",
                        "type": "calls",
                    })

    # String nodes + references
    for i, s in enumerate(strings[:100]):  # Cap at 100 strings
        sid = f"string:{i}"
        _add_node(sid, "string", s[:80])

    # Xref edges
    if isinstance(xrefs, dict):
        for addr, refs in xrefs.items():
            if isinstance(refs, list):
                for ref in refs:
                    ref_str = str(ref)
                    _add_node(f"xref:{addr}", "address", addr)
                    _add_node(f"xref:{ref_str}", "address", ref_str)
                    edges.append({
                        "source": f"xref:{addr}",
                        "target": f"xref:{ref_str}",
                        "type": "references",
                    })

    # Vulnerability indicators from checksec
    checksec = binary_info.get("checksec", {}) or binary_info.get("checksec_pwntools", {})
    if checksec:
        for protection, value in checksec.items():
            # Flag missing protections as potential vulns
            if value in (False, "No", "no", "disabled", "Disabled", "partial"):
                vid = f"vuln:missing_{protection}"
                _add_node(vid, "vulnerability", f"Missing: {protection}",
                          severity="info", protection=protection, value=str(value))

    # Parameter nodes
    if isinstance(params, dict):
        for key, val in params.items():
            if val and val not in (0, "", [], {}, False, None):
                _add_node(f"param:{key}", "parameter", f"{key}={val}")

    graph = {
        "challenge_id": state.get("challenge_id", ""),
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": nodes,
        "edges": edges,
    }
    _write_json(path, graph)


def _emit_ghidra_import_script(state: dict, ghidra_dir: Path) -> None:
    """Emit a Ghidra headless Python script that imports Kraken's annotations.

    Usage:
        analyzeHeadless /path/to/project ProjectName \\
            -import /path/to/binary \\
            -postScript kraken_import.py
    """
    annotations = state.get("function_annotations", {})
    functions = get_artifact(state, "decompiled_functions", "decompiled_functions_handle")
    strings = state.get("strings_of_interest", [])
    call_graph = state.get("call_graph", {})
    binary_info = state.get("binary_info", {})
    challenge_id = state.get("challenge_id", "unknown")

    if not annotations and not functions:
        return

    ghidra_dir.mkdir(parents=True, exist_ok=True)

    # Build the annotation data as embedded JSON
    import_data = {
        "challenge_id": challenge_id,
        "annotations": {},
        "bookmarks": [],
        "plate_comments": {},
    }

    # Function annotations → plate comments + bookmarks
    if isinstance(annotations, dict):
        for func_name, desc in annotations.items():
            # Parse address from func_name (format: "name@0xADDR")
            if "@" in func_name:
                name, addr_str = func_name.rsplit("@", 1)
            else:
                name, addr_str = func_name, ""

            import_data["annotations"][func_name] = {
                "name": name,
                "address": addr_str,
                "description": desc,
            }
            if addr_str:
                import_data["bookmarks"].append({
                    "address": addr_str,
                    "category": "Kraken",
                    "description": f"[Kraken] {desc[:100]}",
                })
                import_data["plate_comments"][addr_str] = f"[Kraken] {desc}"

    # Interesting strings → bookmarks
    for s in strings[:50]:
        import_data["bookmarks"].append({
            "address": "",
            "category": "Kraken-Strings",
            "description": f"String: {s[:80]}",
        })

    # Checksec info → program info comment
    checksec = binary_info.get("checksec", {}) or binary_info.get("checksec_pwntools", {})
    checksec_lines = [f"  {k}: {v}" for k, v in checksec.items()] if checksec else []

    data_json = json.dumps(import_data, indent=2, default=str)

    script = f'''# Ghidra headless script -- import Kraken analysis annotations
# Generated for: {challenge_id}
#
# Usage:
#   analyzeHeadless /path/to/project ProjectName \\
#       -import /path/to/binary \\
#       -postScript kraken_import.py
#
# Or from Ghidra GUI: Script Manager → Run Script → select this file

# @category Kraken
# @menupath Tools.Kraken.Import Annotations

import json

# Embedded Kraken analysis data
KRAKEN_DATA = json.loads(r"""
{data_json}
""")


def run():
    from ghidra.program.model.listing import CodeUnit
    from ghidra.program.model.symbol import SourceType

    program = getCurrentProgram()
    listing = program.getListing()
    bookmark_mgr = program.getBookmarkManager()
    memory = program.getMemory()
    func_mgr = program.getFunctionManager()

    tx = program.startTransaction("Kraken Import")
    try:
        imported = 0

        # Import function annotations as plate comments
        for func_id, info in KRAKEN_DATA.get("annotations", {{}}).items():
            addr_str = info.get("address", "")
            desc = info.get("description", "")
            if not addr_str or not desc:
                continue
            try:
                addr = toAddr(addr_str)
                cu = listing.getCodeUnitAt(addr)
                if cu is not None:
                    existing = cu.getComment(CodeUnit.PLATE_COMMENT) or ""
                    if "[Kraken]" not in existing:
                        new_comment = existing + "\\n" + desc if existing else desc
                        cu.setComment(CodeUnit.PLATE_COMMENT, new_comment)
                        imported += 1
            except Exception:
                pass

        # Import bookmarks
        for bm in KRAKEN_DATA.get("bookmarks", []):
            addr_str = bm.get("address", "")
            if not addr_str:
                continue
            try:
                addr = toAddr(addr_str)
                bookmark_mgr.setBookmark(
                    addr,
                    "Analysis",
                    bm.get("category", "Kraken"),
                    bm.get("description", "")[:200],
                )
            except Exception:
                pass

        # Set program info
        info_lines = [
            "Kraken CTF Auto-Solver Analysis",
            "Challenge: {challenge_id}",
        ]
{chr(10).join(f'        info_lines.append("{line}")' for line in checksec_lines)}
        program.setCompiler("\\n".join(info_lines))

        println("[Kraken] Imported %d annotations" % imported)

    finally:
        program.endTransaction(tx, True)


run()
'''

    script_path = ghidra_dir / "kraken_import.py"
    script_path.write_text(script, encoding="utf-8")

    # Also write raw annotation data for other tools
    _write_json(ghidra_dir / "annotations.json", import_data)


def _emit_reproduce_script(state: dict, solve_result: dict, path: Path) -> None:
    """Emit reproduce.sh -- standalone script to re-run the winning solve."""
    solve_scripts = state.get("solve_scripts", [])
    if not solve_scripts:
        return

    # Find the winning script (last successful one, or just the last one)
    winning = None
    for script in reversed(solve_scripts):
        if script.get("exit_code") == 0:
            winning = script
            break
    if winning is None:
        winning = solve_scripts[-1]

    code = winning.get("code", "")
    if not code:
        return

    challenge_id = state.get("challenge_id", "unknown")
    challenge_dir = state.get("challenge_dir", ".")
    flag_format = state.get("flag_format", "")

    script = f'''#!/usr/bin/env bash
# reproduce.sh -- Re-run the winning solve for: {challenge_id}
# Generated by Kraken CTF Auto-Solver
# No Kraken dependency required -- just Python 3.
#
# Usage:
#   chmod +x reproduce.sh
#   ./reproduce.sh [/path/to/challenge/dir]
#
# Flag format: {flag_format}
set -euo pipefail

CHALLENGE_DIR="${{1:-{challenge_dir}}}"

if [ ! -d "$CHALLENGE_DIR" ]; then
    echo "ERROR: Challenge directory not found: $CHALLENGE_DIR"
    echo "Usage: $0 /path/to/challenge/dir"
    exit 1
fi

echo "=== Kraken Reproduce: {challenge_id} ==="
echo "Challenge dir: $CHALLENGE_DIR"
echo ""

# Write the solve script
SOLVE_SCRIPT=$(mktemp /tmp/kraken_reproduce_XXXXXX.py)
cat > "$SOLVE_SCRIPT" << 'KRAKEN_SOLVE_EOF'
{code}
KRAKEN_SOLVE_EOF

echo "Running solve script..."
cd "$CHALLENGE_DIR"
python3 "$SOLVE_SCRIPT" 2>&1 | tee /tmp/kraken_reproduce_output.txt
EXIT_CODE=${{PIPESTATUS[0]}}

echo ""
echo "=== Exit code: $EXIT_CODE ==="

# Try to extract flag from output
if [ $EXIT_CODE -eq 0 ]; then
    echo "=== Checking for flag ==="
    grep -oE '[A-Za-z0-9_-]{{1,32}}\\{{[^}}]+\\}}' /tmp/kraken_reproduce_output.txt || echo "(no flag pattern found in output)"
fi

rm -f "$SOLVE_SCRIPT"
exit $EXIT_CODE
'''

    path.write_text(script, encoding="utf-8")
    # Make executable
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _emit_attempt_diff(state: dict, workspace: Path, path: Path) -> None:
    """Emit attempt_diff.md -- diff view showing evolution of solve attempts."""
    solve_scripts = state.get("solve_scripts", [])
    if len(solve_scripts) < 2:
        return

    lines = [
        f"# Solve Attempt Diffs: {state.get('challenge_id', '?')}",
        "",
        f"Total attempts: {len(solve_scripts)}",
        "",
    ]

    prev_code = ""
    for i, script in enumerate(solve_scripts):
        code = script.get("code", "")
        exit_code = script.get("exit_code", "?")
        stdout_preview = _redact((script.get("stdout", "") or "")[:300])

        lines.append(f"## Attempt {i + 1} → exit code {exit_code}")
        lines.append("")

        if i == 0:
            lines.append("*(initial attempt)*")
            lines.append("")
            lines.append("```python")
            lines.append(code[:3000] if code else "# (empty)")
            lines.append("```")
        elif code and prev_code:
            # Generate unified diff
            diff = list(difflib.unified_diff(
                prev_code.splitlines(keepends=True),
                code.splitlines(keepends=True),
                fromfile=f"attempt_{i}.py",
                tofile=f"attempt_{i + 1}.py",
                lineterm="",
            ))
            if diff:
                lines.append("```diff")
                lines.extend(d.rstrip() for d in diff[:100])
                if len(diff) > 100:
                    lines.append(f"... ({len(diff) - 100} more diff lines)")
                lines.append("```")
            else:
                lines.append("*(no code changes)*")
        else:
            lines.append("```python")
            lines.append(code[:3000] if code else "# (empty)")
            lines.append("```")

        if stdout_preview:
            lines.append("")
            lines.append("**Output preview:**")
            lines.append(f"```\n{stdout_preview}\n```")

        lines.append("")
        prev_code = code

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
