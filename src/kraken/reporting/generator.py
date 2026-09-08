"""Report generator -- structured documentation output from solve results.

Produces markdown reports suitable for:
- Challenge writeups (CTF documentation)
- Vulnerability assessments (security audits)
- Binary analysis summaries (RE documentation)
- Benchmark result reports
- Solve session mind maps and timelines

Reports can be generated in five modes:
- "writeup": CTF-style challenge writeup with methodology
- "analysis": Technical binary analysis report
- "benchmark": Benchmark run summary with pass/fail metrics
- "mindmap": Decision tree showing solve process branches and outcomes
- "timeline": Step-by-step chronological trace with timings
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


def _format_duration(seconds: float) -> str:
    """Format seconds into human-readable duration."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    mins, secs = divmod(int(seconds), 60)
    if mins < 60:
        return f"{mins}m{secs:02d}s"
    hours, mins = divmod(mins, 60)
    return f"{hours}h{mins:02d}m{secs:02d}s"


def _generate_writeup(result: dict, state: dict) -> str:
    """Generate a CTF-style challenge writeup."""
    challenge_id = state.get("challenge_id", result.get("challenge_id", "unknown"))
    challenge_type = state.get("challenge_type", "unknown")
    description = state.get("challenge_description", "")
    solved = result.get("solved", False)
    flag = result.get("flag", "")
    duration = result.get("duration_seconds", 0)
    strategies = result.get("strategies_tried", [])
    solve_path = result.get("solve_path", [])
    node_timings = result.get("node_timings", [])

    lines = [
        f"# Challenge Writeup: {challenge_id}",
        "",
        f"**Category:** {challenge_type}  ",
        f"**Result:** {'Solved' if solved else 'Unsolved'}  ",
        f"**Duration:** {_format_duration(duration)}  ",
    ]

    if flag:
        lines.append(f"**Flag:** `{flag}`  ")
    lines.append("")

    if description:
        lines += ["## Description", "", description, ""]

    # Binary info
    binary_info = state.get("binary_info", {})
    if binary_info:
        lines += ["## Binary Analysis", ""]
        if binary_info.get("file_type"):
            lines.append(f"- **File type:** {binary_info['file_type']}")
        if binary_info.get("architecture"):
            lines.append(f"- **Architecture:** {binary_info['architecture']}")
        checksec = binary_info.get("checksec", {}) or binary_info.get("checksec_pwntools", {})
        if checksec:
            lines.append("- **Protections:**")
            for prot, val in checksec.items():
                lines.append(f"  - {prot}: {val}")
        lines.append("")

    # Methodology
    lines += ["## Methodology", ""]
    if solve_path:
        lines.append("### Solve Path")
        lines.append("")
        for i, (node, timing) in enumerate(zip(solve_path, node_timings or [{}] * len(solve_path)), 1):
            dur = timing.get("duration_s", 0) if isinstance(timing, dict) else 0
            lines.append(f"{i}. **{node}** ({dur:.1f}s)")
        lines.append("")

    if strategies:
        lines.append("### Strategies Attempted")
        lines.append("")
        for i, s in enumerate(strategies, 1):
            lines.append(f"{i}. {s}")
        lines.append("")

    # Classification
    if challenge_type:
        lines += ["## Classification", ""]
        lines.append(f"Primary type: **{challenge_type}**")
        secondary = state.get("secondary_types", [])
        if secondary:
            lines.append(f"Secondary types: {', '.join(secondary)}")
        hypothesis = state.get("strategy_hypothesis", "")
        if hypothesis:
            lines.append(f"\n*{hypothesis}*")
        lines.append("")

    # Winning solve script
    solve_scripts = state.get("solve_scripts", [])
    if solve_scripts:
        # Find winning script
        winning = None
        for script in reversed(solve_scripts):
            if script.get("exit_code") == 0:
                winning = script
                break
        if winning is None:
            winning = solve_scripts[-1]

        lines += ["## Solve Script", ""]
        lines.append("```python")
        lines.append(winning.get("code", "# No code generated"))
        lines.append("```")
        lines.append("")

        if winning.get("stdout"):
            lines += ["### Output", "```"]
            lines.append(winning["stdout"][:2000])
            lines.append("```")
            lines.append("")

    # Errors encountered
    errors = state.get("error_log", [])
    if errors:
        lines += ["## Errors Encountered", ""]
        for err in errors[-5:]:
            node = err.get("node", "unknown")
            error = err.get("error", "")
            lines.append(f"- **{node}:** {error[:200]}")
        lines.append("")

    return "\n".join(lines)


def _generate_analysis(result: dict, state: dict) -> str:
    """Generate a technical binary analysis report."""
    challenge_id = state.get("challenge_id", result.get("challenge_id", "unknown"))
    challenge_path = state.get("challenge_path", "")

    lines = [
        f"# Binary Analysis Report: {challenge_id}",
        "",
        f"**Binary:** `{challenge_path}`  ",
        f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}  ",
        "",
    ]

    # Binary metadata
    binary_info = state.get("binary_info", {})
    if binary_info:
        lines += ["## File Information", ""]
        for key, val in binary_info.items():
            if isinstance(val, dict):
                lines.append(f"### {key.replace('_', ' ').title()}")
                for k, v in val.items():
                    lines.append(f"- **{k}:** {v}")
            elif isinstance(val, list):
                lines.append(f"- **{key}:** {', '.join(str(v) for v in val[:10])}")
            else:
                lines.append(f"- **{key}:** {val}")
        lines.append("")

    # Functions
    functions = state.get("decompiled_functions", {})
    annotations = state.get("function_annotations", {})
    if functions:
        lines += [f"## Functions ({len(functions)} total)", ""]
        for name, code in list(functions.items())[:20]:
            annotation = annotations.get(name, "")
            lines.append(f"### `{name}`")
            if annotation:
                lines.append(f"*{annotation}*")
            lines.append("")
            lines.append("```c")
            lines.append(code[:1000])
            if len(code) > 1000:
                lines.append(f"// ... ({len(code)} chars total)")
            lines.append("```")
            lines.append("")

    # Strings
    strings = state.get("strings_of_interest", [])
    if strings:
        lines += [f"## Strings of Interest ({len(strings)} total)", ""]
        for s in strings[:30]:
            lines.append(f"- `{s}`")
        lines.append("")

    # Call graph
    call_graph = state.get("call_graph", {})
    if call_graph:
        lines += [f"## Call Graph ({len(call_graph)} callers)", ""]
        for caller, callees in list(call_graph.items())[:15]:
            if isinstance(callees, list):
                lines.append(f"- **{caller}** -> {', '.join(str(c) for c in callees[:5])}")
        lines.append("")

    # Dynamic traces
    traces = state.get("dynamic_traces", [])
    if traces:
        lines += [f"## Dynamic Traces ({len(traces)} entries)", ""]
        for trace in traces[:5]:
            ttype = trace.get("type", "unknown")
            lines.append(f"### {ttype}")
            lines.append(f"```json\n{json.dumps(trace, indent=2, default=str)[:500]}\n```")
            lines.append("")

    # Specialist analysis
    angr_results = state.get("angr_results", {})
    if angr_results:
        lines += ["## Specialist Analysis", ""]
        for key, val in angr_results.items():
            if isinstance(val, dict) and val:
                lines.append(f"### {key.replace('_', ' ').title()}")
                lines.append(f"```json\n{json.dumps(val, indent=2, default=str)[:1000]}\n```")
                lines.append("")

    return "\n".join(lines)


def _generate_benchmark(results: list[dict]) -> str:
    """Generate a benchmark summary report from multiple solve results."""
    total = len(results)
    solved = sum(1 for r in results if r.get("solved"))
    unsolved = total - solved

    lines = [
        "# KRAKEN Benchmark Report",
        "",
        f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}  ",
        f"**Total challenges:** {total}  ",
        f"**Solved:** {solved} ({solved/total*100:.1f}%)  " if total > 0 else "",
        f"**Unsolved:** {unsolved}  ",
        "",
    ]

    # Summary table
    lines += ["## Results Summary", "", "| Challenge | Type | Solved | Time | Strategies |",
              "|-----------|------|--------|------|------------|"]

    for r in sorted(results, key=lambda x: x.get("challenge_id", "")):
        cid = r.get("challenge_id", "?")
        ctype = r.get("challenge_type", "?")
        status = "Yes" if r.get("solved") else "No"
        duration = _format_duration(r.get("duration_seconds", 0))
        strats = len(r.get("strategies_tried", []))
        lines.append(f"| {cid} | {ctype} | {status} | {duration} | {strats} |")

    lines.append("")

    # By category breakdown
    by_type: dict[str, dict] = {}
    for r in results:
        ctype = r.get("challenge_type", "unknown")
        if ctype not in by_type:
            by_type[ctype] = {"total": 0, "solved": 0, "total_time": 0.0}
        by_type[ctype]["total"] += 1
        if r.get("solved"):
            by_type[ctype]["solved"] += 1
        by_type[ctype]["total_time"] += r.get("duration_seconds", 0)

    if by_type:
        lines += ["## By Category", "", "| Category | Solved/Total | Rate | Avg Time |",
                  "|----------|-------------|------|----------|"]
        for ctype, stats in sorted(by_type.items()):
            rate = stats["solved"] / stats["total"] * 100 if stats["total"] > 0 else 0
            avg_time = stats["total_time"] / stats["total"] if stats["total"] > 0 else 0
            lines.append(
                f"| {ctype} | {stats['solved']}/{stats['total']} | {rate:.0f}% | {_format_duration(avg_time)} |"
            )
        lines.append("")

    # Timing statistics
    durations = [r.get("duration_seconds", 0) for r in results]
    if durations:
        lines += [
            "## Timing Statistics",
            "",
            f"- **Mean:** {_format_duration(sum(durations) / len(durations))}",
            f"- **Min:** {_format_duration(min(durations))}",
            f"- **Max:** {_format_duration(max(durations))}",
            f"- **Total:** {_format_duration(sum(durations))}",
            "",
        ]

    return "\n".join(lines)


def _generate_session_writeup(session_data: dict) -> str:
    """Generate a CTF writeup from a SolveSession dict.

    Unlike _generate_writeup (which expects graph state keys), this works
    directly with the SolveSession serialization format.
    """
    challenge_id = session_data.get("challenge_id", "unknown")
    challenge_path = session_data.get("challenge_path", "")
    solved = session_data.get("solved", False)
    flag = session_data.get("flag", "")
    total_elapsed = session_data.get("total_elapsed", 0)
    solving_tool = session_data.get("solving_tool", "")
    steps = session_data.get("steps", [])
    triage_result = session_data.get("triage_result", {})
    decompile_result = session_data.get("decompile_result", {})
    extracted_params = session_data.get("extracted_params", {})
    cascade_results = session_data.get("cascade_results", [])

    binary_info = triage_result.get("binary_info", {})
    strings = triage_result.get("strings_of_interest", [])
    functions = decompile_result.get("decompiled_functions", {})

    lines = [
        f"# {challenge_id}",
        "",
        f"**Result:** {'SOLVED' if solved else 'UNSOLVED'}  ",
        f"**Duration:** {_format_duration(total_elapsed)}  ",
    ]
    if flag:
        lines.append(f"**Flag:** `{flag}`  ")
    if solving_tool:
        lines.append(f"**Solving Tool:** `{solving_tool}`  ")
    lines.append("")

    # Binary Analysis
    if binary_info:
        lines += ["## Binary Analysis", ""]
        if binary_info.get("file_type"):
            lines.append(f"- **File type:** {binary_info['file_type']}")
        if binary_info.get("architecture"):
            lines.append(f"- **Architecture:** {binary_info['architecture']}")
        if binary_info.get("corruption_detected"):
            lines.append("- **Corruption:** Detected (near-miss ELF magic)")
        checksec = binary_info.get("checksec", {}) or binary_info.get("checksec_pwntools", {})
        if checksec:
            lines.append("- **Protections:**")
            for prot, val in checksec.items():
                lines.append(f"  - {prot}: {val}")
        lines.append("")

    # Strings of Interest
    if strings:
        lines += [f"## Strings of Interest ({len(strings)})", ""]
        for s in strings[:15]:
            lines.append(f"- `{s}`")
        if len(strings) > 15:
            lines.append(f"- ... and {len(strings) - 15} more")
        lines.append("")

    # Decompilation Summary
    if functions:
        lines += [f"## Decompiled Functions ({len(functions)})", ""]
        for name in list(functions.keys())[:10]:
            lines.append(f"- `{name}`")
        if len(functions) > 10:
            lines.append(f"- ... and {len(functions) - 10} more")
        lines.append("")

    # Extracted Parameters
    if extracted_params:
        lines += ["## Extracted Parameters", ""]
        for key, val in extracted_params.items():
            if val and val not in (0, "", [], {}, False, None):
                lines.append(f"- **{key}:** `{val}`")
        lines.append("")

    # Pipeline Steps
    lines += ["## Solve Pipeline", ""]
    for i, step in enumerate(steps, 1):
        name = step.get("name", "?")
        elapsed = step.get("elapsed_seconds", 0)
        error = step.get("error", "")
        status = "ERROR" if error else "OK"
        lines.append(f"{i}. **{name.replace('_', ' ').title()}** -- {_format_duration(elapsed)} [{status}]")
        if error:
            lines.append(f"   - {error[:200]}")
    lines.append("")

    # Tool Cascade
    if cascade_results:
        lines += ["## Tool Cascade", ""]
        lines.append("| Tool | Flag | Exit Code |")
        lines.append("|------|------|-----------|")
        for result in cascade_results:
            tool_name = result.get("tool", "?")
            tool_flag = result.get("flag", "")
            exit_code = result.get("exit_code", "?")
            # Show session flag for the solving tool even if not in individual result
            if not tool_flag and tool_name == solving_tool and flag:
                tool_flag = flag
            flag_col = f"`{tool_flag}`" if tool_flag else "-"
            lines.append(f"| {tool_name} | {flag_col} | {exit_code} |")
        lines.append("")

    # Mind map (inline)
    lines += ["## Decision Tree", ""]
    mindmap = _generate_mindmap(session_data)
    # Extract just the code block from the mindmap
    in_block = False
    for line in mindmap.split("\n"):
        if line.strip() == "```" and not in_block:
            in_block = True
            lines.append(line)
        elif line.strip() == "```" and in_block:
            lines.append(line)
            in_block = False
        elif in_block:
            lines.append(line)
    lines.append("")

    return "\n".join(lines)


def _generate_mindmap(session_data: dict) -> str:
    """Generate a text-based decision tree from a SolveSession dict.

    Shows the solve process as a tree with branches for each pipeline step,
    tool cascade results, and final outcome.
    """
    challenge_id = session_data.get("challenge_id", "unknown")
    solved = session_data.get("solved", False)
    flag = session_data.get("flag", "")
    total_elapsed = session_data.get("total_elapsed", 0)
    steps = session_data.get("steps", [])
    cascade_results = session_data.get("cascade_results", [])
    triage_result = session_data.get("triage_result", {})

    # Determine challenge type from triage
    binary_info = triage_result.get("binary_info", {})
    file_type = binary_info.get("file_type", "unknown")[:40]
    strings_count = len(triage_result.get("strings_of_interest", []))
    corruption = binary_info.get("corruption_detected", False)

    lines = [
        f"# Solve Mind Map: {challenge_id}",
        "",
        "```",
        f"Challenge: {challenge_id}",
    ]

    # Render each pipeline step
    for i, step in enumerate(steps):
        name = step.get("name", "?")
        elapsed = step.get("elapsed_seconds", 0)
        error = step.get("error", "")
        is_last_step = i == len(steps) - 1 and not cascade_results
        connector = "\u2514\u2500\u2500" if is_last_step and not cascade_results else "\u251c\u2500\u2500"

        # Add context-specific summary
        summary = ""
        if name == "triage":
            anti_debug = binary_info.get("anti_debug", False)
            summary = f"{file_type}, {strings_count} strings"
            if corruption:
                summary += ", CORRUPTED"
            if anti_debug:
                summary += ", anti-debug"
        elif name == "decompile":
            funcs = step.get("output_snapshot", {})
            func_count = len(funcs.get("decompiled_functions", {}))
            summary = f"{func_count} functions"
        elif name == "extract_params":
            snapshot = step.get("output_snapshot", {})
            parts = []
            if snapshot.get("input_mode"):
                parts.append(f"input={snapshot['input_mode']}")
            if snapshot.get("input_length"):
                parts.append(f"len={snapshot['input_length']}")
            if snapshot.get("success_string"):
                parts.append(f'success="{snapshot["success_string"][:20]}"')
            if snapshot.get("uses_random"):
                parts.append(f"seed={snapshot.get('random_seed', '?')}")
            summary = ", ".join(parts) if parts else "extracted"
        elif name == "tool_cascade":
            summary = f"{len(cascade_results)} tools run"

        if error:
            summary += f" ERROR: {error[:60]}"

        lines.append(
            f"{connector} {name.replace('_', ' ').title()} "
            f"({_format_duration(elapsed)})"
            f"{' \u2192 ' + summary if summary else ''}"
        )

    # Expand tool cascade results
    if cascade_results:
        solving_tool = session_data.get("solving_tool", "")
        total_in_cascade = len(cascade_results)
        has_skipped = solving_tool and total_in_cascade < 11

        for j, tool_result in enumerate(cascade_results):
            tool_name = tool_result.get("tool", "?")
            tool_flag = tool_result.get("flag", "")
            is_last = j == len(cascade_results) - 1

            if is_last and not has_skipped:
                branch = "\u2502   \u2514\u2500\u2500"
            else:
                branch = "\u2502   \u251c\u2500\u2500" if not is_last else "\u2502   \u251c\u2500\u2500"

            if tool_name == solving_tool and solved:
                marker = "FLAG FOUND \u2713"
            elif tool_flag:
                marker = "flag candidate"
            else:
                marker = "no flag"

            lines.append(f"{branch} {tool_name} \u2192 {marker}")

        if has_skipped:
            skipped = 11 - total_in_cascade
            lines.append(f"\u2502   \u2514\u2500\u2500 (skipped remaining {skipped} tools)")

    # Final result line
    if solved:
        lines.append(
            f"\u2514\u2500\u2500 Result: SOLVED in {_format_duration(total_elapsed)} "
            f"\u2192 {flag}"
        )
    else:
        lines.append(
            f"\u2514\u2500\u2500 Result: UNSOLVED after {_format_duration(total_elapsed)}"
        )

    lines.append("```")
    return "\n".join(lines)


def _generate_timeline(session_data: dict) -> str:
    """Generate a chronological step-by-step trace with timings."""
    challenge_id = session_data.get("challenge_id", "unknown")
    session_id = session_data.get("session_id", "?")
    total_elapsed = session_data.get("total_elapsed", 0)
    solved = session_data.get("solved", False)
    flag = session_data.get("flag", "")
    steps = session_data.get("steps", [])
    cascade_results = session_data.get("cascade_results", [])

    lines = [
        f"# Solve Timeline: {challenge_id}",
        "",
        f"**Session:** `{session_id}`  ",
        f"**Total Duration:** {_format_duration(total_elapsed)}  ",
        f"**Result:** {'SOLVED' if solved else 'UNSOLVED'}  ",
        "",
        "## Steps",
        "",
    ]

    cumulative = 0.0
    for i, step in enumerate(steps, 1):
        name = step.get("name", "?")
        elapsed = step.get("elapsed_seconds", 0)
        error = step.get("error", "")
        input_summary = step.get("input_summary", "")
        output_keys = step.get("output_keys", [])

        lines.append(f"### {i}. {name.replace('_', ' ').title()}")
        lines.append("")
        lines.append(
            f"- **Duration:** {_format_duration(elapsed)} "
            f"(cumulative: {_format_duration(cumulative + elapsed)})"
        )
        if input_summary:
            lines.append(f"- **Input:** {input_summary[:200]}")
        if output_keys:
            lines.append(f"- **Output keys:** {', '.join(output_keys[:15])}")
        if error:
            lines.append(f"- **Error:** {error[:300]}")
        lines.append("")
        cumulative += elapsed

    # Tool cascade detail
    if cascade_results:
        lines += ["## Tool Cascade Detail", ""]
        lines.append("| # | Tool | Flag Found | Exit Code |")
        lines.append("|---|------|-----------|-----------|")
        for j, result in enumerate(cascade_results, 1):
            tool_name = result.get("tool", "?")
            found = "Yes" if result.get("flag") else "No"
            exit_code = result.get("exit_code", "?")
            lines.append(f"| {j} | {tool_name} | {found} | {exit_code} |")
        lines.append("")

    # Summary
    lines += ["## Summary", ""]
    if solved:
        lines.append(
            f"Challenge solved by **{session_data.get('solving_tool', '?')}** "
            f"in {_format_duration(total_elapsed)}."
        )
        lines.append(f"Flag: `{flag}`")
    else:
        lines.append(
            f"Challenge unsolved after {_format_duration(total_elapsed)} "
            f"and {len(cascade_results)} tool attempts."
        )

    return "\n".join(lines)


def generate_report(
    result: dict | list[dict],
    state: dict | None = None,
    mode: str = "writeup",
    output_path: str | None = None,
) -> str:
    """Generate a report from solve results.

    Args:
        result: Solve result dict, SolveSession dict, or list of results (for benchmark mode).
        state: Full graph state (required for writeup and analysis modes).
        mode: Report mode -- "writeup", "analysis", "benchmark", "mindmap", or "timeline".
        output_path: Optional file path to write the report to.

    Returns:
        The generated report as a string.
    """
    if mode == "benchmark":
        if not isinstance(result, list):
            result = [result]
        report = _generate_benchmark(result)
    elif mode == "mindmap":
        report = _generate_mindmap(result)  # type: ignore[arg-type]
    elif mode == "timeline":
        report = _generate_timeline(result)  # type: ignore[arg-type]
    elif mode == "analysis":
        report = _generate_analysis(result, state or result)  # type: ignore[arg-type]
    elif mode == "session_writeup":
        report = _generate_session_writeup(result)  # type: ignore[arg-type]
    elif mode == "writeup" and isinstance(result, dict) and "session_id" in result:
        # Auto-detect SolveSession dict and use session-aware writeup
        report = _generate_session_writeup(result)
    else:  # writeup (legacy graph-state format)
        report = _generate_writeup(result, state or result)  # type: ignore[arg-type]

    if output_path:
        Path(output_path).write_text(report)

    return report
