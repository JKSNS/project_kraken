"""Cascade optimizer -- self-improving tool ordering from solve telemetry.

Accumulates per-tool performance stats (success rate, timing) across solves
and generates optimized cascade configurations. The tool_router loads the
learned config to reorder tools, tune timeouts, and skip consistently
failing tools per challenge type.

Data flow:
    kraken_full_solve → PerformanceDB.record_solve() → optimize()
    → benchmarks/cascade_config.json → tool_router (next solve)

Artifacts:
    benchmarks/performance.json -- Structured per-tool stats
    benchmarks/cascade_config.json -- Learned cascade config
    benchmarks/failures.json -- Failure taxonomy records
"""
from __future__ import annotations

import json
import math
import time
from collections import Counter
from enum import Enum
from pathlib import Path
from typing import Any

_BENCHMARKS_DIR = Path("benchmarks")
_PERF_DB_PATH = _BENCHMARKS_DIR / "performance.json"
_CASCADE_CONFIG_PATH = _BENCHMARKS_DIR / "cascade_config.json"
_FAILURES_PATH = _BENCHMARKS_DIR / "failures.json"


class FailureType(str, Enum):
    """Why a challenge failed to solve."""

    NO_TOOL_MATCH = "no_tool_match"       # No tool in cascade produced any output
    TOOL_PARTIAL = "tool_partial"          # Tool found data but couldn't extract flag
    CLASSIFY_WRONG = "classify_wrong"      # Wrong challenge type -> wrong tools ran
    LLM_FLAKY = "llm_flaky"               # LLM-dependent path failed (intermittent)
    TIMEOUT = "timeout"                    # Ran out of time
    TOOL_CRASH = "tool_crash"             # Tool threw an exception
    FLAG_REJECTED = "flag_rejected"        # Found candidate but validation rejected it
    UNKNOWN = "unknown"                    # Can't determine failure mode

# Optimizer constants
_MIN_SAMPLES_FOR_OPTIMIZATION = 5
_MIN_RUNS_FOR_SKIP = 8
_MIN_CASCADE_SIZE = 3
_MAX_ELAPSED_VALUES = 200
_MAX_SOLVE_LOG = 500
_TIMEOUT_P95_MULTIPLIER = 1.3
_TIMEOUT_MIN = 5
_TIMEOUT_MAX = 300


class PerformanceDB:
    """Accumulates per-tool performance statistics across solves.

    Loads/saves from benchmarks/performance.json. Thread-safe for single-process
    access (one MCP server instance).
    """

    def __init__(self, db_path: Path | str | None = None):
        self._path = Path(db_path) if db_path else _PERF_DB_PATH
        self._data: dict[str, Any] = self._load()

    def _load(self) -> dict[str, Any]:
        """Load existing DB or create empty structure."""
        if self._path.exists():
            try:
                return json.loads(self._path.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        return {
            "global_stats": {
                "total_solves": 0,
                "total_failures": 0,
                "total_elapsed": 0.0,
            },
            "tool_stats": {},
            "type_stats": {},
            "solve_log": [],
        }

    def _save(self) -> None:
        """Persist DB to disk."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(self._data, indent=2, default=str) + "\n")

    def record_solve(self, session: dict) -> None:
        """Ingest a session dict and update accumulated stats.

        Args:
            session: A SolveSession.to_dict() output with keys:
                challenge_id, solved, flag, solving_tool, total_elapsed,
                cascade_results, extracted_params, steps, etc.
        """
        solved = session.get("solved", False)
        total_elapsed = session.get("total_elapsed", 0.0)
        challenge_id = session.get("challenge_id", "unknown")
        solving_tool = session.get("solving_tool", "")
        cascade_results = session.get("cascade_results", [])
        params = session.get("extracted_params", {})

        # Determine challenge type
        challenge_type = self._extract_challenge_type(session)

        # Update global stats
        gs = self._data["global_stats"]
        if solved:
            gs["total_solves"] = gs.get("total_solves", 0) + 1
        else:
            gs["total_failures"] = gs.get("total_failures", 0) + 1
        gs["total_elapsed"] = gs.get("total_elapsed", 0.0) + total_elapsed

        # Update per-tool stats
        for result in cascade_results:
            tool_name = result.get("tool", "")
            if not tool_name:
                continue
            tool_succeeded = (tool_name == solving_tool) and solved
            elapsed = result.get("elapsed_seconds", 0.0)
            self._update_tool_stats(tool_name, tool_succeeded, elapsed, challenge_type)

        # Update type stats
        ts = self._data.setdefault("type_stats", {})
        type_entry = ts.setdefault(challenge_type, {
            "total_solves": 0,
            "total_failures": 0,
            "solving_tools": {},
        })
        if solved:
            type_entry["total_solves"] = type_entry.get("total_solves", 0) + 1
            if solving_tool:
                st = type_entry.setdefault("solving_tools", {})
                st[solving_tool] = st.get(solving_tool, 0) + 1
        else:
            type_entry["total_failures"] = type_entry.get("total_failures", 0) + 1

        # Append to solve log (capped)
        log = self._data.setdefault("solve_log", [])
        log.append({
            "challenge_id": challenge_id,
            "challenge_type": challenge_type,
            "solved": solved,
            "solving_tool": solving_tool,
            "total_elapsed": round(total_elapsed, 3),
            "tools_run": len(cascade_results),
            "timestamp": time.time(),
        })
        if len(log) > _MAX_SOLVE_LOG:
            self._data["solve_log"] = log[-_MAX_SOLVE_LOG:]

        self._save()

    def _update_tool_stats(
        self, tool_name: str, succeeded: bool, elapsed: float, challenge_type: str
    ) -> None:
        """Update stats for a single tool execution."""
        tools = self._data.setdefault("tool_stats", {})
        entry = tools.setdefault(tool_name, {
            "runs": 0,
            "successes": 0,
            "elapsed_values": [],
            "by_type": {},
        })

        entry["runs"] = entry.get("runs", 0) + 1
        if succeeded:
            entry["successes"] = entry.get("successes", 0) + 1

        if elapsed > 0:
            ev = entry.setdefault("elapsed_values", [])
            ev.append(round(elapsed, 4))
            if len(ev) > _MAX_ELAPSED_VALUES:
                entry["elapsed_values"] = ev[-_MAX_ELAPSED_VALUES:]

        # Per-type breakdown
        bt = entry.setdefault("by_type", {})
        type_entry = bt.setdefault(challenge_type, {"runs": 0, "successes": 0})
        type_entry["runs"] = type_entry.get("runs", 0) + 1
        if succeeded:
            type_entry["successes"] = type_entry.get("successes", 0) + 1

    def _extract_challenge_type(self, session: dict) -> str:
        """Extract challenge type from session data."""
        # Check extracted_params first
        params = session.get("extracted_params", {})
        ct = params.get("challenge_type", "")
        if ct and ct != "unknown":
            return ct.lower()

        # Check triage result
        triage = session.get("triage_result", {})
        binary_info = triage.get("binary_info", {})
        file_type = binary_info.get("file_type", "")

        # Check steps for challenge_type in tool_cascade input
        for step in session.get("steps", []):
            summary = step.get("input_summary", "")
            if "type=" in summary:
                import re
                m = re.search(r"type=(\w+)", summary)
                if m and m.group(1) != "auto":
                    return m.group(1).lower()

        return "unknown"

    def get_tool_stats(self, tool_name: str, challenge_type: str = "") -> dict:
        """Get accumulated stats for a specific tool.

        Args:
            tool_name: Name of the tool (e.g. "auto_angr").
            challenge_type: Optional filter by challenge type.

        Returns dict with: runs, successes, success_rate, elapsed_p50,
        elapsed_p95, elapsed_mean.
        """
        tools = self._data.get("tool_stats", {})
        entry = tools.get(tool_name, {})

        if challenge_type:
            bt = entry.get("by_type", {})
            type_data = bt.get(challenge_type, {})
            runs = type_data.get("runs", 0)
            successes = type_data.get("successes", 0)
            # No per-type elapsed values stored; use global
            elapsed_values = entry.get("elapsed_values", [])
        else:
            runs = entry.get("runs", 0)
            successes = entry.get("successes", 0)
            elapsed_values = entry.get("elapsed_values", [])

        success_rate = (successes / runs * 100) if runs > 0 else 0.0

        p50 = _percentile(elapsed_values, 50)
        p95 = _percentile(elapsed_values, 95)
        mean = sum(elapsed_values) / len(elapsed_values) if elapsed_values else 0.0

        return {
            "tool": tool_name,
            "challenge_type": challenge_type or "all",
            "runs": runs,
            "successes": successes,
            "success_rate": round(success_rate, 1),
            "elapsed_p50": round(p50, 3),
            "elapsed_p95": round(p95, 3),
            "elapsed_mean": round(mean, 3),
            "elapsed_samples": len(elapsed_values),
        }

    def get_type_summary(self, challenge_type: str) -> dict:
        """Get summary stats for a challenge type.

        Returns dict with: challenge_type, total_solves, total_failures,
        solve_rate, solving_tools, tool_breakdown.
        """
        ts = self._data.get("type_stats", {}).get(challenge_type, {})
        total_solves = ts.get("total_solves", 0)
        total_failures = ts.get("total_failures", 0)
        total = total_solves + total_failures
        solve_rate = (total_solves / total * 100) if total > 0 else 0.0

        # Per-tool breakdown for this type
        tool_breakdown = {}
        for tool_name, entry in self._data.get("tool_stats", {}).items():
            bt = entry.get("by_type", {}).get(challenge_type, {})
            if bt.get("runs", 0) > 0:
                runs = bt["runs"]
                successes = bt.get("successes", 0)
                tool_breakdown[tool_name] = {
                    "runs": runs,
                    "successes": successes,
                    "success_rate": round(successes / runs * 100, 1),
                }

        return {
            "challenge_type": challenge_type,
            "total_solves": total_solves,
            "total_failures": total_failures,
            "solve_rate": round(solve_rate, 1),
            "solving_tools": ts.get("solving_tools", {}),
            "tool_breakdown": tool_breakdown,
        }

    def to_dict(self) -> dict[str, Any]:
        """Return the raw DB data."""
        return self._data


class FailureDB:
    """Tracks failure taxonomy -- why challenges fail and what would fix them.

    Stores failure records in benchmarks/failures.json with classification,
    details, and tools tried. Provides aggregation and improvement suggestions.
    """

    _MAX_FAILURES = 1000

    def __init__(self, db_path: Path | str | None = None):
        self._path = Path(db_path) if db_path else _FAILURES_PATH
        self._data: dict[str, Any] = self._load()

    def _load(self) -> dict[str, Any]:
        """Load existing failure DB or create empty structure."""
        if self._path.exists():
            try:
                return json.loads(self._path.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        return {"failures": [], "summary": {}}

    def _save(self) -> None:
        """Persist failure DB to disk."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(self._data, indent=2, default=str) + "\n")

    def record_failure(
        self,
        challenge_id: str,
        challenge_type: str,
        failure_type: str | FailureType,
        details: str = "",
        tools_tried: list[str] | None = None,
    ) -> dict[str, Any]:
        """Log a failure with classification.

        Args:
            challenge_id: Name or path of the challenge.
            challenge_type: Classification type (crypto, constraint, etc.).
            failure_type: One of FailureType values.
            details: Human-readable explanation of what went wrong.
            tools_tried: List of tool names that were attempted.

        Returns the recorded failure entry.
        """
        # Validate failure_type
        ft_value = failure_type.value if isinstance(failure_type, FailureType) else failure_type
        valid_types = {ft.value for ft in FailureType}
        if ft_value not in valid_types:
            ft_value = FailureType.UNKNOWN.value

        entry = {
            "challenge_id": challenge_id,
            "challenge_type": challenge_type,
            "failure_type": ft_value,
            "details": details,
            "tools_tried": tools_tried or [],
            "timestamp": time.time(),
        }

        failures = self._data.setdefault("failures", [])
        failures.append(entry)

        # Cap the list
        if len(failures) > self._MAX_FAILURES:
            self._data["failures"] = failures[-self._MAX_FAILURES:]

        # Rebuild summary
        self._rebuild_summary()
        self._save()
        return entry

    def _rebuild_summary(self) -> None:
        """Rebuild summary counts from failure list."""
        failures = self._data.get("failures", [])
        counts: dict[str, int] = {}
        for f in failures:
            ft = f.get("failure_type", FailureType.UNKNOWN.value)
            counts[ft] = counts.get(ft, 0) + 1
        counts["total"] = len(failures)
        self._data["summary"] = counts

    def failure_stats(self) -> dict[str, Any]:
        """Return failure counts by failure type and challenge type.

        Returns dict with:
            by_failure_type: {failure_type: count}
            by_challenge_type: {challenge_type: {failure_type: count, total: N}}
            total: total failure count
            top_failures: sorted list of (failure_type, count) descending
        """
        failures = self._data.get("failures", [])

        by_failure_type: dict[str, int] = Counter()
        by_challenge_type: dict[str, dict[str, int]] = {}

        for f in failures:
            ft = f.get("failure_type", FailureType.UNKNOWN.value)
            ct = f.get("challenge_type", "unknown")

            by_failure_type[ft] += 1

            ct_entry = by_challenge_type.setdefault(ct, {})
            ct_entry[ft] = ct_entry.get(ft, 0) + 1
            ct_entry["total"] = ct_entry.get("total", 0) + 1

        top_failures = sorted(by_failure_type.items(), key=lambda x: x[1], reverse=True)

        return {
            "by_failure_type": dict(by_failure_type),
            "by_challenge_type": by_challenge_type,
            "total": len(failures),
            "top_failures": top_failures,
        }

    def suggest_improvements(self) -> list[dict[str, Any]]:
        """Analyze failures and suggest what tools/fixes would help most.

        Returns a list of suggestions sorted by impact (number of challenges fixed).
        Each suggestion has: suggestion, impact, failure_type, challenge_type,
        affected_challenges.
        """
        failures = self._data.get("failures", [])
        if not failures:
            return []

        suggestions: list[dict[str, Any]] = []

        # Group failures by (failure_type, challenge_type)
        groups: dict[tuple[str, str], list[dict]] = {}
        for f in failures:
            ft = f.get("failure_type", FailureType.UNKNOWN.value)
            ct = f.get("challenge_type", "unknown")
            groups.setdefault((ft, ct), []).append(f)

        for (ft, ct), group_failures in groups.items():
            challenge_ids = list({f.get("challenge_id", "?") for f in group_failures})
            count = len(challenge_ids)

            if count == 0:
                continue

            # Generate suggestion based on failure type
            suggestion = self._suggest_for_group(ft, ct, group_failures, challenge_ids)
            if suggestion:
                suggestions.append({
                    "suggestion": suggestion,
                    "impact": count,
                    "failure_type": ft,
                    "challenge_type": ct,
                    "affected_challenges": challenge_ids,
                })

        # Sort by impact descending
        suggestions.sort(key=lambda x: x["impact"], reverse=True)
        return suggestions

    def _suggest_for_group(
        self,
        failure_type: str,
        challenge_type: str,
        failures: list[dict],
        challenge_ids: list[str],
    ) -> str:
        """Generate a human-readable suggestion for a failure group."""
        count = len(challenge_ids)
        ids_str = ", ".join(challenge_ids[:5])
        if len(challenge_ids) > 5:
            ids_str += f" (+{len(challenge_ids) - 5} more)"

        # Collect tools tried across all failures in this group
        all_tools: set[str] = set()
        for f in failures:
            all_tools.update(f.get("tools_tried", []))
        tools_str = ", ".join(sorted(all_tools)[:5]) if all_tools else "none"

        if failure_type == FailureType.NO_TOOL_MATCH.value:
            return (
                f"Add new tool for {challenge_type} challenges -- "
                f"{count} challenge(s) ({ids_str}) have no matching tool. "
                f"Tools tried: {tools_str}"
            )
        elif failure_type == FailureType.TOOL_PARTIAL.value:
            # Look at details for common patterns
            details = [f.get("details", "") for f in failures]
            common_detail = details[0][:100] if details else ""
            return (
                f"Improve extraction in {challenge_type} tools -- "
                f"{count} challenge(s) ({ids_str}) found data but couldn't extract flag. "
                f"Detail: {common_detail}"
            )
        elif failure_type == FailureType.CLASSIFY_WRONG.value:
            return (
                f"Fix classifier for {challenge_type} -- "
                f"{count} challenge(s) ({ids_str}) were misclassified, "
                f"causing wrong tools to run"
            )
        elif failure_type == FailureType.LLM_FLAKY.value:
            return (
                f"Replace LLM-dependent path for {challenge_type} -- "
                f"{count} challenge(s) ({ids_str}) rely on non-deterministic LLM solve"
            )
        elif failure_type == FailureType.TIMEOUT.value:
            return (
                f"Optimize performance for {challenge_type} -- "
                f"{count} challenge(s) ({ids_str}) timed out. "
                f"Consider increasing timeout or optimizing tools: {tools_str}"
            )
        elif failure_type == FailureType.TOOL_CRASH.value:
            return (
                f"Fix crashing tools for {challenge_type} -- "
                f"{count} challenge(s) ({ids_str}) had tool exceptions. "
                f"Crashing tools: {tools_str}"
            )
        elif failure_type == FailureType.FLAG_REJECTED.value:
            return (
                f"Loosen flag validation for {challenge_type} -- "
                f"{count} challenge(s) ({ids_str}) found flag candidates "
                f"but validation rejected them"
            )
        else:
            return (
                f"Investigate {count} {challenge_type} failure(s) ({ids_str}) -- "
                f"failure reason unknown"
            )

    def to_dict(self) -> dict[str, Any]:
        """Return the raw failure DB data."""
        return self._data


def classify_failure(
    cascade_results: list[dict],
    elapsed: float = 0.0,
    timeout: float = 0.0,
) -> str:
    """Auto-classify a solve failure based on cascade results.

    Examines the cascade results to determine the most likely failure type.

    Args:
        cascade_results: List of tool result dicts from the cascade.
        elapsed: Total elapsed time in seconds.
        timeout: Configured timeout in seconds (0 = no timeout check).

    Returns a FailureType value string.
    """
    if not cascade_results:
        return FailureType.NO_TOOL_MATCH.value

    # Check for timeout
    if timeout > 0 and elapsed >= timeout * 0.95:
        return FailureType.TIMEOUT.value

    has_output = False
    has_crash = False
    has_flag_candidate = False

    for result in cascade_results:
        stdout = result.get("stdout", "")
        stderr = result.get("stderr", "")
        exit_code = result.get("exit_code", None)
        tool = result.get("tool", "")

        # Check for crashes (non-zero exit with traceback-like stderr)
        if exit_code is not None and exit_code != 0:
            if "Traceback" in stderr or "Error" in stderr:
                has_crash = True

        # Check for any meaningful output
        if stdout and len(stdout.strip()) > 10:
            has_output = True

        # Check for flag candidates that were found but rejected
        flag_candidate = result.get("flag", result.get("flag_candidate", ""))
        if flag_candidate:
            has_flag_candidate = True

    if has_flag_candidate:
        return FailureType.FLAG_REJECTED.value

    if has_crash:
        return FailureType.TOOL_CRASH.value

    if has_output:
        return FailureType.TOOL_PARTIAL.value

    return FailureType.NO_TOOL_MATCH.value


def optimize(
    perf_db: PerformanceDB | None = None,
    min_samples: int = _MIN_SAMPLES_FOR_OPTIMIZATION,
    config_path: Path | str | None = None,
) -> dict[str, Any]:
    """Analyze performance stats and write optimized cascade config.

    Per challenge type with >= min_samples solves:
    1. Reorder tools by composite score (success_rate * 1000 + speed_score)
    2. Skip tools with 0% success after 8+ runs (never below 3 tools)
    3. Compute per-tool timeouts as ceil(p95 * 1.3) clamped to [5, 300]

    Args:
        perf_db: PerformanceDB instance (loaded from default path if None).
        min_samples: Minimum solves per type before optimizing.
        config_path: Override output path for cascade config.

    Returns the generated config dict.
    """
    if perf_db is None:
        perf_db = PerformanceDB()

    out_path = Path(config_path) if config_path else _CASCADE_CONFIG_PATH
    data = perf_db.to_dict()
    type_stats = data.get("type_stats", {})
    tool_stats = data.get("tool_stats", {})

    config: dict[str, Any] = {
        "generated_at": time.time(),
        "min_samples": min_samples,
        "type_cascades": {},
    }

    for challenge_type, ts in type_stats.items():
        total = ts.get("total_solves", 0) + ts.get("total_failures", 0)
        if total < min_samples:
            config["type_cascades"][challenge_type] = None
            continue

        # Collect per-tool data for this type
        tool_scores: list[tuple[float, str]] = []
        skip_tools: list[str] = []
        tool_timeouts: dict[str, int] = {}

        for tool_name, entry in tool_stats.items():
            bt = entry.get("by_type", {}).get(challenge_type, {})
            runs = bt.get("runs", 0)
            successes = bt.get("successes", 0)

            if runs == 0:
                # Never ran for this type -- append at end (no data)
                tool_scores.append((-1, tool_name))
                continue

            success_rate = successes / runs if runs > 0 else 0.0

            # Skip tools with 0% success after sufficient runs
            if success_rate == 0 and runs >= _MIN_RUNS_FOR_SKIP:
                skip_tools.append(tool_name)
                continue

            # Speed score: inverse of median elapsed (faster = higher)
            elapsed_values = entry.get("elapsed_values", [])
            p50 = _percentile(elapsed_values, 50) if elapsed_values else 30.0
            speed_score = 1000.0 / max(p50, 0.01)  # Cap at 0.01 to avoid div/0

            composite = success_rate * 1000 + speed_score
            tool_scores.append((composite, tool_name))

            # Compute per-tool timeout
            if elapsed_values:
                p95 = _percentile(elapsed_values, 95)
                timeout = int(math.ceil(p95 * _TIMEOUT_P95_MULTIPLIER))
                timeout = max(_TIMEOUT_MIN, min(_TIMEOUT_MAX, timeout))
                tool_timeouts[tool_name] = timeout

        # Sort by composite score descending
        tool_scores.sort(key=lambda x: x[0], reverse=True)
        ordered = [name for _, name in tool_scores]

        # Separate into universal and type-specific ordering
        # (We preserve the universal/type-specific distinction from the
        # registry so the config is compatible with tool_router)
        from kraken.nodes.tool_router import (
            _get_universal_tools,
            _get_type_specific,
            _get_default_type_specific,
        )

        universal_set = set(_get_universal_tools())
        type_specific_set = set(
            _get_type_specific().get(challenge_type, _get_default_type_specific())
        )

        universal_order = [t for t in ordered if t in universal_set]
        type_specific_order = [t for t in ordered if t in type_specific_set]

        # Safety: never reduce cascade below MIN_CASCADE_SIZE
        active_count = len([t for t in ordered if t not in skip_tools])
        while active_count < _MIN_CASCADE_SIZE and skip_tools:
            # Re-admit the least-bad skipped tool
            skip_tools.pop()
            active_count += 1

        # Compute overall type timeout (p95 of all tool elapsed values)
        all_elapsed = []
        for tool_name, entry in tool_stats.items():
            bt = entry.get("by_type", {}).get(challenge_type, {})
            if bt.get("runs", 0) > 0:
                all_elapsed.extend(entry.get("elapsed_values", []))

        type_timeout = None
        if all_elapsed:
            p95 = _percentile(all_elapsed, 95)
            type_timeout = int(math.ceil(p95 * _TIMEOUT_P95_MULTIPLIER))
            type_timeout = max(_TIMEOUT_MIN, min(_TIMEOUT_MAX, type_timeout))

        config["type_cascades"][challenge_type] = {
            "universal_order": universal_order,
            "type_specific_order": type_specific_order,
            "skip_tools": skip_tools,
            "timeouts": tool_timeouts,
            "type_timeout": type_timeout,
            "samples": total,
        }

    # Write config
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(config, indent=2) + "\n")

    return config


def load_cascade_config(config_path: Path | str | None = None) -> dict[str, Any] | None:
    """Load the learned cascade config, or None if missing/invalid.

    Used by tool_router to override hardcoded cascade ordering.
    """
    path = Path(config_path) if config_path else _CASCADE_CONFIG_PATH
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        if not isinstance(data, dict) or "type_cascades" not in data:
            return None
        return data
    except (json.JSONDecodeError, OSError):
        return None


def backfill_from_sessions(sessions_dir: str | Path = "solves") -> dict[str, Any]:
    """Bootstrap the PerformanceDB from existing session.json files.

    Scans the directory tree for session.json files, ingests them all,
    and runs optimize() afterward.

    Args:
        sessions_dir: Root directory to scan for session.json files.

    Returns dict with: sessions_found, sessions_ingested, errors, config.
    """
    root = Path(sessions_dir)
    perf_db = PerformanceDB()
    found = 0
    ingested = 0
    errors: list[str] = []

    for session_path in sorted(root.rglob("session.json")):
        found += 1
        try:
            session = json.loads(session_path.read_text())
            perf_db.record_solve(session)
            ingested += 1
        except Exception as e:
            errors.append(f"{session_path}: {e}")

    # Run optimizer with accumulated data
    config = {}
    if ingested > 0:
        try:
            config = optimize(perf_db=perf_db)
        except Exception as e:
            errors.append(f"optimize: {e}")

    return {
        "sessions_found": found,
        "sessions_ingested": ingested,
        "errors": errors,
        "config": config,
    }


# ── Helpers ──────────────────────────────────────────────────────────────────


def _percentile(values: list[float], pct: int) -> float:
    """Compute the pct-th percentile of a list of values."""
    if not values:
        return 0.0
    sorted_vals = sorted(values)
    k = (len(sorted_vals) - 1) * pct / 100.0
    f = int(k)
    c = f + 1
    if c >= len(sorted_vals):
        return sorted_vals[-1]
    return sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f)
