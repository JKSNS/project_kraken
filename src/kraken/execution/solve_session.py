"""SolveSession -- captures full pipeline state during a solve for post-solve reporting.

Accumulates per-step timing, artifacts, and results as the pipeline runs
(triage → decompile → extract → cascade → validate). Serializable to JSON
and saveable to a structured directory for offline analysis.
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class StepRecord:
    """One pipeline step's captured data."""

    name: str
    started_at: float
    elapsed_seconds: float
    input_summary: str = ""
    output_keys: list[str] = field(default_factory=list)
    output_snapshot: dict[str, Any] = field(default_factory=dict)
    artifacts_created: list[str] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "started_at": self.started_at,
            "elapsed_seconds": round(self.elapsed_seconds, 4),
            "input_summary": self.input_summary,
            "output_keys": self.output_keys,
            "output_snapshot": self.output_snapshot,
            "artifacts_created": self.artifacts_created,
            "error": self.error,
        }


@dataclass
class SolveSession:
    """Full solve pipeline capture -- one per challenge attempt."""

    challenge_id: str
    challenge_path: str
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    started_at: float = field(default_factory=time.monotonic)

    # Per-step captures
    steps: list[StepRecord] = field(default_factory=list)

    # Final result
    flag: str = ""
    solved: bool = False
    solving_tool: str = ""
    total_elapsed: float = 0.0

    # Accumulated artifacts
    triage_result: dict[str, Any] = field(default_factory=dict)
    decompile_result: dict[str, Any] = field(default_factory=dict)
    extracted_params: dict[str, Any] = field(default_factory=dict)
    cascade_results: list[dict[str, Any]] = field(default_factory=list)

    def add_step(
        self,
        name: str,
        input_summary: str,
        output: dict[str, Any],
        elapsed: float,
        *,
        error: str = "",
    ) -> StepRecord:
        """Record a completed pipeline step."""
        snapshot = _safe_snapshot(output)
        step = StepRecord(
            name=name,
            started_at=time.monotonic(),
            elapsed_seconds=elapsed,
            input_summary=input_summary[:500],
            output_keys=list(output.keys()) if isinstance(output, dict) else [],
            output_snapshot=snapshot,
            error=error,
        )
        self.steps.append(step)
        return step

    def finalize(self) -> None:
        """Mark session complete and compute total elapsed time."""
        self.total_elapsed = time.monotonic() - self.started_at

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict."""
        return {
            "session_id": self.session_id,
            "challenge_id": self.challenge_id,
            "challenge_path": self.challenge_path,
            "solved": self.solved,
            "flag": self.flag,
            "solving_tool": self.solving_tool,
            "total_elapsed": round(self.total_elapsed, 3),
            "steps": [s.to_dict() for s in self.steps],
            "triage_result": _safe_snapshot(self.triage_result),
            "decompile_result": _safe_snapshot(self.decompile_result),
            "extracted_params": self.extracted_params,
            "cascade_results": [_safe_snapshot(r) for r in self.cascade_results],
        }

    def save(self, output_dir: Path) -> Path:
        """Persist session artifacts to a structured directory.

        Creates:
            {output_dir}/
            ├── session.json
            ├── README.md           (auto-generated writeup + mindmap)
            ├── flag.txt            (if solved)
            ├── artifacts/
            │   ├── triage.json
            │   ├── decompile.json
            │   ├── params.json
            │   ├── cascade.json
            │   └── timeline.jsonl
            └── scripts/            (placeholder for solve scripts)

        Returns the output_dir Path.
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        artifacts_dir = output_dir / "artifacts"
        artifacts_dir.mkdir(exist_ok=True)
        scripts_dir = output_dir / "scripts"
        scripts_dir.mkdir(exist_ok=True)

        # session.json -- full metadata
        _write_json(output_dir / "session.json", self.to_dict())

        # flag.txt
        if self.flag:
            (output_dir / "flag.txt").write_text(self.flag + "\n")

        # Individual artifact files
        if self.triage_result:
            _write_json(artifacts_dir / "triage.json", _safe_snapshot(self.triage_result))
        if self.decompile_result:
            _write_json(artifacts_dir / "decompile.json", _safe_snapshot(self.decompile_result))
        if self.extracted_params:
            _write_json(artifacts_dir / "params.json", self.extracted_params)
        if self.cascade_results:
            _write_json(
                artifacts_dir / "cascade.json",
                [_safe_snapshot(r) for r in self.cascade_results],
            )

        # timeline.jsonl -- one line per step
        with open(artifacts_dir / "timeline.jsonl", "w") as f:
            for step in self.steps:
                f.write(json.dumps(step.to_dict(), default=str) + "\n")

        # Extract solve scripts from cascade results
        for i, result in enumerate(self.cascade_results):
            script = result.get("script") or result.get("code") or ""
            if script:
                (scripts_dir / f"attempt_{i + 1}.py").write_text(script)

        # Auto-generate README.md writeup
        try:
            from kraken.reporting.generator import generate_report

            readme = generate_report(self.to_dict(), mode="writeup")
            (output_dir / "README.md").write_text(readme)
        except Exception:
            pass  # Non-fatal: don't fail save if report generation has issues

        # Emit comprehensive artifact bundle (analysis, knowledge graph, Ghidra import, etc.)
        try:
            from kraken.storage.artifacts import emit_artifacts

            # Build a state-like dict from session data for the artifact emitter
            state_proxy = {
                "challenge_id": self.challenge_id,
                "challenge_path": self.challenge_path,
                "solve_workspace": str(output_dir),
                "binary_info": self.triage_result.get("binary_info", {}),
                "decompiled_functions": self.decompile_result.get("decompiled_functions", {}),
                "call_graph": self.decompile_result.get("call_graph", {}),
                "strings_of_interest": self.triage_result.get("strings_of_interest", []),
                "xrefs": self.decompile_result.get("xrefs", {}),
                "symbols": self.decompile_result.get("symbols", {}),
                "function_annotations": self.decompile_result.get("function_annotations", {}),
                "extracted_params": self.extracted_params,
                "tool_cascade_results": self.cascade_results,
                "solve_scripts": [
                    {"code": r.get("script") or r.get("code", ""),
                     "exit_code": r.get("exit_code"),
                     "stdout": r.get("stdout", "")}
                    for r in self.cascade_results if r.get("script") or r.get("code")
                ],
                "flag_format": "",
                "category": "",
                "challenge_description": "",
                "challenge_dir": str(Path(self.challenge_path).parent),
                "strategy_hypothesis": "",
                "challenge_type": "",
                "secondary_types": [],
                "error_log": [],
                "rejected_flags": [],
                "failure_diagnosis": "",
                "script_findings": [],
            }
            solve_result = {
                "solved": self.solved,
                "flag": self.flag,
                "duration_seconds": round(self.total_elapsed, 1),
                "cost_usd": 0,
                "steps": len(self.steps),
                "strategies_tried": [],
                "solve_path": [s.name for s in self.steps],
                "node_timings": [{"node": s.name, "duration_s": s.elapsed_seconds} for s in self.steps],
            }
            emit_artifacts(state_proxy, solve_result, workspace=str(output_dir))
        except Exception:
            pass  # Non-fatal

        return output_dir

    @classmethod
    def load(cls, session_path: Path) -> SolveSession:
        """Load a SolveSession from a session.json file."""
        data = json.loads(session_path.read_text())
        session = cls(
            challenge_id=data.get("challenge_id", ""),
            challenge_path=data.get("challenge_path", ""),
            session_id=data.get("session_id", ""),
        )
        session.solved = data.get("solved", False)
        session.flag = data.get("flag", "")
        session.solving_tool = data.get("solving_tool", "")
        session.total_elapsed = data.get("total_elapsed", 0.0)
        session.triage_result = data.get("triage_result", {})
        session.decompile_result = data.get("decompile_result", {})
        session.extracted_params = data.get("extracted_params", {})
        session.cascade_results = data.get("cascade_results", [])

        for step_data in data.get("steps", []):
            step = StepRecord(
                name=step_data.get("name", ""),
                started_at=step_data.get("started_at", 0),
                elapsed_seconds=step_data.get("elapsed_seconds", 0),
                input_summary=step_data.get("input_summary", ""),
                output_keys=step_data.get("output_keys", []),
                output_snapshot=step_data.get("output_snapshot", {}),
                artifacts_created=step_data.get("artifacts_created", []),
                error=step_data.get("error", ""),
            )
            session.steps.append(step)

        return session


# ── Helpers ──────────────────────────────────────────────────────────────────


def _safe_snapshot(data: Any, max_str_len: int = 5000) -> Any:
    """Create a JSON-serializable snapshot, truncating large strings."""
    if isinstance(data, dict):
        return {k: _safe_snapshot(v, max_str_len) for k, v in data.items()}
    if isinstance(data, (list, tuple)):
        return [_safe_snapshot(item, max_str_len) for item in data]
    if isinstance(data, str) and len(data) > max_str_len:
        return data[:max_str_len] + f"... [truncated, {len(data)} chars total]"
    if isinstance(data, bytes):
        return data.hex()[:200]
    if isinstance(data, (int, float, bool, type(None))):
        return data
    return str(data)[:max_str_len]


def _write_json(path: Path, data: Any) -> None:
    """Write JSON with fallback for non-serializable types."""
    path.write_text(json.dumps(data, indent=2, default=str) + "\n")
