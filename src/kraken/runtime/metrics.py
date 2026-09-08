"""Structured telemetry for LLM calls and tool executions.

Collects per-call metrics during a solve session and supports export
to JSON and Markdown for presentation-ready reporting.
"""
from __future__ import annotations

import json
import time
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kraken.logging.structured import get_logger

log = get_logger(__name__)


@dataclass
class LLMCallRecord:
    """Single LLM invocation record."""

    node: str
    tier: str
    model: str
    prompt_tokens: int
    eval_tokens: int
    duration_ms: float
    timestamp: float = field(default_factory=time.time)
    success: bool = True
    error: str = ""


@dataclass
class ToolCallRecord:
    """Single tool invocation record."""

    tool: str
    cmd: str
    exit_code: int
    duration_ms: float
    timestamp: float = field(default_factory=time.time)
    node: str = ""
    success: bool = True


@dataclass
class MetricsCollector:
    """Collects and aggregates runtime metrics."""

    session_id: str = ""
    challenge_id: str = ""
    llm_calls: list[LLMCallRecord] = field(default_factory=list)
    tool_calls: list[ToolCallRecord] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    start_time: float = field(default_factory=time.time)

    def record_llm_call(
        self,
        node: str,
        tier: str,
        model: str,
        prompt_tokens: int,
        eval_tokens: int,
        duration_ms: float,
        success: bool = True,
        error: str = "",
    ) -> None:
        rec = LLMCallRecord(
            node=node,
            tier=tier,
            model=model,
            prompt_tokens=prompt_tokens,
            eval_tokens=eval_tokens,
            duration_ms=duration_ms,
            success=success,
            error=error,
        )
        with self._lock:
            self.llm_calls.append(rec)

    def record_tool_call(
        self,
        tool: str,
        cmd: str,
        exit_code: int,
        duration_ms: float,
        node: str = "",
        success: bool = True,
    ) -> None:
        rec = ToolCallRecord(
            tool=tool,
            cmd=cmd,
            exit_code=exit_code,
            duration_ms=duration_ms,
            node=node,
            success=success,
        )
        with self._lock:
            self.tool_calls.append(rec)

    def summary(self) -> dict[str, Any]:
        """Aggregate metrics summary."""
        total_prompt = sum(r.prompt_tokens for r in self.llm_calls)
        total_eval = sum(r.eval_tokens for r in self.llm_calls)
        total_llm_ms = sum(r.duration_ms for r in self.llm_calls)
        total_tool_ms = sum(r.duration_ms for r in self.tool_calls)

        # Per-node breakdown
        node_stats: dict[str, dict] = {}
        for r in self.llm_calls:
            if r.node not in node_stats:
                node_stats[r.node] = {
                    "llm_calls": 0,
                    "prompt_tokens": 0,
                    "eval_tokens": 0,
                    "duration_ms": 0,
                    "model": r.model,
                    "tier": r.tier,
                }
            ns = node_stats[r.node]
            ns["llm_calls"] += 1
            ns["prompt_tokens"] += r.prompt_tokens
            ns["eval_tokens"] += r.eval_tokens
            ns["duration_ms"] += r.duration_ms

        # Per-model breakdown
        model_stats: dict[str, dict] = {}
        for r in self.llm_calls:
            if r.model not in model_stats:
                model_stats[r.model] = {"calls": 0, "prompt_tokens": 0, "eval_tokens": 0, "duration_ms": 0}
            ms = model_stats[r.model]
            ms["calls"] += 1
            ms["prompt_tokens"] += r.prompt_tokens
            ms["eval_tokens"] += r.eval_tokens
            ms["duration_ms"] += r.duration_ms

        elapsed_s = time.time() - self.start_time

        return {
            "session_id": self.session_id,
            "challenge_id": self.challenge_id,
            "elapsed_seconds": round(elapsed_s, 1),
            "total_llm_calls": len(self.llm_calls),
            "total_tool_calls": len(self.tool_calls),
            "total_prompt_tokens": total_prompt,
            "total_eval_tokens": total_eval,
            "total_tokens": total_prompt + total_eval,
            "total_llm_duration_ms": round(total_llm_ms, 1),
            "total_tool_duration_ms": round(total_tool_ms, 1),
            "tokens_per_second": round(total_eval / (total_llm_ms / 1000), 1) if total_llm_ms > 0 else 0,
            "node_stats": node_stats,
            "model_stats": model_stats,
        }

    def export_json(self, path: str | Path | None = None) -> str:
        """Export metrics as JSON. Returns the JSON string."""
        data = {
            "summary": self.summary(),
            "llm_calls": [
                {
                    "node": r.node,
                    "tier": r.tier,
                    "model": r.model,
                    "prompt_tokens": r.prompt_tokens,
                    "eval_tokens": r.eval_tokens,
                    "duration_ms": round(r.duration_ms, 1),
                    "timestamp": r.timestamp,
                    "success": r.success,
                }
                for r in self.llm_calls
            ],
            "tool_calls": [
                {
                    "tool": r.tool,
                    "cmd": r.cmd[:200],
                    "exit_code": r.exit_code,
                    "duration_ms": round(r.duration_ms, 1),
                    "node": r.node,
                }
                for r in self.tool_calls
            ],
        }
        json_str = json.dumps(data, indent=2, default=str)
        if path:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            Path(path).write_text(json_str)
            log.info("metrics_exported_json", path=str(path))
        return json_str

    def export_markdown(self, path: str | Path | None = None) -> str:
        """Export metrics as presentation-ready Markdown."""
        s = self.summary()
        lines = [
            f"# KRAKEN Runtime Metrics -- {s['challenge_id'] or 'Session'}",
            "",
            "## Summary",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total Time | {s['elapsed_seconds']:.1f}s |",
            f"| LLM Calls | {s['total_llm_calls']} |",
            f"| Tool Calls | {s['total_tool_calls']} |",
            f"| Prompt Tokens | {s['total_prompt_tokens']:,} |",
            f"| Eval Tokens | {s['total_eval_tokens']:,} |",
            f"| Total Tokens | {s['total_tokens']:,} |",
            f"| Tokens/sec | {s['tokens_per_second']:.1f} |",
            f"| LLM Time | {s['total_llm_duration_ms']/1000:.1f}s |",
            "",
            "## Per-Node Breakdown",
            "",
            "| Node | Model | Tier | Calls | Prompt Tok | Eval Tok | Time (s) |",
            "|------|-------|------|------:|----------:|---------:|---------:|",
        ]

        for node, ns in sorted(s["node_stats"].items()):
            lines.append(
                f"| {node} | {ns['model']} | {ns['tier']} | "
                f"{ns['llm_calls']} | {ns['prompt_tokens']:,} | "
                f"{ns['eval_tokens']:,} | {ns['duration_ms']/1000:.1f} |"
            )

        lines.extend([
            "",
            "## Per-Model Breakdown",
            "",
            "| Model | Calls | Prompt Tok | Eval Tok | Time (s) |",
            "|-------|------:|----------:|---------:|---------:|",
        ])

        for model, ms in sorted(s["model_stats"].items()):
            lines.append(
                f"| {model} | {ms['calls']} | {ms['prompt_tokens']:,} | "
                f"{ms['eval_tokens']:,} | {ms['duration_ms']/1000:.1f} |"
            )

        md = "\n".join(lines) + "\n"
        if path:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            Path(path).write_text(md)
            log.info("metrics_exported_markdown", path=str(path))
        return md


# ── Module-level singleton for global metrics collection ──────────────
_global_collector: MetricsCollector | None = None
_global_lock = threading.Lock()


def get_metrics_collector() -> MetricsCollector:
    """Get or create the global metrics collector singleton."""
    global _global_collector
    with _global_lock:
        if _global_collector is None:
            _global_collector = MetricsCollector()
        return _global_collector


def reset_metrics_collector(session_id: str = "", challenge_id: str = "") -> MetricsCollector:
    """Reset the global metrics collector (call at session start)."""
    global _global_collector
    with _global_lock:
        _global_collector = MetricsCollector(session_id=session_id, challenge_id=challenge_id)
        return _global_collector
