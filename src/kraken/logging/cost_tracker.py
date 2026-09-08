"""Token usage tracking with per-node attribution (Ollama -- local, no monetary cost)."""
from __future__ import annotations

import threading
from dataclasses import dataclass, field


@dataclass
class UsageRecord:
    model: str
    input_tokens: int
    output_tokens: int
    node: str = ""  # graph node that triggered this call

    @property
    def cost_usd(self) -> float:
        # Ollama runs locally -- no per-token cost
        return 0.0


@dataclass
class CostTracker:
    max_cost_usd: float = 0.0  # No budget needed for local inference
    records: list[UsageRecord] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @property
    def total_cost(self) -> float:
        return 0.0

    @property
    def total_input_tokens(self) -> int:
        return sum(r.input_tokens for r in self.records)

    @property
    def total_output_tokens(self) -> int:
        return sum(r.output_tokens for r in self.records)

    def record(self, model: str, input_tokens: int, output_tokens: int, node: str = "") -> None:
        rec = UsageRecord(model=model, input_tokens=input_tokens, output_tokens=output_tokens, node=node)
        with self._lock:
            self.records.append(rec)

    def check_budget(self) -> bool:
        # Local inference -- always within budget
        return True

    def per_node_summary(self) -> dict[str, dict]:
        """Per-node token usage breakdown."""
        nodes: dict[str, dict] = {}
        for r in self.records:
            key = r.node or "unknown"
            if key not in nodes:
                nodes[key] = {"calls": 0, "input_tokens": 0, "output_tokens": 0, "model": r.model}
            nodes[key]["calls"] += 1
            nodes[key]["input_tokens"] += r.input_tokens
            nodes[key]["output_tokens"] += r.output_tokens
        return nodes

    def summary(self) -> dict:
        return {
            "total_cost_usd": 0.0,
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "num_calls": len(self.records),
            "budget_remaining_usd": 0.0,
            "backend": "ollama (local)",
            "per_node": self.per_node_summary(),
        }
