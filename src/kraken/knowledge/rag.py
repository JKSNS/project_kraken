"""RAG retrieval to augment solve engine prompts with similar challenge solutions.

The SolveRAG class generates context strings that can be prepended to
solve engine prompts, providing information about similar previously-solved
challenges and recommended tools.
"""

from __future__ import annotations

import logging
from typing import Any

from .trajectory import TrajectoryStore

logger = logging.getLogger(__name__)


class SolveRAG:
    """Retrieval-Augmented Generation for the solve engine.

    Queries the trajectory store for similar solved/failed challenges
    and formats the results into context strings suitable for LLM prompts.
    """

    def __init__(self) -> None:
        self.store = TrajectoryStore()

    @property
    def available(self) -> bool:
        """Whether the RAG system has access to Qdrant."""
        return self.store.available

    # ------------------------------------------------------------------
    # Context generation
    # ------------------------------------------------------------------

    def get_context(self, state: dict[str, Any], max_similar: int = 3) -> str:
        """Generate RAG context string for the solve engine prompt.

        Returns a formatted string describing similar solved challenges,
        their solving tools, and strategies.  Returns empty string if
        Qdrant is unavailable or no similar challenges are found.
        """
        if not self.store.available:
            return ""

        similar = self.store.find_similar_solved(state, limit=max_similar)
        if not similar:
            return ""

        context_parts = [
            "# === SIMILAR SOLVED CHALLENGES (from knowledge base) ==="
        ]

        for i, s in enumerate(similar, 1):
            payload = s.get("payload", {})
            score = s.get("score", 0)

            solving_tool = payload.get("solving_tool", "unknown")
            challenge_type = payload.get("challenge_type", "unknown")
            category = payload.get("category", "")
            strategies = payload.get("strategies_tried", [])
            tool_summary = payload.get("tool_results_summary", "")
            binary_summary = payload.get("binary_info_summary", "")
            elapsed = payload.get("elapsed_seconds", 0)

            context_parts.append(f"""
## Similar Challenge #{i} (similarity: {score:.2f})
- Challenge: {payload.get('challenge_id', '?')}
- Type: {challenge_type}{f' ({category})' if category and category != challenge_type else ''}
- Solved by tool: {solving_tool}
- Solve time: {elapsed:.1f}s
- Binary: {binary_summary}""")

            if strategies:
                context_parts.append(
                    f"- Strategies tried: {', '.join(str(s) for s in strategies[:5])}"
                )

            if tool_summary:
                # Truncate long summaries
                summary_text = str(tool_summary)[:200]
                context_parts.append(f"- Key insight: {summary_text}")

        context_parts.append("")  # Trailing newline
        return "\n".join(context_parts)

    def get_failure_context(self, state: dict[str, Any], max_similar: int = 2) -> str:
        """Generate context about similar failed challenges.

        Helps the solve engine avoid strategies that are known not to work
        on similar challenges.
        """
        if not self.store.available:
            return ""

        failed = self.store.find_similar_failed(state, limit=max_similar)
        if not failed:
            return ""

        context_parts = [
            "# === SIMILAR FAILED CHALLENGES (avoid these approaches) ==="
        ]

        for i, f in enumerate(failed, 1):
            payload = f.get("payload", {})
            score = f.get("score", 0)

            context_parts.append(f"""
## Failed Challenge #{i} (similarity: {score:.2f})
- Challenge: {payload.get('challenge_id', '?')}
- Failure type: {payload.get('failure_type', 'unknown')}
- Strategies that failed: {', '.join(str(s) for s in payload.get('strategies_tried', [])[:5])}
- Tools that produced output but no flag: {', '.join(payload.get('tools_with_output', [])[:5])}""")

            diagnosis = payload.get("failure_diagnosis", "")
            if diagnosis:
                context_parts.append(f"- Diagnosis: {str(diagnosis)[:200]}")

        context_parts.append("")
        return "\n".join(context_parts)

    def get_full_context(self, state: dict[str, Any]) -> str:
        """Generate combined success + failure RAG context.

        Returns both similar solved challenges and similar failed challenges,
        formatted for prepending to a solve engine prompt.
        """
        parts: list[str] = []

        success_ctx = self.get_context(state, max_similar=3)
        if success_ctx:
            parts.append(success_ctx)

        failure_ctx = self.get_failure_context(state, max_similar=2)
        if failure_ctx:
            parts.append(failure_ctx)

        return "\n".join(parts)

    # ------------------------------------------------------------------
    # Tool boosting
    # ------------------------------------------------------------------

    def get_tool_boost(self, state: dict[str, Any]) -> list[str]:
        """Get tools to prioritize based on similar challenges.

        Returns tool names sorted by frequency in similar solved challenges
        (most recommended first).
        """
        return self.store.get_tool_recommendation(state)

    def get_avoidance_strategies(self, state: dict[str, Any]) -> list[str]:
        """Get strategies to avoid based on similar failed challenges."""
        return self.store.get_avoidance_list(state)

    # ------------------------------------------------------------------
    # Combined recommendation
    # ------------------------------------------------------------------

    def get_recommendation(self, state: dict[str, Any]) -> dict[str, Any]:
        """Get a complete recommendation bundle for a challenge.

        Returns a dict with:
          - context: RAG context string for prompts
          - tool_boost: list of tools to prioritize
          - avoid_strategies: list of strategies to avoid
          - similar_count: number of similar challenges found
        """
        context = self.get_full_context(state)
        tool_boost = self.get_tool_boost(state)
        avoid = self.get_avoidance_strategies(state)

        return {
            "context": context,
            "tool_boost": tool_boost,
            "avoid_strategies": avoid,
            "similar_count": len(self.store.find_similar_solved(state, limit=5)),
            "available": self.store.available,
        }
