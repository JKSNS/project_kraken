"""LangChain callback handler for token usage tracking (Ollama backend)."""
from __future__ import annotations

from typing import Any

from langchain_core.callbacks import AsyncCallbackHandler

from kraken.logging.cost_tracker import CostTracker
from kraken.logging.structured import get_logger

log = get_logger(__name__)


class CostTrackingCallback(AsyncCallbackHandler):
    def __init__(self, tracker: CostTracker) -> None:
        self.tracker = tracker

    async def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        usage = getattr(response, "llm_output", {}) or {}
        token_usage = usage.get("token_usage") or {}
        # Ollama reports usage in generation_info or llm_output
        if not token_usage and response.generations:
            gen = response.generations[0][0] if response.generations[0] else None
            if gen and hasattr(gen, "generation_info"):
                token_usage = gen.generation_info.get("usage", {})

        input_tokens = token_usage.get("input_tokens", 0) or token_usage.get(
            "prompt_tokens", 0
        )
        output_tokens = token_usage.get("output_tokens", 0) or token_usage.get(
            "completion_tokens", 0
        )
        model = (
            kwargs.get("tags", ["unknown"])[0]
            if kwargs.get("tags")
            else usage.get("model_name", "unknown")
        )

        if input_tokens or output_tokens:
            self.tracker.record(
                model=model, input_tokens=input_tokens, output_tokens=output_tokens
            )
            log.info(
                "llm_call",
                model=model,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
            )
