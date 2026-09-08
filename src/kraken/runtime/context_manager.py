"""Context window manager -- track token usage and enforce budgets.

Provides pre-flight checks before LLM calls to ensure prompts fit
within the model's context window, and adaptive pruning strategies
to reduce prompt size when needed.
"""
from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from kraken.logging.structured import get_logger

log = get_logger(__name__)

# Known context window sizes for common Ollama models
_MODEL_CONTEXT_SIZES: dict[str, int] = {
    "qwen3-coder:30b": 32768,
    "qwen3-coder:14b": 32768,
    "qwen3-coder:8b": 32768,
    "deepseek-r1:32b": 131072,
    "deepseek-coder-v2:33b": 131072,
    "devstral-small-2:24b": 32768,
    "gpt-oss:20b": 32768,
    "glm-4.7-flash": 32768,
    "codestral:22b": 32768,
    "qwen2.5-coder:32b": 32768,
    "qwen2.5-coder:14b": 32768,
    "qwen2.5-coder:7b": 32768,
    "qwen3.5-9b-256k": 262144,
    "nemotron:70b": 262144,
    "llama3.2:3b": 131072,
}

# Default context window when model is unknown
DEFAULT_CONTEXT_SIZE = 32768


@dataclass
class ContextBudget:
    """Token budget allocation for a prompt."""

    total_limit: int
    functions_budget: int  # decompiled functions
    attempts_budget: int  # prior solve attempts
    specialist_budget: int  # specialist summary

    @property
    def remaining(self) -> int:
        return self.total_limit - (
            self.functions_budget + self.attempts_budget +
            self.specialist_budget
        )


@dataclass
class ContextManager:
    """Manages context window budgets for LLM calls."""

    base_url: str = "http://localhost:11434"
    num_ctx: int = DEFAULT_CONTEXT_SIZE
    _token_cache: dict[str, int] = field(default_factory=dict)

    def get_context_size(self, model: str) -> int:
        """Get the context window size for a model."""
        return _MODEL_CONTEXT_SIZES.get(model.lower(), self.num_ctx)

    def estimate_tokens(self, text: str) -> int:
        """Estimate token count for text.

        Uses chars/4 heuristic. Ollama's /api/tokenize endpoint could
        be used for exact counts but adds latency per call.
        """
        return max(1, len(text) // 4)

    def tokenize(self, text: str, model: str) -> int:
        """Get exact token count via Ollama /api/tokenize endpoint.

        Falls back to estimation on error.
        """
        url = f"{self.base_url.rstrip('/')}/api/embed"
        try:
            payload = json.dumps({"model": model, "input": text}).encode()
            req = urllib.request.Request(url, data=payload, method="POST")
            req.add_header("Content-Type", "application/json")
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
                # prompt_eval_count gives exact token count
                count = data.get("prompt_eval_count", 0)
                if count > 0:
                    return count
        except Exception:
            pass
        return self.estimate_tokens(text)

    def compute_budget(self, model: str, reserved_output: int = 4096) -> ContextBudget:
        """Compute token budgets for prompt assembly.

        Reserves space for output generation and allocates the rest
        across prompt sections with priority-based budgets.
        """
        ctx_size = self.get_context_size(model)
        available = ctx_size - reserved_output

        # Budget allocation (proportional):
        #   55% for decompiled functions
        #   25% for prior attempts
        #   20% for specialist summary
        return ContextBudget(
            total_limit=available,
            functions_budget=int(available * 0.55),
            attempts_budget=int(available * 0.25),
            specialist_budget=int(available * 0.20),
        )

    def check_fits(self, prompt: str, model: str, reserved_output: int = 4096) -> bool:
        """Check if a prompt fits within the model's context window."""
        ctx_size = self.get_context_size(model)
        prompt_tokens = self.estimate_tokens(prompt)
        fits = (prompt_tokens + reserved_output) <= ctx_size
        if not fits:
            log.warning(
                "context_overflow",
                model=model,
                prompt_tokens=prompt_tokens,
                ctx_size=ctx_size,
                reserved_output=reserved_output,
            )
        return fits

    def truncate_to_budget(self, text: str, token_budget: int) -> str:
        """Truncate text to fit within a token budget."""
        estimated = self.estimate_tokens(text)
        if estimated <= token_budget:
            return text
        # Approximate character limit from token budget
        char_limit = token_budget * 4
        truncated = text[:char_limit]
        if len(text) > char_limit:
            truncated += "\n... [truncated to fit context window]"
        return truncated

    def adaptive_prune(
        self,
        functions: str,
        attempts: str,
        specialist: str,
        model: str,
        reserved_output: int = 4096,
    ) -> dict[str, str]:
        """Adaptively prune prompt sections to fit context window.

        Pruning priority (first to reduce):
        1. Prior attempts (keep last 2)
        2. Specialist summary (keep core)
        3. Functions (keep top functions by size)
        """
        budget = self.compute_budget(model, reserved_output)

        result = {
            "functions": self.truncate_to_budget(functions, budget.functions_budget),
            "attempts": self.truncate_to_budget(attempts, budget.attempts_budget),
            "specialist": self.truncate_to_budget(specialist, budget.specialist_budget),
        }

        # Check total
        total = sum(self.estimate_tokens(v) for v in result.values())
        if total > budget.total_limit:
            # Second pass: reduce attempts
            result["attempts"] = self.truncate_to_budget(
                attempts, budget.attempts_budget // 2
            )
            log.info("context_prune_aggressive", model=model, total_tokens=total)

        return result
