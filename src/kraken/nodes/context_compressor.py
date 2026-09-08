"""Context compressor -- LLM (low) summarizes older actions to save context space.

Implements observation masking: strips large tool outputs, keeps only
action + reasoning + result summary for compression.

Fix for unbounded growth: tracks `compressed_action_count` so downstream
nodes know to skip already-compressed actions when reading recent_actions.
"""
from __future__ import annotations

import json

from kraken.state import KrakenState
from kraken.config import ContextConfig, ModelConfig
from kraken.models import direct_generate
from kraken.logging.structured import get_logger

log = get_logger(__name__)


async def context_compressor(state: KrakenState) -> dict:
    """Compress older actions into a summary, keep recent ones verbatim.

    Since recent_actions uses operator.add (append-only), we can't remove
    old entries. Instead, we:
    1. Record `compressed_action_count` = how many actions are now summarized
    2. Store the summary in `context_summary`
    3. Downstream nodes use compressed_action_count to skip old entries
    """
    ctx_cfg = ContextConfig()
    recent = state.get("recent_actions", [])
    already_compressed = state.get("compressed_action_count", 0)

    # Only look at actions not yet compressed
    uncompressed = recent[already_compressed:]

    if len(uncompressed) <= ctx_cfg.full_fidelity_window:
        log.info("compressor_skip", reason="not enough new actions", count=len(uncompressed))
        return {
            "iteration_count": state.get("iteration_count", 0) + 1,
        }

    # Split: compress older uncompressed, keep recent verbatim
    to_compress = uncompressed[:-ctx_cfg.full_fidelity_window]
    kept_count = len(uncompressed) - len(to_compress)

    # Observation masking: strip large outputs, keep reasoning
    masked = []
    for action in to_compress:
        masked.append({
            "action": action.get("action", "unknown"),
            "reasoning": action.get("reasoning", "")[:200],
            "result_summary": action.get("result_summary", "")[:200],
        })

    existing_summary = state.get("context_summary", "")

    prompt = f"""Summarize these reverse engineering analysis steps concisely.
Focus on: what was tried, what was found, what failed and why.
Do NOT include specific hex values, addresses, or code snippets (those are stored separately).

Previous summary:
{existing_summary or 'None -- this is the first compression.'}

New actions to summarize:
{json.dumps(masked, indent=2)}

Write a concise summary (max 500 words) covering all key decisions and findings."""

    cfg = ModelConfig()
    new_summary = await direct_generate(prompt, "low", cfg)

    # Update compressed count: everything before the kept window is now compressed
    new_compressed_count = already_compressed + len(to_compress)

    log.info(
        "compressor_complete",
        compressed=len(to_compress),
        kept=kept_count,
        total_compressed=new_compressed_count,
        summary_len=len(new_summary),
    )

    return {
        "context_summary": new_summary,
        "compressed_action_count": new_compressed_count,
        "iteration_count": state.get("iteration_count", 0) + 1,
    }
