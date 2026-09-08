"""Keygen specialist -- direct solve for simple key checks."""
from __future__ import annotations

import json

from kraken.state import KrakenState
from kraken.models import direct_generate
from kraken.config import ModelConfig
from kraken.logging.structured import get_logger

log = get_logger(__name__)


async def keygen(state: KrakenState) -> dict:
    """Analyze simple key generation/transformation and prepare solve approach."""
    from kraken.storage.artifact_store import get_artifact
    functions = get_artifact(state, "decompiled_functions", "decompiled_functions_handle")
    strings = state.get("strings_of_interest", [])

    log.info("keygen_start")

    prompt = f"""Analyze this CTF reverse engineering challenge. It uses a simple key check or transformation.

## Decompiled Functions
{json.dumps({k: v[:2000] for k, v in list(functions.items())[:10]}, indent=2)}

## Strings
{json.dumps(strings[:20], indent=2)}

Your task: identify the key validation logic and describe how to compute the correct key.
Focus on:
1. What input format is expected?
2. What transformations are applied to the input?
3. What is it compared against?
4. How can we reverse the comparison to find the key?

Respond with JSON:
{{
    "input_format": "description of expected input",
    "transformations": ["list of transformations applied"],
    "comparison_target": "what the transformed input is compared to",
    "reverse_approach": "step-by-step approach to compute the key",
    "key_hint": "any partial key information found"
}}"""

    cfg = ModelConfig()
    content = await direct_generate(prompt, "mid", cfg)

    analysis = {}
    try:
        json_str = content
        if "```json" in content:
            json_str = content.split("```json")[1].split("```")[0]
        elif "```" in content:
            json_str = content.split("```")[1].split("```")[0]
        analysis = json.loads(json_str)
    except (json.JSONDecodeError, IndexError):
        analysis = {"raw_analysis": content}

    log.info("keygen_complete", approach=analysis.get("reverse_approach", "unknown")[:100])

    return {
        "strategy_hypothesis": f"Keygen: {analysis.get('reverse_approach', '')}",
        "recent_actions": [{
            "action": "keygen",
            "reasoning": f"Key analysis: {analysis.get('input_format', 'unknown')}",
            "result_summary": json.dumps(analysis)[:300],
        }],
        "iteration_count": state.get("iteration_count", 0) + 1,
    }
