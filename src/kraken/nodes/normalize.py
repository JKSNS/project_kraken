"""Normalize node -- LLM-assisted variable renaming and annotation.

Uses a low-tier model (Haiku) since hallucination here is non-critical.
Output goes to function_annotations, NEVER to decompiled_functions.
"""
from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from kraken.state import KrakenState
from kraken.models import direct_generate
from kraken.config import ModelConfig
from kraken.logging.structured import get_logger

log = get_logger(__name__)

_PROMPTS_DIR = Path(__file__).resolve().parent.parent / "prompts"


async def normalize(state: KrakenState) -> dict:
    """LLM (low): rename variables and add comments to decompiled code."""
    from kraken.storage.artifact_store import get_artifact
    functions = get_artifact(state, "decompiled_functions", "decompiled_functions_handle")
    if not functions:
        log.info("normalize_skip", reason="no decompiled functions")
        return {
            "recent_actions": [{
                "action": "normalize",
                "reasoning": "Skipped -- no decompiled functions available",
                "result_summary": "No functions to annotate",
            }],
        }

    # Skip LLM for source-only challenges (JS/PHP/Python) -- annotations are
    # useless for readable source code and waste 18+ seconds on Ollama.
    # Keys are __source_file.js__ or __data_description.txt__ -- skip if ALL
    # are source/data (no decompiled binary functions).
    source_keys = [k for k in functions if k.startswith(("__source_", "__data_"))]
    if source_keys and len(source_keys) == len(functions):
        log.info("normalize_skip_source_only", source_count=len(source_keys))
        # Use the raw source as its own annotation (already readable)
        annotations = {k: v[:2000] for k, v in functions.items()}
        return {
            "function_annotations": annotations,
            "recent_actions": [{
                "action": "normalize",
                "reasoning": "Skipped LLM -- challenge contains only source files (already readable)",
                "result_summary": f"Passed through {len(annotations)} source files as-is",
            }],
            "iteration_count": state.get("iteration_count", 0) + 1,
        }

    # Load and render prompt template
    env = Environment(loader=FileSystemLoader(str(_PROMPTS_DIR)))
    template = env.get_template("normalize.j2")

    # Limit to top functions by size to stay within context
    sorted_funcs = sorted(functions.items(), key=lambda x: len(x[1]), reverse=True)
    top_funcs = dict(sorted_funcs[:20])  # Limit to 20 largest functions

    prompt = template.render(functions=top_funcs)

    cfg = ModelConfig()
    content = await direct_generate(prompt, "low", cfg)

    # Parse JSON response
    annotations = {}
    if not content or not content.strip():
        log.warning("normalize_empty_response")
        # Use function names as basic annotations
        annotations = {name: f"// No annotation available\n{code[:500]}" for name, code in top_funcs.items()}
    else:
        try:
            json_str = content
            if "```json" in content:
                json_str = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                json_str = content.split("```")[1].split("```")[0]
            annotations = json.loads(json_str)
        except (json.JSONDecodeError, IndexError):
            log.warning("normalize_parse_failed", content_len=len(content))
            # Still try to use any text content as annotation
            annotations = {name: content[:500] for name in list(top_funcs.keys())[:3]}

    log.info("normalize_complete", num_annotations=len(annotations))

    return {
        "function_annotations": annotations,
        "recent_actions": [{
            "action": "normalize",
            "reasoning": "LLM annotation of decompiled functions (non-critical)",
            "result_summary": f"Annotated {len(annotations)} functions",
        }],
        "iteration_count": state.get("iteration_count", 0) + 1,
    }
