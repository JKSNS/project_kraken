"""Classify node -- LLM-powered challenge type classification.

Uses a mid-tier model with structured output for guaranteed schema.
Includes fallback JSON parsing for models that don't support tool calling.

Enhancement: outputs secondary_types for hybrid challenges (#3, #5).
Enhancement: adds 'pwn' category (#11).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from jinja2 import Environment, FileSystemLoader
from pydantic import BaseModel, Field

from kraken.state import KrakenState
from kraken.models import structured_generate
from kraken.config import ModelConfig
from kraken.storage.artifact_store import get_artifact
from kraken.logging.structured import get_logger
from kraken.storage.ledger import append_ledger_entry

log = get_logger(__name__)

_PROMPTS_DIR = Path(__file__).resolve().parent.parent / "prompts"


class ClassificationResult(BaseModel):
    """Structured output schema for classify node."""
    challenge_type: Literal["constraint", "crypto", "dotnet", "dynamic", "keygen", "pwn", "fuzzing", "web", "firmware", "scripting", "forensics", "steg"]
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str
    key_indicators: list[str]
    secondary_types: list[str] = Field(
        default_factory=list,
        description="Other applicable types ranked by relevance (for hybrid challenges)",
    )


async def classify(state: KrakenState) -> dict:
    """LLM (mid): classify challenge type from analysis artifacts."""
    functions = get_artifact(state, "decompiled_functions", "decompiled_functions_handle")

    # Fast-path: if ALL functions are source/data files (JS/PHP/Python), skip LLM
    src_data_keys = [k for k in functions if k.startswith(("__source_", "__data_"))]
    source_keys = [k for k in functions if k.startswith("__source_")]
    if src_data_keys and len(src_data_keys) == len(functions) and source_keys:
        source_exts = {k.rsplit(".", 1)[-1].rstrip("_") for k in source_keys}
        scripting_exts = {"js", "php", "py", "rb", "pl"}
        if source_exts & scripting_exts:
            log.info("classify_fast_path_scripting", source_exts=list(source_exts))
            result = ClassificationResult(
                challenge_type="scripting",
                confidence=0.95,
                reasoning=f"Source-only challenge with scripting files ({', '.join(source_exts)})",
                key_indicators=[f".{e} source files" for e in source_exts],
                secondary_types=["crypto", "constraint"],
            )
            return _build_classify_output(state, result)

    env = Environment(loader=FileSystemLoader(str(_PROMPTS_DIR)))
    template = env.get_template("classify.j2")

    # Truncate large functions for context efficiency
    truncated = {k: v[:2000] for k, v in list(functions.items())[:15]}

    prompt = template.render(
        challenge_description=state.get("challenge_description", ""),
        binary_info=state.get("binary_info", {}),
        strings=state.get("strings_of_interest", []),
        functions=truncated,
        annotations=state.get("function_annotations", {}),
        challenge_files=state.get("challenge_files", {}),
    )

    model_cfg = ModelConfig()
    result: ClassificationResult | None = None

    # Strategy 1: structured_generate (JSON parse from generate call)
    try:
        schema = ClassificationResult.model_json_schema()
        parsed = await structured_generate(prompt, "low", model_cfg, schema)
        result = ClassificationResult.model_validate(parsed)
        log.info("classify_structured_success")
    except Exception as exc:
        log.warning("classify_structured_failed", error=str(exc))

    # Strategy 3: Last resort -- deterministic heuristics
    if result is None:
        log.warning("classify_all_strategies_failed_using_heuristic")
        result = _heuristic_classify(state)

    return _build_classify_output(state, result)


def _build_classify_output(state: KrakenState, result: ClassificationResult) -> dict:
    """Build the classify node output dict from a ClassificationResult."""
    log.info(
        "classify_complete",
        challenge_type=result.challenge_type,
        confidence=result.confidence,
        reasoning=result.reasoning,
        secondary_types=result.secondary_types,
    )

    updates: dict = {
        "challenge_type": result.challenge_type,
        "strategy_hypothesis": result.reasoning,
        "current_strategy": f"{result.challenge_type}: {result.reasoning}",
        "next_node": result.challenge_type,
        "recent_actions": [{
            "action": "classify",
            "reasoning": result.reasoning,
            "result_summary": (
                f"Type={result.challenge_type} (conf={result.confidence}), "
                f"secondary={result.secondary_types}, "
                f"indicators={result.key_indicators}"
            ),
        }],
        "iteration_count": state.get("iteration_count", 0) + 1,
    }

    # Store secondary types for solve_engine context (#3)
    if result.secondary_types:
        updates["secondary_types"] = result.secondary_types

    append_ledger_entry(
        state.get("solve_ledger_path", ""),
        (
            "\n## Classification\n"
            f"- challenge_type: {result.challenge_type}\n"
            f"- confidence: {result.confidence}\n"
            f"- reasoning: {result.reasoning}\n"
            f"- secondary_types: {', '.join(result.secondary_types) if result.secondary_types else 'none'}\n"
        ),
    )

    return updates


def _heuristic_classify(state: KrakenState) -> ClassificationResult:
    """Fallback heuristic classification based on deterministic artifacts."""
    functions = get_artifact(state, "decompiled_functions", "decompiled_functions_handle")
    strings = state.get("strings_of_interest", [])
    binary_info = state.get("binary_info", {})
    all_code = " ".join(str(v) for v in functions.values()).lower()
    all_strings = " ".join(str(s) for s in strings).lower()

    # Include challenge file contents for directory-only challenges
    challenge_files = state.get("challenge_files", {})
    for finfo in challenge_files.values():
        preview = finfo.get("content_preview", "")
        if preview:
            all_code += " " + preview.lower()

    # Check for crypto indicators
    crypto_keywords = ["xor", "encrypt", "decrypt", "cipher", "aes", "rc4", "base64", "rot13", "caesar"]
    crypto_score = sum(1 for kw in crypto_keywords if kw in all_code or kw in all_strings)

    # Check for constraint/keygen indicators
    constraint_keywords = ["strcmp", "check", "verify", "validate", "password", "correct", "wrong"]
    constraint_score = sum(1 for kw in constraint_keywords if kw in all_code or kw in all_strings)

    # Check for dynamic analysis indicators
    dynamic_keywords = ["ptrace", "anti_debug", "self_modify", "unpack", "vm_", "bytecode", "dispatch"]
    dynamic_score = sum(1 for kw in dynamic_keywords if kw in all_code or kw in all_strings)

    # Check for pwn indicators (#11)
    pwn_keywords = ["gets", "scanf", "strcpy", "sprintf", "system", "execve", "/bin/sh", "buf[", "buffer"]
    pwn_score = sum(1 for kw in pwn_keywords if kw in all_code or kw in all_strings)
    # Boost pwn score if NX/canary/PIE are relevant
    checksec = binary_info.get("checksec", {}) or binary_info.get("checksec_pwntools", {})
    if checksec and not checksec.get("Canary", True):
        pwn_score += 1

    # Check for scripting indicators (JS/PHP/Python source challenges)
    scripting_keywords = ["prompt(", "console.log", "charcodeat", "fromcharcode", "document.",
                          "base64_decode", "shell_exec", "<?php", "def ", "import ", "__import__"]
    scripting_score = sum(1 for kw in scripting_keywords if kw in all_code or kw in all_strings)
    # Boost if all functions are source files
    source_keys = [k for k in functions if k.startswith("__source_")]
    if source_keys and len(source_keys) == len(functions):
        scripting_score += 3

    # Check for web indicators
    web_keywords = ["http", "html", "flask", "express", "django", "cookie", "session", "csrf"]
    web_score = sum(1 for kw in web_keywords if kw in all_code or kw in all_strings)

    # Check for firmware indicators
    firmware_keywords = ["firmware", "bootloader", "u-boot", "busybox", "squashfs", "uart", "gpio", "spi", "i2c"]
    firmware_score = sum(1 for kw in firmware_keywords if kw in all_code or kw in all_strings)

    # Check for fuzzing-relevant indicators
    fuzzing_keywords = ["fuzz", "harness", "afl", "libfuzzer", "corpus", "mutation", "crash"]
    fuzzing_score = sum(1 for kw in fuzzing_keywords if kw in all_code or kw in all_strings)

    # Check for forensics indicators
    forensics_keywords = ["pcap", "wireshark", "capture", "packet", "forensic", "memory", "disk", "volatility", "tcpdump", "network"]
    forensics_score = sum(1 for kw in forensics_keywords if kw in all_code or kw in all_strings)
    # Boost if .pcap files present
    for name in challenge_files:
        if name.lower().endswith((".pcap", ".pcapng")):
            forensics_score += 3
            break

    # Check for steganography indicators
    steg_keywords = ["steganography", "stego", "hidden", "lsb", "pixel", "exif", "watermark", "embedded", "stegano"]
    steg_score = sum(1 for kw in steg_keywords if kw in all_code or kw in all_strings)
    # Boost if image files present without binary
    for name in challenge_files:
        if name.lower().endswith((".png", ".jpg", ".jpeg", ".bmp", ".gif", ".tiff")):
            steg_score += 2
            break

    scores = {
        "crypto": crypto_score,
        "constraint": constraint_score,
        "dynamic": dynamic_score,
        "keygen": 0,
        "pwn": pwn_score,
        "scripting": scripting_score,
        "web": web_score,
        "firmware": firmware_score,
        "fuzzing": fuzzing_score,
        "forensics": forensics_score,
        "steg": steg_score,
    }

    # Simple key reversal if there's a direct comparison
    if constraint_score > 0 and crypto_score == 0 and dynamic_score == 0 and pwn_score == 0:
        if any(kw in all_code for kw in ["== ", "!= ", "strcmp"]):
            scores["keygen"] = constraint_score + 1

    best = max(scores, key=scores.get)  # type: ignore[arg-type]
    total = max(sum(scores.values()), 1)

    # Build secondary types: any type with score > 0 that isn't the primary (#3)
    secondary = [
        t for t, s in sorted(scores.items(), key=lambda x: x[1], reverse=True)
        if s > 0 and t != best
    ]

    return ClassificationResult(
        challenge_type=best,  # type: ignore[arg-type]
        confidence=round(scores[best] / total, 2),
        reasoning=f"Heuristic fallback: highest keyword match for '{best}' ({scores[best]} indicators)",
        key_indicators=[kw for kw in (crypto_keywords + constraint_keywords + dynamic_keywords + pwn_keywords) if kw in all_code or kw in all_strings][:5],
        secondary_types=secondary,
    )


def route_from_classify(state: KrakenState) -> str:
    """Route to the appropriate specialist based on classification."""
    challenge_type = state.get("challenge_type", "constraint")
    route_map = {
        "constraint": "constraint_solver",
        "crypto": "crypto_decode",
        "dotnet": "dotnet_specialist",
        "dynamic": "dynamic_analysis",
        "keygen": "keygen",
        "pwn": "pwn_specialist",
        "fuzzing": "fuzzing_specialist",
        "scripting": "constraint_solver",  # scripting challenges route to constraint (generic analysis)
        "web": "web_specialist",
        "firmware": "firmware_specialist",
        "forensics": "crypto_decode",  # tools do the real work; crypto_decode handles misc analysis
        "steg": "crypto_decode",       # tools do the real work; crypto_decode handles misc analysis
    }
    return route_map.get(challenge_type, "constraint_solver")
