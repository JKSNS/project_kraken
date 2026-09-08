"""Fuzzing specialist -- harness generation and fuzzing strategy.

Identifies fuzzing targets from decompiled code and generates
AFL++/libFuzzer harness code. Deterministic target identification
combined with mid-tier LLM for harness generation.
"""
from __future__ import annotations

import json
import re

from kraken.state import KrakenState
from kraken.models import direct_generate
from kraken.config import ModelConfig
from kraken.logging.structured import get_logger

log = get_logger(__name__)


def _identify_fuzz_targets(
    functions: dict, binary_info: dict, strings: list[str]
) -> dict:
    """Deterministic identification of fuzzing targets and input surfaces."""
    targets: dict = {
        "input_functions": [],
        "parsing_functions": [],
        "dangerous_sinks": [],
        "file_io": [],
        "network_io": [],
        "protocol_hints": [],
        "complexity_score": 0,
    }

    all_code = " ".join(str(v) for v in functions.values())
    all_strings = " ".join(str(s) for s in strings)

    # Input functions -- where data enters
    input_funcs = {
        "read": "reads raw bytes from fd",
        "fread": "reads from FILE stream",
        "recv": "receives from socket",
        "recvfrom": "receives UDP datagram",
        "fgets": "reads line from FILE stream",
        "getline": "reads line with dynamic allocation",
        "scanf": "formatted input parsing",
        "gets": "unbounded line input",
        "getenv": "reads environment variable",
        "mmap": "memory-mapped file input",
    }
    for func, desc in input_funcs.items():
        if func in all_code:
            targets["input_functions"].append({"function": func, "description": desc})

    # Parsing functions -- where data is transformed
    parsing_funcs = {
        "strtol": "string to long conversion",
        "atoi": "string to int conversion",
        "sscanf": "formatted string parsing",
        "strtok": "string tokenization",
        "json_parse": "JSON parsing",
        "xml_parse": "XML parsing",
        "parse_header": "header parsing",
        "deserialize": "deserialization",
        "decode": "decoding operation",
        "uncompress": "decompression",
        "inflate": "zlib inflation",
    }
    for func, desc in parsing_funcs.items():
        if func in all_code.lower():
            targets["parsing_functions"].append({"function": func, "description": desc})

    # Dangerous sinks -- where crashes happen
    sinks = {
        "memcpy": "bounded memory copy",
        "memmove": "bounded memory move",
        "strcpy": "unbounded string copy",
        "strcat": "unbounded string concatenation",
        "sprintf": "unbounded formatted print",
        "malloc": "dynamic allocation (integer overflow?)",
        "realloc": "reallocation (size confusion?)",
        "free": "deallocation (double free? UAF?)",
    }
    for func, desc in sinks.items():
        if func in all_code:
            targets["dangerous_sinks"].append({"function": func, "risk": desc})

    # File I/O patterns
    file_funcs = ["fopen", "open", "creat", "fdopen", "freopen"]
    for func in file_funcs:
        if func in all_code:
            targets["file_io"].append(func)

    # Network I/O patterns
    net_funcs = ["socket", "bind", "listen", "accept", "connect", "send", "recv"]
    for func in net_funcs:
        if func in all_code:
            targets["network_io"].append(func)

    # Protocol hints from strings
    protocol_keywords = {
        "HTTP": ["HTTP/1", "GET ", "POST ", "Content-Type", "Host:"],
        "DNS": ["QUERY", "ANSWER", "CNAME", "A RECORD"],
        "SMTP": ["MAIL FROM", "RCPT TO", "HELO", "EHLO"],
        "FTP": ["USER ", "PASS ", "RETR ", "STOR "],
        "binary": ["magic", "header", "version", "length", "offset", "checksum"],
    }
    for proto, keywords in protocol_keywords.items():
        if any(kw.lower() in all_strings.lower() for kw in keywords):
            targets["protocol_hints"].append(proto)

    # Complexity score (higher = more fuzzing-worthy)
    targets["complexity_score"] = (
        len(targets["input_functions"]) * 2
        + len(targets["parsing_functions"]) * 3
        + len(targets["dangerous_sinks"]) * 2
        + len(targets["file_io"])
        + len(targets["network_io"]) * 2
    )

    # Identify the best entry point for fuzzing
    entry_candidates = []
    for fname, code in functions.items():
        code_str = str(code).lower()
        score = 0
        if any(f in code_str for f in ["read", "recv", "fread", "fgets", "scanf"]):
            score += 3
        if any(f in code_str for f in ["parse", "decode", "process", "handle"]):
            score += 2
        if any(f in code_str for f in ["memcpy", "strcpy", "sprintf"]):
            score += 1
        if score > 0:
            entry_candidates.append({"function": fname, "score": score})

    entry_candidates.sort(key=lambda x: x["score"], reverse=True)
    targets["entry_candidates"] = entry_candidates[:5]

    return targets


async def fuzzing_specialist(state: KrakenState) -> dict:
    """Analyze binary for fuzzing targets and generate harness strategy."""
    from kraken.storage.artifact_store import get_artifact
    functions = get_artifact(state, "decompiled_functions", "decompiled_functions_handle") or {}
    # Ensure values are strings (decompilers may return non-string types)
    functions = {k: str(v) for k, v in functions.items()}
    # Ensure strings list contains only strings (guard against dict elements)
    strings = [str(s) for s in (state.get("strings_of_interest", []) or [])]
    binary_info = state.get("binary_info", {}) or {}
    binary_path = state.get("challenge_path", "")

    log.info("fuzzing_specialist_start")

    # Deterministic target identification
    fuzz_targets = _identify_fuzz_targets(functions, binary_info, strings)

    # Build prompt for LLM harness strategy
    prompt = f"""Analyze this binary for fuzzing and generate a harness strategy.

## Binary Path: {binary_path}

## Binary Info
- Type: {binary_info.get('file_type', 'unknown')}
- Architecture: {binary_info.get('architecture', 'unknown')}

## Input Surface
- Input functions: {json.dumps(fuzz_targets['input_functions'], indent=2)}
- Parsing functions: {json.dumps(fuzz_targets['parsing_functions'], indent=2)}
- File I/O: {fuzz_targets['file_io']}
- Network I/O: {fuzz_targets['network_io']}

## Dangerous Sinks
{json.dumps(fuzz_targets['dangerous_sinks'], indent=2)}

## Protocol Hints: {fuzz_targets['protocol_hints']}

## Top Entry Candidates
{json.dumps(fuzz_targets['entry_candidates'], indent=2)}

## Key Functions (decompiled)
{json.dumps({{k: v[:1500] for k, v in list(functions.items())[:8]}}, indent=2)}

Generate a fuzzing strategy:
1. Which function(s) to target
2. What type of harness (AFL++ persistent mode, libFuzzer, stdin-based, file-based)
3. How to structure the harness (setup, fuzz target, teardown)
4. Seed corpus suggestions based on the input format
5. Dictionary entries for structured input fuzzing

Respond with JSON:
{{
    "harness_type": "afl_persistent|libfuzzer|stdin|file|network",
    "target_function": "function to fuzz",
    "input_format": "description of expected input format",
    "harness_approach": "step-by-step harness construction",
    "seed_corpus": ["example seed inputs"],
    "dictionary_entries": ["keyword1", "keyword2"],
    "mutation_hints": "what to mutate for maximum coverage",
    "crash_likelihood": "low|medium|high with reasoning"
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

    analysis["fuzz_targets"] = fuzz_targets

    log.info(
        "fuzzing_specialist_complete",
        complexity=fuzz_targets["complexity_score"],
        input_funcs=len(fuzz_targets["input_functions"]),
        sinks=len(fuzz_targets["dangerous_sinks"]),
        harness_type=analysis.get("harness_type", "unknown"),
    )

    # Build strategy summary
    parts = [f"Fuzzing: {analysis.get('harness_type', 'unknown')} harness"]
    if analysis.get("target_function"):
        parts.append(f"Target: {analysis['target_function']}")
    if analysis.get("input_format"):
        parts.append(f"Input: {analysis['input_format'][:80]}")
    if fuzz_targets["dangerous_sinks"]:
        parts.append(f"Sinks: {', '.join(s['function'] for s in fuzz_targets['dangerous_sinks'][:3])}")
    strategy = " | ".join(parts)

    # Merge with existing angr_results -- guard against non-dict state
    existing_angr = state.get("angr_results") or {}
    if not isinstance(existing_angr, dict):
        existing_angr = {}
    merged_angr = {**existing_angr, "fuzz_analysis": analysis}

    return {
        "strategy_hypothesis": strategy,
        "angr_results": merged_angr,
        "recent_actions": [{
            "action": "fuzzing_specialist",
            "reasoning": f"Fuzzing analysis: complexity={fuzz_targets['complexity_score']}",
            "result_summary": strategy,
        }],
        "iteration_count": state.get("iteration_count", 0) + 1,
    }
