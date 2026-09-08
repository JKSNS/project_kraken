"""Pwn specialist -- vulnerability identification and exploit prep (#11).

Handles buffer overflow, format string, ROP, and heap challenges.
Combines deterministic tool analysis with mid-tier LLM for strategy.
"""
from __future__ import annotations

import json
import re

from kraken.state import KrakenState
from kraken.models import direct_generate
from kraken.config import ModelConfig
from kraken.logging.structured import get_logger

log = get_logger(__name__)


def _analyze_vuln_indicators(binary_info: dict, functions: dict, strings: list[str]) -> dict:
    """Deterministic vulnerability indicator analysis."""
    indicators: dict = {
        "vuln_type": [],
        "dangerous_funcs": [],
        "protections": {},
        "gadget_hints": [],
        "stack_info": {},
    }

    # Extract protection status
    checksec = binary_info.get("checksec_pwntools", binary_info.get("checksec", {}))
    indicators["protections"] = checksec

    all_code = " ".join(str(v) for v in functions.values())
    all_code_lower = all_code.lower()

    # Dangerous function detection
    dangerous = {
        "gets": "stack buffer overflow (gets has no length check)",
        "scanf": "possible format string / buffer overflow (check format specifier)",
        "strcpy": "stack buffer overflow (no length check)",
        "strcat": "buffer overflow via concatenation",
        "sprintf": "buffer overflow (no length check on destination)",
        "vsprintf": "buffer overflow via va_args",
        "read": "possible overflow if length > buffer size",
        "recv": "possible overflow if length > buffer size",
        "memcpy": "overflow if src length > dst capacity",
    }
    for func, desc in dangerous.items():
        if func in all_code:
            indicators["dangerous_funcs"].append({"function": func, "risk": desc})

    # Vulnerability type inference
    imports = binary_info.get("imports", [])
    plt = binary_info.get("plt", {})
    got = binary_info.get("got", {})
    symbols = binary_info.get("symbols", {})

    # Buffer overflow indicators
    if any(f in all_code for f in ["gets", "strcpy", "sprintf"]):
        indicators["vuln_type"].append("buffer_overflow")
    if re.search(r"char\s+\w+\[\d+\]", all_code):
        # Extract buffer sizes
        for m in re.finditer(r"char\s+(\w+)\[(\d+)\]", all_code):
            indicators["stack_info"][m.group(1)] = int(m.group(2))

    # Format string indicators
    if any(f in all_code for f in ["printf(buf", "printf(input", "printf(argv"]):
        indicators["vuln_type"].append("format_string")
    if re.search(r"printf\s*\(\s*(?!\")", all_code):
        indicators["vuln_type"].append("format_string")

    # ROP indicators (NX enabled, no canary)
    if checksec.get("NX") and not checksec.get("Canary"):
        indicators["vuln_type"].append("rop_candidate")

    # ret2libc / ret2system indicators
    if "system" in str(plt) or "system" in str(got):
        indicators["gadget_hints"].append("system@plt available -- ret2system possible")
    if "/bin/sh" in " ".join(strings):
        indicators["gadget_hints"].append("/bin/sh string found in binary")
    if "execve" in str(plt):
        indicators["gadget_hints"].append("execve@plt available")

    # Heap indicators
    if any(f in all_code for f in ["malloc", "free", "calloc", "realloc"]):
        if "free" in all_code:
            indicators["vuln_type"].append("heap_candidate")
            if "use" in all_code_lower and "after" in all_code_lower and "free" in all_code_lower:
                indicators["vuln_type"].append("use_after_free")

    # GOT overwrite potential
    if not checksec.get("Full RELRO") and not checksec.get("RELRO", "").startswith("Full"):
        if got:
            indicators["gadget_hints"].append(
                f"Partial/No RELRO -- GOT overwrite possible. GOT entries: {list(got.keys())[:10]}"
            )

    # PIE status
    if not checksec.get("PIE"):
        indicators["gadget_hints"].append("No PIE -- addresses are static, no leak needed")
    else:
        indicators["gadget_hints"].append("PIE enabled -- need info leak for addresses")

    return indicators


async def pwn_specialist(state: KrakenState) -> dict:
    """Analyze binary for exploitable vulnerabilities and prepare exploit strategy."""
    from kraken.storage.artifact_store import get_artifact
    functions = get_artifact(state, "decompiled_functions", "decompiled_functions_handle")
    strings = state.get("strings_of_interest", [])
    binary_info = state.get("binary_info", {})
    binary_path = state.get("challenge_path", "")
    remote_info = state.get("remote_info", {})

    log.info("pwn_specialist_start")

    # Deterministic vulnerability analysis
    vuln_info = _analyze_vuln_indicators(binary_info, functions, strings)

    # Build prompt for LLM strategy
    prompt = f"""Analyze this CTF pwn challenge for exploitable vulnerabilities.

## Binary Path: {binary_path}
{"## Remote: " + remote_info.get("host", "") + ":" + str(remote_info.get("port", "")) if remote_info else ""}

## Protections
{json.dumps(vuln_info["protections"], indent=2)}

## Vulnerability Indicators
- Types detected: {vuln_info["vuln_type"]}
- Dangerous functions: {json.dumps(vuln_info["dangerous_funcs"], indent=2)}
- Stack buffers: {json.dumps(vuln_info["stack_info"], indent=2)}

## Gadget Hints
{chr(10).join("- " + h for h in vuln_info["gadget_hints"])}

## Decompiled Functions
{json.dumps({k: v[:2000] for k, v in list(functions.items())[:10]}, indent=2)}

## Strings
{json.dumps(strings[:20], indent=2)}

Identify:
1. The primary vulnerability (buffer overflow, format string, heap, etc.)
2. The attack vector (input method, overflow offset, target address)
3. Exploit strategy considering protections (NX → ROP, no canary → stack smash, etc.)
4. If remote: how to interact (pwntools remote())

Respond with JSON:
{{
    "vulnerability": "type of vulnerability",
    "attack_vector": "how to trigger it",
    "offset": "buffer offset to return address if applicable",
    "exploit_strategy": "step-by-step exploit approach",
    "key_addresses": {{"name": "address or 'needs leak'"}},
    "notes": "additional observations"
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

    # Merge vulnerability info into analysis
    analysis["vuln_indicators"] = vuln_info

    log.info(
        "pwn_specialist_complete",
        vuln_types=vuln_info["vuln_type"],
        dangerous_funcs=len(vuln_info["dangerous_funcs"]),
        vulnerability=analysis.get("vulnerability", "unknown"),
    )

    # Build strategy summary
    parts = [f"Pwn: {analysis.get('vulnerability', 'unknown')}"]
    if analysis.get("exploit_strategy"):
        parts.append(f"Strategy: {analysis['exploit_strategy'][:120]}")
    if analysis.get("offset"):
        parts.append(f"Offset: {analysis['offset']}")
    for hint in vuln_info["gadget_hints"][:3]:
        parts.append(hint)
    strategy = " | ".join(parts)

    return {
        "strategy_hypothesis": strategy,
        "angr_results": {
            **(state.get("angr_results", {})),
            "pwn_analysis": analysis,
        },
        "recent_actions": [{
            "action": "pwn_specialist",
            "reasoning": f"Pwn analysis: {analysis.get('vulnerability', 'unknown')}",
            "result_summary": strategy,
        }],
        "iteration_count": state.get("iteration_count", 0) + 1,
    }
