"""Dynamic analysis specialist -- orchestrates runtime analysis of binary.

Uses Python-native tools instead of GDB:
- subprocess_trace: Run binary and capture output
- multi_input_trace: Differential testing with multiple inputs
- angr_trace: Symbolic execution with multiple strategies
- lief_patch_binary: Patch anti-debug before running
- extract_encrypted_data: Extract embedded encrypted data
"""
from __future__ import annotations

from kraken.state import KrakenState
from kraken.tools.dynamic import (
    subprocess_trace,
    multi_input_trace,
    angr_trace,
    lief_patch_binary,
    extract_encrypted_data,
)
from kraken.logging.structured import get_logger

log = get_logger(__name__)


async def dynamic_analysis(state: KrakenState) -> dict:
    """Run dynamic analysis on the binary using Python-native tools.

    Steps:
    1. If anti-debug detected, patch binary first
    2. Run with multiple inputs to observe behavior
    3. Extract encrypted section data
    4. Run angr symbolic execution with string-based find/avoid
    """
    binary_path = state["challenge_path"]
    binary_info = state.get("binary_info", {})
    symbols = state.get("symbols", {})
    strings = state.get("strings_of_interest", [])

    log.info("dynamic_analysis_start")

    traces = []
    memory_dumps = {}
    analysis_binary = binary_path

    # Step 1: Patch anti-debug if detected
    anti_debug = binary_info.get("anti_debug_indicators", [])
    if anti_debug:
        log.info("dynamic_patching_anti_debug", indicators=anti_debug)
        patch_result = await lief_patch_binary(binary_path, nop_ptrace=True)
        if patch_result.success and patch_result.data:
            analysis_binary = patch_result.data.get("output_path", binary_path)
            traces.append({
                "type": "anti_debug_patch",
                "original": binary_path,
                "patched": analysis_binary,
                "patches_applied": patch_result.data.get("patches_applied", 0),
            })
            log.info("dynamic_patched", patches=patch_result.data.get("patches_applied", 0))

    # Step 2: Multi-input differential testing
    log.info("dynamic_multi_input_trace")
    multi_result = await multi_input_trace(analysis_binary, timeout=10)
    if multi_result.success and multi_result.data:
        input_traces = multi_result.data.get("traces", [])
        traces.append({
            "type": "multi_input_trace",
            "num_inputs": len(input_traces),
            "traces": input_traces,
        })

        # Analyze differences between inputs
        unique_outputs = set()
        for t in input_traces:
            out = t.get("stdout", "").strip()
            if out:
                unique_outputs.add(out[:200])
        if len(unique_outputs) > 1:
            log.info("dynamic_input_dependent", unique_outputs=len(unique_outputs))
    else:
        # Fallback: single basic run
        run_result = await subprocess_trace(analysis_binary, stdin_input="AAAA\n")
        traces.append({
            "type": "basic_run",
            "input": "AAAA",
            "stdout": run_result.data.get("stdout", "")[:500] if run_result.data else "",
            "stderr": run_result.data.get("stderr", "")[:500] if run_result.data else "",
            "exit_code": run_result.data.get("exit_code", -1) if run_result.data else -1,
        })

    # Step 3: Extract encrypted section data
    encrypted_result = await extract_encrypted_data(binary_path)
    if encrypted_result.success and encrypted_result.data:
        enc_data = encrypted_result.data
        if enc_data.get("custom_section_data") or enc_data.get("xor_candidates") or enc_data.get("crypto_constants"):
            traces.append({
                "type": "encrypted_data_extraction",
                "custom_sections": list(enc_data.get("custom_section_data", {}).keys()),
                "xor_candidates": enc_data.get("xor_candidates", []),
                "crypto_constants": enc_data.get("crypto_constants", []),
                "potential_keys": enc_data.get("rodata_keys", [])[:3],
            })

    # Step 4: Targeted angr exploration if we have string hints
    find_strings = []
    avoid_strings = []

    # Build find/avoid from strings of interest
    success_words = ["correct", "success", "flag", "win", "good", "congratul", "yes"]
    failure_words = ["wrong", "fail", "invalid", "bad", "incorrect", "try again", "nope"]

    for s in strings[:50]:
        s_lower = s.lower()
        if any(w in s_lower for w in success_words):
            find_strings.append(s)
        elif any(w in s_lower for w in failure_words):
            avoid_strings.append(s)

    if find_strings or avoid_strings:
        log.info("dynamic_angr_explore", find=find_strings[:3], avoid=avoid_strings[:3])
        angr_result = await angr_trace(
            analysis_binary,
            find_strings=find_strings[:5],
            avoid_strings=avoid_strings[:5],
            stdin_lengths=[32, 64],
            use_veritesting=True,
            timeout=120,
        )
        if angr_result.success and angr_result.data:
            traces.append({
                "type": "angr_symbolic_trace",
                "data": angr_result.data,
            })
            if angr_result.data.get("satisfiable"):
                log.info("dynamic_angr_found_solution")

    log.info("dynamic_analysis_complete", num_traces=len(traces))

    # Build actionable specialist summary
    summary_parts = []
    angr_found = False
    for t in traces:
        ttype = t.get("type", "")
        if ttype == "anti_debug_patch":
            summary_parts.append(f"Anti-debug patched → {t.get('patched', '')}")
        elif ttype == "multi_input_trace":
            input_traces = t.get("traces", [])
            outputs = set()
            for it in input_traces:
                out = it.get("stdout", "").strip()[:80]
                if out:
                    outputs.add(out)
            if len(outputs) > 1:
                summary_parts.append(f"Input-dependent behavior ({len(outputs)} unique outputs)")
            elif len(outputs) == 1:
                summary_parts.append(f"Input-independent: always outputs '{list(outputs)[0][:60]}'")
            else:
                summary_parts.append("No stdout from test runs")
        elif ttype == "angr_symbolic_trace" and t.get("data", {}).get("satisfiable"):
            angr_found = True
            summary_parts.append(f"angr found solution: {t['data'].get('solution_ascii', '')[:80]}")
        elif ttype == "encrypted_data_extraction":
            sects = t.get("custom_sections", [])
            xor = t.get("xor_candidates", [])
            if sects:
                summary_parts.append(f"Encrypted sections extracted: {', '.join(sects)}")
            if xor:
                summary_parts.append(f"XOR candidate: key={xor[0].get('key', '?')}")

    strategy = " | ".join(summary_parts) if summary_parts else f"Dynamic analysis: {len(traces)} traces collected"

    return {
        "dynamic_traces": traces,
        "strategy_hypothesis": strategy,
        "recent_actions": [{
            "action": "dynamic_analysis",
            "reasoning": "Python-native dynamic analysis (subprocess + multi-input + lief + angr)",
            "result_summary": strategy,
        }],
        "iteration_count": state.get("iteration_count", 0) + 1,
    }
