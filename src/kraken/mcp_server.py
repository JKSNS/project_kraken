"""Kraken MCP Server -- exposes deterministic RE tools to Claude Code via stdio.

30 tools: triage, decompile, extract_params, run_tool, run_tool_cascade,
validate_flag, run_script, timing_attack, remote_interact, c_rand_solve,
repair_elf, disassemble, full_solve, solve_report, retrospective, get_insights,
perf_stats, optimize_cascade, backfill_perf, pcap_extract, steg_extract,
pwn_exploit, record_failure, failure_stats, query_knowledge,
pwn_solve, web_exploit, docker_solve, gdb_solve, process_interact.
No LLM calls -- purely deterministic tooling.
"""
from __future__ import annotations

import os
import re
import shutil
import tempfile
import time
from pathlib import Path

from fastmcp import FastMCP

mcp = FastMCP(
    "kraken",
    instructions=(
        "Kraken reverse-engineering toolkit. Provides deterministic binary analysis, "
        "decompilation, tool cascades, and flag validation for CTF challenges. "
        "Use kraken_full_solve for one-shot end-to-end solving. "
        "Manual workflow: triage → decompile → extract_params → run_tool_cascade → validate_flag."
    ),
)


def _err(tool: str, exc: Exception) -> dict:
    """Standard error envelope -- the server never crashes from a tool invocation."""
    return {"error": str(exc), "error_type": type(exc).__name__, "tool": tool}


# ── Tool 1: Triage ──────────────────────────────────────────────────────────


@mcp.tool()
async def kraken_triage(
    challenge_path: str,
    flag_format: str = r"flag\{[a-zA-Z0-9_]+\}",
    challenge_description: str = "",
) -> dict:
    """Triage a CTF challenge: detect binary type, extract strings, symbols, and metadata.

    Detects ELF/PE/Mach-O binaries (including corrupted ELF with near-miss magic),
    .NET assemblies, Python bytecode, Office macros. Extracts encoding hints,
    anti-debug indicators, and remote server info from descriptions/docker-compose.

    Args:
        challenge_path: Path to challenge binary or directory containing challenge files.
        flag_format: Regex pattern for the expected flag format.
        challenge_description: Optional challenge description text (for remote server detection).
            If not provided, triage auto-reads description.txt/readme.md from the challenge directory.

    Returns dict with: binary_info (includes corruption_detected, encoding_hints),
    strings_of_interest, symbols, challenge_files, remote_info,
    challenge_path (resolved if directory was given).
    """
    try:
        from kraken.state import initial_state
        from kraken.nodes.triage import triage

        state = initial_state(
            challenge_id="mcp",
            challenge_path=challenge_path,
            flag_format=flag_format,
        )
        if challenge_description:
            state["challenge_description"] = challenge_description
        result = await triage(state)
        return {
            "binary_info": result.get("binary_info", {}),
            "strings_of_interest": result.get("strings_of_interest", []),
            "symbols": result.get("symbols", {}),
            "challenge_files": result.get("challenge_files", {}),
            "remote_info": result.get("remote_info", {}),
            "challenge_path": result.get("challenge_path", challenge_path),
        }
    except Exception as exc:
        return _err("kraken_triage", exc)


# ── Tool 2: Decompile ───────────────────────────────────────────────────────


@mcp.tool()
async def kraken_decompile(
    challenge_path: str,
    workspace: str = "",
    flag_format: str = r"flag\{[a-zA-Z0-9_]+\}",
) -> dict:
    """Decompile a challenge binary using Ghidra, capstone, or language-specific decompilers.

    Falls back to capstone disassembly if Ghidra is unavailable. Handles .NET (ilspycmd),
    Python bytecode (.pyc), and VBA macros automatically. Validates Ghidra path accessibility
    and falls back to alternate installations if the configured path is inaccessible.

    Args:
        challenge_path: Path to challenge binary or directory.
        workspace: Optional workspace directory for storing decompilation artifacts.
        flag_format: Regex pattern for the expected flag format.

    Returns dict with: decompiled_functions (name -> source), call_graph.
    """
    try:
        from kraken.state import initial_state
        from kraken.nodes.decompile import decompile

        state = initial_state(
            challenge_id="mcp",
            challenge_path=challenge_path,
            flag_format=flag_format,
            solve_workspace=workspace,
        )
        result = await decompile(state)
        return {
            "decompiled_functions": result.get("decompiled_functions", {}),
            "call_graph": result.get("call_graph", {}),
        }
    except Exception as exc:
        return _err("kraken_decompile", exc)


# ── Tool 3: Extract Parameters ──────────────────────────────────────────────


@mcp.tool()
def kraken_extract_params(
    decompiled_functions: dict,
    strings: list[str],
    binary_info: dict,
) -> dict:
    """Extract solve parameters from decompiled code or assembly using regex/heuristics (no LLM).

    Handles both C source (from Ghidra) and assembly (from objdump/capstone).
    Detects srand/rand in assembly via 'call srand@plt' patterns and extracts
    seeds from 'mov edi/rdi, <value>' instructions (AT&T and Intel syntax).

    Args:
        decompiled_functions: Mapping of function name -> decompiled C source or assembly.
        strings: List of strings extracted from the binary (from triage).
        binary_info: Binary metadata dict (from triage).

    Returns dict with: input_mode, input_length, success_string, fail_string,
    flag_format_prefix, key_constants, has_strcmp, comparison_target,
    loop_bound, crypto_indicators, uses_random, random_seed,
    timing_indicator, charset_range.
    """
    try:
        from kraken.tools.param_extractor import extract_solve_params

        return extract_solve_params(decompiled_functions, strings, binary_info)
    except Exception as exc:
        return _err("kraken_extract_params", exc)


# ── Tool 4: Run Single Tool ─────────────────────────────────────────────────


@mcp.tool()
async def kraken_run_tool(
    tool_name: str,
    challenge_path: str,
    flag_format: str = r"flag\{[a-zA-Z0-9_]+\}",
    extra_args: dict | None = None,
    timeout: int = 60,
) -> dict:
    """Run a single kraken helper tool by name.

    Available tools: auto_angr, auto_regex_z3, auto_gdb_cmp, auto_c_brute,
    auto_xor_brute, auto_crypto, auto_c_source_eval, auto_qr_decode,
    auto_maze_solver, auto_archive_search, auto_git_extract, auto_source_decode,
    auto_constraint_extract, auto_run_static, auto_python_reverse,
    auto_table_reverse, auto_ec_vigenere, auto_normalize, auto_patcher, auto_c_rand,
    auto_pcap_extract, auto_steg_extract, auto_pwn_template.

    Args:
        tool_name: Name of the helper tool (e.g. "auto_angr").
        challenge_path: Path to challenge binary or directory.
        flag_format: Regex pattern for the expected flag format.
        extra_args: Optional dict of extra parameters for command building
                    (e.g. {"success_string": "Correct!", "input_length": 32}).
        timeout: Max execution time in seconds.

    Returns dict with: tool, command, exit_code, stdout, stderr, flag_found, flag.
    """
    try:
        from kraken.state import initial_state
        from kraken.nodes.tool_router import _build_tool_command, _run_tool, _check_for_flag

        state = initial_state(
            challenge_id="mcp",
            challenge_path=challenge_path,
            flag_format=flag_format,
        )
        params = extra_args or {}

        cmd = _build_tool_command(tool_name, params, state)
        if not cmd:
            # Fallback: direct invocation of helper script
            helpers_dir = Path(__file__).resolve().parent / "helpers"
            script = helpers_dir / f"{tool_name}.py"
            if script.exists():
                cmd = f'python3 "{script}" "{Path(challenge_path).resolve()}"'
            else:
                return {
                    "tool": tool_name,
                    "error": f"Cannot build command for '{tool_name}' with given parameters and no helper script found at {script}",
                    "error_type": "CommandBuildError",
                }

        cwd = state.get("challenge_dir")
        result = await _run_tool(cmd, cwd, timeout)

        combined = result["stdout"] + "\n" + result["stderr"]
        flag = _check_for_flag(combined, flag_format)

        return {
            "tool": tool_name,
            "command": cmd,
            "exit_code": result["exit_code"],
            "stdout": result["stdout"],
            "stderr": result["stderr"],
            "flag_found": flag is not None,
            "flag": flag or "",
        }
    except Exception as exc:
        return _err("kraken_run_tool", exc)


# ── Tool 5: Run Tool Cascade ────────────────────────────────────────────────


@mcp.tool()
async def kraken_run_tool_cascade(
    challenge_path: str,
    challenge_type: str = "",
    flag_format: str = r"flag\{[a-zA-Z0-9_]+\}",
    extracted_params: dict | None = None,
    triage_result: dict | None = None,
    decompile_result: dict | None = None,
) -> dict:
    """Run the full deterministic tool cascade for a challenge.

    Runs universal tools first (source decode, constraint extract, static run, etc.),
    then type-specific tools (including auto_c_rand for crypto/keygen challenges when
    srand seed is detected, auto_pcap_extract for forensics/network, auto_steg_extract
    for steganography/image forensics, and auto_pwn_template for pwn/exploitation).
    Stops on first valid flag found. Rejects garbled/low-diversity flag bodies from
    prefix-wrap detection.

    For best results, pass triage_result and decompile_result from prior tool calls.

    Args:
        challenge_path: Path to challenge binary or directory.
        challenge_type: Challenge type hint (constraint, crypto, dynamic, keygen, pwn).
        flag_format: Regex pattern for the expected flag format.
        extracted_params: Optional pre-extracted solve parameters (from kraken_extract_params).
        triage_result: Optional output from kraken_triage to enrich tool commands.
        decompile_result: Optional output from kraken_decompile to enrich tool commands.

    Returns dict with: tools_run, tool_results, flag_found, flag, tool_results_summary.
    """
    try:
        from kraken.state import initial_state
        from kraken.nodes.tool_router import tool_router

        state = initial_state(
            challenge_id="mcp",
            challenge_path=challenge_path,
            flag_format=flag_format,
        )

        if challenge_type:
            state["challenge_type"] = challenge_type
        if extracted_params:
            state["extracted_params"] = extracted_params
        if triage_result:
            for key in ("binary_info", "strings_of_interest", "symbols",
                        "challenge_files", "remote_info"):
                if key in triage_result:
                    state[key] = triage_result[key]
            if "challenge_path" in triage_result:
                state["challenge_path"] = triage_result["challenge_path"]
        if decompile_result:
            for key in ("decompiled_functions", "call_graph"):
                if key in decompile_result:
                    state[key] = decompile_result[key]

        result = await tool_router(state)

        tool_results = result.get("tool_cascade_results", [])
        flag = result.get("tool_flag_candidate", "")

        return {
            "tools_run": len(tool_results),
            "tool_results": tool_results,
            "flag_found": bool(flag),
            "flag": flag,
            "tool_results_summary": result.get("tool_results_summary", ""),
        }
    except Exception as exc:
        return _err("kraken_run_tool_cascade", exc)


# ── Tool 6: Validate Flag ───────────────────────────────────────────────────


@mcp.tool()
async def kraken_validate_flag(
    candidate: str,
    flag_format: str = r"flag\{[a-zA-Z0-9_]+\}",
    binary_path: str = "",
) -> dict:
    """Validate a flag candidate against format checks and optional binary verification.

    Checks: printable characters, character diversity, format match, and optionally
    runs the challenge binary with the candidate as input to see if it's accepted.

    Args:
        candidate: The flag candidate string to validate.
        flag_format: Regex pattern for the expected flag format.
        binary_path: Optional path to challenge binary for runtime verification.

    Returns dict with: valid, checks, binary_verification, rejection_reason.
    """
    try:
        from kraken.nodes.flag_validator import (
            _is_likely_printable_flag,
            _is_suspicious_low_diversity_flag,
            _normalized_flag_pattern,
            _verify_flag_with_binary,
        )

        pattern = _normalized_flag_pattern(flag_format)

        checks = {
            "printable": _is_likely_printable_flag(candidate),
            "low_diversity": _is_suspicious_low_diversity_flag(candidate),
            "format_match": bool(re.search(pattern, candidate)),
        }

        rejection_reason = ""
        if not checks["printable"]:
            rejection_reason = "contains non-printable characters"
        elif checks["low_diversity"]:
            rejection_reason = "low character diversity (likely guessed, not computed)"
        elif not checks["format_match"]:
            rejection_reason = f"does not match flag format: {flag_format}"

        binary_verification = None
        if binary_path and not rejection_reason:
            binary_verification = await _verify_flag_with_binary(binary_path, candidate)
            if binary_verification is False:
                rejection_reason = "binary explicitly rejected the flag"

        return {
            "valid": not rejection_reason,
            "checks": checks,
            "binary_verification": binary_verification,
            "rejection_reason": rejection_reason,
        }
    except Exception as exc:
        return _err("kraken_validate_flag", exc)


# ── Tool 7: Run Script ──────────────────────────────────────────────────────


@mcp.tool()
async def kraken_run_script(
    code: str,
    challenge_dir: str,
    timeout: int = 30,
) -> dict:
    """Execute a Python script in the context of a challenge directory.

    Writes the code to a temp file and runs it with python3. Useful for running
    custom solve scripts that need access to challenge files.

    Args:
        code: Python source code to execute.
        challenge_dir: Working directory for execution (so scripts can access challenge files).
        timeout: Max execution time in seconds.

    Returns dict with: exit_code, stdout, stderr.
    """
    try:
        from kraken.tools.script_executor import execute_script

        result = await execute_script(code, timeout=timeout, cwd=challenge_dir)
        return {
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr or result.error,
        }
    except Exception as exc:
        return _err("kraken_run_script", exc)


# ── Tool 8: Timing Attack ────────────────────────────────────────────────────


@mcp.tool()
async def kraken_timing_attack(
    host: str,
    port: int,
    prefix: str = "flag{",
    suffix: str = "}",
    charset: str = "alphanum_under",
    body_length: int = 14,
    timeout_per_char: float = 5.0,
    concurrency: int = 0,
    flag_format: str = r"flag\{[a-zA-Z0-9_]+\}",
    no_banner: bool = True,
    no_newline: bool = True,
) -> dict:
    """Run a timing side-channel attack against a remote TCP service.

    Brute-forces a secret character-by-character by measuring response time
    deltas. Designed for CTF challenges where the server leaks information
    via sleep()/usleep() per correct character.

    Args:
        host: Target hostname or IP.
        port: Target port number.
        prefix: Known flag prefix (e.g. "vere{").
        suffix: Known flag suffix (e.g. "}").
        charset: Charset name (lowercase, uppercase, alpha, alphanum, hex, printable) or literal chars.
        body_length: Number of unknown chars between prefix and suffix.
        timeout_per_char: Timeout per probe in seconds.
        concurrency: Number of concurrent probes (set 1 for sequential).
        flag_format: Flag format regex.
        no_banner: Skip waiting for server banner (default True for timing attacks).
        no_newline: Don't append newline to payload -- raw bytes mode (default True).

    Returns dict with: flag_found, flag, stdout, stderr, elapsed_seconds.
    """
    try:
        from kraken.nodes.tool_router import _run_tool

        helpers_dir = str(Path(__file__).resolve().parent / "helpers")
        cmd = (
            f'python3 {helpers_dir}/auto_timing_attack.py'
            f' --host "{host}" --port {port}'
            f' --prefix "{prefix}" --suffix "{suffix}"'
            f' --charset "{charset}" --body-length {body_length}'
            f' --timeout-per-char {timeout_per_char}'
            f' --concurrency {concurrency}'
            f' --flag-format "{flag_format}"'
        )
        if no_banner:
            cmd += ' --no-banner'
        if no_newline:
            cmd += ' --no-newline'

        t0 = time.monotonic()
        total_timeout = int(body_length * timeout_per_char * 2) + 60
        result = await _run_tool(cmd, None, total_timeout)
        elapsed = time.monotonic() - t0

        flag = None
        marker = re.search(r"EXTRACTED FLAG:\s*(.+)", result["stdout"])
        if marker:
            flag = marker.group(1).strip()

        return {
            "flag_found": flag is not None,
            "flag": flag or "",
            "stdout": result["stdout"],
            "stderr": result["stderr"],
            "elapsed_seconds": round(elapsed, 1),
        }
    except Exception as exc:
        return _err("kraken_timing_attack", exc)


# ── Tool 9: Remote Interact ─────────────────────────────────────────────────


@mcp.tool()
async def kraken_remote_interact(
    host: str,
    port: int,
    send_data: list[str] | None = None,
    expect_patterns: list[str] | None = None,
    timeout: float = 10.0,
    flag_format: str = r"flag\{[a-zA-Z0-9_]+\}",
) -> dict:
    """Connect to a remote TCP service, exchange data, and search for flags.

    General-purpose tool for interacting with network services in CTF
    challenges. Reads banner, sends data, and extracts flags from transcript.

    Args:
        host: Target hostname or IP.
        port: Target port number.
        send_data: List of strings to send (supports \\n escapes).
        expect_patterns: List of regex patterns to match in transcript.
        timeout: Timeout per recv in seconds.
        flag_format: Flag format regex.

    Returns dict with: transcript, flag_found, flag.
    """
    try:
        from kraken.nodes.tool_router import _run_tool

        helpers_dir = str(Path(__file__).resolve().parent / "helpers")
        cmd = f'python3 {helpers_dir}/auto_remote_interact.py --host "{host}" --port {port}'
        cmd += f' --timeout {timeout}'
        cmd += f' --flag-format "{flag_format}"'

        for s in (send_data or []):
            cmd += f' --send "{s}"'
        for p in (expect_patterns or []):
            cmd += f' --expect "{p}"'

        total_timeout = int(timeout * max(len(send_data or []), 1) * 2) + 30
        result = await _run_tool(cmd, None, total_timeout)

        flag = None
        marker = re.search(r"EXTRACTED FLAG:\s*(.+)", result["stdout"])
        if marker:
            flag = marker.group(1).strip()

        return {
            "transcript": result["stdout"],
            "flag_found": flag is not None,
            "flag": flag or "",
        }
    except Exception as exc:
        return _err("kraken_remote_interact", exc)


# ── Tool 10: C-PRNG Solve ────────────────────────────────────────────────────


@mcp.tool()
async def kraken_c_rand_solve(
    seed: int,
    count: int = 50,
    binary_path: str = "",
    prefix: str = "",
    timeout: int = 30,
) -> dict:
    """Generate C rand() sequence and optionally solve XOR-encrypted flags.

    Compiles and runs a small C program that calls srand(seed) then rand()
    `count` times. If a binary is provided, extracts expected int32 arrays
    from its data sections and tries XOR reversal to recover the flag.

    Args:
        seed: Integer seed for srand() (e.g. 0x13337).
        count: Number of rand() values to generate.
        binary_path: Optional path to challenge binary for XOR solve.
        prefix: Expected flag prefix for validation (e.g. "vere{").
        timeout: Max execution time in seconds.

    Returns dict with: flag_found, flag, stdout, stderr.
    """
    try:
        from kraken.nodes.tool_router import _run_tool

        helpers_dir = str(Path(__file__).resolve().parent / "helpers")
        cmd = f'python3 {helpers_dir}/auto_c_rand.py --seed {seed} --count {count}'
        if binary_path:
            cmd += f' --binary "{binary_path}"'
        if prefix:
            cmd += f' --prefix "{prefix}"'

        result = await _run_tool(cmd, None, timeout)

        flag = None
        marker = re.search(r"EXTRACTED FLAG:\s*(.+)", result["stdout"])
        if marker:
            flag = marker.group(1).strip()

        return {
            "flag_found": flag is not None,
            "flag": flag or "",
            "stdout": result["stdout"],
            "stderr": result["stderr"],
        }
    except Exception as exc:
        return _err("kraken_c_rand_solve", exc)


# ── Tool 11: Repair Corrupted ELF ────────────────────────────────────────────


@mcp.tool()
async def kraken_repair_elf(
    binary_path: str,
    auto_repair: bool = False,
) -> dict:
    """Detect and optionally repair ELF corruption in a binary.

    Checks the magic bytes for near-miss ELF signatures (e.g., corrupted first
    byte where header[1:4] == b"ELF" but byte 0 != 0x7f). When auto_repair is
    True, patches the magic byte and returns the path to a fixed copy.

    Args:
        binary_path: Path to potentially corrupted binary.
        auto_repair: If True, create a repaired copy with the magic byte fixed.

    Returns dict with: is_elf, corrupted, corruption_details, magic_bytes,
    repaired_path (only when auto_repair=True and corruption found).
    """
    try:
        p = Path(binary_path)
        if not p.exists():
            return {"error": f"File not found: {binary_path}"}

        with open(binary_path, "rb") as f:
            header = f.read(64)

        magic = header[:4]
        is_elf = magic == b"\x7fELF"
        corrupted = False
        details = []
        repaired_path = ""

        if not is_elf and header[1:4] == b"ELF":
            corrupted = True
            details.append(
                f"Near-miss ELF: byte 0 is 0x{header[0]:02x} "
                f"(expected 0x7f, XOR diff: 0x{header[0] ^ 0x7f:02x})"
            )
            is_elf = True

            if auto_repair:
                with open(binary_path, "rb") as f:
                    data = bytearray(f.read())
                data[0] = 0x7F
                fd, repaired_path = tempfile.mkstemp(suffix="_repaired")
                with os.fdopen(fd, "wb") as f:
                    f.write(data)
                os.chmod(repaired_path, 0o755)
                details.append(f"Repaired magic byte → saved to {repaired_path}")

        return {
            "is_elf": is_elf,
            "corrupted": corrupted,
            "corruption_details": details,
            "magic_bytes": header[:4].hex(),
            "repaired_path": repaired_path,
        }
    except Exception as exc:
        return _err("kraken_repair_elf", exc)


# ── Tool 12: Disassemble ─────────────────────────────────────────────────────


@mcp.tool()
async def kraken_disassemble(
    binary_path: str,
) -> dict:
    """Disassemble a binary using pyelftools + capstone (no Ghidra needed).

    Produces per-function assembly listings from ELF binaries. Useful when
    Ghidra is unavailable or when you need raw assembly (e.g., to detect
    srand/rand patterns in disassembly output).

    Args:
        binary_path: Path to ELF binary.

    Returns dict with: functions (name -> assembly), sections, entry_point.
    """
    try:
        from kraken.tools.disasm import disassemble_elf

        result = await disassemble_elf(binary_path)
        if result.success and isinstance(result.data, dict):
            return {
                "functions": result.data.get("functions", {}),
                "sections": result.data.get("sections", []),
                "entry_point": result.data.get("entry_point", ""),
            }
        return {
            "functions": {},
            "error": result.error or "Disassembly failed",
        }
    except Exception as exc:
        return _err("kraken_disassemble", exc)


# ── Tool 13: Full Solve ──────────────────────────────────────────────────────


@mcp.tool()
async def kraken_full_solve(
    challenge_path: str,
    flag_format: str = r"flag\{[a-zA-Z0-9_]+\}",
    challenge_description: str = "",
    challenge_type: str = "",
    save_session: bool = False,
    output_dir: str = "",
) -> dict:
    """One-shot end-to-end solve: triage → decompile → extract_params → cascade → validate.

    Runs the complete deterministic pipeline in a single call. Returns the flag
    if found, along with detailed results from each stage and a full SolveSession
    with per-step timing and artifact capture.

    Args:
        challenge_path: Path to challenge binary or directory.
        flag_format: Regex pattern for the expected flag format.
        challenge_description: Optional description text (for remote server detection).
        challenge_type: Optional type hint (constraint, crypto, dynamic, keygen, pwn).
        save_session: If True, persist session artifacts to output_dir.
        output_dir: Directory to save session artifacts. Defaults to solves/{challenge_id}/.

    Returns dict with: flag_found, flag, solving_tool, elapsed_seconds,
    triage_summary, decompile_summary, params, cascade_summary, session.
    """
    try:
        from kraken.state import initial_state
        from kraken.nodes.triage import triage
        from kraken.nodes.decompile import decompile
        from kraken.tools.param_extractor import extract_solve_params
        from kraken.nodes.tool_router import tool_router
        from kraken.storage.artifact_store import get_artifact
        from kraken.execution.solve_session import SolveSession

        challenge_id = Path(challenge_path).resolve().name
        session = SolveSession(
            challenge_id=challenge_id,
            challenge_path=str(Path(challenge_path).resolve()),
        )

        # Step 1: Triage
        state = initial_state(
            challenge_id="mcp",
            challenge_path=challenge_path,
            flag_format=flag_format,
        )
        if challenge_description:
            state["challenge_description"] = challenge_description

        t0 = time.monotonic()
        triage_result = await triage(state)
        session.add_step(
            "triage",
            f"challenge_path={challenge_path}",
            triage_result,
            time.monotonic() - t0,
        )
        session.triage_result = triage_result
        state.update(triage_result)

        binary_info = triage_result.get("binary_info", {})
        strings = triage_result.get("strings_of_interest", [])
        triage_summary = (
            f"type={binary_info.get('file_type', 'unknown')[:60]}, "
            f"strings={len(strings)}, "
            f"corrupted={binary_info.get('corruption_detected', False)}"
        )

        # Step 2: Decompile
        t0 = time.monotonic()
        decompile_result = await decompile(state)
        session.add_step(
            "decompile",
            f"binary={state.get('challenge_path', challenge_path)}",
            decompile_result,
            time.monotonic() - t0,
        )
        session.decompile_result = decompile_result
        state.update(decompile_result)

        functions = get_artifact(
            state, "decompiled_functions", "decompiled_functions_handle"
        )
        decompile_summary = f"functions={len(functions)}"

        # Step 3: Extract params
        t0 = time.monotonic()
        params = extract_solve_params(functions, strings, binary_info)
        session.add_step(
            "extract_params",
            f"functions={len(functions)}, strings={len(strings)}",
            params,
            time.monotonic() - t0,
        )
        session.extracted_params = params
        state["extracted_params"] = params

        # Step 3b: Classify challenge type (critical for correct tool selection)
        if challenge_type:
            state["challenge_type"] = challenge_type
        else:
            t0 = time.monotonic()
            try:
                from kraken.nodes.classify import classify
                classify_result = await classify(state)
                state.update(classify_result)
                session.add_step(
                    "classify",
                    f"binary_info={bool(binary_info)}, functions={len(functions)}",
                    classify_result,
                    time.monotonic() - t0,
                )
            except Exception:
                pass  # Non-fatal: cascade will use default tools

        # Step 4: Tool cascade
        t0 = time.monotonic()
        cascade_result = await tool_router(state)
        cascade_elapsed = time.monotonic() - t0
        session.add_step(
            "tool_cascade",
            f"type={challenge_type or 'auto'}, tools_queued=*",
            cascade_result,
            cascade_elapsed,
        )
        session.cascade_results = cascade_result.get("tool_cascade_results", [])
        state.update(cascade_result)

        flag = cascade_result.get("tool_flag_candidate", "")
        tools_run = len(cascade_result.get("tool_cascade_results", []))
        solving_tool = ""
        if flag:
            for r in cascade_result.get("tool_cascade_results", []):
                if r.get("tool"):
                    solving_tool = r["tool"]

        session.flag = flag
        session.solved = bool(flag)
        session.solving_tool = solving_tool
        session.finalize()

        # Persist if requested
        session_path = ""
        if save_session:
            dest = Path(output_dir) if output_dir else Path("solves") / challenge_id
            session.save(dest)
            session_path = str(dest / "session.json")

        # Auto-log retrospective
        try:
            _append_retrospective(session.to_dict(), notes="auto")
        except Exception:
            pass  # Non-fatal: don't fail solve if retrospective logging has issues

        # Auto-update performance DB and re-optimize cascade
        try:
            from kraken.execution.optimizer import PerformanceDB, optimize
            perf_db = PerformanceDB()
            perf_db.record_solve(session.to_dict())
            optimize(perf_db=perf_db)
        except Exception:
            pass  # Non-fatal: don't fail solve if optimizer has issues

        # Auto-classify failure when solve fails
        failure_classification = ""
        if not flag:
            try:
                from kraken.execution.optimizer import FailureDB, classify_failure
                cascade_results_list = cascade_result.get("tool_cascade_results", [])
                failure_classification = classify_failure(
                    cascade_results=cascade_results_list,
                    elapsed=session.total_elapsed,
                )
                # Determine challenge type for the failure record
                fail_challenge_type = (
                    challenge_type
                    or params.get("challenge_type", "")
                    or "unknown"
                )
                tools_tried_list = [
                    r.get("tool", "") for r in cascade_results_list if r.get("tool")
                ]
                fdb = FailureDB()
                fdb.record_failure(
                    challenge_id=challenge_id,
                    challenge_type=fail_challenge_type,
                    failure_type=failure_classification,
                    details=f"Auto-classified from full_solve cascade ({tools_run} tools run)",
                    tools_tried=tools_tried_list,
                )
            except Exception:
                pass  # Non-fatal

        return {
            "flag_found": bool(flag),
            "flag": flag,
            "solving_tool": solving_tool,
            "elapsed_seconds": round(session.total_elapsed, 1),
            "triage_summary": triage_summary,
            "decompile_summary": decompile_summary,
            "params": params,
            "cascade_summary": f"tools_run={tools_run}",
            "remote_info": triage_result.get("remote_info", {}),
            "session": session.to_dict(),
            "session_path": session_path,
            "failure_classification": failure_classification,
        }
    except Exception as exc:
        return _err("kraken_full_solve", exc)


# ── Tool 14: Solve Report ─────────────────────────────────────────────────


@mcp.tool()
def kraken_solve_report(
    session_path: str,
    format: str = "writeup",
) -> dict:
    """Generate a post-solve report from a saved SolveSession.

    Reads a session.json file and produces formatted output showing what happened
    during the solve: timing, decision points, tool results, and outcomes.

    Args:
        session_path: Path to a session.json file (from kraken_full_solve with save_session=True).
        format: Report format -- "writeup", "analysis", "mindmap", or "timeline".

    Returns dict with: format, report (markdown string), session_id.
    """
    try:
        from kraken.execution.solve_session import SolveSession
        from kraken.reporting.generator import generate_report

        session = SolveSession.load(Path(session_path))
        report = generate_report(session.to_dict(), mode=format)

        return {
            "format": format,
            "report": report,
            "session_id": session.session_id,
        }
    except Exception as exc:
        return _err("kraken_solve_report", exc)


# ── Retrospective Helpers ─────────────────────────────────────────────────────

_RETROSPECTIVE_PATH = Path("solves/RETROSPECTIVE.md")


def _append_retrospective(session: dict, notes: str = "") -> str:
    """Analyze a session dict and append a structured entry to RETROSPECTIVE.md.

    Returns the markdown entry that was appended.
    """
    from datetime import datetime, timezone

    challenge_id = session.get("challenge_id", "unknown")
    solved = session.get("solved", False)
    flag = session.get("flag", "")
    solving_tool = session.get("solving_tool", "")
    total_elapsed = session.get("total_elapsed", 0)
    steps = session.get("steps", [])
    cascade_results = session.get("cascade_results", [])
    params = session.get("extracted_params", {})
    challenge_type = params.get("challenge_type", "unknown")

    # Determine challenge type from params or triage
    triage = session.get("triage_result", {})
    if challenge_type == "unknown":
        binary_info = triage.get("binary_info", {})
        challenge_type = binary_info.get("file_type", "unknown")[:30]

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    status = "solved" if solved else "failed"

    # Analyze tools
    tools_tried = []
    tool_timings = []
    for r in cascade_results:
        tool_name = r.get("tool", "")
        if tool_name:
            tools_tried.append(tool_name)
            elapsed = r.get("elapsed_seconds", r.get("elapsed", 0))
            if elapsed:
                tool_timings.append((tool_name, elapsed))

    total_tools = len(tools_tried)

    # Identify bottlenecks (steps > 30s)
    bottlenecks = []
    for step in steps:
        step_elapsed = step.get("elapsed_seconds", 0)
        if step_elapsed > 30:
            bottlenecks.append(f"{step.get('name', '?')} ({step_elapsed:.1f}s)")

    for tool_name, elapsed in tool_timings:
        if elapsed > 30:
            bottlenecks.append(f"{tool_name} ({elapsed:.1f}s)")

    # Near-misses: flags found but rejected (tools that found a flag but it wasn't the solving tool)
    near_misses = []
    for r in cascade_results:
        tool_name = r.get("tool", "")
        output = r.get("output_snapshot", r)
        stdout = output.get("stdout", "") if isinstance(output, dict) else ""
        if "flag{" in stdout.lower() and tool_name != solving_tool:
            near_misses.append(tool_name)

    # Build shortcomings
    shortcomings = []
    if not solved:
        shortcomings.append("No tool in the cascade found a valid flag")
    if bottlenecks:
        shortcomings.append(f"Slow steps: {', '.join(bottlenecks)}")
    if near_misses:
        shortcomings.append(f"Near-miss flags rejected from: {', '.join(near_misses)}")

    # Build entry
    entry_lines = [
        f"### {challenge_id} ({challenge_type}) -- {status} [{timestamp}]",
        f"- **Flag**: {flag or 'NOT FOUND'}",
    ]
    if solving_tool:
        entry_lines.append(f"- **Solving tool**: {solving_tool} (elapsed: {total_elapsed:.1f}s total)")
    entry_lines.append(
        f"- **Tools tried**: {total_tools} ({', '.join(tools_tried[:10]) or 'none'})"
    )
    if bottlenecks:
        entry_lines.append(f"- **Bottleneck**: {', '.join(bottlenecks)}")
    if shortcomings:
        entry_lines.append(f"- **Shortcomings**: {'; '.join(shortcomings)}")
    if notes:
        entry_lines.append(f"- **Notes**: {notes}")

    entry = "\n".join(entry_lines) + "\n"

    # Append to file
    retro_path = _RETROSPECTIVE_PATH
    retro_path.parent.mkdir(parents=True, exist_ok=True)

    if not retro_path.exists():
        retro_path.write_text("# Kraken Retrospective Log\n\nAuto-generated learnings from solve sessions.\n\n")

    with open(retro_path, "a") as f:
        f.write("\n" + entry)

    return entry


# ── Tool 15: Retrospective ───────────────────────────────────────────────────


@mcp.tool()
async def kraken_retrospective(
    session_path: str,
    notes: str = "",
) -> dict:
    """Analyze a completed solve session and log lessons learned.

    Reads a session.json, analyzes tool performance, identifies bottlenecks
    and near-misses, and appends a structured entry to solves/RETROSPECTIVE.md.

    Args:
        session_path: Path to a session.json file (from kraken_full_solve with save_session=True).
        notes: Optional free-text notes to include in the retrospective entry.

    Returns dict with: entry (the markdown logged), retrospective_path, analysis.
    """
    try:
        import json as _json

        p = Path(session_path)
        if not p.exists():
            return {"error": f"Session file not found: {session_path}"}

        session = _json.loads(p.read_text())
        entry = _append_retrospective(session, notes=notes)

        return {
            "entry": entry,
            "retrospective_path": str(_RETROSPECTIVE_PATH.resolve()),
            "challenge_id": session.get("challenge_id", ""),
            "solved": session.get("solved", False),
        }
    except Exception as exc:
        return _err("kraken_retrospective", exc)


# ── Tool 16: Get Insights ────────────────────────────────────────────────────


@mcp.tool()
def kraken_get_insights(
    challenge_type: str = "",
    keywords: str = "",
    max_entries: int = 10,
) -> dict:
    """Retrieve relevant insights from past solves for a new challenge.

    Reads the accumulated retrospective log and filters entries by challenge
    type and/or keywords. Use this before starting a new challenge to learn
    from past successes and failures.

    Args:
        challenge_type: Filter by challenge type (e.g. "rev", "crypto", "constraint").
        keywords: Comma-separated keywords to search for in entries.
        max_entries: Maximum number of entries to return.

    Returns dict with: entries (list of matching retrospective entries),
    total_entries, filters_applied.
    """
    try:
        retro_path = _RETROSPECTIVE_PATH
        if not retro_path.exists():
            return {
                "entries": [],
                "total_entries": 0,
                "filters_applied": {"challenge_type": challenge_type, "keywords": keywords},
                "message": "No retrospective log found yet. Run kraken_full_solve or kraken_retrospective first.",
            }

        content = retro_path.read_text()

        # Split into entries (each starts with ###)
        raw_entries = re.split(r"\n(?=### )", content)
        entries = [e.strip() for e in raw_entries if e.strip().startswith("### ")]

        # Filter by challenge type
        if challenge_type:
            ct_lower = challenge_type.lower()
            entries = [e for e in entries if ct_lower in e.lower()]

        # Filter by keywords
        if keywords:
            kw_list = [k.strip().lower() for k in keywords.split(",") if k.strip()]
            entries = [
                e for e in entries
                if any(kw in e.lower() for kw in kw_list)
            ]

        total = len(entries)
        entries = entries[-max_entries:]  # Return most recent matches

        return {
            "entries": entries,
            "total_entries": total,
            "filters_applied": {"challenge_type": challenge_type, "keywords": keywords},
        }
    except Exception as exc:
        return _err("kraken_get_insights", exc)


# ── Tool 17: Performance Stats ────────────────────────────────────────────────


@mcp.tool()
def kraken_perf_stats(
    challenge_type: str = "",
    tool_name: str = "",
) -> dict:
    """View accumulated performance stats, success rates, and timing percentiles.

    Query the performance database for tool-level or type-level statistics.
    Useful for understanding which tools work best for which challenge types
    and identifying optimization opportunities.

    Args:
        challenge_type: Filter stats by challenge type (e.g. "rev", "crypto").
        tool_name: Filter stats by specific tool name (e.g. "auto_angr").

    Returns dict with: global_stats, tool_stats or type_summary depending on filters.
    """
    try:
        from kraken.execution.optimizer import PerformanceDB

        perf_db = PerformanceDB()
        result: dict = {"global_stats": perf_db.to_dict().get("global_stats", {})}

        if tool_name:
            result["tool_stats"] = perf_db.get_tool_stats(tool_name, challenge_type)
        elif challenge_type:
            result["type_summary"] = perf_db.get_type_summary(challenge_type)
        else:
            # Return summary of all tools
            all_tools = {}
            for tn in perf_db.to_dict().get("tool_stats", {}):
                all_tools[tn] = perf_db.get_tool_stats(tn)
            result["all_tool_stats"] = all_tools

            # Return summary of all types
            all_types = {}
            for ct in perf_db.to_dict().get("type_stats", {}):
                all_types[ct] = perf_db.get_type_summary(ct)
            result["all_type_stats"] = all_types

        return result
    except Exception as exc:
        return _err("kraken_perf_stats", exc)


# ── Tool 18: Optimize Cascade ────────────────────────────────────────────────


@mcp.tool()
def kraken_optimize_cascade(
    min_samples: int = 5,
    dry_run: bool = False,
) -> dict:
    """Manually re-run the cascade optimizer and see what changed.

    Reads accumulated performance stats and generates (or previews) an
    optimized cascade configuration with reordered tools, tuned timeouts,
    and skip-lists per challenge type.

    Args:
        min_samples: Minimum solves per challenge type before optimizing (default 5).
        dry_run: If True, compute config but don't write to disk.

    Returns dict with: config (the generated cascade config), config_path, dry_run.
    """
    try:
        from kraken.execution.optimizer import PerformanceDB, optimize, _CASCADE_CONFIG_PATH

        perf_db = PerformanceDB()

        if dry_run:
            import tempfile
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
                tmp_path = f.name
            config = optimize(perf_db=perf_db, min_samples=min_samples, config_path=tmp_path)
            Path(tmp_path).unlink(missing_ok=True)
            return {
                "config": config,
                "config_path": "(dry run -- not written)",
                "dry_run": True,
            }
        else:
            config = optimize(perf_db=perf_db, min_samples=min_samples)
            return {
                "config": config,
                "config_path": str(_CASCADE_CONFIG_PATH),
                "dry_run": False,
            }
    except Exception as exc:
        return _err("kraken_optimize_cascade", exc)


# ── Tool 19: Backfill Performance DB ─────────────────────────────────────────


@mcp.tool()
def kraken_backfill_perf(
    sessions_dir: str = "solves",
) -> dict:
    """Bootstrap the performance DB from existing session.json files.

    Scans a directory tree for session.json files, ingests them all into
    the performance database, and runs the optimizer. Use this to seed
    the cascade optimizer from historical solve data.

    Args:
        sessions_dir: Root directory to scan for session.json files (default: "solves").

    Returns dict with: sessions_found, sessions_ingested, errors, config.
    """
    try:
        from kraken.execution.optimizer import backfill_from_sessions

        return backfill_from_sessions(sessions_dir)
    except Exception as exc:
        return _err("kraken_backfill_perf", exc)


# ── Tool 20: PCAP Extract ────────────────────────────────────────────────────


@mcp.tool()
def kraken_pcap_extract(
    challenge_dir: str,
    flag_format: str = r"flag\{[a-zA-Z0-9_]+\}",
) -> dict:
    """Extract flags from PCAP network captures using TCP stream reassembly, HTTP parsing, and DNS query extraction.

    Args:
        challenge_dir: Directory containing .pcap/.pcapng files.
        flag_format: Regex for expected flag format.

    Returns dict with: stdout, stderr, exit_code, flag_found, flag.
    """
    try:
        import subprocess

        helpers_dir = Path(__file__).resolve().parent / "helpers"
        cmd = f'python3 {helpers_dir}/auto_pcap_extract.py "{challenge_dir}" --flag-format "{flag_format}"'
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=90)
        flag = None
        marker = re.search(r"EXTRACTED FLAG:\s*(.+)", proc.stdout)
        if marker:
            flag = marker.group(1).strip()
        return {
            "exit_code": proc.returncode,
            "stdout": proc.stdout[:5000],
            "stderr": proc.stderr[:2000],
            "flag_found": flag is not None,
            "flag": flag or "",
        }
    except Exception as exc:
        return _err("kraken_pcap_extract", exc)


# ── Tool 21: Steganography Extract ───────────────────────────────────────────


@mcp.tool()
def kraken_steg_extract(
    challenge_dir: str,
    flag_format: str = r"flag\{[a-zA-Z0-9_]+\}",
) -> dict:
    """Extract hidden data from images using LSB steganography, EXIF metadata, binwalk carving, and pixel channel analysis.

    Args:
        challenge_dir: Directory containing image files (.png, .jpg, .bmp, .gif, .tiff).
        flag_format: Regex for expected flag format.

    Returns dict with: stdout, stderr, exit_code, flag_found, flag.
    """
    try:
        import subprocess

        helpers_dir = Path(__file__).resolve().parent / "helpers"
        cmd = f'python3 {helpers_dir}/auto_steg_extract.py "{challenge_dir}" --flag-format "{flag_format}"'
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=90)
        flag = None
        marker = re.search(r"EXTRACTED FLAG:\s*(.+)", proc.stdout)
        if marker:
            flag = marker.group(1).strip()
        return {
            "exit_code": proc.returncode,
            "stdout": proc.stdout[:5000],
            "stderr": proc.stderr[:2000],
            "flag_found": flag is not None,
            "flag": flag or "",
        }
    except Exception as exc:
        return _err("kraken_steg_extract", exc)


# ── Tool 22: Pwn Exploit ─────────────────────────────────────────────────────


@mcp.tool()
def kraken_pwn_exploit(
    binary_path: str,
    flag_format: str = r"flag\{[a-zA-Z0-9_]+\}",
) -> dict:
    """Attempt automated pwn exploitation: checksec, overflow detection, ret2win, ret2system, format string detection.

    Args:
        binary_path: Path to the vulnerable binary.
        flag_format: Regex for expected flag format.

    Returns dict with: stdout, stderr, exit_code, flag_found, flag.
    """
    try:
        import subprocess

        helpers_dir = Path(__file__).resolve().parent / "helpers"
        cmd = f'python3 {helpers_dir}/auto_pwn_template.py "{binary_path}" --flag-format "{flag_format}"'
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
        flag = None
        marker = re.search(r"EXTRACTED FLAG:\s*(.+)", proc.stdout)
        if marker:
            flag = marker.group(1).strip()
        return {
            "exit_code": proc.returncode,
            "stdout": proc.stdout[:5000],
            "stderr": proc.stderr[:2000],
            "flag_found": flag is not None,
            "flag": flag or "",
        }
    except Exception as exc:
        return _err("kraken_pwn_exploit", exc)


# ── Tool 23: Record Failure ──────────────────────────────────────────────────


@mcp.tool()
def kraken_record_failure(
    challenge_path: str,
    failure_type: str,
    details: str = "",
    tools_tried: list[str] | None = None,
) -> dict:
    """Record a solve failure with classification for the optimizer.

    Logs a failure with its type so the optimizer can track patterns and
    suggest improvements. Use after a failed solve to build failure taxonomy.

    failure_type must be one of: no_tool_match, tool_partial, classify_wrong,
    llm_flaky, timeout, tool_crash, flag_rejected, unknown

    Args:
        challenge_path: Path to the challenge that failed.
        failure_type: Classification of why it failed (see above).
        details: Human-readable explanation of what went wrong.
        tools_tried: List of tool names that were attempted.

    Returns dict with: recorded (bool), failure entry, total_failures.
    """
    try:
        from kraken.execution.optimizer import FailureDB, FailureType

        challenge_id = Path(challenge_path).resolve().name

        # Try to determine challenge type from triage
        challenge_type = "unknown"
        try:
            from kraken.nodes.triage import triage
            from kraken.state import initial_state
            import asyncio

            state = initial_state(
                challenge_id="failure_record",
                challenge_path=challenge_path,
                flag_format=r"flag\{[a-zA-Z0-9_]+\}",
            )
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Can't await in sync context -- skip triage
                pass
            else:
                triage_result = loop.run_until_complete(triage(state))
                params = triage_result.get("extracted_params", {})
                challenge_type = params.get("challenge_type", "unknown")
        except Exception:
            pass  # Best-effort type detection

        fdb = FailureDB()
        entry = fdb.record_failure(
            challenge_id=challenge_id,
            challenge_type=challenge_type,
            failure_type=failure_type,
            details=details,
            tools_tried=tools_tried or [],
        )

        return {
            "recorded": True,
            "failure": entry,
            "total_failures": fdb.to_dict().get("summary", {}).get("total", 0),
        }
    except Exception as exc:
        return _err("kraken_record_failure", exc)


# ── Tool 24: Failure Stats ──────────────────────────────────────────────────


@mcp.tool()
def kraken_failure_stats() -> dict:
    """Get failure statistics -- what types of failures occur most and suggestions for fixes.

    Analyzes the failure taxonomy database and returns:
    - Counts by failure type (no_tool_match, tool_partial, etc.)
    - Breakdown by challenge type
    - Actionable suggestions for what would fix the most challenges

    Returns dict with: stats, suggestions, total_failures.
    """
    try:
        from kraken.execution.optimizer import FailureDB

        fdb = FailureDB()
        stats = fdb.failure_stats()
        suggestions = fdb.suggest_improvements()

        return {
            "stats": stats,
            "suggestions": suggestions,
            "total_failures": stats.get("total", 0),
        }
    except Exception as exc:
        return _err("kraken_failure_stats", exc)


# ── Tool 25: Query Knowledge Base ─────────────────────────────────────────


@mcp.tool()
def kraken_query_knowledge(
    query: str = "",
    technique: str = "",
    constraint_type: str = "",
    challenge_name: str = "",
    binary_info: dict | None = None,
    strings: list[str] | None = None,
) -> dict:
    """Query the solve knowledge base for past patterns and approach suggestions.

    Use this after triage to get suggestions based on similar past challenges.
    Can query by technique name, constraint type, challenge name, or provide
    binary_info for automatic approach matching.

    Args:
        query: Free-text query (searches techniques and constraint types).
        technique: Filter by technique name (substring match, e.g. "xor", "rc4").
        constraint_type: Filter by constraint type (e.g. "xor_decrypt", "rc4_decrypt").
        challenge_name: Find a specific challenge or its similar challenges.
        binary_info: Dict with binary properties (type, stripped, pie, imports, language, etc.)
                     for automatic approach suggestion.
        strings: List of strings from the binary for heuristic matching.

    Returns dict with: results (list of matches or suggestions), stats, query_type.
    """
    try:
        from kraken.storage.solve_knowledge import SolveKnowledgeBase

        kb = SolveKnowledgeBase(solves_root="benchmarks")

        if not kb.patterns:
            return {
                "results": [],
                "stats": {"total_challenges": 0},
                "query_type": "empty",
                "message": "No solve artifacts found in the given directory.",
            }

        # Approach suggestion (highest priority)
        if binary_info is not None:
            suggestions = kb.suggest_approach(binary_info=binary_info, strings=strings)
            return {
                "results": suggestions,
                "stats": kb.stats(),
                "query_type": "suggest_approach",
            }

        # Challenge name lookup (exact + similar)
        if challenge_name:
            exact = kb.query_by_name(challenge_name)
            similar = kb.query_similar(challenge_name)
            results = []
            if exact:
                results.append({
                    "challenge": exact.challenge,
                    "dataset": exact.dataset,
                    "week": exact.week,
                    "category": exact.category,
                    "difficulty": exact.difficulty,
                    "techniques": exact.techniques,
                    "constraint_type": exact.constraint_type,
                    "key_insights": exact.key_insights,
                    "tools_used": exact.tools_used,
                    "solve_method": exact.solve_method,
                    "solve_time_seconds": exact.solve_time_seconds,
                })
            return {
                "results": results,
                "similar": [
                    {
                        "challenge": p.challenge,
                        "techniques": p.techniques,
                        "constraint_type": p.constraint_type,
                    }
                    for p in similar
                ],
                "stats": kb.stats(),
                "query_type": "challenge_lookup",
            }

        # Technique query
        if technique:
            matches = kb.query_by_technique(technique)
            return {
                "results": [
                    {
                        "challenge": p.challenge,
                        "dataset": p.dataset,
                        "week": p.week,
                        "techniques": p.techniques,
                        "constraint_type": p.constraint_type,
                        "key_insights": p.key_insights[:2],
                    }
                    for p in matches
                ],
                "stats": kb.stats(),
                "query_type": "technique",
            }

        # Constraint type query
        if constraint_type:
            matches = kb.query_by_type(constraint_type)
            return {
                "results": [
                    {
                        "challenge": p.challenge,
                        "dataset": p.dataset,
                        "constraint_type": p.constraint_type,
                        "techniques": p.techniques,
                    }
                    for p in matches
                ],
                "stats": kb.stats(),
                "query_type": "constraint_type",
            }

        # Free-text query -- search both techniques and constraint types
        if query:
            tech_matches = kb.query_by_technique(query)
            type_matches = kb.query_by_type(query)
            seen = set()
            combined = []
            for p in tech_matches + type_matches:
                if p.challenge not in seen:
                    seen.add(p.challenge)
                    combined.append({
                        "challenge": p.challenge,
                        "dataset": p.dataset,
                        "techniques": p.techniques,
                        "constraint_type": p.constraint_type,
                    })
            return {
                "results": combined,
                "stats": kb.stats(),
                "query_type": "free_text",
            }

        # Default: return stats and full listing
        return {
            "results": kb.to_dict()["patterns"],
            "stats": kb.stats(),
            "query_type": "list_all",
        }
    except Exception as exc:
        return _err("kraken_query_knowledge", exc)


# ── Tool 26: Pwn Exploit ────────────────────────────────────────────────────


@mcp.tool()
def kraken_pwn_solve(
    binary_path: str,
    source_path: str = "",
    remote_host: str = "",
    remote_port: int = 0,
    flag_prefix: str = "flag",
) -> dict:
    """Full binary exploitation: ret2win, ret2libc, ROP chains, format string, heap.

    Generates and runs actual exploits via pwntools. Tries strategies in order:
    ret2win → ret2shellcode → format string → ret2libc → ROP chain.

    Args:
        binary_path: Path to vulnerable binary.
        source_path: Optional source code path for analysis.
        remote_host: Remote host for network pwn challenges.
        remote_port: Remote port.
        flag_prefix: Flag prefix (default: "flag").
    """
    try:
        import subprocess

        helpers = Path(__file__).resolve().parent / "helpers"
        cmd = f'python3 {helpers}/auto_pwn_solve.py "{binary_path}" --prefix "{flag_prefix}"'
        if source_path:
            cmd += f' --source "{source_path}"'
        if remote_host and remote_port:
            cmd += f' --remote-host "{remote_host}" --remote-port {remote_port}'
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
        flag = None
        marker = re.search(r"EXTRACTED FLAG:\s*(.+)", proc.stdout)
        if not marker:
            marker = re.search(r"FLAG FOUND:\s*(.+)", proc.stdout)
        if marker:
            flag = marker.group(1).strip()
        return {
            "exit_code": proc.returncode,
            "stdout": proc.stdout[:5000],
            "stderr": proc.stderr[:2000],
            "flag_found": flag is not None,
            "flag": flag or "",
        }
    except Exception as exc:
        return _err("kraken_pwn_solve", exc)


# ── Tool 27: Web Exploit ───────────────────────────────────────────────────


@mcp.tool()
def kraken_web_exploit(
    url: str,
    flag_prefix: str = "flag",
    method: str = "GET",
    data: str = "",
    cookie: str = "",
) -> dict:
    """Web exploitation: SQLi, SSTI, command injection, SSRF, LFI, deserialization, JWT.

    Automatically discovers endpoints, tests injection points, and extracts flags.

    Args:
        url: Target URL (e.g., http://target:8080).
        flag_prefix: Flag prefix (default: "flag").
        method: HTTP method (GET or POST).
        data: POST data string.
        cookie: Cookie header value.
    """
    try:
        import subprocess

        helpers = Path(__file__).resolve().parent / "helpers"
        cmd = f'python3 {helpers}/auto_web_exploit.py --url "{url}" --prefix "{flag_prefix}"'
        if method != "GET":
            cmd += f' --method {method}'
        if data:
            cmd += f' --data "{data}"'
        if cookie:
            cmd += f' --cookie "{cookie}"'
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
        flag = None
        marker = re.search(r"(?:EXTRACTED|FLAG FOUND).*?:\s*(.+)", proc.stdout)
        if marker:
            flag = marker.group(1).strip()
        return {
            "exit_code": proc.returncode,
            "stdout": proc.stdout[:5000],
            "stderr": proc.stderr[:2000],
            "flag_found": flag is not None,
            "flag": flag or "",
        }
    except Exception as exc:
        return _err("kraken_web_exploit", exc)


# ── Tool 28: Docker Solve ──────────────────────────────────────────────────


@mcp.tool()
def kraken_docker_solve(
    challenge_dir: str,
    flag_prefix: str = "flag",
    timeout: int = 180,
) -> dict:
    """Solve Docker-based CTF challenges. Builds containers, discovers ports, attacks services.

    Args:
        challenge_dir: Directory containing Dockerfile or docker-compose.yml.
        flag_prefix: Flag prefix (default: "flag").
        timeout: Max time in seconds (default: 180).
    """
    try:
        import subprocess

        helpers = Path(__file__).resolve().parent / "helpers"
        cmd = f'python3 {helpers}/auto_docker_solve.py --challenge-dir "{challenge_dir}" --prefix "{flag_prefix}" --timeout {timeout}'
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout + 30)
        flag = None
        marker = re.search(r"(?:EXTRACTED|FLAG FOUND).*?:\s*(.+)", proc.stdout)
        if marker:
            flag = marker.group(1).strip()
        return {
            "exit_code": proc.returncode,
            "stdout": proc.stdout[:5000],
            "stderr": proc.stderr[:2000],
            "flag_found": flag is not None,
            "flag": flag or "",
        }
    except Exception as exc:
        return _err("kraken_docker_solve", exc)


# ── Tool 29: GDB Solve ────────────────────────────────────────────────────


@mcp.tool()
def kraken_gdb_solve(
    binary_path: str,
    flag_format: str = r"flag\{[a-zA-Z0-9_]+\}",
) -> dict:
    """GDB Python scripting: strcmp/memcmp hooking, anti-debug bypass, runtime decryption.

    Args:
        binary_path: Path to binary to analyze.
        flag_format: Regex for expected flag format.
    """
    try:
        import subprocess

        helpers = Path(__file__).resolve().parent / "helpers"
        cmd = f'python3 {helpers}/auto_gdb_solve.py "{binary_path}" --flag-format "{flag_format}"'
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=90)
        flag = None
        marker = re.search(r"(?:EXTRACTED|FLAG FOUND).*?:\s*(.+)", proc.stdout)
        if marker:
            flag = marker.group(1).strip()
        return {
            "exit_code": proc.returncode,
            "stdout": proc.stdout[:5000],
            "stderr": proc.stderr[:2000],
            "flag_found": flag is not None,
            "flag": flag or "",
        }
    except Exception as exc:
        return _err("kraken_gdb_solve", exc)


# ── Tool 30: Process Interact ──────────────────────────────────────────────


@mcp.tool()
def kraken_process_interact(
    binary_path: str = "",
    host: str = "",
    port: int = 0,
    flag_prefix: str = "flag",
) -> dict:
    """Multi-round process/service interaction with menu exploration and PoW solving.

    Args:
        binary_path: Local binary to interact with.
        host: Remote host (alternative to binary_path).
        port: Remote port.
        flag_prefix: Flag prefix (default: "flag").
    """
    try:
        import subprocess

        helpers = Path(__file__).resolve().parent / "helpers"
        if host and port:
            cmd = f'python3 {helpers}/auto_process_interact.py --host "{host}" --port {port} --prefix "{flag_prefix}"'
        elif binary_path:
            cmd = f'python3 {helpers}/auto_process_interact.py --binary "{binary_path}" --prefix "{flag_prefix}"'
        else:
            return {"error": "Provide either binary_path or host+port"}
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
        flag = None
        marker = re.search(r"(?:EXTRACTED|FLAG FOUND).*?:\s*(.+)", proc.stdout)
        if marker:
            flag = marker.group(1).strip()
        return {
            "exit_code": proc.returncode,
            "stdout": proc.stdout[:5000],
            "stderr": proc.stderr[:2000],
            "flag_found": flag is not None,
            "flag": flag or "",
        }
    except Exception as exc:
        return _err("kraken_process_interact", exc)


# ── Entry point ──────────────────────────────────────────────────────────────


def main():
    """Entry point for the kraken-mcp command."""
    mcp.run()


if __name__ == "__main__":
    main()
