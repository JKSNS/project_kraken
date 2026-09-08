"""DotNet specialist node -- prepares context for solving .NET/CIL challenges.

Gathers runtime information by attempting to execute the binary with mono/dotnet,
and annotates state with available .NET tooling so solve_engine knows what to try.

Uses the KRAKEN tool installer to auto-provision missing runtimes/decompilers.
"""
from __future__ import annotations

import asyncio
import shutil

from kraken.state import KrakenState
from kraken.tools.installer import ensure_tools, is_available
from kraken.logging.structured import get_logger

log = get_logger(__name__)

_DOTNET_RUNTIMES = ["mono", "dotnet"]
_DOTNET_DECOMPILERS = ["ilspycmd", "monodis"]


async def dotnet_specialist(state: KrakenState) -> dict:
    """Probe .NET binary: auto-install missing tools, detect available tools, attempt quick execution."""
    binary_path = state["challenge_path"]
    log.info("dotnet_analysis_start")

    # ── Auto-install missing tools ────────────────────────────────────
    # Try to get at least one decompiler and one runtime if none are available
    missing_runtimes = [r for r in _DOTNET_RUNTIMES if not shutil.which(r)]
    missing_decompilers = [d for d in _DOTNET_DECOMPILERS if not shutil.which(d)]

    install_targets = []
    if missing_runtimes and not any(shutil.which(r) for r in _DOTNET_RUNTIMES):
        install_targets.append("mono")  # Prefer mono -- smaller, more widely available
    if missing_decompilers and not any(shutil.which(d) for d in _DOTNET_DECOMPILERS):
        install_targets.extend(["monodis", "ilspycmd"])  # monodis first (comes with mono-utils)

    if install_targets:
        log.info("dotnet_specialist_installing_tools", tools=install_targets)
        availability = await ensure_tools(*install_targets)
        installed = [t for t, ok in availability.items() if ok]
        if installed:
            log.info("dotnet_specialist_tools_installed", tools=installed)

    # Re-check availability after install attempts
    available_runtimes = [r for r in _DOTNET_RUNTIMES if shutil.which(r)]
    available_decompilers = [d for d in _DOTNET_DECOMPILERS if shutil.which(d)]

    runtime_output: dict = {}

    # Attempt quick execution with first available runtime
    for runtime in available_runtimes:
        try:
            proc = await asyncio.create_subprocess_exec(
                runtime, binary_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.DEVNULL,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
            runtime_output = {
                "runtime": runtime,
                "stdout": stdout.decode(errors="replace")[:2000],
                "stderr": stderr.decode(errors="replace")[:500],
                "exit_code": proc.returncode,
            }
            log.info("dotnet_runtime_execution", runtime=runtime,
                     exit_code=proc.returncode, stdout_len=len(stdout))
            break
        except asyncio.TimeoutError:
            log.warning("dotnet_runtime_timeout", runtime=runtime)
        except Exception as e:
            log.warning("dotnet_runtime_failed", runtime=runtime, error=str(e))

    # Build specialist summary for solve_engine
    tool_guidance = []
    if available_decompilers:
        tool_guidance.append(f"Decompilers available: {', '.join(available_decompilers)}")
        if "ilspycmd" in available_decompilers:
            tool_guidance.append("  Use subprocess(['ilspycmd', binary_path]) to get full C# source")
        if "monodis" in available_decompilers:
            tool_guidance.append("  Use subprocess(['monodis', '--output=/dev/stdout', binary_path]) for CIL disassembly")
    else:
        tool_guidance.append("No .NET decompiler available (install attempts failed).")
        tool_guidance.append("  Fallback: use pefile to parse PE metadata, strings for string literals")
        tool_guidance.append("  Or read __pe_metadata__ from decompiled_functions directly")

    if available_runtimes:
        tool_guidance.append(f"Runtimes available: {', '.join(available_runtimes)}")
        tool_guidance.append(f"  Can execute: subprocess(['{available_runtimes[0]}', binary_path], input=b'...')")
        tool_guidance.append("  Try running with different inputs to observe flag-checking behavior")
    else:
        tool_guidance.append("No .NET runtime available (mono/dotnet install failed).")
        tool_guidance.append("  Static analysis only: use ilspycmd/monodis output if available")

    # dnfile for deeper CIL metadata parsing
    tool_guidance.append("")
    tool_guidance.append("For deep CIL metadata: import dnfile; pe = dnfile.dnPE(binary_path)")

    specialist_summary = "\n".join(tool_guidance)
    if runtime_output:
        out = runtime_output.get("stdout", "")
        err = runtime_output.get("stderr", "")
        specialist_summary += f"\n\nQuick run ({runtime_output['runtime']}) [exit={runtime_output['exit_code']}]:"
        if out:
            specialist_summary += f"\n  stdout: {out[:500]}"
        if err:
            specialist_summary += f"\n  stderr: {err[:200]}"

    log.info(
        "dotnet_analysis_complete",
        available_runtimes=available_runtimes,
        available_decompilers=available_decompilers,
        has_runtime_output=bool(runtime_output),
    )

    # Build dotnet_analysis dict -- stored in angr_results like other specialists
    # so _build_specialist_summary in solve_engine can surface it.
    dotnet_analysis = {
        "available_runtimes": available_runtimes,
        "available_decompilers": available_decompilers,
        "tool_guidance": specialist_summary,
        "runtime_output": runtime_output,
        "can_execute": bool(available_runtimes),
        "can_decompile": bool(available_decompilers),
    }

    existing_angr = state.get("angr_results") or {}
    if not isinstance(existing_angr, dict):
        existing_angr = {}

    return {
        "angr_results": {**existing_angr, "dotnet_analysis": dotnet_analysis},
        "strategy_hypothesis": specialist_summary[:300],
        "recent_actions": [{
            "action": "dotnet_specialist",
            "reasoning": "Detected .NET/CIL assembly -- gathering runtime info and tool availability",
            "result_summary": specialist_summary,
        }],
        "iteration_count": state.get("iteration_count", 0) + 1,
    }
