"""KrakenState -- the central TypedDict flowing through the LangGraph."""

from __future__ import annotations

import operator
from pathlib import Path
from typing import Annotated, Any, TypedDict


def _replace(existing: Any, new: Any) -> Any:
    """Reducer that replaces the old value with the new one (default LangGraph behavior)."""
    return new


class KrakenState(TypedDict, total=False):
    """Full state for the KRAKEN graph.

    Fields are grouped by origin:
      - Challenge metadata (set at ingestion)
      - Deterministic analysis artifacts (from tools only -- never LLM-generated)
      - LLM-generated annotations (non-critical, advisory only)
      - Solve state
      - Control flow
      - Context management
    """

    # ── Challenge metadata ──────────────────────────────────────────
    challenge_id: str
    challenge_path: str
    challenge_dir: str  # original directory containing challenge files (even after binary resolution)
    challenge_description: str
    flag_format: str
    category: str
    solve_workspace: str  # per-challenge artifact directory under invocation CWD

    # ── Deterministic analysis artifacts ────────────────────────────
    binary_info: dict  # file type, arch, protections, sections, entropy
    decompiled_functions: dict  # function_name@addr -> decompiled C code
    call_graph: dict  # function_name@addr -> [callee_name@addr, ...]
    strings_of_interest: list[str]  # filtered strings from binary
    xrefs: dict  # address -> cross-reference info
    symbols: dict  # symbol table entries
    dynamic_traces: list[dict]  # execution traces from debugger
    memory_dumps: dict  # address -> hex bytes
    angr_results: dict  # symbolic execution results
    z3_results: dict  # constraint solver results

    # ── LLM-generated (non-critical, annotation only) ──────────────
    function_annotations: dict  # function_name -> human-readable description
    strategy_hypothesis: str  # manager's current theory about the challenge
    challenge_type: str  # constraint | crypto | dynamic | keygen | pwn
    secondary_types: list[str]  # other applicable types ranked by relevance (#3)

    # ── Solve state ─────────────────────────────────────────────────
    solve_scripts: Annotated[list[dict], operator.add]
    # Each entry: compact summary only (historical details are in solve_ledger.md)
    current_attempt: dict  # full current attempt payload {code, stdout, stderr, ...}
    solve_ledger_path: str
    current_strategy: str  # active approach description
    strategies_tried: Annotated[list[str], operator.add]
    flag: str  # extracted flag (empty until solved)

    # ── Self-correction feedback (#1, #2) ─────────────────────────────
    failure_diagnosis: str  # deterministic failure analysis from flag_validator
    script_findings: list[str]  # intermediate results extracted from script output

    # ── Control flow ────────────────────────────────────────────────
    next_node: str  # routing decision for conditional edges
    iteration_count: int  # total steps taken
    error_log: Annotated[list[dict], operator.add]

    # ── Context management ──────────────────────────────────────────
    context_summary: str  # compressed summary of older analysis
    recent_actions: Annotated[list[dict], operator.add]
    # Each entry: {action, reasoning, result_summary, timestamp}
    compressed_action_count: int  # how many recent_actions have been compressed into context_summary

    # ── Racing (parallel model diversity) ─────────────────────────────
    racing_attempted: bool  # Whether model racing has been tried for this challenge

    # ── Timing / diagnostics ──────────────────────────────────────────
    node_timings: Annotated[list[dict], operator.add]
    # Each: {"node": str, "duration_s": float}
    solve_path: Annotated[list[str], operator.add]
    # Ordered list of node names visited
    framework_crash_count: int

    # ── Multi-file / remote ───────────────────────────────────────────
    challenge_files: dict
    # {"server.py": {"path": "/abs/path", "type": "text (.py)", "size": 1234, "content_preview": "..."}, ...}
    remote_info: dict
    # {"host": str, "port": int, "protocol": "tcp", "source": "description"|"docker-compose"|"challenge_config"}

    # ── Tool router state ─────────────────────────────────────────────
    extracted_params: dict  # deterministic params from param_extractor
    tool_cascade_results: Annotated[list[dict], operator.add]  # tool execution results
    tool_flag_candidate: str  # flag found by tool cascade (empty until found)
    tool_results_summary: str  # human-readable summary for solve_engine prompt

    # ── Hallucination tracking ────────────────────────────────────────
    rejected_flags: Annotated[list[str], operator.add]
    # Flags that were submitted but rejected (tracks hallucination loops)

    # ── Artifact store handles (Phase 1 -- decouple large data) ───────
    artifact_store_path: str  # path to .artifacts directory
    decompiled_functions_handle: str  # handle key for decompiled_functions
    angr_results_handle: str  # handle key for angr_results
    dynamic_traces_handle: str  # handle key for dynamic_traces

    # ── Benchmark mode ───────────────────────────────────────────────
    benchmark: bool


def initial_state(
    challenge_id: str,
    challenge_path: str,
    description: str = "",
    flag_format: str = r"flag\{[a-zA-Z0-9_]+\}",
    category: str = "rev",
    benchmark: bool = False,
    solve_workspace: str = "",
) -> KrakenState:
    """Create initial state for a new challenge."""
    # Derive challenge_dir: resolve to absolute path first so scripts always get
    # an absolute working directory regardless of how the challenge path was passed
    _p = Path(challenge_path).resolve()
    _challenge_dir = str(_p) if _p.is_dir() else str(_p.parent)

    return KrakenState(
        challenge_id=challenge_id,
        challenge_path=str(_p),
        challenge_dir=_challenge_dir,
        challenge_description=description,
        flag_format=flag_format,
        category=category,
        solve_workspace=solve_workspace,
        binary_info={},
        decompiled_functions={},
        call_graph={},
        strings_of_interest=[],
        xrefs={},
        symbols={},
        dynamic_traces=[],
        memory_dumps={},
        angr_results={},
        z3_results={},
        function_annotations={},
        strategy_hypothesis="",
        challenge_type="",
        secondary_types=[],
        solve_scripts=[],
        current_attempt={},
        solve_ledger_path="",
        current_strategy="",
        strategies_tried=[],
        flag="",
        failure_diagnosis="",
        script_findings=[],
        next_node="",
        iteration_count=0,
        error_log=[],
        context_summary="",
        recent_actions=[],
        compressed_action_count=0,
        node_timings=[],
        solve_path=[],
        framework_crash_count=0,
        challenge_files={},
        remote_info={},
        benchmark=benchmark,
        extracted_params={},
        tool_cascade_results=[],
        tool_flag_candidate="",
        tool_results_summary="",
        # Phase 1: Artifact store handles
        artifact_store_path="",
        decompiled_functions_handle="",
        angr_results_handle="",
        dynamic_traces_handle="",
    )
