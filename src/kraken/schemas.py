"""Node I/O schemas -- narrow TypedDicts documenting field access per node.

These schemas serve as documentation and optional debug-time validation.
They do NOT change runtime behavior -- nodes still receive full KrakenState.

Each node has an Input (fields read via state.get / state[]) and an Output
(keys present in the returned dict).  Common bookkeeping keys that almost
every node writes (recent_actions, iteration_count, error_log, node_timings,
solve_path) are collected in _BOOKKEEPING_FIELDS and automatically excluded
from the extra-field warning in the validated_node decorator.
"""
from __future__ import annotations

import functools
from typing import Any, TypedDict

from kraken.logging.structured import get_logger

log = get_logger(__name__)

# Keys that most nodes write as side-effects of the _safe_node wrapper or
# standard bookkeeping.  The validated_node decorator ignores these.
_BOOKKEEPING_FIELDS = frozenset({
    "iteration_count",
    "recent_actions",
    "error_log",
    "node_timings",
    "solve_path",
    "framework_crash_count",
    "next_node",
})


# ---------------------------------------------------------------------------
# Triage
# ---------------------------------------------------------------------------
class TriageInput(TypedDict, total=False):
    challenge_path: str
    challenge_dir: str
    challenge_description: str
    flag_format: str
    solve_workspace: str
    remote_info: dict
    solve_ledger_path: str
    iteration_count: int


class TriageOutput(TypedDict, total=False):
    binary_info: dict
    strings_of_interest: list[str]
    symbols: dict
    challenge_path: str  # updated when directory resolved to binary
    challenge_files: dict
    remote_info: dict
    recent_actions: list[dict]
    iteration_count: int


# ---------------------------------------------------------------------------
# Unpack
# ---------------------------------------------------------------------------
class UnpackInput(TypedDict, total=False):
    challenge_path: str
    binary_info: dict
    strings_of_interest: list[str]
    iteration_count: int


class UnpackOutput(TypedDict, total=False):
    challenge_path: str  # updated when unpacking succeeds
    recent_actions: list[dict]
    error_log: list[dict]
    iteration_count: int


# ---------------------------------------------------------------------------
# Decompile
# ---------------------------------------------------------------------------
class DecompileInput(TypedDict, total=False):
    challenge_path: str
    binary_info: dict
    challenge_files: dict
    strings_of_interest: list[str]
    solve_workspace: str
    iteration_count: int


class DecompileOutput(TypedDict, total=False):
    decompiled_functions: dict
    call_graph: dict
    strings_of_interest: list[str]  # merged with Ghidra strings
    recent_actions: list[dict]
    error_log: list[dict]
    iteration_count: int


# ---------------------------------------------------------------------------
# Normalize
# ---------------------------------------------------------------------------
class NormalizeInput(TypedDict, total=False):
    decompiled_functions: dict
    iteration_count: int


class NormalizeOutput(TypedDict, total=False):
    function_annotations: dict
    recent_actions: list[dict]
    iteration_count: int


# ---------------------------------------------------------------------------
# Classify
# ---------------------------------------------------------------------------
class ClassifyInput(TypedDict, total=False):
    decompiled_functions: dict
    challenge_description: str
    binary_info: dict
    strings_of_interest: list[str]
    function_annotations: dict
    challenge_files: dict
    benchmark: bool
    solve_ledger_path: str
    iteration_count: int


class ClassifyOutput(TypedDict, total=False):
    challenge_type: str
    secondary_types: list[str]
    strategy_hypothesis: str
    current_strategy: str
    next_node: str
    recent_actions: list[dict]
    iteration_count: int


# ---------------------------------------------------------------------------
# Constraint Solver
# ---------------------------------------------------------------------------
class ConstraintSolverInput(TypedDict, total=False):
    challenge_path: str
    decompiled_functions: dict
    symbols: dict
    strings_of_interest: list[str]
    binary_info: dict
    iteration_count: int


class ConstraintSolverOutput(TypedDict, total=False):
    angr_results: dict
    strategy_hypothesis: str
    recent_actions: list[dict]
    iteration_count: int


# ---------------------------------------------------------------------------
# Crypto Decode
# ---------------------------------------------------------------------------
class CryptoDecodeInput(TypedDict, total=False):
    decompiled_functions: dict
    function_annotations: dict
    strings_of_interest: list[str]
    challenge_path: str
    binary_info: dict
    angr_results: dict
    iteration_count: int


class CryptoDecodeOutput(TypedDict, total=False):
    strategy_hypothesis: str
    angr_results: dict  # merged with crypto_analysis
    recent_actions: list[dict]
    iteration_count: int


# ---------------------------------------------------------------------------
# Dynamic Analysis
# ---------------------------------------------------------------------------
class DynamicAnalysisInput(TypedDict, total=False):
    challenge_path: str
    binary_info: dict
    symbols: dict
    strings_of_interest: list[str]
    iteration_count: int


class DynamicAnalysisOutput(TypedDict, total=False):
    dynamic_traces: list[dict]
    strategy_hypothesis: str
    recent_actions: list[dict]
    iteration_count: int


# ---------------------------------------------------------------------------
# Keygen
# ---------------------------------------------------------------------------
class KeygenInput(TypedDict, total=False):
    decompiled_functions: dict
    strings_of_interest: list[str]
    iteration_count: int


class KeygenOutput(TypedDict, total=False):
    strategy_hypothesis: str
    recent_actions: list[dict]
    iteration_count: int


# ---------------------------------------------------------------------------
# Pwn Specialist
# ---------------------------------------------------------------------------
class PwnSpecialistInput(TypedDict, total=False):
    decompiled_functions: dict
    strings_of_interest: list[str]
    binary_info: dict
    challenge_path: str
    remote_info: dict
    angr_results: dict
    iteration_count: int


class PwnSpecialistOutput(TypedDict, total=False):
    strategy_hypothesis: str
    angr_results: dict  # merged with pwn_analysis
    recent_actions: list[dict]
    iteration_count: int


# ---------------------------------------------------------------------------
# Fuzzing Specialist
# ---------------------------------------------------------------------------
class FuzzingSpecialistInput(TypedDict, total=False):
    decompiled_functions: dict
    strings_of_interest: list[str]
    binary_info: dict
    challenge_path: str
    angr_results: dict
    iteration_count: int


class FuzzingSpecialistOutput(TypedDict, total=False):
    strategy_hypothesis: str
    angr_results: dict  # merged with fuzz_analysis
    recent_actions: list[dict]
    iteration_count: int


# ---------------------------------------------------------------------------
# Web Specialist
# ---------------------------------------------------------------------------
class WebSpecialistInput(TypedDict, total=False):
    challenge_files: dict
    strings_of_interest: list[str]
    challenge_description: str
    remote_info: dict
    angr_results: dict
    iteration_count: int


class WebSpecialistOutput(TypedDict, total=False):
    strategy_hypothesis: str
    angr_results: dict  # merged with web_analysis
    recent_actions: list[dict]
    iteration_count: int


# ---------------------------------------------------------------------------
# DotNet Specialist
# ---------------------------------------------------------------------------
class DotnetSpecialistInput(TypedDict, total=False):
    challenge_path: str
    angr_results: dict
    iteration_count: int


class DotnetSpecialistOutput(TypedDict, total=False):
    angr_results: dict  # merged with dotnet_analysis
    strategy_hypothesis: str
    recent_actions: list[dict]
    iteration_count: int


# ---------------------------------------------------------------------------
# Firmware Specialist
# ---------------------------------------------------------------------------
class FirmwareSpecialistInput(TypedDict, total=False):
    binary_info: dict
    strings_of_interest: list[str]
    challenge_path: str
    challenge_description: str
    angr_results: dict
    iteration_count: int


class FirmwareSpecialistOutput(TypedDict, total=False):
    strategy_hypothesis: str
    angr_results: dict  # merged with firmware_analysis
    recent_actions: list[dict]
    iteration_count: int


# ---------------------------------------------------------------------------
# Param Extraction (defined inline in graph.py)
# ---------------------------------------------------------------------------
class ParamExtractionInput(TypedDict, total=False):
    decompiled_functions: dict
    strings_of_interest: list[str]
    binary_info: dict


class ParamExtractionOutput(TypedDict, total=False):
    extracted_params: dict


# ---------------------------------------------------------------------------
# Tool Router
# ---------------------------------------------------------------------------
class ToolRouterInput(TypedDict, total=False):
    challenge_type: str
    extracted_params: dict
    flag_format: str
    solve_workspace: str
    challenge_dir: str
    challenge_path: str
    challenge_files: dict
    challenge_description: str
    decompiled_functions: dict
    strings_of_interest: list[str]


class ToolRouterOutput(TypedDict, total=False):
    tool_cascade_results: list[dict]
    tool_results_summary: str
    tool_flag_candidate: str
    recent_actions: list[dict]


# ---------------------------------------------------------------------------
# Solve Engine
# ---------------------------------------------------------------------------
class SolveEngineInput(TypedDict, total=False):
    # Challenge metadata
    challenge_id: str
    challenge_path: str
    challenge_dir: str
    challenge_description: str
    flag_format: str
    category: str
    solve_workspace: str
    # Analysis artifacts
    decompiled_functions: dict
    call_graph: dict
    strings_of_interest: list[str]
    binary_info: dict
    function_annotations: dict
    angr_results: dict
    dynamic_traces: list[dict]
    challenge_files: dict
    remote_info: dict
    # Strategy / solve state
    challenge_type: str
    secondary_types: list[str]
    current_strategy: str
    strategy_hypothesis: str
    failure_diagnosis: str
    script_findings: list[str]
    solve_scripts: list[dict]
    current_attempt: dict
    rejected_flags: list[str]
    # Tool router output
    extracted_params: dict
    tool_results_summary: str
    # Context
    solve_ledger_path: str
    benchmark: bool
    iteration_count: int


class SolveEngineOutput(TypedDict, total=False):
    solve_scripts: list[dict]
    current_attempt: dict
    failure_diagnosis: str
    script_findings: list[str]
    recent_actions: list[dict]
    error_log: list[dict]
    iteration_count: int


# ---------------------------------------------------------------------------
# Flag Validator
# ---------------------------------------------------------------------------
class FlagValidatorInput(TypedDict, total=False):
    flag_format: str
    solve_scripts: list[dict]
    current_attempt: dict
    tool_flag_candidate: str
    challenge_path: str
    strings_of_interest: list[str]
    current_strategy: str
    solve_ledger_path: str
    rejected_flags: list[str]
    iteration_count: int


class FlagValidatorOutput(TypedDict, total=False):
    flag: str
    next_node: str
    failure_diagnosis: str
    script_findings: list[str]
    rejected_flags: list[str]
    recent_actions: list[dict]
    error_log: list[dict]
    iteration_count: int


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------
class ManagerInput(TypedDict, total=False):
    # Termination checks
    strategies_tried: list[str]
    iteration_count: int
    solve_scripts: list[dict]
    # Anti-thrash guards
    error_log: list[dict]
    current_attempt: dict
    current_strategy: str
    failure_diagnosis: str
    challenge_type: str
    recent_actions: list[dict]
    # LLM prompt context
    challenge_id: str
    challenge_description: str
    context_summary: str
    compressed_action_count: int
    binary_info: dict
    decompiled_functions: dict
    strings_of_interest: list[str]
    dynamic_traces: list[dict]
    angr_results: dict
    solve_ledger_path: str
    benchmark: bool


class ManagerOutput(TypedDict, total=False):
    next_node: str
    current_strategy: str
    strategy_hypothesis: str
    strategies_tried: list[str]
    recent_actions: list[dict]
    iteration_count: int


# ---------------------------------------------------------------------------
# Context Compressor
# ---------------------------------------------------------------------------
class ContextCompressorInput(TypedDict, total=False):
    recent_actions: list[dict]
    compressed_action_count: int
    context_summary: str
    iteration_count: int


class ContextCompressorOutput(TypedDict, total=False):
    context_summary: str
    compressed_action_count: int
    iteration_count: int


# ---------------------------------------------------------------------------
# Convenience mapping: node name -> (InputSchema, OutputSchema)
# ---------------------------------------------------------------------------
NODE_SCHEMAS: dict[str, tuple[type, type]] = {
    "triage": (TriageInput, TriageOutput),
    "unpack": (UnpackInput, UnpackOutput),
    "decompile": (DecompileInput, DecompileOutput),
    "normalize": (NormalizeInput, NormalizeOutput),
    "classify": (ClassifyInput, ClassifyOutput),
    "constraint_solver": (ConstraintSolverInput, ConstraintSolverOutput),
    "crypto_decode": (CryptoDecodeInput, CryptoDecodeOutput),
    "dynamic_analysis": (DynamicAnalysisInput, DynamicAnalysisOutput),
    "keygen": (KeygenInput, KeygenOutput),
    "pwn_specialist": (PwnSpecialistInput, PwnSpecialistOutput),
    "fuzzing_specialist": (FuzzingSpecialistInput, FuzzingSpecialistOutput),
    "web_specialist": (WebSpecialistInput, WebSpecialistOutput),
    "dotnet_specialist": (DotnetSpecialistInput, DotnetSpecialistOutput),
    "firmware_specialist": (FirmwareSpecialistInput, FirmwareSpecialistOutput),
    "param_extraction": (ParamExtractionInput, ParamExtractionOutput),
    "tool_router": (ToolRouterInput, ToolRouterOutput),
    "solve_engine": (SolveEngineInput, SolveEngineOutput),
    "flag_validator": (FlagValidatorInput, FlagValidatorOutput),
    "manager": (ManagerInput, ManagerOutput),
    "context_compressor": (ContextCompressorInput, ContextCompressorOutput),
}


# ---------------------------------------------------------------------------
# Validated Node Decorator
# ---------------------------------------------------------------------------
def validated_node(input_schema: type, output_schema: type):
    """Debug-mode decorator that warns when nodes return keys outside their schema.

    Usage::

        @validated_node(TriageInput, TriageOutput)
        async def triage(state: KrakenState) -> dict:
            ...

    The decorator only checks the *output* dict at runtime (inputs are the
    full KrakenState and cannot be narrowed without breaking LangGraph).
    Common bookkeeping fields (_BOOKKEEPING_FIELDS) are always allowed.
    """
    output_fields = (
        set(output_schema.__annotations__.keys())
        if hasattr(output_schema, "__annotations__")
        else set()
    )
    allowed = output_fields | _BOOKKEEPING_FIELDS

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(state):
            result = await func(state)
            if isinstance(result, dict):
                extra = set(result.keys()) - allowed
                if extra:
                    log.warning(
                        "schema_extra_output",
                        node=func.__name__,
                        extra_fields=sorted(extra),
                    )
            return result

        # Attach schema metadata for introspection / testing
        wrapper._input_schema = input_schema  # type: ignore[attr-defined]
        wrapper._output_schema = output_schema  # type: ignore[attr-defined]
        return wrapper

    return decorator
