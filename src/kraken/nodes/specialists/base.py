"""Base utilities for specialist subgraphs."""
from __future__ import annotations

from typing import Any, TypedDict

from kraken.storage.artifact_store import get_artifact
from kraken.logging.structured import get_logger

log = get_logger(__name__)


class SpecialistInput(TypedDict, total=False):
    """Common input fields for specialist subgraphs."""
    challenge_path: str
    challenge_dir: str
    binary_info: dict
    decompiled_functions: dict
    strings_of_interest: list[str]
    symbols: dict
    function_annotations: dict
    challenge_files: dict
    solve_workspace: str


class SpecialistOutput(TypedDict, total=False):
    """Common output fields from specialist subgraphs."""
    strategy_hypothesis: str
    angr_results: dict
    recent_actions: list[dict]
    iteration_count: int


def build_specialist_input(state: dict) -> SpecialistInput:
    """Extract narrow input from full KrakenState for specialist subgraph."""
    return SpecialistInput(
        challenge_path=state.get("challenge_path", ""),
        challenge_dir=state.get("challenge_dir", ""),
        binary_info=state.get("binary_info", {}),
        decompiled_functions=get_artifact(state, "decompiled_functions", "decompiled_functions_handle"),
        strings_of_interest=state.get("strings_of_interest", []),
        symbols=state.get("symbols", {}),
        function_annotations=state.get("function_annotations", {}),
        challenge_files=state.get("challenge_files", {}),
        solve_workspace=state.get("solve_workspace", ""),
    )
