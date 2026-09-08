"""Constraint solver specialist -- orchestrates angr/z3 for input validation challenges.

Enhanced with:
- veritesting for faster exploration
- Multiple stdin lengths (32, 64, 128, 256)
- String-based find/avoid (not just address-based)
- pwntools ELF for PLT address discovery (strcmp/puts as success/failure markers)
"""
from __future__ import annotations

from kraken.state import KrakenState
from kraken.tools.symbolic import angr_find_input, z3_solve
from kraken.logging.structured import get_logger

log = get_logger(__name__)


def _find_plt_addresses(binary_path: str) -> dict:
    """Use pwntools ELF to find PLT addresses for common functions."""
    try:
        from pwn import ELF
        import pwnlib.context
        pwnlib.context.context.log_level = "error"
        elf = ELF(binary_path, checksec=False)
        return {
            "strcmp": elf.plt.get("strcmp", 0),
            "strncmp": elf.plt.get("strncmp", 0),
            "puts": elf.plt.get("puts", 0),
            "printf": elf.plt.get("printf", 0),
            "exit": elf.plt.get("exit", 0),
            "main": elf.symbols.get("main", 0),
        }
    except Exception:
        return {}


async def constraint_solver(state: KrakenState) -> dict:
    """Analyze binary for constraint satisfaction using angr/z3.

    Tries multiple exploration strategies with veritesting and various
    stdin lengths for better coverage.
    """
    from kraken.storage.artifact_store import get_artifact
    binary_path = state["challenge_path"]
    functions = get_artifact(state, "decompiled_functions", "decompiled_functions_handle")
    symbols = state.get("symbols", {})
    strings = state.get("strings_of_interest", [])
    binary_info = state.get("binary_info", {})

    log.info("constraint_solver_start")

    # Look for success/failure addresses in symbols AND decompiled code
    success_indicators = ["correct", "success", "flag", "win", "good", "congratul", "yes"]
    failure_indicators = ["wrong", "fail", "invalid", "bad", "incorrect", "try again", "nope"]

    find_addr = None
    avoid_addrs = []

    # Check symbol names for success/failure
    for name, info in symbols.items():
        name_lower = name.lower()
        if any(ind in name_lower for ind in success_indicators):
            try:
                find_addr = int(info.get("address", "0"), 16)
            except ValueError:
                pass
        if any(ind in name_lower for ind in failure_indicators):
            try:
                avoid_addrs.append(int(info.get("address", "0"), 16))
            except ValueError:
                pass

    # If no addresses from symbols, scan decompiled code for string references
    success_funcs = []
    failure_funcs = []
    if not find_addr:
        for func_name, code in functions.items():
            code_lower = code.lower()
            for indicator in success_indicators:
                if indicator in code_lower:
                    success_funcs.append(func_name)
                    log.info("constraint_success_in_func", function=func_name, indicator=indicator)
            for indicator in failure_indicators:
                if indicator in code_lower:
                    failure_funcs.append(func_name)
                    log.info("constraint_failure_in_func", function=func_name, indicator=indicator)

    # Use PLT addresses for strcmp/puts as success/failure markers
    plt_addrs = _find_plt_addresses(binary_path)

    # Build string-based find/avoid for angr_trace
    find_strings = [s for s in success_indicators if any(s in st.lower() for st in strings)]
    avoid_strings = [s for s in failure_indicators if any(s in st.lower() for st in strings)]

    angr_data = {}

    # Strategy 1: Address-based exploration (if we have addresses)
    if find_addr:
        log.info("constraint_angr_explore", find=hex(find_addr), avoid=[hex(a) for a in avoid_addrs])
        angr_result = await angr_find_input(
            binary_path, find_addr=find_addr, avoid_addrs=avoid_addrs, stdin_length=64, timeout=120,
        )
        angr_data = angr_result.data or {}
        if angr_data.get("satisfiable"):
            log.info("constraint_angr_result", satisfiable=True, strategy="address_based")
            return _build_result(state, angr_data, find_addr)

    # Strategy 2: String-based exploration with angr_trace (multiple stdin lengths)
    if find_strings or avoid_strings:
        log.info("constraint_angr_string_explore", find=find_strings, avoid=avoid_strings)
        try:
            from kraken.tools.dynamic import angr_trace
            trace_result = await angr_trace(
                binary_path,
                find_strings=find_strings or ["correct", "flag", "success", "win"],
                avoid_strings=avoid_strings or ["wrong", "fail", "invalid", "incorrect"],
                stdin_lengths=[32, 64, 128],
                use_veritesting=True,
                timeout=180,
            )
            if trace_result.success and trace_result.data:
                if trace_result.data.get("satisfiable"):
                    angr_data = trace_result.data
                    log.info("constraint_angr_result", satisfiable=True, strategy="string_based")
                    return _build_result(state, angr_data, find_addr)
                # Merge partial results
                angr_data.update(trace_result.data)
        except Exception as e:
            log.warning("constraint_angr_trace_failed", error=str(e))

    # Strategy 3: Try with PLT-based find/avoid (strcmp as success marker)
    if plt_addrs.get("strcmp") and not angr_data.get("satisfiable"):
        log.info("constraint_angr_plt_explore", strcmp=hex(plt_addrs["strcmp"]))
        for stdin_len in [32, 64, 128, 256]:
            angr_result = await angr_find_input(
                binary_path,
                find_addr=plt_addrs["strcmp"],
                avoid_addrs=[a for a in [plt_addrs.get("exit", 0)] if a],
                stdin_length=stdin_len,
                timeout=60,
            )
            if angr_result.data and angr_result.data.get("satisfiable"):
                angr_data = angr_result.data
                log.info("constraint_angr_result", satisfiable=True, strategy="plt_based", stdin_len=stdin_len)
                return _build_result(state, angr_data, plt_addrs["strcmp"])

    log.info("constraint_angr_result", satisfiable=angr_data.get("satisfiable", False))
    return _build_result(state, angr_data, find_addr)


def _build_result(state: KrakenState, angr_data: dict, find_addr: int | None) -> dict:
    # Build actionable specialist summary
    sat = angr_data.get("satisfiable", False)
    if sat:
        sol = angr_data.get("solution_ascii", angr_data.get("solution", ""))
        summary = f"angr: SATISFIABLE. Solution found: {str(sol)[:100]}"
    else:
        strategies_tried = []
        if find_addr:
            strategies_tried.append(f"address-based (find={hex(find_addr)})")
        strategies_tried.append("string-based find/avoid")
        strategies_tried.append("PLT-based (strcmp/exit)")
        summary = f"angr: UNSATISFIABLE. Tried: {', '.join(strategies_tried)}. Consider: different stdin length, z3 manual constraints, or binary patching."

    return {
        "angr_results": angr_data,
        "strategy_hypothesis": summary,
        "recent_actions": [{
            "action": "constraint_solver",
            "reasoning": f"angr symbolic execution (find={hex(find_addr) if find_addr else 'string-based'})",
            "result_summary": summary,
        }],
        "iteration_count": state.get("iteration_count", 0) + 1,
    }
