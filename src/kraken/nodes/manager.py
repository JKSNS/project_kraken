"""Manager node -- LLM (high) for strategic decisions and retry routing.

Only fires on failure (happy path never touches this node).
Analyzes what went wrong and routes to the best next action.

Enhancement: strategy diversity enforcement (#10) -- categorizes strategies
and prevents routing to the same specialist category repeatedly.
Enhancement: adds 'pwn_specialist' as a valid routing target (#11).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from jinja2 import Environment, FileSystemLoader
from pydantic import BaseModel, Field

from kraken.state import KrakenState
from kraken.models import structured_generate
from kraken.config import ModelConfig, BudgetConfig
from kraken.storage.artifact_store import get_artifact
from kraken.logging.structured import get_logger
from kraken.storage.ledger import append_ledger_entry, read_ledger_all

log = get_logger(__name__)

_PROMPTS_DIR = Path(__file__).resolve().parent.parent / "prompts"


# ── Strategy diversity helpers (#10) ─────────────────────────────────

# Map specialist node names to broad strategy categories
_NODE_CATEGORIES = {
    "constraint_solver": "symbolic",
    "crypto_decode": "crypto",
    "dynamic_analysis": "dynamic",
    "keygen": "keygen",
    "pwn_specialist": "pwn",
    "fuzzing_specialist": "fuzzing",
    "web_specialist": "web",
    "dotnet_specialist": "dotnet",
    "firmware_specialist": "firmware",
    "solve_engine": "solve",
    "triage": "reanalysis",
    "decompile": "reanalysis",
    "normalize": "reanalysis",
    "classify": "reclassify",
    "context_compressor": "housekeeping",
}


def _categorize_strategies(strategies_tried: list[str], solve_scripts: list[dict]) -> dict:
    """Categorize previously tried strategies into broad categories.

    Returns dict mapping category -> count of times used.
    """
    categories: dict[str, int] = {}
    for s in strategies_tried:
        s_lower = s.lower()
        # Infer category from strategy description keywords
        if any(kw in s_lower for kw in ["angr", "symbolic", "z3", "constraint", "sat"]):
            cat = "symbolic"
        elif any(kw in s_lower for kw in ["xor", "crypto", "cipher", "encrypt", "decrypt", "base64", "encoding"]):
            cat = "crypto"
        elif any(kw in s_lower for kw in ["dynamic", "trace", "ptrace", "patch", "anti-debug", "runtime"]):
            cat = "dynamic"
        elif any(kw in s_lower for kw in ["keygen", "key gen", "key check", "reverse key"]):
            cat = "keygen"
        elif any(kw in s_lower for kw in ["pwn", "overflow", "rop", "format string", "exploit"]):
            cat = "pwn"
        elif any(kw in s_lower for kw in ["brute", "brute-force", "bruteforce"]):
            cat = "bruteforce"
        elif any(kw in s_lower for kw in ["lief", "patch", "binary patch"]):
            cat = "patching"
        elif any(kw in s_lower for kw in ["fuzz", "harness", "afl", "libfuzzer", "mutation"]):
            cat = "fuzzing"
        elif any(kw in s_lower for kw in ["web", "http", "xss", "sqli", "ssrf", "ssti"]):
            cat = "web"
        elif any(kw in s_lower for kw in ["firmware", "embedded", "binwalk", "uart", "iot"]):
            cat = "firmware"
        else:
            cat = "other"
        categories[cat] = categories.get(cat, 0) + 1
    return categories


def _build_diversity_hint(strategies_tried: list[str], solve_scripts: list[dict]) -> str:
    """Build a hint about strategy diversity for the manager prompt."""
    if not strategies_tried:
        return ""

    cats = _categorize_strategies(strategies_tried, solve_scripts)
    if not cats:
        return ""

    overused = [cat for cat, count in cats.items() if count >= 2]
    all_categories = ["symbolic", "crypto", "dynamic", "keygen", "pwn", "fuzzing", "web", "firmware", "bruteforce", "patching"]
    untried = [cat for cat in all_categories if cat not in cats]

    parts = [f"Strategy categories tried: {', '.join(f'{c}({n})' for c, n in cats.items())}"]
    if overused:
        parts.append(f"OVERUSED categories (tried 2+ times): {', '.join(overused)} -- avoid these")
    if untried:
        parts.append(f"UNTRIED categories: {', '.join(untried)} -- strongly prefer these")
    return "\n".join(parts)


def _strategy_update_if_new(state: KrakenState, strategy_key: str) -> dict:
    """Return reducer update for strategies_tried only when strategy is new."""
    tried = state.get("strategies_tried", [])
    if strategy_key in tried:
        return {}
    return {"strategies_tried": [strategy_key]}


def _append_strategy_pivot(state: KrakenState, old_strategy: str, reason: str, new_strategy: str) -> None:
    append_ledger_entry(
        state.get("solve_ledger_path", ""),
        f"> STRATEGY PIVOT: Abandoning [{old_strategy or 'none'}] because [{reason}]. Moving to [{new_strategy or 'unknown'}].",
    )

def _racing_escalation_route(state: KrakenState, solve_attempts: int) -> dict | None:
    """Pivot to Codex agentic fallback as a last resort before give_up.

    Only fires when Codex fallback is enabled, hasn't been tried yet,
    and the challenge has exhausted enough normal attempts.
    """
    from kraken.execution.racing import is_codex_fallback_enabled
    from kraken.config import ModelConfig

    if not is_codex_fallback_enabled():
        return None
    if state.get("racing_attempted"):
        return None

    cfg = ModelConfig()
    if solve_attempts < cfg.racing_threshold:
        return None

    return {
        "next_node": "solve_engine",
        "current_strategy": "codex_fallback",
        "strategy_hypothesis": (
            "Normal strategies exhausted. Pivoting to Codex -- an independent "
            "agentic solver that reads files and iterates autonomously."
        ),
        "racing_attempted": True,
        "recent_actions": [{
            "action": "manager",
            "reasoning": f"Pivoting to Codex fallback after {solve_attempts} failed solve attempts",
            "result_summary": "Route -> solve_engine (codex fallback)",
        }],
        "strategies_tried": ["codex_fallback"],
        "iteration_count": state.get("iteration_count", 0) + 1,
    }


def _contract_thrash_route(state: KrakenState) -> dict | None:
    """Detect repeated solve-script contract failures and force a delta action route."""
    errors = [
        str(e.get("error", ""))
        for e in state.get("error_log", [])[-8:]
        if e.get("node") == "solve_engine"
    ]
    contract_hits = [e for e in errors if "Script must" in e or "contract" in e or "Banned import" in e]
    if len(contract_hits) < 3:
        return None

    ctype = state.get("challenge_type", "")
    if ctype == "crypto":
        next_node = "crypto_decode"
        strat = "extract concrete crypto constants before codegen"
    elif ctype == "dynamic":
        next_node = "dynamic_analysis"
        strat = "collect runtime traces before codegen"
    else:
        next_node = "classify"
        strat = "reclassify with contract-failure context"

    updates = {
        "next_node": next_node,
        "current_strategy": f"contract_recovery: {strat}",
        "strategy_hypothesis": "Repeated solve_engine contract rejections detected; forcing artifact collection instead of another immediate codegen attempt.",
        "recent_actions": [{
            "action": "manager",
            "reasoning": "Detected repeated solve script contract failures",
            "result_summary": f"Route -> {next_node}: gather deterministic artifacts before next solve_engine run",
        }],
        "iteration_count": state.get("iteration_count", 0) + 1,
    }
    updates.update(_strategy_update_if_new(state, "contract_recovery"))
    _append_strategy_pivot(state, state.get("current_strategy", ""), "repeated solve script contract failures", updates["current_strategy"])
    return updates


def _no_output_thrash_route(state: KrakenState) -> dict | None:
    """Detect repeated exit=0+no-output attempts and force artifact extraction routes."""
    scripts = state.get("solve_scripts", [])[-6:]
    current = state.get("current_attempt", {})
    if isinstance(current, dict) and current:
        scripts = [*scripts, current]
    no_output = [s for s in scripts if s.get("exit_code") == 0 and not str(s.get("stdout", "")).strip()]
    if len(no_output) < 3:
        return None

    ctype = state.get("challenge_type", "")
    if ctype == "crypto":
        if len(no_output) >= 5:
            next_node = "dynamic_analysis"
            strat = "capture concrete crypto material via runtime traces/memory instead of another static extraction pass"
        else:
            next_node = "crypto_decode"
            strat = "extract concrete key/iv/ciphertext constants before next solve"
    elif ctype in {"dynamic", "pwn"}:
        next_node = "dynamic_analysis"
        strat = "collect runtime traces and concrete buffers before next solve"
    else:
        next_node = "classify"
        strat = "reclassify with no-output failure context"

    updates = {
        "next_node": next_node,
        "current_strategy": f"no_output_recovery: {strat}",
        "strategy_hypothesis": "Repeated scripts exited 0 but produced no output; forcing deterministic artifact extraction before further codegen.",
        "recent_actions": [{
            "action": "manager",
            "reasoning": "Detected repeated no-output solve attempts",
            "result_summary": f"Route -> {next_node}: gather concrete artifacts to avoid empty-output retries",
        }],
        "iteration_count": state.get("iteration_count", 0) + 1,
    }
    updates.update(_strategy_update_if_new(state, "no_output_recovery"))
    _append_strategy_pivot(state, state.get("current_strategy", ""), "repeated exit=0 with no output", updates["current_strategy"])
    return updates




def _helper_pivot_route(state: KrakenState) -> dict | None:
    """Force explicit helper-script pivots for typo-prone solve failures.

    Triggers when recent attempts show:
    - z3/python transcription crashes (TypeError/IndexError), or
    - repeated UNSAT/No-solution outputs.
    """
    scripts = state.get("solve_scripts", [])[-8:]
    current = state.get("current_attempt", {})
    if isinstance(current, dict) and current:
        scripts = [*scripts, current]
    if not scripts:
        return None

    recent = scripts[-4:]
    diagnosis = str(state.get("failure_diagnosis", "")).lower()

    unsat_or_no_solution = 0
    for att in recent:
        combined = f"{att.get('stdout', '')}\n{att.get('stderr', '')}".lower()
        if "no solution found" in combined or "unsat" in combined or "unsatisfiable" in combined:
            unsat_or_no_solution += 1

    latest = recent[-1]
    latest_err = str(latest.get("stderr", "")).lower()
    z3_typo_crash = (
        "typeerror" in latest_err
        or "indexerror" in latest_err
        or ("z3" in latest_err and ("typeerror" in latest_err or "index" in latest_err))
        or "index_error" in diagnosis
        or "type_error" in diagnosis
    )

    if not z3_typo_crash and unsat_or_no_solution < 2:
        return None

    current_strategy = str(state.get("current_strategy", "")).lower()
    if "auto_angr.py" not in current_strategy:
        helper_instruction = (
            "Pivot to helper-first: run `./auto_angr.py <binary> --find \"Correct!\"` first; "
            "if no solve, continue with `./auto_c_brute.py --globals g.c --logic l.c --length <N>` "
            "or `./auto_regex_z3.py decompile.c --length <N>`."
        )
        new_strategy = "helper_pivot: auto_angr first, then auto_c_brute/auto_regex_z3 fallback"
    elif "auto_c_brute.py" not in current_strategy:
        helper_instruction = (
            "Run `./auto_c_brute.py --globals g.c --logic l.c --length <N>` using exact Ghidra logic, "
            "then validate candidate through the binary."
        )
        new_strategy = "helper_pivot: auto_c_brute for exact C-semantics brute"
    else:
        helper_instruction = (
            "Run `./auto_regex_z3.py decompile.c --length <N>` to auto-parse repetitive equations and avoid typo drift."
        )
        new_strategy = "helper_pivot: auto_regex_z3 parser-driven constraints"

    reason = "Detected typo-prone solve failures (Z3/python crash or repeated UNSAT/no-solution); enforcing explicit helper pivot."
    updates = {
        "next_node": "solve_engine",
        "current_strategy": new_strategy,
        "strategy_hypothesis": helper_instruction,
        "recent_actions": [{
            "action": "manager",
            "reasoning": reason,
            "result_summary": f"Route -> solve_engine: {helper_instruction[:130]}",
        }],
        "iteration_count": state.get("iteration_count", 0) + 1,
    }
    updates.update(_strategy_update_if_new(state, "helper_pivot_recovery"))
    _append_strategy_pivot(state, state.get("current_strategy", ""), reason, new_strategy)
    return updates



def _python_error_persistence_route(state: KrakenState) -> dict | None:
    """Keep conceptual strategy and debug Python errors before category pivots.

    SOP: code crashes imply implementation bugs, not necessarily strategy failure.
    For repeated Python runtime errors, route back to solve_engine with explicit
    debugging instructions and preserve current_strategy for up to 3 attempts.
    """
    scripts = state.get("solve_scripts", [])
    current_attempt = state.get("current_attempt", {})
    if isinstance(current_attempt, dict) and current_attempt:
        scripts = [*scripts, current_attempt]
    if not scripts:
        return None

    latest = scripts[-1]
    if int(latest.get("exit_code", 0) or 0) == 0:
        return None

    stderr = str(latest.get("stderr", ""))
    py_markers = ["traceback", "indexerror", "typeerror", "nameerror", "syntaxerror", "attributeerror", "valueerror"]
    if not any(m in stderr.lower() for m in py_markers):
        return None

    # Count recent Python-crash attempts for same conceptual strategy
    current = str(state.get("current_strategy", "")).strip()
    recent = scripts[-6:]
    same_strategy_py_errors = 0
    for att in recent:
        if int(att.get("exit_code", 0) or 0) == 0:
            continue
        if current and str(att.get("strategy", "")).strip() != current:
            continue
        se = str(att.get("stderr", "")).lower()
        if any(m in se for m in py_markers):
            same_strategy_py_errors += 1

    if same_strategy_py_errors >= 3:
        return None

    diagnosis = str(state.get("failure_diagnosis", ""))
    idx_hint = ""
    if "index_error" in diagnosis.lower() or "indexerror" in stderr.lower():
        idx_hint = " Avoid transformation arrays/lambda tables; flatten assignments line-by-line."

    strategy = current or "debug current approach"
    updates = {
        "next_node": "solve_engine",
        "current_strategy": strategy,
        "strategy_hypothesis": (
            "Python implementation failure detected; keep strategy and debug script before pivoting categories."
            + idx_hint
        ),
        "recent_actions": [{
            "action": "manager",
            "reasoning": "SOP persistence: python crash indicates code bug, not strategy invalidation",
            "result_summary": "Route -> solve_engine: debug current strategy implementation",
        }],
        "iteration_count": state.get("iteration_count", 0) + 1,
    }
    updates.update(_strategy_update_if_new(state, "python_debug_persistence"))
    _append_strategy_pivot(state, state.get("current_strategy", ""), "python runtime crash persistence", strategy)
    return updates


def _manager_stall_route(state: KrakenState) -> dict | None:
    """Break loops where manager keeps returning solve_engine with near-identical strategy."""
    actions = state.get("recent_actions", [])[-8:]
    manager_actions = [a for a in actions if a.get("action") == "manager"]
    if len(manager_actions) < 3:
        return None

    # If all recent manager decisions route back to solve_engine, force a specialist pivot.
    recent_results = [str(a.get("result_summary", "")).lower() for a in manager_actions[-3:]]
    if not all("route -> solve_engine" in r for r in recent_results):
        return None

    ctype = (state.get("challenge_type", "") or "").lower()
    if ctype == "crypto":
        next_node = "dynamic_analysis"
        strat = "manager_stall_breaker: validate transform constants via runtime traces and memory snapshots"
        reason = "manager repeatedly routed to solve_engine without convergence"
    elif ctype in {"dynamic", "pwn"}:
        next_node = "classify"
        strat = "manager_stall_breaker: reclassify challenge to break repeated solve-engine loops"
        reason = "manager repeatedly routed to solve_engine without convergence"
    else:
        next_node = "classify"
        strat = "manager_stall_breaker: force reclassification after repeated solve-engine loops"
        reason = "manager repeatedly routed to solve_engine without convergence"

    updates = {
        "next_node": next_node,
        "current_strategy": strat,
        "strategy_hypothesis": "Repeated manager-to-solve_engine loops detected; forcing specialist pivot to gather new deterministic artifacts.",
        "recent_actions": [{
            "action": "manager",
            "reasoning": reason,
            "result_summary": f"Route -> {next_node}: stall breaker pivot",
        }],
        "iteration_count": state.get("iteration_count", 0) + 1,
    }
    updates.update(_strategy_update_if_new(state, "manager_stall_breaker"))
    _append_strategy_pivot(state, state.get("current_strategy", ""), reason, strat)
    return updates


def _loop_detection_route(state: KrakenState) -> dict | None:
    """Break out of detected repetitive loops via sliding-window analysis.

    Checks two signals:
      1. Node-cycle: the graph is visiting the same sequence of nodes repeatedly
         (e.g. manager -> solve_engine -> flag_validator -> manager x5)
      2. Script-repeat: the solve_engine is generating near-identical code across
         attempts (same content hash submitted 3+ times)

    On "break" verdict, forces a hard specialist pivot to break the cycle.
    On "warn" verdict, injects an explicit warning into the strategy hypothesis
    but allows the normal manager LLM call to proceed (returns None).
    """
    from kraken.execution.loop_detect import (
        check_node_cycle,
        check_solve_script_loop,
        VERDICT_BREAK,
        VERDICT_WARN,
        LOOP_WARNING,
    )

    node_verdict = check_node_cycle(state)
    script_verdict = check_solve_script_loop(state)

    # Take the more severe verdict
    if node_verdict == VERDICT_BREAK or script_verdict == VERDICT_BREAK:
        ctype = (state.get("challenge_type") or "").lower()
        # Pick a specialist we haven't exhausted yet
        tried_cats = _categorize_strategies(
            state.get("strategies_tried", []),
            state.get("solve_scripts", []),
        )
        # Priority order of escape hatches
        escape_nodes = [
            ("dynamic_analysis", "dynamic"),
            ("classify", "reclassify"),
            ("crypto_decode", "crypto"),
            ("constraint_solver", "symbolic"),
            ("pwn_specialist", "pwn"),
            ("fuzzing_specialist", "fuzzing"),
        ]
        next_node = "classify"
        for node, cat in escape_nodes:
            if tried_cats.get(cat, 0) < 2:
                next_node = node
                break

        loop_type = []
        if node_verdict == VERDICT_BREAK:
            loop_type.append("node-cycle")
        if script_verdict == VERDICT_BREAK:
            loop_type.append("script-repeat")

        strat = f"loop_break: forced pivot after {'+'.join(loop_type)} detection"
        reason = f"Loop detector triggered ({'+'.join(loop_type)}); forcing hard pivot to {next_node}"

        append_ledger_entry(
            state.get("solve_ledger_path", ""),
            f"> LOOP BREAK: {reason}",
        )

        updates = {
            "next_node": next_node,
            "current_strategy": strat,
            "strategy_hypothesis": LOOP_WARNING,
            "recent_actions": [{
                "action": "manager",
                "reasoning": reason,
                "result_summary": f"Route -> {next_node}: loop breaker pivot",
            }],
            "iteration_count": state.get("iteration_count", 0) + 1,
        }
        updates.update(_strategy_update_if_new(state, "loop_detection_pivot"))
        _append_strategy_pivot(state, state.get("current_strategy", ""), reason, strat)
        return updates

    # "warn" verdict: don't force a route, but we'll let the caller know
    # so the warning can be injected into the LLM prompt context.
    # (Handled by the caller checking state annotations.)
    return None


def _programmatic_extraction_pivot_route(state: KrakenState) -> dict | None:
    """Force programmatic strategies when repeated UNSAT/no-solution appears.

    Option ladder:
      1) Regex Parsing Script (programmatic Z3)
      2) Lazy C Wrapper (compile+run extracted C logic)
      3) Dynamic Analysis (angr/gdb)
    """
    scripts = state.get("solve_scripts", [])[-10:]
    current = state.get("current_attempt", {})
    if isinstance(current, dict) and current:
        scripts = [*scripts, current]

    no_solution_hits = 0
    unsat_hits = 0
    for att in scripts:
        stdout = str(att.get("stdout", "") or "").lower()
        stderr = str(att.get("stderr", "") or "").lower()
        if "no solution found" in stdout:
            no_solution_hits += 1
        if "unsat" in stdout or "unsat" in stderr or "unsatisfiable" in stdout or "unsatisfiable" in stderr:
            unsat_hits += 1

    if (no_solution_hits + unsat_hits) < 2:
        return None

    current_strategy = str(state.get("current_strategy", "")).lower()
    strategies_tried = [s.lower() for s in state.get("strategies_tried", [])]

    # Suggest approaches not yet tried, prioritizing most likely to work
    if "angr" not in current_strategy and not any("angr" in s for s in strategies_tried):
        next_node = "solve_engine"
        new_strategy = "strategy pivot: try angr symbolic execution or auto_angr.py helper"
        task = (
            "Previous constraint approach failed with UNSAT. Try symbolic execution with angr -- "
            "either use ./auto_angr.py or write a custom angr script targeting the success path."
        )
    elif "brute" not in current_strategy and not any("brute" in s for s in strategies_tried):
        next_node = "solve_engine"
        new_strategy = "strategy pivot: direct brute-force or per-byte solving"
        task = (
            "Symbolic approaches failed. Try brute-forcing: per-byte forward search through "
            "printable ASCII, or use ./auto_c_brute.py with extracted C logic."
        )
    else:
        next_node = "solve_engine"
        new_strategy = "strategy pivot: try a completely different technique"
        task = (
            "Multiple constraint/brute-force approaches failed. Try something fundamentally different: "
            "dynamic analysis with GDB, binary patching to bypass checks, regex-based constraint extraction "
            "with ./auto_regex_z3.py, or a custom targeted solution based on what previous attempts revealed."
        )

    reason = (
        "Repeated UNSAT/No-solution outputs indicate the current approach isn't working; pivoting to a different strategy"
    )
    updates = {
        "next_node": next_node,
        "current_strategy": new_strategy,
        "strategy_hypothesis": reason,
        "recent_actions": [{
            "action": "manager",
            "reasoning": reason,
            "result_summary": f"Route -> {next_node}: {task[:110]}",
        }],
        "iteration_count": state.get("iteration_count", 0) + 1,
    }
    updates.update(_strategy_update_if_new(state, "programmatic_extraction_pivot"))
    _append_strategy_pivot(state, state.get("current_strategy", ""), reason, new_strategy)
    return updates

class ManagerDecision(BaseModel):
    """Structured output for manager routing decisions."""
    reasoning: str = Field(description="Why this decision was made")
    next_node: Literal[
        "triage", "decompile", "normalize", "classify",
        "constraint_solver", "crypto_decode", "dynamic_analysis", "keygen",
        "pwn_specialist", "fuzzing_specialist", "web_specialist", "dotnet_specialist",
        "firmware_specialist", "solve_engine", "context_compressor", "give_up"
    ]
    new_strategy: str = Field(description="Updated strategy description")
    task_instruction: str = Field(description="Specific instruction for the target node")


async def manager(state: KrakenState) -> dict:
    """Analyze failure and decide next action."""
    strategies_tried = state.get("strategies_tried", [])
    budget_cfg = BudgetConfig()

    # Check termination conditions
    if len(strategies_tried) >= budget_cfg.max_strategies:
        log.info("manager_give_up", strategies_tried=len(strategies_tried))
        return {
            "next_node": "give_up",
            "recent_actions": [{
                "action": "manager",
                "reasoning": f"Exhausted {len(strategies_tried)} strategies, giving up",
                "result_summary": "GIVE_UP: max strategies reached",
            }],
        }

    if state.get("iteration_count", 0) >= budget_cfg.max_steps:
        log.info("manager_max_steps", steps=state.get("iteration_count", 0))
        return {
            "next_node": "give_up",
            "recent_actions": [{
                "action": "manager",
                "reasoning": f"Max steps ({budget_cfg.max_steps}) reached",
                "result_summary": "GIVE_UP: max steps exceeded",
            }],
        }

    # Hard stop on repeated solve_engine attempts to prevent endless thrash loops
    solve_attempts = len(state.get("solve_scripts", []))
    if solve_attempts >= budget_cfg.max_solve_attempts:
        # Before giving up: try racing if available and not yet attempted
        racing_route = _racing_escalation_route(state, solve_attempts)
        if racing_route is not None:
            log.info("manager_racing_escalation", solve_attempts=solve_attempts)
            return racing_route
        log.info("manager_max_solve_attempts", solve_attempts=solve_attempts)
        return {
            "next_node": "give_up",
            "recent_actions": [{
                "action": "manager",
                "reasoning": f"Max solve attempts ({budget_cfg.max_solve_attempts}) reached",
                "result_summary": "GIVE_UP: max solve attempts exceeded",
            }],
        }

    # Deterministic anti-thrash guard before any LLM call
    forced_route = _contract_thrash_route(state)
    if forced_route is not None:
        log.info("manager_contract_thrash_guard", next_node=forced_route.get("next_node"))
        return forced_route

    forced_no_output = _no_output_thrash_route(state)
    if forced_no_output is not None:
        log.info("manager_no_output_thrash_guard", next_node=forced_no_output.get("next_node"))
        return forced_no_output

    forced_helper_pivot = _helper_pivot_route(state)
    if forced_helper_pivot is not None:
        log.info("manager_helper_pivot", next_node=forced_helper_pivot.get("next_node"))
        return forced_helper_pivot

    forced_py_debug = _python_error_persistence_route(state)
    if forced_py_debug is not None:
        log.info("manager_python_error_persistence", next_node=forced_py_debug.get("next_node"))
        return forced_py_debug

    forced_stall_break = _manager_stall_route(state)
    if forced_stall_break is not None:
        log.info("manager_stall_breaker", next_node=forced_stall_break.get("next_node"))
        return forced_stall_break

    forced_loop_break = _loop_detection_route(state)
    if forced_loop_break is not None:
        log.info("manager_loop_detection", next_node=forced_loop_break.get("next_node"))
        return forced_loop_break

    forced_programmatic = _programmatic_extraction_pivot_route(state)
    if forced_programmatic is not None:
        log.info("manager_programmatic_extraction_pivot", next_node=forced_programmatic.get("next_node"))
        return forced_programmatic

    # Build strategy diversity hint (#10)
    diversity_hint = _build_diversity_hint(
        strategies_tried, state.get("solve_scripts", [])
    )

    # Render manager prompt
    env = Environment(loader=FileSystemLoader(str(_PROMPTS_DIR)))
    template = env.get_template("manager.j2")

    prompt = template.render(
        challenge_id=state.get("challenge_id", "unknown"),
        challenge_description=state.get("challenge_description", ""),
        current_strategy=state.get("current_strategy", "none"),
        strategies_tried=strategies_tried,
        context_summary=state.get("context_summary", ""),
        recent_actions=state.get("recent_actions", []),
        compressed_action_count=state.get("compressed_action_count", 0),
        error_log=state.get("error_log", []),
        binary_info=state.get("binary_info", {}),
        functions_count=len(get_artifact(state, "decompiled_functions", "decompiled_functions_handle")),
        strings_count=len(state.get("strings_of_interest", [])),
        traces_count=len(state.get("dynamic_traces", [])),
        angr_results=state.get("angr_results", {}),
        diversity_hint=diversity_hint,
        solve_ledger=read_ledger_all(state.get("solve_ledger_path", "")),
    )

    cfg = ModelConfig()
    decision: ManagerDecision | None = None

    # Strategy 1: structured_generate (JSON parse from generate call)
    try:
        schema = ManagerDecision.model_json_schema()
        parsed = await structured_generate(prompt, "high", cfg, schema)
        if isinstance(parsed, dict):
            alias_map = {
                "symbolic": "constraint_solver",
                "crypto": "crypto_decode",
                "dynamic": "dynamic_analysis",
                "pwn": "pwn_specialist",
                "web": "web_specialist",
                "firmware": "firmware_specialist",
                "dotnet": "dotnet_specialist",
            }
            nn = str(parsed.get("next_node", "")).strip()
            if nn in alias_map:
                parsed["next_node"] = alias_map[nn]
        decision = ManagerDecision.model_validate(parsed)
        log.info("manager_structured_success")
    except Exception as exc:
        log.warning("manager_structured_failed", error=str(exc))

    # Strategy 3: heuristic -- give up gracefully
    if decision is None:
        log.warning("manager_all_strategies_failed_using_heuristic")
        decision = ManagerDecision(
            reasoning="Manager could not produce valid JSON; defaulting to give_up",
            next_node="give_up",
            new_strategy="give_up_parse_failure",
            task_instruction="No valid routing decision could be made",
        )

    log.info(
        "manager_decision",
        next_node=decision.next_node,
        strategy=decision.new_strategy[:100],
        reasoning=decision.reasoning[:200],
    )

    updates: dict = {
        "next_node": decision.next_node if decision.next_node != "give_up" else "__end__",
        "current_strategy": decision.new_strategy,
        "strategy_hypothesis": decision.reasoning,
        "recent_actions": [{
            "action": "manager",
            "reasoning": decision.reasoning,
            "result_summary": f"Route -> {decision.next_node}: {decision.task_instruction[:100]}",
        }],
        "iteration_count": state.get("iteration_count", 0) + 1,
    }

    # Track new strategy
    if decision.new_strategy and decision.new_strategy not in strategies_tried:
        updates["strategies_tried"] = [decision.new_strategy]

    if decision.new_strategy != state.get("current_strategy", ""):
        _append_strategy_pivot(
            state,
            state.get("current_strategy", ""),
            decision.reasoning,
            decision.new_strategy,
        )

    return updates


def route_from_manager(state: KrakenState) -> str:
    """Conditional edge: route based on manager's decision."""
    node = state.get("next_node", "__end__")
    if node == "give_up" or node == "__end__":
        return "__end__"
    return node
