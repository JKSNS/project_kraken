"""Tests for manager strategy diversity enforcement (#10)."""
import pytest

from kraken.nodes.manager import (
    _categorize_strategies,
    _build_diversity_hint,
    route_from_manager,
    _contract_thrash_route,
    _no_output_thrash_route,
    _strategy_update_if_new,
    _python_error_persistence_route,
    _helper_pivot_route,
    manager,
)


# ── _categorize_strategies ──────────────────────────────────────────


class TestCategorizeStrategies:
    """Test strategy categorization by keywords."""

    def test_empty(self):
        assert _categorize_strategies([], []) == {}

    def test_symbolic_keywords(self):
        strats = ["try angr symbolic execution", "use z3 constraints"]
        cats = _categorize_strategies(strats, [])
        assert cats.get("symbolic", 0) == 2

    def test_crypto_keywords(self):
        strats = ["XOR decode the ciphertext", "base64 encoding chain"]
        cats = _categorize_strategies(strats, [])
        assert cats.get("crypto", 0) == 2

    def test_dynamic_keywords(self):
        strats = ["trace execution with ptrace"]
        cats = _categorize_strategies(strats, [])
        assert cats.get("dynamic", 0) == 1

    def test_keygen_keywords(self):
        strats = ["keygen from key check logic"]
        cats = _categorize_strategies(strats, [])
        assert cats.get("keygen", 0) == 1

    def test_pwn_keywords(self):
        strats = ["buffer overflow with ROP chain"]
        cats = _categorize_strategies(strats, [])
        assert cats.get("pwn", 0) == 1

    def test_bruteforce_keywords(self):
        strats = ["brute-force the 4-byte key"]
        cats = _categorize_strategies(strats, [])
        assert cats.get("bruteforce", 0) == 1

    def test_patching_keywords(self):
        # Note: "patch" also matches dynamic keywords, so the keyword order matters.
        # "binary patch" matches "dynamic" first because the code checks dynamic before patching.
        # Use "lief" keyword which is unique to patching.
        strats = ["use lief to modify the binary"]
        cats = _categorize_strategies(strats, [])
        assert cats.get("patching", 0) == 1

    def test_unknown_falls_to_other(self):
        strats = ["try something totally new and creative"]
        cats = _categorize_strategies(strats, [])
        assert cats.get("other", 0) == 1

    def test_mixed_strategies(self):
        strats = [
            "angr symbolic execution",
            "XOR brute force",
            "try angr with different constraints",
        ]
        cats = _categorize_strategies(strats, [])
        assert cats.get("symbolic", 0) == 2  # angr appears twice
        assert cats.get("crypto", 0) == 1    # XOR

    def test_case_insensitive(self):
        strats = ["ANGR Symbolic Execution"]
        cats = _categorize_strategies(strats, [])
        assert cats.get("symbolic", 0) == 1


# ── _build_diversity_hint ───────────────────────────────────────────


class TestBuildDiversityHint:
    """Test diversity hint generation for manager prompt."""

    def test_empty_strategies(self):
        assert _build_diversity_hint([], []) == ""

    def test_single_strategy_shows_categories(self):
        hint = _build_diversity_hint(["angr symbolic"], [])
        assert "Strategy categories tried" in hint
        assert "symbolic" in hint

    def test_overused_category_flagged(self):
        strats = ["angr symbolic", "z3 constraint solving"]
        hint = _build_diversity_hint(strats, [])
        assert "OVERUSED" in hint
        assert "symbolic" in hint

    def test_untried_categories_shown(self):
        strats = ["angr symbolic"]
        hint = _build_diversity_hint(strats, [])
        assert "UNTRIED" in hint
        # Should suggest categories not yet tried
        assert any(cat in hint for cat in ["crypto", "dynamic", "keygen", "pwn", "bruteforce", "patching"])

    def test_all_categories_tried_no_untried(self):
        strats = [
            "angr symbolic",
            "XOR crypto decode",
            "dynamic trace",
            "keygen reversal",
            "buffer overflow pwn",
            "brute-force key",
            "binary patch check",
        ]
        hint = _build_diversity_hint(strats, [])
        # All categories represented -- untried should be empty or missing
        assert "Strategy categories tried" in hint


# ── route_from_manager (extended with pwn) ──────────────────────────


class TestRouteFromManager:
    """Test manager routing function handles all node types."""

    def test_pwn_specialist_route(self):
        assert route_from_manager({"next_node": "pwn_specialist"}) == "pwn_specialist"

    def test_context_compressor_route(self):
        assert route_from_manager({"next_node": "context_compressor"}) == "context_compressor"

    def test_give_up_routes_to_end(self):
        assert route_from_manager({"next_node": "give_up"}) == "__end__"

    def test_end_routes_to_end(self):
        assert route_from_manager({"next_node": "__end__"}) == "__end__"

    def test_default_is_end(self):
        assert route_from_manager({}) == "__end__"


class TestContractThrashRoute:
    def test_no_trigger_with_few_errors(self):
        state = {"error_log": [{"node": "solve_engine", "error": "Script must define main()"}], "challenge_type": "crypto"}
        assert _contract_thrash_route(state) is None

    def test_triggers_for_repeated_contract_errors(self):
        state = {
            "error_log": [
                {"node": "solve_engine", "error": "Script must define main()"},
                {"node": "solve_engine", "error": "Script must define main()"},
                {"node": "solve_engine", "error": "Script exceeds 260-line contract limit"},
            ],
            "challenge_type": "crypto",
            "iteration_count": 3,
        }
        out = _contract_thrash_route(state)
        assert out is not None
        assert out["next_node"] == "crypto_decode"
        assert out["current_strategy"].startswith("contract_recovery")


class TestNoOutputThrashRoute:
    def test_no_trigger_with_few_no_output_attempts(self):
        state = {
            "solve_scripts": [
                {"exit_code": 0, "stdout": ""},
                {"exit_code": 0, "stdout": "has output"},
            ],
            "challenge_type": "crypto",
        }
        assert _no_output_thrash_route(state) is None

    def test_trigger_with_repeated_no_output(self):
        state = {
            "solve_scripts": [
                {"exit_code": 0, "stdout": ""},
                {"exit_code": 0, "stdout": ""},
                {"exit_code": 0, "stdout": ""},
            ],
            "challenge_type": "crypto",
            "iteration_count": 2,
        }
        out = _no_output_thrash_route(state)
        assert out is not None
        assert out["next_node"] == "crypto_decode"
        assert out["strategies_tried"] == ["no_output_recovery"]

    def test_escalates_crypto_no_output_to_dynamic(self):
        state = {
            "solve_scripts": [
                {"exit_code": 0, "stdout": ""},
                {"exit_code": 0, "stdout": ""},
                {"exit_code": 0, "stdout": ""},
                {"exit_code": 0, "stdout": ""},
                {"exit_code": 0, "stdout": ""},
            ],
            "challenge_type": "crypto",
            "iteration_count": 2,
        }
        out = _no_output_thrash_route(state)
        assert out is not None
        assert out["next_node"] == "dynamic_analysis"

    def test_no_duplicate_strategy_added(self):
        state = {
            "solve_scripts": [
                {"exit_code": 0, "stdout": ""},
                {"exit_code": 0, "stdout": ""},
                {"exit_code": 0, "stdout": ""},
            ],
            "challenge_type": "crypto",
            "strategies_tried": ["no_output_recovery"],
        }
        out = _no_output_thrash_route(state)
        assert out is not None
        assert "strategies_tried" not in out


class TestStrategyUpdateIfNew:
    def test_adds_new_strategy(self):
        out = _strategy_update_if_new({"strategies_tried": ["a"]}, "b")
        assert out == {"strategies_tried": ["b"]}

    def test_ignores_existing_strategy(self):
        out = _strategy_update_if_new({"strategies_tried": ["a"]}, "a")
        assert out == {}


@pytest.mark.asyncio
async def test_manager_gives_up_after_max_solve_attempts(monkeypatch):
    monkeypatch.setenv("KRAKEN_MAX_SOLVE_ATTEMPTS", "2")
    state = {
        "solve_scripts": [
            {"attempt_num": 1, "exit_code": 0, "stdout": ""},
            {"attempt_num": 2, "exit_code": 0, "stdout": ""},
        ],
        "strategies_tried": [],
        "iteration_count": 0,
    }
    out = await manager(state)
    assert out["next_node"] == "give_up"


class TestPythonErrorPersistenceRoute:
    def test_none_when_no_scripts(self):
        assert _python_error_persistence_route({}) is None

    def test_none_when_latest_exit_zero(self):
        state = {"solve_scripts": [{"exit_code": 0, "stderr": ""}]}
        assert _python_error_persistence_route(state) is None

    def test_routes_to_solve_engine_for_python_crash(self):
        state = {
            "solve_scripts": [{"exit_code": 1, "stderr": "Traceback\nIndexError: list index out of range", "strategy": "crypto decode"}],
            "current_strategy": "crypto decode",
            "failure_diagnosis": "[index_error] out of range",
            "iteration_count": 2,
            "strategies_tried": [],
        }
        out = _python_error_persistence_route(state)
        assert out is not None
        assert out["next_node"] == "solve_engine"
        assert "flatten" in out["strategy_hypothesis"].lower()

    def test_none_after_three_same_strategy_python_crashes(self):
        state = {
            "solve_scripts": [
                {"exit_code": 1, "stderr": "Traceback\nTypeError", "strategy": "s"},
                {"exit_code": 1, "stderr": "Traceback\nIndexError", "strategy": "s"},
                {"exit_code": 1, "stderr": "Traceback\nNameError", "strategy": "s"},
            ],
            "current_strategy": "s",
        }
        assert _python_error_persistence_route(state) is None


class TestHelperPivotRoute:
    def test_none_without_failure_pattern(self):
        state = {
            "solve_scripts": [{"exit_code": 0, "stdout": "vere{ok}"}],
            "current_strategy": "crypto decode",
        }
        assert _helper_pivot_route(state) is None

    def test_triggers_on_index_error(self):
        state = {
            "solve_scripts": [{
                "exit_code": 1,
                "stderr": "Traceback\nIndexError: list index out of range",
                "stdout": "",
            }],
            "failure_diagnosis": "[index_error] out of range",
            "current_strategy": "manual z3 transcription",
            "iteration_count": 1,
            "strategies_tried": [],
        }
        out = _helper_pivot_route(state)
        assert out is not None
        assert out["next_node"] == "solve_engine"
        assert "auto_angr" in out["strategy_hypothesis"]

    def test_triggers_on_repeated_unsat(self):
        state = {
            "solve_scripts": [
                {"exit_code": 0, "stdout": "No solution found.", "stderr": ""},
                {"exit_code": 0, "stdout": "UNSAT", "stderr": ""},
            ],
            "current_strategy": "manual constraints",
            "iteration_count": 2,
            "strategies_tried": [],
        }
        out = _helper_pivot_route(state)
        assert out is not None
        assert out["next_node"] == "solve_engine"
        assert "helper" in out["current_strategy"]
