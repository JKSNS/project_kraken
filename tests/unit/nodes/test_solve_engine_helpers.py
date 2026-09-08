"""Tests for solve_engine helper functions -- timeout, budget, specialist summary."""
import pytest

from kraken.nodes.solve_engine import (
    _get_timeout,
    _budget_functions,
    _build_specialist_summary,
    _enforce_script_contract,
    _build_attempt_ledger,
    _repair_truncated_code,
    _STRATEGY_TIMEOUTS,
    _DEFAULT_TIMEOUT,
    _derive_flat_z3_mode,
    _has_angr_failed_marker,
    _recent_angr_failed,
    ANGR_ARG_FLIP_HINT,
)


# ── _get_timeout (#9) ───────────────────────────────────────────────


class TestGetTimeout:
    """Test strategy-based timeout differentiation."""

    def test_constraint_type(self):
        assert _get_timeout({"challenge_type": "constraint"}) == 300

    def test_crypto_type(self):
        assert _get_timeout({"challenge_type": "crypto"}) == 60

    def test_dynamic_type(self):
        assert _get_timeout({"challenge_type": "dynamic"}) == 60

    def test_keygen_type(self):
        assert _get_timeout({"challenge_type": "keygen"}) == 30

    def test_pwn_type(self):
        assert _get_timeout({"challenge_type": "pwn"}) == 120

    def test_unknown_type_default(self):
        assert _get_timeout({"challenge_type": "unknown"}) == _DEFAULT_TIMEOUT

    def test_empty_state_default(self):
        assert _get_timeout({}) == _DEFAULT_TIMEOUT

    def test_angr_keyword_in_strategy(self):
        state = {"current_strategy": "try angr symbolic execution"}
        assert _get_timeout(state) == 300

    def test_z3_keyword_in_strategy(self):
        state = {"current_strategy": "solve z3 constraints"}
        assert _get_timeout(state) == 300

    def test_xor_keyword_in_strategy(self):
        state = {"current_strategy": "reverse xor encoding"}
        assert _get_timeout(state) == 30

    def test_brute_force_keyword(self):
        state = {"current_strategy": "brute-force the key space"}
        assert _get_timeout(state) == 180

    def test_challenge_type_takes_precedence(self):
        """challenge_type should be checked before strategy keywords."""
        state = {"challenge_type": "crypto", "current_strategy": "angr symbolic"}
        assert _get_timeout(state) == 60  # crypto wins over angr in strategy


# ── _budget_functions (#5) ──────────────────────────────────────────


class TestBudgetFunctions:
    """Test call-graph-aware function budget allocation."""

    def test_empty_functions(self):
        assert _budget_functions({}, {}, [], "") == {}

    def test_within_budget_no_truncation(self):
        funcs = {"main": "int main() { return 0; }", "helper": "void helper() {}"}
        result = _budget_functions(funcs, {}, [], "", budget=100000)
        assert result == funcs

    def test_max_funcs_limit(self):
        funcs = {f"func_{i}": f"void func_{i}() {{}}" for i in range(50)}
        result = _budget_functions(funcs, {}, [], "", max_funcs=10)
        assert len(result) <= 10

    def test_specialist_mention_priority(self):
        funcs = {
            "check_flag": "void check_flag() { strcmp(input, secret); }",
            "init_random": "void init_random() { srand(time(0)); }",
            "boring": "void boring() { return; }",
        }
        result = _budget_functions(funcs, {}, [], "check_flag is the key function", budget=200)
        # check_flag should be included (mentioned in specialist summary)
        assert "check_flag" in result

    def test_key_indicator_priority(self):
        funcs = {
            "validate_password": "void validate_password() { if (strcmp(input, flag)) fail(); }",
            "print_banner": "void print_banner() { puts(banner); }",
        }
        result = _budget_functions(funcs, {}, [], "", budget=200)
        # validate_password has flag/strcmp keywords -- should be prioritized
        assert "validate_password" in result

    def test_call_graph_priority(self):
        funcs = {
            "main_helper": "void main_helper() { do_stuff(); }",
            "unused_func": "void unused_func() { nop; nop; nop; nop; nop; }",
        }
        call_graph = {"main": ["main_helper"]}
        result = _budget_functions(funcs, call_graph, [], "", budget=200)
        assert "main_helper" in result

    def test_proportional_truncation(self):
        """When over budget, functions should be truncated proportionally."""
        funcs = {
            "big": "A" * 10000,
            "small": "B" * 100,
        }
        result = _budget_functions(funcs, {}, [], "", budget=5000)
        # Both should be present but big should be truncated
        assert "big" in result
        assert "small" in result
        assert len(result["big"]) < 10000

    def test_minimum_guarantee(self):
        """Each function should get at least 2000 chars even when budget is tight."""
        funcs = {
            "func_a": "X" * 5000,
            "func_b": "Y" * 5000,
        }
        result = _budget_functions(funcs, {}, [], "", budget=3000)
        for v in result.values():
            assert len(v) >= 2000


# ── _build_specialist_summary ───────────────────────────────────────


class TestBuildSpecialistSummary:
    """Test specialist summary aggregation."""

    def test_empty_state(self):
        summary = _build_specialist_summary({})
        assert summary == ""

    def test_angr_satisfiable(self):
        state = {"angr_results": {"satisfiable": True, "solution_ascii": "flag{test}"}}
        summary = _build_specialist_summary(state)
        assert "[angr]" in summary
        assert "SATISFIABLE" in summary

    def test_crypto_analysis(self):
        state = {
            "angr_results": {
                "crypto_analysis": {
                    "algorithm": "XOR",
                    "reverse_approach": "XOR with same key to decrypt",
                }
            }
        }
        summary = _build_specialist_summary(state)
        assert "[crypto]" in summary
        assert "XOR" in summary

    def test_pwn_analysis(self):
        state = {
            "angr_results": {
                "pwn_analysis": {
                    "vulnerability": "buffer_overflow",
                    "exploit_strategy": "Overflow buffer then ROP to system",
                    "offset": "72",
                    "vuln_indicators": {
                        "gadget_hints": ["system@plt available", "No PIE"],
                    },
                }
            }
        }
        summary = _build_specialist_summary(state)
        assert "[pwn]" in summary
        assert "buffer_overflow" in summary
        assert "72" in summary

    def test_dynamic_traces(self):
        state = {
            "dynamic_traces": [
                {"type": "anti_debug_patch", "patches_applied": 3, "patched": "/tmp/patched_bin"},
            ]
        }
        summary = _build_specialist_summary(state)
        assert "[dynamic]" in summary
        assert "Anti-debug" in summary

    def test_strategy_hypothesis(self):
        state = {"strategy_hypothesis": "Try XOR decode with key from strings"}
        summary = _build_specialist_summary(state)
        assert "[strategy]" in summary


class TestAttemptLedger:
    def test_empty_ledger(self):
        assert _build_attempt_ledger([]) == ""

    def test_recent_failures_render(self):
        ledger = _build_attempt_ledger([
            {"attempt_num": 1, "exit_code": 1, "stderr": "Script must print(flag)", "stdout": ""},
            {"attempt_num": 2, "exit_code": 1, "stderr": "SyntaxError before execution", "stdout": ""},
        ])
        assert "attempt=1" in ledger
        assert "attempt=2" in ledger
        assert "SyntaxError" in ledger


class TestRepairTruncatedCode:
    def test_repair_unclosed_paren_tail(self):
        broken = """def main():
    value = (1 + 2
    print(value)

if __name__ == '__main__':
    main()
"""
        repaired = _repair_truncated_code(broken)
        # Should at least return syntactically valid prefix
        assert "def main():" in repaired
        import ast

        ast.parse(repaired)


# ── _enforce_script_contract ─────────────────────────────────────────


class TestEnforceScriptContract:
    def test_valid_contract_script(self):
        code = """def main():
    flag = 'flag{x}'
    print(flag)

if __name__ == '__main__':
    main()
"""
        _, err = _enforce_script_contract(code)
        assert err is None

    def test_repair_missing_main(self):
        code = "flag = 'flag{no_main}'\nprint(flag)"
        repaired, err = _enforce_script_contract(code)
        assert err is None
        assert "def main():" in repaired

    def test_repair_missing_main_call(self):
        code = """def main():
    flag = 'flag{x}'
    print(flag)
"""
        repaired, err = _enforce_script_contract(code)
        assert err is None
        assert "if __name__ == '__main__':" in repaired

    def test_reject_too_many_lines(self):
        body = '\n'.join(["x=1" for _ in range(400)])
        _, err = _enforce_script_contract(body)
        assert "line contract" in err


    def test_autowrap_missing_main(self):
        code = """import math
flag = 'flag{x}'
print(flag)
"""
        new_code, err = _enforce_script_contract(code)
        assert err is None
        assert "def main():" in new_code
        assert "if __name__ == '__main__':" in new_code

    def test_requests_import_removed(self):
        code = """import requests
def main():
    flag = 'flag{x}'
    print(flag)
if __name__ == '__main__':
    main()
"""
        new_code, err = _enforce_script_contract(code)
        assert err is None
        assert "import requests" not in new_code

    def test_allows_try_except(self):
        code = """def main():
    flag = 'flag{x}'
    try:
        print(flag)
    except Exception:
        print(flag)

if __name__ == '__main__':
    main()
"""
        _, err = _enforce_script_contract(code)
        assert err is None

    def test_rewrites_unbounded_chr(self):
        code = """def main():
    flag = chr(300)
    print(flag)

if __name__ == '__main__':
    main()
"""
        new_code, err = _enforce_script_contract(code)
        assert err is None
        assert "chr(300 & 255)" in new_code or "chr((300 & 255))" in new_code

    def test_accepts_bounded_chr(self):
        code = """def main():
    flag = chr((300) % 256)
    print(flag)

if __name__ == '__main__':
    main()
"""
        _, err = _enforce_script_contract(code)
        assert err is None

    def test_autoinserts_print_flag_when_missing(self):
        code = """def main():
    flag = 'flag{x}'
    x = 1

if __name__ == '__main__':
    main()
"""
        new_code, err = _enforce_script_contract(code)
        assert err is None
        assert "print(flag)" in new_code


class TestDeriveFlatZ3Mode:
    def test_disabled_for_non_applicable_type(self):
        assert _derive_flat_z3_mode({"challenge_type": "web"}, []) is False

    def test_enabled_from_failure_diagnosis_index_error(self):
        state = {"challenge_type": "crypto", "failure_diagnosis": "[index_error] Index out of range"}
        assert _derive_flat_z3_mode(state, []) is True

    def test_enabled_after_repeated_recent_index_errors(self):
        attempts = [
            {"stderr": "Traceback... IndexError: list index out of range"},
            {"stderr": "other"},
            {"stderr": "IndexError: list index out of range"},
        ]
        assert _derive_flat_z3_mode({"challenge_type": "constraint"}, attempts) is True

    def test_not_enabled_for_single_index_error(self):
        attempts = [
            {"stderr": "IndexError: list index out of range"},
        ]
        assert _derive_flat_z3_mode({"challenge_type": "dynamic"}, attempts) is False


class TestAngrFailureHinting:
    def test_marker_detection_case_insensitive(self):
        assert _has_angr_failed_marker("[-] ANGR FAILED: explore() returned nothing") is True

    def test_recent_angr_failed_reads_history(self):
        attempts = [
            {"stdout": "ok", "stderr": ""},
            {"stdout": "", "stderr": "[-] ANGR FAILED due to find string mismatch"},
        ]
        assert _recent_angr_failed(attempts) is True

    def test_recent_angr_failed_false_when_absent(self):
        attempts = [{"stdout": "all good", "stderr": ""}]
        assert _recent_angr_failed(attempts) is False

    def test_hint_text_mentions_arg_flip(self):
        assert "adding '--arg'" in ANGR_ARG_FLIP_HINT
        assert "try removing it" in ANGR_ARG_FLIP_HINT
