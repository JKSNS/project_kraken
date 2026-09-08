"""Unit tests for the tool_router node."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from kraken.nodes.tool_router import (
    _DEFAULT_TYPE_SPECIFIC,
    _HELPERS_DIR,
    _TYPE_SPECIFIC,
    _UNIVERSAL_TOOLS,
    _build_tool_command,
    _check_for_flag,
    tool_router,
)

# ── _build_tool_command tests ──────────────────────────────────────────


class TestBuildToolCommand:
    def test_angr_with_full_params(self):
        params = {"success_string": "Correct!", "input_length": 27, "input_mode": "arg"}
        state = {"challenge_path": "./chal", "strings_of_interest": []}
        cmd = _build_tool_command("auto_angr", params, state)
        assert cmd is not None
        assert '--find "Correct!"' in cmd
        assert "--length 27" in cmd
        assert "--arg" in cmd

    def test_angr_stdin_mode(self):
        params = {"success_string": "Win", "input_length": 40, "input_mode": "stdin"}
        state = {"challenge_path": "./chal", "strings_of_interest": []}
        cmd = _build_tool_command("auto_angr", params, state)
        assert cmd is not None
        assert "--arg" not in cmd

    def test_angr_with_avoid_string(self):
        params = {"success_string": "Correct!", "fail_string": "Wrong!", "input_mode": "stdin"}
        state = {"challenge_path": "./chal", "strings_of_interest": []}
        cmd = _build_tool_command("auto_angr", params, state)
        assert cmd is not None
        assert '--avoid "Wrong!"' in cmd

    def test_angr_no_success_string_uses_strings(self):
        params = {"input_mode": "arg"}
        state = {"challenge_path": "./chal", "strings_of_interest": ["Correct!", "Wrong"]}
        cmd = _build_tool_command("auto_angr", params, state)
        assert cmd is not None
        assert "Correct!" in cmd

    def test_angr_no_success_string_or_strings(self):
        params = {}
        state = {"challenge_path": "./chal", "strings_of_interest": []}
        cmd = _build_tool_command("auto_angr", params, state)
        assert cmd is None

    def test_angr_no_binary_path(self):
        params = {"success_string": "Correct!"}
        state = {"challenge_path": "", "strings_of_interest": []}
        cmd = _build_tool_command("auto_angr", params, state)
        assert cmd is None

    def test_gdb_cmp_with_prefix(self):
        params = {"flag_format_prefix": "flag{"}
        state = {"challenge_path": "./chal"}
        cmd = _build_tool_command("auto_gdb_cmp", params, state)
        assert cmd is not None
        assert "flag{" in cmd
        assert "auto_gdb_cmp.py" in cmd

    def test_gdb_cmp_without_prefix(self):
        params = {}
        state = {"challenge_path": "./chal"}
        cmd = _build_tool_command("auto_gdb_cmp", params, state)
        assert cmd is not None
        # 20 A's from "" + "A" * 20
        assert "A" * 20 in cmd

    def test_xor_brute_with_hex_data(self):
        params = {"flag_format_prefix": "vere{"}
        state = {
            "challenge_path": "./chal",
            "strings_of_interest": ["deadbeef1234abcd"],
        }
        cmd = _build_tool_command("auto_xor_brute", params, state)
        assert cmd is not None
        assert '--hex "deadbeef1234abcd"' in cmd
        assert '--prefix "vere{"' in cmd

    def test_xor_brute_no_hex_data(self):
        params = {"flag_format_prefix": "vere{"}
        state = {
            "challenge_path": "./chal",
            "strings_of_interest": ["Hello World", "not hex data"],
        }
        cmd = _build_tool_command("auto_xor_brute", params, state)
        assert cmd is None

    def test_regex_z3_no_decompile(self):
        params = {"input_length": 30}
        state = {
            "challenge_path": "./chal",
            "solve_workspace": "/tmp/nonexistent_workspace_test",
        }
        cmd = _build_tool_command("auto_regex_z3", params, state)
        assert cmd is None

    def test_regex_z3_with_decompile(self, tmp_path):
        decompile_file = tmp_path / "decompile.c"
        decompile_file.write_text("int main() {}")
        params = {"input_length": 35}
        state = {
            "challenge_path": "./chal",
            "solve_workspace": str(tmp_path),
        }
        cmd = _build_tool_command("auto_regex_z3", params, state)
        assert cmd is not None
        assert "--length 35" in cmd
        assert "auto_regex_z3.py" in cmd

    def test_c_brute_no_files(self):
        params = {"input_length": 30}
        state = {
            "challenge_path": "./chal",
            "solve_workspace": "/tmp/nonexistent_workspace_test",
        }
        cmd = _build_tool_command("auto_c_brute", params, state)
        assert cmd is None

    def test_c_brute_with_files(self, tmp_path):
        (tmp_path / "globals.c").write_text("int target[] = {1, 2, 3};")
        (tmp_path / "logic.c").write_text("if (c == target[i]) { found = 1; }")
        params = {"input_length": 25}
        state = {
            "challenge_path": "./chal",
            "solve_workspace": str(tmp_path),
        }
        cmd = _build_tool_command("auto_c_brute", params, state)
        assert cmd is not None
        assert "--length 25" in cmd
        assert "auto_c_brute.py" in cmd

    def test_crypto_returns_none(self):
        """auto_crypto needs --algo/--key/--ct which we can't extract deterministically."""
        params = {"crypto_indicators": ["xor"]}
        state = {"challenge_path": "./chal", "strings_of_interest": []}
        cmd = _build_tool_command("auto_crypto", params, state)
        assert cmd is None

    def test_patcher_returns_none(self):
        """auto_patcher needs --offset/--bytes which we can't extract deterministically."""
        params = {}
        state = {"challenge_path": "./chal"}
        cmd = _build_tool_command("auto_patcher", params, state)
        assert cmd is None

    def test_unknown_tool_returns_none(self):
        params = {}
        state = {"challenge_path": "./chal"}
        cmd = _build_tool_command("unknown_tool", params, state)
        assert cmd is None


# ── _check_for_flag tests ──────────────────────────────────────────────


class TestCheckForFlag:
    def test_standard_flag(self):
        assert _check_for_flag("Output: flag{test123}", "flag{...}") == "flag{test123}"

    def test_custom_format(self):
        assert _check_for_flag("vere{hello_world}", "vere{...}") == "vere{hello_world}"

    def test_no_flag(self):
        assert _check_for_flag("No output here", "flag{...}") is None

    def test_empty_output(self):
        assert _check_for_flag("", "flag{...}") is None

    def test_generic_ctf_flag(self):
        assert _check_for_flag("CTF{abc123}", "") == "CTF{abc123}"

    def test_case_insensitive_flag(self):
        result = _check_for_flag("FLAG{test}", "")
        assert result == "FLAG{test}"

    def test_flag_embedded_in_noise(self):
        output = "[+] ANGR SUCCESS\n[+] EXTRACTED FLAG: flag{s3cret_k3y}\n[*] Done."
        assert _check_for_flag(output, "flag{...}") == "flag{s3cret_k3y}"

    def test_no_flag_format_generic_match(self):
        result = _check_for_flag("result: myctf{answer}", "")
        assert result == "myctf{answer}"

    def test_flag_format_without_brace(self):
        """If flag_format doesn't contain a brace prefix, fall through to generic."""
        result = _check_for_flag("flag{abc}", "some_regex_without_brace")
        assert result == "flag{abc}"

    def test_recon_tool_metadata_not_wrapped_into_flag(self):
        # Regression: auto_existing_exploits emits a "target_dir" metadata token;
        # the bare-token prefix-wrap heuristic wrapped it into vere{target_dir}
        # and reported a false-positive solve on every unsolved rev challenge.
        assert _check_for_flag("target_dir\n", "vere{}", tool_name="auto_existing_exploits") is None

    def test_metadata_identifier_body_rejected_for_any_tool(self):
        # Belt-and-suspenders: metadata identifiers are never real flag bodies,
        # so they are rejected regardless of which tool produced the output.
        assert _check_for_flag("target_dir\n", "vere{}") is None
        assert _check_for_flag("challenge_path\n", "vere{}") is None

    def test_prefix_wrap_still_works_for_real_solver_body(self):
        # The wrap heuristic must still credit a genuine solve-script body
        # printed without the flag wrapper (default tool_name, non-recon).
        assert _check_for_flag("s3cret_k3y_here\n", r"flag\{[^}]+\}") == "flag{s3cret_k3y_here}"

    def test_generic_match_must_honor_requested_prefix(self):
        # Regression: a wrong-prefix word{...} (e.g. an encoded synt{...} blob or a
        # decoy admin{...}) must NOT be accepted when a specific prefix was asked for.
        assert _check_for_flag("synt{ebg13_vf_n_pnrfne_fuvsg}", "flag{}") is None
        assert _check_for_flag("admin{not_the_flag}", "flag{}") is None
        # a correctly-prefixed flag is still found, case-insensitively
        assert _check_for_flag("here is flag{real_answer_123}", "flag{}") == "flag{real_answer_123}"
        assert _check_for_flag("FLAG{upper_is_fine}", "flag{}") == "FLAG{upper_is_fine}"
        # generic detection is unchanged when no format is requested
        assert _check_for_flag("myctf{answer}", "") == "myctf{answer}"


# ── Cascade mapping tests ──────────────────────────────────────────────


class TestToolCascade:
    def test_universal_tools_present(self):
        assert "auto_run_static" in _UNIVERSAL_TOOLS
        assert "auto_python_reverse" in _UNIVERSAL_TOOLS
        assert "auto_c_source_eval" in _UNIVERSAL_TOOLS

    def test_constraint_cascade(self):
        assert "auto_angr" in _TYPE_SPECIFIC["constraint"]
        assert "auto_regex_z3" in _TYPE_SPECIFIC["constraint"]
        assert "auto_gdb_cmp" in _TYPE_SPECIFIC["constraint"]

    def test_crypto_cascade(self):
        assert "auto_xor_brute" in _TYPE_SPECIFIC["crypto"]
        assert "auto_c_brute" in _TYPE_SPECIFIC["crypto"]

    def test_keygen_cascade(self):
        assert "auto_angr" in _TYPE_SPECIFIC["keygen"]
        assert "auto_gdb_cmp" in _TYPE_SPECIFIC["keygen"]

    def test_dynamic_cascade(self):
        assert "auto_gdb_cmp" in _TYPE_SPECIFIC["dynamic"]
        assert "auto_angr" in _TYPE_SPECIFIC["dynamic"]

    def test_web_has_exploit_tools(self):
        assert "auto_web_exploit" in _TYPE_SPECIFIC["web"]

    def test_firmware_has_tools(self):
        assert len(_TYPE_SPECIFIC["firmware"]) > 0

    def test_default_type_specific_has_angr(self):
        assert "auto_angr" in _DEFAULT_TYPE_SPECIFIC

    def test_default_type_specific_has_gdb(self):
        assert "auto_gdb_cmp" in _DEFAULT_TYPE_SPECIFIC

    def test_helpers_dir_exists(self):
        """Verify _HELPERS_DIR points to a real directory."""
        assert _HELPERS_DIR.is_dir(), f"Helpers dir not found: {_HELPERS_DIR}"


# ── tool_router async node tests ───────────────────────────────────────


class TestToolRouterNode:
    @pytest.mark.asyncio
    async def test_empty_cascade_web(self):
        """Web challenges have no tools -- should return empty results."""
        state = {
            "challenge_type": "web",
            "extracted_params": {},
            "flag_format": "flag{...}",
            "challenge_path": "./chal",
            "solve_workspace": "/tmp",
            "strings_of_interest": [],
        }
        result = await tool_router(state)
        assert result["tool_cascade_results"] == []
        assert result["tool_results_summary"] == ""
        assert "tool_flag_candidate" not in result

    @pytest.mark.asyncio
    async def test_skips_when_no_binary_path(self):
        """If no binary path, all tools should be skipped."""
        state = {
            "challenge_type": "constraint",
            "extracted_params": {},
            "flag_format": "",
            "challenge_path": "",
            "solve_workspace": "/tmp",
            "strings_of_interest": [],
        }
        result = await tool_router(state)
        assert result["tool_cascade_results"] == []
        assert len(result["recent_actions"]) == 1
        assert "tool_flag_candidate" not in result

    @pytest.mark.asyncio
    async def test_flag_found_stops_cascade(self):
        """When a tool finds a flag, the cascade should stop."""
        mock_result = {
            "exit_code": 0,
            "stdout": "[+] EXTRACTED FLAG: flag{found_it}",
            "stderr": "",
        }
        state = {
            "challenge_type": "constraint",
            "extracted_params": {"success_string": "Correct!"},
            "flag_format": "flag{...}",
            "challenge_path": "./chal",
            "solve_workspace": "/tmp",
            "challenge_dir": "/tmp",
            "strings_of_interest": [],
        }
        with patch("kraken.nodes.tool_router._run_tool", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = mock_result
            result = await tool_router(state)
            assert result.get("tool_flag_candidate") == "flag{found_it}"
            # Should have stopped after first successful tool
            assert len(result["tool_cascade_results"]) == 1
            assert result["tool_cascade_results"][0]["tool"] == "auto_source_decode"

    @pytest.mark.asyncio
    async def test_no_flag_runs_full_cascade(self):
        """When no flag is found, all buildable tools in the cascade run."""
        mock_result = {
            "exit_code": 1,
            "stdout": "[-] ANGR FAILED: no path found",
            "stderr": "",
        }
        state = {
            "challenge_type": "constraint",
            "extracted_params": {"success_string": "Correct!", "flag_format_prefix": "flag{"},
            "flag_format": "flag{...}",
            "challenge_path": "./chal",
            "solve_workspace": "/tmp",
            "challenge_dir": "/tmp",
            "strings_of_interest": [],
        }
        with patch("kraken.nodes.tool_router._run_tool", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = mock_result
            result = await tool_router(state)
            assert "tool_flag_candidate" not in result
            # angr and gdb_cmp should both run (regex_z3 needs decompile.c)
            tool_names = [r["tool"] for r in result["tool_cascade_results"]]
            assert "auto_angr" in tool_names
            assert "auto_gdb_cmp" in tool_names

    @pytest.mark.asyncio
    async def test_tool_results_summary_format(self):
        """Summary should contain tool name and status."""
        mock_result = {
            "exit_code": 0,
            "stdout": "some output here",
            "stderr": "",
        }
        state = {
            "challenge_type": "constraint",
            "extracted_params": {"success_string": "OK"},
            "flag_format": "",
            "challenge_path": "./chal",
            "solve_workspace": "/tmp",
            "challenge_dir": "/tmp",
            "strings_of_interest": [],
        }
        with patch("kraken.nodes.tool_router._run_tool", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = mock_result
            result = await tool_router(state)
            summary = result["tool_results_summary"]
            assert "[auto_angr] SUCCESS:" in summary

    @pytest.mark.asyncio
    async def test_unknown_challenge_type_uses_default(self):
        """Unknown challenge types should fall back to _DEFAULT_CASCADE."""
        state = {
            "challenge_type": "unknown_type",
            "extracted_params": {"success_string": "Win"},
            "flag_format": "",
            "challenge_path": "./chal",
            "solve_workspace": "/tmp",
            "challenge_dir": "/tmp",
            "strings_of_interest": [],
        }
        mock_result = {
            "exit_code": 1,
            "stdout": "no flag",
            "stderr": "",
        }
        with patch("kraken.nodes.tool_router._run_tool", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = mock_result
            result = await tool_router(state)
            tool_names = [r["tool"] for r in result["tool_cascade_results"]]
            # Default cascade includes angr and gdb_cmp
            assert "auto_angr" in tool_names
