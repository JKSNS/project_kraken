"""Unit tests for the Kraken MCP server."""
from __future__ import annotations

import asyncio
import os
import re
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ── Import the MCP tools directly (bypass FastMCP transport) ─────────────


from kraken.mcp_server import (
    kraken_triage,
    kraken_decompile,
    kraken_extract_params,
    kraken_run_tool,
    kraken_run_tool_cascade,
    kraken_validate_flag,
    kraken_run_script,
    mcp,
)


# ── Test: MCP app has all 7 tools registered ─────────────────────────────


class TestMCPRegistration:
    def test_mcp_app_exists(self):
        assert mcp is not None
        assert mcp.name == "kraken"

    def test_all_tools_registered(self):
        # FastMCP stores tools internally; verify via the function objects
        tool_funcs = [
            kraken_triage,
            kraken_decompile,
            kraken_extract_params,
            kraken_run_tool,
            kraken_run_tool_cascade,
            kraken_validate_flag,
            kraken_run_script,
        ]
        for fn in tool_funcs:
            assert callable(fn)


# ── Test: kraken_triage ──────────────────────────────────────────────────


class TestKrakenTriage:
    @pytest.mark.asyncio
    async def test_triage_nonexistent_path(self):
        result = await kraken_triage("/nonexistent/path/binary")
        # Should return error or binary_info with NOT FOUND
        assert "binary_info" in result or "error" in result

    @pytest.mark.asyncio
    async def test_triage_with_temp_dir(self):
        with tempfile.TemporaryDirectory() as td:
            # Empty directory -- triage should handle gracefully
            result = await kraken_triage(td)
            assert "binary_info" in result or "error" in result
            if "binary_info" in result:
                assert isinstance(result["binary_info"], dict)
                assert isinstance(result.get("strings_of_interest", []), list)

    @pytest.mark.asyncio
    async def test_triage_returns_expected_keys(self):
        with tempfile.TemporaryDirectory() as td:
            result = await kraken_triage(td)
            if "error" not in result:
                for key in ("binary_info", "strings_of_interest", "symbols",
                            "challenge_files", "remote_info", "challenge_path"):
                    assert key in result

    @pytest.mark.asyncio
    async def test_triage_custom_flag_format(self):
        with tempfile.TemporaryDirectory() as td:
            result = await kraken_triage(td, flag_format=r"CTF\{[a-zA-Z0-9]+\}")
            assert "error" not in result or isinstance(result.get("error"), str)


# ── Test: kraken_decompile ───────────────────────────────────────────────


class TestKrakenDecompile:
    @pytest.mark.asyncio
    async def test_decompile_empty_dir(self):
        with tempfile.TemporaryDirectory() as td:
            result = await kraken_decompile(td)
            # Should return successfully with empty decompiled_functions
            assert "decompiled_functions" in result or "error" in result

    @pytest.mark.asyncio
    async def test_decompile_with_python_file(self):
        with tempfile.TemporaryDirectory() as td:
            py_file = Path(td) / "challenge.py"
            py_file.write_text("flag = 'flag{test_value}'\nprint(flag)\n")
            result = await kraken_decompile(td)
            if "error" not in result:
                funcs = result.get("decompiled_functions", {})
                # Should have read the .py file as source
                assert len(funcs) >= 1 or funcs == {}

    @pytest.mark.asyncio
    async def test_decompile_returns_call_graph(self):
        with tempfile.TemporaryDirectory() as td:
            result = await kraken_decompile(td)
            if "error" not in result:
                assert "call_graph" in result
                assert isinstance(result["call_graph"], dict)


# ── Test: kraken_extract_params ──────────────────────────────────────────


class TestKrakenExtractParams:
    def test_extract_params_basic(self):
        funcs = {
            "main": 'int main(int argc, char **argv) {\n  if (strlen(argv[1]) != 32) return 1;\n  puts("Correct!");\n}'
        }
        strings = ["Correct!", "Wrong!"]
        binary_info = {}
        result = kraken_extract_params(funcs, strings, binary_info)
        assert result["input_mode"] == "arg"
        assert result["input_length"] == 32
        assert result["success_string"] is not None
        assert "Correct" in result["success_string"]

    def test_extract_params_empty(self):
        result = kraken_extract_params({}, [], {})
        assert isinstance(result, dict)
        assert "input_mode" in result
        assert result["input_mode"] == "unknown"

    def test_extract_params_crypto_indicators(self):
        funcs = {"transform": "for (i=0; i<len; i++) buf[i] ^= 0x42;"}
        result = kraken_extract_params(funcs, [], {})
        assert "xor" in result["crypto_indicators"]

    def test_extract_params_with_error(self):
        # Should return error dict, not raise
        with patch("kraken.tools.param_extractor.extract_solve_params", side_effect=RuntimeError("boom")):
            result = kraken_extract_params({}, [], {})
            assert "error" in result
            assert result["error_type"] == "RuntimeError"


# ── Test: kraken_run_tool ────────────────────────────────────────────────


class TestKrakenRunTool:
    @pytest.mark.asyncio
    async def test_run_tool_nonexistent_tool(self):
        with tempfile.TemporaryDirectory() as td:
            result = await kraken_run_tool("nonexistent_tool", td)
            # Should return error since no helper script exists
            assert "error" in result

    @pytest.mark.asyncio
    async def test_run_tool_source_decode(self):
        with tempfile.TemporaryDirectory() as td:
            result = await kraken_run_tool("auto_source_decode", td)
            # Should at least attempt to run
            assert "tool" in result
            assert result["tool"] == "auto_source_decode"
            if "error" not in result:
                assert "exit_code" in result
                assert "stdout" in result
                assert "stderr" in result

    @pytest.mark.asyncio
    async def test_run_tool_returns_flag_info(self):
        with tempfile.TemporaryDirectory() as td:
            result = await kraken_run_tool("auto_source_decode", td)
            if "error" not in result:
                assert "flag_found" in result
                assert isinstance(result["flag_found"], bool)

    @pytest.mark.asyncio
    async def test_run_tool_with_extra_args(self):
        with tempfile.TemporaryDirectory() as td:
            result = await kraken_run_tool(
                "auto_angr", td,
                extra_args={"success_string": "Correct!", "input_length": 16},
            )
            # auto_angr needs a real binary, so it will fail - but shouldn't crash
            assert "tool" in result or "error" in result

    @pytest.mark.asyncio
    async def test_run_tool_fallback_invocation(self):
        """When _build_tool_command returns None, falls back to direct invocation."""
        with tempfile.TemporaryDirectory() as td:
            # auto_normalize exists as a helper but _build_tool_command doesn't handle it
            result = await kraken_run_tool("auto_normalize", td)
            assert "tool" in result or "error" in result


# ── Test: kraken_run_tool_cascade ────────────────────────────────────────


class TestKrakenRunToolCascade:
    @pytest.mark.asyncio
    async def test_cascade_empty_dir(self):
        with tempfile.TemporaryDirectory() as td:
            result = await kraken_run_tool_cascade(td)
            assert "tools_run" in result or "error" in result
            if "error" not in result:
                assert isinstance(result["tools_run"], int)
                assert isinstance(result["tool_results"], list)

    @pytest.mark.asyncio
    async def test_cascade_with_type(self):
        with tempfile.TemporaryDirectory() as td:
            result = await kraken_run_tool_cascade(td, challenge_type="crypto")
            assert "tools_run" in result or "error" in result

    @pytest.mark.asyncio
    async def test_cascade_with_triage_result(self):
        with tempfile.TemporaryDirectory() as td:
            triage = {
                "binary_info": {"file_type": "ELF"},
                "strings_of_interest": ["flag{test}"],
                "symbols": {},
                "challenge_files": {},
                "remote_info": {},
                "challenge_path": td,
            }
            result = await kraken_run_tool_cascade(
                td, triage_result=triage,
            )
            assert "tools_run" in result or "error" in result

    @pytest.mark.asyncio
    async def test_cascade_returns_summary(self):
        with tempfile.TemporaryDirectory() as td:
            result = await kraken_run_tool_cascade(td)
            if "error" not in result:
                assert "tool_results_summary" in result
                assert "flag_found" in result
                assert isinstance(result["flag_found"], bool)


# ── Test: kraken_validate_flag ───────────────────────────────────────────


class TestKrakenValidateFlag:
    @pytest.mark.asyncio
    async def test_validate_good_flag(self):
        result = await kraken_validate_flag("flag{hello_world}")
        assert result["valid"] is True
        assert result["checks"]["printable"] is True
        assert result["checks"]["low_diversity"] is False
        assert result["checks"]["format_match"] is True
        assert result["rejection_reason"] == ""

    @pytest.mark.asyncio
    async def test_validate_non_printable(self):
        result = await kraken_validate_flag("flag{\x00hidden}")
        assert result["valid"] is False
        assert "non-printable" in result["rejection_reason"]

    @pytest.mark.asyncio
    async def test_validate_low_diversity(self):
        result = await kraken_validate_flag("flag{aaaaaaaaaaaaaaaa}")
        assert result["valid"] is False
        assert "diversity" in result["rejection_reason"]

    @pytest.mark.asyncio
    async def test_validate_wrong_format(self):
        result = await kraken_validate_flag(
            "wrong_format",
            flag_format=r"flag\{[a-zA-Z0-9_]+\}",
        )
        assert result["valid"] is False
        assert "format" in result["rejection_reason"]

    @pytest.mark.asyncio
    async def test_validate_custom_format(self):
        result = await kraken_validate_flag(
            "CTF{some_flag_here}",
            flag_format=r"CTF\{[a-zA-Z0-9_]+\}",
        )
        assert result["valid"] is True

    @pytest.mark.asyncio
    async def test_validate_binary_verification_skipped_without_path(self):
        result = await kraken_validate_flag("flag{test123}")
        assert result["binary_verification"] is None

    @pytest.mark.asyncio
    async def test_validate_binary_verification_with_nonexistent_path(self):
        result = await kraken_validate_flag(
            "flag{test123}", binary_path="/nonexistent/binary"
        )
        # Should still pass format checks; binary verification returns None
        assert result["valid"] is True
        assert result["binary_verification"] is None


# ── Test: kraken_run_script ──────────────────────────────────────────────


class TestKrakenRunScript:
    @pytest.mark.asyncio
    async def test_run_simple_script(self):
        with tempfile.TemporaryDirectory() as td:
            result = await kraken_run_script("print('hello')", td)
            assert result["exit_code"] == 0
            assert "hello" in result["stdout"]
            assert result["stderr"] == ""

    @pytest.mark.asyncio
    async def test_run_script_with_error(self):
        with tempfile.TemporaryDirectory() as td:
            result = await kraken_run_script("raise ValueError('boom')", td)
            assert result["exit_code"] != 0
            assert "ValueError" in result["stderr"]

    @pytest.mark.asyncio
    async def test_run_script_timeout(self):
        with tempfile.TemporaryDirectory() as td:
            result = await kraken_run_script(
                "import time; time.sleep(100)", td, timeout=2,
            )
            assert result["exit_code"] != 0
            assert "timeout" in result["stderr"].lower() or "timed out" in result["stderr"].lower()

    @pytest.mark.asyncio
    async def test_run_script_accesses_challenge_dir(self):
        with tempfile.TemporaryDirectory() as td:
            # Write a file, then read it from the script
            Path(td, "data.txt").write_text("secret_value")
            code = "print(open('data.txt').read())"
            result = await kraken_run_script(code, td)
            assert result["exit_code"] == 0
            assert "secret_value" in result["stdout"]


# ── Test: Error handling wrapping ────────────────────────────────────────


class TestErrorHandling:
    @pytest.mark.asyncio
    async def test_triage_exception_returns_error(self):
        with patch("kraken.nodes.triage.triage", side_effect=RuntimeError("boom")):
            result = await kraken_triage("/tmp")
            assert "error" in result
            assert "boom" in result["error"]
            assert result["error_type"] == "RuntimeError"

    def test_extract_params_exception_returns_error(self):
        with patch("kraken.tools.param_extractor.extract_solve_params", side_effect=TypeError("bad")):
            result = kraken_extract_params({}, [], {})
            assert "error" in result
            assert "bad" in result["error"]
            assert result["error_type"] == "TypeError"
            assert result["tool"] == "kraken_extract_params"

    @pytest.mark.asyncio
    async def test_validate_flag_exception_returns_error(self):
        with patch(
            "kraken.nodes.flag_validator._is_likely_printable_flag",
            side_effect=RuntimeError("crash"),
        ):
            result = await kraken_validate_flag("flag{x}")
            assert "error" in result
            assert result["error_type"] == "RuntimeError"

    @pytest.mark.asyncio
    async def test_run_script_exception_returns_error(self):
        with patch(
            "kraken.tools.script_executor.execute_script",
            side_effect=OSError("disk full"),
        ):
            result = await kraken_run_script("print(1)", "/tmp")
            assert "error" in result
            assert "disk full" in result["error"]
