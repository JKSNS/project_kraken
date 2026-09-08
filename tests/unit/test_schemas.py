"""Tests for node I/O schemas (Phase 4)."""
from __future__ import annotations

import pytest

from kraken.schemas import (
    NODE_SCHEMAS,
    TriageInput, TriageOutput,
    ClassifyInput, ClassifyOutput,
    SolveEngineInput, SolveEngineOutput,
    FlagValidatorInput, FlagValidatorOutput,
    validated_node,
)


class TestSchemaDefinitions:
    def test_all_nodes_have_schemas(self):
        """Every node in the graph has a schema entry."""
        expected_nodes = {
            "triage", "unpack", "decompile", "normalize", "classify",
            "constraint_solver", "crypto_decode", "dynamic_analysis",
            "keygen", "pwn_specialist", "fuzzing_specialist",
            "web_specialist", "dotnet_specialist", "firmware_specialist",
            "param_extraction", "tool_router", "solve_engine",
            "flag_validator", "manager", "context_compressor",
        }
        assert set(NODE_SCHEMAS.keys()) == expected_nodes

    def test_schemas_are_tuples(self):
        for name, (input_schema, output_schema) in NODE_SCHEMAS.items():
            assert hasattr(input_schema, "__annotations__"), f"{name} input has no annotations"
            assert hasattr(output_schema, "__annotations__"), f"{name} output has no annotations"

    def test_triage_input_fields(self):
        fields = set(TriageInput.__annotations__.keys())
        assert "challenge_path" in fields

    def test_classify_input_fields(self):
        fields = set(ClassifyInput.__annotations__.keys())
        assert "decompiled_functions" in fields
        assert "binary_info" in fields

    def test_solve_engine_has_broad_input(self):
        """SolveEngine should have the broadest input schema."""
        fields = set(SolveEngineInput.__annotations__.keys())
        assert len(fields) >= 10  # It reads many fields

    def test_flag_validator_output_has_flag(self):
        fields = set(FlagValidatorOutput.__annotations__.keys())
        assert "flag" in fields
        assert "next_node" in fields


class TestValidatedNode:
    @pytest.mark.asyncio
    async def test_no_warning_on_valid_output(self, caplog):
        @validated_node(TriageInput, TriageOutput)
        async def good_node(state):
            return {
                "binary_info": {"file_type": "ELF"},
                "strings_of_interest": ["flag{"],
                "recent_actions": [{"action": "triage"}],
                "iteration_count": 1,
            }

        result = await good_node({})
        assert result["binary_info"]["file_type"] == "ELF"

    @pytest.mark.asyncio
    async def test_warning_on_extra_output(self, caplog):
        @validated_node(TriageInput, TriageOutput)
        async def bad_node(state):
            return {
                "binary_info": {},
                "totally_wrong_field": "oops",
            }

        result = await bad_node({})
        assert result["totally_wrong_field"] == "oops"  # still returns it

    @pytest.mark.asyncio
    async def test_bookkeeping_fields_allowed(self):
        """Common bookkeeping fields should not trigger warnings."""
        @validated_node(TriageInput, TriageOutput)
        async def node_with_bookkeeping(state):
            return {
                "binary_info": {},
                "recent_actions": [{}],
                "iteration_count": 1,
                "error_log": [],
                "node_timings": [],
                "solve_path": [],
                "framework_crash_count": 0,
                "next_node": "unpack",
            }

        result = await node_with_bookkeeping({})
        assert "binary_info" in result

    def test_decorated_function_has_schema_attrs(self):
        @validated_node(TriageInput, TriageOutput)
        async def my_node(state):
            return {}

        assert my_node._input_schema is TriageInput
        assert my_node._output_schema is TriageOutput
