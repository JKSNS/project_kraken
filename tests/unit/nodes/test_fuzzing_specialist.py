"""Tests for kraken.nodes.fuzzing_specialist -- fuzz target identification."""
import pytest

from kraken.nodes.fuzzing_specialist import _identify_fuzz_targets


class TestIdentifyFuzzTargets:
    """Test deterministic fuzz target identification (no LLM calls)."""

    def test_input_functions_detected(self):
        functions = {"main": "void main() { fgets(buf, 256, stdin); read(0, buf, 100); }"}
        result = _identify_fuzz_targets(functions, {}, [])
        assert len(result["input_functions"]) > 0
        assert any(f["function"] in ("fgets", "read") for f in result["input_functions"])

    def test_parsing_functions_detected(self):
        functions = {"parse": "int parse(char *data) { sscanf(data, fmt); atoi(str); }"}
        result = _identify_fuzz_targets(functions, {}, [])
        assert len(result["parsing_functions"]) > 0

    def test_dangerous_sinks_detected(self):
        functions = {"vuln": "void vuln(char *in) { memcpy(dst, in, len); strcpy(buf, in); }"}
        result = _identify_fuzz_targets(functions, {}, [])
        assert len(result["dangerous_sinks"]) > 0
        assert any(s["function"] in ("memcpy", "strcpy") for s in result["dangerous_sinks"])

    def test_file_io_detected(self):
        functions = {"load": "FILE *f = fopen(path, \"r\"); fread(buf, 1, sz, f);"}
        result = _identify_fuzz_targets(functions, {}, [])
        assert len(result["file_io"]) > 0

    def test_network_io_detected(self):
        functions = {"server": "int s = socket(AF_INET, SOCK_STREAM, 0); recv(s, buf, 1024, 0);"}
        result = _identify_fuzz_targets(functions, {}, [])
        assert len(result["network_io"]) > 0

    def test_protocol_hints(self):
        strings = ["HTTP/1.1", "Content-Type", "GET /"]
        result = _identify_fuzz_targets({}, {}, strings)
        assert len(result["protocol_hints"]) > 0
        assert any("HTTP" in h for h in result["protocol_hints"])

    def test_entry_candidates_scored(self):
        functions = {
            "main": "int main(int argc, char **argv) { process(argv[1]); }",
            "process": "void process(char *data) { parse(data); }",
            "parse": "int parse(char *buf) { sscanf(buf, fmt); }",
        }
        result = _identify_fuzz_targets(functions, {}, [])
        assert len(result["entry_candidates"]) > 0
        # All candidates should have scores
        for candidate in result["entry_candidates"]:
            assert "score" in candidate
            assert candidate["score"] > 0

    def test_empty_inputs(self):
        result = _identify_fuzz_targets({}, {}, [])
        assert result["input_functions"] == []
        assert result["parsing_functions"] == []
        assert result["dangerous_sinks"] == []
        assert result["file_io"] == []
        assert result["network_io"] == []
        assert result["entry_candidates"] == []

    def test_binary_info_with_shared_lib(self):
        binary_info = {"file_type": "ELF 64-bit LSB shared object"}
        functions = {"process": "void process(char *data) { memcpy(buf, data, len); }"}
        result = _identify_fuzz_targets(functions, binary_info, [])
        # Should still identify dangerous sinks
        assert len(result["dangerous_sinks"]) > 0
