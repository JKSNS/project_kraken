"""Tests for kraken.nodes.pwn_specialist -- vulnerability indicator analysis."""
import pytest

from kraken.nodes.pwn_specialist import _analyze_vuln_indicators


class TestAnalyzeVulnIndicators:
    """Test deterministic vulnerability analysis (no LLM calls)."""

    def test_gets_detected(self):
        functions = {"main": "void main() { char buf[64]; gets(buf); }"}
        result = _analyze_vuln_indicators({}, functions, [])
        assert "buffer_overflow" in result["vuln_type"]
        assert any(d["function"] == "gets" for d in result["dangerous_funcs"])

    def test_strcpy_detected(self):
        functions = {"vuln": "void vuln(char *s) { char dst[32]; strcpy(dst, s); }"}
        result = _analyze_vuln_indicators({}, functions, [])
        assert "buffer_overflow" in result["vuln_type"]
        assert any(d["function"] == "strcpy" for d in result["dangerous_funcs"])

    def test_sprintf_detected(self):
        functions = {"fmt": "void fmt(char *in) { char buf[128]; sprintf(buf, in); }"}
        result = _analyze_vuln_indicators({}, functions, [])
        assert "buffer_overflow" in result["vuln_type"]
        assert any(d["function"] == "sprintf" for d in result["dangerous_funcs"])

    def test_format_string_detected(self):
        functions = {"vuln": 'void vuln(char *buf) { printf(buf); }'}
        result = _analyze_vuln_indicators({}, functions, [])
        assert "format_string" in result["vuln_type"]

    def test_rop_candidate(self):
        """NX enabled + no canary = ROP candidate."""
        binary_info = {"checksec": {"NX": True, "Canary": False}}
        result = _analyze_vuln_indicators(binary_info, {}, [])
        assert "rop_candidate" in result["vuln_type"]

    def test_no_rop_with_canary(self):
        """NX + canary = not a simple ROP target."""
        binary_info = {"checksec": {"NX": True, "Canary": True}}
        result = _analyze_vuln_indicators(binary_info, {}, [])
        assert "rop_candidate" not in result["vuln_type"]

    def test_system_plt_detected(self):
        binary_info = {"plt": {"system": 0x401030}, "got": {}}
        result = _analyze_vuln_indicators(binary_info, {}, [])
        assert any("system@plt" in h for h in result["gadget_hints"])

    def test_bin_sh_detected(self):
        result = _analyze_vuln_indicators({}, {}, ["/bin/sh", "other_string"])
        assert any("/bin/sh" in h for h in result["gadget_hints"])

    def test_heap_candidate(self):
        functions = {"heap_vuln": "void *p = malloc(64); free(p); "}
        result = _analyze_vuln_indicators({}, functions, [])
        assert "heap_candidate" in result["vuln_type"]

    def test_no_pie_hint(self):
        binary_info = {"checksec": {"PIE": False}}
        result = _analyze_vuln_indicators(binary_info, {}, [])
        assert any("No PIE" in h for h in result["gadget_hints"])

    def test_pie_enabled_hint(self):
        binary_info = {"checksec": {"PIE": True}}
        result = _analyze_vuln_indicators(binary_info, {}, [])
        assert any("PIE enabled" in h for h in result["gadget_hints"])

    def test_got_overwrite_partial_relro(self):
        binary_info = {"checksec": {"RELRO": "Partial"}, "got": {"puts": 0x602018}}
        result = _analyze_vuln_indicators(binary_info, {}, [])
        assert any("GOT overwrite" in h for h in result["gadget_hints"])

    def test_full_relro_no_got_hint(self):
        binary_info = {"checksec": {"Full RELRO": True}, "got": {"puts": 0x602018}}
        result = _analyze_vuln_indicators(binary_info, {}, [])
        assert not any("GOT overwrite" in h for h in result["gadget_hints"])

    def test_buffer_size_extraction(self):
        functions = {"main": "char buffer[256]; char name[32];"}
        result = _analyze_vuln_indicators({}, functions, [])
        assert result["stack_info"].get("buffer") == 256
        assert result["stack_info"].get("name") == 32

    def test_checksec_pwntools_fallback(self):
        """Should work with 'checksec_pwntools' key too."""
        binary_info = {"checksec_pwntools": {"NX": True, "Canary": False}}
        result = _analyze_vuln_indicators(binary_info, {}, [])
        assert "rop_candidate" in result["vuln_type"]

    def test_empty_inputs(self):
        result = _analyze_vuln_indicators({}, {}, [])
        assert result["vuln_type"] == []
        assert result["dangerous_funcs"] == []
        assert result["stack_info"] == {}

    def test_multiple_vuln_types(self):
        """Challenge with both overflow and format string."""
        functions = {"vuln": "void v(char *in) { char buf[64]; gets(buf); printf(buf); }"}
        result = _analyze_vuln_indicators({}, functions, [])
        assert "buffer_overflow" in result["vuln_type"]
        assert "format_string" in result["vuln_type"]


@pytest.mark.asyncio
async def test_pwn_specialist_no_unhashable_prompt(monkeypatch):
    from kraken.nodes import pwn_specialist as mod

    async def fake_generate(prompt, tier, cfg):
        assert "Decompiled Functions" in prompt
        return '{"vulnerability":"buffer_overflow","exploit_strategy":"test"}'

    monkeypatch.setattr(mod, "direct_generate", fake_generate)

    state = {
        "decompiled_functions": {"main": "int main(){return 0;}", "check": "void check(){}"},
        "strings_of_interest": ["/bin/sh"],
        "binary_info": {"imports": [], "checksec": {}},
        "challenge_path": "/tmp/bin",
        "remote_info": {},
        "angr_results": {},
        "iteration_count": 0,
    }

    out = await mod.pwn_specialist(state)
    assert "angr_results" in out
    assert "pwn_analysis" in out["angr_results"]
