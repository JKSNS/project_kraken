"""Tests for reversed string detection and fragment assembly in auto_source_decode."""
from __future__ import annotations

import pytest

from kraken.helpers.auto_source_decode import (
    _extract_reversed_flag_fragments,
    _assemble_fragments,
    scan_file,
    _find_flags,
    _decode_base64_strings,
)


class TestReversedFragments:
    def test_simple_reversed_line(self):
        text = "user@tS_u0y_ll1w{BTH"
        frags = _extract_reversed_flag_fragments(text)
        assert any("HTB{" in f for f in frags)

    def test_no_reversed_flags(self):
        text = "this is normal text\nno flags here"
        frags = _extract_reversed_flag_fragments(text)
        assert frags == []

    def test_multiple_prefixes(self):
        text = "}data_emos{galf"
        frags = _extract_reversed_flag_fragments(text)
        assert any("flag{" in f for f in frags)

    def test_short_lines_ignored(self):
        text = "ab\ncd"
        frags = _extract_reversed_flag_fragments(text)
        assert frags == []

    def test_known_prefixes_all_detected(self):
        for prefix in ["HTB{", "flag{", "CTF{", "picoCTF{", "SEKAI{"]:
            rev = prefix[::-1] + "body_data"
            text = rev[::-1]  # reversed back - won't work
            # Build proper reversed line
            full = prefix + "test}"
            reversed_line = full[::-1]
            frags = _extract_reversed_flag_fragments(reversed_line)
            assert any(prefix in f for f in frags), f"Failed for {prefix}"


class TestFragmentAssembly:
    def test_two_fragments_combine(self):
        frags = ["HTB{w1ll_y0u_St", "4nd_y0uR_Gr0uNd!!}"]
        result = _assemble_fragments(frags, r"HTB\{[^}]+\}")
        assert result == "HTB{w1ll_y0u_St4nd_y0uR_Gr0uNd!!}"

    def test_no_fragments_returns_none(self):
        result = _assemble_fragments([], "")
        assert result is None

    def test_too_many_fragments(self):
        frags = [f"frag{i}" for i in range(10)]
        result = _assemble_fragments(frags, "")
        assert result is None


class TestFindFlags:
    def test_finds_standard_flag(self):
        candidates = ["HTB{w1ll_y0u_St4nd_y0uR_Gr0uNd!!}"]
        flags = _find_flags(candidates)
        assert len(flags) == 1
        assert "HTB{" in flags[0]

    def test_no_flag_in_garbage(self):
        flags = _find_flags(["hello world", "foobar"])
        assert flags == []
