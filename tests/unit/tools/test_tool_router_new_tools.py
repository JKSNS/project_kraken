"""Tests for new tool_router build commands (pcap, steg, file_carve, pwn, rop)."""
from __future__ import annotations

import pytest

from kraken.nodes.tool_router import _build_tool_command, _UNIVERSAL_TOOLS, _TYPE_SPECIFIC


class TestNewUniversalTools:
    def test_pcap_extract_in_universal(self):
        assert "auto_pcap_extract" in _UNIVERSAL_TOOLS

    def test_steg_extract_in_universal(self):
        assert "auto_steg_extract" in _UNIVERSAL_TOOLS

    def test_file_carve_in_universal(self):
        assert "auto_file_carve" in _UNIVERSAL_TOOLS


class TestNewTypeSpecific:
    def test_forensics_tools(self):
        assert "forensics" in _TYPE_SPECIFIC
        assert "auto_pcap_extract" in _TYPE_SPECIFIC["forensics"]
        assert "auto_steg_extract" in _TYPE_SPECIFIC["forensics"]

    def test_steg_tools(self):
        assert "steg" in _TYPE_SPECIFIC
        assert "auto_steg_extract" in _TYPE_SPECIFIC["steg"]
        assert "auto_file_carve" in _TYPE_SPECIFIC["steg"]

    def test_pwn_tools(self):
        assert "auto_pwn_template" in _TYPE_SPECIFIC["pwn"]
        assert "auto_rop_extract" in _TYPE_SPECIFIC["pwn"]


class TestBuildPcapExtract:
    def test_with_pcap_file(self):
        state = {
            "challenge_dir": "/tmp/chal",
            "challenge_files": {"capture.pcap": {"path": "/tmp/chal/capture.pcap"}},
            "flag_format": r"flag\{[^}]+\}",
        }
        cmd = _build_tool_command("auto_pcap_extract", {}, state)
        assert cmd is not None
        assert "auto_pcap_extract.py" in cmd
        assert "--flag-format" in cmd

    def test_without_pcap_file(self):
        state = {
            "challenge_dir": "/tmp/chal",
            "challenge_files": {"main.c": {"path": "/tmp/chal/main.c"}},
        }
        cmd = _build_tool_command("auto_pcap_extract", {}, state)
        assert cmd is None

    def test_no_challenge_dir(self):
        state = {"challenge_dir": "", "challenge_files": {}}
        cmd = _build_tool_command("auto_pcap_extract", {}, state)
        assert cmd is None


class TestBuildStegExtract:
    def test_with_image_file(self):
        state = {
            "challenge_dir": "/tmp/chal",
            "challenge_files": {"hidden.png": {"path": "/tmp/chal/hidden.png"}},
        }
        cmd = _build_tool_command("auto_steg_extract", {}, state)
        assert cmd is not None
        assert "auto_steg_extract.py" in cmd

    def test_with_jpg(self):
        state = {
            "challenge_dir": "/tmp/chal",
            "challenge_files": {"photo.jpg": {"path": "/tmp/chal/photo.jpg"}},
        }
        cmd = _build_tool_command("auto_steg_extract", {}, state)
        assert cmd is not None

    def test_without_image_files(self):
        state = {
            "challenge_dir": "/tmp/chal",
            "challenge_files": {"main.c": {"path": "/tmp/chal/main.c"}},
        }
        cmd = _build_tool_command("auto_steg_extract", {}, state)
        assert cmd is None


class TestBuildFileCarve:
    def test_with_challenge_dir(self):
        state = {
            "challenge_dir": "/tmp/chal",
            "challenge_files": {},
        }
        cmd = _build_tool_command("auto_file_carve", {}, state)
        assert cmd is not None
        assert "auto_file_carve.py" in cmd

    def test_no_challenge_dir(self):
        state = {"challenge_dir": ""}
        cmd = _build_tool_command("auto_file_carve", {}, state)
        assert cmd is None


class TestBuildPwnTemplate:
    def test_with_binary(self):
        state = {
            "challenge_path": "/tmp/chal/vuln",
            "flag_format": r"flag\{[^}]+\}",
        }
        cmd = _build_tool_command("auto_pwn_template", {}, state)
        assert cmd is not None
        assert "auto_pwn_template.py" in cmd
        assert "--flag-format" in cmd

    def test_with_directory_path(self, tmp_path):
        """Pwn template needs a binary, not a directory."""
        state = {"challenge_path": str(tmp_path)}
        cmd = _build_tool_command("auto_pwn_template", {}, state)
        assert cmd is None

    def test_no_binary(self):
        state = {"challenge_path": ""}
        cmd = _build_tool_command("auto_pwn_template", {}, state)
        assert cmd is None


class TestBuildRopExtract:
    def test_with_binary(self):
        state = {"challenge_path": "/tmp/chal/vuln"}
        cmd = _build_tool_command("auto_rop_extract", {}, state)
        assert cmd is not None
        assert "auto_rop_extract.py" in cmd

    def test_no_binary(self):
        state = {"challenge_path": ""}
        cmd = _build_tool_command("auto_rop_extract", {}, state)
        assert cmd is None
