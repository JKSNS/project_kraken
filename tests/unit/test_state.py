"""Unit tests for KrakenState and related helpers."""
from kraken.state import KrakenState, initial_state
from kraken.nodes.triage import _detect_remote_from_text, _detect_remote_from_docker_compose


def test_initial_state_fields():
    state = initial_state("test-1", "/tmp/binary")
    assert state["challenge_id"] == "test-1"
    assert state["challenge_path"] == "/tmp/binary"
    assert state["flag_format"] == r"flag\{[a-zA-Z0-9_]+\}"
    assert state["solve_scripts"] == []
    assert state["strategies_tried"] == []
    assert state["iteration_count"] == 0
    assert state["recent_actions"] == []


def test_initial_state_custom_flag():
    state = initial_state("test-2", "/tmp/b", flag_format=r"CTF\{.*\}")
    assert state["flag_format"] == r"CTF\{.*\}"


def test_initial_state_new_fields():
    """Verify new timing, multi-file, and remote fields are initialized."""
    state = initial_state("test-3", "/tmp/binary")
    assert state["node_timings"] == []
    assert state["solve_path"] == []
    assert state["challenge_files"] == {}
    assert state["remote_info"] == {}


def test_initial_state_improvement_fields():
    """Verify fields from improvements #1, #2, #3 are initialized."""
    state = initial_state("test-4", "/tmp/binary")
    assert state["failure_diagnosis"] == ""
    assert state["script_findings"] == []
    assert state["secondary_types"] == []


def test_initial_state_benchmark_mode():
    """Verify benchmark mode can be set."""
    state = initial_state("test-5", "/tmp/binary", benchmark=True)
    assert state["benchmark"] is True
    state_default = initial_state("test-6", "/tmp/binary")
    assert state_default["benchmark"] is False


# ── Remote detection tests ──────────────────────────────────────────


def test_detect_remote_nc():
    text = "Connect with: nc pwn.example.com 1337"
    info = _detect_remote_from_text(text)
    assert info["host"] == "pwn.example.com"
    assert info["port"] == 1337
    assert info["source"] == "description"


def test_detect_remote_ncat():
    text = "ncat challenge.ctf.io 9001"
    info = _detect_remote_from_text(text)
    assert info["host"] == "challenge.ctf.io"
    assert info["port"] == 9001


def test_detect_remote_connect_to():
    text = "Connect to example.com:4444 to get the flag"
    info = _detect_remote_from_text(text)
    assert info["host"] == "example.com"
    assert info["port"] == 4444


def test_detect_remote_standalone_host_port():
    text = "challenge.ctf.io:31337"
    info = _detect_remote_from_text(text)
    assert info["host"] == "challenge.ctf.io"
    assert info["port"] == 31337


def test_detect_remote_no_match():
    text = "This is a regular binary challenge with no remote component."
    info = _detect_remote_from_text(text)
    assert info == {}


def test_detect_remote_docker_compose():
    content = """version: '3'
services:
  chall:
    build: .
    ports:
      - "1337:1337"
"""
    info = _detect_remote_from_docker_compose(content)
    assert info["host"] == "localhost"
    assert info["port"] == 1337
    assert info["source"] == "docker-compose"


def test_detect_remote_docker_compose_no_ports():
    content = """version: '3'
services:
  chall:
    build: .
"""
    info = _detect_remote_from_docker_compose(content)
    assert info == {}
