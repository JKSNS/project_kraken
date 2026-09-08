"""Decompile node -- Ghidra-based analysis with pyelftools+capstone fallback."""
from __future__ import annotations

import os

from kraken.state import KrakenState
from kraken.config import DockerConfig, EvolutionConfig
from kraken.storage.artifact_store import ArtifactStore
from kraken.tools.ghidra import decompile_all_functions, extract_call_graph, GhidraConfig
from kraken.tools.base import ToolResult
from kraken.tools.installer import ensure_tools
from kraken.logging.structured import get_logger

log = get_logger(__name__)


def _is_dotnet_binary(path: str) -> bool:
    """Quick check: is this a .NET assembly?"""
    try:
        data = open(path, "rb").read(4096)
        return b"mscoree.dll" in data or b"_CorExeMain" in data
    except Exception:
        return False


async def _decompile_dotnet(binary_path: str, state: KrakenState) -> dict:
    """Attempt to decompile a .NET/CIL assembly using available tools.

    Tries in order: ilspycmd → monodis → pefile metadata extraction.
    Auto-installs missing tools via the KRAKEN installer before falling back.
    """
    import asyncio
    import shutil

    log.info("decompile_dotnet_start", binary=binary_path)
    functions: dict = {}
    tool_used = "none"

    # Auto-install missing .NET tools before attempting decompilation
    needed = [t for t in ["ilspycmd", "monodis"] if not shutil.which(t)]
    if needed:
        log.info("decompile_dotnet_installing_tools", tools=needed)
        await ensure_tools(*needed)

    # 1. ilspycmd (dotnet tool -- install: dotnet tool install -g ilspycmd)
    if shutil.which("ilspycmd"):
        try:
            proc = await asyncio.create_subprocess_exec(
                "ilspycmd", binary_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            output = stdout.decode(errors="replace")
            if output.strip():
                functions["__cil_source__"] = output[:40000]
                tool_used = "ilspycmd"
                log.info("decompile_dotnet_ilspycmd_success", chars=len(output))
        except Exception as e:
            log.warning("decompile_dotnet_ilspycmd_failed", error=str(e))

    # 2. monodis (from mono-utils package)
    if not functions and shutil.which("monodis"):
        try:
            proc = await asyncio.create_subprocess_exec(
                "monodis", "--output=/dev/stdout", binary_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            output = stdout.decode(errors="replace")
            if output.strip():
                functions["__cil_disasm__"] = output[:40000]
                tool_used = "monodis"
                log.info("decompile_dotnet_monodis_success", chars=len(output))
        except Exception as e:
            log.warning("decompile_dotnet_monodis_failed", error=str(e))

    # 3. pefile metadata extraction (always available -- strings + method names)
    if not functions:
        try:
            import pefile
            pe = pefile.PE(binary_path)
            metadata: list[str] = []

            # Dump all sections
            for sec in pe.sections:
                name = sec.Name.rstrip(b"\x00").decode(errors="replace")
                metadata.append(f"Section: {name}  VSize={sec.Misc_VirtualSize:#x}  RVA={sec.VirtualAddress:#x}")

            # Import table
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode(errors="replace")
                    for imp in entry.imports:
                        func = imp.name.decode(errors="replace") if imp.name else f"ord_{imp.ordinal}"
                        metadata.append(f"Import: {dll}!{func}")

            # String resources / user strings from #US heap (needs dnfile for full CIL)
            dotnet_hint = (
                "\n\nNOTE: This is a .NET/CIL binary. The above is PE metadata only.\n"
                "To get real C# source: install ilspycmd via `dotnet tool install -g ilspycmd`\n"
                "or mono-utils for `monodis`. Then re-run this challenge.\n"
                "The solve engine can also try: subprocess.run(['monodis', path]) "
                "or attempt to run the binary directly with `mono` or `dotnet`."
            )
            functions["__pe_metadata__"] = "\n".join(metadata) + dotnet_hint
            tool_used = "pefile_metadata"
            log.info("decompile_dotnet_pefile_metadata", entries=len(metadata))
        except Exception as e:
            log.warning("decompile_dotnet_pefile_failed", error=str(e))

    action_summary = f".NET binary -- decompiled via {tool_used}" if functions else ".NET binary -- no decompiler available (install ilspycmd or monodis)"

    updates: dict = {
        "recent_actions": [{
            "action": "decompile",
            "reasoning": "Detected .NET/CIL assembly -- using .NET-specific decompilation path",
            "result_summary": action_summary,
        }],
        "iteration_count": state.get("iteration_count", 0) + 1,
    }
    if functions:
        updates["decompiled_functions"] = functions
        log.info("decompile_dotnet_success", tool=tool_used, num_entries=len(functions))
    else:
        updates["error_log"] = [{"node": "decompile", "error": "No .NET decompiler found. Install ilspycmd or monodis."}]
    return updates


async def _decompile_pyc(binary_path: str, state: KrakenState) -> dict:
    """Decompile a Python .pyc file using uncompyle6."""
    import asyncio

    log.info("decompile_pyc_start", binary=binary_path)

    source = ""
    tool_used = "none"

    # Try uncompyle6 first (supports Python 3.8 bytecode)
    try:
        proc = await asyncio.create_subprocess_exec(
            "uncompyle6", binary_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        if proc.returncode == 0 and stdout.strip():
            source = stdout.decode(errors="replace")
            tool_used = "uncompyle6"
            log.info("decompile_pyc_success", tool="uncompyle6", source_len=len(source))
    except (asyncio.TimeoutError, FileNotFoundError):
        pass

    # Try decompile3 / pycdc as fallback
    if not source:
        for tool in ["decompile3", "pycdc"]:
            try:
                import shutil
                if not shutil.which(tool):
                    continue
                proc = await asyncio.create_subprocess_exec(
                    tool, binary_path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
                if proc.returncode == 0 and stdout.strip():
                    source = stdout.decode(errors="replace")
                    tool_used = tool
                    break
            except Exception:
                continue

    # Try Python's dis module as last resort
    if not source:
        try:
            proc = await asyncio.create_subprocess_exec(
                "python3", "-c",
                f"import dis, marshal; f=open('{binary_path}','rb'); f.read(16); code=marshal.loads(f.read()); dis.dis(code)",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            if stdout.strip():
                source = "[dis bytecode]\n" + stdout.decode(errors="replace")
                tool_used = "dis"
        except Exception:
            pass

    functions = {"__pyc_source__": source} if source else {}
    updates: dict = {
        "recent_actions": [{
            "action": "decompile",
            "reasoning": f"Python bytecode decompiled with {tool_used}",
            "result_summary": f"Decompiled {len(source)} chars of Python source" if source else "PYC decompilation failed",
        }],
        "iteration_count": state.get("iteration_count", 0) + 1,
    }
    if functions:
        updates["decompiled_functions"] = functions
        updates.update(_store_decompile_artifact(state, functions))
        log.info("decompile_pyc_complete", tool=tool_used, source_chars=len(source))
    else:
        log.warning("decompile_pyc_failed", binary=binary_path)
        updates["error_log"] = [{"node": "decompile", "error": "PYC decompilation failed. Install: pip install uncompyle6"}]
    return updates


async def _extract_vba_macro(binary_path: str, state: KrakenState) -> dict:
    """Extract VBA macro source from an Office document using olevba."""
    import asyncio
    import shutil

    log.info("decompile_vba_start", binary=binary_path)

    vba_source = ""
    tool_used = "none"

    # Try olevba (oletools)
    olevba_path = shutil.which("olevba") or shutil.which("olevba3")
    if not olevba_path:
        # Try as python module
        try:
            olevba_check = await asyncio.create_subprocess_exec(
                "python3", "-m", "oletools.olevba", "--version",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await olevba_check.communicate()
            olevba_path = "python3 -m oletools.olevba"  # use module form
        except Exception:
            pass

    if olevba_path:
        try:
            if olevba_path.startswith("python3"):
                cmd = ["python3", "-m", "oletools.olevba", "--decode", binary_path]
            else:
                cmd = [olevba_path, "--decode", binary_path]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
            out = stdout.decode(errors="replace")
            if out.strip():
                vba_source = out
                tool_used = "olevba"
                log.info("decompile_vba_success", tool="olevba", source_len=len(vba_source))
        except (asyncio.TimeoutError, Exception) as e:
            log.warning("decompile_vba_olevba_failed", error=str(e))

    functions = {"__vba_source__": vba_source} if vba_source else {}
    updates: dict = {
        "recent_actions": [{
            "action": "decompile",
            "reasoning": f"VBA macro extracted with {tool_used}",
            "result_summary": f"Extracted {len(vba_source)} chars of VBA source" if vba_source else "VBA extraction failed",
        }],
        "iteration_count": state.get("iteration_count", 0) + 1,
    }
    if functions:
        updates["decompiled_functions"] = functions
        log.info("decompile_vba_complete", tool=tool_used, source_chars=len(vba_source))
    else:
        log.warning("decompile_vba_failed", binary=binary_path)
        updates["error_log"] = [{"node": "decompile", "error": "VBA extraction failed. Install: pip install oletools"}]
    return updates


_SOURCE_EXTENSIONS = {".py", ".js", ".rb", ".pl", ".sh", ".c", ".cpp", ".java", ".rs", ".go", ".php", ".lua", ".ts", ".asm", ".s", ".vbs"}
_DATA_TEXT_EXTENSIONS = {".log", ".csv", ".txt", ".xml", ".html", ".sql", ".ini", ".cfg", ".conf", ".toml", ".json", ".yaml", ".yml"}
_SOURCE_SKIP = {"challenge.json", "challenge.yaml", "challenge.yml", "readme.md", "readme.txt"}


def _read_source_files(dir_path: str, state: KrakenState) -> dict:
    """Read source code and text data files from a challenge directory.

    For Python-only, script-based, or forensics challenges that have no binary.
    Reads both source code (.py, .js, etc.) and text data (.log, .csv, etc.).
    """
    from pathlib import Path

    functions: dict = {}
    root = Path(dir_path)

    for entry in sorted(root.rglob("*")):
        if not entry.is_file():
            continue
        if entry.name.lower() in _SOURCE_SKIP:
            continue
        if entry.name.startswith("."):
            continue
        # Skip solve artifacts from previous runs (pollute prompt)
        if entry.name.startswith("solve_attempt"):
            continue

        ext = entry.suffix.lower()
        is_source = ext in _SOURCE_EXTENSIONS
        is_data = ext in _DATA_TEXT_EXTENSIONS

        if not is_source and not is_data:
            continue
        # Skip files larger than 500KB
        if entry.stat().st_size > 500_000:
            continue

        try:
            content = entry.read_text(errors="replace")
            rel = str(entry.relative_to(root))
            prefix = "__source_" if is_source else "__data_"
            key = f"{prefix}{rel}__"
            functions[key] = content[:40000]
            log.info("decompile_read_source", file=rel, chars=len(content), type="source" if is_source else "data")
        except OSError:
            continue

    return functions


def _store_decompile_artifact(state: KrakenState, functions: dict) -> dict:
    """If artifact store is enabled, store functions as an artifact and return handle updates."""
    store_path = state.get("artifact_store_path", "")
    if not store_path or not EvolutionConfig().enable_artifact_store:
        return {}
    try:
        store = ArtifactStore(store_path)
        handle = store.put("decompiled_functions", functions)
        log.info("decompile_artifact_stored", handle=handle, size_keys=len(functions))
        return {"decompiled_functions_handle": handle}
    except Exception as exc:
        log.warning("decompile_artifact_store_failed", error=str(exc))
        return {}


async def decompile(state: KrakenState) -> dict:
    """Run Ghidra headless decompilation. Falls back to capstone disassembly.

    If the challenge path is a directory (no binary found by triage),
    skip decompilation entirely -- the solve engine will work from
    challenge_files content previews instead.
    """
    binary_path = state["challenge_path"]

    log.info("decompile_start", binary=binary_path)

    # If the path is a directory, there's no binary to decompile.
    # But we should check for source files (.py, .js, etc.) and read them.
    if os.path.isdir(binary_path):
        # Check for .pyc files in the directory before reading source
        from pathlib import Path as _P
        _pyc_files = sorted(_P(binary_path).rglob("*.pyc"))
        if _pyc_files:
            log.info("decompile_pyc_in_directory", pyc=str(_pyc_files[0]))
            return await _decompile_pyc(str(_pyc_files[0]), state)

        log.info("decompile_scanning_directory_for_source", directory=binary_path)
        source_functions = _read_source_files(binary_path, state)
        if source_functions:
            log.info("decompile_source_files_found", count=len(source_functions))
            updates = {
                "decompiled_functions": source_functions,
                "recent_actions": [{
                    "action": "decompile",
                    "reasoning": "No binary found -- read source files directly",
                    "result_summary": f"Read {len(source_functions)} source files as decompiled functions",
                }],
                "iteration_count": state.get("iteration_count", 0) + 1,
            }
            updates.update(_store_decompile_artifact(state, source_functions))
            return updates
        log.info("decompile_skip_directory", directory=binary_path)
        return {
            "recent_actions": [{
                "action": "decompile",
                "reasoning": "Challenge path is a directory (no binary, no source) -- skipping decompilation",
                "result_summary": f"Skipped: directory with {len(state.get('challenge_files', {}))} files, no source found",
            }],
            "iteration_count": state.get("iteration_count", 0) + 1,
        }

    # .NET/CIL binaries: try specialised decompilers first, skip Ghidra
    dotnet_note = state.get("binary_info", {}).get("is_dotnet") or _is_dotnet_binary(binary_path)
    if dotnet_note:
        result = await _decompile_dotnet(binary_path, state)
        return result

    # Python bytecode (.pyc): decompile with uncompyle6
    if state.get("binary_info", {}).get("is_pyc") or binary_path.endswith(".pyc"):
        return await _decompile_pyc(binary_path, state)

    # Office macro documents: extract VBA with olevba
    if state.get("binary_info", {}).get("is_macro") or any(
        binary_path.endswith(ext) for ext in (".xlsm", ".xls", ".xlsb", ".doc", ".docm", ".pptm")
    ):
        return await _extract_vba_macro(binary_path, state)

    ghidra_dir = os.environ.get("GHIDRA_INSTALL_DIR") or DockerConfig().ghidra_install_dir
    # Validate the resolved path is accessible; fall back to _find_ghidra()
    if ghidra_dir:
        headless = os.path.join(ghidra_dir, "support", "analyzeHeadless")
        if not os.access(headless, os.X_OK):
            log.info("decompile_ghidra_path_inaccessible", path=ghidra_dir)
            from kraken.tools.ghidra import _find_ghidra
            found = _find_ghidra()
            if found:
                log.info("decompile_ghidra_path_resolved", resolved=found)
                ghidra_dir = found
    ghidra_cfg = GhidraConfig(ghidra_install_dir=ghidra_dir)

    # Try Ghidra first
    try:
        decomp_result = await decompile_all_functions(binary_path, config=ghidra_cfg, workspace_dir=state.get("solve_workspace") or None)
    except Exception as e:
        log.warning("decompile_exception", error=str(e))
        decomp_result = ToolResult(tool="ghidra", success=False, error=str(e))

    try:
        graph_result = await extract_call_graph(binary_path, config=ghidra_cfg, workspace_dir=state.get("solve_workspace") or None)
    except Exception as e:
        log.warning("call_graph_exception", error=str(e))
        graph_result = ToolResult(tool="ghidra", success=False, error=str(e))

    decomp_data = decomp_result.data if isinstance(decomp_result.data, dict) else {}
    functions = decomp_data.get("functions", {})

    # Fallback: if Ghidra failed, use pyelftools + capstone disassembly
    if not functions:
        log.info(
            "decompile_ghidra_unavailable_trying_disasm",
            ghidra_install_dir=ghidra_dir,
            ghidra_error=decomp_result.error or "unknown",
            call_graph_error=graph_result.error or "unknown",
        )
        try:
            from kraken.tools.disasm import disassemble_elf
            disasm_result = await disassemble_elf(binary_path)
            if disasm_result.success and isinstance(disasm_result.data, dict):
                functions = disasm_result.data.get("functions", {})
                log.info("disasm_fallback_success", num_functions=len(functions))
        except Exception as e:
            log.warning("disasm_fallback_failed", error=str(e))

    updates: dict = {
        "recent_actions": [{
            "action": "decompile",
            "reasoning": "Binary analysis (Ghidra or disassembly fallback)",
            "result_summary": f"Extracted {len(functions)} functions" if functions else f"Failed: {decomp_result.error}",
        }],
        "iteration_count": state.get("iteration_count", 0) + 1,
    }

    if functions:
        updates["decompiled_functions"] = functions
        updates.update(_store_decompile_artifact(state, functions))
        log.info("decompile_success", num_functions=len(functions))
    else:
        log.warning("decompile_failed", error=decomp_result.error or decomp_result.stderr)
        updates["error_log"] = [{"node": "decompile", "error": decomp_result.error or decomp_result.stderr}]

    if graph_result.success and isinstance(graph_result.data, dict):
        updates["call_graph"] = graph_result.data.get("call_graph", {})
        ghidra_strings = graph_result.data.get("strings", [])
        existing = state.get("strings_of_interest", [])
        all_strings = list(dict.fromkeys(existing + ghidra_strings))
        updates["strings_of_interest"] = all_strings

    return updates
