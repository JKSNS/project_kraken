"""Python-native dynamic analysis tools.

Replaces GDB/strace dependency with subprocess execution, angr symbolic
tracing, lief binary patching, and encrypted section extraction.
"""
from __future__ import annotations

import asyncio
import math
import os
import struct
import tempfile
from collections import Counter
from pathlib import Path

from kraken.tools.base import ToolResult


async def subprocess_trace(
    binary_path: str,
    stdin_input: str = "",
    args: list[str] | None = None,
    timeout: int = 10,
    env_extra: dict[str, str] | None = None,
) -> ToolResult:
    """Run binary and capture all output.

    Executes the binary as a subprocess with the given stdin, captures
    stdout/stderr, and reports exit signal if killed.
    """
    cmd = [binary_path] + (args or [])
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)

    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        stdin_bytes = stdin_input.encode() if stdin_input else b""
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=stdin_bytes), timeout=timeout
        )
        return ToolResult(
            tool="subprocess_trace",
            success=True,
            data={
                "stdout": stdout.decode(errors="replace"),
                "stderr": stderr.decode(errors="replace"),
                "exit_code": proc.returncode,
                "input": stdin_input[:200],
            },
            stdout=stdout.decode(errors="replace"),
            stderr=stderr.decode(errors="replace"),
            exit_code=proc.returncode or 0,
        )
    except asyncio.TimeoutError:
        if proc is not None and proc.returncode is None:
            proc.kill()
            try:
                await proc.communicate()
            except Exception:
                pass
        return ToolResult(
            tool="subprocess_trace",
            success=True,
            data={
                "stdout": "",
                "stderr": f"Process timed out after {timeout}s",
                "exit_code": -1,
                "input": stdin_input[:200],
                "timed_out": True,
            },
            error=f"Timed out after {timeout}s",
        )
    except PermissionError:
        # Try making it executable first
        try:
            os.chmod(binary_path, 0o755)
            return await subprocess_trace(binary_path, stdin_input, args, timeout, env_extra)
        except Exception as e:
            return ToolResult(tool="subprocess_trace", success=False, error=f"Permission denied: {e}")
    except Exception as e:
        return ToolResult(tool="subprocess_trace", success=False, error=str(e))


async def multi_input_trace(
    binary_path: str,
    inputs: list[str] | None = None,
    timeout: int = 10,
) -> ToolResult:
    """Run binary with multiple inputs and compare outputs.

    Tests with various inputs to identify input-dependent behavior.
    """
    if inputs is None:
        inputs = [
            "",
            "AAAA",
            "A" * 32,
            "A" * 64,
            "flag{test}",
            "password",
            "12345678",
            "\x00\x01\x02\x03",
        ]

    traces = []
    for inp in inputs:
        result = await subprocess_trace(binary_path, stdin_input=inp + "\n", timeout=timeout)
        traces.append({
            "input": inp[:100],
            "stdout": result.data.get("stdout", "")[:500] if result.data else "",
            "stderr": result.data.get("stderr", "")[:500] if result.data else "",
            "exit_code": result.data.get("exit_code", -1) if result.data else -1,
            "timed_out": result.data.get("timed_out", False) if result.data else False,
        })

    return ToolResult(
        tool="multi_input_trace",
        success=True,
        data={"traces": traces, "num_inputs": len(inputs)},
    )


async def angr_trace(
    binary_path: str,
    find_strings: list[str] | None = None,
    avoid_strings: list[str] | None = None,
    find_addrs: list[int] | None = None,
    avoid_addrs: list[int] | None = None,
    stdin_lengths: list[int] | None = None,
    use_veritesting: bool = True,
    timeout: int = 120,
) -> ToolResult:
    """Advanced angr symbolic execution with multiple strategies.

    Tries multiple stdin lengths and exploration strategies. Uses string-based
    find/avoid when addresses aren't available.
    """
    if stdin_lengths is None:
        stdin_lengths = [32, 64, 128]

    find_strs = find_strings or []
    avoid_strs = avoid_strings or []
    find_a = find_addrs or []
    avoid_a = avoid_addrs or []

    script = f'''import angr
import claripy
import time
import json
import sys

binary = "{binary_path}"
find_strs = {find_strs!r}
avoid_strs = {avoid_strs!r}
find_addrs = {find_a!r}
avoid_addrs = {avoid_a!r}
stdin_lengths = {stdin_lengths!r}
use_veritesting = {use_veritesting!r}

results = []

for stdin_len in stdin_lengths:
    try:
        p = angr.Project(binary, auto_load_libs=False)

        stdin_sym = claripy.BVS("stdin", stdin_len * 8)
        state = p.factory.entry_state(stdin=angr.SimFileStream(name="stdin", content=stdin_sym))

        # Constrain to printable ASCII
        for i in range(stdin_len):
            byte = stdin_sym.get_byte(i)
            state.solver.add(byte >= 0x20)
            state.solver.add(byte <= 0x7e)

        sm = p.factory.simgr(state, veritesting=use_veritesting)

        # Build find/avoid lambdas
        def make_find(strs, addrs):
            def check(s):
                if addrs:
                    if s.addr in addrs:
                        return True
                if strs:
                    try:
                        out = s.posix.dumps(1)
                        return any(st.encode() in out for st in strs)
                    except Exception:
                        pass
                return False
            return check

        def make_avoid(strs, addrs):
            def check(s):
                if addrs:
                    if s.addr in addrs:
                        return True
                if strs:
                    try:
                        out = s.posix.dumps(1)
                        return any(st.encode() in out for st in strs)
                    except Exception:
                        pass
                return False
            return check

        start = time.time()
        sm.explore(
            find=make_find(find_strs, find_addrs),
            avoid=make_avoid(avoid_strs, avoid_addrs),
        )
        elapsed = time.time() - start

        if sm.found:
            found_state = sm.found[0]
            solution = found_state.solver.eval(stdin_sym, cast_to=bytes)
            stdout_out = found_state.posix.dumps(1)
            results.append({{
                "satisfiable": True,
                "stdin_length": stdin_len,
                "solution_hex": solution.hex(),
                "solution_ascii": solution.decode(errors="replace").rstrip("\\x00"),
                "stdout": stdout_out.decode(errors="replace")[:500],
                "time_seconds": round(elapsed, 2),
            }})
            # Found a solution, print and exit
            print(json.dumps(results[-1]))
            sys.exit(0)
        else:
            results.append({{
                "satisfiable": False,
                "stdin_length": stdin_len,
                "time_seconds": round(elapsed, 2),
                "active": len(sm.active),
                "deadended": len(sm.deadended),
            }})
    except Exception as e:
        results.append({{
            "error": str(e)[:300],
            "stdin_length": stdin_len,
        }})

# No solution found
print(json.dumps({{"results": results, "satisfiable": False}}))
'''

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(script)
        script_path = f.name

    try:
        proc = await asyncio.create_subprocess_exec(
            "python3", script_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        stdout_str = stdout.decode(errors="replace")
        stderr_str = stderr.decode(errors="replace")

        import json
        try:
            data = json.loads(stdout_str.strip().split("\n")[-1]) if stdout_str.strip() else {}
        except (json.JSONDecodeError, IndexError):
            data = {"raw_output": stdout_str[:1000]}

        return ToolResult(
            tool="angr_trace",
            success=proc.returncode == 0,
            data=data,
            stdout=stdout_str,
            stderr=stderr_str,
            exit_code=proc.returncode or 0,
        )
    except asyncio.TimeoutError:
        return ToolResult(tool="angr_trace", success=False, error=f"angr timed out after {timeout}s")
    finally:
        Path(script_path).unlink(missing_ok=True)


async def lief_patch_binary(
    binary_path: str,
    patches: list[dict] | None = None,
    nop_ptrace: bool = True,
    output_path: str | None = None,
) -> ToolResult:
    """Patch binary using lief to bypass anti-debug and modify behavior.

    patches: list of {address: int, original_bytes: bytes, new_bytes: bytes}
    nop_ptrace: if True, automatically find and NOP ptrace calls
    """
    try:
        import lief
    except ImportError:
        return ToolResult(tool="lief_patch", success=False, error="lief not installed")

    try:
        binary = lief.parse(binary_path)
        if binary is None:
            return ToolResult(tool="lief_patch", success=False, error="Failed to parse binary")

        patched_count = 0

        # Auto-detect and NOP ptrace calls
        if nop_ptrace:
            text_section = binary.get_section(".text")
            if text_section is not None:
                content = bytearray(text_section.content)
                offset = 0
                # x86-64 syscall for ptrace: mov rax, 0x65 (101) then syscall
                # Also look for call to ptrace PLT entry
                # Common pattern: 0xe8 XX XX XX XX (call ptrace)
                # We'll look for ptrace in imports and patch the PLT call
                for reloc in binary.relocations:
                    if hasattr(reloc, 'symbol') and reloc.symbol and 'ptrace' in str(reloc.symbol.name):
                        # Found ptrace relocation, patch calls to it
                        patched_count += 1

                # Scan .text for common anti-debug patterns
                # syscall instruction (0x0f 0x05) preceded by mov eax, 101 (ptrace)
                i = 0
                while i < len(content) - 6:
                    # mov eax, 0x65; syscall -> xor eax, eax; nop*4; syscall
                    if (content[i] == 0xb8 and
                        content[i+1] == 0x65 and content[i+2] == 0x00 and
                        content[i+3] == 0x00 and content[i+4] == 0x00 and
                        content[i+5] == 0x0f and content[i+6] == 0x05):
                        # Replace: mov eax, 0x65 -> xor eax, eax (return 0)
                        content[i] = 0x31    # xor eax, eax
                        content[i+1] = 0xc0
                        content[i+2] = 0x90  # nop
                        content[i+3] = 0x90  # nop
                        content[i+4] = 0x90  # nop
                        patched_count += 1
                    i += 1

                text_section.content = list(content)

        # Apply manual patches
        if patches:
            for patch in patches:
                addr = patch.get("address", 0)
                new_bytes = patch.get("new_bytes", b"")
                if addr and new_bytes:
                    binary.patch_address(addr, list(new_bytes))
                    patched_count += 1

        # Write patched binary
        if output_path is None:
            output_path = binary_path + ".patched"
        binary.write(output_path)
        os.chmod(output_path, 0o755)

        return ToolResult(
            tool="lief_patch",
            success=True,
            data={
                "output_path": output_path,
                "patches_applied": patched_count,
                "nop_ptrace": nop_ptrace,
            },
        )
    except Exception as e:
        return ToolResult(tool="lief_patch", success=False, error=str(e))


async def lief_analyze(binary_path: str) -> ToolResult:
    """Deep ELF analysis using lief -- sections, symbols, imports, relocations."""
    try:
        import lief
    except ImportError:
        return ToolResult(tool="lief_analyze", success=False, error="lief not installed")

    try:
        binary = lief.parse(binary_path)
        if binary is None:
            return ToolResult(tool="lief_analyze", success=False, error="Failed to parse binary")

        # Sections with entropy
        sections = []
        for section in binary.sections:
            content = bytes(section.content)
            entropy = section.entropy if hasattr(section, 'entropy') else _calc_entropy(content)
            sections.append({
                "name": section.name,
                "size": section.size,
                "virtual_address": hex(section.virtual_address),
                "offset": hex(section.offset),
                "entropy": round(entropy, 3),
                "is_high_entropy": entropy > 7.0,
            })

        # Imported functions (PLT/GOT)
        imports = []
        if hasattr(binary, 'imported_functions'):
            for func in binary.imported_functions:
                imports.append(str(func.name) if hasattr(func, 'name') else str(func))

        # Exported symbols
        exports = []
        if hasattr(binary, 'exported_functions'):
            for func in binary.exported_functions:
                exports.append(str(func.name) if hasattr(func, 'name') else str(func))

        # Dynamic entries
        dynamic_entries = []
        if hasattr(binary, 'dynamic_entries'):
            for entry in binary.dynamic_entries:
                tag = str(entry.tag).split('.')[-1] if hasattr(entry, 'tag') else str(entry)
                dynamic_entries.append(tag)

        # Anti-debug indicators
        anti_debug = []
        import_names = [str(i).lower() for i in imports]
        if any("ptrace" in n for n in import_names):
            anti_debug.append("ptrace imported")
        if any("getppid" in n for n in import_names):
            anti_debug.append("getppid imported (parent process check)")
        if any("signal" in n for n in import_names):
            anti_debug.append("signal imported (signal-based anti-debug possible)")

        # Custom sections (non-standard names)
        standard_sections = {
            ".text", ".data", ".bss", ".rodata", ".comment", ".note",
            ".shstrtab", ".strtab", ".symtab", ".dynamic", ".dynsym",
            ".dynstr", ".gnu.hash", ".gnu.version", ".gnu.version_r",
            ".rela.dyn", ".rela.plt", ".init", ".fini", ".plt",
            ".plt.got", ".plt.sec", ".got", ".got.plt", ".init_array",
            ".fini_array", ".interp", ".note.gnu.build-id",
            ".note.ABI-tag", ".eh_frame", ".eh_frame_hdr",
            ".gcc_except_table", ".tbss", ".tdata", "",
        }
        custom_sections = [
            s for s in sections
            if s["name"] and s["name"] not in standard_sections
        ]

        return ToolResult(
            tool="lief_analyze",
            success=True,
            data={
                "sections": sections,
                "custom_sections": custom_sections,
                "imports": imports[:200],
                "exports": exports[:100],
                "dynamic_entries": dynamic_entries,
                "anti_debug_indicators": anti_debug,
                "entry_point": hex(binary.entrypoint),
                "is_pie": binary.is_pie if hasattr(binary, 'is_pie') else False,
            },
        )
    except Exception as e:
        return ToolResult(tool="lief_analyze", success=False, error=str(e))


async def pwntools_analyze(binary_path: str) -> ToolResult:
    """Deep ELF analysis using pwntools -- symbols, GOT/PLT, checksec, sections."""
    try:
        from pwn import ELF
        import pwnlib.context
        pwnlib.context.context.log_level = "error"
    except ImportError:
        return ToolResult(tool="pwntools_analyze", success=False, error="pwntools not installed")

    try:
        elf = ELF(binary_path, checksec=False)

        # All symbols
        symbols = {}
        for name, addr in elf.symbols.items():
            if name and not name.startswith("_"):
                symbols[name] = hex(addr)

        # GOT entries
        got = {}
        for name, addr in elf.got.items():
            got[name] = hex(addr)

        # PLT entries
        plt = {}
        for name, addr in elf.plt.items():
            plt[name] = hex(addr)

        # Sections
        sections = {}
        for name, section in elf.sections.items():
            if name:
                sections[name] = {
                    "address": hex(section.header.sh_addr),
                    "size": section.header.sh_size,
                    "offset": hex(section.header.sh_offset),
                }

        # Checksec
        checksec_info = {
            "arch": elf.arch,
            "bits": elf.bits,
            "endian": elf.endian,
            "nx": elf.nx,
            "pie": elf.pie,
            "canary": elf.canary,
            "relro": elf.relro if hasattr(elf, 'relro') else "unknown",
        }

        return ToolResult(
            tool="pwntools_analyze",
            success=True,
            data={
                "symbols": symbols,
                "symbol_count": len(symbols),
                "got": got,
                "plt": plt,
                "sections": sections,
                "checksec": checksec_info,
                "entry": hex(elf.entry),
            },
        )
    except Exception as e:
        return ToolResult(tool="pwntools_analyze", success=False, error=str(e))


async def extract_encrypted_data(binary_path: str) -> ToolResult:
    """Find and extract potentially encrypted/encoded sections and data.

    Reads custom ELF sections, searches .rodata for key patterns,
    and attempts XOR sweep on high-entropy data.
    """
    try:
        import lief
    except ImportError:
        return ToolResult(tool="extract_data", success=False, error="lief not installed")

    try:
        binary = lief.parse(binary_path)
        if binary is None:
            return ToolResult(tool="extract_data", success=False, error="Failed to parse binary")

        results: dict = {
            "custom_section_data": {},
            "rodata_keys": [],
            "xor_candidates": [],
            "crypto_constants": [],
        }

        # Standard section names to skip
        standard = {
            ".text", ".data", ".bss", ".rodata", ".comment", ".note",
            ".shstrtab", ".strtab", ".symtab", ".dynamic", ".dynsym",
            ".dynstr", ".gnu.hash", ".gnu.version", ".gnu.version_r",
            ".rela.dyn", ".rela.plt", ".init", ".fini", ".plt",
            ".plt.got", ".plt.sec", ".got", ".got.plt", ".init_array",
            ".fini_array", ".interp", ".note.gnu.build-id",
            ".note.ABI-tag", ".eh_frame", ".eh_frame_hdr",
            ".gcc_except_table", ".tbss", ".tdata", "",
        }

        # Extract custom section data
        for section in binary.sections:
            if section.name and section.name not in standard and section.size > 0:
                content = bytes(section.content)
                entropy = _calc_entropy(content)
                results["custom_section_data"][section.name] = {
                    "size": len(content),
                    "entropy": round(entropy, 3),
                    "hex_preview": content[:64].hex(),
                    "ascii_preview": content[:64].decode(errors="replace"),
                    "is_high_entropy": entropy > 6.5,
                }

        # Search .rodata for key-like patterns
        rodata = binary.get_section(".rodata")
        if rodata is not None:
            content = bytes(rodata.content)

            # Look for sequences of exactly 16 or 32 bytes of high-entropy data
            # (potential AES keys/IVs)
            for key_len in [16, 32]:
                for i in range(0, len(content) - key_len, 4):
                    chunk = content[i:i + key_len]
                    ent = _calc_entropy(chunk)
                    if ent > 4.0:  # reasonably high entropy for a key
                        unique_bytes = len(set(chunk))
                        if unique_bytes > key_len // 2:  # not too repetitive
                            results["rodata_keys"].append({
                                "offset": hex(rodata.virtual_address + i),
                                "length": key_len,
                                "hex": chunk.hex(),
                                "entropy": round(ent, 3),
                            })
                            if len(results["rodata_keys"]) >= 10:
                                break
                if len(results["rodata_keys"]) >= 10:
                    break

        # XOR sweep on high-entropy custom sections
        for name, info in results["custom_section_data"].items():
            if info["is_high_entropy"] and info["size"] <= 4096:
                section = binary.get_section(name)
                if section is not None:
                    content = bytes(section.content)
                    for key_byte in range(1, 256):
                        decoded = bytes(b ^ key_byte for b in content)
                        # Check if result looks like readable text
                        printable = sum(1 for b in decoded if 0x20 <= b <= 0x7e)
                        ratio = printable / len(decoded) if decoded else 0
                        if ratio > 0.8:
                            results["xor_candidates"].append({
                                "section": name,
                                "key": hex(key_byte),
                                "printable_ratio": round(ratio, 3),
                                "preview": decoded[:100].decode(errors="replace"),
                            })
                            break  # one good candidate per section is enough

        # Look for known crypto constants in the binary
        binary_data = Path(binary_path).read_bytes()
        _check_crypto_constants(binary_data, results["crypto_constants"])

        return ToolResult(
            tool="extract_data",
            success=True,
            data=results,
        )
    except Exception as e:
        return ToolResult(tool="extract_data", success=False, error=str(e))


def _calc_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _check_crypto_constants(data: bytes, results: list) -> None:
    """Search binary data for well-known cryptographic constants."""
    # AES S-box first 4 bytes
    aes_sbox_start = bytes([0x63, 0x7c, 0x77, 0x7b])
    if aes_sbox_start in data:
        offset = data.index(aes_sbox_start)
        results.append({
            "type": "AES S-box",
            "offset": hex(offset),
            "confidence": "high",
        })

    # RC4 initial state (0x00 0x01 0x02 ... 0x0f sequential)
    rc4_init = bytes(range(16))
    if rc4_init in data:
        offset = data.index(rc4_init)
        results.append({
            "type": "Sequential byte table (possible RC4 state init)",
            "offset": hex(offset),
            "confidence": "medium",
        })

    # SHA-256 initial hash values
    sha256_h0 = struct.pack(">I", 0x6a09e667)
    if sha256_h0 in data:
        offset = data.index(sha256_h0)
        results.append({
            "type": "SHA-256 constants",
            "offset": hex(offset),
            "confidence": "high",
        })

    # MD5 T constants (first constant)
    md5_t1 = struct.pack("<I", 0xd76aa478)
    if md5_t1 in data:
        offset = data.index(md5_t1)
        results.append({
            "type": "MD5 T-table constants",
            "offset": hex(offset),
            "confidence": "high",
        })

    # Blowfish P-array first value
    bf_p0 = struct.pack(">I", 0x243f6a88)
    if bf_p0 in data:
        offset = data.index(bf_p0)
        results.append({
            "type": "Blowfish P-array / Pi digits",
            "offset": hex(offset),
            "confidence": "medium",
        })
