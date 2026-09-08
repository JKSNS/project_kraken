"""Firmware analysis tools -- extraction, architecture detection, config analysis.

Provides wrappers for binwalk, firmware extraction, and embedded system analysis.
Falls back gracefully when tools are not installed.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import struct
import tempfile
from pathlib import Path

from kraken.tools.base import ToolResult
from kraken.logging.structured import get_logger

log = get_logger(__name__)


async def binwalk_scan(binary_path: str, timeout: int = 60) -> ToolResult:
    """Run binwalk signature scan on a binary/firmware image.

    Returns identified file signatures, offsets, and embedded files.
    Falls back to manual signature scanning if binwalk is not installed.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            "binwalk", binary_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        stdout_str = stdout.decode(errors="replace")
        stderr_str = stderr.decode(errors="replace")

        # Parse binwalk output into structured data
        entries = []
        for line in stdout_str.splitlines():
            # binwalk output: DECIMAL  HEXADECIMAL  DESCRIPTION
            match = re.match(r"(\d+)\s+(0x[0-9A-Fa-f]+)\s+(.+)", line)
            if match:
                entries.append({
                    "offset_dec": int(match.group(1)),
                    "offset_hex": match.group(2),
                    "description": match.group(3).strip(),
                })

        return ToolResult(
            tool="binwalk_scan",
            success=True,
            data={"entries": entries, "count": len(entries)},
            stdout=stdout_str,
            stderr=stderr_str,
            exit_code=proc.returncode or 0,
        )
    except FileNotFoundError:
        log.warning("binwalk_not_installed")
        # Fallback: manual signature scanning
        return await _manual_signature_scan(binary_path)
    except asyncio.TimeoutError:
        return ToolResult(tool="binwalk_scan", success=False, error="timeout")


async def binwalk_extract(binary_path: str, output_dir: str | None = None, timeout: int = 120) -> ToolResult:
    """Extract embedded files from firmware image using binwalk -e.

    Returns path to extraction directory with extracted files.
    """
    if output_dir is None:
        output_dir = tempfile.mkdtemp(prefix="kraken_fw_")

    try:
        proc = await asyncio.create_subprocess_exec(
            "binwalk", "-e", "-C", output_dir, binary_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)

        # List extracted files
        extracted_files = []
        for root, dirs, files in os.walk(output_dir):
            for f in files:
                fpath = os.path.join(root, f)
                try:
                    size = os.path.getsize(fpath)
                except OSError:
                    size = 0
                extracted_files.append({
                    "path": fpath,
                    "name": f,
                    "size": size,
                    "relative": os.path.relpath(fpath, output_dir),
                })

        return ToolResult(
            tool="binwalk_extract",
            success=True,
            data={
                "output_dir": output_dir,
                "files": extracted_files,
                "count": len(extracted_files),
            },
            stdout=stdout.decode(errors="replace"),
            stderr=stderr.decode(errors="replace"),
            exit_code=proc.returncode or 0,
        )
    except FileNotFoundError:
        return ToolResult(tool="binwalk_extract", success=False, error="binwalk not installed")
    except asyncio.TimeoutError:
        return ToolResult(tool="binwalk_extract", success=False, error="timeout")


async def detect_architecture(binary_path: str) -> ToolResult:
    """Detect firmware architecture from binary headers and content.

    Identifies: ARM, MIPS, RISC-V, x86, x86_64, PowerPC, etc.
    """
    try:
        with open(binary_path, "rb") as f:
            header = f.read(64)
    except (OSError, IOError) as e:
        return ToolResult(tool="detect_architecture", success=False, error=str(e))

    arch_info = {
        "architecture": "unknown",
        "bits": 0,
        "endianness": "unknown",
        "format": "unknown",
    }

    # ELF detection
    if header[:4] == b"\x7fELF":
        arch_info["format"] = "ELF"
        arch_info["bits"] = 32 if header[4] == 1 else 64
        arch_info["endianness"] = "little" if header[5] == 1 else "big"

        # e_machine field at offset 18 (2 bytes)
        if arch_info["endianness"] == "little":
            machine = struct.unpack("<H", header[18:20])[0]
        else:
            machine = struct.unpack(">H", header[18:20])[0]

        elf_machines = {
            3: "x86", 8: "MIPS", 20: "PowerPC", 40: "ARM",
            62: "x86_64", 183: "AArch64", 243: "RISC-V",
            0xF3: "RISC-V",
        }
        arch_info["architecture"] = elf_machines.get(machine, f"unknown_elf_{machine}")

    # PE detection
    elif header[:2] == b"MZ":
        arch_info["format"] = "PE"
        # Read PE header offset
        if len(header) >= 64:
            pe_offset = struct.unpack("<I", header[60:64])[0]
            try:
                with open(binary_path, "rb") as f:
                    f.seek(pe_offset)
                    pe_header = f.read(6)
                    if pe_header[:4] == b"PE\x00\x00":
                        machine = struct.unpack("<H", pe_header[4:6])[0]
                        pe_machines = {
                            0x14C: "x86", 0x8664: "x86_64",
                            0x1C0: "ARM", 0xAA64: "AArch64",
                        }
                        arch_info["architecture"] = pe_machines.get(machine, f"unknown_pe_{machine:#x}")
                        arch_info["bits"] = 64 if machine in (0x8664, 0xAA64) else 32
            except (OSError, struct.error):
                pass

    # Mach-O detection
    elif header[:4] in (b"\xFE\xED\xFA\xCE", b"\xFE\xED\xFA\xCF",
                         b"\xCE\xFA\xED\xFE", b"\xCF\xFA\xED\xFE"):
        arch_info["format"] = "Mach-O"

    # Raw firmware heuristics
    else:
        # Check for common firmware signatures
        content_sample = header
        try:
            with open(binary_path, "rb") as f:
                content_sample = f.read(4096)
        except (OSError, IOError):
            pass

        if b"uImage" in content_sample or b"\x27\x05\x19\x56" in content_sample[:4]:
            arch_info["format"] = "U-Boot image"
        elif b"squashfs" in content_sample.lower() or b"hsqs" in content_sample:
            arch_info["format"] = "SquashFS"
        elif b"JFFS2" in content_sample or b"\x85\x19" in content_sample[:2]:
            arch_info["format"] = "JFFS2"
        elif b"CramFS" in content_sample or b"\x28\xcd\x3d\x45" in content_sample[:4]:
            arch_info["format"] = "CramFS"

    return ToolResult(
        tool="detect_architecture",
        success=True,
        data=arch_info,
    )


async def find_hardcoded_credentials(binary_path: str) -> ToolResult:
    """Scan firmware/binary for hardcoded credentials and secrets."""
    try:
        with open(binary_path, "rb") as f:
            content = f.read()
    except (OSError, IOError) as e:
        return ToolResult(tool="find_hardcoded_credentials", success=False, error=str(e))

    text = content.decode(errors="replace")
    findings = []

    # Common credential patterns
    patterns = [
        (r"password\s*[=:]\s*['\"]([^'\"]{3,64})['\"]", "hardcoded_password"),
        (r"passwd\s*[=:]\s*['\"]([^'\"]{3,64})['\"]", "hardcoded_password"),
        (r"api[_-]?key\s*[=:]\s*['\"]([^'\"]{8,128})['\"]", "api_key"),
        (r"secret\s*[=:]\s*['\"]([^'\"]{8,128})['\"]", "secret"),
        (r"token\s*[=:]\s*['\"]([^'\"]{8,128})['\"]", "token"),
        (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "private_key"),
        (r"(?:root|admin|user):[^:]+:\d+:\d+:", "passwd_entry"),
        (r"default.*(?:password|passwd|pass)\s*[=:]\s*(\S+)", "default_credential"),
    ]

    for pattern, cred_type in patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            findings.append({
                "type": cred_type,
                "match": match.group(0)[:200],
                "offset": match.start(),
            })

    return ToolResult(
        tool="find_hardcoded_credentials",
        success=True,
        data={"findings": findings[:50], "count": len(findings)},
    )


async def _manual_signature_scan(binary_path: str) -> ToolResult:
    """Fallback signature scanning when binwalk is not available."""
    try:
        with open(binary_path, "rb") as f:
            content = f.read()
    except (OSError, IOError) as e:
        return ToolResult(tool="manual_signature_scan", success=False, error=str(e))

    signatures = {
        b"\x1f\x8b": "gzip compressed data",
        b"BZ": "bzip2 compressed data",
        b"\xfd7zXZ": "xz compressed data",
        b"PK\x03\x04": "ZIP archive",
        b"Rar!": "RAR archive",
        b"\x89PNG": "PNG image",
        b"JFIF": "JPEG image",
        b"ELF": "ELF binary",
        b"#!/": "script (shebang)",
        b"<?xml": "XML data",
        b"<!DOCTYPE": "HTML/SGML document",
        b"hsqs": "SquashFS filesystem",
        b"JFFS2": "JFFS2 filesystem",
    }

    entries = []
    for offset in range(0, min(len(content), 10 * 1024 * 1024), 512):
        chunk = content[offset:offset + 16]
        for sig, desc in signatures.items():
            if chunk.startswith(sig) or sig in chunk:
                entries.append({
                    "offset_dec": offset,
                    "offset_hex": hex(offset),
                    "description": desc,
                })
                break

    return ToolResult(
        tool="manual_signature_scan",
        success=True,
        data={"entries": entries, "count": len(entries), "note": "binwalk not available, using manual scan"},
        stdout="",
    )
