"""Deterministic binary analysis tool wrappers.

All functions here run shell commands and return structured ToolResult.
No LLM calls -- pure subprocess execution.
"""

from __future__ import annotations

import asyncio
import math
import re
from collections import Counter
from pathlib import Path

from kraken.tools.base import ToolResult


async def _run(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    """Run a subprocess and return (exit_code, stdout, stderr)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return proc.returncode or 0, stdout.decode(errors="replace"), stderr.decode(errors="replace")
    except FileNotFoundError:
        return 127, "", f"Command not found: {cmd[0]}"
    except asyncio.TimeoutError:
        return 124, "", f"Command timed out after {timeout}s"


async def file_info(path: str) -> ToolResult:
    """Run `file` command on binary."""
    code, stdout, stderr = await _run(["file", "-b", path])
    return ToolResult(
        tool="file",
        success=code == 0,
        data={"file_type": stdout.strip()},
        stdout=stdout,
        stderr=stderr,
        exit_code=code,
    )


async def checksec(path: str) -> ToolResult:
    """Run `checksec` on binary to get protections."""
    code, stdout, stderr = await _run(["checksec", "--file=" + path, "--output=json"])
    if code == 0:
        import json
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            data = {"raw": stdout.strip()}
    else:
        # Fallback: parse readelf for basic protection info
        data = await _checksec_fallback(path)
    return ToolResult(tool="checksec", success=True, data=data, stdout=stdout, stderr=stderr, exit_code=code)


async def _checksec_fallback(path: str) -> dict:
    """Basic protection detection without checksec binary."""
    protections: dict = {"nx": False, "pie": False, "canary": False, "relro": "none"}

    code, stdout, _ = await _run(["readelf", "-l", path])
    if "GNU_STACK" in stdout and "RWE" not in stdout:
        protections["nx"] = True

    code, stdout, _ = await _run(["readelf", "-h", path])
    if "DYN (Shared object file)" in stdout:
        protections["pie"] = True

    code, stdout, _ = await _run(["readelf", "-s", path])
    if "__stack_chk_fail" in stdout:
        protections["canary"] = True

    code, stdout, _ = await _run(["readelf", "-d", path])
    if "BIND_NOW" in stdout:
        protections["relro"] = "full"
    elif "GNU_RELRO" in stdout:
        protections["relro"] = "partial"

    return protections


async def strings_extract(path: str, min_length: int = 4) -> ToolResult:
    """Extract strings from binary."""
    code, stdout, stderr = await _run(["strings", "-n", str(min_length), path])
    lines = [s for s in stdout.splitlines() if s.strip()]
    return ToolResult(
        tool="strings",
        success=code == 0,
        data={"strings": lines, "count": len(lines)},
        stdout=stdout,
        stderr=stderr,
        exit_code=code,
    )


async def strings_grep(path: str, pattern: str) -> ToolResult:
    """Extract strings matching a regex pattern."""
    result = await strings_extract(path)
    if not result.success:
        return result
    regex = re.compile(pattern, re.IGNORECASE)
    matched = [s for s in result.data["strings"] if regex.search(s)]
    return ToolResult(
        tool="strings_grep",
        success=True,
        data={"matched": matched, "pattern": pattern, "count": len(matched)},
    )


async def readelf_sections(path: str) -> ToolResult:
    """Get section headers via readelf."""
    code, stdout, stderr = await _run(["readelf", "-S", path])
    sections = []
    for line in stdout.splitlines():
        # Parse section lines like: [ 1] .text PROGBITS 00401000 ...
        m = re.match(r'\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)', line)
        if m:
            sections.append({
                "name": m.group(1),
                "type": m.group(2),
                "address": m.group(3),
                "offset": m.group(4),
                "size": m.group(5),
            })
    return ToolResult(
        tool="readelf",
        success=code == 0,
        data={"sections": sections},
        stdout=stdout,
        stderr=stderr,
        exit_code=code,
    )


async def readelf_symbols(path: str) -> ToolResult:
    """Get symbol table via readelf."""
    code, stdout, stderr = await _run(["readelf", "-s", path])
    symbols: dict = {}
    for line in stdout.splitlines():
        # Parse symbol lines
        parts = line.split()
        if len(parts) >= 8 and parts[0].rstrip(":").isdigit():
            addr = parts[1]
            name = parts[7] if len(parts) > 7 else ""
            sym_type = parts[3]
            if name and name != "0" and not name.startswith("_"):
                symbols[name] = {"address": addr, "type": sym_type}
    return ToolResult(
        tool="readelf_symbols",
        success=code == 0,
        data={"symbols": symbols},
        stdout=stdout,
        stderr=stderr,
        exit_code=code,
    )


async def entropy_analysis(path: str, block_size: int = 256) -> ToolResult:
    """Calculate per-block entropy to detect packing/encryption."""
    try:
        data = Path(path).read_bytes()
    except (OSError, IOError) as e:
        return ToolResult(tool="entropy", success=False, error=str(e))

    def _block_entropy(block: bytes) -> float:
        if not block:
            return 0.0
        counts = Counter(block)
        length = len(block)
        ent = 0.0
        for count in counts.values():
            p = count / length
            if p > 0:
                ent -= p * math.log2(p)
        return ent

    blocks = []
    for i in range(0, len(data), block_size):
        chunk = data[i : i + block_size]
        blocks.append(round(_block_entropy(chunk), 3))

    avg_entropy = round(sum(blocks) / len(blocks), 3) if blocks else 0.0
    max_entropy = max(blocks) if blocks else 0.0

    return ToolResult(
        tool="entropy",
        success=True,
        data={
            "average_entropy": avg_entropy,
            "max_entropy": max_entropy,
            "block_count": len(blocks),
            "likely_packed": avg_entropy > 7.0,
            "file_size": len(data),
        },
    )


async def collect_binary_info(path: str) -> dict:
    """Run all binary info tools and return combined results."""
    file_res, sec_res, sections_res, symbols_res, entropy_res, strings_res = await asyncio.gather(
        file_info(path),
        checksec(path),
        readelf_sections(path),
        readelf_symbols(path),
        entropy_analysis(path),
        strings_extract(path),
    )

    return {
        "file_type": file_res.data.get("file_type", "") if file_res.success else "",
        "protections": sec_res.data if sec_res.success else {},
        "sections": sections_res.data.get("sections", []) if sections_res.success else [],
        "symbols": symbols_res.data.get("symbols", {}) if symbols_res.success else {},
        "entropy": entropy_res.data if entropy_res.success else {},
        "strings_count": strings_res.data.get("count", 0) if strings_res.success else 0,
    }
