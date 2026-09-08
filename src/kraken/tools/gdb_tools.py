"""GDB/pwndbg tool wrappers -- subprocess-based, returns structured ToolResult."""
from __future__ import annotations

import asyncio
import json
import re
import tempfile
from pathlib import Path

from kraken.tools.base import ToolResult


async def _run_gdb(binary_path: str, commands: list[str], stdin_input: str | None = None, timeout: int = 30) -> ToolResult:
    """Execute GDB in batch mode with given commands."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".gdb", delete=False) as cmd_file:
        cmd_file.write("\n".join(commands))
        cmd_path = cmd_file.name

    try:
        proc = await asyncio.create_subprocess_exec(
            "gdb", "-batch", "-x", cmd_path, binary_path,
            stdin=asyncio.subprocess.PIPE if stdin_input else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=stdin_input.encode() if stdin_input else None),
            timeout=timeout,
        )
        return ToolResult(
            tool="gdb",
            success=proc.returncode == 0,
            data={"raw_output": stdout.decode(errors="replace")},
            stdout=stdout.decode(errors="replace"),
            stderr=stderr.decode(errors="replace"),
            exit_code=proc.returncode or 0,
        )
    except asyncio.TimeoutError:
        return ToolResult(tool="gdb", success=False, error=f"GDB timed out after {timeout}s")
    except FileNotFoundError:
        return ToolResult(tool="gdb", success=False, error="GDB not found")
    finally:
        Path(cmd_path).unlink(missing_ok=True)


def _parse_registers(output: str) -> dict[str, str]:
    """Parse GDB 'info registers' output into a dict."""
    regs = {}
    for line in output.splitlines():
        m = re.match(r"(\w+)\s+0x([0-9a-f]+)", line)
        if m:
            regs[m.group(1)] = m.group(2)
    return regs


def _parse_memory(output: str) -> list[str]:
    """Parse GDB 'x/' memory dump output."""
    values = []
    for line in output.splitlines():
        # Format: 0xaddr: 0xval1 0xval2 ...
        parts = line.split(":")
        if len(parts) == 2:
            for val in parts[1].strip().split():
                if val.startswith("0x"):
                    values.append(val)
    return values


async def gdb_run(binary_path: str, args: list[str] | None = None, stdin_input: str | None = None, timeout: int = 30) -> ToolResult:
    """Run binary under GDB, capture output."""
    commands = [
        "set pagination off",
        "set confirm off",
        f"run {' '.join(args or [])}",
        "quit",
    ]
    return await _run_gdb(binary_path, commands, stdin_input=stdin_input, timeout=timeout)


async def gdb_break_and_run(
    binary_path: str,
    breakpoints: list[str],
    args: list[str] | None = None,
    stdin_input: str | None = None,
    timeout: int = 30,
) -> ToolResult:
    """Set breakpoints, run, dump state at each breakpoint hit."""
    commands = ["set pagination off", "set confirm off"]
    for bp in breakpoints:
        commands.append(f"break *{bp}")

    # Define commands to run at each breakpoint
    for bp in breakpoints:
        commands.extend([
            f"commands",
            "  info registers",
            "  x/16gx $rsp",
            "  continue",
            "end",
        ])

    commands.append(f"run {' '.join(args or [])}")
    commands.append("quit")

    result = await _run_gdb(binary_path, commands, stdin_input=stdin_input, timeout=timeout)

    if result.success:
        # Parse structured data from output
        registers = _parse_registers(result.stdout)
        memory = _parse_memory(result.stdout)
        result.data = {
            "registers": registers,
            "stack_dump": memory,
            "raw_output": result.stdout,
        }

    return result


async def gdb_memory_dump(
    binary_path: str,
    address: str,
    length: int = 64,
    breakpoint: str | None = None,
    stdin_input: str | None = None,
    timeout: int = 30,
) -> ToolResult:
    """Dump memory at address (optionally at a breakpoint)."""
    commands = ["set pagination off", "set confirm off"]
    if breakpoint:
        commands.append(f"break *{breakpoint}")
        commands.append("run")
    # Dump as hex bytes
    commands.append(f"x/{length}bx {address}")
    commands.append("quit")

    result = await _run_gdb(binary_path, commands, stdin_input=stdin_input, timeout=timeout)

    if result.success:
        # Parse hex bytes from output
        hex_bytes = []
        for line in result.stdout.splitlines():
            if ":" in line:
                parts = line.split(":")[1].strip().split()
                for p in parts:
                    if p.startswith("0x"):
                        hex_bytes.append(p.replace("0x", ""))
        result.data = {
            "address": address,
            "hex_bytes": "".join(hex_bytes),
            "length": len(hex_bytes),
        }

    return result
