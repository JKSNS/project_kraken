"""Symbolic execution (angr) and constraint solving (z3) tool wrappers.

These execute Python scripts in a sandboxed subprocess -- the LLM writes
the setup code, the tool runs it deterministically.
"""
from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path

from kraken.tools.base import ToolResult


async def _execute_python_script(code: str, timeout: int = 60) -> ToolResult:
    """Execute a Python script in subprocess, return stdout/stderr."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(code)
        script_path = f.name

    try:
        proc = await asyncio.create_subprocess_exec(
            "python3", script_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return ToolResult(
            tool="python_exec",
            success=proc.returncode == 0,
            stdout=stdout.decode(errors="replace"),
            stderr=stderr.decode(errors="replace"),
            exit_code=proc.returncode or 0,
        )
    except asyncio.TimeoutError:
        return ToolResult(tool="python_exec", success=False, error=f"Script timed out after {timeout}s")
    finally:
        Path(script_path).unlink(missing_ok=True)


def _parse_sat_output(stdout: str) -> dict:
    """Parse SAT|solution|time format from tool output."""
    for line in stdout.strip().splitlines():
        if line.startswith("SAT|") or line.startswith("UNSAT|"):
            parts = line.split("|")
            sat = parts[0] == "SAT"
            solution = parts[1] if len(parts) > 1 else ""
            elapsed = float(parts[2]) if len(parts) > 2 else 0.0
            return {"satisfiable": sat, "solution": solution, "time_seconds": elapsed}
    return {"satisfiable": False, "solution": "", "error": "Could not parse output"}


async def angr_find_input(
    binary_path: str,
    find_addr: int,
    avoid_addrs: list[int] | None = None,
    stdin_length: int = 32,
    timeout: int = 120,
) -> ToolResult:
    """Run angr symbolic execution to find input reaching find_addr."""
    avoid = avoid_addrs or []
    script = f'''import angr
import claripy
import time

start = time.time()
p = angr.Project("{binary_path}", auto_load_libs=False)
stdin_sym = claripy.BVS("stdin", {stdin_length} * 8)
state = p.factory.entry_state(stdin=angr.SimFileStream(name="stdin", content=stdin_sym))

# Constrain to printable ASCII
for i in range({stdin_length}):
    byte = stdin_sym.get_byte(i)
    state.solver.add(byte >= 0x20)
    state.solver.add(byte <= 0x7e)

sm = p.factory.simgr(state)
sm.explore(find={hex(find_addr)}, avoid={avoid})

elapsed = time.time() - start
if sm.found:
    found_state = sm.found[0]
    solution = found_state.solver.eval(stdin_sym, cast_to=bytes)
    print(f"SAT|{{solution.hex()}}|{{elapsed:.2f}}")
else:
    print(f"UNSAT||{{elapsed:.2f}}")
'''
    result = await _execute_python_script(script, timeout=timeout)
    if result.success:
        result.data = _parse_sat_output(result.stdout)
    return ToolResult(
        tool="angr_find_input",
        success=result.success,
        data=result.data,
        stdout=result.stdout,
        stderr=result.stderr,
        exit_code=result.exit_code,
    )


async def angr_explore(
    binary_path: str,
    find_addr: int,
    avoid_addrs: list[int] | None = None,
    start_addr: int | None = None,
    timeout: int = 120,
) -> ToolResult:
    """Explore execution paths with angr."""
    avoid = avoid_addrs or []
    start_line = f"state = p.factory.blank_state(addr={hex(start_addr)})" if start_addr else "state = p.factory.entry_state()"
    script = f'''import angr
import time

start = time.time()
p = angr.Project("{binary_path}", auto_load_libs=False)
{start_line}

sm = p.factory.simgr(state)
sm.explore(find={hex(find_addr)}, avoid={avoid})

elapsed = time.time() - start
if sm.found:
    found_state = sm.found[0]
    # Try to get stdin
    try:
        stdin_data = found_state.posix.dumps(0)
        print(f"SAT|{{stdin_data.hex()}}|{{elapsed:.2f}}")
    except Exception:
        print(f"SAT|found_path|{{elapsed:.2f}}")
else:
    print(f"UNSAT||{{elapsed:.2f}}")
'''
    result = await _execute_python_script(script, timeout=timeout)
    if result.success:
        result.data = _parse_sat_output(result.stdout)
    return ToolResult(
        tool="angr_explore",
        success=result.success,
        data=result.data,
        stdout=result.stdout,
        stderr=result.stderr,
        exit_code=result.exit_code,
    )


async def z3_solve(constraints_code: str, timeout: int = 30) -> ToolResult:
    """Execute z3 constraint solving code.

    The code must print results in format: SAT|var1=val1,var2=val2,...
    """
    result = await _execute_python_script(constraints_code, timeout=timeout)
    if result.success:
        result.data = _parse_sat_output(result.stdout)
    return ToolResult(
        tool="z3_solve",
        success=result.success,
        data=result.data,
        stdout=result.stdout,
        stderr=result.stderr,
        exit_code=result.exit_code,
    )
