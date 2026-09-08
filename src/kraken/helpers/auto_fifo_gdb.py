#!/usr/bin/env python3
"""auto_fifo_gdb -- run a binary under gdb with stdin fed through a FIFO,
so the debugger can break at user-supplied addresses and inspect state
between timed writes.

This packages the ad-hoc mkfifo + timed-write + gdb-breakpoint harness I
invented during the VERE pwn2 solve. The problem it solves: many pwn
binaries read stdin via multiple staged reads (scanf, then read, then
getchar, then fgets, then ...), and feeding the entire payload at once
causes earlier reads to over-consume and corrupt later stage state.
Piping stdin through a FIFO lets Python write chunks with explicit
`time.sleep()` delays between them, matching what a TCP client would do.

Meanwhile, gdb is running the binary in `-batch` mode with `run < FIFO`
and a breakpoint at any instruction the user cares about (e.g., the
`leave` of a vuln function, right before the ROP chain takes over).
When the breakpoint hits, gdb dumps register state and memory to a log
file which we parse back into Python.

Usage (library):

    from auto_fifo_gdb import run

    result = run(
        binary="./src/pwn-2",
        libc="./libc.so.6",
        breakpoints=[0x40155b],          # useful()'s `leave`
        stages=[
            (b"1\\n",                 0.2),  # scanf answer, then sleep
            (build_stage1_bytes(),   0.3),  # main overflow
            (build_stage2_bytes(),   1.0),  # rop chain
        ],
        dump_at_bp={
            0x40155b: [
                ("regs",  "rax rbx rcx rdx rbp rsp r12 r13 r14 r15"),
                ("mem",   "$rbp-0x20 8"),     # 8 qwords from rbp-0x20
                ("mem",   "0x404040 4"),       # 4 qwords from .data start
            ],
        },
    )
    print(result.bp_hits[0x40155b]["regs"]["r12"])   # reads r12 at breakpoint

Usage (CLI, quick-and-dirty):

    auto_fifo_gdb.py --binary ./pwn-2 --libc ./libc.so.6 \\
        --break 0x40155b --break 0x401529 \\
        --stage stage1.bin:0.3 --stage stage2.bin:1.0
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class BPDump:
    regs: dict[str, int] = field(default_factory=dict)
    mem: dict[str, list[int]] = field(default_factory=dict)
    raw: str = ""


@dataclass
class Result:
    bp_hits: dict[int, BPDump] = field(default_factory=dict)
    gdb_stdout: str = ""
    crashed: bool = False
    exit_code: int | None = None


def run(
    binary: str,
    breakpoints: list[int],
    stages: list[tuple[bytes, float]],
    libc: str | None = None,
    dump_at_bp: dict[int, list[tuple[str, str]]] | None = None,
    timeout: float = 30.0,
) -> Result:
    """Run `binary` under gdb, feed `stages` through a FIFO with delays,
    break at `breakpoints`, and return parsed dump results.

    stages: list of (bytes_to_write, sleep_seconds_after).
    dump_at_bp: {addr: [(kind, arg), ...]} where kind is 'regs' or 'mem'.
        regs arg: space-separated register names.
        mem  arg: "<expr> <count>" where count is number of qwords.
        Defaults to dumping all common GP registers if None for that BP.
    """
    tmp = tempfile.mkdtemp(prefix="afg_")
    fifo_path = os.path.join(tmp, "stdin.fifo")
    log_path = os.path.join(tmp, "gdb.log")
    script_path = os.path.join(tmp, "driver.gdb")
    os.mkfifo(fifo_path)

    try:
        gdb_script = _build_gdb_script(
            binary=binary,
            libc=libc,
            breakpoints=breakpoints,
            dump_at_bp=dump_at_bp or {},
            fifo_path=fifo_path,
            log_path=log_path,
        )
        with open(script_path, "w") as f:
            f.write(gdb_script)

        # Start gdb in the background -- it will block on the FIFO until we write.
        gdb_proc = subprocess.Popen(
            ["gdb", "-batch", "-x", script_path],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )

        # Give gdb time to set breakpoints and start `run`.
        time.sleep(0.3)

        # Open FIFO and feed stages.
        fifo = open(fifo_path, "wb", buffering=0)
        try:
            for data, delay in stages:
                fifo.write(data)
                fifo.flush()
                if delay > 0:
                    time.sleep(delay)
        finally:
            try: fifo.close()
            except Exception: pass

        # Wait for gdb to finish.
        try:
            out, _ = gdb_proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            gdb_proc.kill()
            out, _ = gdb_proc.communicate()

        out_text = out.decode("latin-1", errors="replace") if isinstance(out, bytes) else out
        result = Result(gdb_stdout=out_text, exit_code=gdb_proc.returncode)
        result.crashed = "SIGSEGV" in out_text or "Segmentation fault" in out_text

        # Parse the log file for dumps keyed by breakpoint.
        if os.path.exists(log_path):
            with open(log_path) as f:
                log_text = f.read()
            result.bp_hits = _parse_log(log_text, breakpoints)

        return result
    finally:
        try: os.unlink(fifo_path)
        except OSError: pass
        try: os.unlink(script_path)
        except OSError: pass
        try: os.unlink(log_path)
        except OSError: pass
        try: os.rmdir(tmp)
        except OSError: pass


def _build_gdb_script(
    binary: str,
    libc: str | None,
    breakpoints: list[int],
    dump_at_bp: dict[int, list[tuple[str, str]]],
    fifo_path: str,
    log_path: str,
) -> str:
    lines = [
        "set pagination off",
        f"set logging file {log_path}",
        "set logging overwrite on",
        "set logging enabled on",
    ]
    if libc:
        lines.append(f"set env LD_PRELOAD={os.path.abspath(libc)}")
    lines.append(f"file {binary}")
    for addr in breakpoints:
        default_dumps = dump_at_bp.get(addr) or [
            ("regs", "rax rbx rcx rdx rdi rsi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15"),
        ]
        lines.append(f"break *{hex(addr)}")
        lines.append("commands")
        lines.append("  silent")
        lines.append(f'  printf "\\n=== BP_HIT {hex(addr)} ===\\n"')
        for kind, arg in default_dumps:
            if kind == "regs":
                for reg in arg.split():
                    lines.append(f'  printf "REG {reg}=%#lx\\n", ${reg}')
            elif kind == "mem":
                parts = arg.split()
                expr = parts[0]
                count = int(parts[1]) if len(parts) > 1 else 4
                for i in range(count):
                    off = i * 8
                    lines.append(
                        f'  printf "MEM {expr}+{off:#x}=%#lx\\n", '
                        f'*(unsigned long *)({expr} + {off})'
                    )
            else:
                raise ValueError(f"unknown dump kind {kind}")
        lines.append("  continue")
        lines.append("end")
    lines.append(f"run < {fifo_path}")
    lines.append("info registers")
    lines.append("quit")
    return "\n".join(lines) + "\n"


_RE_BP_HIT  = re.compile(r"=== BP_HIT (0x[0-9a-fA-F]+) ===")
_RE_REG     = re.compile(r"REG (\w+)=(0x[0-9a-fA-F]+)")
_RE_MEM     = re.compile(r"MEM (\S+?)=(0x[0-9a-fA-F]+)")


def _parse_log(text: str, breakpoints: list[int]) -> dict[int, BPDump]:
    hits: dict[int, BPDump] = {}
    current_bp: BPDump | None = None
    current_addr: int | None = None

    for line in text.splitlines():
        m = _RE_BP_HIT.search(line)
        if m:
            if current_addr is not None and current_bp is not None:
                hits[current_addr] = current_bp
            current_addr = int(m.group(1), 16)
            current_bp = BPDump()
            continue
        if current_bp is None:
            continue
        m = _RE_REG.search(line)
        if m:
            current_bp.regs[m.group(1)] = int(m.group(2), 16)
            continue
        m = _RE_MEM.search(line)
        if m:
            key = m.group(1)
            current_bp.mem.setdefault(key, []).append(int(m.group(2), 16))

    if current_addr is not None and current_bp is not None:
        hits[current_addr] = current_bp
    return hits


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_stage(spec: str) -> tuple[bytes, float]:
    """Parse `path:sleep` where path is a file to read."""
    if ":" not in spec:
        raise ValueError(f"bad stage spec {spec!r}, expected path:delay")
    path, delay = spec.rsplit(":", 1)
    with open(path, "rb") as f:
        return f.read(), float(delay)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--libc", default=None)
    ap.add_argument("--break", dest="breakpoints", action="append", type=lambda s: int(s, 0), default=[])
    ap.add_argument("--stage", action="append", default=[], help="file:delay (can repeat)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    if not args.breakpoints:
        print("need at least one --break", file=sys.stderr)
        return 2
    stages = [_parse_stage(s) for s in args.stage]

    res = run(
        binary=args.binary,
        libc=args.libc,
        breakpoints=args.breakpoints,
        stages=stages,
    )

    if args.json:
        out = {
            "crashed": res.crashed,
            "exit_code": res.exit_code,
            "bp_hits": {
                hex(addr): {"regs": d.regs, "mem": d.mem}
                for addr, d in res.bp_hits.items()
            },
        }
        print(json.dumps(out, indent=2))
    else:
        for addr, d in res.bp_hits.items():
            print(f"=== {hex(addr)} ===")
            for k, v in d.regs.items():
                print(f"  {k} = {hex(v)}")
            for k, vals in d.mem.items():
                print(f"  {k} = [{', '.join(hex(v) for v in vals)}]")
        print(f"\ncrashed={res.crashed} exit_code={res.exit_code}")
    return 0 if res.bp_hits else 2


if __name__ == "__main__":
    sys.exit(main())
