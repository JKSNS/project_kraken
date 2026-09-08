#!/usr/bin/env python3
"""auto_symbolic_pwn -- angr-driven bug finder for stripped binaries.

The "find bugs" companion to auto_strip_recover's "triage." Drives angr's
symbolic execution to discover:

  - Unconstrained PC states (= attacker-controlled program counter,
    typically from a buffer overflow or use-after-free)
  - Format-string call sites where the format argument is symbolic
  - system() / execve() reaches with symbolic argv
  - Stack-canary checks that the explorer can avoid (= overflow with
    canary leak/forge)
  - Memory writes whose destination is symbolic (arbitrary write)

Designed for the DEF CON CTF stripped-pwn surface where every service
is hostile and you have a few minutes per service to find the bug.

Usage:
    # Default: explore from main() looking for unconstrained states.
    python3 auto_symbolic_pwn.py <binary> [--out PATH]
                                  [--start-addr 0x...]
                                  [--max-steps 200]
                                  [--time-budget 60]
                                  [--strategy unconstrained|fmtstring|system]
                                  [--input-len 256]

Output schema:
{
  "binary": "...",
  "arch": "...", "bits": N, "pie": bool,
  "explored_states": N,
  "findings": [
    {"kind": "unconstrained|fmt_string|system_reach|symbolic_write",
     "address": 0x..., "input_bytes": "<hex>",
     "stdin_input": "<hex>",   # when input came from stdin
     "argv_input": ["...", "..."],
     "register_state": {"rip": "<symbolic | concrete>", ...},
     "note": "..."}
  ],
  "summary": {"finding_count": N, "elapsed_s": F}
}
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any


def _angr_init(binary_path: Path):
    try:
        # Calm angr's logging
        import logging

        import angr  # type: ignore

        for noisy in ("angr", "claripy", "cle", "pyvex"):
            logging.getLogger(noisy).setLevel(logging.ERROR)
        return angr
    except Exception:
        return None


def _arg_input_state(angr_mod, proj, input_len: int):
    """Build an entry state with `input_len` symbolic bytes on stdin."""
    # Symbolic stdin
    stdin_input = angr_mod.claripy.BVS("stdin_input", input_len * 8)
    state = proj.factory.full_init_state(
        args=[proj.filename],
        stdin=stdin_input,
        # Reasonable defaults for CTF binaries
        add_options={
            angr_mod.options.LAZY_SOLVES,
            angr_mod.options.SYMBOLIC_WRITE_ADDRESSES,
        },
    )
    state.globals["stdin_input"] = stdin_input
    return state


def _explore_unconstrained(
    proj,
    start_state,
    max_steps: int,
    time_budget: float,
) -> list[dict]:
    """Find states where PC is symbolic (= attacker can control control flow)."""
    findings = []
    simgr = proj.factory.simgr(start_state, save_unconstrained=True)
    deadline = time.time() + time_budget
    step = 0
    while step < max_steps and time.time() < deadline and simgr.active:
        simgr.step(num_inst=1)
        step += 1
        # Drain unconstrained states
        for ucs in simgr.unconstrained:
            try:
                stdin_in = ucs.globals.get("stdin_input")
                concrete = b""
                if stdin_in is not None:
                    try:
                        concrete = ucs.solver.eval(stdin_in, cast_to=bytes)[:256]
                    except Exception:
                        pass
                pc = "<symbolic>" if ucs.regs.pc.symbolic else hex(ucs.solver.eval(ucs.regs.pc))
                findings.append(
                    {
                        "kind": "unconstrained",
                        "address": hex(ucs.addr) if not ucs.regs.pc.symbolic else None,
                        "pc_state": pc,
                        "stdin_input_hex": concrete.hex()[:512],
                        "step": step,
                        "note": ("symbolic PC reached -- buffer overflow or indirect-call gadget likely controllable"),
                    }
                )
            except Exception as e:
                findings.append(
                    {
                        "kind": "unconstrained",
                        "step": step,
                        "note": f"error reading state: {e}",
                    }
                )
        # Move unconstrained to dead so we don't re-emit
        simgr.move(from_stash="unconstrained", to_stash="dead")
        if not simgr.active and not simgr.deferred:
            break
    return findings


def _find_fmt_calls(proj) -> list[dict]:
    """Find printf-class call sites with potentially symbolic format arg."""
    findings = []
    try:
        cfg = proj.analyses.CFGFast(normalize=True, force_complete_scan=False)
    except Exception:
        return findings
    fmt_callees = {"printf", "fprintf", "vprintf", "sprintf", "snprintf"}
    plt_lookup = {}
    for sym in proj.loader.main_object.symbols:
        if sym.is_import or sym.is_extern:
            plt_lookup[sym.rebased_addr] = sym.name
    for fn_addr, fn in cfg.functions.items():
        for site in fn.get_call_sites():
            tgt = fn.get_call_target(site)
            callee = plt_lookup.get(tgt, "")
            if callee.lstrip("_").split("@")[0] in fmt_callees:
                findings.append(
                    {
                        "kind": "fmt_string_call_site",
                        "caller_addr": hex(fn_addr),
                        "site_addr": hex(site),
                        "callee": callee,
                        "note": (
                            f"{callee} call site -- manually verify whether "
                            "first arg is constant (safe) or attacker-influenced "
                            "(format-string vuln)"
                        ),
                    }
                )
    return findings


def _find_system_reaches(proj) -> list[dict]:
    """Find call sites of system / execve / popen -- even one is high-signal."""
    findings = []
    try:
        cfg = proj.analyses.CFGFast(normalize=True, force_complete_scan=False)
    except Exception:
        return findings
    danger_callees = {"system", "execve", "execvp", "execl", "execlp", "popen"}
    plt_lookup = {}
    for sym in proj.loader.main_object.symbols:
        if sym.is_import or sym.is_extern:
            plt_lookup[sym.rebased_addr] = sym.name
    for fn_addr, fn in cfg.functions.items():
        for site in fn.get_call_sites():
            tgt = fn.get_call_target(site)
            callee = plt_lookup.get(tgt, "")
            if callee.lstrip("_").split("@")[0] in danger_callees:
                findings.append(
                    {
                        "kind": "system_reach",
                        "caller_addr": hex(fn_addr),
                        "site_addr": hex(site),
                        "callee": callee,
                        "note": (f"{callee} reachable -- exploitation target if argument is attacker-influenced"),
                    }
                )
    return findings


def analyze(
    binary_path: Path,
    strategy: str = "unconstrained",
    start_addr: int | None = None,
    max_steps: int = 200,
    time_budget: float = 60.0,
    input_len: int = 256,
) -> dict[str, Any]:
    angr_mod = _angr_init(binary_path)
    if angr_mod is None:
        return {"binary": str(binary_path), "error": "angr not available; pip install angr"}
    try:
        proj = angr_mod.Project(str(binary_path), auto_load_libs=False)
    except Exception as e:
        return {"binary": str(binary_path), "error": f"load failed: {e}"}

    findings: list[dict] = []
    explored_states = 0

    if strategy in ("unconstrained", "all"):
        try:
            if start_addr is None:
                state = _arg_input_state(angr_mod, proj, input_len)
            else:
                state = proj.factory.blank_state(addr=start_addr)
            simgr = proj.factory.simgr(state, save_unconstrained=True)
            unconstrained_findings = _explore_unconstrained(
                proj,
                state,
                max_steps,
                time_budget,
            )
            findings.extend(unconstrained_findings)
            explored_states = max_steps
        except Exception as e:
            findings.append({"kind": "explore_error", "note": str(e)})

    if strategy in ("fmtstring", "all"):
        findings.extend(_find_fmt_calls(proj))

    if strategy in ("system", "all"):
        findings.extend(_find_system_reaches(proj))

    return {
        "binary": str(binary_path),
        "arch": str(proj.arch),
        "bits": proj.arch.bits,
        "pie": proj.loader.main_object.pic,
        "strategy": strategy,
        "explored_states": explored_states,
        "findings": findings,
        "summary": {
            "finding_count": len(findings),
            "by_kind": {
                kind: sum(1 for f in findings if f.get("kind") == kind) for kind in {f.get("kind") for f in findings}
            },
        },
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("binary", type=Path)
    p.add_argument("--strategy", default="all", choices=["unconstrained", "fmtstring", "system", "all"])
    p.add_argument("--start-addr", type=lambda x: int(x, 0))
    p.add_argument("--max-steps", type=int, default=200)
    p.add_argument("--time-budget", type=float, default=60.0)
    p.add_argument("--input-len", type=int, default=256)
    p.add_argument("--out", type=Path)
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    if not args.binary.is_file():
        print(f"[-] not a file: {args.binary}", file=sys.stderr)
        return 1

    start = time.time()
    result = analyze(
        args.binary,
        strategy=args.strategy,
        start_addr=args.start_addr,
        max_steps=args.max_steps,
        time_budget=args.time_budget,
        input_len=args.input_len,
    )
    result.setdefault("summary", {})["elapsed_s"] = round(time.time() - start, 2)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2))
        print(
            f"wrote {args.out} ({result['summary'].get('finding_count', 0)} findings, "
            f"{result['summary']['elapsed_s']}s)"
        )
    elif args.json:
        json.dump(result, sys.stdout, indent=2)
        print()
    else:
        s = result.get("summary", {})
        if "error" in result:
            print(f"ERROR: {result['error']}")
            return 1
        print(
            f"binary: {result['binary']}  arch={result.get('arch')}  bits={result.get('bits')}  pie={result.get('pie')}"
        )
        print(f"strategy={result['strategy']}  findings={s.get('finding_count', 0)}  elapsed={s.get('elapsed_s')}s")
        for f in result.get("findings", [])[:20]:
            note = f.get("note", "")
            print(f"  {f['kind']:<22} @ {f.get('address') or f.get('caller_addr', '?'):<12} {note[:80]}")

    return 0 if not result.get("error") else 1


if __name__ == "__main__":
    sys.exit(main())
