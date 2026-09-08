#!/usr/bin/env python3
"""auto_classify_wrapper -- static analysis: detect "small wrapper with
a big-fgets into a small local" pattern and estimate the ROP budget.

Motivation: VERE pwn2's `useful()` is a 12-line function that does
`fgets(totally_useless, 0x40, stdin)` into a 20-byte local. A static
detector could flag this pattern at triage time and route straight to
a tight-budget ROP strategy (prefer `one_gadget` with rbp-relative
argv/envp over ret2libc) instead of burning attempts on alignment
faults and doomed budget-overflowing chains.

Heuristic:
  1. For each function with a `sub $NN, %rsp` prologue, measure local
     buffer sizes by tracking `lea -0xNN(%rbp), rdi/rax` sites that
     feed into fgets/read/gets/recv calls.
  2. For each such call, compare buffer size vs the read length.
  3. If read_size > buf_size (stack BOF), compute usable ROP bytes:
     `read_size - (rbp_offset_of_buf + 8)` = bytes past saved retaddr.
     Minus fgets's trailing `\\0` = `read_size - 1` for the fgets case.
  4. Report wrappers + ROP slot budget (bytes // 8).

Usage:
  auto_classify_wrapper.py --binary ./pwn-2

Output (human):
  WRAPPER: useful @ 0x4014ff
    local buffer: [rbp-0x20]  (size 0x20 aligned, 20 logical)
    call: fgets(buf, 0x40, stdin)
    overflow: 0x40 - 0x20 = 0x20 (32 bytes)
    rop_budget: 32 - 16 (saved_rbp + retaddr) = 16 bytes = 2 slots
    classification: TIGHT_BUDGET -- prefer one_gadget with rbp control

Output (JSON via --json).
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class Wrapper:
    name: str
    addr: int
    buf_offset: int           # rbp-0xN where the read lands
    buf_size: int             # conservative buffer size
    read_fn: str              # "fgets" / "read" / "gets" / "recv"
    read_size: int            # size requested in the read call
    read_site: int            # address of the read call
    usable_overflow: int = 0  # bytes past the retaddr slot
    rop_slots: int = 0        # usable_overflow // 8
    classification: str = ""


def disasm(binary: str) -> str:
    r = subprocess.run(
        ["objdump", "-d", "-M", "intel", binary],
        capture_output=True, text=True,
    )
    return r.stdout


_RE_FN_HEADER = re.compile(r"^(?P<addr>[0-9a-f]+)\s+<(?P<name>[\w.@]+)>:$")
_RE_INSN = re.compile(
    r"^\s*(?P<addr>[0-9a-f]+):\s*(?P<bytes>[0-9a-f ]+?)\s+(?P<mnem>\S+)(?:\s+(?P<ops>[^#]*))?"
)


_READ_CALL_PLT = re.compile(r"<(fgets|gets|read|recv|fread)@plt>")


def parse_functions(text: str) -> list[tuple[str, int, list[str]]]:
    """Return [(name, entry_addr, instruction_lines)]."""
    fns: list[tuple[str, int, list[str]]] = []
    cur_name = None
    cur_addr = 0
    cur_lines: list[str] = []
    for line in text.splitlines():
        m = _RE_FN_HEADER.match(line)
        if m:
            if cur_name is not None:
                fns.append((cur_name, cur_addr, cur_lines))
            cur_name = m.group("name")
            cur_addr = int(m.group("addr"), 16)
            cur_lines = []
            continue
        if cur_name is None:
            continue
        cur_lines.append(line)
    if cur_name is not None:
        fns.append((cur_name, cur_addr, cur_lines))
    return fns


def _frame_size(lines: list[str]) -> int | None:
    """Extract `sub $0xNN, rsp` from function prologue."""
    for line in lines[:20]:
        m = re.search(r"sub\s+rsp,0x([0-9a-f]+)", line)
        if m:
            return int(m.group(1), 16)
    return None


def _find_buf_and_read(lines: list[str]) -> list[Wrapper]:
    """Scan instructions for `lea rbp-X -> rdi/rax` feeding a read call."""
    results: list[Wrapper] = []
    pending_lea: tuple[int, int] | None = None  # (offset, line_index)
    for i, line in enumerate(lines):
        # Look for `lea <reg>,[rbp-0xNN]`
        m = re.search(r"lea\s+(r\w\w|rax),\[rbp-0x([0-9a-f]+)\]", line)
        if m:
            pending_lea = (int(m.group(2), 16), i)
            continue
        # Look for `mov esi,0xNN` (fgets/read size, 2nd arg).
        m = re.search(r"mov\s+esi,0x([0-9a-f]+)", line)
        if m and pending_lea is not None:
            size = int(m.group(1), 16)
            # scan a few more lines for the call
            for j in range(i, min(i + 8, len(lines))):
                cm = re.search(_READ_CALL_PLT, lines[j])
                if cm:
                    # Extract call site address
                    am = re.match(r"^\s*([0-9a-f]+):", lines[j])
                    call_addr = int(am.group(1), 16) if am else 0
                    buf_off = pending_lea[0]
                    results.append(Wrapper(
                        name="",   # filled in upstream
                        addr=0,
                        buf_offset=buf_off,
                        buf_size=buf_off,   # conservative: treat the distance rbp-X..rbp as total local space
                        read_fn=cm.group(1),
                        read_size=size,
                        read_site=call_addr,
                    ))
                    break
            pending_lea = None
            continue
        # Also look for `mov edx,0xNN` (read 3rd arg) -- less common for fgets
        m = re.search(r"mov\s+edx,0x([0-9a-f]+)", line)
        if m and pending_lea is not None:
            # tentative; don't commit yet
            pass
    return results


def classify(binary: str) -> list[Wrapper]:
    text = disasm(binary)
    fns = parse_functions(text)
    out: list[Wrapper] = []
    for name, addr, lines in fns:
        frame = _frame_size(lines)
        if frame is None:
            continue
        hits = _find_buf_and_read(lines)
        for h in hits:
            h.name = name
            h.addr = addr
            # fgets writes (read_size - 1) content bytes + 1 NUL at [read_size-1].
            # read()/gets write read_size content bytes (no terminator).
            if h.read_fn == "fgets":
                content = h.read_size - 1
                free_nul = True
            else:
                content = h.read_size
                free_nul = False
            # Distance from buf start to first ROP slot (retaddr):
            #   buf_offset bytes (locals + canary) + 8 (saved rbp) = buf_offset+8
            reach = h.buf_offset + 8
            if content <= reach:
                continue
            past = content - reach     # bytes available starting at retaddr
            h.usable_overflow = past
            full_slots = past // 8
            rem = past % 8
            partial = 0
            if free_nul and rem == 7:
                # fgets's trailing \0 becomes the canonical-high zero byte of the
                # final slot, promoting 7 content bytes to a full address.
                partial = 1
            h.rop_slots = full_slots + partial
            # Classification:
            if h.rop_slots <= 3:
                h.classification = "TIGHT_BUDGET"
            elif h.rop_slots <= 8:
                h.classification = "NORMAL"
            else:
                h.classification = "LOOSE"
            out.append(h)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    wrappers = classify(args.binary)
    if not wrappers:
        print("NO_WRAPPERS")
        return 2

    if args.json:
        print(json.dumps([asdict(w) for w in wrappers], indent=2))
        return 0

    for w in wrappers:
        print(f"WRAPPER: {w.name} @ {hex(w.addr)}")
        print(f"  local buffer at rbp-{hex(w.buf_offset)}  (size {hex(w.buf_size)})")
        print(f"  call: {w.read_fn}(buf, {hex(w.read_size)}, ...) @ {hex(w.read_site)}")
        print(f"  usable_overflow: {w.usable_overflow} bytes  ({w.rop_slots} ROP slots total including retaddr)")
        print(f"  classification: {w.classification}")
        if w.classification == "TIGHT_BUDGET":
            print("  recommendation: prefer one_gadget with rbp-controlled argv/envp;")
            print("                  use auto_one_gadget to pick the cheapest-fit")
    return 0


if __name__ == "__main__":
    sys.exit(main())
