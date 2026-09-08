#!/usr/bin/env python3
"""auto_capstone_recover -- function recovery from PT_LOAD via Capstone.

Closes the v0.2.1 gap on production firmware. OpenWrt and other OT/IoT
vendors strip ELF section headers entirely, so `objdump -d` and `nm` go
silent and our function inventory is empty. PT_LOAD program headers
remain -- they're how the kernel actually loads the binary -- and Capstone
can disassemble those bytes per-arch without needing section tables.

Two function-entry signals, unioned:

  1. **Call targets** -- collect every address targeted by a call / bl /
     blx / jal / jalr. Robust because if anyone calls it, it must be a
     function entry.

  2. **Prologue patterns** -- per arch, recognise the few bytes that
     start most functions:
       x86_64    push rbp ; mov rbp, rsp                      (or endbr64 on CET)
       x86       push ebp ; mov ebp, esp
       aarch64   stp x29, x30, [sp, #-N]!                     (frame setup)
       arm       push {... lr}  /  stmdb sp!, {..., lr}
       mips      addiu $sp, $sp, -N ; sw $ra, K($sp)
       ppc       stwu r1, -N(r1) ; mflr r0 ; stw r0, K(r1)

The recovered set is honest about its source (`recovery_method:
capstone_pt_load`) so the dossier doesn't claim symbol-table grade
truth from heuristics.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Capstone constants used inline; importable lazily so the helper imports
# even on hosts without capstone (degrades cleanly to "needs capstone").

try:
    from elftools.elf.constants import P_FLAGS
    from elftools.elf.elffile import ELFFile

    HAS_ELFTOOLS = True
except ImportError:
    HAS_ELFTOOLS = False

try:
    from capstone import (
        CS_ARCH_ARM,
        CS_ARCH_ARM64,
        CS_ARCH_MIPS,
        CS_ARCH_PPC,
        CS_ARCH_X86,
        CS_MODE_32,
        CS_MODE_64,
        CS_MODE_ARM,
        CS_MODE_BIG_ENDIAN,
        CS_MODE_LITTLE_ENDIAN,
        Cs,
    )

    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False


# ── Arch / mode resolution ────────────────────────────────────────────


def _pick_arch_mode(e_machine: str, endian_le: bool) -> tuple | None:
    """Return (cs_arch, cs_mode, arch_name) or None if unsupported."""
    if not HAS_CAPSTONE:
        return None
    em = e_machine.upper() if isinstance(e_machine, str) else str(e_machine).upper()
    endian = CS_MODE_LITTLE_ENDIAN if endian_le else CS_MODE_BIG_ENDIAN
    if em in ("EM_X86_64",):
        return (CS_ARCH_X86, CS_MODE_64, "x86_64")
    if em in ("EM_386",):
        return (CS_ARCH_X86, CS_MODE_32, "x86")
    if em in ("EM_AARCH64",):
        return (CS_ARCH_ARM64, endian, "aarch64")
    if em in ("EM_ARM",):
        return (CS_ARCH_ARM, CS_MODE_ARM | endian, "arm")
    if em in ("EM_MIPS",):
        return (CS_ARCH_MIPS, CS_MODE_32 | endian, "mips")
    if em in ("EM_PPC", "EM_PPC64"):
        return (CS_ARCH_PPC, CS_MODE_32 | endian, "ppc")
    return None


# ── Per-arch prologue + call mnemonic tables ──────────────────────────

# Mnemonics that imply a call (i.e. their target is a function entry).
_CALL_MNEMONICS = {
    "x86_64": {"call"},
    "x86": {"call"},
    "aarch64": {"bl", "blr"},
    "arm": {"bl", "blx"},
    "mips": {"jal", "jalr", "bal"},
    "ppc": {"bl"},
}

# Prologue-pattern detectors. Each is (mnemonic_match, operand_substring,
# next_mnemonic_match_or_None). When all match, the address is recorded
# as a function entry.
_PROLOGUE_PATTERNS = {
    "x86_64": [
        ("push", "rbp", None),
        ("endbr64", "", None),
    ],
    "x86": [
        ("push", "ebp", None),
        ("endbr32", "", None),
    ],
    "aarch64": [
        ("stp", "x29", None),
        ("paciasp", "", None),  # CPI / pointer authentication
    ],
    "arm": [
        ("push", "lr", None),
        ("stmdb", "sp!", None),
    ],
    "mips": [
        ("addiu", "$sp", "sw"),  # addiu $sp,...,-N + sw $ra,...
    ],
    "ppc": [
        ("stwu", "1,", None),  # stwu r1, -N(r1) -- frame setup
    ],
}

# Return mnemonics -- the next aligned address after one of these (plus its
# delay slot for delayed-branch ISAs) is very likely a function entry.
# Catches leaf functions whose prologue is a no-op (compiler-optimised).
_RETURN_MNEMONICS = {
    "x86_64": {"ret"},
    "x86": {"ret"},
    "aarch64": {"ret"},
    "arm": {"bx"},  # bx lr
    "mips": {"jr"},  # jr $ra
    "ppc": {"blr"},
}

_HAS_DELAY_SLOT = {
    "mips": True,
    "ppc": False,
    "x86": False,
    "x86_64": False,
    "aarch64": False,
    "arm": False,
}

_FN_ALIGN = {
    "x86_64": 1,
    "x86": 1,
    "aarch64": 4,
    "arm": 4,
    "mips": 4,
    "ppc": 4,
}


def _is_return_match(insn, arch_name: str) -> bool:
    if insn is None:
        return False
    rets = _RETURN_MNEMONICS.get(arch_name, set())
    if insn.mnemonic not in rets:
        return False
    if arch_name == "mips" and insn.mnemonic == "jr":
        return "$ra" in insn.op_str
    if arch_name == "arm" and insn.mnemonic == "bx":
        return "lr" in insn.op_str
    return True


def _is_prologue_match(insn, next_insn, arch_name: str) -> bool:
    if insn is None:
        return False
    patterns = _PROLOGUE_PATTERNS.get(arch_name) or []
    for mnem, op_substr, next_mnem in patterns:
        if insn.mnemonic == mnem and (not op_substr or op_substr in insn.op_str):
            if next_mnem is None:
                return True
            if next_insn is not None and next_insn.mnemonic == next_mnem:
                return True
    return False


def _extract_call_target(insn, arch_name: str) -> int | None:
    """Best-effort target-address extraction. Capstone exposes structured
    operands but we work string-level to keep the dependency surface small."""
    if insn.mnemonic not in _CALL_MNEMONICS.get(arch_name, set()):
        return None
    op = insn.op_str.split(",")[0].strip()
    op = op.lstrip("#$")
    if op.startswith("0x"):
        try:
            return int(op, 16)
        except ValueError:
            return None
    if op.isdigit():
        return int(op)
    return None


# ── Top-level recovery ────────────────────────────────────────────────


def recover_functions(
    elf_path: str | Path,
    *,
    max_fns: int = 5000,
) -> dict:
    """Return a dict with a list of recovered function entries + metadata.

    Always returns a dict; on error returns one with `status: error` so
    callers can branch without try/except.
    """
    p = Path(elf_path)
    if not p.exists():
        return {"status": "error", "error": "elf not found", "path": str(p)}

    if not HAS_ELFTOOLS or not HAS_CAPSTONE:
        return {
            "status": "needs_dependencies",
            "missing": [
                d
                for d, present in [
                    ("pyelftools", HAS_ELFTOOLS),
                    ("capstone", HAS_CAPSTONE),
                ]
                if not present
            ],
            "install_hint": "apt-get install python3-pyelftools python3-capstone",
        }

    with p.open("rb") as f:
        try:
            elf = ELFFile(f)
        except Exception as e:
            return {"status": "error", "error": f"elf parse failed: {e}"}

        endian_le = elf.header["e_ident"]["EI_DATA"] == "ELFDATA2LSB"
        arch_tuple = _pick_arch_mode(elf.header["e_machine"], endian_le)
        if arch_tuple is None:
            return {
                "status": "unsupported_arch",
                "e_machine": str(elf.header["e_machine"]),
            }
        cs_arch, cs_mode, arch_name = arch_tuple
        cs = Cs(cs_arch, cs_mode)
        cs.skipdata = True  # don't crash on data interleaved in .text

        prologue_entries: set[int] = set()
        call_targets: set[int] = set()
        epilogue_next_entries: set[int] = set()
        recursive_entries: set[int] = set()
        loadable_ranges: list[tuple[int, int]] = []
        bytes_disassembled = 0

        align = _FN_ALIGN.get(arch_name, 4)
        delay_slot = _HAS_DELAY_SLOT.get(arch_name, False)
        e_entry = elf.header.get("e_entry", 0)

        for seg in elf.iter_segments():
            if seg.header.p_type != "PT_LOAD":
                continue
            if not (seg.header.p_flags & P_FLAGS.PF_X):
                continue
            data = seg.data()
            base = seg.header.p_vaddr
            seg_end = base + len(data)
            loadable_ranges.append((base, seg_end))
            bytes_disassembled += len(data)

            # Walk with previous-insn lookback for the MIPS two-insn pattern.
            # Track returns to mark next-aligned addr as candidate fn entry.
            prev_insn = None
            saw_return_at = None  # address of the last return insn
            for insn in cs.disasm(data, base):
                # Prologue detection (lookback)
                if _is_prologue_match(prev_insn, insn, arch_name) and prev_insn is not None:
                    prologue_entries.add(prev_insn.address)
                # Call-target detection
                tgt = _extract_call_target(insn, arch_name)
                if tgt is not None:
                    call_targets.add(tgt)
                # Return-then-next-aligned detection (catches leaf fns)
                if saw_return_at is not None:
                    # skip exactly one instruction after return on delay-slot
                    # ISAs; otherwise this insn IS the candidate entry
                    if delay_slot:
                        # We're in the delay slot; mark the NEXT addr as entry
                        delay_target = insn.address + insn.size
                        if delay_target % align == 0 and delay_target < seg_end:
                            epilogue_next_entries.add(delay_target)
                        saw_return_at = None
                    else:
                        if insn.address % align == 0:
                            epilogue_next_entries.add(insn.address)
                        saw_return_at = None
                if _is_return_match(insn, arch_name):
                    saw_return_at = insn.address
                prev_insn = insn

        # Filter call targets to those inside loadable ranges (drop noise)
        def _in_loadable(addr: int) -> bool:
            return any(start <= addr < end for start, end in loadable_ranges)

        call_targets = {a for a in call_targets if _in_loadable(a)}
        epilogue_next_entries = {a for a in epilogue_next_entries if _in_loadable(a)}

        # ── Recursive disassembly from e_entry (cleaner CFG) ──────────────
        # BFS: start at e_entry, disassemble each function, follow calls
        # to discover new function entries. This avoids the linear-sweep
        # noise from disassembling ELF header bytes as instructions.
        if e_entry and any(start <= e_entry < end for start, end in loadable_ranges):
            seg_for_entry = next(
                (
                    s
                    for s in elf.iter_segments()
                    if s.header.p_type == "PT_LOAD"
                    and (s.header.p_flags & P_FLAGS.PF_X)
                    and s.header.p_vaddr <= e_entry < s.header.p_vaddr + len(s.data())
                ),
                None,
            )
            if seg_for_entry is not None:
                seg_data = seg_for_entry.data()
                seg_base = seg_for_entry.header.p_vaddr
                seen: set[int] = set()
                queue: list[int] = [e_entry]
                # Seed with all already-discovered call targets in this segment
                queue.extend(a for a in call_targets if seg_base <= a < seg_base + len(seg_data))
                MAX_BFS = 20000
                while queue and len(seen) < MAX_BFS:
                    addr = queue.pop()
                    if addr in seen:
                        continue
                    seen.add(addr)
                    if not (seg_base <= addr < seg_base + len(seg_data)):
                        continue
                    recursive_entries.add(addr)
                    # Disassemble this function -- stop at return / unconditional
                    # branch / max-insns
                    offset = addr - seg_base
                    insns_in_fn = 0
                    for ri in cs.disasm(seg_data[offset:], addr):
                        insns_in_fn += 1
                        if insns_in_fn > 2000:  # safety: don't trace forever
                            break
                        new_tgt = _extract_call_target(ri, arch_name)
                        if new_tgt is not None and new_tgt not in seen:
                            queue.append(new_tgt)
                        if _is_return_match(ri, arch_name):
                            # On delay-slot ISAs, run one more insn (the delay slot)
                            if delay_slot:
                                continue
                            break
        recursive_entries = {a for a in recursive_entries if _in_loadable(a)}

        all_entries = prologue_entries | call_targets | epilogue_next_entries | recursive_entries
        capped = sorted(all_entries)[:max_fns]

        return {
            "status": "ok",
            "arch": arch_name,
            "endian": "little" if endian_le else "big",
            "function_count": len(all_entries),
            "function_count_returned": len(capped),
            "truncated": len(all_entries) > max_fns,
            "by_signal": {
                "prologue_pattern": len(prologue_entries),
                "call_target": len(call_targets),
                "epilogue_next": len(epilogue_next_entries),
                "recursive_from_entry": len(recursive_entries),
                "intersection_prologue_call": len(prologue_entries & call_targets),
                "union": len(all_entries),
            },
            "e_entry": f"0x{e_entry:x}" if e_entry else None,
            "bytes_disassembled": bytes_disassembled,
            "loadable_ranges": [{"start": f"0x{s:x}", "end": f"0x{e:x}"} for s, e in loadable_ranges],
            "functions": [
                {
                    "addr": f"0x{a:x}",
                    "name": f"sub_{a:x}",
                    "source_signals": [
                        s
                        for s, hits in [
                            ("prologue", a in prologue_entries),
                            ("call_target", a in call_targets),
                            ("epilogue_next", a in epilogue_next_entries),
                            ("recursive", a in recursive_entries),
                        ]
                        if hits
                    ],
                }
                for a in capped
            ],
            "recovery_method": "capstone_pt_load",
        }


# ── Playbook-friendly entry ───────────────────────────────────────────


def playbook_recover_functions(*, target: str, max_fns: int = 5000) -> dict:
    return recover_functions(target, max_fns=int(max_fns))


# ── CLI ──────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="auto_capstone_recover",
        description="Capstone-based function recovery from ELF PT_LOAD segments.",
    )
    parser.add_argument("elf")
    parser.add_argument("--max-fns", type=int, default=5000)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    result = recover_functions(args.elf, max_fns=args.max_fns)

    if args.json:
        print(json.dumps(result, indent=2))
        return 0 if result.get("status") == "ok" else 2

    print(f"status:    {result.get('status')}")
    if result.get("status") == "ok":
        sigs = result.get("by_signal") or {}
        print(f"arch:      {result.get('arch')} / {result.get('endian')}")
        print(
            f"functions: {result.get('function_count')} "
            f"(returned {result.get('function_count_returned')}"
            + (", truncated" if result.get("truncated") else "")
            + ")"
        )
        print("  by signal:")
        print(f"    prologue_pattern: {sigs.get('prologue_pattern')}")
        print(f"    call_target:      {sigs.get('call_target')}")
        print(f"    intersection:     {sigs.get('intersection')}")
        print(f"    union:            {sigs.get('union')}")
        print(f"bytes_disassembled: {result.get('bytes_disassembled'):,}")
        print("first 8:")
        for f in result.get("functions", [])[:8]:
            sig = ",".join(f["source_signals"])
            print(f"  {f['addr']}  {f['name']}  ({sig})")
    elif result.get("status") == "needs_dependencies":
        print(f"missing: {result.get('missing')}")
        print(f"hint:    {result.get('install_hint')}")
    else:
        print(f"  error/info: {result}")
    return 0 if result.get("status") == "ok" else 2


if __name__ == "__main__":
    sys.exit(main())
