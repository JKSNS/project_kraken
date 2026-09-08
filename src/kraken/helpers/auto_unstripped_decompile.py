#!/usr/bin/env python3
"""auto_unstripped_decompile -- fast-path decompilation when DWARF is present.

Cold-starting Ghidra to decompile a binary that already ships unstripped
with debug info is wasteful. `nm` + `addr2line` + `objdump`/`r2` give 80%
of the value in <1s.

This helper is the fast path; `auto_focused_decompile.py` (Ghidra-driven)
remains the slow path for stripped binaries.

Usage:
    python3 auto_unstripped_decompile.py <elf> [--out PATH] [--filter REGEX]
                                              [--insns-per-fn N]

Output schema:
{
  "elf": "<path>",
  "has_dwarf": bool,
  "is_unstripped": bool,
  "functions": [
    {"address": 0x..., "name": "...", "size_bytes": N,
     "decl_file": "...", "decl_line": N,
     "section": ".text",
     "first_insns": ["push {r4, r5, r6, lr}", "..."]
    }
  ],
  "summary": {"total_functions": N, "with_disasm": N, "compilation_units": N}
}

When --filter is given, only functions whose name matches the regex are
fully decompiled (with first_insns). Other functions are listed by
address+name+source-line only.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from elftools.elf.elffile import ELFFile


def _has_dwarf(elf_path: Path) -> bool:
    try:
        with open(elf_path, "rb") as f:
            return ELFFile(f).has_dwarf_info()
    except Exception:
        return False


def _is_unstripped(elf_path: Path) -> bool:
    """An ELF is 'unstripped' if it has a non-trivial .symtab."""
    try:
        with open(elf_path, "rb") as f:
            elf = ELFFile(f)
            symtab = elf.get_section_by_name(".symtab")
            return symtab is not None and symtab.num_symbols() > 10
    except Exception:
        return False


def _collect_functions(elf_path: Path) -> list[dict[str, Any]]:
    """Walk DWARF + symtab to build a function list."""
    out = []
    seen = set()
    with open(elf_path, "rb") as f:
        elf = ELFFile(f)

        # First pass: DWARF subprograms (richer info)
        if elf.has_dwarf_info():
            di = elf.get_dwarf_info()
            for cu in di.iter_CUs():
                line_program = di.line_program_for_CU(cu)
                files = []
                if line_program:
                    for fe in line_program.header.file_entry:
                        n = fe.name
                        if isinstance(n, bytes):
                            n = n.decode("utf-8", errors="replace")
                        files.append(n)
                for die in cu.iter_DIEs():
                    if die.tag != "DW_TAG_subprogram":
                        continue
                    name_attr = die.attributes.get("DW_AT_name")
                    if not name_attr:
                        continue
                    name = name_attr.value
                    if isinstance(name, bytes):
                        name = name.decode("utf-8", errors="replace")
                    low = die.attributes.get("DW_AT_low_pc")
                    if not low:
                        continue
                    low_pc = low.value
                    high = die.attributes.get("DW_AT_high_pc")
                    if high is None:
                        continue
                    hv = high.value
                    size = hv if hv < low_pc else hv - low_pc
                    file_idx_attr = die.attributes.get("DW_AT_decl_file")
                    line_attr = die.attributes.get("DW_AT_decl_line")
                    decl_file = None
                    if file_idx_attr is not None and files:
                        idx = file_idx_attr.value
                        if 0 <= idx < len(files):
                            decl_file = files[idx]
                        elif 1 <= idx <= len(files):
                            decl_file = files[idx - 1]
                    decl_line = line_attr.value if line_attr else None
                    if name in seen:
                        continue
                    seen.add(name)
                    out.append(
                        {
                            "address": low_pc,
                            "address_hex": f"0x{low_pc:x}",
                            "name": name,
                            "size_bytes": size,
                            "decl_file": decl_file,
                            "decl_line": decl_line,
                        }
                    )

        # Second pass: pick up STT_FUNC symbols not seen via DWARF
        symtab = elf.get_section_by_name(".symtab")
        if symtab is not None:
            for sym in symtab.iter_symbols():
                if sym["st_info"]["type"] != "STT_FUNC":
                    continue
                if sym.name in seen or not sym.name:
                    continue
                addr = sym["st_value"]
                if addr == 0:
                    continue
                # Strip Thumb LSB
                if addr & 1:
                    addr -= 1
                out.append(
                    {
                        "address": addr,
                        "address_hex": f"0x{addr:x}",
                        "name": sym.name,
                        "size_bytes": sym["st_size"],
                        "decl_file": None,
                        "decl_line": None,
                    }
                )
                seen.add(sym.name)

    return sorted(out, key=lambda x: x["address"])


DISASM_LINE_RE = re.compile(
    # Line shape: optional box-drawing, "0xADDRESS  HEXBYTES  mnemonic operands  ; comment"
    r"0x([0-9a-fA-F]+)\s+([0-9a-fA-F]{2,16})\s+(.+?)(?:\s*;.*)?$"
)


FN_HEADER_RE = re.compile(r"^\s*;--\s+(\w+):\s*$")


def _radare_disasm_batch(elf_path: Path, symbols: list[str], n: int) -> dict[str, list[str]]:
    """Single r2 invocation that disassembles N insns at each symbol.

    Cuts cold-start cost from O(symbols) to O(1). Uses r2's own
    `;-- <name>:` function-header markers to split output between
    requested symbols (chained `?e` sentinels don't survive command
    composition).
    """
    if shutil.which("r2") is None or not symbols:
        return {}
    target_set = set(symbols)
    cmds = ["aaa"] + [f"pd {n} @ sym.{s}" for s in symbols]
    script = "; ".join(cmds)
    try:
        result = subprocess.run(
            ["r2", "-2", "-q", "-e", "scr.color=0", "-c", script, str(elf_path)],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {}
    if result.returncode != 0:
        return {}

    out: dict[str, list[str]] = {s: [] for s in symbols}
    current: str | None = None
    for line in result.stdout.splitlines():
        m_hdr = FN_HEADER_RE.match(line)
        if m_hdr and m_hdr.group(1) in target_set:
            current = m_hdr.group(1)
            continue
        if current is None:
            continue
        if len(out[current]) >= n:
            continue
        m = DISASM_LINE_RE.search(line)
        if not m:
            continue
        mnem = m.group(3).strip()
        if mnem and not mnem.startswith(";"):
            out[current].append(mnem)
    return out


def analyze(elf_path: Path, filter_regex: re.Pattern | None = None, insns_per_fn: int = 8) -> dict[str, Any]:
    has_dwarf = _has_dwarf(elf_path)
    is_unstripped = _is_unstripped(elf_path)

    if not has_dwarf and not is_unstripped:
        return {
            "elf": str(elf_path),
            "has_dwarf": False,
            "is_unstripped": False,
            "error": (
                "binary is stripped and has no DWARF -- fall back to "
                "auto_focused_decompile.py for Ghidra-driven analysis"
            ),
            "functions": [],
            "summary": {
                "total_functions": 0,
                "with_disasm": 0,
                "compilation_units": 0,
            },
        }

    functions = _collect_functions(elf_path)

    # Pick the symbols we want to disassemble, then batch into one r2 call
    targets = [fn["name"] for fn in functions if filter_regex is None or filter_regex.search(fn["name"])]
    # If no filter is given, default to *not* disassembling all 700+ functions
    # -- that would be ~10 MB of mnemonic noise. Caller must opt in via --filter.
    disasm: dict[str, list[str]] = {}
    if filter_regex is not None and targets:
        disasm = _radare_disasm_batch(elf_path, targets, insns_per_fn)

    with_disasm = 0
    for fn in functions:
        insns = disasm.get(fn["name"])
        if insns:
            fn["first_insns"] = insns
            with_disasm += 1

    cu_count = 0
    if has_dwarf:
        with open(elf_path, "rb") as f:
            elf = ELFFile(f)
            di = elf.get_dwarf_info()
            cu_count = sum(1 for _ in di.iter_CUs())

    return {
        "elf": str(elf_path),
        "has_dwarf": has_dwarf,
        "is_unstripped": is_unstripped,
        "functions": functions,
        "summary": {
            "total_functions": len(functions),
            "with_disasm": with_disasm,
            "compilation_units": cu_count,
        },
    }


def _print_human(result: dict[str, Any], filter_regex: re.Pattern | None) -> None:
    if "error" in result:
        print(f"ERROR: {result['error']}")
        return
    s = result["summary"]
    print(f"elf: {result['elf']}")
    print(f"has_dwarf={result['has_dwarf']} is_unstripped={result['is_unstripped']}")
    print(f"functions: {s['total_functions']} (disasm sampled: {s['with_disasm']}, CUs: {s['compilation_units']})")
    print()
    for fn in result["functions"]:
        if filter_regex and not filter_regex.search(fn["name"]):
            continue
        loc = f"  [{fn['decl_file']}:{fn['decl_line']}]" if fn.get("decl_file") else ""
        print(f"{fn['address_hex']:<10} {fn['name']:<32} {fn['size_bytes']}B{loc}")
        if fn.get("first_insns"):
            for insn in fn["first_insns"]:
                print(f"      {insn}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("elf", type=Path, help="ELF with DWARF / debug info")
    p.add_argument("--out", type=Path, help="write JSON to this path")
    p.add_argument("--json", action="store_true", help="emit JSON to stdout")
    p.add_argument(
        "--filter",
        help="only fully decompile functions whose name matches this regex",
    )
    p.add_argument(
        "--insns-per-fn",
        type=int,
        default=8,
        help="how many instructions to sample per function (default 8)",
    )
    args = p.parse_args(argv)

    if not args.elf.is_file():
        print(f"[-] not a file: {args.elf}", file=sys.stderr)
        return 1

    filter_regex = re.compile(args.filter) if args.filter else None

    result = analyze(args.elf, filter_regex, args.insns_per_fn)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2))
        print(f"wrote {args.out} ({result['summary']['total_functions']} functions)")
    elif args.json:
        json.dump(result, sys.stdout, indent=2)
        print()
    else:
        _print_human(result, filter_regex)

    return 0


if __name__ == "__main__":
    sys.exit(main())
