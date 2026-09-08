#!/usr/bin/env python3
"""auto_memory_map -- extract a structured memory map from linker script + ELF.

For embedded targets, the memory map is a critical fact every exploit
references: where does flash live, where does RAM live, where's the stack,
where's the heap, where's the canary, where do secrets sit. Computing this
by hand from `*.ld` + `nm` is mechanical; this helper does it.

Combined with `auto_dwarf_structs` global addresses, the output covers
"every region that matters" for any overflow primitive's reach analysis.

Usage:
    python3 auto_memory_map.py --elf <path.elf> [--ld <path.ld>] [--out PATH]

If `--ld` is omitted, scan the directory of <elf> for `*.ld`/`*.cmd` files.

Output schema:
{
  "elf": "<path>",
  "linker_script": "<path or null>",
  "regions": [
    {"name": "FLASH",  "kind": "rom",   "perms": "RX",
     "base": 0x6000, "end": 0x28000, "size": N,
     "purpose": "firmware code"},
    {"name": "STACK",  "kind": "ram",   "perms": "RW",
     "base": 0x202075c0, "end": 0x20208000, "size": 0xa40,
     "purpose": "stack (grows down)"}
  ],
  "elf_segments": [
    {"section": ".text", "base": 0x..., "size": N, "perms": "RX"}
  ],
  "key_globals": [
    {"name": "__stack_chk_guard", "address": 0x20202694, "size": 4,
     "warning": "fixed RAM address -- overflowable"},
    {"name": "shared_buf", ...}
  ],
  "overflow_reach": {
    "shared_buf -> stack_canary": 0x2594,
    "shared_buf -> stack_top":    0x7f00
  }
}
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from elftools.elf.elffile import ELFFile

# Patterns recognised in linker scripts (TI cgt + GNU ld + ARMCC variants)
RE_MEMORY_BLOCK = re.compile(
    r"^\s*(\w+)\s*\(([RWX!]+)\)\s*:\s*"
    r"origin\s*=\s*([\w()+\-*/\s]+?)\s*,\s*"
    r"length\s*=\s*([\w()+\-*/\s]+?)\s*$",
    re.MULTILINE | re.IGNORECASE,
)

RE_DEFINE = re.compile(
    r"^\s*#define\s+(\w+)\s+(.+?)(?:\s*/\*.*)?$",
    re.MULTILINE,
)


PURPOSE_HINTS = {
    "BOOTLOADER": "bootloader (TI BSL or vendor)",
    "FLASH": "firmware code",
    "FILES": "user-data flash region (eCTF: file storage)",
    "FAT": "filesystem allocation table",
    "APP2": "secondary application slot",
    "RAMFUNC": "RAM-resident code (W^X exception)",
    "STACK_MEM": "stack (grows down)",
    "STACK": "stack (grows down)",
    "WOLFSSL_MEM": "wolfSSL static heap (allocator metadata lives here)",
    "WOLFSSL": "wolfSSL static heap",
    "SRAM": "general data (.data, .bss)",
    "BCR_CONFIG": "TI bootloader config",
    "BSL_CONFIG": "TI bootloader strap config",
}


def _parse_constants(content: str) -> dict[str, int]:
    """Extract simple #define-style integer constants from the linker script."""
    constants: dict[str, int] = {}
    # Multi-pass to resolve forward refs
    for _ in range(4):
        for m in RE_DEFINE.finditer(content):
            name, expr = m.group(1), m.group(2).strip()
            if name in constants:
                continue
            try:
                constants[name] = _eval_expr(expr, constants)
            except Exception:
                pass
    return constants


def _eval_expr(expr: str, constants: dict[str, int]) -> int:
    """Evaluate a simple integer expression with named constants."""
    expr = expr.strip()
    # Direct integer
    try:
        return int(expr, 0)
    except ValueError:
        pass
    # Named constant
    if expr in constants:
        return constants[expr]
    # Replace named tokens with values
    s = expr
    for name, value in sorted(constants.items(), key=lambda x: -len(x[0])):
        s = re.sub(rf"\b{name}\b", str(value), s)
    # Only allow integer arithmetic now
    if not re.fullmatch(r"[\dxXa-fA-F\s+\-*/()]+", s):
        raise ValueError(f"unresolved tokens in {expr!r}")
    return int(eval(s))  # noqa: S307 -- restricted regex above


def parse_linker_script(path: Path) -> list[dict[str, Any]]:
    """Parse a linker script (TI cgt or GNU ld) into a list of memory regions."""
    content = path.read_text(errors="replace")
    constants = _parse_constants(content)

    regions: list[dict[str, Any]] = []
    for m in RE_MEMORY_BLOCK.finditer(content):
        name, perms, origin, length = (
            m.group(1),
            m.group(2),
            m.group(3),
            m.group(4),
        )
        try:
            base = _eval_expr(origin, constants)
            size = _eval_expr(length, constants)
        except Exception:
            continue
        # Heuristic: ROM if RX/R-X, RW if RW
        perm_set = set(perms.upper())
        if "X" in perm_set and "W" not in perm_set:
            kind = "rom"
        elif "W" in perm_set and "X" in perm_set:
            kind = "ramfunc"  # rare W^X exception
        elif "W" in perm_set:
            kind = "ram"
        else:
            kind = "rom"
        regions.append(
            {
                "name": name,
                "kind": kind,
                "perms": "".join(sorted(perm_set)),
                "base": base,
                "base_hex": f"0x{base:x}",
                "end": base + size,
                "end_hex": f"0x{base + size:x}",
                "size": size,
                "purpose": PURPOSE_HINTS.get(name.upper(), "unknown"),
            }
        )
    return sorted(regions, key=lambda r: r["base"])


def collect_elf_sections(elf_path: Path) -> list[dict[str, Any]]:
    """Pull section headers with their addresses for cross-reference."""
    out = []
    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        for section in elf.iter_sections():
            flags = section["sh_flags"]
            addr = section["sh_addr"]
            size = section["sh_size"]
            if addr == 0 and size == 0:
                continue
            perms = ""
            if flags & 0x4:
                perms += "X"
            if flags & 0x1:
                perms += "W"
            perms += "R"
            out.append(
                {
                    "section": section.name,
                    "base": addr,
                    "base_hex": f"0x{addr:x}",
                    "size": size,
                    "perms": perms or "R",
                }
            )
    return out


KEY_GLOBAL_HINTS = {
    "__stack_chk_guard": "fixed RAM address -- overflowable, single canary for the whole binary",
    "shared_buf": "command/response shared union; primary overflow source for UART input",
    "last_challenge_sent": "auth state machine; mutated mid-handshake",
    "last_challenge_received": "auth state machine; mutated mid-handshake",
    "HSM_AUTH_KEY": "shared symmetric key -- single key compromise = total breach",
    "PIN_HASH": "salted SHA-256 of PIN; const so anti-bruteforce is the only barrier",
    "PIN_SALT": "PIN salt",
    "GROUP_KEYS": "per-group keys (read/write AES, Ed25519 receive)",
}


def collect_key_globals(elf_path: Path) -> list[dict[str, Any]]:
    """Heuristically pick out interesting globals by name from the symbol table."""
    out = []
    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name(".symtab")
        if symtab is None:
            return []
        for sym in symtab.iter_symbols():
            name = sym.name
            if not name:
                continue
            hint = None
            for key, message in KEY_GLOBAL_HINTS.items():
                if name == key or name.startswith(key + "."):
                    hint = message
                    break
            if hint is None:
                continue
            out.append(
                {
                    "name": name,
                    "address": sym["st_value"],
                    "address_hex": f"0x{sym['st_value']:x}",
                    "size": sym["st_size"],
                    "warning": hint,
                }
            )
    return out


def compute_overflow_reach(regions: list[dict], globals_: list[dict]) -> dict[str, int]:
    """Compute distances between key overflow sources and protective markers."""
    out: dict[str, int] = {}

    shared_buf = next((g for g in globals_ if g["name"] == "shared_buf"), None)
    canary = next((g for g in globals_ if g["name"] == "__stack_chk_guard"), None)
    stack = next(
        (r for r in regions if r["name"].upper() in ("STACK_MEM", "STACK")),
        None,
    )

    if shared_buf and canary:
        out["shared_buf -> __stack_chk_guard"] = canary["address"] - shared_buf["address"]
        out["shared_buf -> __stack_chk_guard (hex)"] = f"0x{canary['address'] - shared_buf['address']:x}"

    if shared_buf and stack:
        out["shared_buf -> STACK base"] = stack["base"] - shared_buf["address"]
        out["shared_buf -> STACK base (hex)"] = f"0x{stack['base'] - shared_buf['address']:x}"

    if shared_buf and stack:
        out["shared_buf -> STACK top"] = stack["end"] - shared_buf["address"]

    return out


def find_linker_script(elf_path: Path) -> Path | None:
    """Look for a .ld/.cmd in the ELF's directory and parent directory."""
    candidates = []
    for d in (elf_path.parent, elf_path.parent.parent):
        if d.exists():
            candidates.extend(d.glob("*.ld"))
            candidates.extend(d.glob("*.cmd"))
            candidates.extend(d.glob("firmware/*.ld"))
            candidates.extend(d.glob("firmware/*.cmd"))
    return candidates[0] if candidates else None


def analyze(
    elf_path: Path | None,
    ld_path: Path | None,
) -> dict[str, Any]:
    """Produce a memory map from ELF + linker script. Either input is optional.

    Modes:
      - Both ELF and linker script: full output (regions + sections + globals
        + overflow reach).
      - Linker script only: regions only, with `mode = "linker-script-only"`.
        Useful for source-only repos that haven't been built yet.
      - ELF only: sections + globals, with `mode = "elf-only"`. No region map.
    """
    if elf_path is not None and ld_path is None:
        ld_path = find_linker_script(elf_path)

    regions = parse_linker_script(ld_path) if ld_path else []
    sections = collect_elf_sections(elf_path) if elf_path else []
    key_globals = collect_key_globals(elf_path) if elf_path else []
    overflow_reach = compute_overflow_reach(regions, key_globals)

    if elf_path and ld_path:
        mode = "full"
    elif ld_path:
        mode = "linker-script-only"
    elif elf_path:
        mode = "elf-only"
    else:
        mode = "empty"

    return {
        "elf": str(elf_path) if elf_path else None,
        "linker_script": str(ld_path) if ld_path else None,
        "mode": mode,
        "regions": regions,
        "elf_sections": sections,
        "key_globals": sorted(key_globals, key=lambda g: g["address"]),
        "overflow_reach": overflow_reach,
    }


def _print_human(result: dict[str, Any]) -> None:
    print(f"elf: {result['elf']}")
    print(f"linker_script: {result['linker_script']}")
    print()
    if result["regions"]:
        print("=== MEMORY REGIONS (from linker script) ===")
        for r in result["regions"]:
            print(
                f"  {r['name']:<14} {r['kind']:<8} {r['perms']:<5} "
                f"{r['base_hex']:<10} – {r['end_hex']:<10} "
                f"({r['size']:>7d}B)  {r['purpose']}"
            )
    print()
    print("=== KEY GLOBALS (heuristic) ===")
    for g in result["key_globals"]:
        print(f"  {g['address_hex']:<10} {g['name']:<28} ({g['size']}B)  [!] {g['warning']}")
    print()
    if result["overflow_reach"]:
        print("=== OVERFLOW REACH ===")
        for k, v in result["overflow_reach"].items():
            if isinstance(v, int):
                print(f"  {k:<40} {v:>8d} bytes")
            else:
                print(f"  {k:<40} {v}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--elf", type=Path, help="ELF to analyze (optional)")
    p.add_argument("--ld", type=Path, help="linker script (optional; auto-detected from ELF dir)")
    p.add_argument("--out", type=Path, help="write JSON to this path")
    p.add_argument("--json", action="store_true", help="emit JSON to stdout")
    args = p.parse_args(argv)

    if args.elf and not args.elf.is_file():
        print(f"[-] not a file: {args.elf}", file=sys.stderr)
        return 1
    if args.ld and not args.ld.is_file():
        print(f"[-] not a file: {args.ld}", file=sys.stderr)
        return 1
    if not args.elf and not args.ld:
        p.error("provide --elf, --ld, or both")

    result = analyze(args.elf, args.ld)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2))
        print(f"wrote {args.out}")
    elif args.json:
        json.dump(result, sys.stdout, indent=2)
        print()
    else:
        _print_human(result)

    return 0


if __name__ == "__main__":
    sys.exit(main())
