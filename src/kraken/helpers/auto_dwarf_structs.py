#!/usr/bin/env python3
"""auto_dwarf_structs -- extract struct/global ABI facts from a DWARF-bearing ELF.

When firmware ships unstripped with debug info (`-g`) -- common in academic /
eCTF / hobbyist / educational targets -- the compiler has already committed to
struct layouts, typedef chains, array sizes, global addresses, and source
locations. Re-parsing the C is unnecessary and brittle (TI cgt extensions,
preprocessor macros, vendor headers); reading DWARF gives ground-truth ABI
facts directly.

This is the foundation for `protocol_surface.json` per
`docs/kraken_research_mode_synthesis.md`. Downstream helpers
(auto_ingress_contracts, auto_validation_gates, auto_research_report) consume
its output.

Usage:
    python3 auto_dwarf_structs.py <elf> [--out PATH] [--filter-prefix PREFIX]
                                       [--include-anonymous]

Output schema:
{
  "elf": "<path>",
  "structs": [
    {"name": "...", "size_bytes": N, "packed": bool,
     "fields": [{"name": "...", "offset": N, "size_bytes": N,
                 "type": "u8|u16le|u32|char[N]|<typedef>|<struct>", ...}],
     "decl_file": "...", "decl_line": N}
  ],
  "typedefs": [{"name": "...", "underlying_type": "..."}],
  "globals": [
    {"name": "...", "address": 0x..., "size_bytes": N, "type": "...",
     "section_hint": ".bss|.data|.rodata", "decl_file": "...", "decl_line": N}
  ],
  "functions": [
    {"name": "...", "address": 0x..., "size_bytes": N, "decl_file": "...", "decl_line": N}
  ],
  "summary": {"struct_count": N, "global_count": N, "function_count": N,
              "compilation_units": N}
}
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from elftools.dwarf.die import DIE
from elftools.elf.elffile import ELFFile

# DWARF type-name resolution: map common base types to compact names so the
# output is readable. Otherwise we fall back to the raw DWARF type name.
BASE_TYPE_MAP = {
    ("signed char", 1): "i8",
    ("unsigned char", 1): "u8",
    ("char", 1): "char",
    ("short", 2): "i16",
    ("unsigned short", 2): "u16",
    ("int", 4): "i32",
    ("unsigned int", 4): "u32",
    ("long", 4): "i32",
    ("unsigned long", 4): "u32",
    ("long long", 8): "i64",
    ("unsigned long long", 8): "u64",
    ("float", 4): "f32",
    ("double", 8): "f64",
    ("_Bool", 1): "bool",
    ("bool", 1): "bool",
}


def _attr(die: DIE, name: str) -> Any:
    """Fetch a DWARF attribute value or None."""
    attr = die.attributes.get(name)
    return attr.value if attr is not None else None


def _name(die: DIE) -> str | None:
    """Decode DW_AT_name as utf-8 if present."""
    val = _attr(die, "DW_AT_name")
    if isinstance(val, bytes):
        try:
            return val.decode("utf-8", errors="replace")
        except Exception:
            return None
    return val


def _resolve_type(die: DIE, depth: int = 0) -> dict[str, Any]:
    """Resolve a DW_AT_type reference into a compact descriptor.

    Returns a dict with keys:
      - kind: base|pointer|array|struct|union|enum|typedef|const|volatile|function|void|unknown
      - name: best-effort human name
      - size_bytes: in-memory size when knowable
      - elem_type / target_type / underlying / etc. depending on kind
    """
    if depth > 8:
        return {"kind": "unknown", "name": "<recursion>", "size_bytes": None}

    type_ref = die.attributes.get("DW_AT_type")
    if type_ref is None:
        return {"kind": "void", "name": "void", "size_bytes": 0}

    try:
        target = die.get_DIE_from_attribute("DW_AT_type")
    except Exception:
        return {"kind": "unknown", "name": "<unresolved>", "size_bytes": None}

    return _describe_type(target, depth + 1)


def _describe_type(die: DIE, depth: int = 0) -> dict[str, Any]:
    """Describe a type DIE."""
    if depth > 8:
        return {"kind": "unknown", "name": "<recursion>", "size_bytes": None}

    tag = die.tag
    name = _name(die)
    size = _attr(die, "DW_AT_byte_size")

    if tag == "DW_TAG_base_type":
        compact = BASE_TYPE_MAP.get((name, size))
        return {
            "kind": "base",
            "name": compact or name or "<unnamed>",
            "size_bytes": size,
        }

    if tag == "DW_TAG_pointer_type":
        return {
            "kind": "pointer",
            "name": "ptr",
            "size_bytes": size,
            "target_type": _resolve_type(die, depth),
        }

    if tag == "DW_TAG_array_type":
        elem = _resolve_type(die, depth)
        # Array length comes from a DW_TAG_subrange_type child
        length = None
        for child in die.iter_children():
            if child.tag == "DW_TAG_subrange_type":
                ub = _attr(child, "DW_AT_upper_bound")
                cnt = _attr(child, "DW_AT_count")
                if ub is not None:
                    length = ub + 1
                elif cnt is not None:
                    length = cnt
                break
        elem_size = elem.get("size_bytes")
        total = length * elem_size if (length is not None and elem_size) else None
        elem_name = elem.get("name", "?")
        return {
            "kind": "array",
            "name": f"{elem_name}[{length if length is not None else '?'}]",
            "size_bytes": total,
            "elem_type": elem,
            "length": length,
        }

    if tag == "DW_TAG_typedef":
        underlying = _resolve_type(die, depth)
        return {
            "kind": "typedef",
            "name": name or "<anon-typedef>",
            "size_bytes": underlying.get("size_bytes"),
            "underlying": underlying,
        }

    if tag == "DW_TAG_structure_type":
        return {
            "kind": "struct",
            "name": name or "<anon-struct>",
            "size_bytes": size,
        }

    if tag == "DW_TAG_union_type":
        return {
            "kind": "union",
            "name": name or "<anon-union>",
            "size_bytes": size,
        }

    if tag == "DW_TAG_enumeration_type":
        return {
            "kind": "enum",
            "name": name or "<anon-enum>",
            "size_bytes": size,
        }

    if tag == "DW_TAG_const_type":
        underlying = _resolve_type(die, depth)
        return {
            "kind": "const",
            "name": f"const {underlying.get('name', '?')}",
            "size_bytes": underlying.get("size_bytes"),
            "underlying": underlying,
        }

    if tag == "DW_TAG_volatile_type":
        underlying = _resolve_type(die, depth)
        return {
            "kind": "volatile",
            "name": f"volatile {underlying.get('name', '?')}",
            "size_bytes": underlying.get("size_bytes"),
            "underlying": underlying,
        }

    if tag == "DW_TAG_subroutine_type":
        return {
            "kind": "function",
            "name": "func",
            "size_bytes": None,
        }

    return {
        "kind": "unknown",
        "name": name or f"<{tag}>",
        "size_bytes": size,
    }


def _decode_member_offset(die: DIE) -> int | None:
    """Decode DW_AT_data_member_location, which may be int or DWARF expr."""
    attr = die.attributes.get("DW_AT_data_member_location")
    if attr is None:
        return None
    val = attr.value
    if isinstance(val, int):
        return val
    if isinstance(val, list) and len(val) >= 2 and val[0] == 0x23:
        # DW_OP_plus_uconst <ULEB128 offset>
        # ULEB decode
        result = 0
        shift = 0
        for b in val[1:]:
            result |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                break
            shift += 7
        return result
    return None


def _decode_global_address(die: DIE) -> int | None:
    """Decode DW_AT_location for a DW_TAG_variable, supporting DW_OP_addr."""
    attr = die.attributes.get("DW_AT_location")
    if attr is None:
        return None
    val = attr.value
    if isinstance(val, int):
        return val
    if isinstance(val, list) and len(val) >= 5 and val[0] == 0x03:
        # DW_OP_addr <addr>
        # Little-endian 32-bit address (Cortex-M / ARM32)
        return int.from_bytes(bytes(val[1:5]), "little")
    return None


def _decl_location(die: DIE, cu_files: list[str]) -> tuple[str | None, int | None]:
    """Resolve DW_AT_decl_file index → file path, plus DW_AT_decl_line."""
    file_idx = _attr(die, "DW_AT_decl_file")
    line = _attr(die, "DW_AT_decl_line")
    if file_idx is None:
        return (None, line)
    # DWARF file indices are 1-based historically; pyelftools surfaces 0-based
    # for DWARF v5, 1-based for v3/4. Try both.
    if 0 <= file_idx < len(cu_files):
        return (cu_files[file_idx], line)
    if 1 <= file_idx <= len(cu_files):
        return (cu_files[file_idx - 1], line)
    return (None, line)


def _cu_file_table(cu) -> list[str]:
    """Extract the file name table for a CU as a list."""
    line_program = cu.dwarfinfo.line_program_for_CU(cu)
    if line_program is None:
        return []
    files = []
    header = line_program.header
    for fe in header.file_entry:
        name = fe.name
        if isinstance(name, bytes):
            name = name.decode("utf-8", errors="replace")
        dir_idx = fe.dir_index if hasattr(fe, "dir_index") else 0
        directory = ""
        include_dirs = header.include_directory
        if 0 < dir_idx <= len(include_dirs):
            d = include_dirs[dir_idx - 1]
            directory = d.decode("utf-8", errors="replace") if isinstance(d, bytes) else d
        files.append(f"{directory}/{name}" if directory else name)
    return files


def _extract_struct_fields(die: DIE) -> tuple[list[dict], int | None, bool]:
    """Extract field list, size, and packed-flag from a structure_type DIE.

    Returns (fields, size_bytes, packed). Returns ([], None, False) if the
    DIE has no byte_size (forward decl)."""
    size = _attr(die, "DW_AT_byte_size")
    if size is None:
        return ([], None, False)
    fields = []
    for child in die.iter_children():
        if child.tag != "DW_TAG_member":
            continue
        f_name = _name(child)
        offset = _decode_member_offset(child)
        f_type = _resolve_type(child)
        fields.append(
            {
                "name": f_name,
                "offset": offset,
                "size_bytes": f_type.get("size_bytes"),
                "type": f_type.get("name"),
                "type_kind": f_type.get("kind"),
            }
        )
    field_total = 0
    if fields and all(f["offset"] is not None and f["size_bytes"] is not None for f in fields):
        last = fields[-1]
        field_total = last["offset"] + last["size_bytes"]
    packed = bool(fields) and field_total == size
    return (fields, size, packed)


def extract(elf_path: Path) -> dict[str, Any]:
    structs: list[dict] = []
    typedefs: list[dict] = []
    globals_: list[dict] = []
    functions: list[dict] = []
    cu_count = 0
    seen_struct_names = set()
    seen_typedef_names = set()
    seen_global_names = set()
    seen_function_names = set()

    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        if not elf.has_dwarf_info():
            return {
                "elf": str(elf_path),
                "error": "no DWARF debug info",
                "structs": [],
                "typedefs": [],
                "globals": [],
                "functions": [],
                "summary": {
                    "struct_count": 0,
                    "global_count": 0,
                    "function_count": 0,
                    "compilation_units": 0,
                },
            }
        di = elf.get_dwarf_info()

        for cu in di.iter_CUs():
            cu_count += 1
            cu_files = _cu_file_table(cu)
            for die in cu.iter_DIEs():
                if die.tag == "DW_TAG_structure_type":
                    name = _name(die)
                    if not name or name in seen_struct_names:
                        continue
                    fields, size, packed = _extract_struct_fields(die)
                    if size is None:
                        continue  # forward declaration only
                    decl_file, decl_line = _decl_location(die, cu_files)
                    structs.append(
                        {
                            "name": name,
                            "size_bytes": size,
                            "packed": packed,
                            "fields": fields,
                            "decl_file": decl_file,
                            "decl_line": decl_line,
                        }
                    )
                    seen_struct_names.add(name)

                elif die.tag == "DW_TAG_typedef":
                    name = _name(die)
                    if not name or name in seen_typedef_names:
                        continue
                    underlying = _resolve_type(die)
                    typedefs.append(
                        {
                            "name": name,
                            "underlying_type": underlying.get("name"),
                            "size_bytes": underlying.get("size_bytes"),
                        }
                    )
                    seen_typedef_names.add(name)
                    # If the typedef points to an anonymous struct, promote
                    # it as a struct under the typedef name. This is the
                    # canonical eCTF / kernel pattern:
                    #   typedef struct { ... } foo_t;
                    if underlying.get("kind") == "struct" and name not in seen_struct_names:
                        try:
                            target = die.get_DIE_from_attribute("DW_AT_type")
                            fields, size, packed = _extract_struct_fields(target)
                            if size is not None:
                                decl_file, decl_line = _decl_location(die, cu_files)
                                structs.append(
                                    {
                                        "name": name,
                                        "size_bytes": size,
                                        "packed": packed,
                                        "fields": fields,
                                        "decl_file": decl_file,
                                        "decl_line": decl_line,
                                        "via_typedef": True,
                                    }
                                )
                                seen_struct_names.add(name)
                        except Exception:
                            pass

                elif die.tag == "DW_TAG_variable":
                    # Globals only -- skip locals
                    if _attr(die, "DW_AT_external") is None:
                        # Many static globals omit DW_AT_external. Heuristic:
                        # if it has DW_AT_location with DW_OP_addr, treat as global.
                        addr = _decode_global_address(die)
                        if addr is None:
                            continue
                    else:
                        addr = _decode_global_address(die)
                        if addr is None:
                            continue
                    name = _name(die)
                    if not name or name in seen_global_names:
                        continue
                    g_type = _resolve_type(die)
                    decl_file, decl_line = _decl_location(die, cu_files)
                    globals_.append(
                        {
                            "name": name,
                            "address": addr,
                            "address_hex": f"0x{addr:x}",
                            "size_bytes": g_type.get("size_bytes"),
                            "type": g_type.get("name"),
                            "decl_file": decl_file,
                            "decl_line": decl_line,
                        }
                    )
                    seen_global_names.add(name)

                elif die.tag == "DW_TAG_subprogram":
                    name = _name(die)
                    if not name or name in seen_function_names:
                        continue
                    low = _attr(die, "DW_AT_low_pc")
                    high = _attr(die, "DW_AT_high_pc")
                    if low is None:
                        continue
                    # high_pc is either an offset from low_pc or an address
                    if isinstance(high, int):
                        size_bytes = high if high < low else (high - low)
                    else:
                        size_bytes = None
                    decl_file, decl_line = _decl_location(die, cu_files)
                    functions.append(
                        {
                            "name": name,
                            "address": low,
                            "address_hex": f"0x{low:x}",
                            "size_bytes": size_bytes,
                            "decl_file": decl_file,
                            "decl_line": decl_line,
                        }
                    )
                    seen_function_names.add(name)

    return {
        "elf": str(elf_path),
        "structs": structs,
        "typedefs": typedefs,
        "globals": globals_,
        "functions": functions,
        "summary": {
            "struct_count": len(structs),
            "typedef_count": len(typedefs),
            "global_count": len(globals_),
            "function_count": len(functions),
            "compilation_units": cu_count,
        },
    }


def _print_human(result: dict[str, Any], filter_prefix: str | None = None) -> None:
    if "error" in result:
        print(f"ERROR: {result['error']}")
        return
    s = result["summary"]
    print(f"elf: {result['elf']}")
    print(
        f"summary: {s['compilation_units']} CUs, {s['struct_count']} structs, "
        f"{s['typedef_count']} typedefs, {s['global_count']} globals, "
        f"{s['function_count']} functions"
    )

    print("\n=== STRUCTS ===")
    for st in result["structs"]:
        if filter_prefix and not st["name"].startswith(filter_prefix):
            continue
        packed = " (packed)" if st["packed"] else ""
        loc = f" [{st['decl_file']}:{st['decl_line']}]" if st["decl_file"] else ""
        print(f"  {st['name']} ({st['size_bytes']}B){packed}{loc}")
        for fd in st["fields"]:
            off = f"+{fd['offset']:>4d}" if fd["offset"] is not None else "  ?  "
            sz = f"{fd['size_bytes']}B" if fd["size_bytes"] else "?B"
            print(f"    {off}  {fd['name'] or '<unnamed>':<24} {fd['type']} ({sz})")

    print("\n=== KEY GLOBALS ===")
    for g in sorted(result["globals"], key=lambda x: x["address"])[:30]:
        if filter_prefix and not g["name"].startswith(filter_prefix):
            continue
        print(f"  {g['address_hex']:<10} {g['name']:<32} {g['type']} ({g['size_bytes']}B)")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("elf", type=Path, help="ELF with DWARF debug info")
    p.add_argument("--out", type=Path, help="write JSON to this path")
    p.add_argument("--json", action="store_true", help="emit JSON to stdout")
    p.add_argument("--filter-prefix", help="filter human-readable output by name prefix")
    args = p.parse_args(argv)

    if not args.elf.is_file():
        print(f"[-] not a file: {args.elf}", file=sys.stderr)
        return 1

    result = extract(args.elf)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2))
        print(
            f"wrote {args.out} ({result['summary']['struct_count']} structs, "
            f"{result['summary']['global_count']} globals, "
            f"{result['summary']['function_count']} functions)"
        )
    elif args.json:
        json.dump(result, sys.stdout, indent=2)
        print()
    else:
        _print_human(result, args.filter_prefix)

    return 0


if __name__ == "__main__":
    sys.exit(main())
