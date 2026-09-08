#!/usr/bin/env python3
"""auto_source_structs -- extract struct ABI facts from C source via tree-sitter.

Sister helper to `auto_dwarf_structs`. When the target ships source only
(no pre-built ELF), we can't read DWARF -- but we can parse the headers
with tree-sitter-c and recover struct layouts heuristically.

This is the source-only path Codex flagged: "tree-sitter-c for tolerant
indexing of functions, call sites, switches, macros." It does NOT
attempt full type resolution (that would require libclang + a real
preprocessor environment); it produces best-effort ABI facts using
common-typedef heuristics for `uintN_t`, `intN_t`, `char[N]`, etc.

Coverage versus DWARF:
- [+] Struct names, packed flag (via #pragma pack), field names
- [+] Field types (best-effort; uses common-typedef + sizeof tables)
- [+] Approximate field offsets (when all fields have known sizes)
- [x] Field offsets when types depend on `#define`s the parser hasn't
  resolved (e.g. `char name[MAX_NAME_SIZE]` where MAX_NAME_SIZE is in
  another header). Falls back to "size_unknown" annotations.
- [x] Globals + their addresses (DWARF only).
- [x] Function addresses (DWARF only).

The output schema matches `auto_dwarf_structs` so downstream helpers
can consume either source.

Usage:
    python3 auto_source_structs.py <source_file_or_dir> [--out PATH]
                                   [--filter-prefix PREFIX]
                                   [--define KEY=VAL ...]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import tree_sitter_c
from tree_sitter import Language, Parser

# Common eCTF / embedded typedef → byte-size table.
TYPE_SIZE = {
    "char": 1,
    "uint8_t": 1,
    "int8_t": 1,
    "_Bool": 1,
    "bool": 1,
    "uint16_t": 2,
    "int16_t": 2,
    "uint32_t": 4,
    "int32_t": 4,
    "uint64_t": 8,
    "int64_t": 8,
    "size_t": 4,  # 32-bit assumption (Cortex-M); override for 64-bit
    "ssize_t": 4,
    "uintptr_t": 4,
    "intptr_t": 4,
    "void *": 4,
    "void*": 4,
    "uint": 4,
    "int": 4,
    "short": 2,
    "long": 4,
    "long long": 8,
    "float": 4,
    "double": 8,
    "pkt_len_t": 2,  # eCTF convention from commands.h
    # eCTF-specific typedefs we've seen
    "slot_t": 1,
    "group_id_t": 2,
    "pin_t": 6,  # typedef unsigned char pin_t[6]
}


def _lang_parser() -> Parser:
    lang = Language(tree_sitter_c.language())
    return Parser(lang)


def _node_text(src: bytes, node) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _resolve_size(type_str: str, array_dim: str | None, defines: dict[str, int]) -> int | None:
    """Best-effort byte-size resolution for a type spec.

    type_str: e.g. "uint8_t", "char", "interhsm_request_auth_t"
    array_dim: e.g. "16", "MAX_NAME_SIZE", "CHALLENGE_LEN", or None
    """
    base_size = TYPE_SIZE.get(type_str.strip())
    if base_size is None:
        # Unknown user type -- defer
        return None
    if array_dim is None:
        return base_size
    # Try to resolve array_dim as int or via #defines
    array_dim = array_dim.strip()
    try:
        dim = int(array_dim, 0)
    except ValueError:
        if array_dim in defines:
            dim = defines[array_dim]
        else:
            # Try a simple expression evaluator over defines
            expr = array_dim
            for key, val in sorted(defines.items(), key=lambda x: -len(x[0])):
                expr = re.sub(rf"\b{key}\b", str(val), expr)
            if re.fullmatch(r"[\d\s+\-*/()]+", expr):
                try:
                    dim = int(eval(expr))  # noqa: S307
                except Exception:
                    return None
            else:
                return None
    return base_size * dim


def _extract_defines(content: str) -> dict[str, int]:
    """Pull simple integer #defines and #define foo (a + b) from a C source."""
    out: dict[str, int] = {}
    pat = re.compile(
        r"^\s*#define\s+(\w+)\s+(.+?)(?:\s*/\*.*)?(?://.*)?$",
        re.MULTILINE,
    )
    for _ in range(4):  # multi-pass to resolve forward refs
        for m in pat.finditer(content):
            name, expr = m.group(1), m.group(2).strip()
            if name in out:
                continue
            try:
                # Direct integer
                out[name] = int(expr, 0)
                continue
            except ValueError:
                pass
            # Substitute knowns and try eval
            substituted = expr
            for key, val in sorted(out.items(), key=lambda x: -len(x[0])):
                substituted = re.sub(rf"\b{key}\b", str(val), substituted)
            if re.fullmatch(r"[\d\s+\-*/()]+", substituted):
                try:
                    out[name] = int(eval(substituted))  # noqa: S307
                except Exception:
                    pass
    return out


def _extract_typedefs(src: bytes, root) -> dict[str, int]:
    """Extract simple `typedef X name[N]` and `typedef X name` from the AST.

    Returns a name → size map for typedefs whose size we can compute.
    """
    out: dict[str, int] = {}
    for node in _walk(root):
        if node.type != "type_definition":
            continue
        text = _node_text(src, node).strip()
        # typedef unsigned char pin_t[6];
        m = re.match(
            r"typedef\s+(?:(?:unsigned|signed)\s+)?(\w[\w\s]*)\s+(\w+)\s*\[\s*(\w+)\s*\]\s*;",
            text,
        )
        if m:
            base, name, dim = m.group(1).strip(), m.group(2), m.group(3)
            base_size = TYPE_SIZE.get(base)
            if base_size:
                try:
                    n = int(dim, 0)
                    out[name] = base_size * n
                    continue
                except ValueError:
                    pass
        # typedef X Y; (simple alias)
        m = re.match(r"typedef\s+(\w[\w\s]*)\s+(\w+)\s*;", text)
        if m:
            base, name = m.group(1).strip(), m.group(2)
            if base in TYPE_SIZE:
                out[name] = TYPE_SIZE[base]
    return out


def _walk(node):
    yield node
    for c in node.children:
        yield from _walk(c)


def _is_packed_pragma_active(src: bytes, struct_node) -> bool:
    """Heuristic: scan source backwards from struct for #pragma pack(push, 1)."""
    before = src[: struct_node.start_byte].decode("utf-8", errors="replace")
    pushes = list(re.finditer(r"#pragma\s+pack\s*\(\s*push\s*,\s*1\s*\)", before))
    pops = list(re.finditer(r"#pragma\s+pack\s*\(\s*pop\s*\)", before))
    return len(pushes) > len(pops)


def _parse_struct_node(
    src: bytes,
    struct_def_text: str,
    type_defs_text: str | None,
    defines: dict[str, int],
    typedefs: dict[str, int],
) -> tuple[str | None, list[dict], int | None, bool]:
    """Parse a `struct { ... } [name];` chunk and return (name, fields, size, ok).

    Falls back to regex parsing of the source body since tree-sitter-c
    doesn't expose member-by-member offsets without semantic resolution.
    """
    # Extract typedef name (typedef struct { ... } NAME;) or struct tag
    name = None
    if type_defs_text:
        m = re.search(r"\}\s*(\w+)\s*;", type_defs_text)
        if m:
            name = m.group(1)
    if name is None:
        m = re.search(r"struct\s+(\w+)\s*\{", struct_def_text)
        if m:
            name = m.group(1)

    # Extract body between { }
    body_match = re.search(r"\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}", struct_def_text)
    if not body_match:
        return (name, [], None, False)
    body = body_match.group(1)

    # Parse fields. Pattern: `<type> <name>[<dim>];` or `<type> <name>;`
    field_pat = re.compile(
        r"\b((?:(?:const|volatile|unsigned|signed|struct)\s+)*\w[\w\s\*]*?)\s+"
        r"(\w+)\s*(?:\[\s*([\w+\-*/()\s]+?)\s*\])?\s*;",
        re.MULTILINE,
    )
    fields = []
    offset = 0
    all_known = True

    # Strip nested-struct bodies + comments to keep field detection clean
    body_clean = re.sub(r"//.*$", "", body, flags=re.MULTILINE)
    body_clean = re.sub(r"/\*.*?\*/", "", body_clean, flags=re.DOTALL)

    for m in field_pat.finditer(body_clean):
        ftype = m.group(1).strip()
        fname = m.group(2)
        fdim = m.group(3)
        # Skip pre-existing struct/typedef declarations
        if fname in {
            "struct",
            "typedef",
            "const",
            "volatile",
            "extern",
            "static",
        }:
            continue
        # Resolve size -- first via known typedef table, then via TYPE_SIZE
        size = typedefs.get(ftype)
        if size is None:
            size = _resolve_size(ftype, fdim, defines)
        elif fdim is not None:
            try:
                dim_val = int(fdim, 0)
            except ValueError:
                dim_val = defines.get(fdim)
            if dim_val is not None:
                size = size * dim_val
            else:
                size = None
        elif fdim is None and size is not None and ftype in typedefs:
            # already a single-element typedef
            pass

        type_repr = ftype if not fdim else f"{ftype}[{fdim}]"
        fields.append(
            {
                "name": fname,
                "offset": offset if all_known else None,
                "size_bytes": size,
                "type": type_repr,
            }
        )
        if size is None:
            all_known = False
        else:
            offset += size

    total = offset if all_known else None
    return (name, fields, total, all_known)


def extract(
    paths: list[Path],
    extra_defines: dict[str, int] | None = None,
) -> dict[str, Any]:
    parser = _lang_parser()
    all_defines: dict[str, int] = dict(extra_defines or {})
    all_typedefs: dict[str, int] = dict(TYPE_SIZE)
    structs: list[dict] = []
    seen_struct_names: set[str] = set()

    # Ingest all source first so #defines and typedefs from any file
    # are visible before we resolve struct layouts.
    parsed_files = []
    for p in paths:
        if not p.is_file():
            continue
        try:
            content = p.read_text(errors="replace")
        except Exception:
            continue
        all_defines.update(_extract_defines(content))
        src = content.encode("utf-8", errors="replace")
        tree = parser.parse(src)
        all_typedefs.update(_extract_typedefs(src, tree.root_node))
        parsed_files.append((p, content, src, tree))

    # Now extract structs
    for p, content, src, tree in parsed_files:
        for node in _walk(tree.root_node):
            if node.type != "type_definition":
                continue
            text = _node_text(src, node)
            # Find inner struct_specifier
            inner = next(
                (c for c in node.children if c.type == "struct_specifier"),
                None,
            )
            if inner is None:
                continue
            struct_text = _node_text(src, inner)
            packed = _is_packed_pragma_active(src, inner)
            name, fields, size, ok = _parse_struct_node(
                src,
                struct_text,
                text,
                all_defines,
                all_typedefs,
            )
            if not name or name in seen_struct_names or not fields:
                continue
            structs.append(
                {
                    "name": name,
                    "size_bytes": size,
                    "size_known": ok,
                    "packed": packed,
                    "fields": fields,
                    "decl_file": str(p),
                    "via_typedef": True,
                }
            )
            seen_struct_names.add(name)
        # Also bare `struct foo { ... };` (no typedef)
        for node in _walk(tree.root_node):
            if node.type != "struct_specifier":
                continue
            # Skip the ones already handled inside type_definitions
            parent = node.parent
            if parent and parent.type == "type_definition":
                continue
            struct_text = _node_text(src, node)
            packed = _is_packed_pragma_active(src, node)
            name, fields, size, ok = _parse_struct_node(
                src,
                struct_text,
                None,
                all_defines,
                all_typedefs,
            )
            if not name or name in seen_struct_names or not fields:
                continue
            structs.append(
                {
                    "name": name,
                    "size_bytes": size,
                    "size_known": ok,
                    "packed": packed,
                    "fields": fields,
                    "decl_file": str(p),
                    "via_typedef": False,
                }
            )
            seen_struct_names.add(name)

    # Promote captured typedef sizes back into all_typedefs for any later
    # reader (e.g. a downstream consumer sizing a struct of structs)
    for st in structs:
        if st["size_known"] and st["size_bytes"] is not None:
            all_typedefs[st["name"]] = st["size_bytes"]

    return {
        "sources": [str(p) for p in paths],
        "structs": structs,
        "defines": all_defines,
        "typedefs": {k: v for k, v in all_typedefs.items() if k not in TYPE_SIZE},
        "summary": {
            "struct_count": len(structs),
            "struct_count_size_known": sum(1 for s in structs if s["size_known"]),
            "define_count": len(all_defines),
            "typedef_count": len(all_typedefs) - len(TYPE_SIZE),
        },
    }


def _print_human(result: dict[str, Any], filter_prefix: str | None) -> None:
    s = result["summary"]
    print(
        f"sources: {len(result['sources'])} files; "
        f"structs={s['struct_count']} "
        f"(size_known={s['struct_count_size_known']}); "
        f"defines={s['define_count']}; "
        f"typedefs={s['typedef_count']}"
    )
    print()
    for st in result["structs"]:
        if filter_prefix and not st["name"].startswith(filter_prefix):
            continue
        flags = ""
        if st["packed"]:
            flags += " packed"
        if not st["size_known"]:
            flags += " size_unknown"
        sz = st["size_bytes"] if st["size_bytes"] is not None else "?"
        print(f"  {st['name']} ({sz}B){flags}  [{st['decl_file']}]")
        for f in st["fields"]:
            off = f"+{f['offset']:>4d}" if f["offset"] is not None else "+   ?"
            sz = f"{f['size_bytes']}B" if f["size_bytes"] else "?B"
            print(f"    {off}  {f['name']:<24} {f['type']} ({sz})")


VENDOR_SKIP = {
    # Crypto libs
    "wolfssl",
    "openssl",
    "mbedtls",
    "libsodium",
    # MCU vendor SDKs
    "driverlib",
    "tivaware",
    "ti_drivers",
    "ti-cgt",
    "stm32cube",
    "stm32f",
    "stm32l",
    "stm32h",
    "cmsis",
    "nrf",
    "esp-idf",
    "freertos",
    # Build/cache/IDE
    "node_modules",
    ".git",
    "__pycache__",
    "target",
    "vendor",
    "build",
    ".venv",
    "venv",
    ".cache",
}


def _collect_sources(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    found = []
    for ext in ("*.h", "*.hpp", "*.c"):
        for p in target.rglob(ext):
            if any(part.lower() in VENDOR_SKIP for part in p.parts):
                continue
            found.append(p)
    return found


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument(
        "target",
        type=Path,
        help="C source file or directory tree",
    )
    p.add_argument("--out", type=Path)
    p.add_argument("--json", action="store_true")
    p.add_argument("--filter-prefix")
    p.add_argument(
        "--define",
        action="append",
        default=[],
        help="extra define KEY=VAL (e.g. MAX_NAME_SIZE=33)",
    )
    args = p.parse_args(argv)

    if not args.target.exists():
        print(f"[-] not found: {args.target}", file=sys.stderr)
        return 1

    sources = _collect_sources(args.target)
    if not sources:
        print(f"[-] no C sources under {args.target}", file=sys.stderr)
        return 1

    extra: dict[str, int] = {}
    for d in args.define:
        if "=" not in d:
            continue
        k, v = d.split("=", 1)
        try:
            extra[k] = int(v, 0)
        except ValueError:
            pass

    result = extract(sources, extra)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2))
        print(f"wrote {args.out} ({result['summary']['struct_count']} structs)")
    elif args.json:
        json.dump(result, sys.stdout, indent=2)
        print()
    else:
        _print_human(result, args.filter_prefix)

    return 0


if __name__ == "__main__":
    sys.exit(main())
