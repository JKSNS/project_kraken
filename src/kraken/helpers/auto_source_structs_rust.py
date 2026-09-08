#!/usr/bin/env python3
"""auto_source_structs_rust -- extract Rust struct/repr ABI facts via tree-sitter.

Sister helper to `auto_source_structs` (C). Parses Rust source via
tree-sitter-rust and extracts struct definitions with #[repr(C, packed)]
or #[repr(C)] layouts -- the patterns Rust eCTF teams use to talk to
peripheral hardware and to maintain wire-protocol compat.

Findings from validation against 2026 designs:
- Purdue-2026 uses bytemuck::{Pod, Zeroable} + #[repr(C, packed)]
- UIUC-2026 uses wincode::{SchemaRead, SchemaWrite} (serde-style)

Both wire formats are schema-defined and tractable to parse.

Usage:
    python3 auto_source_structs_rust.py <source_file_or_dir> [--out PATH]
                                        [--filter-prefix PREFIX]

Output schema mirrors `auto_source_structs` (C version) so downstream
helpers consume either source.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import tree_sitter_rust
from tree_sitter import Language, Parser

TYPE_SIZE = {
    "u8": 1,
    "i8": 1,
    "bool": 1,
    "u16": 2,
    "i16": 2,
    "u32": 4,
    "i32": 4,
    "f32": 4,
    "char": 4,
    "u64": 8,
    "i64": 8,
    "f64": 8,
    "u128": 16,
    "i128": 16,
    "usize": 4,  # 32-bit assumption (Cortex-M)
    "isize": 4,
    "()": 0,
}


def _lang_parser() -> Parser:
    return Parser(Language(tree_sitter_rust.language()))


def _node_text(src: bytes, node) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _walk(node):
    yield node
    for c in node.children:
        yield from _walk(c)


def _resolve_type(type_str: str, typedefs: dict[str, int]) -> int | None:
    """Compute byte-size for a Rust type string."""
    type_str = type_str.strip()
    # [T; N]
    m = re.match(r"\[\s*(\w+)\s*;\s*(\w+)\s*\]", type_str)
    if m:
        elem, n = m.group(1), m.group(2)
        elem_size = TYPE_SIZE.get(elem) or typedefs.get(elem)
        if elem_size is None:
            return None
        try:
            return elem_size * int(n, 0)
        except ValueError:
            # If N is a const name, we can't resolve here
            return None
    # Plain primitive
    if type_str in TYPE_SIZE:
        return TYPE_SIZE[type_str]
    # User typedef
    return typedefs.get(type_str)


def _has_repr_attr(src: bytes, struct_node, want_packed: bool = False) -> tuple[bool, bool]:
    """Walk back from struct to find #[repr(...)]. Returns (is_repr_c, is_packed)."""
    # Look at preceding siblings within the parent
    parent = struct_node.parent
    if not parent:
        return (False, False)
    # Scan all attribute_item nodes immediately before struct in source
    is_c = False
    is_packed = False
    cursor = struct_node.prev_named_sibling
    while cursor is not None:
        if cursor.type != "attribute_item":
            break
        text = _node_text(src, cursor)
        if "repr" in text:
            if "C" in text:
                is_c = True
            if "packed" in text:
                is_packed = True
        cursor = cursor.prev_named_sibling
    return (is_c, is_packed)


def _extract_const_defs(src: bytes, root) -> dict[str, int]:
    """Pull `const X: usize = N;` and `const X: u32 = N;` integer constants."""
    out = {}
    for node in _walk(root):
        if node.type != "const_item":
            continue
        text = _node_text(src, node)
        m = re.match(
            r"const\s+(\w+)\s*:\s*\w+\s*=\s*(\d+|0x[0-9a-fA-F]+);",
            text.strip(),
        )
        if m:
            try:
                out[m.group(1)] = int(m.group(2), 0)
            except ValueError:
                pass
    return out


def _extract_type_aliases(src: bytes, root) -> dict[str, str]:
    """Pull `type Foo = Bar;` aliases."""
    out = {}
    for node in _walk(root):
        if node.type != "type_item":
            continue
        text = _node_text(src, node)
        m = re.match(r"(?:pub\s+)?type\s+(\w+)\s*=\s*([^;]+);", text)
        if m:
            out[m.group(1)] = m.group(2).strip()
    return out


def _parse_struct(
    src: bytes,
    struct_node,
    defines: dict[str, int],
    typedefs: dict[str, int],
) -> dict[str, Any] | None:
    """Parse a struct_item or tuple-struct node."""
    text = _node_text(src, struct_node)
    name_match = re.match(r"(?:pub\s+)?struct\s+(\w+)", text)
    if not name_match:
        return None
    name = name_match.group(1)

    is_c, is_packed = _has_repr_attr(src, struct_node)

    # Tuple struct: pub struct Foo(pub [u8; 6]);
    tup_m = re.match(
        r"(?:pub\s+)?struct\s+\w+\s*\(\s*(?:pub\s+)?(\[\s*\w+\s*;\s*\w+\s*\]|\w+)\s*\)\s*;",
        text,
    )
    if tup_m:
        type_str = tup_m.group(1)
        # Resolve `[u8; N]` where N might be a const
        m = re.match(r"\[\s*(\w+)\s*;\s*(\w+)\s*\]", type_str)
        size = None
        if m:
            elem, n = m.group(1), m.group(2)
            elem_size = TYPE_SIZE.get(elem)
            if elem_size:
                try:
                    n_val = int(n, 0)
                    size = elem_size * n_val
                except ValueError:
                    if n in defines:
                        size = elem_size * defines[n]
        else:
            size = TYPE_SIZE.get(type_str) or typedefs.get(type_str)
        return {
            "name": name,
            "size_bytes": size,
            "size_known": size is not None,
            "packed": is_packed,
            "repr_c": is_c,
            "kind": "tuple",
            "fields": [
                {"name": "_0", "type": type_str, "offset": 0, "size_bytes": size},
            ],
        }

    # Named-field struct
    body_m = re.search(r"\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}", text, re.DOTALL)
    if not body_m:
        return None
    body = body_m.group(1)
    # Strip comments
    body = re.sub(r"//.*$", "", body, flags=re.MULTILINE)
    body = re.sub(r"/\*.*?\*/", "", body, flags=re.DOTALL)

    fields = []
    offset = 0
    all_known = True
    field_pat = re.compile(
        r"(?:pub\s+)?(?:pub\s*\([^)]+\)\s+)?(\w+)\s*:\s*([^,\n]+?)\s*(?:,|$)",
        re.MULTILINE,
    )
    for m in field_pat.finditer(body):
        f_name = m.group(1)
        f_type = m.group(2).strip()
        if f_name in {"struct", "type", "const", "fn", "impl"}:
            continue
        f_size = _resolve_type(f_type, typedefs)
        fields.append(
            {
                "name": f_name,
                "type": f_type,
                "offset": offset if all_known else None,
                "size_bytes": f_size,
            }
        )
        if f_size is None:
            all_known = False
        else:
            offset += f_size

    return {
        "name": name,
        "size_bytes": offset if all_known else None,
        "size_known": all_known,
        "packed": is_packed,
        "repr_c": is_c,
        "kind": "named",
        "fields": fields,
    }


def extract(paths: list[Path]) -> dict[str, Any]:
    parser = _lang_parser()
    structs: list[dict] = []
    seen = set()
    all_defines: dict[str, int] = {}
    all_typedefs: dict[str, int] = dict(TYPE_SIZE)

    parsed = []
    for p in paths:
        try:
            content = p.read_text(errors="replace")
        except Exception:
            continue
        src = content.encode("utf-8", errors="replace")
        tree = parser.parse(src)
        all_defines.update(_extract_const_defs(src, tree.root_node))
        # Capture type aliases (don't try to resolve transitively for v1)
        parsed.append((p, src, tree))

    for p, src, tree in parsed:
        for node in _walk(tree.root_node):
            if node.type != "struct_item":
                continue
            st = _parse_struct(src, node, all_defines, all_typedefs)
            if not st or st["name"] in seen:
                continue
            st["decl_file"] = str(p)
            structs.append(st)
            seen.add(st["name"])
            if st["size_known"]:
                all_typedefs[st["name"]] = st["size_bytes"]

    return {
        "sources": [str(p) for p in paths],
        "language": "rust",
        "structs": structs,
        "defines": all_defines,
        "summary": {
            "struct_count": len(structs),
            "struct_count_size_known": sum(1 for s in structs if s["size_known"]),
            "struct_count_repr_c": sum(1 for s in structs if s["repr_c"]),
            "struct_count_packed": sum(1 for s in structs if s["packed"]),
            "define_count": len(all_defines),
        },
    }


def _print_human(result: dict[str, Any], filter_prefix: str | None) -> None:
    s = result["summary"]
    print(
        f"sources: {len(result['sources'])} files; "
        f"structs={s['struct_count']} (size_known={s['struct_count_size_known']}, "
        f"repr_c={s['struct_count_repr_c']}, packed={s['struct_count_packed']}); "
        f"const-defs={s['define_count']}"
    )
    print()
    for st in result["structs"]:
        if filter_prefix and not st["name"].startswith(filter_prefix):
            continue
        flags = ""
        if st["packed"]:
            flags += " packed"
        if st["repr_c"]:
            flags += " repr_c"
        if not st["size_known"]:
            flags += " size_unknown"
        sz = st["size_bytes"] if st["size_bytes"] is not None else "?"
        print(f"  {st['name']} ({sz}B){flags}  [{st['decl_file']}]")
        for f in st["fields"]:
            off = f"+{f['offset']:>4d}" if f["offset"] is not None else "+   ?"
            sz = f"{f['size_bytes']}B" if f["size_bytes"] else "?B"
            print(f"    {off}  {f['name']:<24} {f['type']} ({sz})")


def _collect_sources(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    found = []
    for p in target.rglob("*.rs"):
        if any(part in {".git", "target", "vendor", "ascon-c"} for part in p.parts):
            continue
        found.append(p)
    return found


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("target", type=Path)
    p.add_argument("--out", type=Path)
    p.add_argument("--json", action="store_true")
    p.add_argument("--filter-prefix")
    args = p.parse_args(argv)

    if not args.target.exists():
        print(f"[-] not found: {args.target}", file=sys.stderr)
        return 1
    sources = _collect_sources(args.target)
    if not sources:
        print(f"[-] no Rust sources under {args.target}", file=sys.stderr)
        return 1

    result = extract(sources)

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
