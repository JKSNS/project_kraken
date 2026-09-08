#!/usr/bin/env python3
"""auto_ingress_contracts -- extract transport-layer call contracts from C source.

This is Codex's keystone helper from the validation pass: the helper that
would actually have found DSU's `read_packet` length-check bypass. Per
Codex's review:

  The minimum useful extractor is "validation gates plus ingress
  contracts": every `read_packet`/`write_packet` call, length-variable
  initialization, destination object, capacity expression, and post-call
  dispatcher.

What this catches that handler-only validation extractors miss: the bug
where a length variable is initialised to zero before being passed to a
packet-receiver, and the receiver's `*len &&` short-circuit defeats the
size cap. The bug isn't in any handler; it's in the *contract* between
the dispatcher (`main()` in DSU's case) and the transport function
(`read_packet`).

Usage:
    python3 auto_ingress_contracts.py <source_dir> [--out PATH]
                                      [--transport-fn NAME ...]

Output schema:
{
  "sources": [...],
  "transport_callsites": [
    {
      "caller": "main",
      "callee": "read_packet",
      "callsite_file": "...",
      "callsite_line": 94,
      "args": [...],
      "length_var": "pkt_len",
      "length_var_init": "0",   # <-- the bug pattern
      "length_var_init_line": 93,
      "destination": "shared_buf.raw",
      "anomalies": ["length_var_initialized_zero"]
    }
  ],
  "dispatchers": [
    {
      "function": "main",
      "switch_var": "cmd",
      "cases": [
        {"label": "LIST_MSG", "handler_call": "list(...)", "line": 122}
      ]
    }
  ],
  "validation_gates": [
    {
      "function": "list",
      "kind": "size_eq",
      "expression": "pkt_len != sizeof(list_command_t)",
      "line": 340
    }
  ],
  "summary": {
    "callsite_count": N,
    "anomaly_count": N,
    "dispatcher_count": N,
    "validation_gate_count": N
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

import tree_sitter_c
from tree_sitter import Language, Parser

# Default transport / receive function names to look for. Extendable via CLI.
DEFAULT_TRANSPORT_FNS = {
    "read_packet",
    "write_packet",
    "read_bytes",
    "write_bytes",
    "recv",
    "recvfrom",
    "read_header",
    "read_ack",
    "read_msg",
    "uart_read",
    "uart_write",
    "fread",
    "fgets",
    "scanf",
    "gets",  # legacy / classic CTF target
}

VALIDATION_GATE_PATTERNS = [
    # `if (pkt_len != sizeof(...))`
    (
        re.compile(r"\b(\w*len\w*|len|size)\s*!=\s*sizeof\s*\("),
        "size_eq",
    ),
    # `if (pkt_len < ... || pkt_len > ...)`
    (
        re.compile(r"\b(\w*len\w*|len|size)\s*[<>]"),
        "size_range",
    ),
    # `if (... > MAX_...)`
    (
        re.compile(r">\s*MAX_\w+|<\s*MIN_\w+"),
        "max_min",
    ),
    # `if (slot >= MAX_FILE_COUNT)`
    (
        re.compile(r"\b(slot|index|idx)\s*[><=]+\s*\w*MAX\w*"),
        "bounds",
    ),
]


def _lang_parser() -> Parser:
    return Parser(Language(tree_sitter_c.language()))


def _node_text(src: bytes, node) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _walk(node):
    yield node
    for c in node.children:
        yield from _walk(c)


def _enclosing_function(node) -> tuple[str | None, Any]:
    """Walk up to the enclosing function_definition; return (name, node)."""
    cursor = node.parent
    while cursor is not None:
        if cursor.type == "function_definition":
            for c in cursor.children:
                if c.type == "function_declarator":
                    for cc in c.children:
                        if cc.type == "identifier":
                            return (cc.text.decode(), cursor)
                    # Sometimes wrapped in pointer_declarator
                    for cc in _walk(c):
                        if cc.type == "identifier":
                            return (cc.text.decode(), cursor)
            return (None, cursor)
        cursor = cursor.parent
    return (None, None)


def _line_of(src: bytes, node) -> int:
    return src[: node.start_byte].count(b"\n") + 1


def _find_call_args(node) -> list[Any]:
    """Return the argument_list children of a call_expression."""
    for c in node.children:
        if c.type == "argument_list":
            return [arg for arg in c.children if arg.type not in (",", "(", ")")]
    return []


def _find_callee_name(src: bytes, call_node) -> str | None:
    for c in call_node.children:
        if c.type == "identifier":
            return c.text.decode()
        if c.type == "field_expression":
            # Method-style: foo.bar() -- return the field name
            for cc in c.children:
                if cc.type == "field_identifier":
                    return cc.text.decode()
    return None


def _local_assignments(
    src: bytes,
    fn_node,
    var_name: str,
    before_line: int,
) -> list[tuple[int, str]]:
    """Find assignment statements `var_name = X;` in fn_node before
    `before_line`. Returns (line, rhs_text) tuples."""
    results = []
    for n in _walk(fn_node):
        if n.type != "assignment_expression":
            continue
        line = _line_of(src, n)
        if line >= before_line:
            continue
        # Children: lhs, '=', rhs
        if len(n.children) < 3:
            continue
        lhs = n.children[0]
        rhs = n.children[2]
        lhs_text = _node_text(src, lhs).strip()
        if lhs_text == var_name:
            results.append((line, _node_text(src, rhs).strip()))
    # Also check init_declarator -- `int pkt_len = 0;`
    for n in _walk(fn_node):
        if n.type != "init_declarator":
            continue
        line = _line_of(src, n)
        if line >= before_line:
            continue
        # Children: declarator, '=', value
        if len(n.children) < 3:
            continue
        decl = n.children[0]
        val = n.children[2]
        if _node_text(src, decl).strip() == var_name:
            results.append((line, _node_text(src, val).strip()))
    return sorted(results)


def _strip_addr(arg_text: str) -> str:
    """Strip `&` prefix to get the variable name."""
    s = arg_text.strip()
    if s.startswith("&"):
        s = s[1:].strip()
    return s


def _classify_callsite(
    src: bytes,
    fn_node,
    fn_name: str,
    call_node,
    callee: str,
) -> dict | None:
    """Build a callsite record for a transport-fn call, including length-var
    initialisation tracing and anomaly detection."""
    args = _find_call_args(call_node)
    arg_texts = [_node_text(src, a) for a in args]
    line = _line_of(src, call_node)

    record = {
        "caller": fn_name,
        "callee": callee,
        "callsite_line": line,
        "args": arg_texts,
        "anomalies": [],
    }

    # Heuristic: which arg is the length-output pointer?
    # For read_packet(uart, &cmd, buf, &len), it's typically the last
    # `&<name>` argument. For read_bytes(uart, buf, len), the size_t is
    # often a value (3rd arg). Per-callee specialisation:
    if callee in {"read_packet", "read_msg", "recv_msg"}:
        # Expect signature (id, *cmd, *buf, *len) -- last arg is len
        if len(arg_texts) >= 4:
            length_arg = arg_texts[-1]
            dest_arg = arg_texts[-2]
            length_var = _strip_addr(length_arg)
            record["length_var"] = length_var
            record["destination"] = dest_arg.strip()
            # Trace length_var's initialisation in the caller
            if fn_node is not None:
                inits = _local_assignments(src, fn_node, length_var, line)
                if inits:
                    init_line, init_val = inits[-1]
                    record["length_var_init"] = init_val
                    record["length_var_init_line"] = init_line
                    if init_val == "0" or init_val == "0u" or init_val.lower() == "0ull":
                        record["anomalies"].append(
                            "length_var_initialized_zero -- caller passes 0 to "
                            f"{callee}, defeating any *len-gated cap inside the callee"
                        )
                else:
                    record["length_var_init"] = "<not-found-in-caller>"

    elif callee in {"read_bytes", "fread", "uart_read"}:
        # (uart, buf, len) or (buf, size, count, fp) -- destination is 2nd
        if len(arg_texts) >= 2:
            record["destination"] = arg_texts[1].strip() if len(arg_texts) >= 2 else None
            record["length_or_count_arg"] = arg_texts[2] if len(arg_texts) >= 3 else None

    return record


def _extract_dispatcher(src: bytes, fn_node) -> dict | None:
    """Find the largest switch_statement in fn_node and emit a dispatcher map."""
    best: dict | None = None
    best_case_count = 0
    for n in _walk(fn_node):
        if n.type != "switch_statement":
            continue
        # Find the switched-on expression (first non-keyword child)
        switch_var = None
        for c in n.children:
            if c.type == "parenthesized_expression":
                switch_var = _node_text(src, c).strip()[1:-1].strip()
                break
        # Find case_statement nodes inside the body
        cases = []
        for inner in _walk(n):
            if inner.type != "case_statement":
                continue
            label = None
            handler_call = None
            for c in inner.children:
                if c.type in ("identifier", "number_literal", "char_literal"):
                    label = _node_text(src, c)
                    break
            # Find the first call_expression in the case body
            for inner2 in _walk(inner):
                if inner2.type == "call_expression":
                    handler_call = _node_text(src, inner2).strip()
                    break
            if label:
                cases.append(
                    {
                        "label": label,
                        "handler_call": handler_call,
                        "line": _line_of(src, inner),
                    }
                )
        if len(cases) > best_case_count:
            best_case_count = len(cases)
            best = {"switch_var": switch_var, "cases": cases}
    return best


def _extract_validation_gates(src: bytes, fn_node, fn_name: str) -> list[dict]:
    """Find `if (...)` patterns matching VALIDATION_GATE_PATTERNS in fn_node."""
    out = []
    for n in _walk(fn_node):
        if n.type != "if_statement":
            continue
        cond = None
        for c in n.children:
            if c.type == "parenthesized_expression":
                cond = _node_text(src, c).strip()[1:-1].strip()
                break
        if not cond:
            continue
        for pat, kind in VALIDATION_GATE_PATTERNS:
            if pat.search(cond):
                out.append(
                    {
                        "function": fn_name,
                        "kind": kind,
                        "expression": cond[:120],
                        "line": _line_of(src, n),
                    }
                )
                break  # one classification per gate
    return out


def extract(
    paths: list[Path],
    transport_fns: set[str] | None = None,
) -> dict[str, Any]:
    parser = _lang_parser()
    transport_fns = transport_fns or DEFAULT_TRANSPORT_FNS

    callsites: list[dict] = []
    dispatchers: list[dict] = []
    gates: list[dict] = []

    for p in paths:
        try:
            content = p.read_text(errors="replace")
        except Exception:
            continue
        src = content.encode("utf-8", errors="replace")
        tree = parser.parse(src)

        # All call_expression nodes
        for node in _walk(tree.root_node):
            if node.type != "call_expression":
                continue
            callee = _find_callee_name(src, node)
            if callee not in transport_fns:
                continue
            fn_name, fn_node = _enclosing_function(node)
            cs = _classify_callsite(
                src,
                fn_node,
                fn_name or "<top-level>",
                node,
                callee,
            )
            if cs is not None:
                cs["callsite_file"] = str(p)
                callsites.append(cs)

        # Dispatcher: largest switch in main() (if any)
        for node in _walk(tree.root_node):
            if node.type != "function_definition":
                continue
            fn_name = None
            for c in node.children:
                if c.type == "function_declarator":
                    for cc in _walk(c):
                        if cc.type == "identifier":
                            fn_name = cc.text.decode()
                            break
                    break
            if fn_name is None:
                continue
            d = _extract_dispatcher(src, node)
            if d and d.get("cases"):
                d["function"] = fn_name
                d["file"] = str(p)
                dispatchers.append(d)

            # Validation gates per function
            gs = _extract_validation_gates(src, node, fn_name)
            for g in gs:
                g["file"] = str(p)
            gates.extend(gs)

    return {
        "sources": [str(p) for p in paths],
        "transport_callsites": callsites,
        "dispatchers": dispatchers,
        "validation_gates": gates,
        "summary": {
            "callsite_count": len(callsites),
            "anomaly_count": sum(1 for c in callsites if c.get("anomalies")),
            "dispatcher_count": len(dispatchers),
            "validation_gate_count": len(gates),
        },
    }


def _print_human(result: dict[str, Any]) -> None:
    s = result["summary"]
    print(
        f"sources: {len(result['sources'])} files; "
        f"callsites={s['callsite_count']} (anomalies={s['anomaly_count']}); "
        f"dispatchers={s['dispatcher_count']}; "
        f"validation_gates={s['validation_gate_count']}"
    )
    print()
    print("=== TRANSPORT CALLSITES ===")
    for c in result["transport_callsites"]:
        line_loc = f"{Path(c['callsite_file']).name}:{c['callsite_line']}"
        print(f"  [{c['caller']}] -> {c['callee']}({len(c['args'])} args)  {line_loc}")
        if "length_var" in c:
            init = c.get("length_var_init", "?")
            print(f"     length_var={c['length_var']!r}  init={init!r}  dest={c.get('destination', '?')!r}")
        for anom in c.get("anomalies", []):
            print(f"     [!] ANOMALY: {anom}")
    print()
    print("=== DISPATCHERS ===")
    for d in result["dispatchers"]:
        print(
            f"  {d['function']}  (switch on {d.get('switch_var', '?')}, "
            f"{len(d['cases'])} cases)  [{Path(d['file']).name}]"
        )
        for case in d["cases"]:
            handler = case.get("handler_call") or "<no-call>"
            print(f"     case {case['label']}: {handler}  L{case['line']}")
    print()
    print("=== VALIDATION GATES (sampled) ===")
    for g in result["validation_gates"][:30]:
        print(f"  [{g['function']}] {g['kind']}: {g['expression'][:80]}  L{g['line']}")


VENDOR_SKIP = {
    # Crypto libs
    "wolfssl",
    "openssl",
    "mbedtls",
    "libsodium",
    # MCU vendor SDKs (eCTF teams pull these in via Docker)
    "driverlib",  # TI Tiva
    "tivaware",  # TI Tiva legacy
    "ti_drivers",  # TI generic
    "ti-cgt",  # TI compiler (incl. via /opt/...)
    "stm32cube",  # ST
    "stm32f",
    "stm32l",
    "stm32h",
    "cmsis",
    "nrf",  # Nordic
    "esp-idf",
    "freertos",
    # Build/cache/IDE artefacts
    "node_modules",
    ".git",
    "__pycache__",
    "target",  # Cargo
    "vendor",  # Go / Cargo
    "build",  # CMake / Cargo
    ".venv",
    "venv",
    ".cache",
}


def _collect_sources(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    found = []
    for ext in ("*.c", "*.h"):
        for p in target.rglob(ext):
            if any(part.lower() in VENDOR_SKIP for part in p.parts):
                continue
            found.append(p)
    return found


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("target", type=Path, help="C source file or directory")
    p.add_argument("--out", type=Path)
    p.add_argument("--json", action="store_true")
    p.add_argument(
        "--transport-fn",
        action="append",
        default=[],
        help="extra transport function names (can repeat)",
    )
    args = p.parse_args(argv)

    if not args.target.exists():
        print(f"[-] not found: {args.target}", file=sys.stderr)
        return 1

    sources = _collect_sources(args.target)
    if not sources:
        print(f"[-] no C sources under {args.target}", file=sys.stderr)
        return 1

    transport_fns = set(DEFAULT_TRANSPORT_FNS) | set(args.transport_fn)
    result = extract(sources, transport_fns)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2))
        print(
            f"wrote {args.out} ({result['summary']['callsite_count']} callsites, "
            f"{result['summary']['anomaly_count']} anomalies)"
        )
    elif args.json:
        json.dump(result, sys.stdout, indent=2)
        print()
    else:
        _print_human(result)

    return 0


if __name__ == "__main__":
    sys.exit(main())
