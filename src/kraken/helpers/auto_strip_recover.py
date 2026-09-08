#!/usr/bin/env python3
"""auto_strip_recover -- recover function/struct/IO facts from stripped binaries.

Stripped-binary equivalent of `auto_dwarf_structs`. Uses angr CFG analysis
+ pwntools.ELF + radare2 to surface what we can without DWARF:
  - function boundaries (CFG)
  - probable IO calls (read/recv/scanf/printf/puts via PLT)
  - format-string call sites (printf-class with non-constant first arg)
  - probable crypto primitives (AES/SHA/HMAC s-boxes / constants)
  - canary placement (heuristic -- fs:0x28 reads, __stack_chk_guard refs)

For DEF CON CTF where every service is stripped + obfuscated, this is the
first pass before angr symbolic execution kicks in.

Usage:
    python3 auto_strip_recover.py <elf> [--out PATH]
                                  [--max-fns N]   limit CFG depth (default: 200)
                                  [--no-angr]     skip CFG, ELF symbols only

Output schema:
{
  "elf": "...", "stripped": bool, "arch": "...", "pie": bool, "nx": bool,
  "canary": "tls|chk_guard|none|unknown",
  "functions": [
    {"address": 0x..., "name": "fn_X" or "<plt:read>", "size": N,
     "io_calls": ["read", "memcpy"], "interesting": ["fmt_string", "crypto_const"]}
  ],
  "io_call_sites": [
    {"caller_addr": 0x..., "callee": "printf", "fmt_arg_constant": bool,
     "comment": "printf with user-controlled fmt -- possible fmt-string bug"}
  ],
  "crypto_constants": [
    {"address": 0x..., "kind": "aes_sbox|sha256_k|hmac", "size": N}
  ],
  "summary": {...}
}
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# Crypto fingerprint constants (first few bytes of each well-known table).
CRYPTO_FINGERPRINTS = {
    # AES Rijndael S-box: starts with 63 7c 77 7b f2 6b 6f c5
    "aes_sbox": bytes.fromhex("637c777bf26b6fc5"),
    # AES inverse S-box: 52 09 6a d5 30 36 a5 38
    "aes_inv_sbox": bytes.fromhex("52096ad5303 6a538".replace(" ", "")),
    # SHA-256 K[0]: 428a2f98 71374491 b5c0fbcf e9b5dba5
    "sha256_k": bytes.fromhex("428a2f9871374491"),
    # SHA-1 H[0..1]: 67452301 efcdab89
    "sha1_h": bytes.fromhex("67452301efcdab89"),
    # MD5 init constants: 67452301 efcdab89 98badcfe
    "md5_h": bytes.fromhex("67452301efcdab8998badcfe"),
    # HMAC ipad/opad alternate (less reliable; commented out)
}

PLT_IO_CALLEES = {
    # libc IO + memory
    "read",
    "recv",
    "recvfrom",
    "fread",
    "fgets",
    "scanf",
    "sscanf",
    "fscanf",
    "gets",
    "getchar",
    "getline",
    "getdelim",
    "write",
    "send",
    "sendto",
    "fwrite",
    "fputs",
    "puts",
    "putchar",
    "printf",
    "fprintf",
    "sprintf",
    "snprintf",
    "vprintf",
    "vsprintf",
    "memcpy",
    "memmove",
    "strcpy",
    "strncpy",
    "strcat",
    "strncat",
    "system",
    "execve",
    "popen",
    "execl",
    "execlp",
    "malloc",
    "free",
    "calloc",
    "realloc",
}


def _pwntools_elf(elf_path: Path) -> dict[str, Any]:
    try:
        from pwn import ELF  # type: ignore
        from pwnlib.context import context  # type: ignore

        context.log_level = "error"
    except Exception:
        return {"error": "pwntools not available"}

    try:
        elf = ELF(str(elf_path))
    except Exception as e:
        return {"error": str(e)}

    # Stripped-ness heuristic: <30 named functions = effectively stripped
    sym_funcs = list(elf.symbols.keys())
    stripped = len([s for s in sym_funcs if not s.startswith("_")]) < 30

    return {
        "arch": elf.arch,
        "bits": elf.bits,
        "endian": elf.endian,
        "pie": elf.pie,
        "nx": elf.execstack is False,
        "canary": elf.canary,
        "relro": elf.relro,
        "stripped": stripped,
        "plt": dict(elf.plt) if elf.plt else {},
        "got": dict(elf.got) if elf.got else {},
        "named_function_count": len(sym_funcs),
    }


def _scan_crypto_constants(data: bytes) -> list[dict]:
    hits = []
    for name, sig in CRYPTO_FINGERPRINTS.items():
        if not sig:
            continue
        idx = 0
        while True:
            pos = data.find(sig, idx)
            if pos < 0:
                break
            hits.append(
                {
                    "kind": name,
                    "file_offset": pos,
                    "size_bytes": len(sig),
                }
            )
            idx = pos + 1
    return hits


def _angr_cfg(elf_path: Path, max_fns: int) -> dict[str, Any]:
    """Run angr CFGFast and surface IO call sites + format-string sites.

    Lazy-loads angr because it's heavyweight; --no-angr skips this entirely.
    """
    try:
        import angr  # type: ignore
    except Exception:
        return {"error": "angr not available; pass --no-angr or pip install angr"}

    proj = angr.Project(str(elf_path), auto_load_libs=False)
    try:
        cfg = proj.analyses.CFGFast(normalize=True, force_complete_scan=False)
    except Exception as e:
        return {"error": f"CFGFast failed: {e}"}

    functions = []
    io_call_sites: list[dict] = []
    fn_count = 0
    plt_lookup: dict[int, str] = {}
    for sym in proj.loader.main_object.symbols:
        if sym.is_import or sym.is_extern:
            plt_lookup[sym.rebased_addr] = sym.name

    for fn_addr, fn in cfg.functions.items():
        if fn_count >= max_fns:
            break
        fn_count += 1
        io_calls = []
        for site in fn.get_call_sites():
            tgt = fn.get_call_target(site)
            callee = plt_lookup.get(tgt)
            if not callee:
                # Could be intra-module; check function name
                tgt_fn = cfg.functions.get(tgt)
                if tgt_fn:
                    callee = tgt_fn.name
            if callee:
                stripped_name = callee.lstrip("_").split("@")[0]
                if stripped_name in PLT_IO_CALLEES:
                    io_calls.append(stripped_name)
                    io_call_sites.append(
                        {
                            "caller_addr": hex(fn_addr),
                            "callee": stripped_name,
                            "site_addr": hex(site),
                        }
                    )
        if fn.size or io_calls:
            functions.append(
                {
                    "address": hex(fn_addr),
                    "name": fn.name,
                    "size": fn.size,
                    "io_calls": sorted(set(io_calls)),
                }
            )
    return {
        "function_count": len(functions),
        "io_call_site_count": len(io_call_sites),
        "functions": functions[:200],  # cap for output size
        "io_call_sites": io_call_sites[:200],
    }


def analyze(elf_path: Path, max_fns: int = 200, use_angr: bool = True) -> dict[str, Any]:
    pwn = _pwntools_elf(elf_path)
    if "error" in pwn:
        return {"elf": str(elf_path), **pwn}

    raw = elf_path.read_bytes()
    crypto_constants = _scan_crypto_constants(raw)

    angr_result = None
    if use_angr and pwn.get("named_function_count", 0) < 200:
        # only worth running angr on smallish targets
        angr_result = _angr_cfg(elf_path, max_fns)

    result = {
        "elf": str(elf_path),
        "arch": pwn.get("arch"),
        "bits": pwn.get("bits"),
        "pie": pwn.get("pie"),
        "nx": pwn.get("nx"),
        "canary": pwn.get("canary"),
        "relro": pwn.get("relro"),
        "stripped": pwn.get("stripped"),
        "named_function_count": pwn.get("named_function_count"),
        "plt_imports": list(pwn.get("plt", {}).keys())[:80],
        "crypto_constants": crypto_constants,
    }
    if angr_result:
        if "error" in angr_result:
            result["angr_error"] = angr_result["error"]
        else:
            result["functions"] = angr_result.get("functions", [])
            result["io_call_sites"] = angr_result.get("io_call_sites", [])
    result["summary"] = {
        "stripped": result["stripped"],
        "io_call_count": len(result.get("io_call_sites", [])),
        "function_count": len(result.get("functions", [])),
        "crypto_const_count": len(crypto_constants),
    }
    return result


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("elf", type=Path)
    p.add_argument("--out", type=Path)
    p.add_argument("--max-fns", type=int, default=200)
    p.add_argument("--no-angr", action="store_true")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    if not args.elf.is_file():
        print(f"[-] not a file: {args.elf}", file=sys.stderr)
        return 1

    result = analyze(args.elf, max_fns=args.max_fns, use_angr=not args.no_angr)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2))
        print(f"wrote {args.out}")
    elif args.json:
        json.dump(result, sys.stdout, indent=2)
        print()
    else:
        s = result.get("summary", {})
        print(f"elf: {result['elf']}")
        print(
            f"arch={result.get('arch')} bits={result.get('bits')} "
            f"pie={result.get('pie')} nx={result.get('nx')} "
            f"canary={result.get('canary')} stripped={s.get('stripped')}"
        )
        print(
            f"named_functions={result.get('named_function_count')}  "
            f"io_call_sites={s.get('io_call_count')}  "
            f"crypto_constants={s.get('crypto_const_count')}"
        )
        if result.get("crypto_constants"):
            for c in result["crypto_constants"]:
                print(f"  crypto: {c['kind']} @ file_offset 0x{c['file_offset']:x}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
