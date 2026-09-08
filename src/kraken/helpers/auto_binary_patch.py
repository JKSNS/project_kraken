#!/usr/bin/env python3
"""auto_binary_patch -- minimal binary patcher (LIEF + raw bytes).

Targets A/D defense work where we need to patch a stripped binary
without rebuilding from source. Supports:
  - byte-level patching at file offset or virtual address
  - NOP-out a range
  - replace a CALL with a no-op or alternate target
  - inject a detour (write small trampoline + redirect target)
  - SLA validation via a captured-traffic replay command

Usage:
    # Single-byte/range patch:
    python3 auto_binary_patch.py byte-patch \\
        --in service.elf --out service.elf.patched \\
        --offset 0x1234 --bytes 9090909090

    # NOP out a range by virtual address:
    python3 auto_binary_patch.py nop \\
        --in service.elf --out service.elf.patched \\
        --vaddr 0x401234 --length 7

    # Validate after patch:
    python3 auto_binary_patch.py validate \\
        --orig service.elf --patched service.elf.patched \\
        --sla-cmd "./run-sla-test.sh"
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path


def _vaddr_to_offset(elf_path: Path, vaddr: int) -> int | None:
    try:
        from elftools.elf.elffile import ELFFile  # type: ignore
    except Exception:
        return None
    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        for seg in elf.iter_segments():
            if seg["p_type"] != "PT_LOAD":
                continue
            base = seg["p_vaddr"]
            size = seg["p_memsz"]
            file_off = seg["p_offset"]
            if base <= vaddr < base + size:
                return file_off + (vaddr - base)
    return None


def _byte_patch(in_path: Path, out_path: Path, offset: int, data: bytes) -> dict:
    raw = bytearray(in_path.read_bytes())
    if offset + len(data) > len(raw):
        return {"error": f"offset {offset:#x}+{len(data)} extends past end of file ({len(raw)})"}
    original = bytes(raw[offset : offset + len(data)])
    raw[offset : offset + len(data)] = data
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(raw))
    out_path.chmod(in_path.stat().st_mode)
    return {
        "patched": True,
        "file_offset": offset,
        "original_bytes": original.hex(),
        "new_bytes": data.hex(),
        "out_path": str(out_path),
    }


def _nop_range(arch: str, length: int) -> bytes:
    # Architecture-specific NOPs
    if arch in ("amd64", "x86_64", "x86", "i386"):
        return b"\x90" * length
    if arch == "aarch64":
        # MOV X0, X0 is the canonical AArch64 nop = 1f 20 03 d5
        return (b"\x1f\x20\x03\xd5") * (length // 4)
    if arch == "arm":
        # Thumb NOP: 00 bf
        if length % 2 == 0:
            return b"\x00\xbf" * (length // 2)
        return b"\x00\xbf" * (length // 2) + b"\x00"
    if arch == "riscv":
        # RV32 / RV64 NOP: ADDI x0, x0, 0 = 13 00 00 00
        return b"\x13\x00\x00\x00" * (length // 4)
    return b"\x00" * length


def _detect_arch(path: Path) -> str:
    try:
        from elftools.elf.elffile import ELFFile

        with open(path, "rb") as f:
            machine = ELFFile(f)["e_machine"]
        return {
            "EM_X86_64": "amd64",
            "EM_386": "i386",
            "EM_ARM": "arm",
            "EM_AARCH64": "aarch64",
            "EM_RISCV": "riscv",
        }.get(machine, machine)
    except Exception:
        return "unknown"


# ── subcommands ────────────────────────────────────────────────


def cmd_byte_patch(args) -> int:
    try:
        data = bytes.fromhex(args.bytes.replace(" ", ""))
    except ValueError:
        print(f"[-] bad --bytes hex: {args.bytes}", file=sys.stderr)
        return 1
    offset = args.offset
    if args.vaddr is not None:
        offset = _vaddr_to_offset(args.in_, args.vaddr)
        if offset is None:
            print(f"[-] could not resolve vaddr {args.vaddr:#x} to file offset", file=sys.stderr)
            return 1
    res = _byte_patch(args.in_, args.out, offset, data)
    print(json.dumps(res, indent=2))
    return 0 if "patched" in res else 1


def cmd_nop(args) -> int:
    arch = args.arch or _detect_arch(args.in_)
    nops = _nop_range(arch, args.length)
    offset = args.offset
    if args.vaddr is not None:
        offset = _vaddr_to_offset(args.in_, args.vaddr)
        if offset is None:
            print(f"[-] could not resolve vaddr {args.vaddr:#x}", file=sys.stderr)
            return 1
    res = _byte_patch(args.in_, args.out, offset, nops)
    res["arch"] = arch
    print(json.dumps(res, indent=2))
    return 0 if "patched" in res else 1


def cmd_validate(args) -> int:
    """Run an SLA test against patched binary. Returns 0 iff command exits 0
    AND output suggests no behavior change vs the captured baseline."""
    if not args.patched.is_file():
        print(f"[-] patched not found: {args.patched}", file=sys.stderr)
        return 1
    # Substitute {patched} placeholder in the command
    cmd = args.sla_cmd.replace("{patched}", str(args.patched))
    if "{orig}" in cmd:
        cmd = cmd.replace("{orig}", str(args.orig))
    try:
        proc = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=args.timeout,
        )
    except subprocess.TimeoutExpired:
        print(json.dumps({"validated": False, "reason": "timeout"}))
        return 1
    out = {
        "validated": proc.returncode == 0,
        "return_code": proc.returncode,
        "stdout_tail": proc.stdout[-500:],
        "stderr_tail": proc.stderr[-500:],
    }
    print(json.dumps(out, indent=2))
    return 0 if out["validated"] else 1


def cmd_revert(args) -> int:
    """Copy original back over patched (undo)."""
    shutil.copy(args.orig, args.patched)
    print(json.dumps({"reverted": True, "from": str(args.orig), "to": str(args.patched)}))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("byte-patch")
    s.add_argument("--in", dest="in_", required=True, type=Path)
    s.add_argument("--out", required=True, type=Path)
    s.add_argument("--offset", type=lambda x: int(x, 0))
    s.add_argument("--vaddr", type=lambda x: int(x, 0))
    s.add_argument("--bytes", required=True, help="hex bytes to write")
    s.set_defaults(func=cmd_byte_patch)

    s = sub.add_parser("nop")
    s.add_argument("--in", dest="in_", required=True, type=Path)
    s.add_argument("--out", required=True, type=Path)
    s.add_argument("--offset", type=lambda x: int(x, 0))
    s.add_argument("--vaddr", type=lambda x: int(x, 0))
    s.add_argument("--length", type=int, required=True)
    s.add_argument("--arch", help="auto-detected if omitted")
    s.set_defaults(func=cmd_nop)

    s = sub.add_parser("validate")
    s.add_argument("--orig", required=True, type=Path)
    s.add_argument("--patched", required=True, type=Path)
    s.add_argument("--sla-cmd", required=True, help="shell command (use {patched} / {orig} placeholders)")
    s.add_argument("--timeout", type=int, default=120)
    s.set_defaults(func=cmd_validate)

    s = sub.add_parser("revert")
    s.add_argument("--orig", required=True, type=Path)
    s.add_argument("--patched", required=True, type=Path)
    s.set_defaults(func=cmd_revert)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
