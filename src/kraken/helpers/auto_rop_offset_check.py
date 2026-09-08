#!/usr/bin/env python3
"""auto_rop_offset_check -- cyclic-pattern ROP offset finder.

Before sending a real ROP chain, this helper sends a de Bruijn cyclic pattern
into an overflow and captures the crash signal to compute the exact byte
offset to saved_rbp, saved retaddr, and the argument slots in the faulting
frame.

Motivating case: VERE pwn2's stage 2 was 1 byte off for ~hours because
`getchar()` in `useful()` consumed a leftover `\\n` from FILE*stdin's pushback
buffer (unrelated to the attacker's payload). The wrong getchar-prefix
assumption shifted the whole chain by one byte into non-canonical RIP. A
cyclic-pattern probe would have spotted the shift on the first attempt by
revealing exact SIGSEGV fault addresses vs. expected offsets.

How it works:
  1. Caller provides a "stage 1" driver function (connect, send setup,
     reach the overflow point) and a "stage 2" sender that takes a single
     bytes payload.
  2. We generate a de Bruijn cyclic pattern of the given max length and send
     it via stage 2.
  3. We watch the process until it faults. Two modes:
     - LOCAL (process / socat): check returncode == -11, read /proc/*/syscall
       or core dump to find faulting RIP/RBP.
     - REMOTE: scrape stderr for "Segmentation fault" or catch a disconnect;
       optionally read out any leaked register state through a side channel.
  4. Use pwntools' `cyclic_find` to compute the byte offset within the
     pattern where RIP / RBP / specific slots came from.
  5. Report a table of offsets plus a consistency check (did RBP-offset fall
     exactly 8 bytes before RIP-offset? If not, frame layout differs from
     textbook).

Usage (as a library):
    from auto_rop_offset_check import find_offsets
    result = find_offsets(
        connect=lambda: remote(HOST, PORT),
        drive_to_overflow=drive,        # pre-overflow setup (choice=1, etc.)
        send_overflow=lambda io, p: io.send(p),
        max_len=200,
        fault_rip_regex=rb"core|Segmentation|0x([0-9a-f]{12,16})",
    )
    print(result["rip_offset"], result["rbp_offset"])

Usage (standalone CLI for local binary):
    auto_rop_offset_check.py --binary ./pwn-2 --libc ./libc.so.6 \\
        --pre-file pre.bin --overflow-len 200 --break-at 0x40155b

Limitations:
  - Local mode pipes stdin all-at-once. For binaries where `read(0, ...)`
    is sensitive to packet boundaries (e.g., a strlen-bypass BOF that
    depends on the FIRST read returning ONLY the setup bytes), you need
    to feed input via FIFO or socket with proper timing -- use the
    library `find_offsets_remote(...)` API with a socket tube.
  - `--break-at` should be the `leave` instruction of the vulnerable
    function, NOT `ret` -- by the time `ret` runs, `rbp` is already the
    popped cyclic bytes and dereferencing it fails.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


# ---------------------------------------------------------------------------
# De Bruijn pattern generation (compatible with pwntools.cyclic)
# ---------------------------------------------------------------------------

_ALPHABET = b"abcdefghijklmnopqrstuvwxyz0123456789"  # 36 chars → 36^4 > 1.6M


def _de_bruijn(alphabet: bytes, n: int) -> bytes:
    k = len(alphabet)
    a = [0] * (k * n)
    out = bytearray()

    def db(t: int, p: int) -> None:
        if t > n:
            if n % p == 0:
                for j in range(1, p + 1):
                    out.append(alphabet[a[j]])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)
    db(1, 1)
    return bytes(out)


def cyclic(length: int, subseq_n: int = 4) -> bytes:
    """Generate a de Bruijn cyclic pattern of `length` bytes."""
    full = _de_bruijn(_ALPHABET, subseq_n)
    # Repeat if caller asked for more than the de Bruijn sequence's period.
    while len(full) < length:
        full += full
    return full[:length]


def cyclic_find(needle: bytes | int, pattern: bytes, subseq_n: int = 4) -> int:
    """Find the offset of `needle` in the cyclic pattern. Returns -1 if absent."""
    if isinstance(needle, int):
        # Treat int as little-endian qword; look for first subseq_n bytes that
        # fit in the alphabet.
        b = needle.to_bytes(8, "little", signed=False)
        # Strip trailing zero bytes (not in alphabet -- indicates top of address)
        needle = b.rstrip(b"\x00")
        if len(needle) < subseq_n:
            return -1
    if len(needle) > subseq_n:
        needle = needle[:subseq_n]
    return pattern.find(needle)


# ---------------------------------------------------------------------------
# Local probe -- run binary with pre-bytes + cyclic overflow, capture crash
# ---------------------------------------------------------------------------

@dataclass
class ProbeResult:
    sent_len: int
    rip_bytes: Optional[bytes] = None
    rip_offset: Optional[int] = None
    rbp_bytes: Optional[bytes] = None
    rbp_offset: Optional[int] = None
    raw: dict = field(default_factory=dict)

    def ok(self) -> bool:
        return self.rip_offset is not None


def probe_local(
    binary: str,
    pre_bytes: bytes,
    overflow_len: int,
    env: dict[str, str] | None = None,
    timeout: float = 5.0,
    break_at: int | None = None,
) -> ProbeResult:
    """Run `binary` with `pre_bytes + cyclic_pattern` on stdin; inspect frame
    state either at a user-supplied breakpoint or on SIGSEGV, and compute
    offsets by finding cyclic bytes in the saved rbp / saved retaddr slots.

    pre_bytes: everything fed before the overflow (scanf answers, stage 1).
    overflow_len: number of cyclic bytes to append (stage 2 budget).
    break_at: address (e.g. of a `leave` or `ret` instruction in the vuln
              function) where gdb should break BEFORE the frame is torn
              down. If None, we just run and hope to catch the SIGSEGV --
              but that usually corrupts rbp first, so breaking is preferred.
    """
    pattern = cyclic(overflow_len)
    payload = pre_bytes + pattern

    stdin_path = f"/tmp/aroc_stdin_{os.getpid()}.bin"
    with open(stdin_path, "wb") as f:
        f.write(payload)

    if break_at is not None:
        bp = f"""
break *{hex(break_at)}
commands
  silent
  printf "SAVED_RBP=%#lx\\n", *(unsigned long *)$rbp
  printf "SAVED_RIP=%#lx\\n", *(unsigned long *)($rbp+8)
  printf "SAVED_TOP_STACK=%#lx\\n", *(unsigned long *)$rsp
  printf "RBP_REG=%#lx RSP_REG=%#lx\\n", $rbp, $rsp
  quit
end"""
    else:
        bp = ""

    gdb_script = f"""
set pagination off
{_env_lines(env)}
file {binary}
{bp}
run < {stdin_path}
info registers rip rbp rsp rbx r12 r13 r14 r15
quit
"""
    script_path = f"/tmp/aroc_gdb_{os.getpid()}.gdb"
    with open(script_path, "w") as f:
        f.write(gdb_script)

    try:
        r = subprocess.run(
            ["gdb", "-batch", "-x", script_path],
            capture_output=True, text=True, timeout=timeout,
        )
        out = r.stdout + "\n" + r.stderr
    finally:
        try: os.unlink(stdin_path)
        except OSError: pass
        try: os.unlink(script_path)
        except OSError: pass

    return _parse_gdb_regs(out, pattern, overflow_len)


def _env_lines(env: dict[str, str] | None) -> str:
    if not env:
        return ""
    return "\n".join(f"set env {k}={v}" for k, v in env.items())


_RE_REG = re.compile(r"^(\w+)\s+(0x[0-9a-fA-F]+)", re.MULTILINE)
_RE_SAVED_RBP = re.compile(r"SAVED_RBP=(0x[0-9a-fA-F]+)")
_RE_SAVED_RIP = re.compile(r"SAVED_RIP=(0x[0-9a-fA-F]+)")
_RE_SAVED_TOP = re.compile(r"SAVED_TOP_STACK=(0x[0-9a-fA-F]+)")


def _parse_gdb_regs(out: str, pattern: bytes, sent_len: int) -> ProbeResult:
    res = ProbeResult(sent_len=sent_len)
    regs: dict[str, int] = {}
    for m in _RE_REG.finditer(out):
        regs[m.group(1)] = int(m.group(2), 16)
    res.raw = regs

    # Preferred path: breakpoint mode dumped SAVED_RBP / SAVED_RIP from the
    # stack BEFORE leave;ret ran -- these are raw cyclic bytes.
    m_rbp = _RE_SAVED_RBP.search(out)
    m_rip = _RE_SAVED_RIP.search(out)
    if m_rbp:
        v = int(m_rbp.group(1), 16)
        res.rbp_bytes = _to_le(v)
        res.rbp_offset = cyclic_find(res.rbp_bytes, pattern)
    if m_rip:
        v = int(m_rip.group(1), 16)
        res.rip_bytes = _to_le(v)
        res.rip_offset = cyclic_find(res.rip_bytes, pattern)
    # Fallback: if no breakpoint hit, fall back to SIGSEGV register state.
    if res.rbp_offset is None and "rbp" in regs:
        res.rbp_bytes = _to_le(regs["rbp"])
        res.rbp_offset = cyclic_find(res.rbp_bytes, pattern)
    if res.rip_offset is None and "rip" in regs:
        res.rip_bytes = _to_le(regs["rip"])
        res.rip_offset = cyclic_find(res.rip_bytes, pattern)
    return res


def _to_le(v: int) -> bytes:
    """Little-endian bytes, stripping the always-zero top bytes of canonical addrs."""
    b = (v & ((1 << 64) - 1)).to_bytes(8, "little")
    return b.rstrip(b"\x00") or b[:1]


# ---------------------------------------------------------------------------
# Remote probe library API -- caller provides a tube builder and a driver
# ---------------------------------------------------------------------------

def find_offsets_remote(
    connect: Callable[[], Any],
    drive_to_overflow: Callable[[Any], None],
    send_overflow: Callable[[Any, bytes], None],
    capture_rip: Callable[[Any], int | None],
    overflow_len: int,
) -> ProbeResult:
    """Probe a remote (or process) tube to find the saved retaddr offset.

    drive_to_overflow: called after connect(), drives the program to the
        point where the next `send_overflow` will fill the vulnerable
        buffer.
    send_overflow: sends the cyclic pattern as the overflow payload.
    capture_rip: returns the value that RIP took on crash, or None if
        not observable. Typical implementations: read a `_dl_runtime`-
        style fault trace, parse `Segmentation fault (pid=..., sig=...)`
        lines from the wrapped service, or use a pre-installed signal
        handler that dumps state.

    If your service is a raw xinetd binary with no observability, this
    function is NOT useful -- use the library's offline `probe_local` with
    a matching synthetic wrapper instead.
    """
    pattern = cyclic(overflow_len)
    io = connect()
    try:
        drive_to_overflow(io)
        send_overflow(io, pattern)
        rip = capture_rip(io)
    finally:
        try: io.close()
        except Exception: pass
    res = ProbeResult(sent_len=overflow_len)
    if rip is not None:
        res.rip_bytes = _to_le(rip)
        res.rip_offset = cyclic_find(res.rip_bytes, pattern)
    return res


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--libc")
    ap.add_argument("--pre-file",
                    help="file containing pre-overflow bytes (stage 1 + scanf answers)")
    ap.add_argument("--overflow-len", type=int, default=200)
    ap.add_argument("--break-at", type=lambda s: int(s, 0), default=None,
                    help="hex address of leave/ret instruction to break at (preferred)")
    args = ap.parse_args()

    pre = b""
    if args.pre_file:
        with open(args.pre_file, "rb") as f:
            pre = f.read()

    env = {}
    if args.libc:
        env["LD_PRELOAD"] = os.path.abspath(args.libc)

    res = probe_local(
        binary=args.binary,
        pre_bytes=pre,
        overflow_len=args.overflow_len,
        env=env,
        break_at=args.break_at,
    )

    print(f"SENT_LEN: {res.sent_len}")
    if res.rip_bytes:
        print(f"RIP: {res.rip_bytes.hex()}  (offset {res.rip_offset})")
    if res.rbp_bytes:
        print(f"RBP: {res.rbp_bytes.hex()}  (offset {res.rbp_offset})")
    # Consistency check: normal frame layout has RBP 8 bytes before RIP slot.
    if res.rip_offset is not None and res.rbp_offset is not None:
        gap = res.rip_offset - res.rbp_offset
        if gap == 8:
            print("FRAME_OK: rbp is exactly 8 bytes before retaddr (textbook)")
        else:
            print(f"FRAME_SHIFT: rip_offset - rbp_offset = {gap} "
                  f"(expected 8 -- payload alignment is off by {gap - 8})")
    return 0 if res.ok() else 2


if __name__ == "__main__":
    sys.exit(main())
