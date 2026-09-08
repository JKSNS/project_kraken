#!/usr/bin/env python3
"""auto_dynamic_trace -- Dynamic tracing (strace/ltrace) flag extractor.

Runs a binary under ltrace and strace to intercept string comparison
functions, write() syscalls, and library calls that may reveal flag content.

Techniques:
  1. ltrace:  Intercept strcmp/strncmp/memcmp/puts/printf/write for flag strings
  2. strace:  Parse write() syscalls for flag content
  3. /proc memory strings: Read mapped memory of the running process
  4. Input probing: Run with various inputs and diff outputs
  5. Crypto library detection: Flag crypto/hash/encoding function calls

Outputs EXTRACTED FLAG: <flag> on success.
"""
import argparse
import os
import re
import signal
import subprocess
import sys
import tempfile
import time

TECHNIQUE_TIMEOUT = 10

DEFAULT_FLAG_PATTERN = r"[A-Za-z_]{2,}\{[^\}]{3,}\}"

# Functions to intercept with ltrace
LTRACE_FUNCTIONS = "strcmp+strncmp+memcmp+puts+printf+write+fputs+sprintf+snprintf"

# Crypto/hash/encoding functions to detect
CRYPTO_FUNCTIONS = re.compile(
    r"(EVP_[A-Za-z_]+|AES_[a-z_]+|RC4|SHA[0-9]*_|MD5_|"
    r"base64_[a-z]+|BIO_[a-z_]+|HMAC|DES_[a-z_]+)",
)


def _is_elf(path: str) -> bool:
    """Check if file is an ELF binary."""
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
        return magic == b"\x7fELF"
    except (OSError, IOError):
        return False


def _find_flags(text: str, flag_format: str) -> list[str]:
    """Return all flag-pattern matches found in text."""
    flags: list[str] = []
    if flag_format:
        # Build pattern from prefix: e.g. "flag{" -> flag\{[^\}]{3,}\}
        prefix = re.escape(flag_format.rstrip("{"))
        pattern = prefix + r"\{[^\}]{3,}\}"
    else:
        pattern = DEFAULT_FLAG_PATTERN
    for m in re.finditer(pattern, text):
        candidate = m.group(0)
        # Basic sanity: body must have some diversity
        body_match = re.search(r"\{(.+)\}", candidate)
        if body_match:
            body = body_match.group(1)
            if len(body) >= 3 and len(set(body)) >= 2:
                flags.append(candidate)
    return flags


def _run_with_timeout(cmd: list[str], stdin_data: str = "AAAA\n",
                      timeout: int = TECHNIQUE_TIMEOUT,
                      env: dict | None = None) -> tuple[str, str]:
    """Run a command with timeout, return (stdout, stderr). Kill on timeout."""
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            preexec_fn=os.setsid,
        )
        try:
            stdout, stderr = proc.communicate(
                input=stdin_data.encode(), timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            # Kill entire process group
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (OSError, ProcessLookupError):
                pass
            proc.kill()
            try:
                stdout, stderr = proc.communicate(timeout=2)
            except Exception:
                stdout, stderr = b"", b""
        return (
            stdout.decode("utf-8", errors="replace"),
            stderr.decode("utf-8", errors="replace"),
        )
    except FileNotFoundError:
        return ("", f"[!] Command not found: {cmd[0]}")
    except Exception as e:
        return ("", f"[!] Error running {cmd[0]}: {e}")


def _cleanup_pid(pid: int) -> None:
    """Ensure a process and its group are dead."""
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(os.getpgid(pid), sig)
        except (OSError, ProcessLookupError):
            pass
        try:
            os.kill(pid, sig)
        except (OSError, ProcessLookupError):
            pass


# ---------------------------------------------------------------------------
# Technique 1: ltrace
# ---------------------------------------------------------------------------

def technique_ltrace(binary: str, flag_format: str) -> list[str]:
    """Run ltrace to intercept string comparison and output functions."""
    print("[*] Technique 1: ltrace interception")

    cmd = [
        "ltrace", "-s", "1024", "-e", LTRACE_FUNCTIONS,
        binary,
    ]
    # Try multiple inputs
    inputs = ["AAAA\n", "\n", flag_format + "test}\n", "A" * 100 + "\n"]
    all_flags: list[str] = []

    for test_input in inputs:
        stdout, stderr = _run_with_timeout(cmd, stdin_data=test_input)
        combined = stdout + "\n" + stderr

        # Parse ltrace output for string arguments in comparisons
        # ltrace format: strcmp("user_input", "flag{secret}") = -1
        for line in combined.splitlines():
            # Extract all quoted strings from ltrace output
            quoted = re.findall(r'"([^"]*)"', line)
            for s in quoted:
                flags = _find_flags(s, flag_format)
                all_flags.extend(flags)

            # Also check unquoted content (some ltrace versions)
            flags = _find_flags(line, flag_format)
            all_flags.extend(flags)

    if all_flags:
        print(f"[+] ltrace found {len(all_flags)} flag candidate(s)")
    else:
        print("[-] ltrace: no flags found in comparison arguments")

    return all_flags


# ---------------------------------------------------------------------------
# Technique 2: strace
# ---------------------------------------------------------------------------

def technique_strace(binary: str, flag_format: str) -> list[str]:
    """Run strace to intercept write/read syscalls for flag content."""
    print("[*] Technique 2: strace write/read interception")

    cmd = [
        "strace", "-s", "1024", "-e", "trace=write,read",
        binary,
    ]
    inputs = ["AAAA\n", "\n", flag_format + "test}\n"]
    all_flags: list[str] = []

    for test_input in inputs:
        stdout, stderr = _run_with_timeout(cmd, stdin_data=test_input)
        combined = stdout + "\n" + stderr

        # strace format: write(1, "flag{content}\n", 15) = 15
        for line in combined.splitlines():
            # Extract strings from write() and read() calls
            str_match = re.findall(r'(?:write|read)\(\d+,\s*"([^"]*)"', line)
            for s in str_match:
                # Unescape strace escapes (\n, \t, etc.)
                s = s.replace("\\n", "\n").replace("\\t", "\t")
                flags = _find_flags(s, flag_format)
                all_flags.extend(flags)

            # Also check the raw line
            flags = _find_flags(line, flag_format)
            all_flags.extend(flags)

    if all_flags:
        print(f"[+] strace found {len(all_flags)} flag candidate(s)")
    else:
        print("[-] strace: no flags in write/read syscalls")

    return all_flags


# ---------------------------------------------------------------------------
# Technique 3: /proc memory strings
# ---------------------------------------------------------------------------

def technique_proc_strings(binary: str, flag_format: str) -> list[str]:
    """Run the binary, then read strings from /proc/$PID mapped memory."""
    print("[*] Technique 3: /proc memory string extraction")

    all_flags: list[str] = []
    proc = None
    try:
        proc = subprocess.Popen(
            [binary],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid,
        )
        # Give the process a moment to initialize
        time.sleep(0.3)

        if proc.poll() is not None:
            # Process already exited -- read its output instead
            stdout = proc.stdout.read().decode("utf-8", errors="replace")
            stderr = proc.stderr.read().decode("utf-8", errors="replace")
            all_flags.extend(_find_flags(stdout + stderr, flag_format))
            if all_flags:
                print(f"[+] /proc: found flag in process output")
            else:
                print("[-] /proc: process exited immediately, no flag in output")
            return all_flags

        pid = proc.pid
        maps_path = f"/proc/{pid}/maps"

        try:
            with open(maps_path, "r") as mf:
                maps = mf.readlines()
        except (OSError, PermissionError) as e:
            print(f"[-] /proc: cannot read {maps_path}: {e}")
            return all_flags

        # Read readable memory segments
        mem_path = f"/proc/{pid}/mem"
        try:
            with open(mem_path, "rb") as mem:
                for line in maps:
                    # Parse: addr_start-addr_end perms ...
                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    perms = parts[1]
                    if "r" not in perms:
                        continue
                    addrs = parts[0].split("-")
                    if len(addrs) != 2:
                        continue
                    try:
                        start = int(addrs[0], 16)
                        end = int(addrs[1], 16)
                    except ValueError:
                        continue

                    # Skip very large segments (> 10MB) to avoid hanging
                    if end - start > 10 * 1024 * 1024:
                        continue

                    try:
                        mem.seek(start)
                        data = mem.read(end - start)
                    except (OSError, OverflowError, ValueError):
                        continue

                    # Extract printable strings (min 4 chars)
                    text = data.decode("utf-8", errors="replace")
                    flags = _find_flags(text, flag_format)
                    all_flags.extend(flags)

        except (OSError, PermissionError) as e:
            # Fall back to running strings on the binary itself
            print(f"[-] /proc: cannot read process memory: {e}")
            stdout, _ = _run_with_timeout(
                ["strings", "-a", "-n", "6", binary], stdin_data="",
            )
            all_flags.extend(_find_flags(stdout, flag_format))

    except Exception as e:
        print(f"[-] /proc: error: {e}")
    finally:
        if proc is not None:
            _cleanup_pid(proc.pid)
            try:
                proc.kill()
            except Exception:
                pass

    if all_flags:
        print(f"[+] /proc: found {len(all_flags)} flag candidate(s) in memory")
    else:
        print("[-] /proc: no flags found in mapped memory")

    return all_flags


# ---------------------------------------------------------------------------
# Technique 4: Input probing (diff-based)
# ---------------------------------------------------------------------------

def technique_input_probe(binary: str, flag_format: str) -> list[str]:
    """Run with various inputs and look for flag content in outputs."""
    print("[*] Technique 4: input probing with differential analysis")

    all_flags: list[str] = []
    outputs: dict[str, str] = {}

    test_inputs = [
        ("empty", "\n"),
        ("padding", "A" * 100 + "\n"),
        ("prefix", flag_format + "test}\n"),
        ("prefix_long", flag_format + "A" * 40 + "}\n"),
        ("newline_only", "\n\n\n"),
    ]

    for label, test_input in test_inputs:
        stdout, stderr = _run_with_timeout(
            [binary], stdin_data=test_input,
        )
        combined = stdout + stderr
        outputs[label] = combined

        # Check each output for flags
        flags = _find_flags(combined, flag_format)
        all_flags.extend(flags)

    # Also try running with argv input
    for label, arg in [("argv_test", "test"), ("argv_prefix", flag_format + "x}")]:
        stdout, stderr = _run_with_timeout(
            [binary, arg], stdin_data="",
        )
        combined = stdout + stderr
        flags = _find_flags(combined, flag_format)
        all_flags.extend(flags)

    if all_flags:
        print(f"[+] probe: found {len(all_flags)} flag candidate(s)")
    else:
        print("[-] probe: no flags found in any output variant")

    return all_flags


# ---------------------------------------------------------------------------
# Technique 5: Library call / crypto detection
# ---------------------------------------------------------------------------

def technique_library_detect(binary: str, flag_format: str) -> list[str]:
    """Parse ltrace for crypto/hash/encoding function calls and report."""
    print("[*] Technique 5: library call interception (crypto/hash/encoding)")

    all_flags: list[str] = []
    crypto_calls: list[str] = []

    # Run ltrace without function filter to see all library calls
    cmd = ["ltrace", "-s", "1024", binary]
    stdout, stderr = _run_with_timeout(cmd, stdin_data="AAAA\n")
    combined = stdout + "\n" + stderr

    for line in combined.splitlines():
        # Check for crypto function calls
        cm = CRYPTO_FUNCTIONS.search(line)
        if cm:
            crypto_calls.append(line.strip())

        # Also extract any string arguments that might be flags
        quoted = re.findall(r'"([^"]*)"', line)
        for s in quoted:
            flags = _find_flags(s, flag_format)
            all_flags.extend(flags)

        # Check full line
        flags = _find_flags(line, flag_format)
        all_flags.extend(flags)

    if crypto_calls:
        print(f"[+] Detected {len(crypto_calls)} crypto/hash library call(s):")
        for call in crypto_calls[:10]:
            print(f"    {call}")

    # Also run strings on the binary for static flag instances
    stdout, _ = _run_with_timeout(
        ["strings", "-a", "-n", "6", binary], stdin_data="",
    )
    string_flags = _find_flags(stdout, flag_format)
    all_flags.extend(string_flags)
    if string_flags:
        print(f"[+] strings: found {len(string_flags)} flag candidate(s) in binary")

    if all_flags:
        print(f"[+] library/strings: found {len(all_flags)} total candidate(s)")
    else:
        print("[-] library/strings: no flags found")

    return all_flags


# ---------------------------------------------------------------------------
# Byte-by-byte comparison leak
# ---------------------------------------------------------------------------

def technique_char_leak(binary: str, flag_format: str) -> str | None:
    """Try to leak flag character-by-character via ltrace strcmp interception.

    Some binaries compare user input against the flag using strcmp/strncmp.
    By providing the flag prefix and observing which argument the binary
    compares against, we can extract the expected flag.
    """
    print("[*] Technique 6: character-by-character comparison leak")

    cmd = [
        "ltrace", "-s", "1024", "-e", "strcmp+strncmp+memcmp",
        binary,
    ]

    # First, try with the flag prefix to see if the expected value leaks
    test_input = flag_format + "PROBE}\n"
    stdout, stderr = _run_with_timeout(cmd, stdin_data=test_input)
    combined = stdout + "\n" + stderr

    # Look for the comparison target: the OTHER argument in strcmp
    # If binary does strcmp(user_input, expected), expected is the flag
    for line in combined.splitlines():
        quoted = re.findall(r'"([^"]*)"', line)
        for s in quoted:
            # Skip if this is our own probe input
            if "PROBE" in s:
                continue
            flags = _find_flags(s, flag_format)
            if flags:
                print(f"[+] char-leak: found flag in comparison: {flags[0]}")
                return flags[0]

    print("[-] char-leak: no comparison-based flag leak detected")
    return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _deduplicate(flags: list[str]) -> list[str]:
    """Deduplicate while preserving order."""
    seen: set[str] = set()
    result: list[str] = []
    for f in flags:
        if f not in seen:
            seen.add(f)
            result.append(f)
    return result


def _score_flag(flag: str, flag_format: str) -> int:
    """Score a flag candidate: higher is better."""
    score = 0
    # Matches expected prefix
    prefix = flag_format.rstrip("{")
    if flag.startswith(prefix + "{"):
        score += 100
    # Has closing brace
    if flag.endswith("}"):
        score += 50
    # Body length
    body_match = re.search(r"\{(.+)\}", flag)
    if body_match:
        body = body_match.group(1)
        score += len(body)
        # Character diversity
        score += len(set(body)) * 2
    return score


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Kraken Dynamic Trace -- extract flags via strace/ltrace",
    )
    parser.add_argument("binary", help="Path to the ELF binary")
    parser.add_argument(
        "--flag-format", default="flag{",
        help="Expected flag prefix (default: 'flag{')",
    )
    args = parser.parse_args()

    binary = os.path.abspath(args.binary)
    flag_format = args.flag_format

    # --- Validate binary ---
    if not os.path.isfile(binary):
        print(f"[-] File not found: {binary}")
        sys.exit(1)

    if not _is_elf(binary):
        print(f"[-] Not an ELF binary: {binary}")
        sys.exit(1)

    # Ensure executable
    if not os.access(binary, os.X_OK):
        print(f"[*] Setting executable permission on {binary}")
        try:
            os.chmod(binary, os.stat(binary).st_mode | 0o111)
        except OSError as e:
            print(f"[-] Cannot make executable: {e}")
            sys.exit(1)

    print(f"[*] Dynamic tracing: {binary}")
    print(f"[*] Flag format: {flag_format}")
    print()

    all_candidates: list[str] = []

    # Run all techniques, collecting candidates
    techniques = [
        ("ltrace", lambda: technique_ltrace(binary, flag_format)),
        ("strace", lambda: technique_strace(binary, flag_format)),
        ("proc_strings", lambda: technique_proc_strings(binary, flag_format)),
        ("input_probe", lambda: technique_input_probe(binary, flag_format)),
        ("library_detect", lambda: technique_library_detect(binary, flag_format)),
    ]

    for name, func in techniques:
        try:
            results = func()
            if results:
                all_candidates.extend(results)
        except Exception as e:
            print(f"[!] Technique {name} failed: {e}")
        print()

    # Also try the character leak technique
    try:
        leaked = technique_char_leak(binary, flag_format)
        if leaked:
            all_candidates.append(leaked)
    except Exception as e:
        print(f"[!] Technique char_leak failed: {e}")

    # Deduplicate and score
    candidates = _deduplicate(all_candidates)

    if not candidates:
        print("[-] No flag candidates found via dynamic tracing.")
        sys.exit(1)

    # Sort by score (best first)
    candidates.sort(key=lambda f: _score_flag(f, flag_format), reverse=True)

    print(f"\n[+] Found {len(candidates)} unique candidate(s):")
    for i, c in enumerate(candidates[:10], 1):
        print(f"    {i}. {c}")

    best = candidates[0]
    print(f"\nEXTRACTED FLAG: {best}")


if __name__ == "__main__":
    main()
