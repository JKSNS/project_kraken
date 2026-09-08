#!/usr/bin/env python3
"""auto_process_interact -- Multi-round process/service interaction engine.

Automates interaction with local binaries and remote services for CTF:
  1. Local process interaction -- spawn binary, send/receive, extract flag
  2. Remote service interaction -- connect to host:port, multi-round exchange
  3. Multi-round protocols -- challenge-response, proof-of-work, menu-driven
  4. Pattern-based responses -- detect prompts, auto-respond
  5. Proof-of-work solving -- SHA256/MD5 prefix brute-force, hashcash
  6. Menu navigation -- detect numbered/letter menus, explore all paths
  7. Brute-force interaction -- try different inputs, track responses

Usage:
    python3 auto_process_interact.py --binary ./challenge --prefix flag
    python3 auto_process_interact.py --host localhost --port 1337 --prefix flag
    python3 auto_process_interact.py --binary ./challenge --script "recv;send:password;recv"
    python3 auto_process_interact.py --host 10.0.0.1 --port 9999 --rounds 5

Outputs EXTRACTED FLAG: <flag> on success.
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import os
import re
import select
import signal
import socket
import string
import struct
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
RECV_TIMEOUT = 3.0
TECHNIQUE_TIMEOUT = 15
DEFAULT_FLAG_PATTERN = re.compile(r"[A-Za-z_]{2,}\{[^\}]{3,}\}")

# Common prompts and auto-responses
PROMPT_RESPONSES = [
    (re.compile(r"(?:enter\s+)?(?:password|pass(?:wd|word)?)\s*[:>]?\s*$", re.I), [
        "password", "admin", "secret", "flag", "root", "test", "guest",
    ]),
    (re.compile(r"(?:user(?:name)?|login)\s*[:>]?\s*$", re.I), [
        "admin", "root", "user", "guest", "flag",
    ]),
    (re.compile(r"(?:enter|input|type)\s+(?:the\s+)?(?:flag|key|answer)\s*[:>]?\s*$", re.I), [
        "flag{test}", "flag", "key",
    ]),
    (re.compile(r"(?:y/?n|yes/?no)\s*[:>]?\s*$", re.I), [
        "y", "yes",
    ]),
    (re.compile(r"(?:press\s+)?enter\s+(?:to\s+)?continue", re.I), [
        "",
    ]),
    (re.compile(r"(?:choice|option|select|menu)\s*[:>]?\s*$", re.I), [
        "1", "2", "3",
    ]),
]


# ---------------------------------------------------------------------------
# Flag helpers
# ---------------------------------------------------------------------------
def _find_flags(text: str, prefix: str) -> list[str]:
    """Return all flag-pattern matches found in text."""
    flags: list[str] = []
    if prefix:
        escaped = re.escape(prefix.rstrip("{"))
        pattern = escaped + r"\{[^\}]{3,}\}"
    else:
        pattern = r"[A-Za-z_]{2,}\{[^\}]{3,}\}"
    for m in re.finditer(pattern, text):
        candidate = m.group(0)
        body_match = re.search(r"\{(.+)\}", candidate)
        if body_match:
            body = body_match.group(1)
            if len(body) >= 3 and len(set(body)) >= 2:
                flags.append(candidate)
    return flags


def _deduplicate(items: list[str]) -> list[str]:
    """Deduplicate while preserving order."""
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _score_flag(flag: str, prefix: str) -> int:
    """Score a flag candidate: higher is better."""
    score = 0
    pfx = prefix.rstrip("{")
    if flag.startswith(pfx + "{"):
        score += 100
    if flag.endswith("}"):
        score += 50
    body_match = re.search(r"\{(.+)\}", flag)
    if body_match:
        body = body_match.group(1)
        score += len(body)
        score += len(set(body)) * 2
    return score


# ---------------------------------------------------------------------------
# Connection abstraction
# ---------------------------------------------------------------------------
class Connection:
    """Unified interface for local process or remote socket."""

    def __init__(self):
        self.proc: subprocess.Popen | None = None
        self.sock: socket.socket | None = None
        self.transcript: list[str] = []
        self._buffer = b""

    @classmethod
    def local(cls, binary: str, args: list[str] | None = None) -> "Connection":
        """Start a local process."""
        conn = cls()
        cmd = [binary] + (args or [])
        try:
            conn.proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=0,
                preexec_fn=os.setsid,
            )
        except FileNotFoundError:
            raise RuntimeError(f"Binary not found: {binary}")
        except PermissionError:
            # Try making it executable
            os.chmod(binary, os.stat(binary).st_mode | 0o111)
            conn.proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=0,
                preexec_fn=os.setsid,
            )
        return conn

    @classmethod
    def remote(cls, host: str, port: int, timeout: float = 10.0) -> "Connection":
        """Connect to a remote TCP service."""
        conn = cls()
        conn.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.sock.settimeout(timeout)
        try:
            conn.sock.connect((host, port))
        except (socket.timeout, OSError) as e:
            raise RuntimeError(f"Connection failed to {host}:{port}: {e}")
        return conn

    def is_alive(self) -> bool:
        """Check if the connection is still active."""
        if self.proc:
            return self.proc.poll() is None
        if self.sock:
            try:
                # Peek without consuming
                self.sock.setblocking(False)
                try:
                    data = self.sock.recv(1, socket.MSG_PEEK)
                    return len(data) > 0 or True
                except BlockingIOError:
                    return True
                except (ConnectionError, OSError):
                    return False
                finally:
                    self.sock.setblocking(True)
            except Exception:
                return False
        return False

    def recv(self, timeout: float = RECV_TIMEOUT, max_bytes: int = 8192) -> str:
        """Receive data with timeout. Returns decoded string."""
        data = b""
        deadline = time.time() + timeout

        if self.proc:
            fd = self.proc.stdout.fileno()
            while time.time() < deadline:
                remaining = max(0.01, deadline - time.time())
                ready, _, _ = select.select([fd], [], [], remaining)
                if ready:
                    try:
                        chunk = os.read(fd, max_bytes)
                        if not chunk:
                            break
                        data += chunk
                        # If we got some data and there's nothing more immediately available
                        if len(chunk) < max_bytes:
                            # Brief wait to see if more is coming
                            time.sleep(0.05)
                            ready2, _, _ = select.select([fd], [], [], 0.1)
                            if not ready2:
                                break
                    except (OSError, ValueError):
                        break
                else:
                    break

        elif self.sock:
            self.sock.settimeout(timeout)
            try:
                while time.time() < deadline:
                    remaining = max(0.01, deadline - time.time())
                    self.sock.settimeout(remaining)
                    try:
                        chunk = self.sock.recv(max_bytes)
                        if not chunk:
                            break
                        data += chunk
                        # Check for more data
                        self.sock.settimeout(0.1)
                        try:
                            more = self.sock.recv(max_bytes)
                            if more:
                                data += more
                            else:
                                break
                        except socket.timeout:
                            break
                    except socket.timeout:
                        break
            except (ConnectionError, OSError):
                pass

        text = data.decode("utf-8", errors="replace")
        if text:
            self.transcript.append(f"<<< {text}")
        return text

    def recv_until(self, pattern: str, timeout: float = RECV_TIMEOUT) -> str:
        """Receive until a regex pattern is matched."""
        accumulated = ""
        deadline = time.time() + timeout
        compiled = re.compile(pattern)

        while time.time() < deadline:
            remaining = max(0.01, deadline - time.time())
            chunk = self.recv(timeout=min(remaining, 0.5))
            accumulated += chunk
            if compiled.search(accumulated):
                break
            if not chunk and not self.is_alive():
                break

        return accumulated

    def send(self, data: str | bytes) -> None:
        """Send data to the process/socket."""
        if isinstance(data, str):
            data = data.encode()

        self.transcript.append(f">>> {data.decode('utf-8', errors='replace').rstrip()}")

        if self.proc and self.proc.stdin:
            try:
                self.proc.stdin.write(data)
                self.proc.stdin.flush()
            except (BrokenPipeError, OSError):
                pass
        elif self.sock:
            try:
                self.sock.sendall(data)
            except (ConnectionError, OSError):
                pass

    def sendline(self, data: str | bytes = b"") -> None:
        """Send data followed by newline."""
        if isinstance(data, str):
            data = data.encode()
        self.send(data + b"\n")

    def close(self) -> None:
        """Close the connection and clean up."""
        if self.proc:
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
            except (OSError, ProcessLookupError):
                pass
            try:
                self.proc.kill()
            except Exception:
                pass
            try:
                self.proc.wait(timeout=2)
            except Exception:
                pass
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                self.sock.close()
            except Exception:
                pass

    def get_transcript(self) -> str:
        """Return full interaction transcript."""
        return "\n".join(self.transcript)


# ---------------------------------------------------------------------------
# Proof-of-Work solver
# ---------------------------------------------------------------------------
def solve_pow(challenge_text: str) -> str | None:
    """Detect and solve proof-of-work challenges.

    Supported patterns:
      - sha256(PREFIX + ???) starts with "00000"
      - md5(??? + SUFFIX) == TARGET
      - hashcash style
    """
    # Pattern: find X such that sha256(PREFIX + X) starts with "00000..."
    sha_prefix_match = re.search(
        r"(?:sha256|SHA256)\s*\(\s*[\"']?(\w+)[\"']?\s*\+\s*(?:\?\?\?|X|x|input|s)"
        r".*?starts?\s*with\s*[\"']?(0{3,})[\"']?",
        challenge_text, re.I,
    )
    if sha_prefix_match:
        prefix = sha_prefix_match.group(1)
        target_prefix = sha_prefix_match.group(2)
        print(f"[*] PoW: sha256({prefix} + X) starts with '{target_prefix}'")
        return _brute_sha256_prefix(prefix, target_prefix)

    # Pattern: find X such that md5(X).startswith("...")
    md5_match = re.search(
        r"(?:md5|MD5)\s*\(\s*(?:\?\?\?|X|x|input|s)\s*\)"
        r".*?(?:starts?\s*with|==)\s*[\"']?([0-9a-fA-F]+)[\"']?",
        challenge_text, re.I,
    )
    if md5_match:
        target = md5_match.group(1)
        print(f"[*] PoW: md5(X) starts with '{target}'")
        return _brute_md5_prefix("", target)

    # Pattern: sha256(X) has N leading zeros
    zeros_match = re.search(
        r"(?:sha256|SHA256|hash)\s*\(\s*(?:\?\?\?|X|x|input|s)\s*\)"
        r".*?(\d+)\s*(?:leading\s*)?(?:zero|0)",
        challenge_text, re.I,
    )
    if zeros_match:
        n_zeros = int(zeros_match.group(1))
        target_prefix = "0" * n_zeros
        print(f"[*] PoW: sha256(X) with {n_zeros} leading zeros")
        return _brute_sha256_prefix("", target_prefix)

    # Generic: find suffix such that hash starts with target
    generic_match = re.search(
        r"[\"']([A-Za-z0-9]+)[\"']\s*\+\s*[\"']?(\?\?\?|XXXX|unknown)",
        challenge_text,
    )
    if generic_match:
        known_prefix = generic_match.group(1)
        # Look for expected hash prefix
        hex_target = re.search(r"(?:==|starts?\s*with)\s*[\"']?([0-9a-fA-F]{4,})", challenge_text)
        if hex_target:
            print(f"[*] PoW: hash({known_prefix} + X) starts with '{hex_target.group(1)}'")
            return _brute_sha256_prefix(known_prefix, hex_target.group(1))

    return None


def _brute_sha256_prefix(prefix: str, target_start: str, max_iters: int = 10_000_000) -> str | None:
    """Brute-force find suffix such that sha256(prefix+suffix) starts with target."""
    charset = string.ascii_letters + string.digits
    for length in range(1, 8):
        for combo in itertools.product(charset, repeat=length):
            suffix = "".join(combo)
            h = hashlib.sha256((prefix + suffix).encode()).hexdigest()
            if h.startswith(target_start):
                print(f"[+] PoW solved: suffix = '{suffix}'")
                return suffix
            max_iters -= 1
            if max_iters <= 0:
                print("[-] PoW: max iterations reached")
                return None
    return None


def _brute_md5_prefix(prefix: str, target_start: str, max_iters: int = 10_000_000) -> str | None:
    """Brute-force find suffix such that md5(prefix+suffix) starts with target."""
    charset = string.ascii_letters + string.digits
    for length in range(1, 8):
        for combo in itertools.product(charset, repeat=length):
            suffix = "".join(combo)
            h = hashlib.md5((prefix + suffix).encode()).hexdigest()
            if h.startswith(target_start):
                print(f"[+] PoW solved: suffix = '{suffix}'")
                return suffix
            max_iters -= 1
            if max_iters <= 0:
                print("[-] PoW: max iterations reached")
                return None
    return None


# ---------------------------------------------------------------------------
# Menu explorer
# ---------------------------------------------------------------------------
def _detect_menu(text: str) -> list[str]:
    """Detect menu options from text output.

    Returns list of option strings to try (e.g., ["1", "2", "3"]).
    """
    options: list[str] = []

    # Numbered menus: "1. Option", "1) Option", "[1] Option"
    numbered = re.findall(r"^\s*[\[\(]?(\d+)[.\)\]]\s+\w", text, re.M)
    if numbered:
        options.extend(numbered)

    # Letter menus: "a. Option", "(a) Option"
    lettered = re.findall(r"^\s*[\[\(]?([a-zA-Z])[.\)\]]\s+\w", text, re.M)
    if lettered:
        options.extend(lettered)

    # "Enter X to ..." patterns
    enter_opts = re.findall(r"[Ee]nter\s+[\"']?(\w+)[\"']?\s+to\s+", text)
    if enter_opts:
        options.extend(enter_opts)

    return _deduplicate(options)


# ---------------------------------------------------------------------------
# Interaction strategies
# ---------------------------------------------------------------------------
class ProcessInteractor:
    """Multi-round process/service interaction engine."""

    def __init__(
        self,
        binary: str | None = None,
        host: str | None = None,
        port: int | None = None,
        prefix: str = "flag",
        timeout: float = TECHNIQUE_TIMEOUT,
        binary_args: list[str] | None = None,
        max_rounds: int = 10,
        script: str | None = None,
    ):
        self.binary = os.path.abspath(binary) if binary else None
        self.host = host
        self.port = port
        self.prefix = prefix
        self.timeout = timeout
        self.binary_args = binary_args or []
        self.max_rounds = max_rounds
        self.script = script
        self.all_flags: list[str] = []

    def _connect(self) -> Connection:
        """Create a new connection (local process or remote)."""
        if self.binary:
            return Connection.local(self.binary, self.binary_args)
        elif self.host and self.port:
            return Connection.remote(self.host, self.port, self.timeout)
        else:
            raise RuntimeError("No binary or host:port specified")

    def _check_for_flags(self, text: str) -> list[str]:
        """Check text for flag patterns."""
        return _find_flags(text, self.prefix)

    # ----- Strategy 1: Simple run and collect -----
    def strategy_simple_run(self) -> list[str]:
        """Just run the binary / connect and collect all output."""
        print("[*] Strategy 1: simple run and collect output")
        flags: list[str] = []

        try:
            conn = self._connect()
            time.sleep(0.3)

            # Receive initial output
            output = conn.recv(timeout=self.timeout)
            if output:
                print(f"    Received {len(output)} chars")
                flags.extend(self._check_for_flags(output))

            # Try sending empty line to trigger more output
            if conn.is_alive():
                conn.sendline("")
                more = conn.recv(timeout=2.0)
                if more:
                    output += more
                    flags.extend(self._check_for_flags(more))

            conn.close()
        except Exception as e:
            print(f"[-] Simple run failed: {e}")

        if flags:
            print(f"[+] Simple run found {len(flags)} flag(s)")
        else:
            print("[-] Simple run: no flags in output")
        return flags

    # ----- Strategy 2: Menu exploration -----
    def strategy_menu_explore(self) -> list[str]:
        """Detect and explore menu-driven interfaces."""
        print("[*] Strategy 2: menu exploration")
        flags: list[str] = []

        try:
            conn = self._connect()
            output = conn.recv(timeout=3.0)
            flags.extend(self._check_for_flags(output))

            # Detect menu options
            options = _detect_menu(output)
            if not options:
                # Try sending enter first
                conn.sendline("")
                more = conn.recv(timeout=2.0)
                output += more
                flags.extend(self._check_for_flags(more))
                options = _detect_menu(output)

            if options:
                print(f"    Detected menu options: {options}")
                for opt in options[:8]:  # Limit exploration
                    try:
                        # Reconnect for each option to start fresh
                        conn.close()
                        conn = self._connect()
                        initial = conn.recv(timeout=2.0)

                        conn.sendline(opt)
                        response = conn.recv(timeout=3.0)
                        print(f"    Option '{opt}': {len(response)} chars")

                        flags.extend(self._check_for_flags(response))

                        # Try to navigate deeper (one more round)
                        if conn.is_alive():
                            sub_options = _detect_menu(response)
                            for sub in sub_options[:3]:
                                conn.sendline(sub)
                                deeper = conn.recv(timeout=2.0)
                                flags.extend(self._check_for_flags(deeper))

                    except Exception as e:
                        print(f"    Option '{opt}' error: {e}")
                        continue

            conn.close()
        except Exception as e:
            print(f"[-] Menu exploration failed: {e}")

        if flags:
            print(f"[+] Menu exploration found {len(flags)} flag(s)")
        else:
            print("[-] Menu exploration: no flags")
        return flags

    # ----- Strategy 3: Prompt-based auto-response -----
    def strategy_auto_respond(self) -> list[str]:
        """Detect prompts and respond with appropriate inputs."""
        print("[*] Strategy 3: prompt-based auto-response")
        flags: list[str] = []

        try:
            conn = self._connect()
            accumulated = ""

            for round_num in range(self.max_rounds):
                output = conn.recv(timeout=3.0)
                if not output and not conn.is_alive():
                    break
                accumulated += output
                flags.extend(self._check_for_flags(output))
                if flags:
                    break

                # Check if output matches any known prompt
                responded = False
                for prompt_re, responses in PROMPT_RESPONSES:
                    if prompt_re.search(output):
                        for resp in responses:
                            print(f"    Round {round_num + 1}: detected prompt, trying '{resp}'")
                            conn.sendline(resp)
                            reply = conn.recv(timeout=2.0)
                            accumulated += reply
                            found = self._check_for_flags(reply)
                            if found:
                                flags.extend(found)
                                break
                            # Check for "wrong" / "incorrect" to try next
                            if re.search(r"(?:wrong|incorrect|invalid|denied|error|fail)", reply, re.I):
                                continue
                            else:
                                responded = True
                                break
                        if flags or responded:
                            break

                if flags:
                    break

                # If no prompt matched, try sending newline
                if not responded and conn.is_alive():
                    conn.sendline("")

            conn.close()

            # Check full accumulated transcript
            flags.extend(self._check_for_flags(accumulated))

        except Exception as e:
            print(f"[-] Auto-respond failed: {e}")

        flags = _deduplicate(flags)
        if flags:
            print(f"[+] Auto-respond found {len(flags)} flag(s)")
        else:
            print("[-] Auto-respond: no flags")
        return flags

    # ----- Strategy 4: Common input brute-force -----
    def strategy_brute_inputs(self) -> list[str]:
        """Try common inputs and check for flag in output."""
        print("[*] Strategy 4: common input brute-force")
        flags: list[str] = []

        test_inputs = [
            "", "admin", "password", "flag", "secret", "test",
            "root", "1", "0", "yes", "no", "y", "n",
            "guest", "user", "login", "help", "quit",
            "cat flag.txt", "cat flag", "id", "ls",
            f"{self.prefix}{{test}}",
            "A" * 100,  # Buffer overflow probe
        ]

        for test_input in test_inputs:
            try:
                conn = self._connect()
                # Read initial prompt
                initial = conn.recv(timeout=2.0)
                flags.extend(self._check_for_flags(initial))
                if flags:
                    conn.close()
                    break

                # Send test input
                conn.sendline(test_input)
                response = conn.recv(timeout=2.0)
                found = self._check_for_flags(response)
                if found:
                    flags.extend(found)
                    conn.close()
                    break

                # Check for success indicators
                if re.search(r"(?:correct|success|congrat|winner|flag|you\s+(?:got|win|found))", response, re.I):
                    print(f"    [+] Positive response to input '{test_input}': {response[:100]}")
                    # Read more output
                    more = conn.recv(timeout=2.0)
                    flags.extend(self._check_for_flags(more))

                conn.close()
            except Exception:
                continue

        if flags:
            print(f"[+] Brute-force found {len(flags)} flag(s)")
        else:
            print("[-] Brute-force: no flags with common inputs")
        return flags

    # ----- Strategy 5: Script-driven interaction -----
    def strategy_scripted(self, script: str) -> list[str]:
        """Execute a semicolon-separated interaction script.

        Script format: "recv;send:data;recv;send:more_data;recv"
        Commands:
            recv           -- receive data
            recv:PATTERN   -- receive until pattern
            send:DATA      -- send data (\\n for newline)
            sendline:DATA  -- send data + newline
            sleep:N        -- sleep N seconds
            pow            -- solve proof-of-work from last received data
        """
        print(f"[*] Strategy 5: scripted interaction: {script[:60]}...")
        flags: list[str] = []

        try:
            conn = self._connect()
            last_received = ""

            for cmd in script.split(";"):
                cmd = cmd.strip()
                if not cmd:
                    continue

                if cmd == "recv":
                    last_received = conn.recv(timeout=3.0)
                    print(f"    recv: {len(last_received)} chars")
                    flags.extend(self._check_for_flags(last_received))

                elif cmd.startswith("recv:"):
                    pattern = cmd[5:]
                    last_received = conn.recv_until(pattern, timeout=5.0)
                    print(f"    recv_until('{pattern}'): {len(last_received)} chars")
                    flags.extend(self._check_for_flags(last_received))

                elif cmd.startswith("send:"):
                    data = cmd[5:].replace("\\n", "\n").replace("\\r", "\r")
                    conn.send(data.encode())
                    print(f"    send: '{data.rstrip()}'")

                elif cmd.startswith("sendline:"):
                    data = cmd[9:].replace("\\n", "\n").replace("\\r", "\r")
                    conn.sendline(data)
                    print(f"    sendline: '{data.rstrip()}'")

                elif cmd.startswith("sleep:"):
                    n = float(cmd[6:])
                    time.sleep(n)

                elif cmd == "pow":
                    solution = solve_pow(last_received)
                    if solution:
                        conn.sendline(solution)
                        print(f"    pow solved: '{solution}'")
                        last_received = conn.recv(timeout=3.0)
                        flags.extend(self._check_for_flags(last_received))
                    else:
                        print("    pow: could not solve")

                if flags:
                    break

            # Final receive
            if conn.is_alive():
                final = conn.recv(timeout=2.0)
                flags.extend(self._check_for_flags(final))

            conn.close()
        except Exception as e:
            print(f"[-] Script execution failed: {e}")

        if flags:
            print(f"[+] Script found {len(flags)} flag(s)")
        else:
            print("[-] Script: no flags")
        return flags

    # ----- Strategy 6: PoW auto-detect and solve -----
    def strategy_pow_solve(self) -> list[str]:
        """Detect proof-of-work challenge and solve it."""
        print("[*] Strategy 6: proof-of-work detection and solving")
        flags: list[str] = []

        try:
            conn = self._connect()
            output = conn.recv(timeout=5.0)
            flags.extend(self._check_for_flags(output))
            if flags:
                conn.close()
                return flags

            # Check if output contains a PoW challenge
            if re.search(r"(?:proof|pow|hash|sha256|md5|challenge).*(?:\?\?\?|find|solve|compute)", output, re.I):
                print("    [*] PoW challenge detected")
                solution = solve_pow(output)
                if solution:
                    conn.sendline(solution)
                    response = conn.recv(timeout=5.0)
                    flags.extend(self._check_for_flags(response))

                    # Continue interaction after PoW
                    for _ in range(5):
                        if not conn.is_alive():
                            break
                        more = conn.recv(timeout=2.0)
                        if more:
                            flags.extend(self._check_for_flags(more))
                        if flags:
                            break
                        conn.sendline("")

            conn.close()
        except Exception as e:
            print(f"[-] PoW strategy failed: {e}")

        if flags:
            print(f"[+] PoW strategy found {len(flags)} flag(s)")
        else:
            print("[-] PoW: no flags or no PoW detected")
        return flags

    # ----- Strategy 7: Multi-round conversation -----
    def strategy_multi_round(self) -> list[str]:
        """Engage in multi-round conversation, adapting to responses."""
        print(f"[*] Strategy 7: multi-round conversation (max {self.max_rounds} rounds)")
        flags: list[str] = []

        try:
            conn = self._connect()
            accumulated = ""

            for round_num in range(self.max_rounds):
                output = conn.recv(timeout=3.0)
                if not output:
                    if not conn.is_alive():
                        break
                    continue

                accumulated += output
                flags.extend(self._check_for_flags(output))
                if flags:
                    break

                print(f"    Round {round_num + 1}: {output[:80].strip()}")

                # Adaptive response logic
                response = self._generate_response(output, round_num)
                if response is not None:
                    conn.sendline(response)
                    print(f"    -> Sent: '{response}'")
                else:
                    conn.sendline("")

            # Check full transcript
            flags.extend(self._check_for_flags(accumulated))
            conn.close()
        except Exception as e:
            print(f"[-] Multi-round failed: {e}")

        flags = _deduplicate(flags)
        if flags:
            print(f"[+] Multi-round found {len(flags)} flag(s)")
        else:
            print("[-] Multi-round: no flags")
        return flags

    def _generate_response(self, output: str, round_num: int) -> str | None:
        """Generate a contextual response to the current output."""
        # Check known prompts
        for prompt_re, responses in PROMPT_RESPONSES:
            if prompt_re.search(output):
                idx = min(round_num, len(responses) - 1)
                return responses[idx]

        # Math challenge: "What is X + Y?"
        math_match = re.search(r"[Ww]hat\s+is\s+(\d+)\s*([+\-*/])\s*(\d+)", output)
        if math_match:
            a, op, b = int(math_match.group(1)), math_match.group(2), int(math_match.group(3))
            result = {"+": a + b, "-": a - b, "*": a * b, "/": a // b if b else 0}.get(op, 0)
            return str(result)

        # Hex/decimal conversion: "Convert 0xFF to decimal"
        hex_match = re.search(r"[Cc]onvert\s+0x([0-9a-fA-F]+)\s+to\s+decimal", output)
        if hex_match:
            return str(int(hex_match.group(1), 16))

        # Echo/repeat: "Say 'WORD'"
        echo_match = re.search(r"[Ss]ay\s+[\"'](.+?)[\"']", output)
        if echo_match:
            return echo_match.group(1)

        # Number extraction: "Enter the number: 42"
        num_match = re.search(r"(?:enter|type|send|input)\s+(?:the\s+)?(?:number|value)\s*[:=]?\s*(\d+)", output, re.I)
        if num_match:
            return num_match.group(1)

        # Question mark at end suggests a question -- try "yes"
        if output.rstrip().endswith("?"):
            return "yes"

        # Colon at end suggests input prompt
        if output.rstrip().endswith(":"):
            return ""

        return None

    # ----- Main solve orchestrator -----
    def solve(self) -> list[str]:
        """Try all interaction strategies, return found flags."""
        target = self.binary or f"{self.host}:{self.port}"
        print(f"[*] Process Interactor: {target}")
        print(f"[*] Flag prefix: {self.prefix}")
        print()

        # If a script is provided, run it first
        if self.script:
            flags = self.strategy_scripted(self.script)
            if flags:
                self.all_flags.extend(flags)

        if not self.all_flags:
            # Run strategies in order of likelihood
            strategies: list[tuple[str, callable]] = [
                ("simple run", self.strategy_simple_run),
                ("auto-respond", self.strategy_auto_respond),
                ("menu exploration", self.strategy_menu_explore),
                ("multi-round", self.strategy_multi_round),
                ("pow solve", self.strategy_pow_solve),
                ("brute inputs", self.strategy_brute_inputs),
            ]

            for name, strategy_fn in strategies:
                try:
                    flags = strategy_fn()
                    if flags:
                        self.all_flags.extend(flags)
                        break
                except Exception as e:
                    print(f"[!] Strategy '{name}' failed: {e}")
                print()

        self.all_flags = _deduplicate(self.all_flags)

        if self.all_flags:
            self.all_flags.sort(
                key=lambda f: _score_flag(f, self.prefix), reverse=True,
            )
            best = self.all_flags[0]
            print(f"\nEXTRACTED FLAG: {best}")
            if len(self.all_flags) > 1:
                print(f"[*] Also found: {self.all_flags[1:]}")
        else:
            print("\n[-] No flags found via process interaction.")

        return self.all_flags


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Kraken Process Interact -- multi-round binary/service interaction",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--binary", help="Path to local binary")
    group.add_argument("--host", help="Remote host to connect to")
    parser.add_argument(
        "--port", type=int, default=None,
        help="Remote port (required with --host)",
    )
    parser.add_argument(
        "--prefix", default="flag",
        help="Flag prefix (default: 'flag')",
    )
    parser.add_argument(
        "--timeout", type=float, default=TECHNIQUE_TIMEOUT,
        help="Timeout per strategy in seconds (default: 15)",
    )
    parser.add_argument(
        "--args", nargs="*", default=[],
        help="Arguments to pass to the binary",
    )
    parser.add_argument(
        "--rounds", type=int, default=10,
        help="Max interaction rounds per strategy (default: 10)",
    )
    parser.add_argument(
        "--script", default=None,
        help="Interaction script: 'recv;send:data;recv;sendline:more;recv'",
    )
    args = parser.parse_args()

    if args.host and not args.port:
        print("[-] --port is required with --host", file=sys.stderr)
        sys.exit(1)

    interactor = ProcessInteractor(
        binary=args.binary,
        host=args.host,
        port=args.port,
        prefix=args.prefix,
        timeout=args.timeout,
        binary_args=args.args,
        max_rounds=args.rounds,
        script=args.script,
    )

    found = interactor.solve()
    sys.exit(0 if found else 1)


if __name__ == "__main__":
    main()
