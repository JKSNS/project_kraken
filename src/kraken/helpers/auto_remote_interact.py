#!/usr/bin/env python3
"""General-purpose TCP service interaction tool.

Connects to a remote TCP service, reads a banner, executes send/recv
exchanges, and searches the full transcript for flags.

Usage:
    python3 auto_remote_interact.py --host 172.16.16.7 --port 26682 \
        --send "hello\\n" --send "test\\n" --expect "flag" --timeout 10
"""
from __future__ import annotations

import argparse
import asyncio
import re
import sys


async def interact(
    host: str,
    port: int,
    sends: list[str],
    expects: list[str],
    timeout: float,
    flag_format: str,
) -> tuple[str, str | None]:
    """Connect, exchange data, and return (transcript, flag_or_None)."""
    transcript_parts: list[str] = []

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except (asyncio.TimeoutError, OSError) as exc:
        msg = f"[!] Connection failed: {exc}"
        print(msg, file=sys.stderr)
        return msg, None

    try:
        # Read initial banner
        try:
            banner = await asyncio.wait_for(reader.read(4096), timeout=3.0)
            decoded = banner.decode(errors="replace")
            transcript_parts.append(f"<<< {decoded}")
            print(f"<<< {decoded}", end="")
        except asyncio.TimeoutError:
            transcript_parts.append("<<< (no banner)")

        # Execute send/recv exchanges
        for data in sends:
            # Unescape common escape sequences
            raw = data.replace("\\n", "\n").replace("\\r", "\r").replace("\\t", "\t")
            transcript_parts.append(f">>> {raw.rstrip()}")
            print(f">>> {raw.rstrip()}")

            writer.write(raw.encode())
            await writer.drain()

            # Read response
            try:
                resp = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                decoded = resp.decode(errors="replace")
                transcript_parts.append(f"<<< {decoded}")
                print(f"<<< {decoded}", end="")
            except asyncio.TimeoutError:
                transcript_parts.append("<<< (timeout)")
                print("<<< (timeout)")

        # If no sends, just read whatever the server sends for a bit
        if not sends:
            try:
                data_bytes = await asyncio.wait_for(reader.read(8192), timeout=timeout)
                decoded = data_bytes.decode(errors="replace")
                transcript_parts.append(f"<<< {decoded}")
                print(f"<<< {decoded}", end="")
            except asyncio.TimeoutError:
                pass

    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    transcript = "\n".join(transcript_parts)

    # Search transcript for flags
    flag = _find_flag(transcript, flag_format)

    # Check expect patterns
    if expects:
        for pattern in expects:
            if re.search(pattern, transcript):
                print(f"\n[+] Expected pattern matched: {pattern}")

    if flag:
        print(f"\nEXTRACTED FLAG: {flag}")

    return transcript, flag


def _find_flag(text: str, flag_format: str) -> str | None:
    """Search text for a flag matching the format."""
    if flag_format:
        try:
            m = re.search(flag_format, text)
            if m:
                return m.group(0)
        except re.error:
            pass

        # Try prefix{...} pattern from format
        prefix_m = re.match(r"([A-Za-z_]+)\\?\{", flag_format)
        if prefix_m:
            prefix = re.escape(prefix_m.group(1))
            m = re.search(prefix + r"\{[^}]+\}", text)
            if m:
                return m.group(0)

    # Generic patterns
    for pat in [r"[Ff][Ll][Aa][Gg]\{[^}]+\}", r"CTF\{[^}]+\}",
                r"[a-zA-Z]+\{[^\s}]{3,}\}"]:
        m = re.search(pat, text)
        if m:
            return m.group(0)

    return None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="TCP service interaction and flag extraction"
    )
    parser.add_argument("--host", required=True, help="Target host")
    parser.add_argument("--port", required=True, type=int, help="Target port")
    parser.add_argument("--send", action="append", default=[],
                        help="Data to send (repeatable, supports \\n escapes)")
    parser.add_argument("--expect", action="append", default=[],
                        help="Regex to match in transcript (repeatable)")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="Timeout per recv in seconds")
    parser.add_argument("--flag-format", default=r"flag\{[a-zA-Z0-9_]+\}",
                        help="Flag format regex")
    args = parser.parse_args()

    transcript, flag = asyncio.run(interact(
        host=args.host,
        port=args.port,
        sends=args.send,
        expects=args.expect,
        timeout=args.timeout,
        flag_format=args.flag_format,
    ))

    sys.exit(0 if flag else 1)


if __name__ == "__main__":
    main()
