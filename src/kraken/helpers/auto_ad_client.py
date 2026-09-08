#!/usr/bin/env python3
"""auto_ad_client -- A/D game-protocol client (Faust, iCTF, Nautilus, OOO).

Speaks the common attack/defense game protocols so kraken can play
without bespoke per-event integration. Handles:
  - flag submission (TCP, JSON, multi-flag-per-tick)
  - scoreboard polling (JSON, periodic)
  - team-list discovery (live targets per round)
  - tick boundary detection (poll game state, sleep until next tick)

Supported flavours:
  - faust       FAUST CTF (TCP "<flag>\\n", "OK"/"INV" reply)
  - ictf        iCTF / Polito (HTTP JSON {"flag":...} → {"accepted":bool})
  - nautilus    DEF CON CTF (TLS line-protocol, varies per year)
  - generic     pluggable via --submit-cmd / --scoreboard-cmd

Usage:
    python3 auto_ad_client.py submit \\
        --protocol faust --host 10.10.0.1 --port 31337 \\
        --token TEAM_TOKEN_HERE  --flags-file new_flags.txt

    python3 auto_ad_client.py scoreboard \\
        --protocol ictf --url https://game.example.com/scoreboard.json \\
        --out scoreboard.json

    python3 auto_ad_client.py teams \\
        --protocol ictf --url https://game.example.com/teams.json
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time
import urllib.request
from pathlib import Path

# ── flag submission backends ──────────────────────────────────────────


def _submit_faust(
    host: str,
    port: int,
    token: str | None,
    flags: list[str],
    timeout: float = 30.0,
) -> list[dict]:
    """FAUST CTF protocol: send "<flag>\\n", read line, repeat. Some events
    require a token sent first; toggle via --token."""
    results = []
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        if token:
            sock.sendall((token + "\n").encode())
        # Drain banner if any
        sock.settimeout(0.5)
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
        except TimeoutError:
            pass
        sock.settimeout(timeout)
        for flag in flags:
            sock.sendall((flag + "\n").encode())
            line = b""
            while not line.endswith(b"\n"):
                ch = sock.recv(1)
                if not ch:
                    break
                line += ch
            results.append(
                {
                    "flag": flag,
                    "response": line.decode("utf-8", "replace").strip(),
                }
            )
    finally:
        sock.close()
    return results


def _submit_ictf(
    url: str,
    token: str | None,
    flags: list[str],
    timeout: float = 30.0,
) -> list[dict]:
    """iCTF / Polito JSON protocol. Submit each flag with token header."""
    results = []
    for flag in flags:
        body = json.dumps({"flag": flag}).encode()
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json", **({"X-Team-Token": token} if token else {})},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                response_text = resp.read().decode("utf-8", "replace")
                accepted = False
                try:
                    accepted = json.loads(response_text).get("accepted", False)
                except Exception:
                    pass
                results.append(
                    {
                        "flag": flag,
                        "status_code": resp.status,
                        "response": response_text,
                        "accepted": accepted,
                    }
                )
        except Exception as e:
            results.append({"flag": flag, "error": str(e)})
    return results


def _submit_nautilus(
    host: str,
    port: int,
    token: str | None,
    flags: list[str],
    timeout: float = 30.0,
) -> list[dict]:
    """Nautilus / OOO DEF CON CTF protocol -- submit flags over TLS line.

    The exact protocol varies per year; this client speaks the common
    pattern: TLS connection, send '<token>:<flag>\\n', read 'CORRECT' /
    'INCORRECT' / 'OWNFLAG' / etc. Override via env NAUTILUS_FORMAT.
    """
    import ssl

    fmt = ":{flag}".format
    if token:
        fmt = (token + ":{flag}").format

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((host, port), timeout=timeout)
    try:
        sock = ctx.wrap_socket(raw, server_hostname=host)
    except ssl.SSLError:
        sock = raw  # try plaintext fallback
    results = []
    try:
        for flag in flags:
            line = (fmt(flag=flag) + "\n").encode()
            sock.sendall(line)
            buf = b""
            while not buf.endswith(b"\n"):
                ch = sock.recv(1)
                if not ch:
                    break
                buf += ch
            results.append(
                {
                    "flag": flag,
                    "response": buf.decode("utf-8", "replace").strip(),
                }
            )
    finally:
        sock.close()
    return results


# ── scoreboard / teams ────────────────────────────────────────────────


def _fetch_json(url: str, timeout: float = 30.0) -> dict | list:
    req = urllib.request.Request(url, headers={"User-Agent": "kraken-ad-client"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


# ── command dispatch ──────────────────────────────────────────────────


def cmd_submit(args) -> int:
    if not args.flags_file or not args.flags_file.is_file():
        print("[-] --flags-file required", file=sys.stderr)
        return 1
    flags = [
        line.strip()
        for line in args.flags_file.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if args.protocol == "faust":
        results = _submit_faust(args.host, args.port, args.token, flags)
    elif args.protocol == "ictf":
        results = _submit_ictf(args.url, args.token, flags)
    elif args.protocol == "nautilus":
        results = _submit_nautilus(args.host, args.port, args.token, flags)
    else:
        print(f"[-] unknown protocol {args.protocol!r}", file=sys.stderr)
        return 1

    accepted = sum(
        1
        for r in results
        if r.get("accepted")
        or (
            isinstance(r.get("response"), str)
            and any(s in r["response"].upper() for s in ("OK", "ACCEPTED", "CORRECT"))
        )
    )
    output = {
        "protocol": args.protocol,
        "submitted": len(results),
        "accepted": accepted,
        "results": results,
    }
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(output, indent=2))
        print(f"wrote {args.out} ({accepted}/{len(results)} accepted)")
    else:
        print(json.dumps(output, indent=2))
    return 0 if accepted else 1


def cmd_scoreboard(args) -> int:
    data = _fetch_json(args.url)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(data, indent=2))
        print(f"wrote {args.out}")
    else:
        print(json.dumps(data, indent=2))
    return 0


def cmd_teams(args) -> int:
    data = _fetch_json(args.url)
    teams = []
    if isinstance(data, dict) and "teams" in data:
        teams = data["teams"]
    elif isinstance(data, list):
        teams = data
    print(json.dumps(teams, indent=2))
    return 0


def cmd_wait_tick(args) -> int:
    """Poll scoreboard until tick number changes; emit when next tick lands."""
    initial = _fetch_json(args.url)
    initial_tick = initial.get("round") or initial.get("tick") or 0
    print(f"current tick: {initial_tick}", file=sys.stderr)
    deadline = time.time() + args.max_wait
    while time.time() < deadline:
        time.sleep(args.poll_interval)
        try:
            d = _fetch_json(args.url)
        except Exception:
            continue
        cur = d.get("round") or d.get("tick") or 0
        if cur != initial_tick:
            print(json.dumps({"prev_tick": initial_tick, "new_tick": cur}))
            return 0
    print("[-] tick did not advance within window", file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("submit")
    s.add_argument("--protocol", required=True, choices=["faust", "ictf", "nautilus"])
    s.add_argument("--host")
    s.add_argument("--port", type=int)
    s.add_argument("--url")
    s.add_argument("--token")
    s.add_argument("--flags-file", type=Path, required=True)
    s.add_argument("--out", type=Path)
    s.set_defaults(func=cmd_submit)

    s = sub.add_parser("scoreboard")
    s.add_argument("--url", required=True)
    s.add_argument("--protocol", default="ictf")
    s.add_argument("--out", type=Path)
    s.set_defaults(func=cmd_scoreboard)

    s = sub.add_parser("teams")
    s.add_argument("--url", required=True)
    s.add_argument("--protocol", default="ictf")
    s.set_defaults(func=cmd_teams)

    s = sub.add_parser("wait-tick")
    s.add_argument("--url", required=True)
    s.add_argument("--poll-interval", type=float, default=5.0)
    s.add_argument("--max-wait", type=float, default=600.0)
    s.set_defaults(func=cmd_wait_tick)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
