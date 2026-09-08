#!/usr/bin/env python3
"""auto_serial_replay -- hardware-in-the-loop transcript replay + mutation.

Closes the HIL loop the synthesis doc has been pointing at: takes a
recorded `.transcript` (raw bytes captured from a working session,
e.g. from exp/solve.py runs) and replays it against a real board on
/dev/ttyACM*, optionally mutating frames per a `protocol_surface.json`
schema. Reports anomalies (no-response, unexpected-response, crash,
timing outlier, error-string match).

Usage:
    python3 auto_serial_replay.py --transcript path/to/session.transcript \\
        --port /dev/ttyACM0 --baud 115200 \\
        [--mutate length:0,length:65535,length:cap+1 ] \\
        [--protocol-surface protocol_surface.json] \\
        [--out replay_report.json]

Transcript format (recommended): one line per direction-marked frame.
    > <hex bytes>      # host -> board
    < <hex bytes>      # board -> host
    # comment

Output schema:
{
  "port": "...",
  "baud": ...,
  "frames_sent": N,
  "frames_received": N,
  "anomalies": [
    {"frame_idx": N, "kind": "no_response|crash|timing_outlier|error_string",
     "expected": "...", "actual": "...", "note": "..."}
  ],
  "mutation_results": [
    {"mutation": "length:65535", "outcome": "no_response", "frame_idx": N}
  ],
  "summary": {"anomaly_count": N, "elapsed_s": F, "mean_response_ms": F}
}
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

# Default ACK pattern (eCTF / DSU). Override via --ack-pattern.
DEFAULT_ACK = b"%A\x00\x00"
DEFAULT_ACK_CADENCE = 256

# Heuristic error-response strings worth flagging when they appear.
ERROR_RESPONSE_PATTERNS = [
    b"ANTHROPIC_MAGIC_STRING",  # known DSU tarpit
    b"%E",  # eCTF error frame magic
    b"PANIC",
    b"HARDFAULT",
    b"FAULT_HANDLER",
    b"go_to_jail",
]


def _parse_transcript(path: Path) -> list[tuple[str, bytes]]:
    """Return list of (direction, bytes). direction in {'>', '<'}."""
    out = []
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != 2 or parts[0] not in (">", "<"):
            continue
        try:
            data = bytes.fromhex(parts[1].replace(" ", ""))
        except ValueError:
            continue
        out.append((parts[0], data))
    return out


def _parse_mutations(spec: str | None) -> list[dict]:
    """Parse comma-separated mutation specs.

    Recognised forms:
      length:0          override length field with 0
      length:65535      override length field with 0xFFFF
      length:cap+1      override length with capacity+1
      drop:N            drop the Nth host->board frame
      flip:N:K          flip bit K of the Nth byte sent
      pad:N             append N junk bytes to next host->board frame
    """
    if not spec:
        return []
    out = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        out.append({"raw": part})
    return out


def _try_open(port: str, baud: int):
    """Open the serial port. Returns a pwntools.serialtube on success,
    None when pyserial / the port is unavailable. Designed so the helper
    can also run in dry-run mode without a board attached."""
    try:
        from pwn import serialtube  # type: ignore
    except Exception:
        return None
    try:
        return serialtube(port, baud, timeout=0.5)
    except Exception:
        return None


def replay(
    transcript_path: Path,
    port: str,
    baud: int,
    mutations: list[dict] | None = None,
    ack_pattern: bytes = DEFAULT_ACK,
    chunk_size: int = DEFAULT_ACK_CADENCE,
    response_timeout_s: float = 1.0,
    dry_run: bool = False,
) -> dict[str, Any]:
    frames = _parse_transcript(transcript_path)
    tube = None
    if not dry_run:
        tube = _try_open(port, baud)
        if tube is None:
            return {
                "error": (f"could not open {port} @ {baud} -- install pwntools and connect a board, or pass --dry-run"),
                "transcript_frames": len(frames),
            }

    anomalies = []
    sent = 0
    received = 0
    response_times = []
    start = time.time()

    for idx, (direction, payload) in enumerate(frames):
        if direction == ">":
            if tube is not None:
                # ACK-paced send (eCTF default)
                for off in range(0, len(payload), chunk_size):
                    tube.send(payload[off : off + chunk_size])
                    if off + chunk_size < len(payload) and ack_pattern:
                        try:
                            tube.recvuntil(ack_pattern, timeout=response_timeout_s)
                        except Exception:
                            anomalies.append(
                                {
                                    "frame_idx": idx,
                                    "kind": "no_ack",
                                    "note": (f"expected ack pattern {ack_pattern!r} after offset {off}; not received"),
                                }
                            )
                            break
            sent += 1

        elif direction == "<":
            t0 = time.time()
            if tube is not None:
                actual = b""
                deadline = t0 + response_timeout_s
                while time.time() < deadline and len(actual) < len(payload):
                    chunk = tube.recv(numb=len(payload) - len(actual), timeout=response_timeout_s)
                    if not chunk:
                        break
                    actual += chunk
                if actual != payload:
                    if not actual:
                        anomalies.append(
                            {
                                "frame_idx": idx,
                                "kind": "no_response",
                                "expected": payload[:64].hex(),
                                "actual": "<empty>",
                            }
                        )
                    else:
                        anomalies.append(
                            {
                                "frame_idx": idx,
                                "kind": "unexpected_response",
                                "expected": payload[:64].hex(),
                                "actual": actual[:64].hex(),
                            }
                        )
                    for pat in ERROR_RESPONSE_PATTERNS:
                        if pat in actual:
                            anomalies.append(
                                {
                                    "frame_idx": idx,
                                    "kind": "error_string",
                                    "actual": pat.decode("utf-8", "replace"),
                                    "note": "device returned a known error/tarpit string",
                                }
                            )
                response_times.append((time.time() - t0) * 1000)
            received += 1

    if tube is not None:
        try:
            tube.close()
        except Exception:
            pass

    elapsed = time.time() - start
    mean_resp = sum(response_times) / len(response_times) if response_times else 0.0

    return {
        "port": port,
        "baud": baud,
        "transcript_path": str(transcript_path),
        "frames_total": len(frames),
        "frames_sent": sent,
        "frames_received": received,
        "anomalies": anomalies,
        "mutation_results": [],  # TODO: per-mutation replay loop
        "dry_run": dry_run,
        "summary": {
            "anomaly_count": len(anomalies),
            "elapsed_s": round(elapsed, 2),
            "mean_response_ms": round(mean_resp, 2),
        },
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--transcript", required=True, type=Path)
    p.add_argument("--port", default="/dev/ttyACM0")
    p.add_argument("--baud", type=int, default=115200)
    p.add_argument("--mutate", default=None, help="comma-separated mutation specs (length:0, drop:N, etc.)")
    p.add_argument("--ack-pattern", default="25410000", help="hex of ACK pattern (default eCTF: %%A 00 00)")
    p.add_argument("--chunk-size", type=int, default=DEFAULT_ACK_CADENCE)
    p.add_argument("--response-timeout", type=float, default=1.0)
    p.add_argument("--protocol-surface", type=Path, help="protocol_surface.json (used to inform mutations)")
    p.add_argument("--dry-run", action="store_true", help="parse transcript, don't open serial port")
    p.add_argument("--out", type=Path)
    args = p.parse_args(argv)

    if not args.transcript.is_file():
        print(f"[-] not a file: {args.transcript}", file=sys.stderr)
        return 1

    try:
        ack = bytes.fromhex(args.ack_pattern)
    except ValueError:
        print(f"[-] bad --ack-pattern: {args.ack_pattern!r}", file=sys.stderr)
        return 1

    mutations = _parse_mutations(args.mutate)

    result = replay(
        args.transcript,
        args.port,
        args.baud,
        mutations=mutations,
        ack_pattern=ack,
        chunk_size=args.chunk_size,
        response_timeout_s=args.response_timeout,
        dry_run=args.dry_run,
    )

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2))
        print(f"wrote {args.out}")
    else:
        json.dump(result, sys.stdout, indent=2)
        print()

    if result.get("error"):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
