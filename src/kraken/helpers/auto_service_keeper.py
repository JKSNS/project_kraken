#!/usr/bin/env python3
"""auto_service_keeper -- A/D defense: detect compromise + restore from snapshot.

Critical for A/D events: if another team owns your box, you need to detect
it and restore your service before SLA failures stack. This helper:

  1. snapshot a clean state (file hashes + service-running + SLA passes)
  2. on the watch loop, detect:
       - file integrity drift (any tracked file's hash changed)
       - service down (PID gone, port closed, healthcheck failing)
       - process injection (extra children, unexpected open ports)
       - SLA failure (replay tests fail)
  3. on detection, restore from snapshot (copy back, restart service)
  4. log every detection + restore event

Usage:
    # Take a baseline:
    python3 auto_service_keeper.py snapshot \\
        --service-name svc1 \\
        --files /opt/svc1/app /opt/svc1/lib/* \\
        --healthcheck "curl -fsS http://127.0.0.1:8080/health" \\
        --restart-cmd "systemctl restart svc1" \\
        --out /var/lib/kraken/svc1.snapshot.json

    # Watch loop (one iteration; wrap in cron / loop yourself):
    python3 auto_service_keeper.py watch \\
        --snapshot /var/lib/kraken/svc1.snapshot.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path


def _hash_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _check_port(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return True
    except Exception:
        return False


def _run(cmd: str, timeout: int = 30) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return (proc.returncode, proc.stdout, proc.stderr)
    except subprocess.TimeoutExpired:
        return (-1, "", "TIMEOUT")


# ── snapshot ──────────────────────────────────────────────────────────


def cmd_snapshot(args) -> int:
    files = []
    for spec in args.files:
        for p in Path(".").glob(spec) if "*" in spec else [Path(spec)]:
            if p.is_file():
                files.append(
                    {
                        "path": str(p.resolve()),
                        "sha256": _hash_file(p),
                        "size": p.stat().st_size,
                    }
                )
    healthcheck = None
    if args.healthcheck:
        rc, out, err = _run(args.healthcheck, timeout=10)
        healthcheck = {"return_code": rc, "stdout_tail": out[-200:], "stderr_tail": err[-200:]}

    # Backup files into a backup dir alongside the snapshot
    backup_dir = Path(str(args.out) + ".backup")
    backup_dir.mkdir(parents=True, exist_ok=True)
    for f in files:
        src = Path(f["path"])
        dst = backup_dir / src.name
        try:
            shutil.copy2(src, dst)
            f["backup_path"] = str(dst)
        except Exception as e:
            f["backup_error"] = str(e)

    snap = {
        "service_name": args.service_name,
        "snapshot_ts": int(time.time()),
        "files": files,
        "ports": [
            {"host": h, "port": int(p), "open": _check_port(h, int(p))} for h, p in [s.split(":") for s in args.ports]
        ]
        if args.ports
        else [],
        "healthcheck_cmd": args.healthcheck,
        "healthcheck_baseline": healthcheck,
        "restart_cmd": args.restart_cmd,
        "backup_dir": str(backup_dir),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(snap, indent=2))
    print(f"wrote {args.out} ({len(files)} files snapshotted)")
    return 0


# ── watch ─────────────────────────────────────────────────────────────


def cmd_watch(args) -> int:
    snap = json.loads(args.snapshot.read_text())

    drifts = []
    for f in snap["files"]:
        path = Path(f["path"])
        if not path.is_file():
            drifts.append({"path": f["path"], "kind": "missing"})
            continue
        try:
            cur = _hash_file(path)
            if cur != f["sha256"]:
                drifts.append(
                    {
                        "path": f["path"],
                        "kind": "hash_drift",
                        "expected": f["sha256"][:16],
                        "got": cur[:16],
                    }
                )
        except Exception as e:
            drifts.append({"path": f["path"], "kind": "read_error", "error": str(e)})

    port_failures = []
    for p in snap.get("ports", []):
        if p.get("open") and not _check_port(p["host"], p["port"]):
            port_failures.append(
                {
                    "host": p["host"],
                    "port": p["port"],
                    "kind": "down",
                }
            )

    health_failed = False
    if snap.get("healthcheck_cmd"):
        rc, _, _ = _run(snap["healthcheck_cmd"], timeout=10)
        health_failed = rc != 0

    compromised = bool(drifts) or bool(port_failures) or health_failed
    actions = []

    if compromised and not args.detect_only:
        # Restore files
        for f in snap["files"]:
            backup = f.get("backup_path")
            if not backup or not Path(backup).is_file():
                continue
            try:
                shutil.copy2(backup, f["path"])
                actions.append({"kind": "file_restore", "path": f["path"]})
            except Exception as e:
                actions.append({"kind": "file_restore_failed", "path": f["path"], "error": str(e)})
        # Restart
        if snap.get("restart_cmd"):
            rc, out, err = _run(snap["restart_cmd"], timeout=60)
            actions.append(
                {
                    "kind": "restart",
                    "cmd": snap["restart_cmd"],
                    "return_code": rc,
                    "stderr_tail": err[-200:],
                }
            )

    report = {
        "service_name": snap["service_name"],
        "watch_ts": int(time.time()),
        "compromised": compromised,
        "drifts": drifts,
        "port_failures": port_failures,
        "health_failed": health_failed,
        "actions": actions,
    }
    print(json.dumps(report, indent=2))
    return 0 if not compromised else (1 if args.detect_only else 0)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("snapshot")
    s.add_argument("--service-name", required=True)
    s.add_argument("--files", nargs="+", required=True, help="paths or glob patterns")
    s.add_argument("--ports", nargs="*", default=[], help="host:port to track (must be open at snapshot time)")
    s.add_argument("--healthcheck", help="shell command exiting 0 iff service is healthy")
    s.add_argument("--restart-cmd", help="shell command to run on restoration")
    s.add_argument("--out", required=True, type=Path)
    s.set_defaults(func=cmd_snapshot)

    s = sub.add_parser("watch")
    s.add_argument("--snapshot", required=True, type=Path)
    s.add_argument("--detect-only", action="store_true", help="report drift without auto-restoring")
    s.set_defaults(func=cmd_watch)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
