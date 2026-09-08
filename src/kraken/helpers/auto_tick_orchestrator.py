#!/usr/bin/env python3
"""auto_tick_orchestrator -- A/D tick scheduler.

Glues `auto_exploit_deployer` + `auto_service_keeper` + `auto_ad_client`
into a per-tick loop:

  loop:
    1. wait for next tick boundary (via ad_client wait-tick)
    2. for each exploit in --exploits-dir, deploy against --targets-file
    3. submit captured flags via ad_client submit
    4. run service_keeper watch on each --keeper-snapshot
    5. log per-tick report to --log-dir/tick_<N>.json

Usage:
    python3 auto_tick_orchestrator.py \\
        --exploits-dir ./exploits/ \\
        --targets-file targets.txt \\
        --flag-format "FLG{" \\
        --scoreboard-url https://game.example.com/scoreboard.json \\
        --submit-protocol faust \\
        --submit-host 10.10.0.1 --submit-port 31337 --submit-token TOKEN \\
        --keeper-snapshot /var/lib/kraken/svc1.snap.json \\
        --log-dir ./tick-logs/ \\
        --max-ticks 100
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
HELPERS = REPO_ROOT / "src" / "kraken" / "helpers"


def _run_helper(name: str, args: list[str], timeout: int = 60) -> dict:
    helper = HELPERS / f"{name}.py"
    proc = subprocess.run(
        [sys.executable, str(helper)] + args,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return {
        "rc": proc.returncode,
        "stdout": proc.stdout,
        "stderr_tail": proc.stderr[-300:],
    }


def run_tick(
    tick_id: int,
    exploits_dir: Path,
    targets_file: Path,
    flag_format: str,
    log_dir: Path,
    submit: dict | None,
    keeper_snapshot: Path | None,
    jobs: int,
    exploit_timeout: int,
) -> dict[str, Any]:
    log_dir.mkdir(parents=True, exist_ok=True)
    tick_log = log_dir / f"tick_{tick_id}.json"
    flags_file = log_dir / f"tick_{tick_id}_flags.txt"

    captured: list[str] = []
    deploy_results = []

    # Run every exploit script in parallel (they each fan out to targets)
    exploits = sorted([e for e in exploits_dir.glob("*.py") if e.is_file()])
    for exploit in exploits:
        out = log_dir / f"tick_{tick_id}_{exploit.stem}.json"
        proc = _run_helper(
            "auto_exploit_deployer",
            [
                "--exploit",
                str(exploit),
                "--targets-file",
                str(targets_file),
                "--flag-format",
                flag_format,
                "--jobs",
                str(jobs),
                "--timeout",
                str(exploit_timeout),
                "--tick-id",
                str(tick_id),
                "--out",
                str(out),
            ],
            timeout=exploit_timeout * 4,
        )
        try:
            res = json.loads(out.read_text()) if out.is_file() else {}
        except Exception:
            res = {}
        deploy_results.append(
            {
                "exploit": exploit.name,
                "captured": res.get("captured_count", 0),
                "out": str(out),
                "rc": proc["rc"],
            }
        )
        captured.extend(res.get("flags", []))

    # Submit captured flags
    submit_result = None
    if submit and captured:
        flags_file.write_text("\n".join(captured) + "\n")
        submit_args = [
            "submit",
            "--protocol",
            submit["protocol"],
            "--flags-file",
            str(flags_file),
            "--out",
            str(log_dir / f"tick_{tick_id}_submit.json"),
        ]
        if submit.get("token"):
            submit_args += ["--token", submit["token"]]
        if submit.get("host"):
            submit_args += ["--host", submit["host"]]
        if submit.get("port"):
            submit_args += ["--port", str(submit["port"])]
        if submit.get("url"):
            submit_args += ["--url", submit["url"]]
        proc = _run_helper("auto_ad_client", submit_args, timeout=120)
        submit_result = {"rc": proc["rc"], "stderr_tail": proc["stderr_tail"]}

    # Defense: run keeper watch
    keeper_result = None
    if keeper_snapshot:
        proc = _run_helper(
            "auto_service_keeper",
            ["watch", "--snapshot", str(keeper_snapshot)],
            timeout=120,
        )
        try:
            keeper_result = json.loads(proc["stdout"])
        except Exception:
            keeper_result = {"rc": proc["rc"], "stderr_tail": proc["stderr_tail"]}

    report = {
        "tick_id": tick_id,
        "tick_ts": int(time.time()),
        "exploits_run": len(exploits),
        "captured_total": len(captured),
        "deploy_results": deploy_results,
        "submit": submit_result,
        "keeper": keeper_result,
        "captured_flags": captured,
    }
    tick_log.write_text(json.dumps(report, indent=2))
    print(
        f"[tick {tick_id}] captured={len(captured)} "
        f"submit={submit_result is not None} "
        f"keeper_compromised="
        f"{keeper_result.get('compromised') if keeper_result else 'n/a'} "
        f"→ {tick_log}"
    )
    return report


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--exploits-dir", required=True, type=Path)
    p.add_argument("--targets-file", required=True, type=Path)
    p.add_argument("--flag-format", default="flag{")
    p.add_argument("--log-dir", required=True, type=Path)

    p.add_argument("--scoreboard-url", help="if set, wait for tick boundary via this URL")
    p.add_argument("--tick-interval", type=float, default=120.0, help="fallback tick period when no scoreboard URL")
    p.add_argument("--max-ticks", type=int, default=10)
    p.add_argument("--start-tick", type=int, default=1)

    p.add_argument("--submit-protocol", choices=["faust", "ictf", "nautilus"])
    p.add_argument("--submit-host")
    p.add_argument("--submit-port", type=int)
    p.add_argument("--submit-url")
    p.add_argument("--submit-token")
    p.add_argument("--keeper-snapshot", type=Path)
    p.add_argument("--jobs", type=int, default=8)
    p.add_argument("--exploit-timeout", type=int, default=30)
    args = p.parse_args(argv)

    submit = None
    if args.submit_protocol:
        submit = {
            "protocol": args.submit_protocol,
            "host": args.submit_host,
            "port": args.submit_port,
            "url": args.submit_url,
            "token": args.submit_token,
        }

    for tick in range(args.start_tick, args.start_tick + args.max_ticks):
        if args.scoreboard_url:
            _run_helper(
                "auto_ad_client",
                ["wait-tick", "--url", args.scoreboard_url, "--max-wait", str(args.tick_interval * 2)],
                timeout=int(args.tick_interval * 3),
            )
        else:
            time.sleep(args.tick_interval)

        try:
            run_tick(
                tick,
                args.exploits_dir,
                args.targets_file,
                args.flag_format,
                args.log_dir,
                submit,
                args.keeper_snapshot,
                args.jobs,
                args.exploit_timeout,
            )
        except Exception as e:
            (args.log_dir / f"tick_{tick}_error.txt").write_text(repr(e))
            print(f"[tick {tick}] ERROR {e}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
