#!/usr/bin/env python3
"""make_submission.py -- assemble an autonomous-CTF competition submission bundle.

Runs KRAKEN over a directory of challenges (or bundles an already-solved
directory), then packages the four artifacts a typical autonomous-agent CTF
asks for:

  1. Agent implementation  -- a git archive of this repo (source + install docs).
  2. Flag submission        -- flags.txt / flags.json  (challenge_id -> flag).
  3. Execution logs         -- per-challenge reasoning / tool-call / output logs,
                              harvested from KRAKEN's own run artifacts, which is
                              the evidence that the flags were obtained autonomously.
  4. Technical report       -- REPORT.md, filled with the live results table +
                              efficiency stats (total time, per-challenge tool calls).

Everything lands in an output dir and a single submission.zip.

Usage:
  # solve + bundle in one shot
  python3 scripts/make_submission.py ./challenges --flag-format "flag{}" --team "MyTeam" --solve

  # bundle a directory KRAKEN already solved
  python3 scripts/make_submission.py ./challenges --flag-format "flag{}" --team "MyTeam"

Autonomy note: this script only ORCHESTRATES and COLLECTS. It never edits a flag
or a log. The logs it bundles are produced by KRAKEN during the solve.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import zipfile
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Per-challenge artifact filenames KRAKEN drops that constitute execution evidence.
LOG_ARTIFACTS = (
    "timeline.jsonl",  # ordered reasoning + tool-call trace (best autonomy evidence)
    "session.json",  # {challenge,start_ts,end_ts,total_elapsed,status,flag,source}
    "triage.json",  # initial analysis
    "decompile.json",  # RE output
    "README.md",  # human-readable solve writeup
    "solve.py",  # generated solve script
    "solve.sh",
    "exploit.py",
)


def run_solver(challenge_dir: Path, flag_format: str, jobs: int, timeout: int, log_path: Path) -> int:
    """Run the hybrid solver, teeing combined output to log_path. Returns exit code."""
    cmd = [
        sys.executable,
        str(REPO_ROOT / "scripts" / "hybrid_solve.py"),
        str(challenge_dir),
        "--flag-format",
        flag_format,
        "-j",
        str(jobs),
        "--timeout",
        str(timeout),
    ]
    print(f"[make_submission] solving: {' '.join(cmd)}")
    with log_path.open("w") as fh:
        fh.write(f"# KRAKEN solver run -- {datetime.now(UTC).isoformat()}\n")
        fh.write(f"# command: {' '.join(cmd)}\n\n")
        fh.flush()
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        for line in proc.stdout:
            sys.stdout.write(line)
            fh.write(line)
        proc.wait()
    return proc.returncode


def read_flag(chal: Path) -> str:
    """Recover the flag for one challenge from flag.txt or session.json."""
    ft = chal / "flag.txt"
    if ft.is_file():
        val = ft.read_text(errors="replace").strip()
        if val:
            return val
    sj = chal / "session.json"
    if sj.is_file():
        try:
            return (json.loads(sj.read_text()).get("flag") or "").strip()
        except Exception:
            pass
    return ""


def read_session(chal: Path) -> dict:
    sj = chal / "session.json"
    if sj.is_file():
        try:
            return json.loads(sj.read_text())
        except Exception:
            return {}
    return {}


def count_tool_calls(chal: Path) -> int | None:
    """Approximate reasoning/tool steps from timeline.jsonl line count."""
    tl = chal / "timeline.jsonl"
    if tl.is_file():
        try:
            return sum(1 for _ in tl.open())
        except Exception:
            return None
    return None


def harvest(challenge_dir: Path, out: Path) -> list[dict]:
    """Walk challenge subdirs, collect flags + copy execution-log artifacts."""
    logs_root = out / "logs"
    logs_root.mkdir(parents=True, exist_ok=True)
    out_resolved = out.resolve()
    results: list[dict] = []
    for chal in sorted(p for p in challenge_dir.iterdir() if p.is_dir()):
        # Never treat our own output dir (if nested under challenge_dir) as a challenge.
        cr = chal.resolve()
        if cr == out_resolved or out_resolved in cr.parents or cr in out_resolved.parents:
            continue
        flag = read_flag(chal)
        session = read_session(chal)
        dest = logs_root / chal.name
        dest.mkdir(parents=True, exist_ok=True)
        copied = []
        for name in LOG_ARTIFACTS:
            src = chal / name
            if src.is_file():
                (dest / name).write_bytes(src.read_bytes())
                copied.append(name)
        results.append(
            {
                "challenge_id": chal.name,
                "flag": flag,
                "status": "SOLVED" if flag else session.get("status", "UNSOLVED"),
                "elapsed_s": session.get("total_elapsed"),
                "engine": session.get("source", ""),
                "tool_calls": count_tool_calls(chal),
                "log_artifacts": copied,
            }
        )
    return results


def write_flags(results: list[dict], out: Path) -> None:
    solved = [r for r in results if r["flag"]]
    # tab-separated: <challenge_id>\t<flag> -- the common expected format
    lines = [f"{r['challenge_id']}\t{r['flag']}" for r in solved]
    (out / "flags.txt").write_text("\n".join(lines) + ("\n" if lines else ""))
    (out / "flags.json").write_text(json.dumps({r["challenge_id"]: r["flag"] for r in solved}, indent=2) + "\n")


def archive_agent_source(out: Path) -> str | None:
    """git archive the repo (source only, no runtime state) as the agent bundle."""
    dest = out / "agent-src.tar.gz"
    try:
        with dest.open("wb") as fh:
            subprocess.run(["git", "archive", "--format=tar.gz", "HEAD"], cwd=REPO_ROOT, stdout=fh, check=True)
        return dest.name
    except Exception as e:
        print(f"[make_submission] WARN: git archive failed ({e}); include the repo source manually.")
        return None


def render_report(results: list[dict], team: str, flag_format: str, solver_exit: int | None) -> str:
    solved = [r for r in results if r["flag"]]
    total = len(results)
    n = len(solved)
    tool_calls = [r["tool_calls"] for r in solved if r["tool_calls"]]
    times = [r["elapsed_s"] for r in solved if r["elapsed_s"]]
    rows = "\n".join(
        f"| {r['challenge_id']} | {r['status']} | "
        f"{'`' + r['flag'] + '`' if r['flag'] else '--'} | "
        f"{r['engine'] or '--'} | {r['tool_calls'] if r['tool_calls'] is not None else '--'} | "
        f"{r['elapsed_s'] if r['elapsed_s'] is not None else '--'} |"
        for r in results
    )
    ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    total_time = f"{sum(times):.0f}s" if times else "n/a"
    total_calls = str(sum(tool_calls)) if tool_calls else "n/a"
    return f"""# KRAKEN -- Autonomous CTF Submission Report

**Team:** {team}  ·  **Generated:** {ts}  ·  **Flag format:** `{flag_format}`

## 1. Results

**Solved {n} / {total} challenges.**

| Challenge | Status | Flag | Engine | Tool calls | Time (s) |
|---|---|---|---|---|---|
{rows}

## 2. Efficiency

- Total autonomous solve time (solved challenges): **{total_time}**
- Total tool/reasoning steps (solved challenges): **{total_calls}**
- Per-challenge timing and step counts are in `logs/<challenge>/session.json`
  and `logs/<challenge>/timeline.jsonl`.

## 3. Agent architecture (summary)

KRAKEN is a LangGraph state machine that routes each challenge through a
cheapest-first cascade: (1) deterministic tooling (disassembly, symbolic
execution, classic crypto attacks) with no LLM, (2) LLM-authored solve scripts,
(3) interactive pwntools exploitation, (4) an optional independent agentic
fallback. Per-category specialist agents (rev/pwn/web/crypto/forensics/firmware)
and a deterministic flag validator sit around the core. Default backend is a
local model via Ollama, so solves are offline and cost $0. See `docs/TECHNICAL.md`.

## 4. Autonomy

Every flag in this bundle was obtained by the agent with no human intervention.
The evidence is in `logs/<challenge>/`: `timeline.jsonl` is the ordered
reasoning + tool-call trace, `session.json` records start/end timing and the
recovered flag, and the generated solve scripts show exactly what the agent ran.
`make_submission.py` only orchestrated the run and collected these artifacts -- it
never edited a flag or a log.

## 5. Reproduce

```bash
pip install -e .
ollama pull gpt-oss-20b-131k:latest
python3 scripts/make_submission.py <challenge_dir> --flag-format "{flag_format}" --team "{team}" --solve
```

Solver exit code this run: {solver_exit if solver_exit is not None else "n/a (bundle-only)"}.
"""


def zip_bundle(out: Path, zip_path: Path) -> None:
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(out.rglob("*")):
            if p.is_file() and p.resolve() != zip_path.resolve():
                zf.write(p, p.relative_to(out))


def main() -> int:
    ap = argparse.ArgumentParser(description="Assemble an autonomous-CTF submission bundle")
    ap.add_argument("challenge_dir", help="Directory of challenge subdirectories")
    ap.add_argument("--flag-format", default=r"flag\{[^}]+\}", help="Flag format / regex")
    ap.add_argument("--team", default="TEAM", help="Team name for the report")
    ap.add_argument("--out", default="submission", help="Output directory")
    ap.add_argument(
        "--solve", action="store_true", help="Run the solver first (otherwise bundle an already-solved dir)"
    )
    ap.add_argument("-j", "--parallel", type=int, default=8)
    ap.add_argument("--timeout", type=int, default=480, help="Per-challenge timeout (s)")
    args = ap.parse_args()

    challenge_dir = Path(args.challenge_dir).resolve()
    if not challenge_dir.is_dir():
        print(f"error: {challenge_dir} is not a directory", file=sys.stderr)
        return 2

    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)

    solver_exit = None
    if args.solve:
        solver_exit = run_solver(
            challenge_dir, args.flag_format, args.parallel, args.timeout, out / "logs" / "solver_stdout.log"
        )

    results = harvest(challenge_dir, out)
    write_flags(results, out)
    archive_agent_source(out)
    (out / "REPORT.md").write_text(render_report(results, args.team, args.flag_format, solver_exit))
    (out / "MANIFEST.json").write_text(
        json.dumps(
            {
                "team": args.team,
                "flag_format": args.flag_format,
                "generated": datetime.now(UTC).isoformat(),
                "solved": sum(1 for r in results if r["flag"]),
                "total": len(results),
                "results": results,
            },
            indent=2,
        )
        + "\n"
    )

    zip_path = out.parent / f"{out.name}.zip"
    zip_bundle(out, zip_path)

    n = sum(1 for r in results if r["flag"])
    print(f"\n[make_submission] bundled {n}/{len(results)} solved -> {out}")
    print(f"[make_submission] zip: {zip_path}")
    print("[make_submission] contents: flags.txt, flags.json, logs/, REPORT.md, MANIFEST.json, agent-src.tar.gz")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
