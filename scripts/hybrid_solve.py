#!/usr/bin/env python3
"""Hybrid parallel CTF solver -- routes each challenge to the fastest engine.

Architecture (cascade-first, Codex-fallback):
  1. Triage ALL challenges in parallel (fast, <2s each)
  2. Run cascade on ALL challenges (deterministic, free, <30s each)
  3. Challenges the cascade solved → done (zero LLM tokens)
  4. Failures → Codex parallel (GPT-5.4, only for what cascade can't solve)
  5. Wall-clock = max(cascade batch, Codex fallback batch)

Usage:
    python3 scripts/hybrid_solve.py ./challenges/pwn --flag-format "flag{}" -j 4
    python3 scripts/hybrid_solve.py challenges/ --flag-format "CTF{}" -j 8
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

# Add kraken to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))


@dataclass
class ChallengeInfo:
    name: str
    path: str
    description: str = ""
    remote_host: str = ""
    remote_port: int = 0
    tier: str = "STATIC"  # STATIC, REMOTE, MIXED
    flag: str = ""
    status: str = "PENDING"
    tool: str = ""
    elapsed: float = 0.0
    error: str = ""


def discover_challenges(challenge_dir: str) -> list[ChallengeInfo]:
    """Find all challenge subdirectories and classify them."""
    challenges = []
    base = Path(challenge_dir)
    for d in sorted(base.iterdir()):
        if not d.is_dir():
            continue

        info = ChallengeInfo(name=d.name, path=str(d.resolve()))

        # Read description
        desc_file = d / "description.txt"
        if desc_file.exists():
            info.description = desc_file.read_text(errors="replace").strip()

        # Detect remote service
        nc_match = re.search(r'nc\s+(\S+)\s+(\d+)', info.description)
        if nc_match:
            info.remote_host = nc_match.group(1)
            info.remote_port = int(nc_match.group(2))
            info.tier = "REMOTE"

        # Check for binary
        has_binary = any(
            f.is_file() and not f.suffix and os.access(f, os.X_OK)
            for f in d.iterdir()
        )
        if has_binary and info.tier == "REMOTE":
            info.tier = "REMOTE"  # pwn with binary + remote
        elif not has_binary and not info.remote_host:
            info.tier = "STATIC"

        challenges.append(info)

    return challenges


async def solve_cascade(chal: ChallengeInfo, flag_format: str, cascade_timeout: int = 60) -> ChallengeInfo:
    """Solve via kraken deterministic cascade. Fast for static challenges.

    Timeout caps cascade at 60s -- if it hasn't found a flag by then,
    it won't. Remote tools are slow and wasteful; let Codex handle those.
    """
    t0 = time.time()
    try:
        from kraken.mcp_server import kraken_full_solve
        result = await asyncio.wait_for(
            kraken_full_solve(
                challenge_path=chal.path,
                flag_format=flag_format,
                challenge_description=chal.description,
                save_session=True,
                output_dir=chal.path + "/",
            ),
            timeout=cascade_timeout,
        )
        chal.elapsed = round(time.time() - t0, 1)

        if result.get("flag_found"):
            chal.flag = result["flag"]
            chal.status = "SOLVED"
            chal.tool = f"cascade:{result.get('solving_tool', 'unknown')}"
            Path(chal.path, "flag.txt").write_text(chal.flag + "\n")
        else:
            chal.status = "CASCADE_FAILED"
            chal.tool = "cascade"
    except asyncio.TimeoutError:
        chal.elapsed = round(time.time() - t0, 1)
        chal.status = "CASCADE_FAILED"
        chal.tool = "cascade"
        chal.error = f"cascade timeout ({cascade_timeout}s)"
    except Exception as e:
        chal.elapsed = round(time.time() - t0, 1)
        chal.status = "CASCADE_ERROR"
        chal.error = str(e)[:200]

    return chal


def solve_codex(chal: ChallengeInfo, flag_format: str, timeout: int = 480) -> ChallengeInfo:
    """Solve via Codex (GPT-5.4) with direct shell access. Best for remote pwn."""
    t0 = time.time()

    # Check codex is available
    if not shutil.which("codex"):
        chal.status = "SKIP"
        chal.error = "codex CLI not found"
        return chal

    # Build libc hint based on common CTF setups
    libc_hint = ""
    if "ubuntu" in chal.description.lower() or "24.04" in chal.description.lower():
        libc_hint = "Ubuntu 24.04 libc 2.39-0ubuntu8.2: puts=0x87bd0, system=0x58740, /bin/sh=0x1cb42f, read=0x11ba50"

    prompt = f"""You are solving a CTF pwn challenge.

Challenge directory: {chal.path}
Description: {chal.description}
Target: {chal.remote_host}:{chal.remote_port}
Flag format: {flag_format}

Instructions:
1. Run 'file' and 'checksec' on the binary in {chal.path}
2. Disassemble with 'objdump -d' to find key functions
3. Write a pwntools exploit at {chal.path}/exploit.py
4. Run: cd {chal.path} && python3 exploit.py
5. If it fails, read the error, fix, retry (max 3 attempts)
6. When you get a shell: cat /ctf/flag.txt || cat flag.txt
7. Write the flag to {chal.path}/flag.txt

{libc_hint}

Output the flag as: FLAG=<the flag>"""

    try:
        proc = subprocess.run(
            ["codex", "exec", "--dangerously-bypass-approvals-and-sandbox", prompt],
            capture_output=True, text=True, timeout=timeout,
            cwd=chal.path,
        )
        chal.elapsed = round(time.time() - t0, 1)

        # Extract flag
        output = proc.stdout + proc.stderr
        flag_file = Path(chal.path, "flag.txt")

        if flag_file.exists():
            chal.flag = flag_file.read_text().strip()
        if not chal.flag:
            m = re.search(r'FLAG=(\S+)', output)
            if m:
                chal.flag = m.group(1)
        if not chal.flag:
            # Try generic flag pattern
            fmt_prefix = re.match(r'([A-Za-z_]+)', flag_format.replace("\\{", "{"))
            if fmt_prefix:
                pat = fmt_prefix.group(1) + r'\{[^}]+\}'
                m = re.search(pat, output)
                if m:
                    chal.flag = m.group(0)

        if chal.flag:
            chal.status = "SOLVED"
            chal.tool = "codex"
            flag_file.write_text(chal.flag + "\n")
        else:
            chal.status = "FAILED"
            chal.tool = "codex"
            chal.error = f"exit={proc.returncode}"

    except subprocess.TimeoutExpired:
        chal.elapsed = round(time.time() - t0, 1)
        chal.status = "TIMEOUT"
        chal.tool = "codex"
        chal.error = f"timeout after {timeout}s"
    except Exception as e:
        chal.elapsed = round(time.time() - t0, 1)
        chal.status = "ERROR"
        chal.error = str(e)[:200]

    return chal


async def hybrid_solve(
    challenge_dir: str,
    flag_format: str = r"flag\{[^}]+\}",
    max_parallel: int = 8,
    timeout: int = 480,
) -> list[ChallengeInfo]:
    """Run the hybrid solver: classify → route → parallel solve."""

    # Step 1: Discover and classify
    challenges = discover_challenges(challenge_dir)
    if not challenges:
        print("No challenges found.")
        return []

    print("=" * 60)
    print("  HYBRID SOLVER (cascade-first, codex-fallback)")
    print("=" * 60)
    print(f"  Challenges: {len(challenges)}")
    print(f"  Flag format: {flag_format}")
    print(f"  Timeout: {timeout}s (codex fallback only)")
    print("=" * 60)
    print()

    batch_start = time.time()

    # Phase 1: Cascade ALL challenges in parallel (free, fast)
    print(f"[{time.strftime('%H:%M:%S')}] Phase 1: Cascade (all {len(challenges)} challenges)")
    cascade_tasks = []
    for chal in challenges:
        cascade_tasks.append(solve_cascade(chal, flag_format))

    cascade_results = await asyncio.gather(*cascade_tasks)

    solved_phase1 = []
    failed_phase1 = []
    for chal in cascade_results:
        if chal.status == "SOLVED":
            solved_phase1.append(chal)
            print(f"[{time.strftime('%H:%M:%S')}] [+] {chal.name} (cascade:{chal.tool}) {chal.elapsed}s → {chal.flag[:40]}")
        else:
            failed_phase1.append(chal)
            print(f"[{time.strftime('%H:%M:%S')}] · {chal.name} (cascade failed, {chal.elapsed}s)")

    phase1_elapsed = round(time.time() - batch_start, 1)
    print(f"\n[{time.strftime('%H:%M:%S')}] Phase 1 done: {len(solved_phase1)}/{len(challenges)} solved in {phase1_elapsed}s")

    # Phase 2: Codex fallback ONLY for failures
    if failed_phase1:
        print(f"\n[{time.strftime('%H:%M:%S')}] Phase 2: Codex fallback ({len(failed_phase1)} unsolved)")

        from concurrent.futures import ThreadPoolExecutor
        executor = ThreadPoolExecutor(max_workers=max_parallel)
        codex_futures = {}

        for chal in failed_phase1:
            target = f"{chal.remote_host}:{chal.remote_port}" if chal.remote_host else "local"
            print(f"[{time.strftime('%H:%M:%S')}] → {chal.name} (codex, {target})")
            future = executor.submit(solve_codex, chal, flag_format, timeout)
            codex_futures[chal.name] = future

        for name, future in codex_futures.items():
            chal = future.result()
            status_icon = "[+]" if chal.status == "SOLVED" else "[x]"
            print(f"[{time.strftime('%H:%M:%S')}] {status_icon} {chal.name} (codex) {chal.elapsed}s"
                  + (f" → {chal.flag[:40]}" if chal.flag else f" ({chal.error})"))

        executor.shutdown(wait=False)
    else:
        print(f"\n[{time.strftime('%H:%M:%S')}] All solved by cascade -- no Codex needed.")

    batch_elapsed = round(time.time() - batch_start, 1)

    # Step 3: Summary
    solved = [c for c in challenges if c.status == "SOLVED"]
    total = len(challenges)

    print()
    print("=" * 60)
    print("  RESULTS")
    print("=" * 60)
    print()
    print("| # | Challenge | Tier | Status | Flag | Engine | Time |")
    print("|---|-----------|------|--------|------|--------|------|")
    for i, c in enumerate(challenges, 1):
        flag_display = c.flag[:30] + "..." if len(c.flag) > 30 else c.flag
        print(f"| {i} | {c.name} | {c.tier} | {c.status} | {flag_display} | {c.tool} | {c.elapsed}s |")

    print()
    rate = f"{len(solved)/total*100:.0f}%" if total else "0%"
    print(f"Score: {len(solved)}/{total} ({rate}) in {batch_elapsed}s (parallel)")
    print()

    return challenges


def main():
    parser = argparse.ArgumentParser(description="Hybrid parallel CTF solver")
    parser.add_argument("challenge_dir", help="Directory containing challenge subdirectories")
    parser.add_argument("--flag-format", default=r"flag\{[^}]+\}", help="Flag format regex")
    parser.add_argument("-j", "--parallel", type=int, default=8, help="Max parallel solvers")
    parser.add_argument("--timeout", type=int, default=480, help="Per-challenge timeout (seconds)")
    args = parser.parse_args()

    results = asyncio.run(hybrid_solve(
        args.challenge_dir,
        flag_format=args.flag_format,
        max_parallel=args.parallel,
        timeout=args.timeout,
    ))

    # Exit code = number of unsolved
    unsolved = sum(1 for c in results if c.status != "SOLVED")
    sys.exit(unsolved)


if __name__ == "__main__":
    main()
