"""Kraken CTF Autopilot -- fully autonomous jeopardy CTF solver.

Connects to a live CTFd instance, downloads challenges, solves them using
the KRAKEN graph, and submits flags automatically.  Supports parallel
execution, live scoreboard monitoring, and automatic trajectory ingestion
for future RAG retrieval.

Usage:
    kraken-autopilot --url https://ctf.example.com --token API_TOKEN
    python3 -m kraken.execution.autopilot --url https://ctf.example.com --token API_TOKEN

Options:
    --concurrent N    Max parallel solves (default: 3)
    --timeout N       Timeout per challenge in seconds (default: 600)
    --monitor         Keep watching for new challenges after initial pass
    --category web    Filter by category (repeatable)
    --backend ollama  LLM backend (default: ollama)
    --model MODEL     LLM model tag (default: gpt-oss-20b-131k:latest)
    --dry-run         Download and solve but do NOT submit flags
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import shutil
import signal
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from kraken.platform.ctfd import CTFdClient
from kraken.state import initial_state
from kraken.graph import build_graph
from kraken.logging.structured import get_logger

log = get_logger(__name__)


# ── Utilities ────────────────────────────────────────────────────────────────


def _ts() -> str:
    """ISO-8601 timestamp for console output."""
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def _guess_flag_format(challenge: dict[str, Any]) -> str:
    """Infer a flag regex from challenge metadata.

    Checks the description for an explicit format declaration, then falls back
    to common CTF prefixes, then to a generic ``flag{...}`` pattern.
    """
    desc = challenge.get("description", "") or ""
    tags = [t.lower() for t in challenge.get("tags", [])]
    name = challenge.get("name", "").lower()

    # 1. Explicit flag format in description: "flag format: PREFIX{"
    fmt_match = re.search(r"flag\s*format[:\s]+(\w+)\{", desc, re.IGNORECASE)
    if fmt_match:
        prefix = fmt_match.group(1)
        return re.escape(prefix) + r"\{[^}]+\}"

    # 2. Look for PREFIX{...} pattern directly in description
    prefix_match = re.search(r"\b([A-Za-z][A-Za-z0-9_]{1,20})\{[^}]*\}", desc)
    if prefix_match:
        prefix = prefix_match.group(1)
        return re.escape(prefix) + r"\{[^}]+\}"

    # 3. Common CTF competition prefixes (check tags first, then desc)
    common_prefixes = [
        "flag", "ctf", "FLAG", "CTF", "picoCTF", "HTB",
        "ractf", "hsctf", "uiuctf", "lactf", "bcactf",
    ]
    combined = " ".join([desc.lower()] + tags + [name])
    for prefix in common_prefixes:
        if prefix.lower() in combined:
            return re.escape(prefix) + r"\{[^}]+\}"

    # 4. Fallback
    return r"flag\{[^}]+\}"


def _category_map(raw: str) -> str:
    """Normalize CTFd category strings to Kraken category codes."""
    mapping: dict[str, str] = {
        "reverse engineering": "rev",
        "reverse": "rev",
        "reversing": "rev",
        "rev": "rev",
        "binary exploitation": "pwn",
        "binary": "pwn",
        "exploitation": "pwn",
        "pwn": "pwn",
        "web": "web",
        "web exploitation": "web",
        "cryptography": "crypto",
        "crypto": "crypto",
        "forensics": "forensics",
        "misc": "misc",
        "miscellaneous": "misc",
        "osint": "misc",
        "steganography": "forensics",
        "stego": "forensics",
        "hardware": "misc",
        "blockchain": "crypto",
        "network": "forensics",
    }
    key = raw.strip().lower()
    return mapping.get(key, key[:12] or "misc")


# ── Prioritization ──────────────────────────────────────────────────────────


def prioritize(challenges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sort unsolved challenges by estimated ease.

    Primary: most-solved first (community signal for easiest).
    Secondary: lowest point value first (often correlates with difficulty).
    """
    return sorted(
        challenges,
        key=lambda c: (-c.get("solves", 0), c.get("value", 0)),
    )


# ── Single challenge solver ────────────────────────────────────────────────


async def solve_challenge(
    client: CTFdClient,
    challenge: dict[str, Any],
    work_dir: str,
    *,
    backend: str = "ollama",
    model: str = "gpt-oss-20b-131k:latest",
    dry_run: bool = False,
) -> dict[str, Any]:
    """Download, solve, and optionally submit for one challenge.

    Returns a result dict with keys: solved, flag, submit, error, elapsed_s.
    """
    chal_id = challenge["id"]
    chal_name = challenge["name"]
    chal_dir = os.path.join(work_dir, f"{chal_id}_{re.sub(r'[^A-Za-z0-9_-]', '_', chal_name)}")
    os.makedirs(chal_dir, exist_ok=True)

    t0 = time.monotonic()
    result: dict[str, Any] = {
        "solved": False,
        "flag": "",
        "submit": {},
        "error": "",
        "elapsed_s": 0.0,
        "challenge_id": chal_id,
        "challenge_name": chal_name,
    }

    try:
        # 1. Download challenge files
        log.info("download_start", challenge=chal_name, chal_id=chal_id)
        try:
            files = client.download_challenge_files(chal_id, chal_dir)
            log.info("download_done", challenge=chal_name, files=len(files))
        except Exception as exc:
            log.warning("download_failed", challenge=chal_name, error=str(exc))
            files = []

        # If no files, write description to a file so triage can still work
        desc = challenge.get("description", "")
        if not files and desc:
            desc_path = os.path.join(chal_dir, "challenge_description.txt")
            Path(desc_path).write_text(desc)
            files = [desc_path]

        # 2. Set environment for backend/model
        os.environ["KRAKEN_BACKEND"] = backend
        os.environ["KRAKEN_MODEL_HIGH"] = model
        os.environ["KRAKEN_MODEL_MID"] = model
        os.environ["KRAKEN_MODEL_LOW"] = model

        # 3. Build initial state
        flag_format = _guess_flag_format(challenge)
        category = _category_map(challenge.get("category", "misc"))

        # Determine challenge_path: use first file if only one, else directory
        if len(files) == 1:
            challenge_path = files[0]
        else:
            challenge_path = chal_dir

        state = initial_state(
            challenge_id=chal_name,
            challenge_path=challenge_path,
            description=desc,
            flag_format=flag_format,
            category=category,
            benchmark=False,
            solve_workspace=os.path.join(chal_dir, "workspace"),
        )

        # Inject description explicitly (initial_state uses challenge_description)
        state["challenge_description"] = desc

        # 4. Build and run the graph
        log.info("solve_start", challenge=chal_name, category=category, flag_format=flag_format)
        graph = build_graph()
        graph_result = await graph.ainvoke(
            state,
            config={"configurable": {"thread_id": f"autopilot_{chal_id}_{int(time.time())}"}},
        )

        # 5. Extract flag
        flag = (
            graph_result.get("flag")
            or graph_result.get("tool_flag_candidate")
            or ""
        )

        if flag:
            result["flag"] = flag
            result["solved"] = True
            log.info("flag_found", challenge=chal_name, flag=flag)

            # 6. Submit flag (unless dry-run)
            if not dry_run:
                try:
                    submit_result = client.submit_flag(chal_id, flag)
                    result["submit"] = submit_result
                    status = submit_result.get("status", "unknown")
                    log.info("flag_submitted", challenge=chal_name, status=status,
                             message=submit_result.get("message", ""))

                    # If incorrect, try alternate flag formats from state
                    if status == "incorrect":
                        result["solved"] = False
                        # Check rejected_flags for other candidates
                        for alt_flag in graph_result.get("rejected_flags", []):
                            if alt_flag and alt_flag != flag:
                                alt_result = client.submit_flag(chal_id, alt_flag)
                                if alt_result.get("status") == "correct":
                                    result["flag"] = alt_flag
                                    result["solved"] = True
                                    result["submit"] = alt_result
                                    break
                except Exception as exc:
                    log.error("submit_failed", challenge=chal_name, error=str(exc))
                    result["submit"] = {"status": "error", "message": str(exc)}
        else:
            log.info("no_flag", challenge=chal_name)

        # Record trajectory information for RAG ingestion
        result["graph_state"] = {
            k: graph_result.get(k)
            for k in (
                "challenge_id", "challenge_type", "category", "flag",
                "flag_format", "solve_path", "iteration_count",
                "strategies_tried", "tool_cascade_results",
                "tool_results_summary", "binary_info",
                "strings_of_interest", "extracted_params",
                "secondary_types", "elapsed_seconds",
                "tool_flag_candidate", "flag_found",
            )
            if graph_result.get(k)
        }

    except Exception as exc:
        log.error("solve_error", challenge=chal_name, error=str(exc))
        result["error"] = str(exc)

    result["elapsed_s"] = round(time.monotonic() - t0, 1)
    return result


# ── Trajectory ingestion ────────────────────────────────────────────────────


def _try_ingest_trajectory(result: dict[str, Any]) -> None:
    """Best-effort ingest of a solve trajectory into Qdrant.

    Silently ignores failures (Qdrant offline, import errors, etc).
    """
    try:
        from kraken.knowledge.trajectory import TrajectoryStore

        store = TrajectoryStore()
        if not store.available:
            return

        graph_state = result.get("graph_state", {})
        if not graph_state:
            return

        if result.get("solved"):
            store.record_solve(graph_state, ground_truth_flag=result.get("flag", ""))
        else:
            failure_type = "timeout" if result.get("timeout") else "unsolved"
            store.record_failure(graph_state, failure_type=failure_type)

    except Exception:
        pass  # Best-effort


# ── Main autopilot loop ────────────────────────────────────────────────────


async def run_autopilot(
    url: str,
    token: str,
    *,
    max_concurrent: int = 3,
    timeout_per: int = 600,
    monitor: bool = False,
    monitor_interval: int = 300,
    categories: list[str] | None = None,
    backend: str = "ollama",
    model: str = "gpt-oss-20b-131k:latest",
    dry_run: bool = False,
) -> dict[str, Any]:
    """Run the full autopilot loop.

    1. Connect to CTFd and list challenges
    2. Filter + prioritize unsolved ones
    3. Solve concurrently with a semaphore
    4. Submit flags
    5. Optionally monitor for new challenges

    Returns aggregate results dict.
    """
    # -- Connect --
    print(f"[{_ts()}] Kraken Autopilot starting")
    print(f"[{_ts()}] Target: {url}")
    print(f"[{_ts()}] Backend: {backend} / {model}")
    print(f"[{_ts()}] Concurrency: {max_concurrent} | Timeout: {timeout_per}s")
    if dry_run:
        print(f"[{_ts()}] DRY-RUN mode: flags will NOT be submitted")
    print()

    try:
        client = CTFdClient(url=url, token=token)
    except Exception as exc:
        print(f"[{_ts()}] ERROR: Failed to connect to CTFd: {exc}")
        return {"error": str(exc)}

    # -- Fetch challenges --
    try:
        all_challenges = client.list_challenges()
    except Exception as exc:
        print(f"[{_ts()}] ERROR: Failed to list challenges: {exc}")
        return {"error": str(exc)}

    print(f"[{_ts()}] Found {len(all_challenges)} total challenges")

    # -- Filter by category --
    if categories:
        cat_set = {c.lower() for c in categories}
        all_challenges = [
            c for c in all_challenges
            if c.get("category", "").lower() in cat_set
        ]
        print(f"[{_ts()}] Filtered to {len(all_challenges)} challenges in categories: {', '.join(categories)}")

    # -- Separate solved/unsolved --
    unsolved = [c for c in all_challenges if not c.get("solved_by_me")]
    already_solved = len(all_challenges) - len(unsolved)

    print(f"[{_ts()}] Already solved: {already_solved}")
    print(f"[{_ts()}] Unsolved: {len(unsolved)}")

    if not unsolved:
        print(f"[{_ts()}] Nothing to solve!")
        return {"total": len(all_challenges), "already_solved": already_solved, "solved": 0}

    # -- Prioritize --
    unsolved = prioritize(unsolved)

    print(f"\n{'='*70}")
    print(f"  CHALLENGE QUEUE ({len(unsolved)} challenges)")
    print(f"{'='*70}")
    for i, c in enumerate(unsolved, 1):
        print(f"  {i:3d}. [{c.get('category', '?'):10s}] {c['name']:<40s} "
              f"{c.get('value', 0):4d}pts  ({c.get('solves', 0)} solves)")
    print(f"{'='*70}\n")

    # -- Scoreboard snapshot --
    try:
        my_score = client.get_my_score()
        print(f"[{_ts()}] Current score: {my_score.get('score', 0)} | "
              f"Rank: {my_score.get('place', '?')}")
    except Exception:
        pass

    # -- Work directory --
    work_dir = tempfile.mkdtemp(prefix="kraken_autopilot_")
    print(f"[{_ts()}] Work directory: {work_dir}\n")

    # -- State tracking --
    results: dict[str, dict[str, Any]] = {}
    attempted: set[str] = set()
    sem = asyncio.Semaphore(max_concurrent)

    async def solve_with_sem(challenge: dict[str, Any]) -> None:
        """Solve a single challenge under the concurrency semaphore."""
        chal_name = challenge["name"]
        attempted.add(chal_name)

        async with sem:
            print(f"[{_ts()}] >>> STARTING: {chal_name} "
                  f"[{challenge.get('category', '?')}] "
                  f"({challenge.get('value', 0)}pts)")

            try:
                result = await asyncio.wait_for(
                    solve_challenge(
                        client, challenge, work_dir,
                        backend=backend, model=model, dry_run=dry_run,
                    ),
                    timeout=timeout_per,
                )
            except asyncio.TimeoutError:
                result = {
                    "solved": False,
                    "flag": "",
                    "error": f"Timeout after {timeout_per}s",
                    "timeout": True,
                    "elapsed_s": timeout_per,
                    "challenge_name": chal_name,
                    "challenge_id": challenge["id"],
                }
                print(f"[{_ts()}]  TIMEOUT: {chal_name} (>{timeout_per}s)")
            except Exception as exc:
                result = {
                    "solved": False,
                    "flag": "",
                    "error": str(exc),
                    "elapsed_s": 0,
                    "challenge_name": chal_name,
                    "challenge_id": challenge["id"],
                }
                print(f"[{_ts()}]  ERROR: {chal_name}: {exc}")

            results[chal_name] = result

            if result.get("solved"):
                submit_status = result.get("submit", {}).get("status", "")
                submit_info = f" [{submit_status}]" if submit_status else ""
                print(f"[{_ts()}]  SOLVED: {chal_name} -> {result['flag']}{submit_info} "
                      f"({result.get('elapsed_s', 0):.0f}s)")
            elif not result.get("timeout"):
                print(f"[{_ts()}]  FAILED: {chal_name} ({result.get('elapsed_s', 0):.0f}s)")

            # Ingest trajectory (best-effort)
            _try_ingest_trajectory(result)

            # Periodic scoreboard update
            _print_progress(client, results, len(unsolved))

    # -- Launch all solves --
    tasks = [asyncio.create_task(solve_with_sem(c)) for c in unsolved]
    await asyncio.gather(*tasks, return_exceptions=True)

    # -- Post-first-pass summary --
    _print_summary(results, len(unsolved))

    # -- Scoreboard after first pass --
    try:
        my_score = client.get_my_score()
        print(f"  Final score: {my_score.get('score', 0)} | "
              f"Rank: {my_score.get('place', '?')}")
    except Exception:
        pass

    # -- Monitor loop --
    if monitor:
        print(f"\n[{_ts()}] Entering monitor mode (checking every {monitor_interval}s)")
        print(f"[{_ts()}] Press Ctrl+C to stop\n")

        stop_event = asyncio.Event()

        def _sig_handler(sig, frame):
            stop_event.set()

        signal.signal(signal.SIGINT, _sig_handler)
        signal.signal(signal.SIGTERM, _sig_handler)

        while not stop_event.is_set():
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=monitor_interval)
                break  # Event was set
            except asyncio.TimeoutError:
                pass  # Normal: interval elapsed, check for new challenges

            try:
                fresh_challenges = client.list_challenges()
                if categories:
                    cat_set = {c.lower() for c in categories}
                    fresh_challenges = [
                        c for c in fresh_challenges
                        if c.get("category", "").lower() in cat_set
                    ]

                new_unsolved = [
                    c for c in fresh_challenges
                    if not c.get("solved_by_me")
                    and c["name"] not in attempted
                ]

                if new_unsolved:
                    print(f"\n[{_ts()}] NEW CHALLENGES DETECTED: "
                          f"{[c['name'] for c in new_unsolved]}")
                    new_unsolved = prioritize(new_unsolved)
                    new_tasks = [
                        asyncio.create_task(solve_with_sem(c))
                        for c in new_unsolved
                    ]
                    await asyncio.gather(*new_tasks, return_exceptions=True)
                    _print_summary(results, len(attempted))
                else:
                    print(f"[{_ts()}] No new challenges (checked {len(fresh_challenges)} total)")

            except Exception as exc:
                print(f"[{_ts()}] Monitor check failed: {exc}")

    # -- Cleanup --
    try:
        shutil.rmtree(work_dir, ignore_errors=True)
        log.info("cleanup_done", work_dir=work_dir)
    except Exception:
        pass

    # -- Save results to JSON --
    results_file = f"autopilot_results_{int(time.time())}.json"
    try:
        serializable = {}
        for name, r in results.items():
            entry = {k: v for k, v in r.items() if k != "graph_state"}
            serializable[name] = entry
        Path(results_file).write_text(json.dumps(serializable, indent=2, default=str))
        print(f"\n  Results saved to: {results_file}")
    except Exception:
        pass

    solved_count = sum(1 for r in results.values() if r.get("solved"))
    return {
        "total": len(all_challenges),
        "attempted": len(attempted),
        "solved": solved_count,
        "failed": len(attempted) - solved_count,
        "results": {k: {"solved": v.get("solved"), "flag": v.get("flag", "")}
                    for k, v in results.items()},
    }


# ── Output helpers ──────────────────────────────────────────────────────────


def _print_progress(
    client: CTFdClient,
    results: dict[str, dict[str, Any]],
    total_unsolved: int,
) -> None:
    """Print a compact progress line."""
    solved = sum(1 for r in results.values() if r.get("solved"))
    failed = sum(1 for r in results.values() if not r.get("solved"))
    remaining = total_unsolved - len(results)

    parts = [f"Progress: {solved} solved"]
    if failed:
        parts.append(f"{failed} failed")
    if remaining > 0:
        parts.append(f"{remaining} remaining")

    try:
        score = client.get_my_score()
        parts.append(f"Score: {score.get('score', 0)} (#{score.get('place', '?')})")
    except Exception:
        pass

    print(f"[{_ts()}]  {' | '.join(parts)}")


def _print_summary(results: dict[str, dict[str, Any]], total: int) -> None:
    """Print final summary table."""
    solved = sum(1 for r in results.values() if r.get("solved"))
    failed = sum(1 for r in results.values() if not r.get("solved") and not r.get("timeout"))
    timed_out = sum(1 for r in results.values() if r.get("timeout"))
    total_time = sum(r.get("elapsed_s", 0) for r in results.values())

    print(f"\n{'='*70}")
    print(f"  AUTOPILOT RESULTS")
    print(f"{'='*70}")
    print(f"  Solved:    {solved}/{total}")
    print(f"  Failed:    {failed}")
    print(f"  Timed out: {timed_out}")
    print(f"  Total time: {total_time:.0f}s ({total_time/60:.1f}min)")
    print(f"{'='*70}")

    # Detail table
    if results:
        print(f"\n  {'Challenge':<40s} {'Status':<10s} {'Flag':<30s} {'Time':>6s}")
        print(f"  {'-'*40} {'-'*10} {'-'*30} {'-'*6}")
        for name, r in sorted(results.items()):
            if r.get("solved"):
                status = "SOLVED"
                flag = r.get("flag", "")[:28]
            elif r.get("timeout"):
                status = "TIMEOUT"
                flag = ""
            else:
                status = "FAILED"
                flag = ""
            elapsed = f"{r.get('elapsed_s', 0):.0f}s"
            print(f"  {name:<40s} {status:<10s} {flag:<30s} {elapsed:>6s}")

    print(f"{'='*70}")


# ── CLI ──────────────────────────────────────────────────────────────────────


def main() -> None:
    """CLI entry point for Kraken Autopilot."""
    parser = argparse.ArgumentParser(
        prog="kraken-autopilot",
        description="Kraken CTF Autopilot -- autonomous jeopardy CTF solver",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  kraken-autopilot --url https://ctf.example.com --token abc123
  kraken-autopilot --url https://ctf.example.com --token abc123 --category web crypto
  kraken-autopilot --url https://ctf.example.com --token abc123 --monitor --concurrent 5
  kraken-autopilot --url https://ctf.example.com --token abc123 --dry-run
""",
    )

    parser.add_argument(
        "--url", required=True,
        help="CTFd instance URL (e.g., https://ctf.example.com)",
    )
    parser.add_argument(
        "--token", required=True,
        help="CTFd API token (from Settings > Access Tokens)",
    )
    parser.add_argument(
        "--concurrent", type=int, default=3,
        help="Maximum number of parallel solves (default: 3)",
    )
    parser.add_argument(
        "--timeout", type=int, default=600,
        help="Timeout per challenge in seconds (default: 600)",
    )
    parser.add_argument(
        "--monitor", action="store_true",
        help="After initial pass, keep watching for new challenges",
    )
    parser.add_argument(
        "--monitor-interval", type=int, default=300,
        help="Seconds between new-challenge checks in monitor mode (default: 300)",
    )
    parser.add_argument(
        "--category", nargs="*", default=None,
        help="Filter by challenge category (e.g., --category web crypto rev)",
    )
    parser.add_argument(
        "--backend", default="ollama",
        help="LLM backend: ollama, claude, anthropic, openai (default: ollama)",
    )
    parser.add_argument(
        "--model", default="gpt-oss-20b-131k:latest",
        help="LLM model tag (default: gpt-oss-20b-131k:latest)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Solve challenges but do NOT submit flags to CTFd",
    )

    args = parser.parse_args()

    # Banner
    print(r"""
    ╔═══════════════════════════════════════════════════════════╗
    ║   KRAKEN AUTOPILOT  --  Autonomous CTF Competition Mode   ║
    ╚═══════════════════════════════════════════════════════════╝
    """)

    try:
        aggregate = asyncio.run(
            run_autopilot(
                url=args.url,
                token=args.token,
                max_concurrent=args.concurrent,
                timeout_per=args.timeout,
                monitor=args.monitor,
                monitor_interval=args.monitor_interval,
                categories=args.category,
                backend=args.backend,
                model=args.model,
                dry_run=args.dry_run,
            )
        )
    except KeyboardInterrupt:
        print(f"\n[{_ts()}] Interrupted by user")
        sys.exit(130)

    # Exit code: 0 if at least one solve, 1 otherwise
    if aggregate.get("solved", 0) > 0:
        sys.exit(0)
    elif aggregate.get("error"):
        sys.exit(2)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
