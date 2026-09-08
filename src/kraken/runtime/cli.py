"""CLI entry point for ``kraken-runtime``.

Subcommands:
  solve <challenge.json>         -- solve with KRAKEN Runtime
  resume <session-id>            -- resume a paused session
  benchmark <dir> --output <dir> -- batch benchmark
  models                         -- list available Ollama models + tier assignments
  sessions                       -- list saved sessions
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path


def _cmd_solve(args) -> int:
    """Solve a single challenge."""
    from kraken.config import KrakenConfig
    from kraken.logging.structured import configure_logging
    from kraken.runtime.kraken_runtime import KrakenRuntime

    configure_logging(json_output=args.verbose)

    config = KrakenConfig()
    config.budget.timeout_minutes = args.timeout
    config.models.backend = "ollama"
    config.runtime.provider = "kraken"

    runtime = KrakenRuntime(workspace=args.workspace)

    result = asyncio.run(runtime.solve_challenge(
        config=config,
        challenge_json_path=args.challenge,
    ))

    print(json.dumps(result, indent=2, default=str))

    if result.get("solved"):
        print(f"\nFLAG: {result['flag']}")
        return 0
    else:
        print("\nChallenge not solved.")
        return 1


def _cmd_resume(args) -> int:
    """Resume a paused session."""
    from kraken.config import KrakenConfig
    from kraken.logging.structured import configure_logging
    from kraken.runtime.kraken_runtime import KrakenRuntime

    configure_logging()

    config = KrakenConfig()
    config.models.backend = "ollama"
    config.runtime.provider = "kraken"

    runtime = KrakenRuntime(workspace=args.workspace)

    result = asyncio.run(runtime.solve_challenge(
        config=config,
        resume_session=args.session_id,
    ))

    print(json.dumps(result, indent=2, default=str))
    return 0 if result.get("solved") else 1


def _cmd_benchmark(args) -> int:
    """Run benchmark on a directory of challenges."""
    from kraken.config import KrakenConfig
    from kraken.logging.structured import configure_logging
    from kraken.runtime.kraken_runtime import KrakenRuntime

    configure_logging(json_output=args.verbose)

    config = KrakenConfig()
    config.models.backend = "ollama"
    config.runtime.provider = "kraken"

    runtime = KrakenRuntime(workspace=args.workspace)

    result = asyncio.run(runtime.benchmark(
        challenges_dir=args.directory,
        output_dir=args.output,
        config=config,
        timeout_minutes=args.timeout,
    ))

    print(json.dumps(result, indent=2, default=str))
    return 0 if result.get("solved", 0) > 0 else 1


def _cmd_models(args) -> int:
    """List available Ollama models and tier assignments."""
    from kraken.config import KrakenConfig
    from kraken.runtime.kraken_runtime import KrakenRuntime

    config = KrakenConfig()
    runtime = KrakenRuntime(workspace=args.workspace)

    asyncio.run(runtime.initialize(config))
    print(runtime.list_models())
    return 0


def _cmd_sessions(args) -> int:
    """List saved sessions."""
    from kraken.runtime.session import SessionManager
    import time

    sm = SessionManager(args.workspace)
    sessions = sm.list_sessions()

    if not sessions:
        print("No saved sessions found.")
        return 0

    print(f"{'ID':<10s} {'Challenge':<20s} {'Status':<12s} {'Checkpoints':<12s} {'Updated'}")
    print("-" * 70)
    for s in sessions:
        updated = time.strftime("%Y-%m-%d %H:%M", time.localtime(s["updated_at"])) if s["updated_at"] else "?"
        print(f"{s['session_id']:<10s} {s['challenge_id']:<20s} {s['status']:<12s} {s['checkpoints']:<12d} {updated}")

    return 0


def main():
    """CLI entry point for kraken-runtime."""
    parser = argparse.ArgumentParser(
        description="KRAKEN Runtime -- Intelligent Offline CTF Solver",
        prog="kraken-runtime",
    )
    parser.add_argument("--workspace", default=".", help="Workspace directory (default: cwd)")

    subparsers = parser.add_subparsers(dest="command")

    # solve
    solve_p = subparsers.add_parser("solve", help="Solve a challenge with KRAKEN Runtime")
    solve_p.add_argument("challenge", help="Path to challenge JSON config")
    solve_p.add_argument("--timeout", type=int, default=30, help="Timeout in minutes (default: 30)")
    solve_p.add_argument("--verbose", action="store_true", help="Verbose JSON logging")

    # resume
    resume_p = subparsers.add_parser("resume", help="Resume a paused session")
    resume_p.add_argument("session_id", help="Session ID to resume")

    # benchmark
    bench_p = subparsers.add_parser("benchmark", help="Batch benchmark challenges")
    bench_p.add_argument("directory", help="Directory containing challenges")
    bench_p.add_argument("--output", default=None, help="Output directory for results")
    bench_p.add_argument("--timeout", type=int, default=30, help="Per-challenge timeout in minutes")
    bench_p.add_argument("--verbose", action="store_true", help="Verbose JSON logging")

    # models
    subparsers.add_parser("models", help="List available Ollama models + tier assignments")

    # sessions
    subparsers.add_parser("sessions", help="List saved sessions")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    commands = {
        "solve": _cmd_solve,
        "resume": _cmd_resume,
        "benchmark": _cmd_benchmark,
        "models": _cmd_models,
        "sessions": _cmd_sessions,
    }

    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
