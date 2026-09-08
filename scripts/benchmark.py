#!/usr/bin/env python3
"""Benchmark runner for KRAKEN against CTFTiny or local challenges."""
import asyncio
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from kraken.orchestrator import Orchestrator
from kraken.config import KrakenConfig
from kraken.logging.structured import configure_logging


async def run_benchmark(challenges_dir: str, max_cost: float = 3.0):
    configure_logging(json_output=False)
    config = KrakenConfig()
    config.budget.max_cost_usd = max_cost

    challenges_path = Path(challenges_dir)
    results = []

    for challenge_dir in sorted(challenges_path.iterdir()):
        config_file = challenge_dir / "challenge.json"
        if not config_file.exists():
            continue

        challenge_config = json.loads(config_file.read_text())
        challenge_config["benchmark"] = True  # disable RAG retrieval + trajectory storage
        print(f"\n{'='*60}")
        print(f"Challenge: {challenge_config['challenge_id']}")
        print(f"{'='*60}")

        orchestrator = Orchestrator(config=config)
        start = time.monotonic()

        try:
            result = await orchestrator.solve(challenge_config)
        except Exception as e:
            result = {"solved": False, "flag": "", "cost_usd": 0, "error": str(e),
                      "challenge_id": challenge_config["challenge_id"]}

        result["wall_time"] = round(time.monotonic() - start, 1)
        results.append(result)

        status = "SOLVED" if result.get("solved") else "FAILED"
        print(f"  Status: {status}")
        print(f"  Cost: ${result.get('cost_usd', 0):.4f}")
        print(f"  Time: {result.get('wall_time', 0):.1f}s")
        if result.get("flag"):
            print(f"  Flag: {result['flag']}")

    # Summary
    solved = sum(1 for r in results if r.get("solved"))
    total = len(results)
    total_cost = sum(r.get("cost_usd", 0) for r in results)

    print(f"\n{'='*60}")
    print(f"BENCHMARK RESULTS: {solved}/{total} solved")
    print(f"Total cost: ${total_cost:.4f}")
    print(f"{'='*60}")

    # Save results
    output_path = Path(challenges_dir) / "benchmark_results.json"
    output_path.write_text(json.dumps(results, indent=2))
    print(f"Results saved to {output_path}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="KRAKEN Benchmark")
    parser.add_argument("challenges_dir", help="Path to challenges directory")
    parser.add_argument("--max-cost", type=float, default=3.0)
    args = parser.parse_args()

    asyncio.run(run_benchmark(args.challenges_dir, args.max_cost))


if __name__ == "__main__":
    main()
