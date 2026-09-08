"""Store and retrieve solution trajectories for learning.

Records both successful solves and failures into Qdrant so that similar
challenges can be found and tool recommendations can be generated.

CLI mode:
    python3 -m kraken.knowledge.trajectory --ingest <results_dir>
    python3 -m kraken.knowledge.trajectory --stats
    python3 -m kraken.knowledge.trajectory --search <challenge_json>
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

from .embeddings import embed_challenge, embed_challenge_compact
from .qdrant_store import KrakenQdrant

logger = logging.getLogger(__name__)


class TrajectoryStore:
    """Stores solved challenge trajectories and finds similar challenges.

    Gracefully degrades if Qdrant is unreachable -- all public methods
    return empty results or silently skip writes.
    """

    def __init__(self) -> None:
        try:
            self.qdrant = KrakenQdrant()
            self.available = True
            logger.info("TrajectoryStore connected to Qdrant")
        except Exception as exc:
            logger.info("Qdrant unavailable, TrajectoryStore in offline mode: %s", exc)
            self.qdrant = None  # type: ignore[assignment]
            self.available = False

    # ------------------------------------------------------------------
    # Record solves & failures
    # ------------------------------------------------------------------

    def record_solve(self, state: dict[str, Any], ground_truth_flag: str = "") -> bool:
        """Record a successful solve for future retrieval.

        Returns True if the trajectory was stored successfully.
        """
        if not self.available:
            return False

        features = embed_challenge(state)

        # Determine which tool found the flag -- multi-source extraction
        solving_tool = _resolve_solving_tool(state)

        payload: dict[str, Any] = {
            "challenge_id": state.get("challenge_id", ""),
            "challenge_type": state.get("challenge_type", ""),
            "category": state.get("category", ""),
            "flag": state.get("flag", "") or state.get("flag_found", ""),
            "ground_truth_flag": ground_truth_flag,
            "solving_tool": solving_tool,
            "solve_path": state.get("solve_path", []),
            "elapsed_seconds": state.get("elapsed_seconds", 0),
            "iteration_count": state.get("iteration_count", 0),
            "strategies_tried": state.get("strategies_tried", []),
            "tool_results_summary": str(state.get("tool_results_summary", ""))[:500],
            "binary_info_summary": _summarize_binary_info(state.get("binary_info") or {}),
            "flag_format": state.get("flag_format", ""),
            "timestamp": time.time(),
            "solved": True,
        }

        challenge_id = state.get("challenge_id", "unknown")
        success = self.qdrant.store_trajectory(
            challenge_id=challenge_id,
            features=features,
            payload=payload,
        )

        # Also store tool performance data
        if solving_tool:
            compact_features = embed_challenge_compact(state)
            self.qdrant.store_tool_performance(
                tool_name=solving_tool,
                challenge_id=challenge_id,
                features=compact_features,
                payload={
                    "tool_name": solving_tool,
                    "challenge_id": challenge_id,
                    "challenge_type": state.get("challenge_type", ""),
                    "category": state.get("category", ""),
                    "success": True,
                    "elapsed_seconds": state.get("elapsed_seconds", 0),
                    "timestamp": time.time(),
                },
            )

        if success:
            logger.info("Recorded solve trajectory for %s (tool: %s)", challenge_id, solving_tool)
        return success

    def record_failure(self, state: dict[str, Any], failure_type: str = "") -> bool:
        """Record a failed solve attempt for learning.

        Returns True if the trajectory was stored.
        """
        if not self.available:
            return False

        features = embed_challenge(state)

        # Collect tools that produced some output
        tools_with_output: list[str] = []
        all_tools_tried: list[str] = []
        for result in (state.get("tool_cascade_results") or []):
            if isinstance(result, dict):
                tool = result.get("tool", "")
                if tool:
                    all_tools_tried.append(tool)
                    if result.get("stdout") or result.get("output"):
                        tools_with_output.append(tool)

        payload: dict[str, Any] = {
            "challenge_id": state.get("challenge_id", ""),
            "challenge_type": state.get("challenge_type", ""),
            "category": state.get("category", ""),
            "failure_type": failure_type,
            "strategies_tried": state.get("strategies_tried", []),
            "tools_tried": all_tools_tried,
            "tools_with_output": tools_with_output,
            "solve_path": state.get("solve_path", []),
            "elapsed_seconds": state.get("elapsed_seconds", 0),
            "iteration_count": state.get("iteration_count", 0),
            "failure_diagnosis": str(state.get("failure_diagnosis", ""))[:500],
            "binary_info_summary": _summarize_binary_info(state.get("binary_info") or {}),
            "flag_format": state.get("flag_format", ""),
            "rejected_flags": state.get("rejected_flags", []),
            "timestamp": time.time(),
            "solved": False,
        }

        challenge_id = f"fail_{state.get('challenge_id', 'unknown')}"
        success = self.qdrant.store_trajectory(
            challenge_id=challenge_id,
            features=features,
            payload=payload,
        )

        if success:
            logger.info("Recorded failure trajectory for %s (%s)", challenge_id, failure_type)
        return success

    def record_tool_performance(self, tool_name: str, state: dict[str, Any], success: bool, elapsed: float) -> bool:
        """Record per-tool performance for tool selection optimization.

        Returns True if the record was stored successfully.
        """
        if not self.available:
            return False

        try:
            features = embed_challenge_compact(state)
            challenge_id = state.get("challenge_id", "unknown")
            return self.qdrant.store_tool_performance(
                tool_name=tool_name,
                challenge_id=challenge_id,
                features=features,
                payload={
                    "tool_name": tool_name,
                    "challenge_id": challenge_id,
                    "challenge_type": state.get("challenge_type", ""),
                    "category": state.get("category", ""),
                    "success": success,
                    "elapsed_seconds": elapsed,
                    "timestamp": time.time(),
                },
            )
        except Exception as exc:
            logger.warning("Failed to record tool performance for %s: %s", tool_name, exc)
            return False

    # ------------------------------------------------------------------
    # Similarity search
    # ------------------------------------------------------------------

    def find_similar_solved(self, state: dict[str, Any], limit: int = 3) -> list[dict[str, Any]]:
        """Find similar previously-solved challenges.

        Returns list of dicts with keys: id, score, payload.
        Only returns challenges that were solved successfully.
        """
        if not self.available:
            return []

        features = embed_challenge(state)
        results = self.qdrant.find_similar(features, limit=limit * 2)  # Fetch extra, filter below

        # Filter to only solved challenges
        solved = [r for r in results if r.get("payload", {}).get("solved", True)]
        return solved[:limit]

    def find_similar_failed(self, state: dict[str, Any], limit: int = 3) -> list[dict[str, Any]]:
        """Find similar previously-failed challenges.

        Useful for avoiding strategies that are known not to work.
        """
        if not self.available:
            return []

        features = embed_challenge(state)
        results = self.qdrant.find_similar(features, limit=limit * 2)

        # Filter to only failed challenges
        failed = [r for r in results if not r.get("payload", {}).get("solved", True)]
        return failed[:limit]

    # ------------------------------------------------------------------
    # Tool recommendation
    # ------------------------------------------------------------------

    def get_tool_recommendation(self, state: dict[str, Any]) -> list[str]:
        """Recommend tools based on similar solved challenges.

        Returns tool names sorted by frequency in similar solves
        (most common first).
        """
        similar = self.find_similar_solved(state, limit=5)

        tool_counts: dict[str, int] = {}
        for s in similar:
            tool = s.get("payload", {}).get("solving_tool", "")
            if tool:
                tool_counts[tool] = tool_counts.get(tool, 0) + 1

        return sorted(tool_counts.keys(), key=lambda t: tool_counts[t], reverse=True)

    def get_avoidance_list(self, state: dict[str, Any]) -> list[str]:
        """Get strategies to avoid based on similar failed challenges.

        Returns strategies that consistently failed on similar challenges.
        """
        failed = self.find_similar_failed(state, limit=5)

        failed_strategies: dict[str, int] = {}
        for f in failed:
            for strat in f.get("payload", {}).get("strategies_tried", []):
                if strat:
                    failed_strategies[strat] = failed_strategies.get(strat, 0) + 1

        # Only return strategies that failed multiple times
        return [s for s, c in failed_strategies.items() if c >= 2]

    # ------------------------------------------------------------------
    # Bulk ingestion from benchmark results
    # ------------------------------------------------------------------

    def ingest_results_dir(self, results_dir: str | Path) -> dict[str, int]:
        """Bulk-import past solve results from a benchmark run directory.

        Expects structure:
            results_dir/
                summary.json
                challenges/
                    challenge1.json
                    challenge2.json
                    ...

        Returns dict with counts: {"ingested": N, "skipped": N, "errors": N}
        """
        results_path = Path(results_dir)
        stats = {"ingested": 0, "skipped": 0, "errors": 0}

        if not self.available:
            logger.warning("Qdrant unavailable, cannot ingest results")
            return stats

        # Try to load summary.json for additional metadata
        summary: dict[str, Any] = {}
        summary_path = results_path / "summary.json"
        if summary_path.exists():
            try:
                summary = json.loads(summary_path.read_text())
            except (json.JSONDecodeError, OSError):
                pass

        # Build a lookup from summary results for extra fields
        summary_lookup: dict[str, dict[str, Any]] = {}
        for r in summary.get("results", []):
            cid = r.get("challenge_id", "")
            if cid:
                summary_lookup[cid] = r

        # Process individual challenge result files
        challenges_dir = results_path / "challenges"
        if not challenges_dir.is_dir():
            logger.warning("No challenges/ directory in %s", results_dir)
            return stats

        for challenge_file in sorted(challenges_dir.glob("*.json")):
            try:
                data = json.loads(challenge_file.read_text())
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Failed to read %s: %s", challenge_file, exc)
                stats["errors"] += 1
                continue

            challenge_id = data.get("challenge_id", challenge_file.stem)

            # Merge with summary data if available
            extra = summary_lookup.get(challenge_id, {})
            merged = {**extra, **data}  # data takes precedence

            # Build a state-like dict for embedding
            state: dict[str, Any] = {
                "challenge_id": challenge_id,
                "challenge_type": merged.get("challenge_type", ""),
                "category": merged.get("category", ""),
                "flag_format": merged.get("flag_format", ""),
                "challenge_description": merged.get("description", ""),
                "binary_info": merged.get("binary_info", {}),
                "strings_of_interest": merged.get("strings_of_interest", []),
                "extracted_params": merged.get("extracted_params", {}),
                "decompiled_functions": merged.get("decompiled_functions", {}),
                "solve_path": merged.get("solve_path", []),
                "node_timings": merged.get("node_timings", []),
                "iteration_count": merged.get("iterations", 0),
                "strategies_tried": merged.get("strategies_tried", []),
                "tool_cascade_results": merged.get("tool_cascade_results", []),
                "tool_results_summary": merged.get("tool_results_summary", ""),
                "flag": merged.get("flag_found", ""),
                "flag_found": merged.get("flag_found", ""),
                "elapsed_seconds": merged.get("elapsed_seconds", 0),
                "secondary_types": merged.get("secondary_types", []),
            }

            solved = merged.get("solved", False)
            if solved:
                ground_truth = merged.get("flag_expected", "")
                if self.record_solve(state, ground_truth_flag=ground_truth):
                    stats["ingested"] += 1
                else:
                    stats["errors"] += 1
            else:
                error_msg = merged.get("error", "") or ""
                failure_type = "timeout" if merged.get("timeout", False) else (
                    "error" if error_msg else "unsolved"
                )
                if self.record_failure(state, failure_type=failure_type):
                    stats["ingested"] += 1
                else:
                    stats["errors"] += 1

        logger.info(
            "Ingested %d trajectories from %s (skipped: %d, errors: %d)",
            stats["ingested"], results_dir, stats["skipped"], stats["errors"],
        )
        return stats

    def ingest_all_results(self, results_root: str | Path = "results") -> dict[str, int]:
        """Ingest all benchmark run directories under a root path.

        Scans for directories containing challenges/ subdirectories.
        Returns aggregate counts.
        """
        root = Path(results_root)
        totals = {"ingested": 0, "skipped": 0, "errors": 0, "runs_processed": 0}

        if not root.is_dir():
            logger.warning("Results root %s not found", results_root)
            return totals

        for run_dir in sorted(root.iterdir()):
            if not run_dir.is_dir():
                continue
            challenges_dir = run_dir / "challenges"
            if not challenges_dir.is_dir():
                continue

            logger.info("Ingesting run: %s", run_dir.name)
            stats = self.ingest_results_dir(run_dir)
            totals["ingested"] += stats["ingested"]
            totals["skipped"] += stats["skipped"]
            totals["errors"] += stats["errors"]
            totals["runs_processed"] += 1

        return totals

    # ------------------------------------------------------------------
    # Info
    # ------------------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        """Return trajectory store statistics."""
        if not self.available:
            return {"available": False}

        counts = self.qdrant.collection_counts()
        return {
            "available": True,
            "collections": counts,
        }


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _summarize_binary_info(binary_info: dict[str, Any]) -> str:
    """Create a concise summary string from binary_info dict."""
    parts: list[str] = []

    arch = binary_info.get("architecture", "") or binary_info.get("arch", "")
    if arch:
        parts.append(arch)

    file_type = binary_info.get("type", "") or binary_info.get("file_type", "")
    if file_type:
        # Truncate long file type strings
        parts.append(str(file_type)[:80])

    protections: list[str] = []
    if binary_info.get("nx"):
        protections.append("NX")
    if binary_info.get("pie"):
        protections.append("PIE")
    if binary_info.get("canary"):
        protections.append("Canary")
    if binary_info.get("stripped"):
        protections.append("Stripped")
    relro = binary_info.get("relro", "")
    if relro:
        protections.append(f"RELRO={relro}")
    if protections:
        parts.append(f"[{', '.join(protections)}]")

    return " | ".join(parts) if parts else "unknown"


def _resolve_solving_tool(state: dict[str, Any]) -> str:
    """Best-effort extraction of the tool name that produced the flag.

    Checks the most recent solve script, tool cascade results, and the
    ``current_strategy`` state field (in that order).
    """
    # 1. Latest solve script may carry the tool name
    scripts = state.get("solve_scripts", [])
    if scripts:
        latest = scripts[-1] if isinstance(scripts[-1], dict) else {}
        tool = latest.get("tool", "") or latest.get("strategy", "")
        if tool:
            return tool

    # 2. Last successful tool cascade entry (one that found a flag)
    cascade = state.get("tool_cascade_results", [])
    for result in reversed(cascade or []):
        if isinstance(result, dict) and result.get("flag"):
            tool = result.get("tool", "")
            if tool:
                return tool

    # 3. Last tool cascade entry with any output
    if cascade:
        last = cascade[-1]
        if isinstance(last, dict):
            tool = last.get("tool", "")
            if tool:
                return tool

    # 4. Fallback to current strategy
    return state.get("current_strategy", "")


# ------------------------------------------------------------------
# CLI entry point
# ------------------------------------------------------------------


def _cli_main() -> None:
    """CLI for trajectory management."""
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        prog="python3 -m kraken.knowledge.trajectory",
        description="Manage Kraken solve trajectories in Qdrant.",
    )
    parser.add_argument(
        "--ingest",
        metavar="DIR",
        help="Ingest challenge results from a single run directory",
    )
    parser.add_argument(
        "--ingest-all",
        metavar="DIR",
        default=None,
        help="Ingest all runs under a results root directory (default: results/)",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Show trajectory store statistics",
    )
    parser.add_argument(
        "--search",
        metavar="FILE",
        help="Find similar challenges given a challenge result JSON file",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=5,
        help="Number of results to return for search (default: 5)",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    store = TrajectoryStore()

    if not store.available:
        print("ERROR: Qdrant is not available at http://localhost:6333", file=sys.stderr)
        print("Start Qdrant first: docker run -p 6333:6333 qdrant/qdrant", file=sys.stderr)
        sys.exit(1)

    if args.ingest:
        results_dir = Path(args.ingest)
        if not results_dir.is_dir():
            print(f"ERROR: Directory not found: {args.ingest}", file=sys.stderr)
            sys.exit(1)
        stats = store.ingest_results_dir(results_dir)
        print(f"Ingested: {stats['ingested']}, Skipped: {stats['skipped']}, Errors: {stats['errors']}")

    elif args.ingest_all is not None:
        root = args.ingest_all or "results"
        stats = store.ingest_all_results(root)
        print(
            f"Processed {stats['runs_processed']} runs: "
            f"Ingested {stats['ingested']}, Skipped: {stats['skipped']}, Errors: {stats['errors']}"
        )

    elif args.stats:
        info = store.stats()
        print(json.dumps(info, indent=2))

    elif args.search:
        search_path = Path(args.search)
        if not search_path.exists():
            print(f"ERROR: File not found: {args.search}", file=sys.stderr)
            sys.exit(1)
        try:
            data = json.loads(search_path.read_text())
        except json.JSONDecodeError as exc:
            print(f"ERROR: Invalid JSON: {exc}", file=sys.stderr)
            sys.exit(1)

        similar = store.find_similar_solved(data, limit=args.limit)
        if not similar:
            print("No similar solved challenges found.")
        else:
            print(f"Top {len(similar)} similar solved challenges:\n")
            for i, s in enumerate(similar, 1):
                payload = s.get("payload", {})
                score = s.get("score", 0)
                print(f"  {i}. {payload.get('challenge_id', '?')} (similarity: {score:.3f})")
                print(f"     Type: {payload.get('challenge_type', '?')}")
                print(f"     Category: {payload.get('category', '?')}")
                print(f"     Solved by: {payload.get('solving_tool', '?')}")
                print(f"     Time: {payload.get('elapsed_seconds', 0):.1f}s")
                print()

        # Also show tool recommendations
        recommendations = store.get_tool_recommendation(data)
        if recommendations:
            print(f"Recommended tools: {', '.join(recommendations)}")

    else:
        parser.print_help()


if __name__ == "__main__":
    _cli_main()
