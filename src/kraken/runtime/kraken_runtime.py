"""KRAKEN Runtime -- intelligent offline agentic CTF solver.

Assembles model routing, session persistence, metrics collection,
context management, and project context into a unified runtime that
wraps the standard LocalRuntime with enhanced capabilities.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path
from typing import Any

from kraken.config import KrakenConfig
from kraken.logging.structured import configure_logging, get_logger
from kraken.runtime.local_runtime import LocalRuntime
from kraken.runtime.model_router import ModelRouter
from kraken.runtime.session import SessionManager
from kraken.runtime.context_manager import ContextManager
from kraken.runtime.project_context import ProjectContext
from kraken.runtime.metrics import MetricsCollector, reset_metrics_collector

log = get_logger(__name__)


class KrakenRuntime(LocalRuntime):
    """Full-featured offline runtime with session persistence and metrics."""

    name = "kraken"

    def __init__(self, workspace: str | Path | None = None):
        super().__init__()
        self.workspace = Path(workspace or os.environ.get("KRAKEN_WORKSPACE", ".")).resolve()
        self.model_router = ModelRouter()
        self.session_manager = SessionManager(self.workspace)
        self.context_manager = ContextManager()
        self.project_context = ProjectContext(self.workspace)
        self.metrics: MetricsCollector | None = None
        self._initialized = False

    async def initialize(self, config: KrakenConfig | None = None) -> None:
        """Initialize runtime: discover models, set up metrics."""
        if self._initialized:
            return

        config = config or KrakenConfig()

        # Discover available Ollama models
        if config.runtime.auto_discover_models:
            base_url = config.models.ollama_base_url
            await self.model_router.discover_models(base_url)
            self.model_router.assign_tiers()

            # Apply discovered models to config
            overrides = self.model_router.get_config_overrides()
            config.models.model_high = overrides["model_high"]
            config.models.model_mid = overrides["model_mid"]
            config.models.model_low = overrides["model_low"]
            config.models.backend = "ollama"

        # Set up context manager
        self.context_manager.base_url = config.models.ollama_base_url
        self.context_manager.num_ctx = config.models.num_ctx

        self._initialized = True
        log.info(
            "kraken_runtime_initialized",
            workspace=str(self.workspace),
            models_discovered=len(self.model_router.available),
        )

    async def solve_challenge(
        self,
        config: KrakenConfig | None = None,
        challenge_config: dict | None = None,
        challenge_json_path: str | None = None,
        resume_session: str | None = None,
    ) -> dict:
        """Solve a challenge using the full KRAKEN pipeline.

        Args:
            config: KrakenConfig (uses defaults if None)
            challenge_config: Challenge config dict
            challenge_json_path: Path to challenge JSON file
            resume_session: Session ID to resume from

        Returns:
            Solve result dict with metrics
        """
        from kraken.orchestrator import Orchestrator, _normalize_challenge_id

        config = config or KrakenConfig()
        await self.initialize(config)

        # Load challenge config
        if challenge_json_path and not challenge_config:
            challenge_config = json.loads(Path(challenge_json_path).read_text())
            challenge_config = _normalize_challenge_id(challenge_config, challenge_json_path)

        if not challenge_config:
            raise ValueError("Either challenge_config or challenge_json_path required")

        challenge_id = challenge_config.get("challenge_id", "unknown")

        # Resume session if requested
        if resume_session:
            restored = self.session_manager.resume_session(resume_session)
            if restored:
                log.info("kraken_runtime_resuming", session_id=resume_session)
                challenge_config.update(restored)

        # Apply model router overrides
        if self.model_router._discovered:
            overrides = self.model_router.get_config_overrides()
            challenge_config.setdefault("backend", overrides["backend"])
            for key in ("model_high", "model_mid", "model_low"):
                challenge_config.setdefault(key, overrides[key])

        # Initialize metrics
        self.metrics = reset_metrics_collector(
            session_id=resume_session or "",
            challenge_id=challenge_id,
        )

        # Create session
        session = self.session_manager.create_session(challenge_id, challenge_config)

        # Run the orchestrator
        orchestrator = Orchestrator(config=config)
        start_time = time.time()

        try:
            result = await orchestrator.solve(challenge_config, progress=True)
        except Exception as exc:
            result = {
                "solved": False,
                "flag": "",
                "error": str(exc),
                "challenge_id": challenge_id,
            }
            log.error("kraken_runtime_solve_error", error=str(exc)[:300])

        elapsed = time.time() - start_time

        # Save session
        self.session_manager.complete_session(session.session_id, result)

        # Update project context
        self.project_context.append_learning(
            challenge_id=challenge_id,
            challenge_type=result.get("challenge_type", "unknown"),
            outcome="solved" if result.get("solved") else "failed",
            strategy=", ".join(result.get("strategies_tried", [])) or "direct",
            notes=(result.get("error") or "")[:200] if not result.get("solved") else "",
        )

        # Export metrics
        metrics_dir = self.workspace / ".kraken" / "metrics"
        if self.metrics:
            self.metrics.export_json(metrics_dir / f"{challenge_id}_metrics.json")
            self.metrics.export_markdown(metrics_dir / f"{challenge_id}_metrics.md")

        # Enrich result
        result["session_id"] = session.session_id
        result["metrics"] = self.metrics.summary() if self.metrics else {}
        result["runtime"] = "kraken"
        result["models"] = self.model_router.tier_assignments

        return result

    async def benchmark(
        self,
        challenges_dir: str | Path,
        output_dir: str | Path | None = None,
        config: KrakenConfig | None = None,
        timeout_minutes: int = 30,
    ) -> dict:
        """Run benchmark across multiple challenges.

        Args:
            challenges_dir: Directory containing challenge subdirs or JSON files
            output_dir: Where to write results (default: challenges_dir/.kraken/benchmark)
            config: KrakenConfig to use
            timeout_minutes: Per-challenge timeout

        Returns:
            Benchmark summary dict
        """
        import sys

        config = config or KrakenConfig()
        config.budget.timeout_minutes = timeout_minutes
        await self.initialize(config)

        challenges_path = Path(challenges_dir).resolve()
        output_path = Path(output_dir or challenges_path / ".kraken" / "benchmark").resolve()
        output_path.mkdir(parents=True, exist_ok=True)

        # Discover challenges
        challenge_files = sorted(challenges_path.glob("**/*.json"))
        if not challenge_files:
            # Check for subdirectories with challenge.json
            for sub in sorted(challenges_path.iterdir()):
                if sub.is_dir() and (sub / "challenge.json").exists():
                    challenge_files.append(sub / "challenge.json")

        results = []
        solved = 0
        total = len(challenge_files)

        sys.stderr.write(f"\nKRAKEN Runtime Benchmark: {total} challenges\n")
        sys.stderr.write(f"Models: {self.model_router.tier_assignments}\n")
        sys.stderr.write(f"{'='*60}\n\n")

        for i, cf in enumerate(challenge_files):
            try:
                challenge_config = json.loads(cf.read_text())
                from kraken.orchestrator import _normalize_challenge_id
                challenge_config = _normalize_challenge_id(challenge_config, str(cf))
                challenge_config["benchmark"] = True
                cid = challenge_config.get("challenge_id", cf.stem)

                sys.stderr.write(f"  [{i+1}/{total}] {cid}... ")
                sys.stderr.flush()

                result = await asyncio.wait_for(
                    self.solve_challenge(config=config, challenge_config=challenge_config),
                    timeout=timeout_minutes * 60,
                )

                if result.get("solved"):
                    solved += 1
                    sys.stderr.write(f"SOLVED ({result.get('duration_seconds', 0):.0f}s)\n")
                else:
                    sys.stderr.write("FAILED\n")

                results.append(result)

            except asyncio.TimeoutError:
                sys.stderr.write("TIMEOUT\n")
                results.append({
                    "challenge_id": cf.stem,
                    "solved": False,
                    "error": "timeout",
                })
            except Exception as exc:
                sys.stderr.write(f"ERROR: {str(exc)[:50]}\n")
                results.append({
                    "challenge_id": cf.stem,
                    "solved": False,
                    "error": str(exc)[:200],
                })

        # Summary
        summary = {
            "total": total,
            "solved": solved,
            "failed": total - solved,
            "solve_rate": f"{solved/total*100:.1f}%" if total > 0 else "0%",
            "models": self.model_router.tier_assignments,
            "results": results,
        }

        # Write results
        (output_path / "benchmark_results.json").write_text(
            json.dumps(summary, indent=2, default=str)
        )

        sys.stderr.write(f"\n{'='*60}\n")
        sys.stderr.write(f"  Results: {solved}/{total} solved ({summary['solve_rate']})\n")
        sys.stderr.write(f"  Output: {output_path}\n")
        sys.stderr.write(f"{'='*60}\n")

        return summary

    def list_models(self) -> str:
        """Format available models for display."""
        if not self.model_router._discovered:
            return "Models not yet discovered. Run `kraken-runtime models` to discover."
        return self.model_router.format_table()
