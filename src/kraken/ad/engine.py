"""Kraken A/D Game Engine -- tick-based attack/defense orchestration.

The engine runs a continuous loop where each "tick" (typically 2-5 minutes)
executes offense (exploit throwing + flag submission), defense (traffic
analysis + patching), SLA monitoring, and scoreboard updates concurrently.

Designed for 6-10 hour DEF CON Finals-style competitions.
"""

from __future__ import annotations

import asyncio
import logging
import signal
import time
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .config import GameConfig
from .defense.firewall import DynamicFirewall
from .defense.patcher import ServicePatcher
from .defense.sla_monitor import SLAMonitor
from .defense.traffic_analyzer import TrafficAnalyzer
from .infra.scoreboard import ScoreboardTracker
from .infra.team_manager import TeamManager
from .offense.exploit_manager import ExploitManager
from .offense.flag_submitter import FlagSubmitter
from .offense.thrower import ExploitThrower

logger = logging.getLogger("kraken.ad.engine")


@dataclass
class TickStats:
    """Statistics for a single game tick."""

    tick_number: int
    start_time: float
    end_time: float = 0.0
    flags_captured: int = 0
    flags_submitted: int = 0
    flags_accepted: int = 0
    exploits_run: int = 0
    sla_checks_passed: int = 0
    sla_checks_failed: int = 0
    attacks_detected: int = 0
    patches_applied: int = 0
    errors: List[str] = field(default_factory=list)

    @property
    def duration(self) -> float:
        return self.end_time - self.start_time if self.end_time else 0.0


class GameEngine:
    """Main game engine -- tick loop, orchestration, and component management.

    The engine coordinates all attack/defense operations on a per-tick basis:
    1. Offense: Run exploits against all opponents, capture and submit flags
    2. Defense: Analyze traffic, detect attacks, apply patches
    3. SLA: Verify our services are up and passing availability checks
    4. Scoreboard: Fetch and display current standings

    All four phases run concurrently each tick. The engine handles graceful
    shutdown via SIGINT/SIGTERM and supports hot-reloading of exploits and
    patches without restart.
    """

    def __init__(self, config: GameConfig):
        self.config = config
        self.tick_number: int = 0
        self.running: bool = False
        self.tick_history: List[TickStats] = []

        # Initialize all subsystems
        self.team_mgr = TeamManager(
            ip_template=config.network.ip_template,
            our_team_id=config.network.our_team_id,
        )
        # Auto-populate opponent teams
        for tid in range(1, config.network.team_count + 1):
            self.team_mgr.add_team(tid, name=f"Team {tid}")
        # Register service ports
        for svc in config.services:
            self.team_mgr.register_service(svc.name, svc.port)

        self.exploit_mgr = ExploitManager(
            exploit_dir=config.exploit_dir,
            flag_regex=config.flag_regex,
        )

        self.flag_submitter = FlagSubmitter(
            scorebot_url=config.scoring.scorebot_url,
            token=config.scoring.scorebot_token,
            rate_limit=config.scoring.submit_rate_limit,
            enabled=config.submit_flags,
        )

        self.thrower = ExploitThrower(
            exploit_manager=self.exploit_mgr,
            team_manager=self.team_mgr,
            flag_submitter=self.flag_submitter,
            max_concurrent=config.max_concurrent_exploits,
        )

        self.traffic_analyzer = TrafficAnalyzer(
            interface=config.network.game_interface,
            our_team_id=config.network.our_team_id,
            pcap_dir=config.pcap_dir,
        )

        self.patcher = ServicePatcher(
            service_dir="",  # Set per-service
            backup_dir=config.backup_dir,
        )

        sla_services = {}
        for svc in config.services:
            sla_services[svc.name] = {
                "port": svc.port,
                "protocol": svc.protocol,
                "check_script": svc.check_script,
                "timeout": svc.timeout,
            }
        self.sla_monitor = SLAMonitor(services=sla_services)

        self.firewall = DynamicFirewall()
        self.scoreboard = ScoreboardTracker()

        # Event hooks for external integrations
        self._tick_callbacks: List[Callable[[TickStats], Any]] = []

    def on_tick(self, callback: Callable[[TickStats], Any]) -> None:
        """Register a callback invoked after each tick with stats."""
        self._tick_callbacks.append(callback)

    async def run(self) -> None:
        """Main game loop -- runs until stopped via signal or .stop().

        Each tick runs offense, defense, SLA checks, and scoreboard updates
        concurrently. Remaining time in the tick is spent sleeping.
        """
        self.running = True
        loop = asyncio.get_running_loop()

        # Register signal handlers for graceful shutdown
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, self._handle_signal)

        # Ensure directories exist
        self.config.ensure_dirs()

        # Load existing exploits from disk
        self.exploit_mgr.load_exploits()

        # Start the flag submitter background task
        submitter_task = asyncio.create_task(self.flag_submitter.run())

        logger.info(
            "Game engine started | tick=%ds | services=%d | teams=%d",
            self.config.tick_duration,
            len(self.config.services),
            self.config.network.team_count,
        )

        try:
            while self.running:
                self.tick_number += 1
                stats = TickStats(
                    tick_number=self.tick_number,
                    start_time=time.time(),
                )

                logger.info(
                    "=== TICK %d START ===",
                    self.tick_number,
                )

                # Hot-reload exploits every tick (picks up new scripts)
                self.exploit_mgr.load_exploits()

                try:
                    results = await asyncio.gather(
                        self._run_offense(stats),
                        self._run_defense(stats),
                        self._check_sla(stats),
                        self._update_scoreboard(stats),
                        return_exceptions=True,
                    )

                    # Log any exceptions from gather
                    for i, result in enumerate(results):
                        if isinstance(result, Exception):
                            phase_name = ["offense", "defense", "sla", "scoreboard"][i]
                            logger.error(
                                "Tick %d %s error: %s",
                                self.tick_number,
                                phase_name,
                                result,
                            )
                            stats.errors.append(f"{phase_name}: {result}")

                except Exception as exc:
                    logger.error("Tick %d fatal error: %s", self.tick_number, exc)
                    stats.errors.append(f"fatal: {exc}")

                stats.end_time = time.time()
                self.tick_history.append(stats)

                # Invoke tick callbacks
                for cb in self._tick_callbacks:
                    try:
                        result = cb(stats)
                        if asyncio.iscoroutine(result):
                            await result
                    except Exception as exc:
                        logger.error("Tick callback error: %s", exc)

                self._print_tick_summary(stats)

                # Sleep until next tick
                elapsed = stats.duration
                sleep_time = max(0, self.config.tick_duration - elapsed)
                if sleep_time > 0:
                    logger.info(
                        "Tick %d done in %.1fs, sleeping %.1fs",
                        self.tick_number,
                        elapsed,
                        sleep_time,
                    )
                    await asyncio.sleep(sleep_time)
                else:
                    logger.warning(
                        "Tick %d OVERRAN by %.1fs (took %.1fs, budget %ds)",
                        self.tick_number,
                        -sleep_time,
                        elapsed,
                        self.config.tick_duration,
                    )
        finally:
            # Shutdown
            self.running = False
            self.flag_submitter.stop()
            submitter_task.cancel()
            with suppress(asyncio.CancelledError):
                await submitter_task
            logger.info("Game engine stopped after %d ticks", self.tick_number)

    def stop(self) -> None:
        """Signal the engine to stop after the current tick."""
        logger.info("Stop requested")
        self.running = False

    def _handle_signal(self) -> None:
        """Handle SIGINT/SIGTERM for graceful shutdown."""
        logger.info("Signal received, stopping after current tick...")
        self.stop()

    # ------------------------------------------------------------------
    # Exploit selection
    # ------------------------------------------------------------------

    def _select_exploits_for_team(
        self,
        team_id: int,
        service_name: str,
    ) -> List[Path]:
        """Select exploits to run against a specific team, skipping known-failures.

        Exploits with a success rate at or below 5% (and at least one prior
        attempt) are excluded to avoid wasting time on broken scripts.

        Args:
            team_id: Numeric team identifier.
            team_ip: (derived internally) the team's IP.
            service_name: Service to attack.

        Returns:
            Filtered list of exploit :class:`~pathlib.Path` objects.
        """
        all_exploits = self.exploit_mgr.exploits.get(service_name, [])
        rates = self.exploit_mgr.success_rate.get(service_name, {})

        selected: List[Path] = []
        for exploit in all_exploits:
            rate = rates.get(exploit.name)
            # Include if untried (rate is None / not in dict) or > 5%
            if rate is None or rate > 0.05:
                selected.append(exploit)
            else:
                logger.debug(
                    "Skipping %s for team %d (success_rate=%.1f%%)",
                    exploit.name,
                    team_id,
                    rate * 100,
                )
        return selected

    # ------------------------------------------------------------------
    # Tick phases
    # ------------------------------------------------------------------

    async def _run_offense(self, stats: TickStats) -> None:
        """Run all exploits against all opponent teams."""
        service_names = self.config.service_names()
        if not service_names:
            return

        result = await self.thrower.throw_tick(service_names)
        stats.flags_captured = sum(result.values())
        stats.exploits_run = self.thrower.last_exploit_count

        # Update submitter stats
        stats.flags_submitted = self.flag_submitter.total_submitted
        stats.flags_accepted = self.flag_submitter.accepted

    async def _run_defense(self, stats: TickStats) -> None:
        """Monitor traffic, detect attacks, optionally auto-patch."""
        if not self.config.capture_traffic:
            return

        # Start or rotate pcap capture
        pcap_path = str(
            Path(self.config.pcap_dir) / f"tick_{self.tick_number}.pcap"
        )

        # Analyze previous tick's pcap (if exists)
        prev_pcap = str(
            Path(self.config.pcap_dir) / f"tick_{self.tick_number - 1}.pcap"
        )
        prev_path = Path(prev_pcap)
        if prev_path.exists():
            attacks = self.traffic_analyzer.detect_new_attacks(prev_pcap)
            stats.attacks_detected = len(attacks)

            if attacks and self.config.auto_patch:
                for attack in attacks:
                    service = attack.get("service", "")
                    if service:
                        logger.info(
                            "Auto-patching %s for detected attack", service
                        )
                        svc_config = self.config.get_service(service)
                        if svc_config and svc_config.binary:
                            self.patcher.service_dir = Path(svc_config.binary).parent
                            self.patcher.backup_service(service)
                            self.patcher.patch_source(
                                svc_config.binary,
                                attack.get("vuln_type", "unknown"),
                            )
                            # Validate patch doesn't break SLA
                            if self.patcher.validate_patch(
                                service, self.sla_monitor
                            ):
                                stats.patches_applied += 1
                                logger.info("Patch for %s validated OK", service)
                            else:
                                self.patcher.rollback(service)
                                logger.warning(
                                    "Patch for %s broke SLA, rolled back", service
                                )

            # --- Pcap-to-exploit replay pipeline ---
            # Try to convert detected attacks into deployable exploits
            if attacks:
                for attack in attacks:
                    if self.traffic_analyzer.replay_and_verify(attack):
                        exploit_path = self.traffic_analyzer.extract_exploit_from_attack(attack)
                        if exploit_path:
                            service_name = attack.get("service", "")
                            if service_name:
                                self.exploit_mgr.add_exploit(service_name, exploit_path)
                            logger.info(
                                "ad_exploit_from_pcap: path=%s type=%s",
                                exploit_path,
                                attack.get("vuln_type", "unknown"),
                            )

            # --- Auto-firewall rules ---
            if attacks and self.config.auto_firewall:
                # Use the new bulk auto-block method
                self.firewall.auto_block_from_traffic(attacks)
                # Also keep the legacy per-payload blocking
                for attack in attacks:
                    payload = attack.get("payload")
                    port = attack.get("port", 0)
                    if payload and port:
                        self.firewall.block_payload(
                            payload.encode() if isinstance(payload, str) else payload,
                            port,
                        )

        # Start capture for this tick
        self.traffic_analyzer.start_capture(
            self.config.pcap_dir,
            duration=self.config.tick_duration,
        )

    async def _check_sla(self, stats: TickStats) -> None:
        """Verify our services are up and responding correctly."""
        our_ip = self.team_mgr.get_ip(self.config.our_team_id)
        results = await self.sla_monitor.check_all(host=our_ip)

        for service, up in results.items():
            if up:
                stats.sla_checks_passed += 1
            else:
                stats.sla_checks_failed += 1
                logger.warning("SLA FAIL: %s is DOWN", service)

    async def _update_scoreboard(self, stats: TickStats) -> None:
        """Fetch and track current scoreboard."""
        if self.config.scoring.scorebot_url:
            await self.scoreboard.fetch(self.config.scoring.scorebot_url)

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def _print_tick_summary(self, stats: TickStats) -> None:
        """Print a human-readable tick summary to the log."""
        sla_str = f"{stats.sla_checks_passed}/{stats.sla_checks_passed + stats.sla_checks_failed}"
        logger.info(
            "=== TICK %d SUMMARY === "
            "duration=%.1fs | flags_captured=%d | flags_accepted=%d | "
            "sla=%s | attacks_detected=%d | patches=%d | errors=%d",
            stats.tick_number,
            stats.duration,
            stats.flags_captured,
            stats.flags_accepted,
            sla_str,
            stats.attacks_detected,
            stats.patches_applied,
            len(stats.errors),
        )

    def get_status(self) -> Dict[str, Any]:
        """Return current engine status as a dict (for CLI/API)."""
        last_tick = self.tick_history[-1] if self.tick_history else None
        return {
            "running": self.running,
            "tick_number": self.tick_number,
            "total_flags_captured": sum(t.flags_captured for t in self.tick_history),
            "total_flags_accepted": self.flag_submitter.accepted,
            "total_flags_rejected": self.flag_submitter.rejected,
            "total_flags_duplicate": self.flag_submitter.duplicate,
            "total_attacks_detected": sum(
                t.attacks_detected for t in self.tick_history
            ),
            "total_patches_applied": sum(
                t.patches_applied for t in self.tick_history
            ),
            "services": {
                name: self.sla_monitor.get_uptime(name)
                for name in self.config.service_names()
            },
            "exploits_loaded": {
                svc: len(scripts)
                for svc, scripts in self.exploit_mgr.exploits.items()
            },
            "last_tick": {
                "number": last_tick.tick_number,
                "duration": last_tick.duration,
                "flags": last_tick.flags_captured,
                "sla_ok": last_tick.sla_checks_failed == 0,
                "errors": last_tick.errors,
            }
            if last_tick
            else None,
        }
