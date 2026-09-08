"""Deploy exploits against all opponent teams in parallel.

The thrower is responsible for executing exploit scripts against every
opponent team during each tick, managing concurrency limits to avoid
overwhelming the network or the host machine.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Dict, List, Optional

from ..infra.team_manager import TeamManager
from .exploit_manager import ExploitManager
from .flag_submitter import FlagSubmitter

logger = logging.getLogger("kraken.ad.offense.thrower")


class ExploitThrower:
    """Deploy exploits against all opponent teams with concurrency control."""

    def __init__(
        self,
        exploit_manager: ExploitManager,
        team_manager: TeamManager,
        flag_submitter: FlagSubmitter,
        max_concurrent: int = 50,
    ):
        self.exploit_mgr = exploit_manager
        self.team_mgr = team_manager
        self.flag_sub = flag_submitter
        self.max_concurrent = max_concurrent
        self.last_exploit_count: int = 0

        # Per-tick stats
        self._tick_flags: Dict[str, int] = {}

    async def throw_tick(self, services: List[str]) -> Dict[str, int]:
        """Run all exploits against all opponents for given services.

        Returns a dict mapping service name to number of flags captured
        this tick.
        """
        self._tick_flags = {svc: 0 for svc in services}
        opponents = self.team_mgr.get_opponents()
        self.last_exploit_count = 0

        if not opponents:
            logger.warning("No opponent teams configured")
            return self._tick_flags

        # Build task list: (service, team_id)
        tasks = []
        for svc in services:
            if svc not in self.exploit_mgr.exploits:
                continue
            for team_id in opponents:
                tasks.append((svc, team_id))

        if not tasks:
            logger.info("No exploits loaded for any service")
            return self._tick_flags

        self.last_exploit_count = len(tasks)
        logger.info(
            "Throwing %d exploit tasks across %d services x %d teams",
            len(tasks),
            len(services),
            len(opponents),
        )

        # Execute with semaphore for concurrency control
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def _bounded_throw(service: str, team_id: int) -> None:
            async with semaphore:
                await self.throw_single(service, team_id)

        start = time.time()
        await asyncio.gather(
            *[_bounded_throw(svc, tid) for svc, tid in tasks],
            return_exceptions=True,
        )
        elapsed = time.time() - start

        total_flags = sum(self._tick_flags.values())
        logger.info(
            "Throw complete in %.1fs: %d flags captured across %d services",
            elapsed,
            total_flags,
            len(services),
        )

        return dict(self._tick_flags)

    async def throw_single(self, service: str, team_id: int) -> None:
        """Run exploits for one service against one team.

        Captured flags are immediately submitted to the flag submitter.
        """
        target_ip = self.team_mgr.get_ip(team_id, service)
        target_port = self.team_mgr.get_port(service)

        if target_port == 0:
            return

        try:
            flags = await self.exploit_mgr.run_exploit(
                service, target_ip, target_port
            )
            if flags:
                self._tick_flags[service] = (
                    self._tick_flags.get(service, 0) + len(flags)
                )
                for flag in flags:
                    await self.flag_sub.submit(flag)
                logger.debug(
                    "Team %d/%s: %d flag(s)", team_id, service, len(flags)
                )
        except Exception as exc:
            logger.debug(
                "Team %d/%s error: %s", team_id, service, exc
            )

    async def throw_targeted(
        self,
        service: str,
        team_ids: List[int],
        exploit_name: Optional[str] = None,
    ) -> Dict[int, List[str]]:
        """Run a specific exploit against specific teams (for testing).

        Returns dict mapping team_id to list of captured flags.
        """
        results: Dict[int, List[str]] = {}
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def _run(tid: int) -> None:
            async with semaphore:
                target_ip = self.team_mgr.get_ip(tid, service)
                target_port = self.team_mgr.get_port(service)
                flags = await self.exploit_mgr.run_exploit(
                    service, target_ip, target_port
                )
                results[tid] = flags

        await asyncio.gather(
            *[_run(tid) for tid in team_ids],
            return_exceptions=True,
        )
        return results
