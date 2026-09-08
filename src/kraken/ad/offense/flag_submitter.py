"""Submit captured flags to the scorebot.

Handles rate limiting, deduplication, retry on failure, and tracks
acceptance/rejection/duplicate statistics.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from enum import Enum
from typing import Deque, Dict, Optional, Set

logger = logging.getLogger("kraken.ad.offense.flag_submitter")


class FlagStatus(Enum):
    """Possible responses from the scorebot."""

    ACCEPTED = "accepted"
    REJECTED = "rejected"
    DUPLICATE = "duplicate"
    EXPIRED = "expired"
    OWN_FLAG = "own_flag"
    INVALID = "invalid"
    ERROR = "error"


class FlagSubmitter:
    """Queue and submit captured flags to the competition scorebot.

    Features:
    - Async queue-based submission
    - Rate limiting to avoid scorebot throttling
    - Deduplication (won't resubmit known flags)
    - Retry on network errors
    - Statistics tracking
    """

    def __init__(
        self,
        scorebot_url: str,
        token: str,
        rate_limit: float = 0.1,
        max_retries: int = 3,
        enabled: bool = True,
    ):
        self.url = scorebot_url
        self.token = token
        self.rate_limit = rate_limit
        self.max_retries = max_retries
        self.enabled = enabled

        self.queue: asyncio.Queue[str] = asyncio.Queue()
        self.submitted: Set[str] = set()
        self.accepted: int = 0
        self.rejected: int = 0
        self.duplicate: int = 0
        self.expired: int = 0
        self.errors: int = 0
        self.total_submitted: int = 0

        # Recent submission log for debugging
        self.recent_submissions: Deque[Dict] = deque(maxlen=500)

        self._running = False
        self._session = None

    async def submit(self, flag: str) -> None:
        """Queue a flag for submission (deduplicates automatically)."""
        if flag in self.submitted:
            return
        await self.queue.put(flag)

    async def submit_batch(self, flags: list[str]) -> None:
        """Queue multiple flags for submission."""
        for flag in flags:
            await self.submit(flag)

    async def run(self) -> None:
        """Continuously submit flags from queue. Run as a background task.

        This method runs until ``stop()`` is called. It processes the
        queue one flag at a time, respecting the rate limit.
        """
        self._running = True

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                self._session = session
                while self._running:
                    try:
                        flag = await asyncio.wait_for(
                            self.queue.get(), timeout=1.0
                        )
                    except asyncio.TimeoutError:
                        continue

                    if flag in self.submitted:
                        self.queue.task_done()
                        continue

                    status = await self._submit_single(session, flag)
                    self._record_submission(flag, status)
                    self.queue.task_done()

                    await asyncio.sleep(self.rate_limit)
        except ImportError:
            logger.error(
                "aiohttp not installed -- flag submission disabled. "
                "Install with: pip install aiohttp"
            )
        except asyncio.CancelledError:
            logger.info("Flag submitter cancelled, draining queue...")
            await self._drain_queue()
        finally:
            self._running = False
            self._session = None

    def stop(self) -> None:
        """Signal the submitter to stop."""
        self._running = False

    async def _submit_single(self, session, flag: str) -> FlagStatus:
        """Submit a single flag to the scorebot with retry logic."""
        if not self.enabled:
            logger.info("Flag submission disabled, would submit: %s", flag)
            self.submitted.add(flag)
            self.total_submitted += 1
            return FlagStatus.ACCEPTED

        if not self.url:
            logger.warning("No scorebot URL configured")
            return FlagStatus.ERROR

        for attempt in range(1, self.max_retries + 1):
            try:
                headers = {}
                if self.token:
                    headers["Authorization"] = f"Bearer {self.token}"
                    headers["X-Team-Token"] = self.token

                async with session.post(
                    self.url,
                    json={"flag": flag},
                    headers=headers,
                    timeout=10,
                ) as resp:
                    self.submitted.add(flag)
                    self.total_submitted += 1

                    if resp.status == 200:
                        try:
                            result = await resp.json()
                        except Exception:
                            result = {"status": (await resp.text()).strip().lower()}

                        status_str = str(result.get("status", "")).lower()
                        msg = result.get("message", result.get("msg", ""))

                        if status_str in ("accepted", "ok", "correct"):
                            self.accepted += 1
                            logger.info("FLAG ACCEPTED: %s", flag[:12] + "...")
                            return FlagStatus.ACCEPTED
                        elif status_str in ("duplicate", "already"):
                            self.duplicate += 1
                            return FlagStatus.DUPLICATE
                        elif status_str in ("expired", "old"):
                            self.expired += 1
                            return FlagStatus.EXPIRED
                        elif "own" in status_str:
                            return FlagStatus.OWN_FLAG
                        else:
                            self.rejected += 1
                            logger.debug(
                                "Flag rejected: %s (%s)", flag[:12], msg
                            )
                            return FlagStatus.REJECTED
                    elif resp.status == 429:
                        # Rate limited -- back off
                        logger.warning("Scorebot rate limit hit, backing off")
                        await asyncio.sleep(2.0 * attempt)
                        continue
                    else:
                        logger.warning(
                            "Scorebot HTTP %d for flag %s",
                            resp.status,
                            flag[:12],
                        )
                        if attempt < self.max_retries:
                            await asyncio.sleep(1.0 * attempt)
                            continue
                        self.errors += 1
                        return FlagStatus.ERROR

            except asyncio.TimeoutError:
                logger.warning(
                    "Scorebot timeout (attempt %d/%d)", attempt, self.max_retries
                )
                if attempt < self.max_retries:
                    await asyncio.sleep(1.0 * attempt)
            except Exception as exc:
                logger.warning(
                    "Scorebot error (attempt %d/%d): %s",
                    attempt,
                    self.max_retries,
                    exc,
                )
                if attempt < self.max_retries:
                    await asyncio.sleep(1.0 * attempt)

        self.errors += 1
        return FlagStatus.ERROR

    def _record_submission(self, flag: str, status: FlagStatus) -> None:
        """Record a submission in the recent log."""
        self.recent_submissions.append(
            {
                "flag": flag[:16] + "...",
                "status": status.value,
                "time": time.time(),
            }
        )

    async def _drain_queue(self) -> None:
        """Submit remaining flags in queue on shutdown."""
        if not self._session or self.queue.empty():
            return

        remaining = 0
        while not self.queue.empty():
            try:
                flag = self.queue.get_nowait()
                if flag not in self.submitted:
                    await self._submit_single(self._session, flag)
                    remaining += 1
                self.queue.task_done()
            except asyncio.QueueEmpty:
                break

        if remaining:
            logger.info("Drained %d flags from queue on shutdown", remaining)

    def get_stats(self) -> Dict[str, int]:
        """Return submission statistics."""
        return {
            "queued": self.queue.qsize(),
            "submitted": self.total_submitted,
            "accepted": self.accepted,
            "rejected": self.rejected,
            "duplicate": self.duplicate,
            "expired": self.expired,
            "errors": self.errors,
            "unique_flags": len(self.submitted),
        }
