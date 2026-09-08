"""Parse and track the competition scoreboard.

Fetches scoreboard data from the game infrastructure, tracks score
history over time, and provides ranking/analysis utilities.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("kraken.ad.infra.scoreboard")


@dataclass
class TeamScore:
    """Score data for a single team at a point in time."""

    team_id: int
    team_name: str = ""
    attack_score: float = 0.0
    defense_score: float = 0.0
    sla_score: float = 0.0
    total_score: float = 0.0
    rank: int = 0
    services_up: int = 0
    services_total: int = 0


class ScoreboardTracker:
    """Track and analyze competition scoreboard over time.

    Fetches scoreboard data from the scorebot API, maintains history,
    and provides analysis tools for understanding scoring trends.
    """

    def __init__(self):
        self.current_scores: Dict[int, TeamScore] = {}
        self.history: List[Dict[int, TeamScore]] = []
        self.fetch_count: int = 0
        self.last_fetch_time: float = 0.0

    async def fetch(self, scorebot_url: str, token: str = "") -> bool:
        """Fetch current scoreboard from the scorebot API.

        Tries multiple common scoreboard API formats:
        - /api/scoreboard
        - /scores
        - /api/scores
        - /scoreboard.json

        Args:
            scorebot_url: Base URL of the scorebot.
            token: Optional authentication token.

        Returns:
            True if fetch was successful.
        """
        try:
            import aiohttp
        except ImportError:
            logger.warning("aiohttp not installed -- scoreboard fetch disabled")
            return False

        # Try common API endpoints
        base = scorebot_url.rstrip("/")
        endpoints = [
            base,
            f"{base}/api/scoreboard",
            f"{base}/scores",
            f"{base}/api/scores",
            f"{base}/scoreboard.json",
        ]

        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
            headers["X-Team-Token"] = token

        async with aiohttp.ClientSession() as session:
            for endpoint in endpoints:
                try:
                    async with session.get(
                        endpoint,
                        headers=headers,
                        timeout=10,
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            self._parse_scoreboard(data)
                            self.last_fetch_time = time.time()
                            self.fetch_count += 1
                            return True
                except Exception:
                    continue

        logger.warning("Failed to fetch scoreboard from any endpoint")
        return False

    def _parse_scoreboard(self, data: dict) -> None:
        """Parse scoreboard JSON into TeamScore objects.

        Handles multiple common scoreboard formats:
        - {"teams": [{"id": 1, "score": 100, ...}]}
        - {"scoreboard": [{"team_id": 1, "total": 100}]}
        - [{"id": 1, "name": "team1", "score": 100}]
        """
        teams_data = []

        if isinstance(data, list):
            teams_data = data
        elif isinstance(data, dict):
            teams_data = (
                data.get("teams")
                or data.get("scoreboard")
                or data.get("standings")
                or data.get("scores")
                or []
            )

        new_scores: Dict[int, TeamScore] = {}

        for i, team in enumerate(teams_data):
            if not isinstance(team, dict):
                continue

            tid = team.get("id") or team.get("team_id") or team.get("team", 0)
            if not tid:
                continue

            score = TeamScore(
                team_id=tid,
                team_name=team.get("name", team.get("team_name", "")),
                attack_score=float(team.get("attack", team.get("attack_score", 0))),
                defense_score=float(team.get("defense", team.get("defense_score", 0))),
                sla_score=float(team.get("sla", team.get("sla_score", team.get("availability", 0)))),
                total_score=float(team.get("score", team.get("total", team.get("total_score", 0)))),
                rank=int(team.get("rank", team.get("position", i + 1))),
                services_up=int(team.get("services_up", 0)),
                services_total=int(team.get("services_total", 0)),
            )

            # If total wasn't provided, calculate it
            if score.total_score == 0:
                score.total_score = (
                    score.attack_score + score.defense_score + score.sla_score
                )

            new_scores[tid] = score

        if new_scores:
            # Assign ranks if not provided
            sorted_teams = sorted(
                new_scores.values(),
                key=lambda t: t.total_score,
                reverse=True,
            )
            for i, team in enumerate(sorted_teams):
                if team.rank == 0:
                    team.rank = i + 1

            self.current_scores = new_scores
            self.history.append(dict(new_scores))

    def load_from_file(self, path: str) -> bool:
        """Load scoreboard data from a JSON file (offline/testing)."""
        try:
            data = json.loads(Path(path).read_text())
            self._parse_scoreboard(data)
            return True
        except Exception as exc:
            logger.warning("Failed to load scoreboard from %s: %s", path, exc)
            return False

    def save_to_file(self, path: str) -> None:
        """Save current scoreboard to a JSON file."""
        data = {
            "timestamp": time.time(),
            "fetch_count": self.fetch_count,
            "teams": [
                {
                    "id": s.team_id,
                    "name": s.team_name,
                    "attack": s.attack_score,
                    "defense": s.defense_score,
                    "sla": s.sla_score,
                    "total": s.total_score,
                    "rank": s.rank,
                }
                for s in sorted(
                    self.current_scores.values(),
                    key=lambda t: t.rank,
                )
            ],
        }
        Path(path).write_text(json.dumps(data, indent=2))

    def get_our_rank(self, our_team_id: int) -> int:
        """Get our current rank."""
        team = self.current_scores.get(our_team_id)
        return team.rank if team else -1

    def get_our_score(self, our_team_id: int) -> Optional[TeamScore]:
        """Get our current score breakdown."""
        return self.current_scores.get(our_team_id)

    def get_top_n(self, n: int = 5) -> List[TeamScore]:
        """Get top N teams by total score."""
        return sorted(
            self.current_scores.values(),
            key=lambda t: t.total_score,
            reverse=True,
        )[:n]

    def get_score_trend(self, team_id: int) -> List[float]:
        """Get score history for a team (one entry per fetch)."""
        return [
            snapshot.get(team_id, TeamScore(team_id=team_id)).total_score
            for snapshot in self.history
        ]

    def get_rank_trend(self, team_id: int) -> List[int]:
        """Get rank history for a team."""
        return [
            snapshot.get(team_id, TeamScore(team_id=team_id)).rank
            for snapshot in self.history
        ]

    def print_standings(self, top_n: int = 10) -> str:
        """Format current standings as a human-readable string."""
        if not self.current_scores:
            return "No scoreboard data available"

        lines = ["Rank | Team                | Attack | Defense | SLA    | Total"]
        lines.append("-" * 70)

        for team in self.get_top_n(top_n):
            lines.append(
                f"{team.rank:4d} | {team.team_name[:20]:<20s} | "
                f"{team.attack_score:6.0f} | {team.defense_score:7.0f} | "
                f"{team.sla_score:6.0f} | {team.total_score:6.0f}"
            )

        return "\n".join(lines)
