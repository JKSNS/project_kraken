"""Track teams, IPs, and service endpoints.

Manages the mapping between team IDs, IP addresses, and service ports
for the A/D competition network topology.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger("kraken.ad.infra.team_manager")


@dataclass
class Team:
    """Representation of a competing team."""

    id: int
    name: str = ""
    ip_base: str = ""
    services: Dict[str, int] = field(default_factory=dict)  # service_name -> port
    score: float = 0.0
    active: bool = True


class TeamManager:
    """Track teams, IP addresses, and service endpoints.

    Uses an IP template (e.g., ``10.{team_id}.{service_id}.2``) to
    generate team-specific service addresses. Supports dynamic team
    registration and auto-population from scoreboard data.
    """

    def __init__(
        self,
        ip_template: str = "10.{team_id}.{service_id}.2",
        our_team_id: int = 1,
    ):
        self.ip_template = ip_template
        self.our_team_id = our_team_id
        self.teams: Dict[int, Team] = {}
        self._service_ports: Dict[str, int] = {}
        self._service_ids: Dict[str, int] = {}

    def add_team(self, team_id: int, name: str = "", ip_base: str = "") -> Team:
        """Register a team.

        Args:
            team_id: Unique team identifier.
            name: Human-readable team name.
            ip_base: Override IP for this team (bypasses template).

        Returns:
            The created Team object.
        """
        team = Team(
            id=team_id,
            name=name or f"Team {team_id}",
            ip_base=ip_base,
        )
        self.teams[team_id] = team
        return team

    def remove_team(self, team_id: int) -> bool:
        """Remove a team from tracking."""
        return self.teams.pop(team_id, None) is not None

    def register_service(self, service_name: str, port: int, service_id: int = 0) -> None:
        """Register a service with its port number.

        Args:
            service_name: Name of the service.
            port: Port the service listens on.
            service_id: Numeric ID for IP template substitution.
        """
        self._service_ports[service_name] = port
        if service_id or service_name not in self._service_ids:
            self._service_ids[service_name] = service_id or len(self._service_ids) + 1

    def get_ip(self, team_id: int, service: Optional[str] = None) -> str:
        """Get IP address for a team's service.

        Args:
            team_id: Team ID.
            service: Service name (for service-specific IP templates).

        Returns:
            IP address string.
        """
        team = self.teams.get(team_id)

        # If team has a custom IP base, use it
        if team and team.ip_base:
            return team.ip_base

        # Use IP template
        service_id = self._service_ids.get(service or "", 1)
        try:
            return self.ip_template.format(
                team_id=team_id,
                service_id=service_id,
            )
        except (KeyError, IndexError):
            # Fallback: simple template
            return f"10.{team_id}.{service_id}.2"

    def get_port(self, service: str) -> int:
        """Get port for a service.

        Args:
            service: Service name.

        Returns:
            Port number, or 0 if service not registered.
        """
        return self._service_ports.get(service, 0)

    def get_opponents(self) -> List[int]:
        """Return all team IDs except ours."""
        return [
            tid
            for tid in sorted(self.teams.keys())
            if tid != self.our_team_id and self.teams[tid].active
        ]

    def get_all_teams(self) -> List[Team]:
        """Return all teams sorted by ID."""
        return [self.teams[tid] for tid in sorted(self.teams.keys())]

    def get_team(self, team_id: int) -> Optional[Team]:
        """Look up a team by ID."""
        return self.teams.get(team_id)

    def get_our_team(self) -> Optional[Team]:
        """Return our team object."""
        return self.teams.get(self.our_team_id)

    def set_team_active(self, team_id: int, active: bool) -> None:
        """Mark a team as active or inactive (e.g., if they drop out)."""
        team = self.teams.get(team_id)
        if team:
            team.active = active

    def load_from_scoreboard(self, scoreboard_data: dict) -> int:
        """Auto-populate teams from scoreboard data.

        Expects scoreboard_data to have a "teams" key with a list of
        team dicts, each having at minimum "id" and optionally "name",
        "ip", "score", "active".

        Returns number of teams loaded.
        """
        teams_data = scoreboard_data.get("teams", [])
        count = 0

        for team_data in teams_data:
            tid = team_data.get("id")
            if tid is None:
                continue

            self.add_team(
                team_id=tid,
                name=team_data.get("name", ""),
                ip_base=team_data.get("ip", ""),
            )

            team = self.teams[tid]
            team.score = team_data.get("score", 0.0)
            team.active = team_data.get("active", True)

            # Load service ports if provided
            for svc in team_data.get("services", []):
                if isinstance(svc, dict):
                    svc_name = svc.get("name", "")
                    svc_port = svc.get("port", 0)
                    if svc_name and svc_port:
                        team.services[svc_name] = svc_port
                        self._service_ports[svc_name] = svc_port

            count += 1

        logger.info("Loaded %d teams from scoreboard data", count)
        return count

    def get_target_list(self, service: str) -> List[Dict[str, any]]:
        """Get list of all targets for a service (for exploit throwing).

        Returns list of dicts with team_id, ip, port for each opponent.
        """
        port = self.get_port(service)
        return [
            {
                "team_id": tid,
                "ip": self.get_ip(tid, service),
                "port": port,
                "name": self.teams[tid].name,
            }
            for tid in self.get_opponents()
        ]

    def __len__(self) -> int:
        return len(self.teams)

    def __repr__(self) -> str:
        return (
            f"TeamManager(teams={len(self.teams)}, "
            f"our_team={self.our_team_id}, "
            f"services={list(self._service_ports.keys())})"
        )
