"""Kraken A/D Configuration -- game settings, network topology, service definitions.

Supports loading from YAML config files and environment variables.
All durations are in seconds unless otherwise noted.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


@dataclass
class ServiceConfig:
    """Configuration for a single vulnerable service."""

    name: str
    port: int
    protocol: str = "tcp"  # tcp, http, udp
    binary: str = ""  # Path to service binary/script
    check_script: str = ""  # Custom SLA check script
    flag_id_url: str = ""  # URL to get flag IDs (some games use this)
    timeout: float = 10.0  # Exploit/check timeout per team


@dataclass
class NetworkConfig:
    """Network topology configuration."""

    our_team_id: int = 1
    team_count: int = 20
    ip_template: str = "10.{team_id}.{service_id}.2"
    game_interface: str = "game"
    vpn_interface: str = "tun0"
    dns_server: str = ""
    # Map service names to numeric IDs for IP template substitution
    service_id_map: Dict[str, int] = field(default_factory=dict)


@dataclass
class ScoringConfig:
    """Scorebot / flag submission configuration."""

    scorebot_url: str = ""
    scorebot_token: str = ""
    flag_format: str = r"[A-Z0-9]{31}="
    submit_rate_limit: float = 0.1  # Minimum seconds between submissions
    submit_batch_size: int = 1  # Flags per submission request
    # Some scorebot APIs accept bulk submissions
    bulk_submit_url: str = ""


@dataclass
class GameConfig:
    """Top-level game configuration."""

    # Timing
    tick_duration: int = 120  # Seconds between ticks
    flag_lifetime: int = 5  # Ticks before a flag expires

    # Network
    network: NetworkConfig = field(default_factory=NetworkConfig)

    # Scoring
    scoring: ScoringConfig = field(default_factory=ScoringConfig)

    # Services
    services: List[ServiceConfig] = field(default_factory=list)

    # Directories
    exploit_dir: str = "./exploits"
    patch_dir: str = "./patches"
    pcap_dir: str = "./pcaps"
    backup_dir: str = "./backups"
    log_dir: str = "./logs"

    # Concurrency
    max_concurrent_exploits: int = 50
    max_concurrent_checks: int = 20

    # Feature toggles
    auto_patch: bool = False  # Auto-apply patches when attacks detected
    auto_firewall: bool = False  # Auto-add firewall rules
    capture_traffic: bool = True  # Capture pcaps each tick
    submit_flags: bool = True  # Actually submit flags (disable for testing)

    @property
    def flag_regex(self) -> re.Pattern:
        """Compiled flag format regex."""
        return re.compile(self.scoring.flag_format)

    @property
    def our_team_id(self) -> int:
        return self.network.our_team_id

    @property
    def team_count(self) -> int:
        return self.network.team_count

    def get_service(self, name: str) -> Optional[ServiceConfig]:
        """Look up a service by name."""
        for svc in self.services:
            if svc.name == name:
                return svc
        return None

    def service_names(self) -> List[str]:
        """Return list of all service names."""
        return [s.name for s in self.services]

    def ensure_dirs(self) -> None:
        """Create all configured directories if they don't exist."""
        for d in [
            self.exploit_dir,
            self.patch_dir,
            self.pcap_dir,
            self.backup_dir,
            self.log_dir,
        ]:
            Path(d).mkdir(parents=True, exist_ok=True)


def load_config(path: str) -> GameConfig:
    """Load game configuration from a YAML file.

    Supports environment variable substitution in values using ``${VAR}``
    or ``${VAR:-default}`` syntax.
    """
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    raw = config_path.read_text()
    # Substitute environment variables: ${VAR} and ${VAR:-default}
    raw = _substitute_env_vars(raw)
    data = yaml.safe_load(raw)

    return _parse_config(data)


def _substitute_env_vars(text: str) -> str:
    """Replace ${VAR} and ${VAR:-default} patterns with env values."""

    def _replace(match: re.Match) -> str:
        var_name = match.group(1)
        default = match.group(3)  # May be None
        value = os.environ.get(var_name)
        if value is not None:
            return value
        if default is not None:
            return default
        return match.group(0)  # Leave unsubstituted

    return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(:-(.*?))?\}", _replace, text)


def _parse_config(data: Dict[str, Any]) -> GameConfig:
    """Parse raw YAML dict into GameConfig dataclass."""
    game_section = data.get("game", {})
    scoring_section = data.get("scoring", {})
    network_section = data.get("network", {})
    services_section = data.get("services", [])

    network = NetworkConfig(
        our_team_id=network_section.get("our_team_id", 1),
        team_count=network_section.get("team_count", 20),
        ip_template=network_section.get("ip_template", "10.{team_id}.{service_id}.2"),
        game_interface=network_section.get("game_interface", "game"),
        vpn_interface=network_section.get("vpn_interface", "tun0"),
        dns_server=network_section.get("dns_server", ""),
        service_id_map=network_section.get("service_id_map", {}),
    )

    scoring = ScoringConfig(
        scorebot_url=scoring_section.get("scorebot_url", ""),
        scorebot_token=scoring_section.get("scorebot_token", ""),
        flag_format=game_section.get("flag_format", r"[A-Z0-9]{31}="),
        submit_rate_limit=scoring_section.get("submit_rate_limit", 0.1),
        submit_batch_size=scoring_section.get("submit_batch_size", 1),
        bulk_submit_url=scoring_section.get("bulk_submit_url", ""),
    )

    services = []
    for svc_data in services_section:
        services.append(
            ServiceConfig(
                name=svc_data["name"],
                port=svc_data["port"],
                protocol=svc_data.get("protocol", "tcp"),
                binary=svc_data.get("binary", ""),
                check_script=svc_data.get("check_script", ""),
                flag_id_url=svc_data.get("flag_id_url", ""),
                timeout=svc_data.get("timeout", 10.0),
            )
        )

    return GameConfig(
        tick_duration=game_section.get("tick_duration", 120),
        flag_lifetime=game_section.get("flag_lifetime", 5),
        network=network,
        scoring=scoring,
        services=services,
        exploit_dir=data.get("exploit_dir", "./exploits"),
        patch_dir=data.get("patch_dir", "./patches"),
        pcap_dir=data.get("pcap_dir", "./pcaps"),
        backup_dir=data.get("backup_dir", "./backups"),
        log_dir=data.get("log_dir", "./logs"),
        max_concurrent_exploits=data.get("max_concurrent_exploits", 50),
        max_concurrent_checks=data.get("max_concurrent_checks", 20),
        auto_patch=data.get("auto_patch", False),
        auto_firewall=data.get("auto_firewall", False),
        capture_traffic=data.get("capture_traffic", True),
        submit_flags=data.get("submit_flags", True),
    )
