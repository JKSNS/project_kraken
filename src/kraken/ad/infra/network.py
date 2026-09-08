"""VPN/network utilities for A/D competition infrastructure.

Handles VPN connection management, network interface configuration,
and connectivity testing for the game network.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("kraken.ad.infra.network")


class NetworkManager:
    """Manage network configuration for A/D competitions.

    Handles:
    - OpenVPN connection to game network
    - WireGuard tunnel management
    - Network interface status monitoring
    - Connectivity testing to game infrastructure
    - Route management for game network
    """

    def __init__(
        self,
        game_interface: str = "game",
        vpn_interface: str = "tun0",
    ):
        self.game_interface = game_interface
        self.vpn_interface = vpn_interface
        self._vpn_proc: Optional[subprocess.Popen] = None

    def connect_openvpn(
        self,
        config_path: str,
        auth_file: Optional[str] = None,
        log_file: str = "/tmp/kraken_vpn.log",
    ) -> bool:
        """Connect to game network via OpenVPN.

        Args:
            config_path: Path to .ovpn configuration file.
            auth_file: Optional path to auth credentials file.
            log_file: Path to write VPN logs.

        Returns:
            True if connection initiated successfully.
        """
        if not Path(config_path).exists():
            logger.error("OpenVPN config not found: %s", config_path)
            return False

        cmd = [
            "sudo", "openvpn",
            "--config", config_path,
            "--log", log_file,
            "--daemon", "kraken-vpn",
        ]

        if auth_file:
            cmd.extend(["--auth-user-pass", auth_file])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                logger.info("OpenVPN connection initiated")
                return True
            else:
                logger.error("OpenVPN failed: %s", result.stderr)
                return False
        except Exception as exc:
            logger.error("Failed to start OpenVPN: %s", exc)
            return False

    def connect_wireguard(self, config_path: str) -> bool:
        """Connect to game network via WireGuard.

        Args:
            config_path: Path to WireGuard .conf file.

        Returns:
            True if connection successful.
        """
        if not Path(config_path).exists():
            logger.error("WireGuard config not found: %s", config_path)
            return False

        interface = Path(config_path).stem

        try:
            result = subprocess.run(
                ["sudo", "wg-quick", "up", config_path],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode == 0:
                logger.info("WireGuard interface %s up", interface)
                return True
            else:
                logger.error("WireGuard failed: %s", result.stderr)
                return False
        except Exception as exc:
            logger.error("Failed to start WireGuard: %s", exc)
            return False

    def disconnect_wireguard(self, config_path: str) -> bool:
        """Disconnect WireGuard tunnel."""
        try:
            result = subprocess.run(
                ["sudo", "wg-quick", "down", config_path],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except Exception as exc:
            logger.warning("Failed to disconnect WireGuard: %s", exc)
            return False

    def get_interfaces(self) -> List[Dict[str, str]]:
        """List network interfaces with their IP addresses."""
        interfaces = []
        try:
            result = subprocess.run(
                ["ip", "-4", "addr", "show"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            current_iface = ""
            for line in result.stdout.splitlines():
                # Interface line
                iface_match = re.match(r"\d+:\s+(\S+):", line)
                if iface_match:
                    current_iface = iface_match.group(1)

                # IP address line
                ip_match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", line)
                if ip_match and current_iface:
                    interfaces.append(
                        {
                            "name": current_iface,
                            "ip": ip_match.group(1),
                        }
                    )

        except Exception as exc:
            logger.warning("Failed to list interfaces: %s", exc)

        return interfaces

    def is_game_network_up(self) -> bool:
        """Check if the game network interface is up."""
        interfaces = self.get_interfaces()
        game_ifaces = [
            i for i in interfaces
            if i["name"] in (self.game_interface, self.vpn_interface)
        ]
        return len(game_ifaces) > 0

    def get_our_ip(self) -> Optional[str]:
        """Get our IP address on the game network."""
        interfaces = self.get_interfaces()
        for iface in interfaces:
            if iface["name"] in (self.game_interface, self.vpn_interface):
                return iface["ip"].split("/")[0]
        return None

    async def test_connectivity(
        self,
        target_ip: str,
        count: int = 3,
        timeout: float = 5.0,
    ) -> Tuple[bool, float]:
        """Test network connectivity to a target.

        Returns (reachable, avg_latency_ms).
        """
        try:
            proc = await asyncio.create_subprocess_exec(
                "ping", "-c", str(count), "-W", str(int(timeout)), target_ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 5)
            output = stdout.decode()

            if proc.returncode == 0:
                # Parse average latency
                match = re.search(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/", output)
                latency = float(match.group(1)) if match else 0.0
                return True, latency
            return False, 0.0

        except (asyncio.TimeoutError, Exception):
            return False, 0.0

    async def scan_team_services(
        self,
        team_ip: str,
        ports: List[int],
        timeout: float = 2.0,
    ) -> Dict[int, bool]:
        """Quick port scan of a team's services.

        Returns dict mapping port to open/closed status.
        """
        results: Dict[int, bool] = {}

        async def _check_port(port: int) -> None:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(team_ip, port),
                    timeout=timeout,
                )
                writer.close()
                await writer.wait_closed()
                results[port] = True
            except Exception:
                results[port] = False

        await asyncio.gather(*[_check_port(p) for p in ports])
        return results

    def add_route(self, network: str, gateway: str, interface: str = "") -> bool:
        """Add a network route.

        Args:
            network: Target network (e.g., "10.0.0.0/8").
            gateway: Gateway IP address.
            interface: Optional network interface.
        """
        cmd = ["sudo", "ip", "route", "add", network, "via", gateway]
        if interface:
            cmd.extend(["dev", interface])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                logger.info("Added route: %s via %s", network, gateway)
                return True
            else:
                logger.warning("Failed to add route: %s", result.stderr)
                return False
        except Exception as exc:
            logger.warning("Route command failed: %s", exc)
            return False

    def get_routes(self) -> List[str]:
        """Get current routing table."""
        try:
            result = subprocess.run(
                ["ip", "route", "show"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.stdout.strip().splitlines()
        except Exception:
            return []
