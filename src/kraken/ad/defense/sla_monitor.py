"""Monitor service availability for SLA compliance.

In Attack/Defense CTFs, services must remain available to the game's
SLA checker. If a service goes down or returns incorrect responses,
the team loses defense points. This monitor tracks uptime and alerts
on failures.
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
import time
from typing import Dict, Optional

logger = logging.getLogger("kraken.ad.defense.sla_monitor")


class SLAMonitor:
    """Monitor service availability and track uptime statistics.

    Supports TCP connectivity checks, HTTP health checks, and custom
    check scripts. Records historical uptime percentage per service.
    """

    def __init__(self, services: Dict[str, Dict]):
        """Initialize with service definitions.

        Args:
            services: Mapping of service name to config dict with keys:
                - port: int
                - protocol: "tcp" | "http" | "udp"
                - check_script: optional path to custom check script
                - timeout: float (seconds)
        """
        self.services = services
        self.status: Dict[str, Dict] = {}

        # Initialize status tracking
        for name in services:
            self.status[name] = {
                "up": True,
                "last_check": 0.0,
                "checks_total": 0,
                "checks_passed": 0,
                "consecutive_failures": 0,
                "last_error": "",
            }

    async def check_all(self, host: str = "127.0.0.1") -> Dict[str, bool]:
        """Check all services and return status map.

        Args:
            host: IP address to check services on (our team's IP).

        Returns:
            Dict mapping service name to up/down boolean.
        """
        tasks = {}
        for name, config in self.services.items():
            tasks[name] = self._check_service(name, config, host)

        results: Dict[str, bool] = {}
        for name, coro in tasks.items():
            try:
                results[name] = await coro
            except Exception as exc:
                logger.warning("SLA check error for %s: %s", name, exc)
                results[name] = False
                self._record_failure(name, str(exc))

        return results

    async def check_service(self, service_name: str, host: str = "127.0.0.1") -> bool:
        """Check a single service by name."""
        config = self.services.get(service_name)
        if not config:
            logger.warning("Unknown service: %s", service_name)
            return False
        return await self._check_service(service_name, config, host)

    async def _check_service(self, name: str, config: Dict, host: str) -> bool:
        """Internal: run the appropriate check for a service."""
        protocol = config.get("protocol", "tcp")
        port = config.get("port", 0)
        timeout = config.get("timeout", 5.0)
        check_script = config.get("check_script", "")

        up = False

        if check_script:
            up = await self.check_custom(check_script, host, port, timeout)
        elif protocol == "http":
            url = f"http://{host}:{port}/"
            up = await self.check_http(url, timeout=timeout)
        elif protocol == "udp":
            up = await self.check_udp(host, port, timeout=timeout)
        else:
            up = await self.check_tcp(host, port, timeout=timeout)

        self._record_result(name, up)
        return up

    async def check_tcp(
        self,
        host: str,
        port: int,
        timeout: float = 5.0,
    ) -> bool:
        """TCP connectivity check -- verify the port accepts connections."""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )
            writer.close()
            await writer.wait_closed()
            return True
        except asyncio.TimeoutError:
            return False
        except (ConnectionRefusedError, OSError):
            return False
        except Exception as exc:
            logger.debug("TCP check %s:%d failed: %s", host, port, exc)
            return False

    async def check_http(
        self,
        url: str,
        expected_status: int = 200,
        timeout: float = 5.0,
    ) -> bool:
        """HTTP health check -- verify the service responds with expected status."""
        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=timeout) as resp:
                    return resp.status == expected_status
        except ImportError:
            # Fallback to basic TCP if aiohttp not available
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return await self.check_tcp(
                parsed.hostname or "127.0.0.1",
                parsed.port or 80,
                timeout=timeout,
            )
        except Exception:
            return False

    async def check_udp(
        self,
        host: str,
        port: int,
        timeout: float = 5.0,
    ) -> bool:
        """UDP connectivity check -- send a probe and check for response or ICMP unreachable."""
        try:
            loop = asyncio.get_running_loop()

            # Create UDP socket
            transport, protocol = await asyncio.wait_for(
                loop.create_datagram_endpoint(
                    asyncio.DatagramProtocol,
                    remote_addr=(host, port),
                ),
                timeout=timeout,
            )

            # Send probe
            transport.sendto(b"\x00")

            # Wait briefly for ICMP unreachable (would cause an error)
            await asyncio.sleep(0.5)

            transport.close()
            return True

        except Exception:
            return False

    async def check_custom(
        self,
        script_path: str,
        host: str = "127.0.0.1",
        port: int = 0,
        timeout: float = 10.0,
    ) -> bool:
        """Run a custom SLA check script.

        The script receives HOST and PORT as arguments and environment
        variables. Exit code 0 means the check passed.
        """
        try:
            proc = await asyncio.create_subprocess_exec(
                "python3", script_path, host, str(port),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={
                    **dict(__import__("os").environ),
                    "SLA_HOST": host,
                    "SLA_PORT": str(port),
                },
            )
            _, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return proc.returncode == 0
        except asyncio.TimeoutError:
            logger.warning("Custom SLA check timed out: %s", script_path)
            try:
                proc.kill()  # type: ignore
            except Exception:
                pass
            return False
        except Exception as exc:
            logger.warning("Custom SLA check failed: %s", exc)
            return False

    def _record_result(self, name: str, up: bool) -> None:
        """Record a check result for uptime tracking."""
        if name not in self.status:
            self.status[name] = {
                "up": True,
                "last_check": 0.0,
                "checks_total": 0,
                "checks_passed": 0,
                "consecutive_failures": 0,
                "last_error": "",
            }

        self.status[name]["up"] = up
        self.status[name]["last_check"] = time.time()
        self.status[name]["checks_total"] += 1

        if up:
            self.status[name]["checks_passed"] += 1
            self.status[name]["consecutive_failures"] = 0
        else:
            self.status[name]["consecutive_failures"] += 1

    def _record_failure(self, name: str, error: str) -> None:
        """Record an error message for a failed check."""
        if name in self.status:
            self.status[name]["last_error"] = error

    def get_uptime(self, service: str) -> float:
        """Return uptime percentage for a service (0.0 - 100.0)."""
        s = self.status.get(service)
        if not s or s["checks_total"] == 0:
            return 100.0  # No checks yet = assume up
        return (s["checks_passed"] / s["checks_total"]) * 100.0

    def get_status_summary(self) -> Dict[str, Dict]:
        """Return status summary for all services."""
        return {
            name: {
                "up": s["up"],
                "uptime": self.get_uptime(name),
                "consecutive_failures": s["consecutive_failures"],
                "last_check": s["last_check"],
                "last_error": s.get("last_error", ""),
            }
            for name, s in self.status.items()
        }

    def is_any_down(self) -> bool:
        """Return True if any service is currently down."""
        return any(not s["up"] for s in self.status.values())

    def get_critical_services(self, max_failures: int = 3) -> list[str]:
        """Return services with too many consecutive failures."""
        return [
            name
            for name, s in self.status.items()
            if s["consecutive_failures"] >= max_failures
        ]
