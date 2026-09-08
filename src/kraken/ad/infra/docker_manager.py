"""Manage service containers for A/D competitions.

Handles Docker container lifecycle for vulnerable services, including
starting, stopping, restarting, health checks, and log retrieval.
Also supports deploying patched service versions.
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("kraken.ad.infra.docker_manager")


@dataclass
class ContainerInfo:
    """Information about a running service container."""

    container_id: str
    service_name: str
    image: str
    status: str  # running, stopped, restarting, dead
    port_mapping: str  # e.g., "0.0.0.0:1337->1337/tcp"
    created_at: str = ""
    uptime: str = ""


class ServiceDockerManager:
    """Manage Docker containers for vulnerable services.

    Provides lifecycle management for A/D service containers:
    - Start/stop/restart services
    - Deploy patched versions with zero-downtime
    - Monitor container health
    - Retrieve logs for debugging
    - Snapshot/restore container state
    """

    def __init__(self, compose_file: str = "", use_sudo: bool = False):
        """Initialize the Docker manager.

        Args:
            compose_file: Path to docker-compose.yml (if using compose).
            use_sudo: Whether to prefix docker commands with sudo.
        """
        self.compose_file = compose_file
        self.use_sudo = use_sudo
        self.containers: Dict[str, ContainerInfo] = {}

    def _docker_cmd(self, *args: str) -> List[str]:
        """Build a docker command with optional sudo prefix."""
        cmd = []
        if self.use_sudo:
            cmd.append("sudo")
        cmd.append("docker")
        cmd.extend(args)
        return cmd

    def _run(
        self,
        *args: str,
        timeout: int = 30,
        check: bool = False,
    ) -> subprocess.CompletedProcess:
        """Execute a docker command."""
        cmd = self._docker_cmd(*args)
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=check,
        )

    def list_containers(self, service_filter: str = "") -> List[ContainerInfo]:
        """List running containers, optionally filtered by service name."""
        try:
            result = self._run(
                "ps", "--format",
                "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}",
            )

            containers = []
            for line in result.stdout.strip().splitlines():
                parts = line.split("\t")
                if len(parts) < 4:
                    continue

                info = ContainerInfo(
                    container_id=parts[0][:12],
                    service_name=parts[1],
                    image=parts[2],
                    status=parts[3],
                    port_mapping=parts[4] if len(parts) > 4 else "",
                )

                if service_filter and service_filter not in info.service_name:
                    continue

                containers.append(info)
                self.containers[info.service_name] = info

            return containers

        except Exception as exc:
            logger.warning("Failed to list containers: %s", exc)
            return []

    def start_service(
        self,
        service_name: str,
        image: str = "",
        port: int = 0,
        volumes: Optional[List[str]] = None,
        env_vars: Optional[Dict[str, str]] = None,
    ) -> Optional[str]:
        """Start a service container.

        Args:
            service_name: Container name.
            image: Docker image to run.
            port: Host port to expose.
            volumes: Volume mounts (host:container).
            env_vars: Environment variables.

        Returns:
            Container ID if started successfully, None otherwise.
        """
        if not image:
            logger.error("No image specified for service %s", service_name)
            return None

        args = [
            "run", "-d",
            "--name", service_name,
            "--restart", "unless-stopped",
        ]

        if port:
            args.extend(["-p", f"{port}:{port}"])

        for vol in (volumes or []):
            args.extend(["-v", vol])

        for key, val in (env_vars or {}).items():
            args.extend(["-e", f"{key}={val}"])

        args.append(image)

        try:
            result = self._run(*args)
            if result.returncode == 0:
                container_id = result.stdout.strip()[:12]
                logger.info(
                    "Started container %s (%s) for %s",
                    container_id, image, service_name,
                )
                return container_id
            else:
                logger.error(
                    "Failed to start %s: %s", service_name, result.stderr.strip()
                )
                return None
        except Exception as exc:
            logger.error("Docker run failed for %s: %s", service_name, exc)
            return None

    def stop_service(self, service_name: str, timeout: int = 10) -> bool:
        """Stop a service container gracefully."""
        try:
            result = self._run("stop", "-t", str(timeout), service_name)
            if result.returncode == 0:
                logger.info("Stopped container %s", service_name)
                return True
            else:
                logger.warning("Failed to stop %s: %s", service_name, result.stderr)
                return False
        except Exception as exc:
            logger.warning("Stop command failed for %s: %s", service_name, exc)
            return False

    def restart_service(self, service_name: str) -> bool:
        """Restart a service container."""
        try:
            result = self._run("restart", service_name)
            if result.returncode == 0:
                logger.info("Restarted container %s", service_name)
                return True
            return False
        except Exception as exc:
            logger.warning("Restart failed for %s: %s", service_name, exc)
            return False

    def deploy_patched(
        self,
        service_name: str,
        new_image: str,
        port: int = 0,
        volumes: Optional[List[str]] = None,
        env_vars: Optional[Dict[str, str]] = None,
    ) -> bool:
        """Deploy a patched version of a service with minimal downtime.

        Strategy:
        1. Start new container with temporary name
        2. Verify new container is healthy
        3. Stop old container
        4. Rename new container to original name

        Args:
            service_name: Name of the service to update.
            new_image: Docker image with the patched version.
            port: Port to expose.
            volumes: Volume mounts.
            env_vars: Environment variables.

        Returns:
            True if deployment was successful.
        """
        temp_name = f"{service_name}_new"

        # Start new container
        new_id = self.start_service(
            temp_name,
            image=new_image,
            port=port + 1 if port else 0,  # Temp port
            volumes=volumes,
            env_vars=env_vars,
        )
        if not new_id:
            return False

        # Brief health check on new container
        time.sleep(2)
        if not self.is_healthy(temp_name):
            logger.warning("New container unhealthy, aborting deployment")
            self._run("rm", "-f", temp_name)
            return False

        # Stop old container
        self.stop_service(service_name, timeout=5)
        self._run("rm", service_name)

        # Rename new container
        result = self._run("rename", temp_name, service_name)
        if result.returncode != 0:
            logger.error("Failed to rename container: %s", result.stderr)
            return False

        # If we had a temporary port, we need to recreate with correct port
        # Docker doesn't support changing port mappings on a running container
        if port:
            self.stop_service(service_name, timeout=5)
            self._run("rm", service_name)
            final_id = self.start_service(
                service_name,
                image=new_image,
                port=port,
                volumes=volumes,
                env_vars=env_vars,
            )
            return final_id is not None

        logger.info("Deployed patched %s (%s)", service_name, new_image)
        return True

    def is_healthy(self, service_name: str) -> bool:
        """Check if a container is running and healthy."""
        try:
            result = self._run(
                "inspect", "--format", "{{.State.Running}}", service_name
            )
            return result.stdout.strip() == "true"
        except Exception:
            return False

    def get_logs(
        self,
        service_name: str,
        lines: int = 100,
        since: str = "",
    ) -> str:
        """Retrieve container logs.

        Args:
            service_name: Container name.
            lines: Number of lines to retrieve (tail).
            since: Time filter (e.g., "5m", "1h").

        Returns:
            Log output as string.
        """
        args = ["logs", "--tail", str(lines)]
        if since:
            args.extend(["--since", since])
        args.append(service_name)

        try:
            result = self._run(*args)
            return result.stdout + result.stderr
        except Exception as exc:
            return f"Failed to get logs: {exc}"

    def exec_in_container(
        self,
        service_name: str,
        command: List[str],
        timeout: int = 30,
    ) -> Tuple[int, str]:
        """Execute a command inside a running container.

        Returns (exit_code, output).
        """
        args = ["exec", service_name] + command
        try:
            result = self._run(*args, timeout=timeout)
            return result.returncode, result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return -1, "Command timed out"
        except Exception as exc:
            return -1, str(exc)

    def snapshot(self, service_name: str, tag: str = "backup") -> Optional[str]:
        """Create a snapshot (commit) of a container's current state.

        Returns the image ID of the snapshot, or None on failure.
        """
        image_name = f"{service_name}:{tag}"
        try:
            result = self._run("commit", service_name, image_name)
            if result.returncode == 0:
                image_id = result.stdout.strip()[:12]
                logger.info("Snapshot %s -> %s", service_name, image_name)
                return image_id
            return None
        except Exception as exc:
            logger.warning("Snapshot failed for %s: %s", service_name, exc)
            return None

    def restore(
        self,
        service_name: str,
        tag: str = "backup",
        port: int = 0,
    ) -> bool:
        """Restore a container from a snapshot.

        Stops the current container and starts a new one from the snapshot image.
        """
        image_name = f"{service_name}:{tag}"

        # Verify snapshot exists
        result = self._run("image", "inspect", image_name)
        if result.returncode != 0:
            logger.error("Snapshot %s not found", image_name)
            return False

        # Stop and remove current container
        self.stop_service(service_name, timeout=5)
        self._run("rm", service_name)

        # Start from snapshot
        new_id = self.start_service(
            service_name,
            image=image_name,
            port=port,
        )
        return new_id is not None

    def compose_up(self, services: Optional[List[str]] = None) -> bool:
        """Start services using docker-compose.

        Args:
            services: Optional list of specific services to start.
        """
        if not self.compose_file:
            logger.error("No compose file configured")
            return False

        cmd = self._docker_cmd("compose", "-f", self.compose_file, "up", "-d")
        if services:
            cmd.extend(services)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )
            return result.returncode == 0
        except Exception as exc:
            logger.error("docker-compose up failed: %s", exc)
            return False

    def compose_down(self) -> bool:
        """Stop all services managed by docker-compose."""
        if not self.compose_file:
            return False

        cmd = self._docker_cmd("compose", "-f", self.compose_file, "down")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            return result.returncode == 0
        except Exception as exc:
            logger.error("docker-compose down failed: %s", exc)
            return False
