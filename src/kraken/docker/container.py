"""Docker container lifecycle management for challenge execution."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from kraken.config import DockerConfig
from kraken.logging.structured import get_logger

log = get_logger(__name__)


class ChallengeContainer:
    """Manages an isolated Docker container for a single challenge."""

    def __init__(self, challenge_id: str, config: DockerConfig | None = None):
        self.challenge_id = challenge_id
        self.config = config or DockerConfig()
        self._container = None
        self._client = None

    async def start(self, challenge_path: str) -> str:
        """Create and start a container with the challenge binary.

        Returns the container ID.
        """
        import docker

        self._client = docker.from_env()
        container_name = f"kraken-{self.challenge_id}"

        # Remove existing container if present
        try:
            old = self._client.containers.get(container_name)
            old.remove(force=True)
        except docker.errors.NotFound:
            pass

        log.info("container_start", challenge=self.challenge_id, image=self.config.image)

        self._container = self._client.containers.run(
            self.config.image,
            name=container_name,
            detach=True,
            tty=True,
            cap_add=["SYS_PTRACE"],
            security_opt=["seccomp=unconfined"],
            network_mode=self.config.network_mode,
            working_dir="/challenge",
            command="sleep infinity",
        )

        # Copy challenge files into container
        challenge_dir = Path(challenge_path)
        if challenge_dir.is_file():
            self._copy_to_container(str(challenge_dir), f"/challenge/{challenge_dir.name}")
        elif challenge_dir.is_dir():
            for f in challenge_dir.iterdir():
                if f.is_file():
                    self._copy_to_container(str(f), f"/challenge/{f.name}")

        log.info("container_ready", container_id=self._container.short_id)
        return self._container.id

    def _copy_to_container(self, src: str, dst: str) -> None:
        """Copy a file into the running container."""
        import tarfile
        import io

        data = Path(src).read_bytes()
        tar_stream = io.BytesIO()
        with tarfile.open(fileobj=tar_stream, mode="w") as tar:
            info = tarfile.TarInfo(name=Path(dst).name)
            info.size = len(data)
            info.mode = 0o755
            tar.addfile(info, io.BytesIO(data))
        tar_stream.seek(0)

        self._container.put_archive(str(Path(dst).parent), tar_stream)

    async def exec_run(self, cmd: str | list[str], timeout: int | None = None) -> dict:
        """Execute a command inside the container.

        Returns dict with exit_code, stdout, stderr.
        """
        if self._container is None:
            raise RuntimeError("Container not started")

        timeout = timeout or self.config.tool_timeout

        if isinstance(cmd, str):
            cmd = ["sh", "-c", cmd]

        log.debug("container_exec", cmd=cmd[:3])

        exit_code, output = self._container.exec_run(cmd, demux=True)
        stdout = output[0].decode(errors="replace") if output[0] else ""
        stderr = output[1].decode(errors="replace") if output[1] else ""

        return {
            "exit_code": exit_code,
            "stdout": stdout,
            "stderr": stderr,
        }

    async def stop(self) -> None:
        """Stop and remove the container."""
        if self._container:
            log.info("container_stop", container_id=self._container.short_id)
            try:
                self._container.stop(timeout=5)
                self._container.remove(force=True)
            except Exception as e:
                log.warning("container_stop_error", error=str(e))
            self._container = None

        if self._client:
            self._client.close()
            self._client = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.stop()
