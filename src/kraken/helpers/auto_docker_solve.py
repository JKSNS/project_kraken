#!/usr/bin/env python3
"""auto_docker_solve -- Orchestrate Docker-based CTF challenges.

Detects Docker configuration (docker-compose.yml, Dockerfile) in a challenge
directory, builds and starts services, discovers exposed ports, waits for
readiness, then attacks services and scans logs/env/files for flags.

Capabilities:
  - Detect Dockerfile / docker-compose.yml in challenge directory
  - Build and start services (docker-compose up / docker build+run)
  - Discover exposed ports and map to localhost
  - Wait for service readiness with TCP health checks
  - Attack web and binary services using available helper scripts
  - Scan container logs, environment, and common file paths for flags
  - Cleanup: stop and remove containers after solving

Outputs EXTRACTED FLAG: <flag> on success.
"""
from __future__ import annotations

import argparse
import os
import re
import socket
import subprocess
import sys
import time

try:
    import yaml

    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

DEFAULT_FLAG_RE = re.compile(r"[a-zA-Z_]{2,}\{[^}]{3,}\}")


def _flag_re(prefix: str = "flag") -> re.Pattern:
    """Build flag regex from prefix."""
    return re.compile(rf"{re.escape(prefix)}\{{[A-Za-z0-9_\-\.]+\}}")


def _find_flags(text: str, pattern: re.Pattern) -> list[str]:
    """Extract all flag matches from text."""
    return pattern.findall(text)


def _docker_available() -> bool:
    """Check if Docker is available on this system."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _compose_command() -> list[str] | None:
    """Detect which compose command is available (v2 or v1)."""
    # Try docker compose (v2) first
    try:
        result = subprocess.run(
            ["docker", "compose", "version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return ["docker", "compose"]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Fall back to docker-compose (v1)
    try:
        result = subprocess.run(
            ["docker-compose", "version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return ["docker-compose"]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return None


class DockerSolver:
    """Orchestrates Docker-based CTF challenge solving."""

    def __init__(
        self,
        challenge_dir: str,
        prefix: str = "flag",
        timeout: int = 120,
        no_cleanup: bool = False,
    ):
        self.challenge_dir = os.path.abspath(challenge_dir)
        self.prefix = prefix
        self.timeout = timeout
        self.no_cleanup = no_cleanup
        self.flag_pattern = _flag_re(prefix)
        self.containers: list[str] = []
        self.ports: dict[int, int] = {}  # container_port -> host_port
        self.compose_cmd = _compose_command()
        self.compose_file: str | None = None

    def detect_docker_config(self) -> tuple[str | None, str | None]:
        """Find Docker configuration in challenge directory.

        Returns (config_type, config_path) where config_type is
        'compose' or 'dockerfile', or (None, None) if not found.
        """
        compose_names = [
            "docker-compose.yml",
            "docker-compose.yaml",
            "compose.yml",
            "compose.yaml",
        ]
        for name in compose_names:
            path = os.path.join(self.challenge_dir, name)
            if os.path.exists(path):
                self.compose_file = path
                return "compose", path

        dockerfile = os.path.join(self.challenge_dir, "Dockerfile")
        if os.path.exists(dockerfile):
            return "dockerfile", dockerfile

        return None, None

    def parse_compose(self, compose_path: str) -> dict:
        """Parse docker-compose.yml to extract service info.

        Returns dict of service_name -> {image, build, ports, environment}.
        """
        if not _HAS_YAML:
            print("[-] PyYAML not available, cannot parse compose file")
            return {}

        try:
            with open(compose_path, "r") as f:
                config = yaml.safe_load(f)
        except Exception as exc:
            print(f"[-] Failed to parse {compose_path}: {exc}")
            return {}

        if not config or "services" not in config:
            return {}

        services = {}
        for name, svc in config.get("services", {}).items():
            ports = []
            for port_mapping in svc.get("ports", []):
                if isinstance(port_mapping, str):
                    # Handle "8080:80", "8080:80/tcp", "80"
                    parts = port_mapping.replace("/tcp", "").replace("/udp", "")
                    pieces = parts.split(":")
                    if len(pieces) == 2:
                        try:
                            ports.append(
                                {
                                    "host": int(pieces[0]),
                                    "container": int(pieces[1]),
                                }
                            )
                        except ValueError:
                            pass
                    elif len(pieces) == 3:
                        # "0.0.0.0:8080:80"
                        try:
                            ports.append(
                                {
                                    "host": int(pieces[1]),
                                    "container": int(pieces[2]),
                                }
                            )
                        except ValueError:
                            pass
                    elif len(pieces) == 1:
                        try:
                            p = int(pieces[0])
                            ports.append({"host": p, "container": p})
                        except ValueError:
                            pass
                elif isinstance(port_mapping, dict):
                    target = port_mapping.get("target")
                    published = port_mapping.get("published", target)
                    if target:
                        ports.append({"host": int(published), "container": int(target)})
                elif isinstance(port_mapping, int):
                    ports.append({"host": port_mapping, "container": port_mapping})

            services[name] = {
                "image": svc.get("image", ""),
                "build": svc.get("build", ""),
                "ports": ports,
                "environment": svc.get("environment", {}),
            }

        return services

    def build_and_start(self, config_type: str, config_path: str) -> bool:
        """Build and start Docker services. Returns True on success."""
        if config_type == "compose":
            return self._start_compose(config_path)
        elif config_type == "dockerfile":
            return self._start_dockerfile(config_path)
        return False

    def _start_compose(self, config_path: str) -> bool:
        """Start services via docker-compose / docker compose."""
        if not self.compose_cmd:
            print("[-] No docker-compose or docker compose command found")
            return False

        cmd = self.compose_cmd + ["-f", config_path, "up", "-d", "--build"]
        print(f"[*] Running: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                cwd=self.challenge_dir,
                capture_output=True,
                text=True,
                timeout=180,
            )
        except subprocess.TimeoutExpired:
            print("[-] docker-compose up timed out (180s)")
            return False

        if result.returncode != 0:
            print(f"[-] docker-compose up failed: {result.stderr[:500]}")
            return False

        print("[+] Services started successfully")
        return True

    def _start_dockerfile(self, config_path: str) -> bool:
        """Build and run a single Dockerfile."""
        tag = f"kraken-{os.path.basename(self.challenge_dir).lower()}"
        container_name = f"kraken-{tag}"

        # Build image
        print(f"[*] Building image: {tag}")
        try:
            result = subprocess.run(
                ["docker", "build", "-t", tag, "."],
                cwd=self.challenge_dir,
                capture_output=True,
                text=True,
                timeout=180,
            )
        except subprocess.TimeoutExpired:
            print("[-] docker build timed out (180s)")
            return False

        if result.returncode != 0:
            print(f"[-] docker build failed: {result.stderr[:500]}")
            return False

        # Remove existing container with same name (if any)
        subprocess.run(
            ["docker", "rm", "-f", container_name],
            capture_output=True,
            timeout=10,
        )

        # Run container with automatic port mapping
        print(f"[*] Starting container: {container_name}")
        try:
            result = subprocess.run(
                ["docker", "run", "-d", "-P", "--name", container_name, tag],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except subprocess.TimeoutExpired:
            print("[-] docker run timed out")
            return False

        if result.returncode == 0:
            self.containers.append(container_name)
            print(f"[+] Container started: {container_name}")
            return True

        print(f"[-] docker run failed: {result.stderr[:500]}")
        return False

    def discover_ports(self) -> dict[int, int]:
        """Find which ports the services exposed. Returns {container_port: host_port}."""
        # Method 1: docker ps with port parsing
        try:
            result = subprocess.run(
                ["docker", "ps", "--format", "{{.Ports}}\t{{.Names}}"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            port_pattern = re.compile(
                r"(?:\d+\.\d+\.\d+\.\d+|:::?)(\d+)->(\d+)/(tcp|udp)"
            )
            for line in result.stdout.strip().splitlines():
                for match in port_pattern.finditer(line):
                    host_port = int(match.group(1))
                    container_port = int(match.group(2))
                    self.ports[container_port] = host_port
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Method 2: docker port for named containers
        for container in self.containers:
            try:
                result = subprocess.run(
                    ["docker", "port", container],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                # Format: "80/tcp -> 0.0.0.0:32768"
                for line in result.stdout.strip().splitlines():
                    m = re.match(r"(\d+)/\w+\s*->\s*[\d.:]+:(\d+)", line)
                    if m:
                        container_port = int(m.group(1))
                        host_port = int(m.group(2))
                        self.ports[container_port] = host_port
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        return self.ports

    def wait_for_service(self, host: str, port: int, timeout: int = 30) -> bool:
        """Wait for a TCP service to accept connections."""
        start = time.time()
        while time.time() - start < timeout:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((host, port))
                sock.close()
                return True
            except (ConnectionRefusedError, socket.timeout, OSError):
                time.sleep(1)
        return False

    def _run_compose_cmd(self, *extra_args: str) -> subprocess.CompletedProcess:
        """Run a compose command against the current project."""
        if not self.compose_cmd or not self.compose_file:
            return subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="")
        cmd = self.compose_cmd + ["-f", self.compose_file] + list(extra_args)
        try:
            return subprocess.run(
                cmd,
                cwd=self.challenge_dir,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr="")

    def check_flag_in_logs(self) -> list[str]:
        """Check container logs for flag patterns."""
        flags: list[str] = []

        # Compose logs
        if self.compose_file:
            result = self._run_compose_cmd("logs", "--no-color")
            flags.extend(_find_flags(result.stdout + result.stderr, self.flag_pattern))

        # Named container logs
        for container in self.containers:
            try:
                result = subprocess.run(
                    ["docker", "logs", container],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                flags.extend(
                    _find_flags(result.stdout + result.stderr, self.flag_pattern)
                )
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        return flags

    def check_flag_in_env(self) -> list[str]:
        """Check container environment variables for flag patterns."""
        flags: list[str] = []

        # Get service names from compose
        if self.compose_file:
            result = self._run_compose_cmd("ps", "--services")
            services = result.stdout.strip().splitlines()
            for svc in services:
                if not svc.strip():
                    continue
                result = self._run_compose_cmd("exec", "-T", svc.strip(), "env")
                flags.extend(_find_flags(result.stdout, self.flag_pattern))

        # Named containers
        for container in self.containers:
            try:
                result = subprocess.run(
                    ["docker", "exec", container, "env"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                flags.extend(_find_flags(result.stdout, self.flag_pattern))
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        return flags

    def check_flag_in_files(self) -> list[str]:
        """Check common flag file locations inside containers."""
        flags: list[str] = []
        flag_paths = [
            "/flag",
            "/flag.txt",
            "/root/flag.txt",
            "/home/ctf/flag.txt",
            "/home/user/flag.txt",
            "/app/flag.txt",
            "/app/flag",
            "/tmp/flag.txt",
            "/opt/flag.txt",
        ]

        # Compose services
        if self.compose_file:
            result = self._run_compose_cmd("ps", "--services")
            services = result.stdout.strip().splitlines()
            for svc in services:
                svc = svc.strip()
                if not svc:
                    continue
                for fpath in flag_paths:
                    result = self._run_compose_cmd("exec", "-T", svc, "cat", fpath)
                    flags.extend(_find_flags(result.stdout, self.flag_pattern))
                    if flags:
                        return flags

        # Named containers
        for container in self.containers:
            for fpath in flag_paths:
                try:
                    result = subprocess.run(
                        ["docker", "exec", container, "cat", fpath],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    flags.extend(_find_flags(result.stdout, self.flag_pattern))
                    if flags:
                        return flags
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    pass

        return flags

    def attack_service(self, host: str, port: int) -> list[str]:
        """Determine service type and launch appropriate attack."""
        flags: list[str] = []

        # Grab banner to detect service type
        banner = ""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            sock.settimeout(3)
            try:
                banner = sock.recv(4096).decode("utf-8", errors="ignore")
            except socket.timeout:
                pass
            sock.close()
        except (ConnectionRefusedError, socket.timeout, OSError):
            pass

        # Check banner for flags
        flags.extend(_find_flags(banner, self.flag_pattern))
        if flags:
            return flags

        # Route to attack type
        is_http = (
            "HTTP" in banner
            or "<!DOCTYPE" in banner.lower()
            or "<html" in banner.lower()
            or port in (80, 443, 8080, 8443, 3000, 5000, 8000)
        )

        if is_http:
            flags.extend(self._attack_web(host, port))
        if not flags:
            flags.extend(self._attack_binary(host, port))

        return flags

    def _attack_web(self, host: str, port: int) -> list[str]:
        """Launch web attacks against HTTP service."""
        flags: list[str] = []
        helpers_dir = os.path.dirname(os.path.abspath(__file__))

        # Try auto_web_exploit helper
        web_exploit = os.path.join(helpers_dir, "auto_web_exploit.py")
        if os.path.exists(web_exploit):
            print(f"[*] Running auto_web_exploit against http://{host}:{port}")
            try:
                result = subprocess.run(
                    [
                        sys.executable,
                        web_exploit,
                        "--url",
                        f"http://{host}:{port}",
                        "--prefix",
                        self.prefix,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                )
                flags.extend(_find_flags(result.stdout, self.flag_pattern))
                if flags:
                    return flags
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        # Manual: probe common endpoints
        print(f"[*] Probing common HTTP endpoints on port {port}")
        try:
            from urllib.request import Request, urlopen
            from urllib.error import URLError
        except ImportError:
            return flags

        probe_paths = [
            "/",
            "/flag",
            "/flag.txt",
            "/admin",
            "/api",
            "/api/flag",
            "/robots.txt",
            "/.git/HEAD",
            "/.env",
            "/debug",
            "/console",
            "/source",
            "/shell",
        ]

        for path in probe_paths:
            try:
                url = f"http://{host}:{port}{path}"
                req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
                resp = urlopen(req, timeout=5)
                data = resp.read().decode("utf-8", errors="ignore")
                found = _find_flags(data, self.flag_pattern)
                if found:
                    flags.extend(found)
                    return flags
                # Also check response headers
                for header, value in resp.headers.items():
                    found = _find_flags(str(value), self.flag_pattern)
                    if found:
                        flags.extend(found)
                        return flags
            except Exception:
                pass

        return flags

    def _attack_binary(self, host: str, port: int) -> list[str]:
        """Launch binary/TCP attacks against a service."""
        flags: list[str] = []
        helpers_dir = os.path.dirname(os.path.abspath(__file__))

        # Try auto_remote_interact helper
        remote_interact = os.path.join(helpers_dir, "auto_remote_interact.py")
        if os.path.exists(remote_interact):
            print(f"[*] Running auto_remote_interact against {host}:{port}")
            try:
                result = subprocess.run(
                    [
                        sys.executable,
                        remote_interact,
                        "--host",
                        host,
                        "--port",
                        str(port),
                        "--flag-format",
                        rf"{re.escape(self.prefix)}\{{[a-zA-Z0-9_]+\}}",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                )
                flags.extend(_find_flags(result.stdout, self.flag_pattern))
                if flags:
                    return flags
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        # Try auto_pwn_template helper
        pwn_template = os.path.join(helpers_dir, "auto_pwn_template.py")
        if os.path.exists(pwn_template):
            print(f"[*] Running auto_pwn_template against {host}:{port}")
            try:
                result = subprocess.run(
                    [
                        sys.executable,
                        pwn_template,
                        "--host",
                        host,
                        "--port",
                        str(port),
                        "--prefix",
                        self.prefix,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                )
                flags.extend(_find_flags(result.stdout, self.flag_pattern))
                if flags:
                    return flags
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        # Manual: try basic TCP payloads
        print(f"[*] Trying basic TCP payloads on {host}:{port}")
        payloads = [
            b"",
            b"\n",
            b"help\n",
            b"flag\n",
            b"cat /flag*\n",
            b"1\n",
            b"admin\n",
        ]
        for payload in payloads:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((host, port))

                # Receive initial data
                data = b""
                try:
                    sock.settimeout(2)
                    data = sock.recv(4096)
                except socket.timeout:
                    pass

                if payload:
                    sock.send(payload)
                    time.sleep(0.5)
                    try:
                        sock.settimeout(3)
                        data += sock.recv(4096)
                    except socket.timeout:
                        pass

                sock.close()

                text = data.decode("utf-8", errors="ignore")
                found = _find_flags(text, self.flag_pattern)
                if found:
                    flags.extend(found)
                    return flags
            except (ConnectionRefusedError, socket.timeout, OSError):
                pass

        return flags

    def cleanup(self) -> None:
        """Stop and remove all containers."""
        if self.no_cleanup:
            print("[*] Skipping cleanup (--no-cleanup)")
            return

        print("[*] Cleaning up containers...")

        # Compose down
        if self.compose_file and self.compose_cmd:
            try:
                subprocess.run(
                    self.compose_cmd + ["-f", self.compose_file, "down", "-v", "--remove-orphans"],
                    cwd=self.challenge_dir,
                    capture_output=True,
                    timeout=30,
                )
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        # Remove named containers
        for container in self.containers:
            try:
                subprocess.run(
                    ["docker", "rm", "-f", container],
                    capture_output=True,
                    timeout=10,
                )
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

    def solve(self) -> list[str]:
        """Main solve loop. Returns list of flags found."""
        if not _docker_available():
            print("[-] Docker is not available on this system")
            return []

        try:
            config_type, config_path = self.detect_docker_config()
            if not config_type:
                print("[-] No Docker configuration found in challenge directory")
                return []

            print(f"[*] Found {config_type}: {config_path}")

            # Parse compose for port info before starting
            compose_services = {}
            if config_type == "compose" and _HAS_YAML:
                compose_services = self.parse_compose(config_path)
                if compose_services:
                    for name, svc in compose_services.items():
                        port_str = ", ".join(
                            f"{p['host']}:{p['container']}" for p in svc["ports"]
                        )
                        print(f"  [*] Service '{name}': ports={port_str or 'none'}")

            # Build and start
            print("[*] Building and starting services...")
            if not self.build_and_start(config_type, config_path):
                print("[-] Failed to start services")
                return []

            # Give services time to initialize
            time.sleep(3)

            # Discover ports
            self.discover_ports()

            # If no ports discovered via docker ps, use compose file ports
            if not self.ports and compose_services:
                for _name, svc in compose_services.items():
                    for port_info in svc["ports"]:
                        self.ports[port_info["container"]] = port_info["host"]

            if self.ports:
                port_str = ", ".join(
                    f"{cp}->{hp}" for cp, hp in self.ports.items()
                )
                print(f"[*] Exposed ports: {port_str}")
            else:
                print("[*] No exposed ports detected")

            # Phase 1: Check easy wins -- logs, env, files
            print("[*] Phase 1: Checking logs, environment, and files...")

            flags = self.check_flag_in_logs()
            if flags:
                for f in flags:
                    print(f"EXTRACTED FLAG: {f}")
                return flags

            flags = self.check_flag_in_env()
            if flags:
                for f in flags:
                    print(f"EXTRACTED FLAG: {f}")
                return flags

            flags = self.check_flag_in_files()
            if flags:
                for f in flags:
                    print(f"EXTRACTED FLAG: {f}")
                return flags

            # Phase 2: Attack each exposed port
            print("[*] Phase 2: Attacking exposed services...")
            for container_port, host_port in self.ports.items():
                print(f"[*] Waiting for service on port {host_port} (container:{container_port})...")
                if self.wait_for_service("localhost", host_port, timeout=30):
                    print(f"[*] Service ready on port {host_port}, attacking...")
                    flags = self.attack_service("localhost", host_port)
                    if flags:
                        for f in flags:
                            print(f"EXTRACTED FLAG: {f}")
                        return flags
                else:
                    print(f"[-] Service on port {host_port} did not become ready")

            # Phase 3: Re-check logs after attacks (flag may appear in response logs)
            print("[*] Phase 3: Re-checking logs after interactions...")
            flags = self.check_flag_in_logs()
            if flags:
                for f in flags:
                    print(f"EXTRACTED FLAG: {f}")
                return flags

            print("[-] Could not extract flag from Docker challenge")
            return []

        finally:
            self.cleanup()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Kraken Docker Solver -- orchestrate Docker-based CTF challenges"
    )
    parser.add_argument(
        "--challenge-dir",
        required=True,
        help="Challenge directory containing Docker config",
    )
    parser.add_argument("--prefix", default="flag", help="Flag prefix (default: flag)")
    parser.add_argument(
        "--timeout",
        type=int,
        default=120,
        help="Timeout per attack in seconds (default: 120)",
    )
    parser.add_argument(
        "--no-cleanup",
        action="store_true",
        help="Don't cleanup containers after solving",
    )
    args = parser.parse_args()

    if not os.path.isdir(args.challenge_dir):
        print(f"[-] Not a directory: {args.challenge_dir}", file=sys.stderr)
        sys.exit(1)

    solver = DockerSolver(
        args.challenge_dir,
        prefix=args.prefix,
        timeout=args.timeout,
        no_cleanup=args.no_cleanup,
    )
    flags = solver.solve()
    sys.exit(0 if flags else 1)


if __name__ == "__main__":
    main()
