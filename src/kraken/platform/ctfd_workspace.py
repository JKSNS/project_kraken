"""CTFd platform client -- pull challenges and submit flags.

Handles the full lifecycle of a live CTF competition:
  1. Authenticate with a CTFd instance via API token
  2. Pull all challenges (metadata, descriptions, file attachments)
  3. Create local directory structure for the solver pipeline
  4. Submit validated flags back to the platform

Authentication:
    CTFd uses bearer tokens generated at /settings → Access Tokens.
    All requests use ``Authorization: Token <access_token>`` header.

Flag submission policy:
    Only HIGH CONFIDENCE flags are submitted automatically:
      - Flag must match the locked flag format regex
      - Flag must not be a known false positive pattern
      - One submission per challenge (no brute-force, no retries on "incorrect")

Usage:
    from kraken.platform.ctfd_workspace import CTFdClient

    client = CTFdClient("https://ctf.example.com", token="ctfd_xxx")
    challenges = client.pull_challenges()
    workspace = client.setup_workspace(challenges, base_dir="ctfs/")

    # After solving:
    client.submit_flag(challenge_id=42, flag="flag{...}")
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests

from kraken.logging.structured import get_logger

log = get_logger(__name__)

# Flags that look valid but are test/example values -- never submit these
_FALSE_POSITIVE_FLAGS = {
    "flag{test}",
    "flag{example}",
    "flag{placeholder}",
    "flag{TODO}",
    "flag{flag}",
    "flag{REDACTED}",
    "flag{...}",
    "flag{}",
}


@dataclass
class CTFdChallenge:
    """A challenge pulled from CTFd."""

    id: int
    name: str
    category: str
    description: str
    value: int
    files: list[str] = field(default_factory=list)  # relative download URLs
    tags: list[str] = field(default_factory=list)
    solves: int = 0
    solved_by_me: bool = False
    local_dir: str = ""  # set after setup_workspace
    connection_info: str = ""  # nc host port, https URL, or "in-person" marker

    @property
    def is_physical(self) -> bool:
        """True if connection_info indicates an in-person/physical challenge."""
        if not self.connection_info:
            return False
        needles = ("in person", "in-person", "on campus", "library")
        return any(n in self.connection_info.lower() for n in needles)

    @property
    def is_remote_network(self) -> bool:
        """True if connection_info points to a reachable network service."""
        if self.is_physical or not self.connection_info:
            return False
        ci = self.connection_info.strip().lower()
        return ci.startswith(("nc ", "http://", "https://", "ssh ", "tcp ")) or ":" in ci


@dataclass
class SubmitResult:
    """Result of a flag submission attempt."""

    challenge_id: int
    flag: str
    status: str  # "correct", "incorrect", "already_solved", "ratelimited", "paused"
    message: str = ""


class CTFdClient:
    """Client for interacting with a CTFd instance.

    Args:
        url: Base URL of the CTFd instance (e.g., "https://ctf.example.com")
        token: API access token (generated at /settings → Access Tokens)
        timeout: Request timeout in seconds
    """

    def __init__(self, url: str, token: str, timeout: int = 30):
        self.base_url = url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Authorization": f"Token {token}",
                "Content-Type": "application/json",
            }
        )
        self._ctf_name: str = ""

    @property
    def ctf_name(self) -> str:
        """CTF name, derived from URL or fetched from API."""
        if not self._ctf_name:
            self._ctf_name = urlparse(self.base_url).hostname or "ctf"
            # Try to get the real name from the API
            try:
                resp = self._get("/api/v1/configs/ctf_name")
                if resp.get("success"):
                    self._ctf_name = resp["data"].get("value", self._ctf_name)
            except Exception:
                pass
            # Sanitize for filesystem
            self._ctf_name = re.sub(r"[^A-Za-z0-9._-]+", "_", self._ctf_name).strip("._")
        return self._ctf_name

    def _request(self, method: str, path: str, retries: int = 3, **kwargs) -> requests.Response:
        """HTTP request with retry, backoff, and rate limit handling."""
        url = urljoin(self.base_url + "/", path.lstrip("/"))
        kwargs.setdefault("timeout", self.timeout)

        for attempt in range(retries):
            try:
                resp = self._session.request(method, url, **kwargs)
                if resp.status_code == 429:
                    wait = min(2**attempt * 2, 30)
                    log.warning("ctfd_rate_limited", url=path, wait=wait)
                    time.sleep(wait)
                    continue
                resp.raise_for_status()
                return resp
            except requests.ConnectionError as e:
                if attempt < retries - 1:
                    wait = 2**attempt
                    log.warning("ctfd_connection_error", url=path, attempt=attempt, wait=wait, error=str(e)[:100])
                    time.sleep(wait)
                    continue
                raise

        raise RuntimeError(f"CTFd request failed after {retries} attempts: {method} {path}")

    def _get(self, path: str) -> dict:
        """GET request to CTFd API with retry."""
        return self._request("GET", path).json()

    def _post(self, path: str, data: dict) -> dict:
        """POST request to CTFd API with retry."""
        return self._request("POST", path, json=data).json()

    @staticmethod
    def _clean_html(text: str) -> str:
        """Strip HTML tags and decode entities from CTFd descriptions."""
        import html

        # Replace <br>, <p>, <li> with newlines for readability
        text = re.sub(r"<br\s*/?>", "\n", text, flags=re.IGNORECASE)
        text = re.sub(r"</p>|</li>|</div>", "\n", text, flags=re.IGNORECASE)
        # Replace <code> blocks with backticks
        text = re.sub(r"<code>(.*?)</code>", r"`\1`", text, flags=re.DOTALL)
        # Strip remaining tags
        text = re.sub(r"<[^>]+>", "", text)
        # Decode HTML entities (&amp; → &, &#39; → ', etc.)
        text = html.unescape(text)
        # Collapse excessive whitespace
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text.strip()

    def _download_file(self, file_url: str, dest: Path) -> Path:
        """Download a challenge file attachment with retry."""
        if file_url.startswith("/"):
            url = file_url
        elif file_url.startswith("http"):
            # Absolute URL -- use directly, but still need auth
            url = file_url.replace(self.base_url, "")
            if url.startswith("http"):
                # External URL, download without auth
                resp = requests.get(file_url, timeout=self.timeout, stream=True)
                resp.raise_for_status()
                filename = Path(urlparse(file_url).path).name or "attachment"
                dest_path = dest / filename
                with open(dest_path, "wb") as f:
                    for chunk in resp.iter_content(chunk_size=8192):
                        f.write(chunk)
                return dest_path
        else:
            url = "/" + file_url

        resp = self._request("GET", url, stream=True)

        # Derive filename from URL or Content-Disposition
        filename = Path(urlparse(resp.url).path).name or "attachment"
        cd = resp.headers.get("Content-Disposition", "")
        cd_match = re.search(r'filename="?([^";\s]+)"?', cd)
        if cd_match:
            filename = cd_match.group(1)

        dest_path = dest / filename
        with open(dest_path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)

        return dest_path

    def pull_challenges(self) -> list[CTFdChallenge]:
        """Fetch all challenges from the CTFd instance.

        Returns:
            List of CTFdChallenge objects with metadata and file URLs.
        """
        log.info("ctfd_pull_start", url=self.base_url)

        data = self._get("/api/v1/challenges")
        if not data.get("success"):
            raise RuntimeError(f"CTFd API error: {data}")

        challenges = []
        for item in data["data"]:
            cid = item["id"]

            # Fetch full details (includes description + files)
            detail = self._get(f"/api/v1/challenges/{cid}")
            if not detail.get("success"):
                log.warning("ctfd_challenge_fetch_failed", id=cid, name=item.get("name"))
                continue

            d = detail["data"]
            challenges.append(
                CTFdChallenge(
                    id=cid,
                    name=d.get("name", f"challenge_{cid}"),
                    category=d.get("category", "misc"),
                    description=self._clean_html(d.get("description", "")),
                    value=d.get("value", 0),
                    files=d.get("files", []),
                    tags=[t.get("value", "") for t in d.get("tags", [])],
                    solves=d.get("solves", 0),
                    solved_by_me=d.get("solved_by_me", False),
                    # CRITICAL: connection_info is where the CTFd admin puts the
                    # `nc host port` / `https://...` / "in-person" marker. Pass 1
                    # of every Kraken run MUST check this field before dispatching
                    # solve agents -- it determines whether a challenge is remote,
                    # physical, or needs a service banner probe. Missing this cost
                    # the BYU EOS CTF ~10 flags in the first pass.
                    connection_info=(d.get("connection_info") or "").strip(),
                )
            )

        log.info("ctfd_pull_complete", num_challenges=len(challenges))
        return challenges

    def setup_workspace(
        self,
        challenges: list[CTFdChallenge],
        base_dir: str = "ctfs",
    ) -> Path:
        """Create local directory structure and download all files.

        Directory layout:
            ctfs/{ctf_name}/
                {category}/
                    {challenge_name}/
                        description.txt
                        challenge.json
                        <downloaded files>

        Args:
            challenges: List of challenges from pull_challenges()
            base_dir: Parent directory for CTF workspaces

        Returns:
            Path to the CTF workspace root (ctfs/{ctf_name}/)
        """
        workspace = Path(base_dir) / self.ctf_name
        log.info("ctfd_workspace_setup", path=str(workspace), num_challenges=len(challenges))

        for chal in challenges:
            # Sanitize names for filesystem
            safe_cat = re.sub(r"[^A-Za-z0-9._-]+", "_", chal.category).strip("._") or "misc"
            safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", chal.name).strip("._") or f"chal_{chal.id}"
            chal_dir = workspace / safe_cat / safe_name
            chal_dir.mkdir(parents=True, exist_ok=True)
            chal.local_dir = str(chal_dir)

            # Write description
            (chal_dir / "description.txt").write_text(
                f"{chal.description}\n",
                encoding="utf-8",
            )

            # Write challenge metadata. `connection_info` is included so the
            # triage step can route challenges without re-querying the CTFd API.
            import json

            (chal_dir / "challenge.json").write_text(
                json.dumps(
                    {
                        "name": chal.name,
                        "category": chal.category,
                        "description": chal.description,
                        "value": chal.value,
                        "ctfd_id": chal.id,
                        "tags": chal.tags,
                        "solves": chal.solves,
                        "connection_info": chal.connection_info,
                        "is_physical": chal.is_physical,
                        "is_remote_network": chal.is_remote_network,
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )

            # Download file attachments
            for file_url in chal.files:
                try:
                    dl_path = self._download_file(file_url, chal_dir)
                    log.info("ctfd_file_downloaded", challenge=chal.name, file=dl_path.name)
                except Exception as e:
                    log.warning("ctfd_file_download_failed", challenge=chal.name, url=file_url, error=str(e))

        log.info("ctfd_workspace_ready", path=str(workspace))
        return workspace

    def submit_flag(
        self,
        challenge_id: int,
        flag: str,
        flag_format: str = "",
    ) -> SubmitResult:
        """Submit a flag to CTFd with confidence checks.

        Only submits if the flag passes all confidence gates:
          1. Not a known false positive
          2. Matches the expected flag format (if provided)
          3. Minimum length check

        Args:
            challenge_id: CTFd challenge ID
            flag: The flag string to submit
            flag_format: Regex pattern the flag should match

        Returns:
            SubmitResult with status and message
        """
        # ── Confidence gates ─────────────────────────────────────────
        if not flag or len(flag) < 4:
            return SubmitResult(challenge_id, flag, "skipped", "Flag too short")

        if flag.lower() in _FALSE_POSITIVE_FLAGS or flag in _FALSE_POSITIVE_FLAGS:
            return SubmitResult(challenge_id, flag, "skipped", "Known false positive")

        if flag_format:
            try:
                if not re.search(flag_format, flag):
                    return SubmitResult(challenge_id, flag, "skipped", f"Does not match format: {flag_format}")
            except re.error:
                pass

        # Generic sanity: must contain { and }
        if "{" not in flag or "}" not in flag:
            return SubmitResult(challenge_id, flag, "skipped", "Missing braces -- likely not a real flag")

        # ── Submit ───────────────────────────────────────────────────
        log.info("ctfd_submit_flag", challenge_id=challenge_id, flag=flag[:30] + "...")

        try:
            resp = self._post(
                "/api/v1/challenges/attempt",
                {
                    "challenge_id": challenge_id,
                    "submission": flag,
                },
            )
        except requests.HTTPError as e:
            if e.response is not None and e.response.status_code == 429:
                return SubmitResult(challenge_id, flag, "ratelimited", "Rate limited -- try again later")
            raise

        if not resp.get("success"):
            return SubmitResult(challenge_id, flag, "error", str(resp))

        status = resp["data"].get("status", "unknown")
        message = resp["data"].get("message", "")

        log.info("ctfd_submit_result", challenge_id=challenge_id, status=status, message=message)
        return SubmitResult(challenge_id, flag, status, message)
