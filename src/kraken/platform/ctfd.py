"""CTFd platform client for live CTF competition integration.

Supports:
- Challenge listing and metadata retrieval
- Flag submission with rate limiting
- Scoreboard monitoring
- Challenge file download
- Team/user score tracking

Usage:
    client = CTFdClient("https://ctf.example.com", token="your_api_token")
    challenges = client.list_challenges()
    result = client.submit_flag(challenge_id=1, flag="flag{example}")
    scoreboard = client.get_scoreboard()
"""
import json
import os
import re
import time
import requests
from pathlib import Path
from typing import Optional


class CTFdClient:
    """Client for CTFd API v1/v2."""

    def __init__(self, url: str, token: str = "", session_cookie: str = "",
                 rate_limit: float = 1.0):
        """Initialize CTFd client.

        Args:
            url: Base URL of CTFd instance (e.g., https://ctf.example.com)
            token: API token (from Settings > Access Tokens in CTFd)
            session_cookie: Alternative: use session cookie for auth
            rate_limit: Minimum seconds between flag submissions
        """
        self.base_url = url.rstrip("/")
        self.session = requests.Session()
        self.rate_limit = rate_limit
        self._last_submit = 0

        if token:
            self.session.headers["Authorization"] = f"Token {token}"
            self.session.headers["Content-Type"] = "application/json"
        elif session_cookie:
            self.session.cookies.set("session", session_cookie)

        # Auto-detect API version
        self._api_prefix = "/api/v1"

    def _get(self, endpoint: str, **kwargs) -> dict:
        """Make authenticated GET request."""
        url = f"{self.base_url}{self._api_prefix}{endpoint}"
        resp = self.session.get(url, timeout=15, **kwargs)
        resp.raise_for_status()
        return resp.json()

    def _post(self, endpoint: str, data: dict, **kwargs) -> dict:
        """Make authenticated POST request."""
        url = f"{self.base_url}{self._api_prefix}{endpoint}"
        resp = self.session.post(url, json=data, timeout=15, **kwargs)
        resp.raise_for_status()
        return resp.json()

    # === Challenge Operations ===

    def list_challenges(self) -> list[dict]:
        """List all visible challenges.

        Returns list of:
            {"id": 1, "name": "Challenge Name", "category": "web",
             "value": 500, "solves": 12, "solved_by_me": False}
        """
        result = self._get("/challenges")
        challenges = result.get("data", [])
        return [{
            "id": c["id"],
            "name": c["name"],
            "category": c.get("category", "misc"),
            "value": c.get("value", 0),
            "solves": c.get("solves", 0),
            "solved_by_me": c.get("solved_by_me", False),
            "description": c.get("description", ""),
            "max_attempts": c.get("max_attempts", 0),
            "tags": [t.get("value", "") for t in c.get("tags", [])],
        } for c in challenges]

    def get_challenge(self, challenge_id: int) -> dict:
        """Get detailed challenge info including files and hints."""
        result = self._get(f"/challenges/{challenge_id}")
        return result.get("data", {})

    def download_challenge_files(self, challenge_id: int, output_dir: str) -> list[str]:
        """Download all files for a challenge.

        Returns list of downloaded file paths.
        """
        challenge = self.get_challenge(challenge_id)
        files = challenge.get("files", [])
        downloaded = []

        os.makedirs(output_dir, exist_ok=True)

        for file_url in files:
            if not file_url.startswith("http"):
                file_url = f"{self.base_url}{file_url}"

            filename = file_url.split("/")[-1].split("?")[0]
            filepath = os.path.join(output_dir, filename)

            resp = self.session.get(file_url, timeout=60)
            with open(filepath, "wb") as f:
                f.write(resp.content)
            downloaded.append(filepath)

        return downloaded

    # === Flag Submission ===

    def submit_flag(self, challenge_id: int, flag: str) -> dict:
        """Submit a flag for a challenge.

        Returns:
            {"status": "correct|incorrect|already_solved", "message": "..."}
        """
        # Rate limiting
        elapsed = time.time() - self._last_submit
        if elapsed < self.rate_limit:
            time.sleep(self.rate_limit - elapsed)

        self._last_submit = time.time()

        result = self._post("/challenges/attempt", {
            "challenge_id": challenge_id,
            "submission": flag,
        })

        data = result.get("data", {})
        status = data.get("status", "incorrect")
        message = data.get("message", "")

        return {"status": status, "message": message}

    # === Scoreboard ===

    def get_scoreboard(self, count: int = 20) -> list[dict]:
        """Get current scoreboard.

        Returns list of:
            {"pos": 1, "name": "Team Name", "score": 1500}
        """
        result = self._get(f"/scoreboard/top/{count}")
        teams = result.get("data", {})
        scoreboard = []
        for pos, team_data in sorted(teams.items(), key=lambda x: int(x[0])):
            scoreboard.append({
                "pos": int(pos),
                "name": team_data.get("name", ""),
                "score": team_data.get("score", 0),
            })
        return scoreboard

    def get_my_score(self) -> dict:
        """Get our team's current score and rank."""
        # Try team endpoint first
        try:
            result = self._get("/teams/me")
            data = result.get("data", {})
            return {
                "name": data.get("name", ""),
                "score": data.get("score", 0),
                "place": data.get("place", ""),
            }
        except Exception:
            pass
        # Fall back to user endpoint
        try:
            result = self._get("/users/me")
            data = result.get("data", {})
            return {
                "name": data.get("name", ""),
                "score": data.get("score", 0),
                "place": data.get("place", ""),
            }
        except Exception:
            return {"name": "unknown", "score": 0, "place": "?"}

    # === Competition Strategy ===

    def get_unsolved_by_value(self) -> list[dict]:
        """Get unsolved challenges sorted by points (highest first).

        Useful for prioritizing which challenges to attempt.
        """
        challenges = self.list_challenges()
        unsolved = [c for c in challenges if not c["solved_by_me"]]
        return sorted(unsolved, key=lambda c: c["value"], reverse=True)

    def get_unsolved_by_solves(self) -> list[dict]:
        """Get unsolved challenges sorted by solve count (most solved first).

        Challenges solved by many teams are likely easier.
        """
        challenges = self.list_challenges()
        unsolved = [c for c in challenges if not c["solved_by_me"]]
        return sorted(unsolved, key=lambda c: c["solves"], reverse=True)

    def get_low_hanging_fruit(self) -> list[dict]:
        """Get challenges with highest solves-to-points ratio (easiest first)."""
        challenges = self.list_challenges()
        unsolved = [c for c in challenges if not c["solved_by_me"]]
        for c in unsolved:
            c["difficulty_score"] = c["solves"] / max(c["value"], 1)
        return sorted(unsolved, key=lambda c: c["difficulty_score"], reverse=True)


class RCTFClient:
    """Client for rCTF platform API."""

    def __init__(self, url: str, token: str = ""):
        self.base_url = url.rstrip("/")
        self.session = requests.Session()
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"

    def list_challenges(self) -> list[dict]:
        resp = self.session.get(f"{self.base_url}/api/v1/challs", timeout=15)
        data = resp.json().get("data", [])
        return [{"id": c["id"], "name": c["name"], "category": c.get("category", ""),
                 "points": c.get("points", 0), "solves": c.get("solves", 0)} for c in data]

    def submit_flag(self, challenge_id: str, flag: str) -> dict:
        resp = self.session.post(f"{self.base_url}/api/v1/challs/{challenge_id}/submit",
                                json={"flag": flag}, timeout=15)
        return resp.json()


# === CLI Interface ===

def main():
    """CLI for CTF platform operations."""
    import argparse
    parser = argparse.ArgumentParser(description="Kraken CTF Platform Client")
    parser.add_argument("--url", required=True, help="CTFd instance URL")
    parser.add_argument("--token", default="", help="API token")
    parser.add_argument("--cookie", default="", help="Session cookie")

    sub = parser.add_subparsers(dest="command")

    sub.add_parser("challenges", help="List challenges")
    sub.add_parser("scoreboard", help="Show scoreboard")
    sub.add_parser("unsolved", help="Show unsolved challenges")
    sub.add_parser("easy", help="Show easiest unsolved challenges")

    submit_p = sub.add_parser("submit", help="Submit a flag")
    submit_p.add_argument("challenge_id", type=int)
    submit_p.add_argument("flag")

    dl_p = sub.add_parser("download", help="Download challenge files")
    dl_p.add_argument("challenge_id", type=int)
    dl_p.add_argument("--output", default="./challenge_files")

    args = parser.parse_args()

    client = CTFdClient(args.url, token=args.token, session_cookie=args.cookie)

    if args.command == "challenges":
        for c in client.list_challenges():
            solved = "V" if c["solved_by_me"] else " "
            print(f"[{solved}] {c['id']:3d} | {c['category']:10s} | {c['value']:4d}pts | {c['solves']:3d} solves | {c['name']}")

    elif args.command == "scoreboard":
        for team in client.get_scoreboard():
            print(f"#{team['pos']:2d} | {team['score']:5d}pts | {team['name']}")

    elif args.command == "unsolved":
        for c in client.get_unsolved_by_value():
            print(f"{c['id']:3d} | {c['category']:10s} | {c['value']:4d}pts | {c['solves']:3d} solves | {c['name']}")

    elif args.command == "easy":
        for c in client.get_low_hanging_fruit()[:10]:
            print(f"{c['id']:3d} | {c['category']:10s} | {c['value']:4d}pts | {c['solves']:3d} solves | {c['name']}")

    elif args.command == "submit":
        result = client.submit_flag(args.challenge_id, args.flag)
        print(f"{result['status']}: {result['message']}")

    elif args.command == "download":
        files = client.download_challenge_files(args.challenge_id, args.output)
        for f in files:
            print(f"Downloaded: {f}")


if __name__ == "__main__":
    main()
