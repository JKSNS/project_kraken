"""Session persistence -- save/restore KrakenState across process restarts.

Sessions are stored as JSON files under ``{workspace}/.kraken/sessions/``.
Each file captures a snapshot of the KrakenState at a checkpoint, plus
metadata (timestamps, status, challenge info).
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kraken.logging.structured import get_logger

log = get_logger(__name__)


@dataclass
class Session:
    """Persistent session record."""

    session_id: str = ""
    challenge_id: str = ""
    status: str = "running"  # running | paused | completed | failed
    state_snapshot: dict[str, Any] = field(default_factory=dict)
    created_at: float = 0.0
    updated_at: float = 0.0
    checkpoints: int = 0

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "challenge_id": self.challenge_id,
            "status": self.status,
            "state_snapshot": self.state_snapshot,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "checkpoints": self.checkpoints,
        }

    @classmethod
    def from_dict(cls, data: dict) -> Session:
        return cls(
            session_id=data.get("session_id", ""),
            challenge_id=data.get("challenge_id", ""),
            status=data.get("status", "running"),
            state_snapshot=data.get("state_snapshot", {}),
            created_at=data.get("created_at", 0.0),
            updated_at=data.get("updated_at", 0.0),
            checkpoints=data.get("checkpoints", 0),
        )


def _sanitize_state_for_json(state: dict) -> dict:
    """Make KrakenState JSON-serializable by converting non-serializable values."""
    clean: dict[str, Any] = {}
    for key, value in state.items():
        try:
            json.dumps(value)
            clean[key] = value
        except (TypeError, ValueError):
            clean[key] = str(value)
    return clean


class SessionManager:
    """Manage session persistence on the filesystem."""

    def __init__(self, workspace: str | Path = "."):
        self.workspace = Path(workspace)
        self.sessions_dir = self.workspace / ".kraken" / "sessions"

    def _ensure_dir(self) -> None:
        self.sessions_dir.mkdir(parents=True, exist_ok=True)

    def _session_path(self, session_id: str) -> Path:
        return self.sessions_dir / f"{session_id}.json"

    def create_session(self, challenge_id: str, initial_state: dict) -> Session:
        """Create a new session and persist it."""
        self._ensure_dir()
        session = Session(
            session_id=str(uuid.uuid4())[:8],
            challenge_id=challenge_id,
            status="running",
            state_snapshot=_sanitize_state_for_json(initial_state),
            created_at=time.time(),
            updated_at=time.time(),
            checkpoints=0,
        )
        self._write(session)
        log.info("session_created", session_id=session.session_id, challenge=challenge_id)
        return session

    def save_checkpoint(self, session_id: str, state: dict, status: str = "running") -> None:
        """Save a checkpoint of the current state."""
        path = self._session_path(session_id)
        if not path.exists():
            log.warning("session_checkpoint_missing", session_id=session_id)
            return

        session = self._read(session_id)
        if session is None:
            return

        session.state_snapshot = _sanitize_state_for_json(state)
        session.status = status
        session.updated_at = time.time()
        session.checkpoints += 1
        self._write(session)

    def load_session(self, session_id: str) -> Session | None:
        """Load a session by ID."""
        return self._read(session_id)

    def list_sessions(self) -> list[dict]:
        """List all sessions with summary info."""
        self._ensure_dir()
        sessions = []
        for p in sorted(self.sessions_dir.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
            try:
                data = json.loads(p.read_text())
                sessions.append({
                    "session_id": data.get("session_id", p.stem),
                    "challenge_id": data.get("challenge_id", "?"),
                    "status": data.get("status", "?"),
                    "checkpoints": data.get("checkpoints", 0),
                    "updated_at": data.get("updated_at", 0),
                })
            except Exception:
                continue
        return sessions

    def resume_session(self, session_id: str) -> dict | None:
        """Load session state for resumption. Returns the state snapshot or None."""
        session = self._read(session_id)
        if session is None:
            log.warning("session_resume_not_found", session_id=session_id)
            return None

        if session.status == "completed":
            log.warning("session_resume_completed", session_id=session_id)
            return None

        session.status = "running"
        session.updated_at = time.time()
        self._write(session)
        log.info("session_resumed", session_id=session_id, challenge=session.challenge_id)
        return session.state_snapshot

    def complete_session(self, session_id: str, final_state: dict) -> None:
        """Mark session as completed with final state."""
        session = self._read(session_id)
        if session is None:
            return
        session.state_snapshot = _sanitize_state_for_json(final_state)
        session.status = "completed" if final_state.get("flag") else "failed"
        session.updated_at = time.time()
        self._write(session)
        log.info("session_completed", session_id=session_id, status=session.status)

    def _write(self, session: Session) -> None:
        self._ensure_dir()
        path = self._session_path(session.session_id)
        path.write_text(json.dumps(session.to_dict(), indent=2, default=str))

    def _read(self, session_id: str) -> Session | None:
        path = self._session_path(session_id)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text())
            return Session.from_dict(data)
        except Exception as exc:
            log.warning("session_read_error", session_id=session_id, error=str(exc)[:200])
            return None
