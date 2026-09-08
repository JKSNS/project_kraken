"""Background job management for async solve operations with progress streaming."""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class JobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class SolveEvent:
    """A single progress event from a running solve."""
    node: str
    status: str  # "started", "completed", "error", "skipped"
    timestamp: float = field(default_factory=time.time)
    data: dict = field(default_factory=dict)
    duration_s: float = 0.0


@dataclass
class Job:
    """Tracks a background solve operation."""
    id: str
    challenge_path: str
    status: JobStatus = JobStatus.PENDING
    created_at: float = field(default_factory=time.time)
    started_at: float | None = None
    completed_at: float | None = None
    events: list[SolveEvent] = field(default_factory=list)
    result: dict = field(default_factory=dict)
    error: str = ""
    active_node: str = ""
    flag: str = ""
    challenge_type: str = ""
    tools_run: int = 0
    batch_id: str = ""

    @property
    def elapsed_s(self) -> float:
        if self.started_at is None:
            return 0.0
        end = self.completed_at or time.time()
        return end - self.started_at

    def to_dict(self, include_events: bool = True) -> dict:
        d: dict[str, Any] = {
            "id": self.id,
            "challenge_path": self.challenge_path,
            "status": self.status.value,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "elapsed_s": round(self.elapsed_s, 2),
            "active_node": self.active_node,
            "flag": self.flag,
            "challenge_type": self.challenge_type,
            "tools_run": self.tools_run,
            "error": self.error,
            "batch_id": self.batch_id,
        }
        if include_events:
            d["events"] = [
                {
                    "node": e.node,
                    "status": e.status,
                    "timestamp": e.timestamp,
                    "duration_s": round(e.duration_s, 2),
                    "data": e.data,
                }
                for e in self.events
            ]
        return d


class JobStore:
    """In-memory job store with WebSocket subscriber management and disk persistence."""

    _HISTORY_FILE = Path.home() / ".kraken" / "gui_history.json"

    def __init__(self, max_jobs: int = 200):
        self._jobs: dict[str, Job] = {}
        self._max_jobs = max_jobs
        self._subscribers: dict[str, list[asyncio.Queue]] = {}
        self._lock = asyncio.Lock()
        self._batches: dict[str, list[str]] = {}  # batch_id -> [job_ids]
        self._history_path = self._HISTORY_FILE
        self._load_from_disk()

    def create(self, challenge_path: str, batch_id: str = "") -> Job:
        job_id = uuid.uuid4().hex[:8]
        job = Job(id=job_id, challenge_path=challenge_path, batch_id=batch_id)
        self._jobs[job_id] = job
        if batch_id:
            self._batches.setdefault(batch_id, []).append(job_id)
        self._trim()
        return job

    def get(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)

    def list_all(self, limit: int = 50) -> list[dict]:
        jobs = sorted(self._jobs.values(), key=lambda j: j.created_at, reverse=True)
        return [j.to_dict(include_events=False) for j in jobs[:limit]]

    def list_batch(self, batch_id: str) -> list[dict]:
        """List all jobs belonging to a batch."""
        job_ids = self._batches.get(batch_id, [])
        return [self._jobs[jid].to_dict(include_events=False) for jid in job_ids if jid in self._jobs]

    async def publish(self, job_id: str, event: SolveEvent):
        """Publish a progress event to all subscribers of a job."""
        job = self._jobs.get(job_id)
        if job:
            job.events.append(event)
            job.active_node = event.node if event.status == "started" else ""
            if event.node == "__done__":
                self._save_to_disk()
        queues = self._subscribers.get(job_id, [])
        payload = {
            "node": event.node,
            "status": event.status,
            "timestamp": event.timestamp,
            "duration_s": round(event.duration_s, 2),
            "data": event.data,
        }
        for q in queues:
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                pass

    async def subscribe(self, job_id: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=256)
        async with self._lock:
            self._subscribers.setdefault(job_id, []).append(q)
        return q

    async def unsubscribe(self, job_id: str, q: asyncio.Queue):
        async with self._lock:
            subs = self._subscribers.get(job_id, [])
            if q in subs:
                subs.remove(q)

    def _load_from_disk(self):
        """Load completed jobs from persistent storage on startup."""
        if not self._history_path.exists():
            return
        try:
            data = json.loads(self._history_path.read_text())
            for entry in data:
                jid = entry.get("id")
                if not jid or jid in self._jobs:
                    continue
                job = Job(
                    id=jid,
                    challenge_path=entry.get("challenge_path", ""),
                    status=JobStatus(entry.get("status", "failed")),
                    created_at=entry.get("created_at", 0),
                    started_at=entry.get("started_at"),
                    completed_at=entry.get("completed_at"),
                    flag=entry.get("flag", ""),
                    challenge_type=entry.get("challenge_type", ""),
                    tools_run=entry.get("tools_run", 0),
                    error=entry.get("error", ""),
                    batch_id=entry.get("batch_id", ""),
                )
                # Restore events (truncated on save)
                for ev in entry.get("events", []):
                    job.events.append(SolveEvent(
                        node=ev.get("node", ""),
                        status=ev.get("status", ""),
                        timestamp=ev.get("timestamp", 0),
                        data=ev.get("data", {}),
                        duration_s=ev.get("duration_s", 0),
                    ))
                self._jobs[jid] = job
        except (json.JSONDecodeError, OSError, KeyError, ValueError):
            pass

    def _save_to_disk(self):
        """Persist completed/failed jobs to disk with truncated events."""
        try:
            self._history_path.parent.mkdir(parents=True, exist_ok=True)
            completed = []
            for j in self._jobs.values():
                if j.status not in (JobStatus.COMPLETED, JobStatus.FAILED):
                    continue
                d = j.to_dict(include_events=True)
                # Truncate events to last 50 per job to control file size
                if len(d.get("events", [])) > 50:
                    d["events"] = d["events"][-50:]
                # Truncate large data payloads in events
                for ev in d.get("events", []):
                    for key in list(ev.get("data", {}).keys()):
                        val = ev["data"][key]
                        if isinstance(val, str) and len(val) > 500:
                            ev["data"][key] = val[:500] + "..."
                completed.append(d)
            completed.sort(key=lambda x: x.get("created_at", 0), reverse=True)
            self._history_path.write_text(json.dumps(completed[:500]))
        except OSError:
            pass

    def _trim(self):
        if len(self._jobs) <= self._max_jobs:
            return
        sorted_jobs = sorted(self._jobs.values(), key=lambda j: j.created_at)
        while len(self._jobs) > self._max_jobs:
            old = sorted_jobs.pop(0)
            if old.status in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED):
                del self._jobs[old.id]
                self._subscribers.pop(old.id, None)


store = JobStore()
