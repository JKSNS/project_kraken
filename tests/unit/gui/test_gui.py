"""Unit tests for the Kraken GUI backend."""

import time

import pytest

# Test job store in isolation (no FastAPI dependency)
from kraken.gui.jobs import Job, JobStatus, JobStore, SolveEvent


class TestJob:
    def test_create_job(self):
        job = Job(id="abc123", challenge_path="/tmp/test")
        assert job.id == "abc123"
        assert job.status == JobStatus.PENDING
        assert job.elapsed_s == 0.0
        assert job.flag == ""

    def test_elapsed_running(self):
        job = Job(id="t1", challenge_path="/tmp/test")
        job.started_at = time.time() - 5.0
        assert 4.5 < job.elapsed_s < 6.0

    def test_elapsed_completed(self):
        job = Job(id="t2", challenge_path="/tmp/test")
        job.started_at = 1000.0
        job.completed_at = 1010.0
        assert job.elapsed_s == 10.0

    def test_to_dict(self):
        job = Job(id="t3", challenge_path="/tmp/test", flag="flag{abc}", challenge_type="crypto")
        d = job.to_dict()
        assert d["id"] == "t3"
        assert d["flag"] == "flag{abc}"
        assert d["challenge_type"] == "crypto"
        assert "events" in d

    def test_to_dict_without_events(self):
        job = Job(id="t4", challenge_path="/tmp/test")
        job.events.append(SolveEvent(node="triage", status="completed"))
        d = job.to_dict(include_events=False)
        assert "events" not in d

    def test_batch_id(self):
        job = Job(id="t5", challenge_path="/tmp/test", batch_id="batch1")
        assert job.batch_id == "batch1"
        d = job.to_dict()
        assert d["batch_id"] == "batch1"


class TestSolveEvent:
    def test_create_event(self):
        evt = SolveEvent(node="triage", status="completed", duration_s=1.5)
        assert evt.node == "triage"
        assert evt.status == "completed"
        assert evt.duration_s == 1.5
        assert evt.timestamp > 0


class TestJobStore:
    def test_create_and_get(self):
        store = JobStore.__new__(JobStore)
        store._jobs = {}
        store._max_jobs = 100
        store._subscribers = {}
        store._batches = {}
        store._lock = None
        store._history_path = None

        job = store.create("/tmp/test")
        assert len(job.id) == 8
        assert store.get(job.id) is job

    def test_list_all(self):
        store = JobStore.__new__(JobStore)
        store._jobs = {}
        store._max_jobs = 100
        store._subscribers = {}
        store._batches = {}
        store._lock = None
        store._history_path = None

        store.create("/tmp/a")
        store.create("/tmp/b")
        store.create("/tmp/c")

        result = store.list_all(2)
        assert len(result) == 2

    def test_batch_tracking(self):
        store = JobStore.__new__(JobStore)
        store._jobs = {}
        store._max_jobs = 100
        store._subscribers = {}
        store._batches = {}
        store._lock = None
        store._history_path = None

        j1 = store.create("/tmp/a", batch_id="b1")
        j2 = store.create("/tmp/b", batch_id="b1")
        j3 = store.create("/tmp/c", batch_id="b2")

        batch1 = store.list_batch("b1")
        assert len(batch1) == 2
        assert {j["id"] for j in batch1} == {j1.id, j2.id}

        batch2 = store.list_batch("b2")
        assert len(batch2) == 1
        assert batch2[0]["id"] == j3.id

    def test_get_nonexistent(self):
        store = JobStore.__new__(JobStore)
        store._jobs = {}
        assert store.get("nonexistent") is None

    def test_trim(self):
        store = JobStore.__new__(JobStore)
        store._jobs = {}
        store._max_jobs = 3
        store._subscribers = {}
        store._batches = {}
        store._lock = None
        store._history_path = None

        j1 = store.create("/tmp/a")
        j1.status = JobStatus.COMPLETED
        store.create("/tmp/b")
        store.create("/tmp/c")
        store.create("/tmp/d")  # triggers trim

        # Oldest completed job should be removed
        assert len(store._jobs) <= 3

    def test_save_and_load(self, tmp_path):
        history_file = tmp_path / "history.json"

        # Create store and add completed jobs
        store1 = JobStore.__new__(JobStore)
        store1._jobs = {}
        store1._max_jobs = 100
        store1._subscribers = {}
        store1._batches = {}
        store1._lock = None
        store1._history_path = history_file

        job = store1.create("/tmp/test")
        job.status = JobStatus.COMPLETED
        job.flag = "flag{test}"
        job.challenge_type = "crypto"
        job.started_at = 1000.0
        job.completed_at = 1010.0
        job.events.append(SolveEvent(node="triage", status="completed", duration_s=2.0))
        store1._save_to_disk()

        assert history_file.exists()

        # Create new store and verify it loads
        store2 = JobStore.__new__(JobStore)
        store2._jobs = {}
        store2._max_jobs = 100
        store2._subscribers = {}
        store2._batches = {}
        store2._lock = None
        store2._history_path = history_file
        store2._load_from_disk()

        loaded = store2.get(job.id)
        assert loaded is not None
        assert loaded.flag == "flag{test}"
        assert loaded.challenge_type == "crypto"
        assert len(loaded.events) == 1
        assert loaded.events[0].node == "triage"


# FastAPI endpoint tests (require httpx)
try:
    from httpx import ASGITransport, AsyncClient

    @pytest.fixture
    def client():
        from kraken.gui.app import app

        transport = ASGITransport(app=app)
        return AsyncClient(transport=transport, base_url="http://test")

    class TestAPIEndpoints:
        async def test_health(self, client):
            resp = await client.get("/api/health")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "ok"
            assert "uptime_s" in data

        async def test_pipeline(self, client):
            resp = await client.get("/api/pipeline")
            assert resp.status_code == 200
            nodes = resp.json()["nodes"]
            assert len(nodes) > 0
            assert any(n["id"] == "triage" for n in nodes)

        async def test_tools(self, client):
            resp = await client.get("/api/tools")
            assert resp.status_code == 200
            tools = resp.json()["tools"]
            assert len(tools) > 0
            assert "auto_angr" in tools

        async def test_solves_list(self, client):
            resp = await client.get("/api/solves")
            assert resp.status_code == 200
            assert "solves" in resp.json()

        async def test_jobs_alias(self, client):
            resp = await client.get("/api/jobs")
            assert resp.status_code == 200
            assert "solves" in resp.json()

        async def test_stats(self, client):
            resp = await client.get("/api/stats")
            assert resp.status_code == 200

        async def test_cascade_config(self, client):
            resp = await client.get("/api/stats/cascade")
            assert resp.status_code == 200

        async def test_solve_not_found(self, client):
            resp = await client.get("/api/solve/nonexistent")
            assert resp.status_code == 404

        async def test_solve_bad_path(self, client):
            resp = await client.post("/api/solve", json={"challenge_path": "/nonexistent/path/xyz123"})
            assert resp.status_code == 400

        async def test_validate_flag_valid(self, client):
            resp = await client.post(
                "/api/validate",
                json={
                    "flag": "flag{hello_world}",
                    "flag_format": r"flag\{[a-zA-Z0-9_]+\}",
                },
            )
            assert resp.status_code == 200
            assert resp.json()["valid"] is True

        async def test_validate_flag_invalid(self, client):
            resp = await client.post(
                "/api/validate",
                json={
                    "flag": "not_a_flag",
                    "flag_format": r"flag\{[a-zA-Z0-9_]+\}",
                },
            )
            assert resp.status_code == 200
            assert resp.json()["valid"] is False

        async def test_index_page(self, client):
            resp = await client.get("/")
            assert resp.status_code == 200
            assert "kraken" in resp.text.lower()

        async def test_batch_status(self, client):
            resp = await client.get("/api/batch-status")
            assert resp.status_code == 200
            data = resp.json()
            assert "total" in data
            assert "completed" in data

        async def test_batch_not_found(self, client):
            resp = await client.get("/api/batch/nonexistent123")
            assert resp.status_code == 404

        async def test_cancel_not_found(self, client):
            resp = await client.delete("/api/solve/nonexistent")
            assert resp.status_code == 404

except ImportError:
    pass
