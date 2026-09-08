"""Kraken GUI -- FastAPI web interface for the KRAKEN CTF solver.

Serves a modern single-page application with:
  - REST API for solve operations, triage, decompile, tool cascade
  - WebSocket for real-time solve progress streaming
  - Static file serving for the frontend SPA

Launch:
    python -m kraken.gui            # Default: localhost:7777
    kraken-gui                      # Via entry point
    kraken-gui --host 0.0.0.0 -p 8080  # Custom bind
"""

from __future__ import annotations

import asyncio
import json
import os
import time
import traceback
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from kraken.gui.jobs import store, Job, JobStatus, SolveEvent

# ── App Setup ────────────────────────────────────────────────────────────────

_STATIC_DIR = Path(__file__).parent / "static"
_START_TIME = time.time()

app = FastAPI(
    title="Kraken",
    description="KRAKEN CTF Solver GUI",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Request / Response Models ────────────────────────────────────────────────


class SolveRequest(BaseModel):
    challenge_path: str
    flag_format: str = r"flag\{[a-zA-Z0-9_]+\}"
    challenge_description: str = ""
    backend: str = ""
    model: str = ""
    timeout_minutes: int = 30


class TriageRequest(BaseModel):
    challenge_path: str
    flag_format: str = r"flag\{[a-zA-Z0-9_]+\}"
    challenge_description: str = ""


class DecompileRequest(BaseModel):
    challenge_path: str
    flag_format: str = r"flag\{[a-zA-Z0-9_]+\}"


class ToolRunRequest(BaseModel):
    tool_name: str
    challenge_path: str
    flag_format: str = r"flag\{[a-zA-Z0-9_]+\}"
    extra_args: dict | None = None
    timeout: int = 60


class CascadeRequest(BaseModel):
    challenge_path: str
    challenge_type: str = ""
    flag_format: str = r"flag\{[a-zA-Z0-9_]+\}"
    extracted_params: dict | None = None


class ValidateRequest(BaseModel):
    flag: str
    flag_format: str = r"flag\{[a-zA-Z0-9_]+\}"
    challenge_path: str = ""


class BatchSolveRequest(BaseModel):
    directory: str
    flag_format: str = r"flag\{[a-zA-Z0-9_]+\}"
    timeout_minutes: int = 10
    challenge_description: str = ""
    concurrency: int = 3


# ── Pipeline graph node definitions ─────────────────────────────────────────

PIPELINE_NODES = [
    {"id": "triage", "label": "Triage", "group": "analysis"},
    {"id": "unpack", "label": "Unpack", "group": "analysis"},
    {"id": "decompile", "label": "Decompile", "group": "analysis"},
    {"id": "normalize", "label": "Normalize", "group": "analysis"},
    {"id": "classify", "label": "Classify", "group": "analysis"},
    {"id": "specialist", "label": "Specialist", "group": "specialist"},
    {"id": "param_extraction", "label": "Extract Params", "group": "solve"},
    {"id": "tool_router", "label": "Tool Cascade", "group": "solve"},
    {"id": "flag_validator", "label": "Validate Flag", "group": "solve"},
    {"id": "solve_engine", "label": "Solve Engine", "group": "llm"},
    {"id": "manager", "label": "Manager", "group": "llm"},
]

def _load_available_tools() -> list[str]:
    """Load the tool list from the registry (tool_meta.json) dynamically.

    Falls back to scanning helpers/ for auto_*.py if registry is empty.
    Universal tools are listed first (in their configured order), followed
    by non-universal tools sorted alphabetically.
    """
    try:
        from kraken.helpers.registry import (
            get_registry, get_universal_tools,
        )
        registry = get_registry()
        if registry:
            universal = get_universal_tools()
            non_universal = sorted(
                name for name in registry if name not in universal
            )
            return universal + non_universal
    except Exception:
        pass

    # Fallback: scan helpers directory for auto_*.py files
    helpers_dir = Path(__file__).resolve().parent.parent / "helpers"
    if helpers_dir.exists():
        return sorted(
            p.stem for p in helpers_dir.glob("auto_*.py")
            if p.stem != "__init__"
        )
    return []


AVAILABLE_TOOLS = _load_available_tools()


# ── Helper: run solve in background ─────────────────────────────────────────


async def _run_solve_job(job: Job, req: SolveRequest):
    """Execute a full solve as a background task, publishing progress events."""
    job.status = JobStatus.RUNNING
    job.started_at = time.time()

    try:
        from kraken.state import initial_state
        from kraken.graph import build_graph
        from kraken.config import KrakenConfig
        from kraken.orchestrator import _resolve_solve_workspace, _merge_state_update

        # Build config with optional overrides
        env_overrides = {}
        if req.backend:
            env_overrides["KRAKEN_BACKEND"] = req.backend
        if req.model:
            env_overrides["KRAKEN_MODEL_HIGH"] = req.model
            env_overrides["KRAKEN_MODEL_MID"] = req.model

        old_env = {}
        for k, v in env_overrides.items():
            old_env[k] = os.environ.get(k)
            os.environ[k] = v

        try:
            config = KrakenConfig()
            challenge_name = Path(req.challenge_path).name
            workspace = _resolve_solve_workspace(challenge_name)

            state = initial_state(
                challenge_id=challenge_name,
                challenge_path=req.challenge_path,
                flag_format=req.flag_format,
                solve_workspace=workspace,
            )
            if req.challenge_description:
                state["challenge_description"] = req.challenge_description

            graph = build_graph()
            run_config = {
                "recursion_limit": config.budget.max_steps,
                "configurable": {"thread_id": job.id},
            }

            accumulated = dict(state)
            async for chunk in graph.astream(state, config=run_config):
                for node_name, node_output in chunk.items():
                    if not isinstance(node_output, dict):
                        continue

                    node_start = time.time()
                    accumulated = _merge_state_update(accumulated, node_output)

                    event_data: dict[str, Any] = {}
                    if "challenge_type" in node_output:
                        job.challenge_type = node_output["challenge_type"]
                        event_data["challenge_type"] = node_output["challenge_type"]
                    if "binary_info" in node_output:
                        bi = node_output["binary_info"]
                        event_data["file_type"] = bi.get("file_type", "")
                        event_data["arch"] = bi.get("arch", "")
                    if "tool_cascade_results" in node_output:
                        results = node_output["tool_cascade_results"]
                        job.tools_run = len(results)
                        event_data["tools_run"] = len(results)
                        event_data["tools"] = [
                            {"tool": r.get("tool", ""), "flag_found": r.get("flag_found", False)}
                            for r in results[-5:]
                        ]
                    if "flag" in node_output and node_output["flag"]:
                        job.flag = node_output["flag"]
                        event_data["flag"] = node_output["flag"]
                    if "tool_flag_candidate" in node_output and node_output["tool_flag_candidate"]:
                        event_data["flag_candidate"] = node_output["tool_flag_candidate"]
                    if "decompiled_functions" in node_output:
                        event_data["functions_count"] = len(node_output["decompiled_functions"])

                    # Map specialist nodes to generic "specialist" for pipeline display
                    display_node = node_name
                    specialist_nodes = {
                        "constraint_solver", "crypto_decode", "dynamic_analysis",
                        "keygen", "pwn_specialist", "fuzzing_specialist",
                        "web_specialist", "dotnet_specialist", "firmware_specialist",
                        "specialist_fanout",
                    }
                    if node_name in specialist_nodes:
                        display_node = "specialist"

                    event = SolveEvent(
                        node=display_node,
                        status="completed",
                        data=event_data,
                        duration_s=time.time() - node_start,
                    )
                    await store.publish(job.id, event)

            # Solve finished
            job.flag = accumulated.get("flag", "")
            job.challenge_type = accumulated.get("challenge_type", "")
            job.result = {
                "flag": job.flag,
                "challenge_type": job.challenge_type,
                "tools_run": job.tools_run,
                "strategies_tried": accumulated.get("strategies_tried", []),
                "node_timings": accumulated.get("node_timings", []),
            }
            job.status = JobStatus.COMPLETED if job.flag else JobStatus.FAILED

        finally:
            for k, v in old_env.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

    except Exception as exc:
        job.status = JobStatus.FAILED
        job.error = f"{type(exc).__name__}: {exc}"
        await store.publish(job.id, SolveEvent(
            node="error",
            status="error",
            data={"error": str(exc), "traceback": traceback.format_exc()[-500:]},
        ))

    job.completed_at = time.time()
    await store.publish(job.id, SolveEvent(
        node="__done__",
        status=job.status.value,
        data={"flag": job.flag, "elapsed_s": round(job.elapsed_s, 2)},
    ))


async def _run_batch(batch_id: str, challenge_dirs: list[str], req: BatchSolveRequest):
    """Run batch solves with concurrency limiting."""
    sem = asyncio.Semaphore(req.concurrency)

    async def _solve_one(cp: str):
        async with sem:
            job = store.create(cp, batch_id=batch_id)
            solve_req = SolveRequest(
                challenge_path=cp,
                flag_format=req.flag_format,
                timeout_minutes=req.timeout_minutes,
                challenge_description=req.challenge_description,
            )
            await _run_solve_job(job, solve_req)

    await asyncio.gather(*[_solve_one(cp) for cp in challenge_dirs], return_exceptions=True)


# ── API Routes ───────────────────────────────────────────────────────────────


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "version": "1.0.0",
        "uptime_s": round(time.time() - _START_TIME, 1),
    }


@app.get("/api/pipeline")
async def pipeline_info():
    """Return the pipeline node graph definition."""
    return {"nodes": PIPELINE_NODES}


@app.get("/api/tools")
async def list_tools():
    return {"tools": AVAILABLE_TOOLS}


# ── Solve ────────────────────────────────────────────────────────────────────


@app.post("/api/solve")
async def start_solve(req: SolveRequest):
    path = Path(req.challenge_path).expanduser()
    if not path.exists():
        raise HTTPException(400, f"Path not found: {req.challenge_path}")

    job = store.create(str(path.resolve()))
    asyncio.create_task(_run_solve_job(job, req))
    return {"job_id": job.id, "status": job.status.value}


@app.get("/api/solve/{job_id}")
async def get_solve(job_id: str):
    job = store.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return job.to_dict()


@app.delete("/api/solve/{job_id}")
async def cancel_solve(job_id: str):
    job = store.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    if job.status in (JobStatus.RUNNING, JobStatus.PENDING):
        job.status = JobStatus.CANCELLED
        job.completed_at = time.time()
        await store.publish(job_id, SolveEvent(
            node="__done__",
            status="cancelled",
            data={"reason": "Cancelled by user"},
        ))
    return {"status": job.status.value}


@app.get("/api/solves")
async def list_solves(limit: int = Query(50, ge=1, le=200)):
    return {"solves": store.list_all(limit)}


# Alias for discoverability
@app.get("/api/jobs")
async def list_jobs(limit: int = Query(50, ge=1, le=200)):
    return {"solves": store.list_all(limit)}


# ── WebSocket: Live Solve Progress ───────────────────────────────────────────


@app.websocket("/ws/solve/{job_id}")
async def ws_solve(websocket: WebSocket, job_id: str):
    job = store.get(job_id)
    if not job:
        await websocket.close(code=4004, reason="Job not found")
        return

    await websocket.accept()
    q = await store.subscribe(job_id)

    try:
        # Send current state first (replay existing events)
        await websocket.send_json({
            "type": "init",
            "job": job.to_dict(),
        })

        # Stream new events
        while True:
            try:
                event = await asyncio.wait_for(q.get(), timeout=30.0)
                await websocket.send_json({"type": "event", "event": event})
                if event.get("node") == "__done__":
                    break
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping"})
    except WebSocketDisconnect:
        pass
    finally:
        await store.unsubscribe(job_id, q)


# ── Pipeline Stage Endpoints ─────────────────────────────────────────────────


@app.post("/api/pipeline/triage")
async def run_triage(req: TriageRequest):
    try:
        from kraken.state import initial_state
        from kraken.nodes.triage import triage

        state = initial_state(
            challenge_id="gui",
            challenge_path=req.challenge_path,
            flag_format=req.flag_format,
        )
        if req.challenge_description:
            state["challenge_description"] = req.challenge_description
        result = await triage(state)
        return {
            "binary_info": result.get("binary_info", {}),
            "strings_of_interest": result.get("strings_of_interest", []),
            "symbols": result.get("symbols", {}),
            "challenge_files": result.get("challenge_files", {}),
            "challenge_path": result.get("challenge_path", req.challenge_path),
        }
    except Exception as exc:
        raise HTTPException(500, str(exc))


@app.post("/api/pipeline/decompile")
async def run_decompile(req: DecompileRequest):
    try:
        from kraken.state import initial_state
        from kraken.nodes.decompile import decompile

        state = initial_state(
            challenge_id="gui",
            challenge_path=req.challenge_path,
            flag_format=req.flag_format,
        )
        result = await decompile(state)
        return {
            "decompiled_functions": result.get("decompiled_functions", {}),
            "call_graph": result.get("call_graph", {}),
        }
    except Exception as exc:
        raise HTTPException(500, str(exc))


@app.post("/api/pipeline/tool-cascade")
async def run_cascade(req: CascadeRequest):
    try:
        from kraken.state import initial_state
        from kraken.nodes.tool_router import tool_router

        state = initial_state(
            challenge_id="gui",
            challenge_path=req.challenge_path,
            flag_format=req.flag_format,
        )
        if req.challenge_type:
            state["challenge_type"] = req.challenge_type
        if req.extracted_params:
            state["extracted_params"] = req.extracted_params

        result = await tool_router(state)
        tool_results = result.get("tool_cascade_results", [])
        flag = result.get("tool_flag_candidate", "")
        return {
            "tools_run": len(tool_results),
            "tool_results": tool_results,
            "flag_found": bool(flag),
            "flag": flag or "",
        }
    except Exception as exc:
        raise HTTPException(500, str(exc))


@app.post("/api/pipeline/tool")
async def run_tool(req: ToolRunRequest):
    try:
        from kraken.state import initial_state
        from kraken.nodes.tool_router import _build_tool_command, _run_tool, _check_for_flag

        state = initial_state(
            challenge_id="gui",
            challenge_path=req.challenge_path,
            flag_format=req.flag_format,
        )
        params = req.extra_args or {}
        cmd = _build_tool_command(req.tool_name, params, state)

        if not cmd:
            helpers_dir = Path(__file__).resolve().parent.parent / "helpers"
            script = helpers_dir / f"{req.tool_name}.py"
            if script.exists():
                cmd = f'python3 "{script}" "{Path(req.challenge_path).resolve()}"'
            else:
                raise HTTPException(400, f"Unknown tool: {req.tool_name}")

        cwd = state.get("challenge_dir")
        result = await _run_tool(cmd, cwd, req.timeout)
        combined = result["stdout"] + "\n" + result["stderr"]
        flag = _check_for_flag(combined, req.flag_format)

        return {
            "tool": req.tool_name,
            "command": cmd,
            "exit_code": result["exit_code"],
            "stdout": result["stdout"][-5000:],
            "stderr": result["stderr"][-2000:],
            "flag_found": flag is not None,
            "flag": flag or "",
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, str(exc))


@app.post("/api/validate")
async def validate_flag(req: ValidateRequest):
    import re
    match = re.fullmatch(req.flag_format, req.flag)
    return {
        "flag": req.flag,
        "valid": match is not None,
        "format": req.flag_format,
    }


# ── Stats & History ──────────────────────────────────────────────────────────


@app.get("/api/stats")
async def get_stats():
    try:
        perf_path = Path("benchmarks/performance.json")
        if perf_path.exists():
            data = json.loads(perf_path.read_text())
            return {
                "global": data.get("global_stats", {}),
                "per_type": data.get("per_type", {}),
                "per_tool": data.get("per_tool", {}),
            }
        return {"global": {}, "per_type": {}, "per_tool": {}}
    except Exception:
        return {"global": {}, "per_type": {}, "per_tool": {}}


@app.get("/api/stats/cascade")
async def get_cascade_config():
    try:
        cfg_path = Path("benchmarks/cascade_config.json")
        if cfg_path.exists():
            return json.loads(cfg_path.read_text())
        return {}
    except Exception:
        return {}


# ── Challenges Browser ───────────────────────────────────────────────────────


@app.get("/api/challenges")
async def browse_challenges(path: str = Query("challenges")):
    """List challenge directories/files at a given path."""
    target = Path(path).expanduser().resolve()
    if not target.exists():
        raise HTTPException(404, f"Path not found: {path}")

    entries = []
    if target.is_dir():
        try:
            children = sorted(target.iterdir())
        except PermissionError:
            raise HTTPException(403, f"Permission denied: {path}")
        for item in children:
            try:
                entry: dict[str, Any] = {
                    "name": item.name,
                    "path": str(item),
                    "is_dir": item.is_dir(),
                    "size": item.stat().st_size if item.is_file() else 0,
                }
                if item.is_dir():
                    sub_children = list(item.iterdir())
                    entry["file_count"] = len(sub_children)
                    child_names = {c.name.lower() for c in sub_children}
                    entry["has_binary"] = any(
                        c.suffix in (".elf", ".exe", ".bin", "") and c.is_file() and c.stat().st_size > 100
                        for c in sub_children
                    )
                    entry["has_description"] = bool(
                        child_names & {"description.txt", "readme.md", "readme.txt", "description.md"}
                    )
                entries.append(entry)
            except (PermissionError, OSError):
                continue
    else:
        entries.append({
            "name": target.name,
            "path": str(target),
            "is_dir": False,
            "size": target.stat().st_size,
        })

    return {"path": str(target), "entries": entries}


# ── Config ───────────────────────────────────────────────────────────────────


@app.get("/api/config")
async def get_config():
    try:
        from kraken.config import KrakenConfig
        cfg = KrakenConfig()
        return {
            "model": {
                "backend": cfg.models.backend,
                "model_high": cfg.models.model_high,
                "model_mid": cfg.models.model_mid,
                "model_low": cfg.models.model_low,
                "ollama_base_url": cfg.models.ollama_base_url,
                "num_ctx": cfg.models.num_ctx,
            },
            "budget": {
                "max_steps": cfg.budget.max_steps,
                "timeout_minutes": cfg.budget.timeout_minutes,
                "max_strategies": cfg.budget.max_strategies,
                "max_solve_attempts": cfg.budget.max_solve_attempts,
            },
        }
    except Exception as exc:
        raise HTTPException(500, f"Failed to load config: {exc}")


# ── Batch Solve ──────────────────────────────────────────────────────────────


@app.post("/api/batch-solve")
async def start_batch_solve(req: BatchSolveRequest):
    """Start solving all challenge subdirectories in a directory."""
    target = Path(req.directory).expanduser().resolve()
    if not target.exists() or not target.is_dir():
        raise HTTPException(400, f"Not a directory: {req.directory}")

    challenge_dirs = [
        str(item) for item in sorted(target.iterdir())
        if item.is_dir() and any(item.iterdir())
    ]
    if not challenge_dirs:
        raise HTTPException(400, "No challenge subdirectories found")

    batch_id = uuid.uuid4().hex[:8]

    # Pre-create jobs so we can return IDs immediately
    jobs_info = []
    for cp in challenge_dirs:
        job = store.create(cp, batch_id=batch_id)
        jobs_info.append({"job_id": job.id, "challenge": cp})

    # Run solves in background with concurrency limit
    asyncio.create_task(_run_batch_with_jobs(batch_id, jobs_info, req))

    return {"batch_id": batch_id, "batch_size": len(jobs_info), "jobs": jobs_info}


async def _run_batch_with_jobs(batch_id: str, jobs_info: list[dict], req: BatchSolveRequest):
    """Run batch solves using pre-created jobs with concurrency limiting."""
    sem = asyncio.Semaphore(req.concurrency)

    async def _solve_one(job_id: str, cp: str):
        async with sem:
            job = store.get(job_id)
            if not job:
                return
            solve_req = SolveRequest(
                challenge_path=cp,
                flag_format=req.flag_format,
                timeout_minutes=req.timeout_minutes,
                challenge_description=req.challenge_description,
            )
            await _run_solve_job(job, solve_req)

    await asyncio.gather(
        *[_solve_one(j["job_id"], j["challenge"]) for j in jobs_info],
        return_exceptions=True,
    )


@app.get("/api/batch/{batch_id}")
async def get_batch_status(batch_id: str):
    """Get status of all jobs in a batch."""
    jobs = store.list_batch(batch_id)
    if not jobs:
        raise HTTPException(404, "Batch not found")
    return {
        "batch_id": batch_id,
        "total": len(jobs),
        "completed": sum(1 for j in jobs if j["status"] == "completed"),
        "failed": sum(1 for j in jobs if j["status"] == "failed"),
        "running": sum(1 for j in jobs if j["status"] == "running"),
        "pending": sum(1 for j in jobs if j["status"] == "pending"),
        "flags_found": sum(1 for j in jobs if j.get("flag")),
        "jobs": jobs,
    }


@app.get("/api/batch-status")
async def batch_status():
    """Summary status of all jobs (legacy compat)."""
    all_jobs = store.list_all(200)
    return {
        "total": len(all_jobs),
        "completed": sum(1 for j in all_jobs if j["status"] == "completed"),
        "failed": sum(1 for j in all_jobs if j["status"] == "failed"),
        "running": sum(1 for j in all_jobs if j["status"] == "running"),
        "pending": sum(1 for j in all_jobs if j["status"] == "pending"),
        "flags_found": sum(1 for j in all_jobs if j.get("flag")),
    }


# ── Static Files & SPA ──────────────────────────────────────────────────────


@app.get("/")
async def index():
    return FileResponse(_STATIC_DIR / "index.html")


# Mount static last so API routes take precedence
app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


# ── Entrypoint ───────────────────────────────────────────────────────────────


def main():
    import argparse
    import uvicorn

    parser = argparse.ArgumentParser(description="Kraken GUI Server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address")
    parser.add_argument("-p", "--port", type=int, default=7777, help="Port")
    parser.add_argument("--reload", action="store_true", help="Auto-reload on code changes")
    args = parser.parse_args()

    print(f"\n  KRAKEN GUI → http://{args.host}:{args.port}\n")
    uvicorn.run(
        "kraken.gui.app:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )


if __name__ == "__main__":
    main()
