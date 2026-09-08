# gui/

A FastAPI browser front end for KRAKEN. It exposes the same solve pipeline the CLI
drives, but over HTTP with live progress streaming, so you can watch a solve
unfold in a browser instead of reading a terminal.

Entry point: `kraken-gui` (`app.py`), default `http://127.0.0.1:7777`.

- `app.py`, the FastAPI app. REST endpoints for health, the pipeline/tool
  inventory, launching a solve (`POST /api/solve`), and listing solves; a
  WebSocket (`/ws/solve/{job_id}`) streams live solve events as they happen.
- `jobs.py`, an in-memory background job store tracking each solve's status and
  event stream.
- `static/`, the single-page front end served at `/`.

Run it:

```bash
pip install -e ".[gui]"
kraken-gui                 # http://127.0.0.1:7777
kraken-gui --port 8080     # or pick a port
```

The GUI makes no model calls of its own; it drives the same graph the CLI does and
reports what the pipeline produces.

## Status: present, not exercised

Full honesty: this GUI ships and runs, but it has not actually been used to run real
work. Every solve, competition, and benchmark result in this project came from the
CLI and the MCP surface, never from this browser front end. It is here as a working
starting point, not a validated workflow. Treat it as a convenience that has not yet
earned a track record, and prefer the CLI for anything that matters.
