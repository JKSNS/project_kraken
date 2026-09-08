# KRAKEN, developer notes for Claude Code

KRAKEN is an autonomous CTF auto-solver. This file orients an agent working on the
codebase; end-user docs live in `README.md` and `docs/`.

## Layout

- `src/kraken/`, the solver. `orchestrator.py` (entry), `graph.py` (LangGraph
  assembly), `nodes/` (triage, tool_router, solve_engine, flag_validator),
  `helpers/auto_*.py` (analysis primitives), `runtime/` (model router + CLI),
  `mcp_server.py` (MCP surface).
- `scripts/`, `hybrid_solve.py` (fastest multi-engine solver), `submit_flags.py`,
  `extract_solve_times.py`, and `scripts/ghidra/` (headless Ghidra helper scripts:
  decompile-all, call-graph export, function dump, import call-site listing).
- `tests/`, pytest suite (`unit/`, `integration/`, `e2e/`).
- `docs/`, architecture (`TECHNICAL.md`), the offline runtime guide
  (`RUNTIME_GUIDE.md`), and a pwn cheat-sheet (`PITFALLS.md`).
- `paper/`, the technical report (`kraken_whitepaper.tex`).

## Working on the solver

Only these files carry solver behavior and should be the focus of improvements:
- `src/kraken/helpers/*.py`, tool scripts
- `src/kraken/nodes/tool_router.py`, tool routing
- `src/kraken/nodes/flag_validator.py`, flag validation

Never regress the CTFTiny gate (23/23). Run the suite before committing:

```bash
pip install -e ".[dev]"
pytest -q
```

## Model backend

Local Ollama by default. `kraken-runtime models` shows discovered models and how
they map to KRAKEN's high/mid/low tiers. Set `OLLAMA_HOST` to point elsewhere.
