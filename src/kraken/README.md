# src/kraken/

The KRAKEN package. This is the solver and everything around it. If you are here
to understand or extend the system, start with the map below, then read the
[technical report](../../paper/kraken_whitepaper.tex) for the full design.

## What is proven vs. what is growing

KRAKEN has two capability surfaces at very different maturity levels. Be honest
about which is which when you read the code or cite results.

- **CTF auto-solving (jeopardy), proven.** This is the load-bearing capability
  and the one with a track record: the cheapest-first cascade, the nine
  specialists, the tool router and library, the flag validator, the manager, and
  the learned optimizer. It has cleared public benchmarks and live competitions
  end to end (see the report). The whole `nodes/`, `tools/`, `helpers/`, and
  `runtime/` surface, plus the graph spine, serves this path. When the docs say
  KRAKEN "solves," they mean this.

- **Attack-defense (`ad/`), growing.** A full A-D tick engine (offense, defense,
  SLA, scoreboard) that turns one bug into a field-wide flag harvest and can
  auto-patch and self-heal a service. It is built and unit-tested (the engine
  alone carries over a hundred tests) but has **not** been proven across a full
  live A-D competition. Treat it as an architecture with test coverage, not a
  track record. It is described honestly this way in the report too.

Other subsystems (`knowledge/` retrieval, the `gui/`, the Docker sandbox) are real
and wired to varying degrees; each is noted below. In particular the `gui/` runs but
has never been used for real work (every result came from the CLI and MCP surface),
so treat it as an unexercised convenience, not a validated workflow.

## Layout

The top level holds the eight spine modules, the recognizable core API. Everything
else lives in a named subpackage.

**Spine (top level)**

| Module | Role |
|---|---|
| `orchestrator.py` | Entry point (`kraken`, `kraken-init`); drives a solve or a live competition |
| `graph.py` | LangGraph `StateGraph` assembly, the ~20-node processing graph |
| `state.py` | `KrakenState` TypedDict (~48 fields) threaded through the graph |
| `models.py` | The model layer: Claude / OpenAI / Ollama generation + fallback |
| `schemas.py` | Shared typed schemas |
| `config.py` | Settings (env-driven) for models, Docker, and the cascade |
| `mcp_server.py` | MCP server (`kraken-mcp`) exposing the tooling to an external agent |

**Subpackages**

| Package | Role |
|---|---|
| `nodes/` | Graph nodes: triage, classify, the nine `specialists/`, tool router, solve engine, flag validator, manager |
| `tools/` | Tool-router support and tool metadata |
| `helpers/` | The analysis-tool library, ~100 `auto_*.py` scripts (decoders, symbolic exec, crypto, carving, pwn). See `helpers/README.md` |
| `runtime/` | Model router + `kraken-runtime` CLI (tiering, model discovery) |
| `storage/` | Persistence: artifact store, run ledger, solve-knowledge base |
| `execution/` | Execution mechanics: solve sessions, model racing, live-competition autopilot, loop detection, cascade optimizer |
| `platform/` | CTF-platform clients (CTFd workspace client + generic REST/scoreboard client) |
| `knowledge/` | Optional retrieval: embeddings, Qdrant store, RAG, trajectory memory |
| `agents/` | Agentic delegation seat (the Tier-4 full-shell fallback) |
| `ad/` | Attack-defense engine (`kraken-ad`), offense / defense / infra. See "growing" above |
| `gui/` | FastAPI browser GUI (`kraken-gui`) with live solve streaming |
| `docker/` | Optional sandboxed challenge-binary execution |
| `reporting/`, `logging/`, `prompts/` | Report generation, structured logs + cost tracking, solve-prompt templates |

## The two design rules

Everything above serves two rules, stated once so the code makes sense:

1. **Model-last.** The top cascade tier tries to find the flag with deterministic
   tooling and no model call. A model enters only when the tools stall.
2. **The validator is the oracle.** A model may *propose* a flag; only the
   deterministic validator can *confirm* one. On rejection the run retries a
   different way rather than declaring victory.

## Working on it

The behavior-carrying files are `helpers/*.py`, `nodes/tool_router.py`, and
`nodes/flag_validator.py`. Never regress the CTFTiny gate. Run the suite before
committing:

```bash
pip install -e ".[dev,gui]"
pytest -q
```
