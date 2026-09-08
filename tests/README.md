# tests/

The pytest suite. The whole suite is offline and deterministic: model calls are
mocked, so nothing here needs Ollama or a network. Run it before every commit.

```bash
pip install -e ".[dev,gui]"
pytest -q
```

## Layout

- `unit/`: the bulk of the coverage, organized to mirror the package. Subfolders
  match `src/kraken/`: `nodes/`, `tools/`, `storage/`, `execution/`, `ad/`,
  `runtime/`, `knowledge/`, `gui/`. Cross cutting core tests (state, schemas,
  orchestrator, mcp_server, failure taxonomy) sit at the `unit/` root.
- `integration/`: multi node behavior, such as graph routing and cached node
  wrappers.
- `e2e/`: end to end flows over small fixture challenges.

## What the suite is strict about

- The flag validator has golden tests that assert real flags are accepted and that
  flags embedded in comments, regexes, and format strings are rejected.
- Two strict `xfail` tests in `unit/tools/test_registry.py` document the known gap
  that about 19 older helper scripts are not yet registered. They are recorded, not
  hidden; a passing run keeps them visibly pending rather than silently green.
