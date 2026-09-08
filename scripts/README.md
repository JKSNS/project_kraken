# scripts/

Operational scripts around the solver. The solver itself lives in
[`../src/kraken/`](../src/kraken); these are the tools you run beside it.

## Solving and competitions

- `hybrid_solve.py`: the fastest multi engine solver. Auto routes each challenge
  between the deterministic cascade and an agent, and runs a directory in parallel.
- `codex_solve_all.sh`: drive a whole challenge directory through the agent path.
- `submit_flags.py`: submit recovered flags to a CTFd instance under the
  conservative one submission per challenge policy.
- `make_submission.py`: package a competition submission from a solve workspace.
- `solve_second_pass.py`: re run the challenges a first pass did not solve.
- `solve_license_angr.py`: a worked angr driver kept as a reference solve.

## Measurement and indexing

- `benchmark.py`: time boxed batch runner for measuring solve rate and latency.
- `precision_regression.py`: guardrail run that checks the flag validator does not
  start accepting non flags.
- `extract_solve_times.py`: pull per challenge timing out of solve artifacts.
- `build_rag.py`, `build_tree_index.py`: build the optional retrieval and code index
  used by the knowledge subsystem.

## Environment

- `preflight.sh`: check the local environment (Python, Ollama, external tools).
- `run.py`: small entry point helper.

## ghidra/

Headless Ghidra helper scripts used by the decompilation tooling: decompile every
function, export the call graph, dump functions, and list import call sites.
