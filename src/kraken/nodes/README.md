# nodes/

The graph nodes. These are the steps of the LangGraph state machine assembled in
[`../graph.py`](../graph.py), each one a function over `KrakenState`. This is where
the solve actually happens.

## The spine

Every challenge flows through the intake pipeline first:

- `triage.py`: identify what the challenge is and what it ships (files, a remote
  service, a category hint).
- `unpack.py`: extract archives and nested containers.
- `decompile.py`: recover source or pseudocode from binaries.
- `normalize.py`: put the challenge into a common shape.
- `classify.py`: decide the category and route to a specialist.

## The nine specialists

`classify` routes to one per category. `specialist_fanout.py` runs them:
`constraint_solver.py`, `crypto_decode.py`, `pwn_specialist.py`,
`web_specialist.py`, `keygen.py`, `dynamic_analysis.py`, `fuzzing_specialist.py`,
`dotnet_specialist.py`, `firmware_specialist.py`. The heavier ones have subgraphs
under [`specialists/`](specialists).

## Convergence and control

- `tool_router.py`: run the deterministic tool cascade. If a tool produces a valid
  flag it short circuits straight to the validator, with no model call.
- `solve_engine.py`: when the tools stall, the model writes and runs a targeted
  solve script.
- `flag_validator.py`: the oracle. Only this node can confirm a flag; a model may
  propose but never certify one.
- `manager.py`: recovery. It fires only on failure and can reroute to any node or
  end the run.
- `context_compressor.py`, `failure_analysis.py`: keep long runs within budget and
  turn a failure into a next move.

The two files that carry the most behavior, and that you should change most
carefully, are `tool_router.py` and `flag_validator.py`.
