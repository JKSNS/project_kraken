# runtime/

The model layer and the `kraken-runtime` CLI. This is what makes KRAKEN model
agnostic: the rest of the system asks for a generation at a tier (high, mid, low)
and this package decides which backend and model actually serve it.

- `model_router.py`: discover the available models and assign them to tiers. This
  is what lets the same solver run on a local Ollama model or a frontier one without
  the graph knowing the difference.
- `factory.py`: build the runtime for the selected backend.
- `base.py`: the common runtime interface every backend implements.
- `local_runtime.py`: the local backend (Ollama and similar).
- `claude_code_runtime.py`: run inside Claude Code, using its model as the backend.
- `kraken_runtime.py`: the default runtime wiring.
- `context_manager.py`, `project_context.py`, `session.py`: keep a solve within the
  model's context window and carry per session state.
- `metrics.py`: token and cost accounting.
- `cli.py`: the `kraken-runtime` command. `kraken-runtime models` shows the
  discovered models and how they map to the high, mid, and low tiers.

Set `OLLAMA_HOST` to point at a non default Ollama endpoint. Tier assignments are
env overridable via `KRAKEN_MODEL_HIGH`, `KRAKEN_MODEL_MID`, and `KRAKEN_MODEL_LOW`.
