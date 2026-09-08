# docs/

Reference documentation for KRAKEN. The `README.md` at the repository root is the
front door; these are the deeper references.

- [`TECHNICAL.md`](TECHNICAL.md): the full architecture. Graph topology, the state
  machine, the node and component model, the tool cascade, and how the pieces fit.
  Start here if you want to understand or extend the system.
- [`RUNTIME_GUIDE.md`](RUNTIME_GUIDE.md): running KRAKEN, with a focus on the fully
  offline path (local models via Ollama, model tiering, batch solving).
- [`PITFALLS.md`](PITFALLS.md): a practical cheat sheet of binary
  exploitation pitfalls the solver and its authors have hit.

The authoritative design writeup, longer and more complete than any of these, is
the technical report in [`../paper/`](../paper).
