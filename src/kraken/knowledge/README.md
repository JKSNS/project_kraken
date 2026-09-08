# knowledge/

Optional retrieval and solve memory. This package lets KRAKEN learn across solves
by remembering what worked and surfacing it on similar challenges.

- `trajectory.py`, records solve trajectories (what was tried, what won).
- `embeddings.py` + `qdrant_store.py`, embed challenge material and past solves
  into a Qdrant vector store.
- `rag.py`, retrieve similar prior cases to prime a new solve.

**Optional by design.** The proven solve path does not require this to be
populated; retrieval is an accelerant, not a dependency. Standing up the vector
store needs Qdrant reachable, when it is not configured, KRAKEN degrades to
running without prior-case retrieval rather than failing. The MCP
`kraken_similar` / knowledge-query tools and the post-solve retrospective read
from here.
