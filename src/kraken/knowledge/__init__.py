"""Kraken Knowledge Base -- Qdrant-powered challenge similarity and RAG.

Provides:
- TrajectoryStore: Record and retrieve solved/failed challenge trajectories
- SolveRAG: Retrieval-augmented generation context for the solve engine
- KrakenQdrant: Low-level Qdrant collection management
- embed_challenge: Deterministic feature vector from challenge state
"""


def __getattr__(name: str):
    """Lazy imports to avoid circular import issues with -m execution."""
    if name == "TrajectoryStore":
        from .trajectory import TrajectoryStore
        return TrajectoryStore
    if name == "SolveRAG":
        from .rag import SolveRAG
        return SolveRAG
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["TrajectoryStore", "SolveRAG"]
