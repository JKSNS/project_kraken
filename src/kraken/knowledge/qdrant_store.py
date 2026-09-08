"""Qdrant vector store for Kraken knowledge base.

Manages three collections:
  - challenge_trajectories: Solved/failed challenge feature vectors + payloads
  - writeups: CTF writeup embeddings for RAG retrieval
  - tool_performance: Per-tool performance indexed by challenge features

All operations are try/except wrapped -- if Qdrant is unreachable, callers get
empty results and stores silently no-op.
"""

from __future__ import annotations

import hashlib
import logging
import os
import struct
from typing import Any

from qdrant_client import QdrantClient
from qdrant_client.models import (
    Distance,
    FieldCondition,
    Filter,
    MatchValue,
    PointStruct,
    VectorParams,
)

logger = logging.getLogger(__name__)

QDRANT_URL = os.environ.get("QDRANT_URL", "http://host.docker.internal:6333")
EMBEDDING_DIM = 384  # Deterministic feature vectors (no ML model)


class KrakenQdrant:
    """Manages Qdrant collections for challenge knowledge.

    Auto-creates collections on first use.  All public methods are
    safe to call even if Qdrant is unreachable -- they return empty
    results or silently skip writes.
    """

    COLLECTIONS: dict[str, dict[str, Any]] = {
        "challenge_trajectories": {
            "size": EMBEDDING_DIM,
            "distance": Distance.COSINE,
            "description": "Solved challenge trajectories with features and solutions",
        },
        "writeups": {
            "size": EMBEDDING_DIM,
            "distance": Distance.COSINE,
            "description": "CTF writeup knowledge for RAG retrieval",
        },
        "tool_performance": {
            "size": 64,  # Smaller feature vector for tool stats
            "distance": Distance.EUCLID,
            "description": "Per-tool performance indexed by challenge features",
        },
    }

    def __init__(self, url: str = QDRANT_URL):
        self.client = QdrantClient(url=url, timeout=10)
        # Verify connectivity -- raises if Qdrant is unreachable
        self.client.get_collections()
        self._ensure_collections()

    # ------------------------------------------------------------------
    # Collection management
    # ------------------------------------------------------------------

    def _ensure_collections(self) -> None:
        """Create any missing collections."""
        try:
            existing = {c.name for c in self.client.get_collections().collections}
        except Exception as exc:
            logger.warning("Qdrant unreachable during collection check: %s", exc)
            return

        for name, config in self.COLLECTIONS.items():
            if name not in existing:
                try:
                    self.client.create_collection(
                        collection_name=name,
                        vectors_config=VectorParams(
                            size=config["size"],
                            distance=config["distance"],
                        ),
                    )
                    logger.info("Created Qdrant collection: %s", name)
                except Exception as exc:
                    logger.warning("Failed to create collection %s: %s", name, exc)

    # ------------------------------------------------------------------
    # Trajectory storage
    # ------------------------------------------------------------------

    def store_trajectory(
        self,
        challenge_id: str,
        features: list[float],
        payload: dict[str, Any],
    ) -> bool:
        """Store a solved/failed challenge trajectory.

        Uses a deterministic point ID derived from challenge_id so that
        re-ingesting the same challenge overwrites rather than duplicates.

        Returns True if the upsert succeeded.
        """
        point_id = self._deterministic_id(challenge_id)
        try:
            self.client.upsert(
                collection_name="challenge_trajectories",
                points=[
                    PointStruct(
                        id=point_id,
                        vector=features,
                        payload=payload,
                    )
                ],
            )
            return True
        except Exception as exc:
            logger.warning("Failed to store trajectory for %s: %s", challenge_id, exc)
            return False

    # ------------------------------------------------------------------
    # Similarity search
    # ------------------------------------------------------------------

    def find_similar(
        self,
        features: list[float],
        collection: str = "challenge_trajectories",
        limit: int = 5,
        filter_: Filter | None = None,
    ) -> list[dict[str, Any]]:
        """Find similar points by feature vector.

        Returns list of dicts with keys: id, score, payload.
        """
        try:
            results = self.client.query_points(
                collection_name=collection,
                query=features,
                limit=limit,
                query_filter=filter_,
                with_payload=True,
            )
            return [
                {
                    "id": point.id,
                    "score": point.score,
                    "payload": point.payload or {},
                }
                for point in results.points
            ]
        except Exception as exc:
            logger.warning("Qdrant similarity search failed: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Writeup storage
    # ------------------------------------------------------------------

    def store_writeup(
        self,
        writeup_id: str,
        embedding: list[float],
        payload: dict[str, Any],
    ) -> bool:
        """Store a writeup chunk for RAG retrieval."""
        point_id = self._deterministic_id(writeup_id)
        try:
            self.client.upsert(
                collection_name="writeups",
                points=[
                    PointStruct(
                        id=point_id,
                        vector=embedding,
                        payload=payload,
                    )
                ],
            )
            return True
        except Exception as exc:
            logger.warning("Failed to store writeup %s: %s", writeup_id, exc)
            return False

    def search_writeups(
        self,
        embedding: list[float],
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        """Search writeups by embedding similarity."""
        return self.find_similar(embedding, collection="writeups", limit=limit)

    # ------------------------------------------------------------------
    # Tool performance storage
    # ------------------------------------------------------------------

    def store_tool_performance(
        self,
        tool_name: str,
        challenge_id: str,
        features: list[float],
        payload: dict[str, Any],
    ) -> bool:
        """Store per-tool performance on a challenge."""
        point_id = self._deterministic_id(f"{tool_name}_{challenge_id}")
        try:
            self.client.upsert(
                collection_name="tool_performance",
                points=[
                    PointStruct(
                        id=point_id,
                        vector=features[:64],  # Truncate to 64-dim
                        payload=payload,
                    )
                ],
            )
            return True
        except Exception as exc:
            logger.warning(
                "Failed to store tool perf for %s/%s: %s",
                tool_name,
                challenge_id,
                exc,
            )
            return False

    def find_similar_tool_performance(
        self,
        features: list[float],
        tool_name: str | None = None,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Find similar tool performance records, optionally filtered by tool."""
        filter_ = None
        if tool_name:
            filter_ = Filter(
                must=[
                    FieldCondition(
                        key="tool_name",
                        match=MatchValue(value=tool_name),
                    )
                ]
            )
        return self.find_similar(
            features[:64],
            collection="tool_performance",
            limit=limit,
            filter_=filter_,
        )

    # ------------------------------------------------------------------
    # Collection info
    # ------------------------------------------------------------------

    def collection_counts(self) -> dict[str, int]:
        """Return point counts for all managed collections."""
        counts: dict[str, int] = {}
        for name in self.COLLECTIONS:
            try:
                info = self.client.get_collection(collection_name=name)
                counts[name] = info.points_count or 0
            except Exception:
                counts[name] = -1  # Unreachable
        return counts

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _deterministic_id(key: str) -> int:
        """Generate a deterministic positive integer ID from a string key.

        Uses the first 8 bytes of a SHA-256 hash, interpreted as an
        unsigned 64-bit integer, then masked to stay within qdrant's
        signed 64-bit range.
        """
        digest = hashlib.sha256(key.encode("utf-8")).digest()
        (value,) = struct.unpack(">Q", digest[:8])
        # Qdrant uses unsigned 64-bit IDs; mask to 63 bits to be safe
        return value & 0x7FFFFFFFFFFFFFFF
