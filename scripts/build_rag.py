#!/usr/bin/env python3
"""Build the RAG knowledge store index in Qdrant."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from kraken.config import QdrantConfig
from kraken.rag.store import build_store


def main():
    knowledge_dir = str(Path(__file__).resolve().parent.parent / "knowledge_store")
    config = QdrantConfig()

    print(f"Building RAG index from {knowledge_dir}...")
    print(f"Qdrant URL: {config.url}")
    print(f"Collection: {config.collection_name}")
    store = build_store(knowledge_dir, config=config)
    print("Index built successfully in Qdrant")
    return 0


if __name__ == "__main__":
    exit(main())
