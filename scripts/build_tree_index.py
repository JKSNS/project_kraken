#!/usr/bin/env python3
"""Build the tree index from knowledge_store/ markdown files.

Replaces scripts/build_rag.py for the tree-based retrieval mode.

Usage:
    python3 scripts/build_tree_index.py [--knowledge-dir knowledge_store/] [--output .kraken/tree_index.json]
"""
import argparse
import asyncio
import sys
from pathlib import Path

# Add src to path for development installs
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from kraken.config import ModelConfig
from kraken.rag.tree_index import TreeIndex


async def main():
    parser = argparse.ArgumentParser(description="Build tree index for vectorless RAG")
    parser.add_argument(
        "--knowledge-dir",
        default="knowledge_store",
        help="Directory containing knowledge markdown files",
    )
    parser.add_argument(
        "--output",
        default=".kraken/tree_index.json",
        help="Output path for the tree index",
    )
    parser.add_argument(
        "--backend",
        default="ollama",
        help="LLM backend for summarization (ollama, claude, anthropic)",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Model name override for summarization",
    )
    args = parser.parse_args()

    config = ModelConfig(backend=args.backend)
    if args.model:
        config = ModelConfig(backend=args.backend, model_low=args.model)

    index = TreeIndex(index_path=Path(args.output))

    print(f"Building tree index from {args.knowledge_dir}...")
    await index.build(args.knowledge_dir, config)
    print(f"Tree index saved to {args.output}")


if __name__ == "__main__":
    asyncio.run(main())
