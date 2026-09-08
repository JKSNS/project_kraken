"""Intelligent model router -- discovers Ollama models and maps to tiers.

At startup, queries the Ollama ``/api/tags`` endpoint to list pulled models,
then assigns them to KRAKEN's three tiers (high, mid, low) based on a
preference table.  Falls back to environment variable or a single default.
"""
from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from kraken.logging.structured import get_logger

log = get_logger(__name__)

# ── Tier preference tables ────────────────────────────────────────────
# Ordered by preference (first match wins).  Keys are lowercased Ollama
# model tags.  The router normalises pulled model names before matching.

_TIER_PREFERENCES: dict[str, list[str]] = {
    "high": [
        "qwen3-coder:30b",
        "deepseek-r1:32b",
        "deepseek-coder-v2:33b",
        "codestral:22b",
        "qwen2.5-coder:32b",
        "devstral-small-2:24b",
        "gpt-oss:20b",
        "qwen3-coder:14b",
        "qwen3.5-9b-256k",
        "glm-4.7-flash",
    ],
    "mid": [
        "devstral-small-2:24b",
        "qwen3-coder:14b",
        "qwen3.5-9b-256k",
        "gpt-oss:20b",
        "qwen2.5-coder:14b",
        "deepseek-coder-v2:16b",
        "glm-4.7-flash",
    ],
    "low": [
        "qwen3.5-9b-256k",
        "glm-4.7-flash",
        "qwen2.5-coder:7b",
        "qwen3-coder:8b",
        "llama3.2:3b",
        "phi-4-mini",
    ],
}

# Static defaults when no discovery is available
TIER_DEFAULTS: dict[str, str] = {
    "high": "qwen3-coder:30b",
    "mid": "devstral-small-2:24b",
    "low": "glm-4.7-flash",
}


@dataclass
class ModelProfile:
    """Metadata about a discovered Ollama model."""

    name: str  # full tag, e.g. "qwen3-coder:30b"
    size_bytes: int = 0
    parameter_size: str = ""  # e.g. "30B"
    quantization: str = ""  # e.g. "Q4_K_M"
    family: str = ""
    modified_at: str = ""

    @property
    def display(self) -> str:
        parts = [self.name]
        if self.parameter_size:
            parts.append(f"({self.parameter_size})")
        if self.quantization:
            parts.append(f"[{self.quantization}]")
        return " ".join(parts)


@dataclass
class ModelRouter:
    """Discovers available Ollama models and selects best-fit per tier."""

    base_url: str = "http://localhost:11434"
    available: dict[str, ModelProfile] = field(default_factory=dict)
    tier_assignments: dict[str, str] = field(default_factory=dict)
    _discovered: bool = False

    async def discover_models(self, base_url: str | None = None) -> dict[str, ModelProfile]:
        """Query Ollama /api/tags and populate available models.

        Uses synchronous urllib to avoid requiring an async HTTP client
        dependency -- the call is fast (local loopback).
        """
        url = f"{(base_url or self.base_url).rstrip('/')}/api/tags"
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
        except Exception as exc:
            log.warning("model_router_discover_failed", error=str(exc)[:200], url=url)
            return {}

        models: dict[str, ModelProfile] = {}
        for entry in data.get("models", []):
            name = entry.get("name", "") or entry.get("model", "")
            if not name:
                continue
            details = entry.get("details", {})
            profile = ModelProfile(
                name=name,
                size_bytes=entry.get("size", 0),
                parameter_size=details.get("parameter_size", ""),
                quantization=details.get("quantization_level", ""),
                family=details.get("family", ""),
                modified_at=entry.get("modified_at", ""),
            )
            models[name.lower()] = profile

        self.available = models
        self._discovered = True
        log.info("model_router_discovered", count=len(models), models=list(models.keys()))
        return models

    def select_for_tier(self, tier: str) -> str:
        """Select the best available model for a tier.

        Walks the preference list for *tier* and returns the first model
        that exists in ``self.available``.  Falls back to ``TIER_DEFAULTS``.
        """
        if not self._discovered or not self.available:
            return TIER_DEFAULTS.get(tier, "glm-4.7-flash")

        preferences = _TIER_PREFERENCES.get(tier, [])
        for candidate in preferences:
            if candidate.lower() in self.available:
                return candidate

        # No preference matched -- return default
        return TIER_DEFAULTS.get(tier, "glm-4.7-flash")

    def assign_tiers(self) -> dict[str, str]:
        """Assign models to all tiers based on available models."""
        self.tier_assignments = {
            tier: self.select_for_tier(tier)
            for tier in ("high", "mid", "low")
        }
        log.info("model_router_tiers_assigned", **self.tier_assignments)
        return self.tier_assignments

    def get_config_overrides(self) -> dict[str, Any]:
        """Return ModelConfig field overrides based on tier assignments."""
        if not self.tier_assignments:
            self.assign_tiers()
        return {
            "backend": "ollama",
            "model_high": self.tier_assignments.get("high", TIER_DEFAULTS["high"]),
            "model_mid": self.tier_assignments.get("mid", TIER_DEFAULTS["mid"]),
            "model_low": self.tier_assignments.get("low", TIER_DEFAULTS["low"]),
        }

    def format_table(self) -> str:
        """Format a human-readable table of available models and tier assignments."""
        if not self.tier_assignments:
            self.assign_tiers()

        lines = ["Available Ollama Models:", "=" * 60]
        for name, profile in sorted(self.available.items()):
            tier_label = ""
            for tier, assigned in self.tier_assignments.items():
                if assigned.lower() == name:
                    tier_label = f"  <- {tier.upper()} tier"
                    break
            size_mb = profile.size_bytes / (1024 * 1024) if profile.size_bytes else 0
            lines.append(
                f"  {profile.name:<30s} {profile.parameter_size:>6s} "
                f"{size_mb:>8.0f}MB {profile.quantization:<10s}{tier_label}"
            )

        lines.append("")
        lines.append("Tier Assignments:")
        lines.append("-" * 40)
        for tier in ("high", "mid", "low"):
            model = self.tier_assignments.get(tier, "?")
            lines.append(f"  {tier:<6s} -> {model}")
        return "\n".join(lines)
