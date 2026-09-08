"""Configuration via Pydantic Settings -- env vars and defaults."""

from __future__ import annotations

import os

from pydantic_settings import BaseSettings
from pydantic import Field


def _default_ollama_base_url() -> str:
    """Resolve default Ollama endpoint for mixed local/proxy environments."""
    return (
        os.environ.get("OLLAMA_HOST")
        or os.environ.get("ANTHROPIC_BASE_URL")
        or "http://localhost:11434"
    )


class ModelConfig(BaseSettings):
    """LLM model configuration per tier.

    Supports four backends:
      - ``claude``: Uses ``claude -p`` CLI (Max subscription, no API key needed)
      - ``anthropic``: Uses the Anthropic Python SDK (requires ANTHROPIC_API_KEY) (#12)
      - ``openai``: Uses the OpenAI Python SDK (requires OPENAI_API_KEY)
      - ``ollama``: Uses local Ollama server
    """

    model_config = {"env_prefix": "KRAKEN_"}

    # Backend selection: "claude", "anthropic", "openai", "ollama" (+ "codex" for racing only)
    backend: str = Field(default="claude", description="LLM backend: 'claude', 'anthropic', 'openai', or 'ollama'")

    # Model IDs per tier -- Ollama tags when backend=ollama, Claude model aliases when backend=claude
    model_high: str = Field(default="sonnet-4.6", description="Largest model for manager + solve_engine")
    model_mid: str = Field(default="sonnet-4.6", description="Mid-tier for classify + specialists")
    model_low: str = Field(default="haiku", description="Smallest model for normalize + compactor")

    # Temperature per tier
    temperature_high: float = 0.3
    temperature_mid: float = 0.1
    temperature_low: float = 0.0

    # Ollama connection (only used when backend=ollama)
    ollama_base_url: str = Field(default_factory=_default_ollama_base_url, description="Ollama server base URL")

    # Context window -- MUST be large enough for solve_engine prompts (~10K tokens)
    # Only used for Ollama backend; Claude handles context automatically.
    num_ctx: int = Field(default=131072, description="Ollama context window size in tokens")

    # Context budget and template mode for adaptive prompt sizing
    context_budget: int = 131072
    solve_template_mode: str = "auto"  # "auto", "compact", "full"

    # Generation budgets (mostly relevant to Ollama/local inference)
    solve_num_predict: int = Field(
        default=24576,
        description="Max tokens for solve_engine generation",
    )
    solve_inner_retries: int = Field(
        default=3,
        description="Max inner fix iterations per solve_engine call",
    )

    # Racing configuration (parallel model diversity)
    racing_enabled: bool = Field(
        default=False,
        description="Enable parallel model racing on hard challenges (KRAKEN_RACING_ENABLED or KRAKEN_ENABLE_RACING=1)",
    )
    racing_threshold: int = Field(
        default=6,
        description="Min solve attempts before racing activates as escalation",
    )


class BudgetConfig(BaseSettings):
    """Resource and time budgets."""

    model_config = {"env_prefix": "KRAKEN_"}

    max_steps: int = Field(default=600, description="Max graph iterations")
    timeout_minutes: int = Field(default=30, description="Wall clock timeout")
    max_strategies: int = Field(default=5, description="Max distinct strategies before giving up")
    max_self_corrections: int = Field(default=3, description="Max solve_engine retries before escalating")
    max_solve_attempts: int = Field(
        default=20,
        description="Hard cap on total solve_engine script executions before give_up",
    )


class ContextConfig(BaseSettings):
    """Context management parameters."""

    model_config = {"env_prefix": "KRAKEN_CTX_"}

    full_fidelity_window: int = 10
    summarization_batch_size: int = 15
    max_summary_tokens: int = 4000
    total_context_budget: int = 24000


class DockerConfig(BaseSettings):
    """Docker / container settings."""

    model_config = {"env_prefix": "KRAKEN_DOCKER_"}

    image: str = "kraken:latest"
    tool_timeout: int = Field(default=30, description="Tool execution timeout in seconds")
    ghidra_install_dir: str = "/opt/ghidra"
    network_mode: str = "bridge"


class CheckpointerConfig(BaseSettings):
    """Checkpointer selection."""

    model_config = {"env_prefix": "KRAKEN_"}

    checkpointer: str = Field(
        default="memory",
        description="memory | sqlite | postgres",
    )
    sqlite_path: str = "kraken_checkpoints.db"
    postgres_uri: str = ""


class RuntimeConfig(BaseSettings):
    """Execution runtime selection (independent from model backend)."""

    model_config = {"env_prefix": "KRAKEN_RUNTIME_"}

    provider: str = Field(
        default="claude_code",
        description="Execution runtime provider: 'claude_code', 'local', or 'kraken'",
    )
    workspace: str = Field(
        default=".",
        description="Workspace directory for session/metrics storage",
    )
    auto_discover_models: bool = Field(
        default=True,
        description="Auto-discover Ollama models at startup (kraken runtime only)",
    )
    session_persistence: bool = Field(
        default=True,
        description="Enable session save/restore across restarts",
    )
    project_context: bool = Field(
        default=True,
        description="Enable KRAKEN.md project context accumulation",
    )
    metrics_dir: str = Field(
        default="",
        description="Directory for metrics output (default: {workspace}/.kraken/metrics)",
    )


class EvolutionConfig(BaseSettings):
    """Feature flags for architectural evolution phases."""

    model_config = {"env_prefix": "KRAKEN_EVO_"}

    # Phase 1: Artifact Store
    enable_artifact_store: bool = Field(default=True, description="Decouple large artifacts from state via handle pattern")
    # Phase 4: Schema Validation (debug only)
    enable_schema_validation: bool = Field(default=False, description="Warn when nodes access fields outside their schema")
    # Phase 5: Specialist Subgraphs
    enable_subgraphs: bool = Field(default=True, description="Use isolated LangGraph subgraphs for specialists")
    # Phase 6: Parallel Specialists
    enable_parallel_specialists: bool = Field(default=True, description="Fan-out multiple specialists in parallel")
    # Phase 7: Recursive Delegation
    enable_delegation: bool = Field(default=True, description="Allow solve_engine to spawn scoped sub-agents")


class KrakenConfig(BaseSettings):
    """Top-level config aggregating all sub-configs."""

    model_config = {"env_prefix": "KRAKEN_"}

    models: ModelConfig = Field(default_factory=ModelConfig)
    budget: BudgetConfig = Field(default_factory=BudgetConfig)
    context: ContextConfig = Field(default_factory=ContextConfig)
    docker: DockerConfig = Field(default_factory=DockerConfig)
    runtime: RuntimeConfig = Field(default_factory=RuntimeConfig)
    checkpointer: CheckpointerConfig = Field(default_factory=CheckpointerConfig)
    evolution: EvolutionConfig = Field(default_factory=EvolutionConfig)

    # Challenge defaults
    default_flag_format: str = r"flag\{[a-zA-Z0-9_]+\}"
