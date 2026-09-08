"""LLM model factory -- 3-tier strategy with pluggable backends.

Backends:
  - ``claude``: Calls the ``claude`` CLI via subprocess (``claude -p``).
    Uses the user's Max subscription -- no API key required.
  - ``anthropic``: Uses the Anthropic Python SDK directly (#12).
    Requires ANTHROPIC_API_KEY env var. Better connection pooling, native async.
  - ``openai``: Uses the OpenAI Python SDK (Chat Completions API).
  - ``ollama``: Calls local Ollama server directly or via langchain-ollama.

Primary interface:
  - ``direct_generate(prompt, tier, config)`` → str
    Works with all backends.  Preferred path for all nodes.

  - ``structured_generate(prompt, tier, config, json_schema)`` → dict
    Returns validated JSON.  Uses ``--json-schema`` on Claude backend,
    ``with_structured_output()`` on Ollama backend.

  - ``get_model(tier, config)`` → ChatOllama
    LangChain-compatible model (Ollama only, kept for backward compat).
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import urllib.request
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from kraken.config import ModelConfig

from kraken.logging.structured import get_logger

log = get_logger(__name__)

_TIER_MAP = {
    "high": ("model_high", "temperature_high"),
    "mid": ("model_mid", "temperature_mid"),
    "low": ("model_low", "temperature_low"),
}


# Backend-specific aliases to keep defaults ergonomic
_CLAUDE_MODEL_MAP = {
    "sonnet-4.6": "sonnet",
    "sonnet": "sonnet",
    "haiku": "haiku",
    "opus": "opus",
    "opus-4.6": "opus",
}

_OLLAMA_TIER_DEFAULTS = {
    "high": "gpt-oss-20b-131k:latest",
    "mid": "gpt-oss-20b-131k:latest",
    "low": "gpt-oss-20b-131k:latest",
}

_OLLAMA_FALLBACK_ALIAS = {
    "sonnet": "gpt-oss-20b-131k:latest",
    "sonnet-4.6": "gpt-oss-20b-131k:latest",
    "haiku": "gpt-oss-20b-131k:latest",
    "opus": "gpt-oss-20b-131k:latest",
    "opus-4.6": "gpt-oss-20b-131k:latest",
}

_OLLAMA_FALLBACK_DISABLED_REASON: str | None = None
_OLLAMA_SELECTED_BASE_URL: str | None = None



def _resolve_model_for_backend(model: str, backend: str) -> str:
    """Resolve friendly model aliases into backend-specific identifiers."""
    m = (model or "").strip()
    if backend == "claude":
        return _CLAUDE_MODEL_MAP.get(m, m)
    if backend == "anthropic":
        return _ANTHROPIC_MODEL_MAP.get(m, m)
    return m


def _with_ollama_fallback_config(config: "ModelConfig") -> "ModelConfig":
    """Create an Ollama config fallback using tiered model defaults.

    Tier-aware: maps high/mid/low to appropriate Ollama models instead
    of routing everything to a single model.  Falls back to the alias
    map and then to env var default.

    Supports legacy Ollama-via-Anthropic proxy setups by honoring
    ``ANTHROPIC_BASE_URL`` when ``KRAKEN_OLLAMA_BASE_URL`` is not set.
    """
    fallback_default = os.environ.get("KRAKEN_OLLAMA_FALLBACK_MODEL", "glm-4.7-flash-256k:latest")

    def _pick(name: str, tier: str = "") -> str:
        # 1) Check tier defaults first
        if tier and tier in _OLLAMA_TIER_DEFAULTS:
            return _OLLAMA_TIER_DEFAULTS[tier]
        # 2) Then alias map
        if name and name in _OLLAMA_FALLBACK_ALIAS:
            return _OLLAMA_FALLBACK_ALIAS[name]
        # 3) Then env fallback
        return name or fallback_default

    fallback_base_url = (
        os.environ.get("KRAKEN_OLLAMA_BASE_URL")
        or os.environ.get("OLLAMA_HOST")
        or os.environ.get("ANTHROPIC_BASE_URL")
        or config.ollama_base_url
    )

    return config.model_copy(update={
        "backend": "ollama",
        "model_high": _pick(config.model_high, "high"),
        "model_mid": _pick(config.model_mid, "mid"),
        "model_low": _pick(config.model_low, "low"),
        "ollama_base_url": fallback_base_url,
    })




def _probe_ollama_base_url(base_url: str, timeout_s: float = 1.5) -> bool:
    """Return True when Ollama endpoint responds successfully to /api/tags."""
    url = f"{base_url.rstrip('/')}/api/tags"
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return 200 <= getattr(resp, "status", 0) < 300
    except Exception:
        return False


def _resolve_ollama_base_url(config: "ModelConfig") -> str:
    """Resolve and cache a working Ollama endpoint for this process run."""
    global _OLLAMA_SELECTED_BASE_URL
    if _OLLAMA_SELECTED_BASE_URL:
        return _OLLAMA_SELECTED_BASE_URL

    candidates = [
        os.environ.get("KRAKEN_OLLAMA_BASE_URL"),
        "http://host.docker.internal:11434",
        "http://localhost:11434",
        config.ollama_base_url,
        os.environ.get("OLLAMA_HOST"),
        os.environ.get("ANTHROPIC_BASE_URL"),
    ]
    seen: set[str] = set()
    ordered: list[str] = []
    for raw in candidates:
        norm = (raw or "").rstrip("/")
        if not norm or norm in seen:
            continue
        seen.add(norm)
        ordered.append(norm)

    for candidate in ordered:
        if _probe_ollama_base_url(candidate):
            _OLLAMA_SELECTED_BASE_URL = candidate
            os.environ["KRAKEN_OLLAMA_BASE_URL"] = candidate
            log.info("ollama_endpoint_selected", endpoint=candidate)
            return candidate

    raise RuntimeError(
        "Failed to connect to Ollama. Checked host.docker.internal:11434 and localhost:11434. "
        "Please ensure Ollama is running and reachable."
    )


def _reset_ollama_endpoint_selection() -> None:
    """Reset process-local selected Ollama endpoint (primarily for tests)."""
    global _OLLAMA_SELECTED_BASE_URL
    _OLLAMA_SELECTED_BASE_URL = None

def _should_fallback_to_ollama(exc: Exception) -> bool:
    """Detect provider/model-access failures where Ollama fallback should activate."""
    if str(os.environ.get("KRAKEN_OLLAMA_AUTO_FALLBACK", "1")).lower() in {"0", "false", "no"}:
        return False
    msg = str(exc).lower()
    needles = [
        "selected model",
        "may not exist",
        "do not have access",
        "you may not have access",
        "api key",
        "authentication",
        "unauthorized",
    ]
    return any(n in msg for n in needles)


def _is_ollama_connectivity_error(exc: Exception) -> bool:
    """Detect Ollama connectivity errors that should disable further fallback attempts."""
    msg = str(exc).lower()
    needles = [
        "failed to connect to ollama",
        "connection refused",
        "cannot connect",
        "connect error",
    ]
    return any(n in msg for n in needles)


def _ollama_fallback_allowed() -> bool:
    """Return whether Claude→Ollama fallback is currently allowed in this process."""
    return _OLLAMA_FALLBACK_DISABLED_REASON is None


def _disable_ollama_fallback(reason: str) -> None:
    """Disable Claude→Ollama fallback for subsequent calls after connection failure."""
    global _OLLAMA_FALLBACK_DISABLED_REASON
    _OLLAMA_FALLBACK_DISABLED_REASON = reason


def _reset_ollama_fallback_state() -> None:
    """Reset process-local fallback disable state (primarily for tests)."""
    global _OLLAMA_FALLBACK_DISABLED_REASON
    _OLLAMA_FALLBACK_DISABLED_REASON = None


def _ollama_fallback_disabled_reason() -> str:
    """Return the reason fallback is disabled (empty string when enabled)."""
    return _OLLAMA_FALLBACK_DISABLED_REASON or ""


# ── Claude CLI backend ───────────────────────────────────────────────


async def _claude_generate(
    prompt: str,
    model: str,
    *,
    system_prompt: str = "",
    timeout_seconds: int | None = None,
    retries: int = 1,
) -> dict:
    """Call ``claude -p`` as an async subprocess.

    Returns the raw parsed JSON response from the CLI.
    Must unset CLAUDECODE env var to avoid nested-session error.
    timeout_seconds=None means no timeout -- let the CLI run as long as it needs.
    Retries non-timeout failures (rate limits, exit code 1) up to *retries* times.
    Timeouts are never retried -- they fail fast to let the graph handle it.
    """
    cmd = [
        "claude", "-p", prompt,
        "--output-format", "json",
        "--no-session-persistence",
        "--dangerously-skip-permissions",
        "--max-turns", "1",
        "--tools", "",
        "--model", model,
    ]
    if system_prompt:
        cmd += ["--system-prompt", system_prompt]

    # Strip CLAUDECODE to avoid nested-session block
    env = {k: v for k, v in os.environ.items() if k != "CLAUDECODE"}

    last_error: RuntimeError | None = None
    for attempt in range(1 + retries):
        if attempt > 0:
            delay = 3
            log.info("claude_cli_retry", attempt=attempt, delay=delay, model=model)
            await asyncio.sleep(delay)

        log.debug("claude_cli_exec", model=model, timeout=timeout_seconds, attempt=attempt)

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        try:
            if timeout_seconds is None:
                stdout_bytes, stderr_bytes = await proc.communicate()
            else:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout_seconds,
                )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            # Never retry timeouts -- fail fast
            raise RuntimeError(
                f"claude CLI timed out after {timeout_seconds}s (model={model})"
            )

        stdout_text = stdout_bytes.decode(errors="replace")
        stderr_text = stderr_bytes.decode(errors="replace")

        if proc.returncode != 0:
            # Claude CLI may put errors in stdout (JSON) or stderr
            detail = stderr_text.strip() or stdout_text.strip()
            log.warning(
                "claude_cli_failed",
                returncode=proc.returncode,
                attempt=attempt,
                stderr=stderr_text[:300],
                stdout=stdout_text[:300],
            )
            last_error = RuntimeError(
                f"claude CLI exited {proc.returncode}: {detail[:500]}"
            )
            continue

        data = json.loads(stdout_text)
        if data.get("is_error"):
            raise RuntimeError(f"claude returned error: {data.get('result', '')[:500]}")

        return data

    # All retries exhausted
    raise last_error or RuntimeError("claude CLI failed after all retries")


async def claude_generate(
    prompt: str,
    tier: str,
    config: "ModelConfig",
    *,
    system_prompt: str = "",
) -> str:
    """Generate text using the Claude CLI. Returns content string."""
    model_attr, _ = _TIER_MAP[tier]
    model = _resolve_model_for_backend(getattr(config, model_attr), "claude")

    log.info("claude_generate_start", model=model, tier=tier, prompt_len=len(prompt))

    data = await _claude_generate(prompt, model, system_prompt=system_prompt)

    content = data.get("result", "")
    usage = data.get("usage", {})
    cost = data.get("total_cost_usd", 0)

    log.info(
        "claude_generate_complete",
        model=model,
        content_len=len(content),
        cost_usd=round(cost, 6),
        input_tokens=usage.get("input_tokens", 0),
        output_tokens=usage.get("output_tokens", 0),
        duration_ms=data.get("duration_ms", 0),
    )

    return content.strip()


async def claude_structured_generate(
    prompt: str,
    tier: str,
    config: "ModelConfig",
    json_schema: dict,
    *,
    system_prompt: str = "",
) -> dict:
    """Generate structured JSON using Claude CLI.

    Uses plain text generation + JSON extraction instead of --json-schema,
    which conflicts with --tools "" (disabling tools also disables schema
    enforcement, producing empty responses).
    """
    # Append schema hint to the prompt so Claude returns valid JSON
    schema_hint = (
        "\n\nYou MUST respond with a JSON object matching this schema. "
        "Output ONLY the JSON, no markdown fences, no explanation.\n"
        f"Schema: {json.dumps(json_schema, indent=2)}"
    )
    enriched_prompt = prompt + schema_hint

    # Use the plain generate path (no --json-schema flag)
    content = await claude_generate(enriched_prompt, tier, config, system_prompt=system_prompt)

    parsed = _extract_json_from_text(content)
    if parsed is not None:
        log.info("claude_structured_complete", tier=tier, keys=list(parsed.keys()))
        return parsed

    raise RuntimeError(f"Claude did not return valid JSON. Preview: {content[:300]}")


# ── Anthropic SDK backend (#12) ───────────────────────────────────────

# Model alias mapping for the Anthropic API
_ANTHROPIC_MODEL_MAP = {
    "sonnet": "claude-sonnet-4-20250514",
    "sonnet-4.6": "claude-sonnet-4-6-20250311",
    "haiku": "claude-haiku-4-5-20251001",
    "opus": "claude-opus-4-20250514",
    "opus-4.6": "claude-opus-4-6-20250311",
}

# Singleton client for connection pooling
_anthropic_client = None
_openai_client = None


def _get_anthropic_client():
    """Get or create a singleton Anthropic AsyncClient."""
    global _anthropic_client
    if _anthropic_client is None:
        try:
            import anthropic
            _anthropic_client = anthropic.AsyncAnthropic()
        except ImportError:
            raise RuntimeError("anthropic package not installed. Run: pip install anthropic")
    return _anthropic_client


async def anthropic_generate(
    prompt: str,
    tier: str,
    config: "ModelConfig",
    *,
    system_prompt: str = "",
    num_predict: int = 4096,
) -> str:
    """Generate text using the Anthropic Python SDK."""
    model_attr, temp_attr = _TIER_MAP[tier]
    model_alias = getattr(config, model_attr)
    model_id = _resolve_model_for_backend(model_alias, "anthropic")
    temperature = getattr(config, temp_attr)

    log.info("anthropic_generate_start", model=model_id, tier=tier, prompt_len=len(prompt))

    client = _get_anthropic_client()
    kwargs: dict = {
        "model": model_id,
        "max_tokens": num_predict,
        "temperature": temperature,
        "messages": [{"role": "user", "content": prompt}],
    }
    if system_prompt:
        kwargs["system"] = system_prompt

    response = await client.messages.create(**kwargs)

    content = ""
    for block in response.content:
        if block.type == "text":
            content += block.text

    usage = response.usage
    log.info(
        "anthropic_generate_complete",
        model=model_id,
        content_len=len(content),
        input_tokens=usage.input_tokens,
        output_tokens=usage.output_tokens,
    )

    return content.strip()


async def anthropic_structured_generate(
    prompt: str,
    tier: str,
    config: "ModelConfig",
    json_schema: dict,
    *,
    system_prompt: str = "",
) -> dict:
    """Generate structured JSON using the Anthropic SDK with tool_use."""
    model_attr, temp_attr = _TIER_MAP[tier]
    model_alias = getattr(config, model_attr)
    model_id = _resolve_model_for_backend(model_alias, "anthropic")
    temperature = getattr(config, temp_attr)

    log.info("anthropic_structured_start", model=model_id, tier=tier, prompt_len=len(prompt))

    client = _get_anthropic_client()

    # Use tool_use to enforce JSON schema
    tool_name = "structured_output"
    tools = [{
        "name": tool_name,
        "description": "Output structured data",
        "input_schema": json_schema,
    }]

    sys_prompt = system_prompt or "You must use the structured_output tool to respond."
    if "structured_output" not in sys_prompt:
        sys_prompt += " You must use the structured_output tool to respond."

    response = await client.messages.create(
        model=model_id,
        max_tokens=4096,
        temperature=temperature,
        system=sys_prompt,
        messages=[{"role": "user", "content": prompt}],
        tools=tools,
        tool_choice={"type": "tool", "name": tool_name},
    )

    # Extract tool_use block
    for block in response.content:
        if block.type == "tool_use" and block.name == tool_name:
            log.info("anthropic_structured_complete", model=model_id)
            return block.input

    # Fallback: try parsing text content as JSON
    for block in response.content:
        if block.type == "text":
            parsed = _extract_json_from_text(block.text)
            if parsed:
                return parsed

    raise RuntimeError("Anthropic SDK did not return structured output")


# ── OpenAI backend ───────────────────────────────────────────────────


def _get_openai_client():
    """Get or create a singleton OpenAI Async client."""
    global _openai_client
    if _openai_client is None:
        try:
            from openai import AsyncOpenAI
            _openai_client = AsyncOpenAI()
        except ImportError:
            raise RuntimeError("openai package not installed. Run: pip install openai")
    return _openai_client


async def openai_generate(
    prompt: str,
    tier: str,
    config: "ModelConfig",
    *,
    system_prompt: str = "",
    num_predict: int = 4096,
) -> str:
    """Generate text using OpenAI Chat Completions."""
    model_attr, temp_attr = _TIER_MAP[tier]
    model_name = getattr(config, model_attr)
    temperature = getattr(config, temp_attr)

    log.info("openai_generate_start", model=model_name, tier=tier, prompt_len=len(prompt))

    client = _get_openai_client()

    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})

    response = await client.chat.completions.create(
        model=model_name,
        messages=messages,
        temperature=temperature,
        max_tokens=num_predict,
    )

    content = (response.choices[0].message.content or "").strip()
    usage = getattr(response, "usage", None)
    input_tokens = getattr(usage, "prompt_tokens", 0) if usage else 0
    output_tokens = getattr(usage, "completion_tokens", 0) if usage else 0

    log.info(
        "openai_generate_complete",
        model=model_name,
        content_len=len(content),
        input_tokens=input_tokens,
        output_tokens=output_tokens,
    )

    return content


async def openai_structured_generate(
    prompt: str,
    tier: str,
    config: "ModelConfig",
    json_schema: dict,
    *,
    system_prompt: str = "",
) -> dict:
    """Generate structured JSON using OpenAI backend with prompt-enforced schema."""
    schema_hint = (
        "\n\nYou MUST respond with a JSON object matching this schema. "
        "Output ONLY the JSON, no markdown fences, no explanation.\n"
        f"Schema: {json.dumps(json_schema, indent=2)}"
    )
    content = await openai_generate(
        prompt + schema_hint,
        tier,
        config,
        system_prompt=system_prompt,
    )

    parsed = _extract_json_from_text(content)
    if parsed is not None:
        log.info("openai_structured_complete", tier=tier, keys=list(parsed.keys()))
        return parsed

    raise RuntimeError(f"OpenAI did not return valid JSON. Preview: {content[:300]}")


# ── Ollama backend ───────────────────────────────────────────────────


def get_model(
    tier: str,
    config: "ModelConfig",
    *,
    num_predict: int = 4096,
    callbacks: list | None = None,
):
    """Return a ChatOllama instance for LangChain use (Ollama backend only)."""
    from langchain_ollama import ChatOllama

    model_attr, temp_attr = _TIER_MAP[tier]
    resolved_base_url = _resolve_ollama_base_url(config)
    return ChatOllama(
        model=getattr(config, model_attr),
        temperature=getattr(config, temp_attr),
        num_predict=num_predict,
        num_ctx=config.num_ctx,
        base_url=resolved_base_url,
        callbacks=callbacks or [],
        reasoning=False,
        keep_alive="30m",
    )


async def ollama_generate(
    prompt: str,
    tier: str,
    config: "ModelConfig",
    *,
    num_predict: int = 4096,
    system_prompt: str = "",
) -> str:
    """Call Ollama directly, bypassing langchain-ollama."""
    from ollama import AsyncClient as _OllamaAsyncClient

    model_attr, temp_attr = _TIER_MAP[tier]
    model_name = getattr(config, model_attr)
    temperature = getattr(config, temp_attr)

    resolved_base_url = _resolve_ollama_base_url(config)
    client = _OllamaAsyncClient(host=resolved_base_url)

    log.info(
        "ollama_generate_start",
        model=model_name,
        prompt_len=len(prompt),
        num_predict=num_predict,
        num_ctx=config.num_ctx,
    )

    async def _chat(user_prompt: str, sys_prompt: str = ""):
        messages = []
        if sys_prompt:
            messages.append({"role": "system", "content": sys_prompt})
        messages.append({"role": "user", "content": user_prompt})
        return await client.chat(
            model=model_name,
            messages=messages,
            stream=False,
            think=False,
            keep_alive="30m",
            options={
                "temperature": temperature,
                "num_predict": num_predict,
                "num_ctx": config.num_ctx,
            },
        )

    try:
        response = await _chat(prompt, sys_prompt=system_prompt)
    except Exception as chat_exc:
        # Ollama sometimes misinterprets model output as a tool call and returns
        # HTTP 500 with "error parsing tool call: raw='<actual_content>'".
        # Extract the raw content and use it as the response.
        err_msg = str(chat_exc)
        raw_match = re.search(r"error parsing tool call: raw='(.*?)', err=", err_msg, re.DOTALL)
        if raw_match:
            extracted = raw_match.group(1)
            # Unescape common escape sequences from the error string
            extracted = extracted.replace("\\n", "\n").replace("\\t", "\t").replace("\\'", "'")
            log.warning("ollama_tool_call_parse_recovery", recovered_len=len(extracted))
            return extracted.strip()
        # Not the tool-call parse error -- re-raise
        raise

    # Extract content from the raw response
    content = ""
    msg = response.get("message", {})
    if isinstance(msg, dict):
        content = msg.get("content", "") or ""
    else:
        content = getattr(msg, "content", None) or ""

    # Check for thinking content if main content is empty
    if not content.strip():
        thinking = None
        if isinstance(msg, dict):
            thinking = msg.get("thinking", "")
        else:
            thinking = getattr(msg, "thinking", None)
        if thinking:
            content = re.sub(r"</?think>", "", str(thinking)).strip()

    eval_count = response.get("eval_count", 0)
    prompt_eval_count = response.get("prompt_eval_count", 0)
    done_reason = response.get("done_reason", "")
    total_duration = response.get("total_duration", 0)  # nanoseconds
    duration_ms = total_duration / 1_000_000 if total_duration else 0

    log.info(
        "ollama_generate_complete",
        content_len=len(content),
        eval_count=eval_count,
        prompt_eval_count=prompt_eval_count,
        done_reason=done_reason,
    )

    # Emit metrics if collector is active
    try:
        from kraken.runtime.metrics import get_metrics_collector
        collector = get_metrics_collector()
        if collector.session_id or collector.challenge_id:
            collector.record_llm_call(
                node="ollama_generate",
                tier=tier,
                model=model_name,
                prompt_tokens=prompt_eval_count,
                eval_tokens=eval_count,
                duration_ms=duration_ms,
            )
    except Exception:
        pass

    if not content.strip():
        log.warning(
            "ollama_generate_empty",
            eval_count=eval_count,
            prompt_eval_count=prompt_eval_count,
            done_reason=done_reason,
            msg_keys=list(msg.keys()) if isinstance(msg, dict) else dir(msg),
        )

    # Strip <think> tags if present (do this early so continuations don't re-send reasoning)
    content = _strip_think_tags(content).strip()

    # Auto-continue once for truncated long-form generations (e.g., solve scripts)
    if done_reason == "length" and tier == "high" and content:
        # Use only the last 4K chars for continuation context to avoid huge prompts
        tail = content[-4000:] if len(content) > 4000 else content
        cont_prompt = (
            "Continue EXACTLY from the prior response with no preamble and no repetition. "
            "Output only the remaining content.\n\n"
            "--- PRIOR PARTIAL OUTPUT (tail) ---\n"
            f"{tail}\n"
            "--- END ---"
        )
        log.info("ollama_generate_continue", model=model_name, prompt_len=len(cont_prompt), num_predict=num_predict)
        try:
            response2 = await _chat(cont_prompt)
        except Exception as cont_exc:
            raw_match = re.search(r"error parsing tool call: raw='(.*?)', err=", str(cont_exc), re.DOTALL)
            if raw_match:
                extracted = raw_match.group(1).replace("\\n", "\n").replace("\\t", "\t").replace("\\'", "'")
                log.warning("ollama_tool_call_parse_recovery_cont", recovered_len=len(extracted))
                content = f"{content}\n{extracted}".strip()
                return content
            log.warning("ollama_continue_failed", error=str(cont_exc)[:200])
            return content  # Return what we have so far
        msg2 = response2.get("message", {})
        content2 = msg2.get("content", "") if isinstance(msg2, dict) else getattr(msg2, "content", None) or ""
        content2 = _strip_think_tags(content2).strip()
        if content2:
            content = f"{content}\n{content2}".strip()

    return content


# ── Unified interface ────────────────────────────────────────────────


async def direct_generate(
    prompt: str,
    tier: str,
    config: "ModelConfig",
    *,
    num_predict: int = 4096,
    system_prompt: str = "",
) -> str:
    """Generate text using the configured backend.

    This is the primary interface -- all nodes should use this.
    Dispatches to Claude CLI or Ollama based on ``config.backend``.
    """
    if config.backend == "claude":
        try:
            return await claude_generate(prompt, tier, config, system_prompt=system_prompt)
        except Exception as exc:
            if _should_fallback_to_ollama(exc) and _ollama_fallback_allowed():
                fallback_cfg = _with_ollama_fallback_config(config)
                log.warning("claude_fallback_to_ollama", error=str(exc)[:200], tier=tier, model=getattr(config, _TIER_MAP[tier][0]))
                try:
                    return await ollama_generate(prompt, tier, fallback_cfg, num_predict=num_predict, system_prompt=system_prompt)
                except Exception as ollama_exc:
                    if _is_ollama_connectivity_error(ollama_exc):
                        reason = str(ollama_exc)[:300]
                        _disable_ollama_fallback(reason)
                        log.warning("ollama_fallback_disabled", reason=reason)
                    raise RuntimeError(
                        f"Claude generation failed and Ollama fallback also failed. "
                        f"claude_error={str(exc)[:220]} ollama_error={str(ollama_exc)[:220]}"
                    ) from ollama_exc
            if _should_fallback_to_ollama(exc) and not _ollama_fallback_allowed():
                raise RuntimeError(
                    f"Claude generation failed and Ollama fallback is disabled: {_ollama_fallback_disabled_reason()}. "
                    f"claude_error={str(exc)[:220]}"
                ) from exc
            raise
    elif config.backend == "anthropic":
        return await anthropic_generate(
            prompt, tier, config, system_prompt=system_prompt, num_predict=num_predict,
        )
    elif config.backend == "openai":
        return await openai_generate(
            prompt, tier, config, system_prompt=system_prompt, num_predict=num_predict,
        )
    else:
        return await ollama_generate(prompt, tier, config, num_predict=num_predict, system_prompt=system_prompt)


async def structured_generate(
    prompt: str,
    tier: str,
    config: "ModelConfig",
    json_schema: dict,
    *,
    system_prompt: str = "",
) -> dict:
    """Generate structured JSON using the configured backend.

    On Claude: uses ``--json-schema`` for guaranteed schema compliance.
    On Ollama: falls back to ``with_structured_output()`` then JSON parsing.
    """
    if config.backend == "claude":
        try:
            return await claude_structured_generate(
                prompt, tier, config, json_schema, system_prompt=system_prompt,
            )
        except Exception as exc:
            if _should_fallback_to_ollama(exc) and _ollama_fallback_allowed():
                fallback_cfg = _with_ollama_fallback_config(config)
                log.warning("claude_structured_fallback_to_ollama", error=str(exc)[:200], tier=tier)
                try:
                    raw = await ollama_generate(prompt, tier, fallback_cfg)
                except Exception as ollama_exc:
                    if _is_ollama_connectivity_error(ollama_exc):
                        reason = str(ollama_exc)[:300]
                        _disable_ollama_fallback(reason)
                        log.warning("ollama_structured_fallback_disabled", reason=reason)
                    raise RuntimeError(
                        f"Claude structured generation failed and Ollama fallback also failed. "
                        f"claude_error={str(exc)[:220]} ollama_error={str(ollama_exc)[:220]}"
                    ) from ollama_exc
                parsed = _extract_json_from_text(raw)
                if parsed is not None:
                    return parsed
            if _should_fallback_to_ollama(exc) and not _ollama_fallback_allowed():
                raise RuntimeError(
                    f"Claude structured generation failed and Ollama fallback is disabled: {_ollama_fallback_disabled_reason()}. "
                    f"claude_error={str(exc)[:220]}"
                ) from exc
            raise
    elif config.backend == "anthropic":
        return await anthropic_structured_generate(
            prompt, tier, config, json_schema, system_prompt=system_prompt,
        )
    elif config.backend == "openai":
        return await openai_structured_generate(
            prompt, tier, config, json_schema, system_prompt=system_prompt,
        )

    # Ollama fallback: direct_generate + JSON extraction
    raw = await ollama_generate(prompt, tier, config)
    parsed = _extract_json_from_text(raw)
    if parsed is not None:
        return parsed
    raise RuntimeError(f"Ollama did not return valid JSON. Preview: {raw[:300]}")


# ── Utilities ────────────────────────────────────────────────────────


def _strip_think_tags(content: str) -> str:
    """Remove <think>...</think> tags, keeping content after closing tag if present."""
    if "<think>" not in content:
        return content
    parts_split = content.split("</think>")
    if len(parts_split) > 1:
        after_think = parts_split[-1].strip()
        if after_think:
            return after_think
        return re.sub(r"</?think>", "", content).strip()
    return content.replace("<think>", "").strip()


def _extract_json_from_text(text: str) -> dict | None:
    """Extract JSON object from LLM response text."""
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    for pattern in [r"```json\s*\n?(.*?)\n?\s*```", r"```\s*\n?(.*?)\n?\s*```"]:
        match = re.search(pattern, text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1).strip())
            except json.JSONDecodeError:
                continue

    brace_start = text.find("{")
    if brace_start != -1:
        depth = 0
        for i in range(brace_start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[brace_start:i + 1])
                    except json.JSONDecodeError:
                        break
    return None


def extract_content(response: Any) -> str:
    """Extract usable text from a LangChain LLM response.

    Handles qwen3 thinking mode, multimodal list content, and
    empty-response fallbacks.
    """
    content: str = ""
    if hasattr(response, "content"):
        raw = response.content
    else:
        raw = str(response)

    if isinstance(raw, list):
        parts: list[str] = []
        for item in raw:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict) and "text" in item:
                parts.append(item["text"])
        content = "\n".join(parts)
    else:
        content = str(raw) if raw else ""

    content = _strip_think_tags(content)

    if not content.strip() and hasattr(response, "additional_kwargs"):
        ak = response.additional_kwargs or {}
        reasoning = (
            ak.get("reasoning_content", "")
            or ak.get("thinking_content", "")
            or ak.get("thinking", "")
        )
        if reasoning:
            reasoning_str = str(reasoning).strip()
            reasoning_str = re.sub(r"</?think>", "", reasoning_str).strip()
            content = reasoning_str

    return content.strip()
