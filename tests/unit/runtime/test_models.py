"""Tests for kraken.models -- extract_content, get_model, direct_generate, claude_generate, anthropic_generate."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from kraken.config import ModelConfig
from kraken.models import (
    _ANTHROPIC_MODEL_MAP,
    _extract_json_from_text,
    _ollama_fallback_allowed,
    _reset_ollama_endpoint_selection,
    _reset_ollama_fallback_state,
    _resolve_model_for_backend,
    _resolve_ollama_base_url,
    _strip_think_tags,
    _with_ollama_fallback_config,
    anthropic_generate,
    anthropic_structured_generate,
    claude_generate,
    claude_structured_generate,
    direct_generate,
    extract_content,
    get_model,
    ollama_generate,
    openai_generate,
    openai_structured_generate,
    structured_generate,
)

# ── extract_content ──────────────────────────────────────────────────


class TestExtractContent:
    """Test extract_content with various response shapes."""

    def test_plain_string(self):
        resp = MagicMock()
        resp.content = "Hello, world!"
        assert extract_content(resp) == "Hello, world!"

    def test_thinking_tags_strips(self):
        resp = MagicMock()
        resp.content = "<think>Let me reason...</think>\nprint('hello')"
        result = extract_content(resp)
        assert "<think>" not in result
        assert "print('hello')" in result

    def test_only_thinking_content_returned_when_no_answer(self):
        resp = MagicMock()
        resp.content = "<think>All reasoning, no answer</think>"
        result = extract_content(resp)
        assert "All reasoning, no answer" in result

    def test_unclosed_think_tag(self):
        resp = MagicMock()
        resp.content = "<think>partial thinking content"
        result = extract_content(resp)
        assert "partial thinking content" in result
        assert "<think>" not in result

    def test_empty_content_reasoning_in_additional_kwargs(self):
        resp = MagicMock()
        resp.content = ""
        resp.additional_kwargs = {"reasoning_content": "This is the reasoning"}
        result = extract_content(resp)
        assert result == "This is the reasoning"

    def test_empty_content_empty_kwargs(self):
        resp = MagicMock()
        resp.content = ""
        resp.additional_kwargs = {}
        result = extract_content(resp)
        assert result == ""

    def test_list_content_multimodal(self):
        resp = MagicMock()
        resp.content = [
            {"type": "text", "text": "Hello"},
            {"type": "text", "text": "World"},
        ]
        result = extract_content(resp)
        assert "Hello" in result
        assert "World" in result

    def test_list_content_with_strings(self):
        resp = MagicMock()
        resp.content = ["Part 1", "Part 2"]
        result = extract_content(resp)
        assert "Part 1" in result
        assert "Part 2" in result

    def test_none_content(self):
        resp = MagicMock()
        resp.content = None
        resp.additional_kwargs = {}
        result = extract_content(resp)
        assert result == ""

    def test_think_tags_in_reasoning_content(self):
        resp = MagicMock()
        resp.content = ""
        resp.additional_kwargs = {"reasoning_content": "<think>reasoning with tags</think>"}
        result = extract_content(resp)
        assert "reasoning with tags" in result
        assert "<think>" not in result


# ── _strip_think_tags ────────────────────────────────────────────────


class TestStripThinkTags:
    def test_no_tags(self):
        assert _strip_think_tags("hello world") == "hello world"

    def test_closed_tags_with_answer(self):
        result = _strip_think_tags("<think>reasoning</think>\nthe answer")
        assert result == "the answer"

    def test_closed_tags_no_answer(self):
        result = _strip_think_tags("<think>only reasoning</think>")
        assert "only reasoning" in result
        assert "<think>" not in result

    def test_unclosed_tag(self):
        result = _strip_think_tags("<think>partial")
        assert result == "partial"


# ── _extract_json_from_text ──────────────────────────────────────────


class TestExtractJson:
    def test_raw_json(self):
        assert _extract_json_from_text('{"key": "value"}') == {"key": "value"}

    def test_markdown_code_block(self):
        text = 'some text\n```json\n{"key": "value"}\n```\nmore text'
        assert _extract_json_from_text(text) == {"key": "value"}

    def test_embedded_json(self):
        text = 'Here is my answer: {"key": "value"} and that is it'
        assert _extract_json_from_text(text) == {"key": "value"}

    def test_no_json(self):
        assert _extract_json_from_text("no json here") is None


# ── get_model (Ollama) ───────────────────────────────────────────────


class TestGetModel:
    """Test get_model factory (Ollama backend)."""

    def test_reasoning_disabled(self):
        config = ModelConfig(backend="ollama", model_high="test-model")
        model = get_model("high", config)
        assert model.reasoning is False

    def test_num_predict_default(self):
        config = ModelConfig(backend="ollama", model_high="test-model")
        model = get_model("high", config)
        assert model.num_predict == 4096

    def test_num_predict_custom(self):
        config = ModelConfig(backend="ollama", model_high="test-model")
        model = get_model("high", config, num_predict=8192)
        assert model.num_predict == 8192

    def test_num_ctx_set(self):
        config = ModelConfig(backend="ollama", model_high="test-model")
        model = get_model("high", config)
        assert model.num_ctx == 131072

    def test_tier_model_selection(self):
        config = ModelConfig(
            backend="ollama",
            model_high="big-model",
            model_mid="mid-model",
            model_low="small-model",
        )
        assert get_model("high", config).model == "big-model"
        assert get_model("mid", config).model == "mid-model"
        assert get_model("low", config).model == "small-model"


# ── direct_generate dispatch ─────────────────────────────────────────


class TestDirectGenerate:
    """Test direct_generate dispatches to correct backend."""

    @pytest.mark.asyncio
    async def test_dispatch_to_ollama(self):
        """When backend=ollama, direct_generate calls ollama_generate."""
        config = ModelConfig(backend="ollama", model_high="test-model")

        mock_response = {
            "message": {"role": "assistant", "content": "ollama response"},
            "done": True,
            "done_reason": "stop",
            "eval_count": 10,
            "prompt_eval_count": 50,
        }
        mock_client = AsyncMock()
        mock_client.chat = AsyncMock(return_value=mock_response)

        with patch("ollama.AsyncClient", return_value=mock_client):
            result = await direct_generate("test", "high", config)

        assert "ollama response" in result

    @pytest.mark.asyncio
    async def test_ollama_continues_once_on_length(self):
        config = ModelConfig(backend="ollama", model_high="test-model")
        mock_client = AsyncMock()
        mock_client.chat = AsyncMock(
            side_effect=[
                {
                    "message": {"role": "assistant", "content": "part1"},
                    "done": True,
                    "done_reason": "length",
                    "eval_count": 10,
                    "prompt_eval_count": 50,
                },
                {
                    "message": {"role": "assistant", "content": "part2"},
                    "done": True,
                    "done_reason": "stop",
                    "eval_count": 8,
                    "prompt_eval_count": 20,
                },
            ]
        )

        with patch("ollama.AsyncClient", return_value=mock_client):
            result = await ollama_generate("test", "high", config)

        assert "part1" in result
        assert "part2" in result
        assert mock_client.chat.await_count == 2

    @pytest.mark.asyncio
    async def test_dispatch_to_claude(self):
        """When backend=claude, direct_generate calls claude_generate."""
        config = ModelConfig(backend="claude", model_high="sonnet")

        mock_data = {
            "type": "result",
            "is_error": False,
            "result": "claude response",
            "total_cost_usd": 0.01,
            "usage": {},
            "duration_ms": 500,
        }

        with patch("kraken.models._claude_generate", new_callable=AsyncMock, return_value=mock_data):
            result = await direct_generate("test", "high", config)

        assert result == "claude response"


# ── claude_generate ──────────────────────────────────────────────────


class TestClaudeGenerate:
    @pytest.mark.asyncio
    async def test_returns_result_field(self):
        config = ModelConfig(backend="claude", model_high="sonnet")
        mock_data = {
            "type": "result",
            "is_error": False,
            "result": "the answer",
            "total_cost_usd": 0.02,
            "usage": {"input_tokens": 10, "output_tokens": 5},
            "duration_ms": 800,
        }

        with patch("kraken.models._claude_generate", new_callable=AsyncMock, return_value=mock_data):
            result = await claude_generate("prompt", "high", config)

        assert result == "the answer"

    @pytest.mark.asyncio
    async def test_structured_returns_parsed_json(self):
        config = ModelConfig(backend="claude", model_high="sonnet")
        json_text = '{"challenge_type": "crypto", "reasoning": "XOR detected"}'

        schema = {"type": "object", "properties": {"challenge_type": {"type": "string"}}}
        with patch("kraken.models.claude_generate", new_callable=AsyncMock, return_value=json_text):
            result = await claude_structured_generate("prompt", "high", config, schema)

        assert result["challenge_type"] == "crypto"


# ── Anthropic SDK backend (#12) ─────────────────────────────────────


class TestAnthropicModelMap:
    """Test model alias mapping for Anthropic API."""

    def test_sonnet_alias(self):
        assert "sonnet" in _ANTHROPIC_MODEL_MAP
        assert "claude-sonnet" in _ANTHROPIC_MODEL_MAP["sonnet"]

    def test_haiku_alias(self):
        assert "haiku" in _ANTHROPIC_MODEL_MAP
        assert "claude-haiku" in _ANTHROPIC_MODEL_MAP["haiku"]

    def test_opus_alias(self):
        assert "opus" in _ANTHROPIC_MODEL_MAP
        assert "claude-opus" in _ANTHROPIC_MODEL_MAP["opus"]


class TestAnthropicGenerate:
    """Test Anthropic SDK text generation."""

    @pytest.mark.asyncio
    async def test_basic_generation(self):
        config = ModelConfig(backend="anthropic", model_high="sonnet")

        # Mock the Anthropic client
        mock_response = MagicMock()
        mock_block = MagicMock()
        mock_block.type = "text"
        mock_block.text = "anthropic response"
        mock_response.content = [mock_block]
        mock_response.usage = MagicMock(input_tokens=10, output_tokens=5)

        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(return_value=mock_response)

        with patch("kraken.models._get_anthropic_client", return_value=mock_client):
            result = await anthropic_generate("test prompt", "high", config)

        assert result == "anthropic response"
        mock_client.messages.create.assert_called_once()

    @pytest.mark.asyncio
    async def test_dispatch_to_anthropic(self):
        """direct_generate should dispatch to anthropic_generate when backend=anthropic."""
        config = ModelConfig(backend="anthropic", model_high="sonnet")

        mock_response = MagicMock()
        mock_block = MagicMock()
        mock_block.type = "text"
        mock_block.text = "from anthropic"
        mock_response.content = [mock_block]
        mock_response.usage = MagicMock(input_tokens=10, output_tokens=5)

        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(return_value=mock_response)

        with patch("kraken.models._get_anthropic_client", return_value=mock_client):
            result = await direct_generate("test", "high", config)

        assert result == "from anthropic"


class TestAnthropicStructuredGenerate:
    """Test Anthropic SDK structured output via tool_use."""

    @pytest.mark.asyncio
    async def test_structured_via_tool_use(self):
        config = ModelConfig(backend="anthropic", model_high="sonnet")

        mock_tool_block = MagicMock()
        mock_tool_block.type = "tool_use"
        mock_tool_block.name = "structured_output"
        mock_tool_block.input = {"challenge_type": "crypto", "confidence": 0.9}

        mock_response = MagicMock()
        mock_response.content = [mock_tool_block]
        mock_response.usage = MagicMock(input_tokens=10, output_tokens=5)

        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(return_value=mock_response)

        schema = {"type": "object", "properties": {"challenge_type": {"type": "string"}}}

        with patch("kraken.models._get_anthropic_client", return_value=mock_client):
            result = await anthropic_structured_generate("test", "high", config, schema)

        assert result["challenge_type"] == "crypto"
        assert result["confidence"] == 0.9

    @pytest.mark.asyncio
    async def test_structured_dispatch(self):
        """structured_generate should dispatch to anthropic when backend=anthropic."""
        config = ModelConfig(backend="anthropic", model_high="sonnet")

        mock_tool_block = MagicMock()
        mock_tool_block.type = "tool_use"
        mock_tool_block.name = "structured_output"
        mock_tool_block.input = {"key": "value"}

        mock_response = MagicMock()
        mock_response.content = [mock_tool_block]
        mock_response.usage = MagicMock(input_tokens=10, output_tokens=5)

        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(return_value=mock_response)

        schema = {"type": "object", "properties": {"key": {"type": "string"}}}

        with patch("kraken.models._get_anthropic_client", return_value=mock_client):
            result = await structured_generate("test", "high", config, schema)

        assert result["key"] == "value"


class TestOpenAIGenerate:
    """Test OpenAI backend generation and dispatch."""

    @pytest.mark.asyncio
    async def test_basic_generation(self):
        config = ModelConfig(backend="openai", model_high="gpt-5")

        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = "openai response"
        mock_response.choices = [mock_choice]
        mock_response.usage = MagicMock(prompt_tokens=11, completion_tokens=7)

        mock_client = AsyncMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)

        with patch("kraken.models._get_openai_client", return_value=mock_client):
            result = await openai_generate("test prompt", "high", config)

        assert result == "openai response"
        mock_client.chat.completions.create.assert_called_once()

    @pytest.mark.asyncio
    async def test_dispatch_to_openai(self):
        config = ModelConfig(backend="openai", model_high="gpt-5")

        with patch("kraken.models.openai_generate", new_callable=AsyncMock, return_value="from openai"):
            result = await direct_generate("test", "high", config)

        assert result == "from openai"


class TestOpenAIStructuredGenerate:
    """Test OpenAI backend structured output."""

    @pytest.mark.asyncio
    async def test_structured_generation_parses_json(self):
        config = ModelConfig(backend="openai", model_high="gpt-5")
        schema = {"type": "object", "properties": {"challenge_type": {"type": "string"}}}

        with patch("kraken.models.openai_generate", new_callable=AsyncMock, return_value='{"challenge_type":"crypto"}'):
            result = await openai_structured_generate("prompt", "high", config, schema)

        assert result["challenge_type"] == "crypto"

    @pytest.mark.asyncio
    async def test_structured_dispatch(self):
        config = ModelConfig(backend="openai", model_high="gpt-5")
        schema = {"type": "object", "properties": {"key": {"type": "string"}}}

        with patch("kraken.models.openai_structured_generate", new_callable=AsyncMock, return_value={"key": "value"}):
            result = await structured_generate("test", "high", config, schema)

        assert result["key"] == "value"


class TestOllamaEndpointResolution:
    def setup_method(self):
        _reset_ollama_endpoint_selection()

    def test_prefers_host_docker_internal_then_caches(self, monkeypatch):
        monkeypatch.setenv("KRAKEN_OLLAMA_BASE_URL", "http://localhost:11434")
        calls = []

        def fake_probe(url: str, timeout_s: float = 1.5) -> bool:
            calls.append(url)
            return url == "http://host.docker.internal:11434"

        monkeypatch.setattr("kraken.models._probe_ollama_base_url", fake_probe)

        cfg = ModelConfig(backend="ollama", model_high="glm-4.7-flash")
        selected1 = _resolve_ollama_base_url(cfg)
        selected2 = _resolve_ollama_base_url(cfg)

        assert selected1 == "http://host.docker.internal:11434"
        assert selected2 == "http://host.docker.internal:11434"
        assert calls.count("http://host.docker.internal:11434") == 1

    def test_raises_when_no_endpoint_works(self, monkeypatch):
        monkeypatch.setattr("kraken.models._probe_ollama_base_url", lambda *_a, **_k: False)
        cfg = ModelConfig(backend="ollama", model_high="glm-4.7-flash")

        with pytest.raises(RuntimeError, match="Failed to connect to Ollama"):
            _resolve_ollama_base_url(cfg)


class TestModelConfigOllamaBaseUrl:
    def test_model_config_uses_anthropic_base_url_for_ollama_default(self, monkeypatch):
        monkeypatch.delenv("KRAKEN_OLLAMA_BASE_URL", raising=False)
        monkeypatch.delenv("OLLAMA_HOST", raising=False)
        monkeypatch.setenv("ANTHROPIC_BASE_URL", "http://host.docker.internal:11434")

        cfg = ModelConfig(backend="ollama", model_high="glm-4.7-flash")

        assert cfg.ollama_base_url == "http://host.docker.internal:11434"


class TestOllamaFallbackConfig:
    def test_uses_anthropic_base_url_when_kraken_ollama_url_missing(self, monkeypatch):
        monkeypatch.delenv("KRAKEN_OLLAMA_BASE_URL", raising=False)
        monkeypatch.delenv("OLLAMA_HOST", raising=False)
        monkeypatch.setenv("ANTHROPIC_BASE_URL", "http://host.docker.internal:11434")

        cfg = ModelConfig(backend="claude", model_high="sonnet-4.6")
        fallback = _with_ollama_fallback_config(cfg)

        assert fallback.ollama_base_url == "http://host.docker.internal:11434"


class TestModelAliasResolution:
    def test_claude_sonnet_46_alias(self):
        assert _resolve_model_for_backend("sonnet-4.6", "claude") == "sonnet"


class TestClaudeFallbackToOllama:
    def setup_method(self):
        # Reset process-local breaker for deterministic tests
        _reset_ollama_fallback_state()

    @pytest.mark.asyncio
    async def test_direct_generate_falls_back_to_ollama_on_model_access_error(self):
        config = ModelConfig(backend="claude", model_high="sonnet-4.6")
        claude_error = RuntimeError(
            "There's an issue with the selected model (claude-sonnet-4-6). It may not exist or you may not have access to it."
        )

        mock_response = {
            "message": {"role": "assistant", "content": "ollama fallback response"},
            "done": True,
            "done_reason": "stop",
            "eval_count": 10,
            "prompt_eval_count": 50,
        }
        mock_client = AsyncMock()
        mock_client.chat = AsyncMock(return_value=mock_response)

        with patch("kraken.models._claude_generate", new_callable=AsyncMock, side_effect=claude_error):
            with patch("ollama.AsyncClient", return_value=mock_client):
                # Pin the Ollama endpoint so the fallback path is hermetic:
                # no live network probe, no dependence on test-collection order.
                with patch("kraken.models._resolve_ollama_base_url", return_value="http://localhost:11434"):
                    result = await direct_generate("test", "high", config)

        assert "ollama fallback response" in result

    @pytest.mark.asyncio
    async def test_direct_generate_disables_fallback_after_ollama_connect_error(self):
        config = ModelConfig(backend="claude", model_high="sonnet-4.6")
        claude_error = RuntimeError("authentication error: token expired")
        ollama_error = RuntimeError("Failed to connect to Ollama. Please check that Ollama is downloaded")

        with patch("kraken.models._claude_generate", new_callable=AsyncMock, side_effect=claude_error):
            with patch("kraken.models.ollama_generate", new_callable=AsyncMock, side_effect=ollama_error):
                with pytest.raises(RuntimeError, match="fallback also failed"):
                    await direct_generate("test", "high", config)

        assert _ollama_fallback_allowed() is False
