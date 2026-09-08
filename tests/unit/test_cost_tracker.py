"""Unit tests for cost tracker (Ollama -- local, no monetary cost)."""
from kraken.logging.cost_tracker import CostTracker, UsageRecord


def test_empty_tracker():
    tracker = CostTracker()
    assert tracker.total_cost == 0.0
    assert tracker.check_budget() is True


def test_record_and_tokens():
    tracker = CostTracker()
    tracker.record("qwen2.5:7b", input_tokens=1000, output_tokens=100)
    assert tracker.total_cost == 0.0  # Ollama is free
    assert tracker.total_input_tokens == 1000
    assert tracker.total_output_tokens == 100


def test_budget_always_ok():
    tracker = CostTracker()
    tracker.record("qwen2.5:32b", input_tokens=100000, output_tokens=10000)
    assert tracker.check_budget() is True  # Local inference, always within budget


def test_summary():
    tracker = CostTracker()
    tracker.record("qwen2.5:14b", input_tokens=500, output_tokens=200)
    s = tracker.summary()
    assert s["total_cost_usd"] == 0.0
    assert s["num_calls"] == 1
    assert s["backend"] == "ollama (local)"
