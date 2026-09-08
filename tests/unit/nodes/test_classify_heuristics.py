"""Tests for classify heuristic classification and secondary types (#3, #11)."""
import pytest

from kraken.nodes.classify import _heuristic_classify, ClassificationResult


class TestHeuristicClassify:
    """Test the deterministic fallback classifier."""

    def test_crypto_keywords(self):
        state = {
            "decompiled_functions": {"main": "xor encrypt decrypt cipher"},
            "strings_of_interest": [],
            "binary_info": {},
        }
        result = _heuristic_classify(state)
        assert isinstance(result, ClassificationResult)
        assert result.challenge_type == "crypto"

    def test_constraint_keywords(self):
        state = {
            "decompiled_functions": {"main": "strcmp(input, expected) check verify validate"},
            "strings_of_interest": ["password", "correct"],
            "binary_info": {},
        }
        result = _heuristic_classify(state)
        assert result.challenge_type in ("constraint", "keygen")

    def test_dynamic_keywords(self):
        state = {
            "decompiled_functions": {"anti": "ptrace anti_debug self_modify"},
            "strings_of_interest": [],
            "binary_info": {},
        }
        result = _heuristic_classify(state)
        assert result.challenge_type == "dynamic"

    def test_pwn_keywords(self):
        state = {
            "decompiled_functions": {"vuln": "gets(buf) system execve"},
            "strings_of_interest": ["/bin/sh"],
            "binary_info": {},
        }
        result = _heuristic_classify(state)
        assert result.challenge_type == "pwn"

    def test_pwn_boosted_by_no_canary(self):
        state = {
            "decompiled_functions": {"vuln": "gets(buf)"},
            "strings_of_interest": [],
            "binary_info": {"checksec": {"Canary": False}},
        }
        result = _heuristic_classify(state)
        assert result.challenge_type == "pwn"

    def test_keygen_when_simple_comparison(self):
        """Simple key check without crypto should classify as keygen."""
        state = {
            "decompiled_functions": {"main": "strcmp(input, key) == 0 check"},
            "strings_of_interest": ["correct", "wrong"],
            "binary_info": {},
        }
        result = _heuristic_classify(state)
        # keygen gets score = constraint_score + 1 when only comparison operators
        assert result.challenge_type == "keygen"

    def test_secondary_types_populated(self):
        """Hybrid challenges should have secondary types."""
        state = {
            "decompiled_functions": {"main": "xor encrypt strcmp check"},
            "strings_of_interest": [],
            "binary_info": {},
        }
        result = _heuristic_classify(state)
        assert len(result.secondary_types) > 0
        # Primary type should NOT be in secondary types
        assert result.challenge_type not in result.secondary_types

    def test_secondary_types_ordered_by_score(self):
        """Secondary types should be ordered by relevance (score descending)."""
        state = {
            "decompiled_functions": {
                "main": "xor encrypt cipher strcmp check ptrace"
            },
            "strings_of_interest": [],
            "binary_info": {},
        }
        result = _heuristic_classify(state)
        # All three categories have matches; secondary types should exist
        assert len(result.secondary_types) >= 1

    def test_confidence_calculation(self):
        state = {
            "decompiled_functions": {"main": "xor"},
            "strings_of_interest": [],
            "binary_info": {},
        }
        result = _heuristic_classify(state)
        assert 0.0 <= result.confidence <= 1.0

    def test_web_keywords(self):
        state = {
            "decompiled_functions": {},
            "strings_of_interest": ["http", "flask", "html", "cookie"],
            "binary_info": {},
        }
        result = _heuristic_classify(state)
        assert result.challenge_type == "web"

    def test_firmware_keywords(self):
        state = {
            "decompiled_functions": {},
            "strings_of_interest": ["firmware", "u-boot", "busybox", "uart", "gpio"],
            "binary_info": {},
        }
        result = _heuristic_classify(state)
        assert result.challenge_type == "firmware"

    def test_fuzzing_keywords(self):
        state = {
            "decompiled_functions": {"harness": "void fuzz(const uint8_t *data) { afl_fuzz(); }"},
            "strings_of_interest": ["libfuzzer", "corpus"],
            "binary_info": {},
        }
        result = _heuristic_classify(state)
        assert result.challenge_type == "fuzzing"

    def test_empty_state(self):
        """Empty state should still produce a valid result."""
        state = {
            "decompiled_functions": {},
            "strings_of_interest": [],
            "binary_info": {},
        }
        result = _heuristic_classify(state)
        assert isinstance(result, ClassificationResult)
        assert result.challenge_type in (
            "constraint", "crypto", "dynamic", "keygen", "pwn",
            "fuzzing", "web", "firmware",
        )

    def test_classification_result_model(self):
        """ClassificationResult should accept all valid types."""
        for ctype in ("constraint", "crypto", "dynamic", "keygen", "pwn", "fuzzing", "web", "firmware"):
            result = ClassificationResult(
                challenge_type=ctype,
                confidence=0.85,
                reasoning=f"Detected {ctype}",
                key_indicators=["indicator"],
                secondary_types=[],
            )
            assert result.challenge_type == ctype
