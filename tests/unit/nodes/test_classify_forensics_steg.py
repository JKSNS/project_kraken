"""Tests for forensics and steg heuristic classification."""
from __future__ import annotations

import pytest

from kraken.nodes.classify import _heuristic_classify, ClassificationResult


class TestForensicsClassification:
    def test_pcap_keywords(self):
        state = {
            "decompiled_functions": {},
            "strings_of_interest": ["pcap wireshark capture"],
            "binary_info": {},
            "challenge_files": {},
        }
        result = _heuristic_classify(state)
        assert result.challenge_type == "forensics"

    def test_pcap_file_boost(self):
        state = {
            "decompiled_functions": {},
            "strings_of_interest": [],
            "binary_info": {},
            "challenge_files": {"traffic.pcap": {"path": "/tmp/traffic.pcap", "type": "network capture (PCAP)"}},
        }
        result = _heuristic_classify(state)
        assert result.challenge_type == "forensics"

    def test_pcapng_file_boost(self):
        state = {
            "decompiled_functions": {},
            "strings_of_interest": [],
            "binary_info": {},
            "challenge_files": {"capture.pcapng": {"path": "/tmp/capture.pcapng"}},
        }
        result = _heuristic_classify(state)
        assert result.challenge_type == "forensics"

    def test_memory_forensics(self):
        state = {
            "decompiled_functions": {},
            "strings_of_interest": ["memory forensic volatility disk"],
            "binary_info": {},
            "challenge_files": {},
        }
        result = _heuristic_classify(state)
        assert result.challenge_type == "forensics"


class TestStegClassification:
    def test_steg_keywords(self):
        state = {
            "decompiled_functions": {},
            "strings_of_interest": ["steganography hidden lsb pixel"],
            "binary_info": {},
            "challenge_files": {},
        }
        result = _heuristic_classify(state)
        assert result.challenge_type == "steg"

    def test_image_file_boost(self):
        state = {
            "decompiled_functions": {},
            "strings_of_interest": ["hidden"],
            "binary_info": {},
            "challenge_files": {"secret.png": {"path": "/tmp/secret.png"}},
        }
        result = _heuristic_classify(state)
        assert result.challenge_type == "steg"

    def test_steg_in_classification_result_literal(self):
        """Verify steg is a valid classification type."""
        result = ClassificationResult(
            challenge_type="steg",
            confidence=0.9,
            reasoning="test",
            key_indicators=["lsb"],
        )
        assert result.challenge_type == "steg"

    def test_forensics_in_classification_result_literal(self):
        """Verify forensics is a valid classification type."""
        result = ClassificationResult(
            challenge_type="forensics",
            confidence=0.9,
            reasoning="test",
            key_indicators=["pcap"],
        )
        assert result.challenge_type == "forensics"
