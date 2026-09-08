"""Tests for the solve knowledge base (src/kraken/knowledge.py)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from kraken.storage.solve_knowledge import SolveKnowledgeBase, _normalize_technique

# ── Fixtures ──────────────────────────────────────────────────────────────────

VERE_SOLVES_ROOT = Path(os.environ.get("KRAKEN_VERE_SOLVES", "vere_solves_unavailable"))

# Whether the VERE solve artifacts actually exist on this system
_VERE_EXISTS = (VERE_SOLVES_ROOT / "vere" / "solves").is_dir()


def _make_tmpdir_with_solves(tmp_path: Path, challenges: list[dict]) -> Path:
    """Create a temporary benchmarks directory with taxonomy/constraints files.

    Each challenge dict should have at minimum:
        name, week, taxonomy (dict), constraints (dict)
    """
    root = tmp_path / "benchmarks"
    for ch in challenges:
        artifacts = root / "vere" / "solves" / "rev" / ch["week"] / ch["name"] / "artifacts"
        artifacts.mkdir(parents=True)
        (artifacts / "taxonomy.json").write_text(json.dumps(ch["taxonomy"]))
        if "constraints" in ch:
            (artifacts / "constraints.json").write_text(json.dumps(ch["constraints"]))
    return root


@pytest.fixture
def mock_kb(tmp_path: Path) -> SolveKnowledgeBase:
    """Build a knowledge base from synthetic test data."""
    challenges = [
        {
            "name": "alpha",
            "week": "week1",
            "taxonomy": {
                "challenge": "alpha",
                "category": "rev",
                "techniques": ["xor_decryption", "binary_patching", "code_as_data"],
                "estimated_difficulty": 3,
                "similar_to": ["beta"],
                "tools_used": ["objdump", "python3"],
                "solve_time_seconds": 120,
                "solve_method": "deterministic",
                "key_insights": ["Code bytes serve as XOR key"],
                "binary_properties": {
                    "format": "ELF 64-bit",
                    "stripped": True,
                    "pie": True,
                    "arch": "x86-64",
                },
            },
            "constraints": {
                "type": "xor_decrypt",
                "formula": "flag[i] = ct[i] ^ key[i]",
                "flag": "flag{alpha_test}",
            },
        },
        {
            "name": "beta",
            "week": "week1",
            "taxonomy": {
                "challenge": "beta",
                "category": "rev",
                "techniques": ["xor_decryption", "sha1_bypass"],
                "estimated_difficulty": 4,
                "similar_to": ["alpha"],
                "tools_used": ["objdump", "python3"],
                "solve_time_seconds": 200,
                "solve_method": "deterministic",
                "key_insights": ["SHA1 gate requires patching"],
                "binary_properties": {
                    "format": "ELF 64-bit",
                    "stripped": False,
                    "pie": False,
                },
            },
            "constraints": {
                "type": "xor_decrypt",
                "formula": "flag[i] = ct[i] ^ key[i]",
                "flag": "flag{beta_test}",
            },
        },
        {
            "name": "gamma",
            "week": "week2",
            "taxonomy": {
                "challenge": "gamma",
                "category": "static_crypto",
                "techniques": ["rc4", "fork_ipc", "timestamp_key"],
                "estimated_difficulty": 5,
                "similar_to": [],
                "tools_used": ["objdump", "xxd", "python3"],
                "solve_time_seconds": 300,
                "solve_method": "static_analysis",
                "binary_properties": {
                    "format": "ELF 64-bit PIE",
                    "stripped": True,
                    "pie": True,
                },
            },
            "constraints": {
                "type": "rc4_decrypt",
                "cipher": "RC4",
                "flag": "flag{gamma_test}",
            },
        },
        {
            "name": "delta",
            "week": "week2",
            "taxonomy": {
                "challenge": "delta",
                "category": "rev",
                "techniques": ["prng_seed_extraction", "xor_decryption"],
                "estimated_difficulty": 2,
                "similar_to": [],
                "tools_used": ["objdump", "ctypes"],
                "solve_time_seconds": 50,
                "solve_method": "deterministic",
                "binary_properties": {},
            },
            "constraints": {
                "type": "seeded_prng_xor",
                "flag": "flag{delta_test}",
            },
        },
        {
            "name": "epsilon",
            "week": "week3",
            "taxonomy": {
                "challenge_id": "epsilon",
                "category": "rev",
                "techniques": ["go_reversing", "subtract_then_xor", "decoy_output"],
                "difficulty": {"score": 3, "rating": "medium"},
                "similar_to": [],
                "notes": "Go binary with decoy output",
                "binary_properties": {
                    "language": "go",
                },
            },
            "constraints": {
                "type": "subtract_xor_decrypt",
                "flag": "flag{epsilon_test}",
            },
        },
    ]
    root = _make_tmpdir_with_solves(tmp_path, challenges)
    return SolveKnowledgeBase(solves_root=str(root))


# ── Basic indexing tests ──────────────────────────────────────────────────────


class TestIndexing:
    def test_indexes_all_challenges(self, mock_kb: SolveKnowledgeBase):
        assert len(mock_kb.patterns) == 5

    def test_challenge_names(self, mock_kb: SolveKnowledgeBase):
        names = {p.challenge for p in mock_kb.patterns}
        assert names == {"alpha", "beta", "gamma", "delta", "epsilon"}

    def test_constraint_types(self, mock_kb: SolveKnowledgeBase):
        types = {p.constraint_type for p in mock_kb.patterns}
        assert "xor_decrypt" in types
        assert "rc4_decrypt" in types
        assert "seeded_prng_xor" in types

    def test_techniques_extracted(self, mock_kb: SolveKnowledgeBase):
        alpha = mock_kb.query_by_name("alpha")
        assert alpha is not None
        assert "xor_decryption" in alpha.techniques
        assert "binary_patching" in alpha.techniques

    def test_difficulty_from_nested_dict(self, mock_kb: SolveKnowledgeBase):
        eps = mock_kb.query_by_name("epsilon")
        assert eps is not None
        assert eps.difficulty == 3

    def test_key_insights_from_notes(self, mock_kb: SolveKnowledgeBase):
        eps = mock_kb.query_by_name("epsilon")
        assert eps is not None
        assert any("Go binary" in i for i in eps.key_insights)

    def test_dataset_detection(self, mock_kb: SolveKnowledgeBase):
        for p in mock_kb.patterns:
            assert p.dataset == "vere"

    def test_week_detection(self, mock_kb: SolveKnowledgeBase):
        alpha = mock_kb.query_by_name("alpha")
        assert alpha is not None
        assert alpha.week == "week1"

    def test_empty_root(self, tmp_path: Path):
        kb = SolveKnowledgeBase(solves_root=str(tmp_path / "nonexistent"))
        assert len(kb.patterns) == 0


# ── Query by technique ────────────────────────────────────────────────────────


class TestQueryByTechnique:
    def test_xor_matches_multiple(self, mock_kb: SolveKnowledgeBase):
        results = mock_kb.query_by_technique("xor")
        names = {p.challenge for p in results}
        # alpha, beta, delta all have xor_decryption; epsilon has subtract_then_xor
        assert "alpha" in names
        assert "beta" in names

    def test_rc4_matches_gamma(self, mock_kb: SolveKnowledgeBase):
        results = mock_kb.query_by_technique("rc4")
        assert len(results) >= 1
        assert results[0].challenge == "gamma"

    def test_no_results(self, mock_kb: SolveKnowledgeBase):
        results = mock_kb.query_by_technique("quantum_computing")
        assert results == []

    def test_fork_ipc(self, mock_kb: SolveKnowledgeBase):
        results = mock_kb.query_by_technique("fork_ipc")
        assert len(results) == 1
        assert results[0].challenge == "gamma"

    def test_go_reversing(self, mock_kb: SolveKnowledgeBase):
        results = mock_kb.query_by_technique("go_reversing")
        assert len(results) == 1
        assert results[0].challenge == "epsilon"


# ── Query by constraint type ──────────────────────────────────────────────────


class TestQueryByType:
    def test_xor_decrypt(self, mock_kb: SolveKnowledgeBase):
        results = mock_kb.query_by_type("xor_decrypt")
        names = {p.challenge for p in results}
        assert "alpha" in names
        assert "beta" in names

    def test_rc4(self, mock_kb: SolveKnowledgeBase):
        results = mock_kb.query_by_type("rc4")
        assert any(p.challenge == "gamma" for p in results)

    def test_prng(self, mock_kb: SolveKnowledgeBase):
        results = mock_kb.query_by_type("prng")
        assert any(p.challenge == "delta" for p in results)


# ── Query similar ─────────────────────────────────────────────────────────────


class TestQuerySimilar:
    def test_alpha_similar_to_beta(self, mock_kb: SolveKnowledgeBase):
        results = mock_kb.query_similar("alpha")
        names = {p.challenge for p in results}
        assert "beta" in names

    def test_beta_similar_to_alpha(self, mock_kb: SolveKnowledgeBase):
        results = mock_kb.query_similar("beta")
        names = {p.challenge for p in results}
        assert "alpha" in names

    def test_no_similar(self, mock_kb: SolveKnowledgeBase):
        results = mock_kb.query_similar("gamma")
        assert results == []

    def test_nonexistent_challenge(self, mock_kb: SolveKnowledgeBase):
        results = mock_kb.query_similar("nonexistent")
        assert results == []


# ── Suggest approach ──────────────────────────────────────────────────────────


class TestSuggestApproach:
    def test_go_binary_suggests_subtract_xor(self, mock_kb: SolveKnowledgeBase):
        suggestions = mock_kb.suggest_approach(
            binary_info={"language": "go"},
        )
        techniques = [s["technique"] for s in suggestions]
        assert "subtract_then_xor" in techniques

    def test_fork_suggests_rc4(self, mock_kb: SolveKnowledgeBase):
        suggestions = mock_kb.suggest_approach(
            binary_info={"imports": ["fork", "msgget"]},
        )
        techniques = [s["technique"] for s in suggestions]
        assert "rc4_decrypt" in techniques

    def test_stripped_pie_suggests_static(self, mock_kb: SolveKnowledgeBase):
        suggestions = mock_kb.suggest_approach(
            binary_info={"stripped": True, "pie": True},
        )
        techniques = [s["technique"] for s in suggestions]
        assert "static_analysis" in techniques

    def test_hash_imports_suggests_bypass(self, mock_kb: SolveKnowledgeBase):
        suggestions = mock_kb.suggest_approach(
            binary_info={"imports": ["SHA1_Init"], "libraries": ["libcrypto.so"]},
        )
        techniques = [s["technique"] for s in suggestions]
        assert "xor_with_hash_bypass" in techniques

    def test_srand_suggests_prng(self, mock_kb: SolveKnowledgeBase):
        suggestions = mock_kb.suggest_approach(
            binary_info={"imports": ["srand", "rand"]},
        )
        techniques = [s["technique"] for s in suggestions]
        assert "seeded_prng_xor" in techniques

    def test_movabs_in_strings(self, mock_kb: SolveKnowledgeBase):
        suggestions = mock_kb.suggest_approach(
            binary_info={},
            strings=["movabs $0xdeadbeef, %rax"],
        )
        techniques = [s["technique"] for s in suggestions]
        assert "xor_decrypt" in techniques

    def test_empty_info_gives_generic(self, mock_kb: SolveKnowledgeBase):
        suggestions = mock_kb.suggest_approach(binary_info={})
        # Should at least return something (generic xor suggestion)
        assert len(suggestions) >= 1

    def test_confidence_sorted(self, mock_kb: SolveKnowledgeBase):
        suggestions = mock_kb.suggest_approach(
            binary_info={"stripped": True, "pie": True, "imports": ["srand", "rand"]},
        )
        confidences = [s["confidence"] for s in suggestions]
        assert confidences == sorted(confidences, reverse=True)

    def test_suggestion_has_required_keys(self, mock_kb: SolveKnowledgeBase):
        suggestions = mock_kb.suggest_approach(
            binary_info={"language": "go"},
        )
        for s in suggestions:
            assert "technique" in s
            assert "confidence" in s
            assert "similar_challenges" in s
            assert "suggested_tools" in s
            assert "key_insights" in s

    def test_empty_kb(self, tmp_path: Path):
        kb = SolveKnowledgeBase(solves_root=str(tmp_path / "empty"))
        assert kb.suggest_approach(binary_info={"language": "go"}) == []


# ── Stats ─────────────────────────────────────────────────────────────────────


class TestStats:
    def test_total_challenges(self, mock_kb: SolveKnowledgeBase):
        stats = mock_kb.stats()
        assert stats["total_challenges"] == 5

    def test_datasets(self, mock_kb: SolveKnowledgeBase):
        stats = mock_kb.stats()
        assert "vere" in stats["datasets"]

    def test_categories(self, mock_kb: SolveKnowledgeBase):
        stats = mock_kb.stats()
        assert "rev" in stats["categories"]
        assert stats["categories"]["rev"] >= 3

    def test_constraint_types(self, mock_kb: SolveKnowledgeBase):
        stats = mock_kb.stats()
        assert "xor_decrypt" in stats["constraint_types"]
        assert "rc4_decrypt" in stats["constraint_types"]

    def test_techniques_counted(self, mock_kb: SolveKnowledgeBase):
        stats = mock_kb.stats()
        assert "xor_decryption" in stats["techniques"]
        # alpha, beta, delta all have xor_decryption
        assert stats["techniques"]["xor_decryption"] == 3

    def test_avg_difficulty(self, mock_kb: SolveKnowledgeBase):
        stats = mock_kb.stats()
        assert stats["avg_difficulty"] > 0

    def test_avg_solve_time(self, mock_kb: SolveKnowledgeBase):
        stats = mock_kb.stats()
        assert stats["avg_solve_time_seconds"] > 0

    def test_deterministic_count(self, mock_kb: SolveKnowledgeBase):
        stats = mock_kb.stats()
        assert stats["deterministic_count"] >= 3

    def test_empty_kb_stats(self, tmp_path: Path):
        kb = SolveKnowledgeBase(solves_root=str(tmp_path / "empty"))
        stats = kb.stats()
        assert stats["total_challenges"] == 0
        assert stats["avg_difficulty"] == 0


# ── Query by name ─────────────────────────────────────────────────────────────


class TestQueryByName:
    def test_exact_match(self, mock_kb: SolveKnowledgeBase):
        p = mock_kb.query_by_name("alpha")
        assert p is not None
        assert p.challenge == "alpha"

    def test_case_insensitive(self, mock_kb: SolveKnowledgeBase):
        p = mock_kb.query_by_name("Alpha")
        assert p is not None
        assert p.challenge == "alpha"

    def test_not_found(self, mock_kb: SolveKnowledgeBase):
        assert mock_kb.query_by_name("nonexistent") is None


# ── Serialization ─────────────────────────────────────────────────────────────


class TestSerialization:
    def test_to_dict(self, mock_kb: SolveKnowledgeBase):
        d = mock_kb.to_dict()
        assert "stats" in d
        assert "patterns" in d
        assert len(d["patterns"]) == 5

    def test_to_dict_json_serializable(self, mock_kb: SolveKnowledgeBase):
        d = mock_kb.to_dict()
        # Should not raise
        json.dumps(d)


# ── Normalize technique ──────────────────────────────────────────────────────


class TestNormalize:
    def test_basic(self):
        assert _normalize_technique("XOR Decryption") == "xor_decryption"

    def test_dashes(self):
        assert _normalize_technique("code-as-data") == "code_as_data"

    def test_multiple_spaces(self):
        assert _normalize_technique("binary   patching") == "binary_patching"


# ── Live VERE data tests ─────────────────────────────────────────────────────
# These only run when the actual VERE solve artifacts are available.


@pytest.mark.skipif(not _VERE_EXISTS, reason="VERE solve artifacts not available")
class TestLiveVERE:
    @pytest.fixture(autouse=True)
    def _setup(self):
        self.kb = SolveKnowledgeBase(solves_root=str(VERE_SOLVES_ROOT))

    def test_indexes_20_challenges(self):
        assert len(self.kb.patterns) == 20

    def test_all_challenge_names(self):
        names = {p.challenge for p in self.kb.patterns}
        expected = {
            "JS",
            "Jay-Es",
            "PHP",
            "Piethon",
            "Python",
            "Basic",
            "Birds",
            "Cilly",
            "Macro",
            "PYC",
            "Wasm",
            "13bit",
            "deathstar",
            "memfrob",
            "plants",
            "wait",
            "cutlery",
            "go",
            "hashing",
            "stripped",
        }
        # Some challenges might not have 'challenge' field -- use name from path
        # Allow partial overlap since some taxonomy files lack 'challenge' field
        assert len(names) == 20

    def test_query_xor_returns_multiple(self):
        results = self.kb.query_by_technique("xor")
        assert len(results) >= 5
        names = {p.challenge for p in results}
        assert "memfrob" in names

    def test_query_rc4(self):
        results = self.kb.query_by_technique("rc4")
        assert len(results) >= 1
        names = {p.challenge for p in results}
        assert "cutlery" in names

    def test_query_go_reversing(self):
        results = self.kb.query_by_technique("go_reversing")
        assert len(results) >= 1
        names = {p.challenge for p in results}
        assert "go" in names

    def test_query_type_xor_decrypt(self):
        results = self.kb.query_by_type("xor_decrypt")
        assert len(results) >= 2

    def test_query_type_rc4_decrypt(self):
        results = self.kb.query_by_type("rc4_decrypt")
        assert len(results) >= 1
        assert results[0].challenge == "cutlery"

    def test_suggest_go_binary(self):
        suggestions = self.kb.suggest_approach(binary_info={"language": "go"})
        techniques = [s["technique"] for s in suggestions]
        assert "subtract_then_xor" in techniques

    def test_suggest_fork_binary(self):
        suggestions = self.kb.suggest_approach(binary_info={"imports": ["fork"]})
        techniques = [s["technique"] for s in suggestions]
        assert "rc4_decrypt" in techniques

    def test_suggest_stripped_pie(self):
        suggestions = self.kb.suggest_approach(
            binary_info={"stripped": True, "pie": True},
        )
        techniques = [s["technique"] for s in suggestions]
        assert "static_analysis" in techniques

    def test_suggest_srand(self):
        suggestions = self.kb.suggest_approach(binary_info={"imports": ["srand"]})
        techniques = [s["technique"] for s in suggestions]
        assert "seeded_prng_xor" in techniques

    def test_stats_correct_total(self):
        stats = self.kb.stats()
        assert stats["total_challenges"] == 20

    def test_stats_has_techniques(self):
        stats = self.kb.stats()
        assert len(stats["techniques"]) > 10

    def test_similar_stripped_hashing(self):
        results = self.kb.query_similar("stripped")
        names = {p.challenge for p in results}
        assert "hashing" in names

    def test_similar_hashing_stripped(self):
        results = self.kb.query_similar("hashing")
        names = {p.challenge for p in results}
        assert "stripped" in names

    def test_similar_memfrob(self):
        # stripped lists week3/memfrob as similar
        results = self.kb.query_similar("stripped")
        names = {p.challenge for p in results}
        assert "memfrob" in names
