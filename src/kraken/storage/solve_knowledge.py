"""Query past solve artifacts to inform new challenge approaches.

Indexes taxonomy.json and constraints.json from solved challenges and provides
query functions for technique matching, constraint type lookup, and approach
suggestion based on binary properties and strings.

Purely deterministic -- no LLM calls.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class SolvePattern:
    """A single indexed solve with its taxonomy + constraint metadata."""

    challenge: str
    week: str
    dataset: str
    flag: str
    techniques: list[str]
    category: str
    difficulty: int
    constraint_type: str
    key_insights: list[str]
    similar_to: list[str]
    tools_used: list[str]
    solve_time_seconds: int
    solve_method: str
    binary_properties: dict[str, Any]
    constraint_data: dict[str, Any]
    taxonomy_data: dict[str, Any]


def _normalize_technique(t: str) -> str:
    """Lowercase, strip whitespace, collapse separators."""
    return re.sub(r"[\s_-]+", "_", t.strip().lower())


def _extract_challenge_name(path: Path) -> str:
    """Extract challenge name from a taxonomy.json path.

    Expected layouts:
      .../week{N}/{challenge}/artifacts/taxonomy.json
      .../{dataset}/solves/{category}/{challenge}/artifacts/taxonomy.json
      .../{challenge}/artifacts/taxonomy.json
    """
    # artifacts/ is the parent, challenge is grandparent
    if path.parent.name == "artifacts":
        return path.parent.parent.name
    return path.parent.name


def _extract_week(path: Path) -> str:
    """Extract week identifier from path (e.g. 'week4')."""
    for part in path.parts:
        if re.match(r"week\d+", part, re.IGNORECASE):
            return part
    return ""


def _extract_dataset(path: Path) -> str:
    """Extract dataset name from path (e.g. 'vere', 'ctftiny')."""
    for part in path.parts:
        if part in ("vere", "ctftiny", "cybench", "nyuctf", "standalone"):
            return part
    return "unknown"


def _safe_int(val: Any, default: int = 0) -> int:
    """Coerce a value to int, returning default on failure."""
    if isinstance(val, int):
        return val
    if isinstance(val, dict):
        # Handle {"score": 5, ...} nested dicts
        for k in ("score", "rating", "estimated_difficulty"):
            if k in val and isinstance(val[k], (int, float)):
                return int(val[k])
        return default
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def _extract_similar_to(raw: Any) -> list[str]:
    """Normalize similar_to which can be list[str] or list[dict]."""
    if not raw:
        return []
    result = []
    for item in raw:
        if isinstance(item, str):
            result.append(item)
        elif isinstance(item, dict):
            name = item.get("challenge", item.get("name", ""))
            if name:
                result.append(name)
    return result


class SolveKnowledgeBase:
    """Index and query past solve artifacts (taxonomy.json + constraints.json)."""

    def __init__(self, solves_root: str = "benchmarks"):
        self.patterns: list[SolvePattern] = []
        self._technique_index: dict[str, list[int]] = {}
        self._type_index: dict[str, list[int]] = {}
        self._name_index: dict[str, int] = {}
        self._index_solves(Path(solves_root))

    def _index_solves(self, root: Path) -> None:
        """Scan all solve directories for taxonomy.json + constraints.json."""
        root = root.resolve() if root.exists() else root

        # Find all taxonomy.json files under the root
        taxonomy_files = sorted(root.rglob("taxonomy.json"))

        for tax_path in taxonomy_files:
            try:
                tax_data = json.loads(tax_path.read_text())
            except (json.JSONDecodeError, OSError):
                continue

            # Look for constraints.json alongside taxonomy.json
            con_path = tax_path.parent / "constraints.json"
            con_data: dict[str, Any] = {}
            if con_path.exists():
                try:
                    con_data = json.loads(con_path.read_text())
                except (json.JSONDecodeError, OSError):
                    pass

            challenge_name = (
                tax_data.get("challenge")
                or tax_data.get("challenge_id")
                or _extract_challenge_name(tax_path)
            )
            week = tax_data.get("week", _extract_week(tax_path))
            if isinstance(week, int):
                week = f"week{week}"

            # Extract techniques -- always a list[str]
            techniques_raw = tax_data.get("techniques", [])
            techniques = []
            for t in techniques_raw:
                if isinstance(t, str):
                    techniques.append(t)

            # Extract difficulty
            difficulty_raw = tax_data.get("estimated_difficulty", tax_data.get("difficulty", 0))
            difficulty = _safe_int(difficulty_raw)

            # Category
            category = tax_data.get("category", "")

            # Constraint type
            constraint_type = con_data.get("type", con_data.get("puzzle_type", con_data.get("cipher", "")))

            # Key insights
            key_insights = tax_data.get("key_insights", [])
            if not key_insights and "notes" in tax_data:
                key_insights = [tax_data["notes"]]

            # Similar to
            similar_to = _extract_similar_to(tax_data.get("similar_to", []))

            # Tools used
            tools_used = tax_data.get("tools_used", [])
            if not tools_used:
                auto = tax_data.get("automation", {})
                if isinstance(auto, dict):
                    tools_used = auto.get("tools_used", [])

            # Solve time
            solve_time = _safe_int(tax_data.get("solve_time_seconds", 0))

            # Solve method
            solve_method = tax_data.get("solve_method", tax_data.get("solve_approach", ""))
            if not solve_method:
                auto = tax_data.get("automation", {})
                if isinstance(auto, dict) and auto.get("deterministic"):
                    solve_method = "deterministic"

            # Binary properties
            binary_props = tax_data.get("binary_properties", {})

            # Flag from constraints
            flag = con_data.get("flag", "")

            pattern = SolvePattern(
                challenge=challenge_name,
                week=str(week),
                dataset=_extract_dataset(tax_path),
                flag=flag,
                techniques=techniques,
                category=category,
                difficulty=difficulty,
                constraint_type=constraint_type,
                key_insights=key_insights,
                similar_to=similar_to,
                tools_used=tools_used,
                solve_time_seconds=solve_time,
                solve_method=solve_method,
                binary_properties=binary_props,
                constraint_data=con_data,
                taxonomy_data=tax_data,
            )

            idx = len(self.patterns)
            self.patterns.append(pattern)

            # Build indices
            self._name_index[challenge_name.lower()] = idx

            for tech in techniques:
                key = _normalize_technique(tech)
                self._technique_index.setdefault(key, []).append(idx)

            if constraint_type:
                ct_key = _normalize_technique(constraint_type)
                self._type_index.setdefault(ct_key, []).append(idx)

    def query_by_technique(self, technique: str) -> list[SolvePattern]:
        """Find all challenges solved with a given technique.

        Performs substring matching: query "xor" matches "xor_decryption",
        "xor_key_extraction", "subtract_then_xor", etc.
        """
        query = _normalize_technique(technique)
        results: list[SolvePattern] = []
        seen: set[int] = set()

        # Exact key match first
        for key, indices in self._technique_index.items():
            if query in key or key in query:
                for idx in indices:
                    if idx not in seen:
                        seen.add(idx)
                        results.append(self.patterns[idx])

        return results

    def query_by_type(self, constraint_type: str) -> list[SolvePattern]:
        """Find challenges with similar constraint types (xor_decrypt, rc4, etc).

        Performs substring matching on constraint type.
        """
        query = _normalize_technique(constraint_type)
        results: list[SolvePattern] = []
        seen: set[int] = set()

        for key, indices in self._type_index.items():
            if query in key or key in query:
                for idx in indices:
                    if idx not in seen:
                        seen.add(idx)
                        results.append(self.patterns[idx])

        return results

    def query_by_name(self, challenge_name: str) -> SolvePattern | None:
        """Look up a specific challenge by name."""
        idx = self._name_index.get(challenge_name.lower())
        if idx is not None:
            return self.patterns[idx]
        return None

    def query_similar(self, challenge_name: str) -> list[SolvePattern]:
        """Find challenges marked as similar_to this one.

        Searches both directions: challenges that list this one as similar,
        and challenges that this one lists as similar.
        """
        name_lower = challenge_name.lower()
        results: list[SolvePattern] = []
        seen: set[str] = set()

        # 1. Get the challenge itself and its similar_to list
        source = self.query_by_name(challenge_name)
        if source:
            for sim_name in source.similar_to:
                sim_lower = sim_name.lower()
                # Handle "week3/memfrob" format
                if "/" in sim_lower:
                    sim_lower = sim_lower.rsplit("/", 1)[-1]
                target = self.query_by_name(sim_lower)
                if target and target.challenge.lower() not in seen:
                    seen.add(target.challenge.lower())
                    results.append(target)

        # 2. Find challenges that list this one as similar
        for pattern in self.patterns:
            if pattern.challenge.lower() == name_lower:
                continue
            for sim in pattern.similar_to:
                sim_check = sim.lower()
                if "/" in sim_check:
                    sim_check = sim_check.rsplit("/", 1)[-1]
                if sim_check == name_lower and pattern.challenge.lower() not in seen:
                    seen.add(pattern.challenge.lower())
                    results.append(pattern)

        return results

    def suggest_approach(
        self,
        binary_info: dict[str, Any] | None = None,
        strings: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Given triage output, suggest likely approaches based on past solves.

        Returns ranked list of dicts:
        {
            "technique": str,
            "confidence": float,
            "similar_challenges": [str, ...],
            "suggested_tools": [str, ...],
            "key_insights": [str, ...]
        }
        """
        if not self.patterns:
            return []

        binary_info = binary_info or {}
        strings = strings or []
        strings_lower = " ".join(s.lower() for s in strings)

        scores: dict[str, dict[str, Any]] = {}

        def _add_suggestion(
            technique: str,
            confidence: float,
            challenges: list[str],
            tools: list[str],
            insights: list[str],
        ) -> None:
            key = _normalize_technique(technique)
            if key in scores:
                entry = scores[key]
                entry["confidence"] = max(entry["confidence"], confidence)
                for c in challenges:
                    if c not in entry["similar_challenges"]:
                        entry["similar_challenges"].append(c)
                for t in tools:
                    if t not in entry["suggested_tools"]:
                        entry["suggested_tools"].append(t)
                for i in insights:
                    if i not in entry["key_insights"]:
                        entry["key_insights"].append(i)
            else:
                scores[key] = {
                    "technique": technique,
                    "confidence": confidence,
                    "similar_challenges": list(challenges),
                    "suggested_tools": list(tools),
                    "key_insights": list(insights),
                }

        # --- Heuristic rules based on binary_info ---

        file_type = str(binary_info.get("type", "")).lower()
        is_stripped = binary_info.get("stripped", False)
        is_pie = binary_info.get("pie", False)
        imports = [s.lower() for s in binary_info.get("imports", [])]
        libraries = [s.lower() for s in binary_info.get("libraries", [])]
        arch = str(binary_info.get("arch", "")).lower()
        language = str(binary_info.get("language", "")).lower()

        # Rule: Go binary -> subtract-then-XOR pattern
        if "go" in language or "go" in file_type:
            matching = [p for p in self.patterns if "go_reversing" in [_normalize_technique(t) for t in p.techniques]]
            _add_suggestion(
                "subtract_then_xor",
                0.8,
                [p.challenge for p in matching] or ["go"],
                ["auto_source_decode", "auto_constraint_extract"],
                ["Go binaries use stack arrays -- look for subtract-then-XOR pattern",
                 "Watch for decoy output that changes every run"],
            )

        # Rule: fork in imports -> RC4 + IPC (cutlery pattern)
        if "fork" in imports or any("fork" in lib for lib in libraries):
            matching = [p for p in self.patterns if "fork_ipc" in [_normalize_technique(t) for t in p.techniques]]
            _add_suggestion(
                "rc4_decrypt",
                0.7,
                [p.challenge for p in matching] or ["cutlery"],
                ["auto_c_source_eval", "auto_source_decode"],
                ["fork + IPC often means split RC4 stream cipher",
                 "Look for message queue or pipe-based state sharing",
                 "Key may be derived from timestamp -- check description"],
            )

        # Rule: SHA1/hash imports -> XOR + hash bypass
        hash_libs = {"libcrypto", "sha1", "sha256", "md5", "openssl"}
        if any(h in imp for imp in imports for h in hash_libs) or any(h in lib for lib in libraries for h in hash_libs):
            matching = [p for p in self.patterns if "sha1_bypass" in [_normalize_technique(t) for t in p.techniques]]
            _add_suggestion(
                "xor_with_hash_bypass",
                0.7,
                [p.challenge for p in matching] or ["stripped", "hashing"],
                ["auto_source_decode", "auto_xor_brute"],
                ["Hash check may be intentionally unsolvable -- try binary patching (je->jmp)",
                 "Code bytes of a function may serve as XOR key material"],
            )

        # Rule: stripped + PIE -> angr likely fails
        if is_stripped and is_pie:
            matching = [p for p in self.patterns
                        if p.binary_properties.get("stripped") and p.binary_properties.get("pie")]
            _add_suggestion(
                "static_analysis",
                0.6,
                [p.challenge for p in matching] or ["stripped"],
                ["auto_source_decode", "auto_constraint_extract", "auto_c_source_eval"],
                ["Stripped PIE binaries defeat angr -- prefer static disassembly",
                 "Look for movabs instructions with embedded ciphertext"],
            )

        # Rule: srand/rand -> seeded PRNG XOR
        if "srand" in imports or "rand" in imports or any("rand" in s for s in strings):
            matching = [p for p in self.patterns if "prng_seed_extraction" in [_normalize_technique(t) for t in p.techniques]]
            _add_suggestion(
                "seeded_prng_xor",
                0.8,
                [p.challenge for p in matching] or ["plants"],
                ["auto_c_rand", "auto_c_source_eval"],
                ["Extract seed from srand() call in disassembly",
                 "Must use glibc rand (not Python random) -- use ctypes or C",
                 "Watch for compiler strength-reduction of modulus operations"],
            )

        # Rule: movabs in strings/disassembly -> XOR with embedded data
        if "movabs" in strings_lower:
            matching = [p for p in self.patterns if "movabs_byte_extraction" in [_normalize_technique(t) for t in p.techniques]]
            _add_suggestion(
                "xor_decrypt",
                0.8,
                [p.challenge for p in matching] or ["memfrob", "stripped", "hashing"],
                ["auto_source_decode", "auto_xor_brute"],
                ["movabs instructions embed 8-byte immediates as ciphertext",
                 "Watch for overlapping writes (later movabs overwrites earlier bytes)",
                 "Little-endian byte order in immediates"],
            )

        # Rule: memfrob -> multi-stage XOR
        if "memfrob" in strings_lower:
            matching = self.query_by_technique("memfrob")
            _add_suggestion(
                "xor_chain_decode",
                0.9,
                [p.challenge for p in matching] or ["memfrob"],
                ["auto_source_decode", "auto_xor_brute"],
                ["memfrob is glibc's XOR 0x2A joke function",
                 "Multi-stage: source XOR key, then memfrob on input, then compare"],
            )

        # Rule: Python/PHP/JS source -> source code analysis
        if any(lang in language for lang in ("python", "php", "javascript", "node")):
            _add_suggestion(
                "source_code_analysis",
                0.7,
                [],
                ["auto_source_decode", "auto_constraint_extract"],
                ["Source code challenges -- look for encoding layers (base64, hex, chr)",
                 "Check for obfuscation patterns (variable renaming, string tables)"],
            )

        # Rule: .pyc -> Python bytecode decompilation
        if ".pyc" in file_type or "python bytecode" in file_type:
            matching = self.query_by_technique("Python bytecode decompilation")
            _add_suggestion(
                "python_bytecode_decompilation",
                0.8,
                [p.challenge for p in matching] or ["PYC"],
                ["auto_source_decode"],
                ["Use uncompyle6 for decompilation",
                 "Look for standard crypto with obfuscated names (AES S-box fingerprinting)"],
            )

        # Rule: ELF repair needed (corrupted magic)
        if binary_info.get("corruption_detected") or "corrupted" in file_type:
            matching = self.query_by_technique("elf_header_analysis")
            _add_suggestion(
                "elf_repair",
                0.8,
                [p.challenge for p in matching] or ["13bit"],
                ["auto_patcher", "kraken_repair_elf"],
                ["Check ELF magic, e_phoff, e_entry, interpreter path",
                 "Multiple independent corruptions may coexist",
                 "After repair, look for XOR decryption in restored code"],
            )

        # Rule: timing/sleep in strings or binary -> timing side channel
        if any(kw in strings_lower for kw in ("sleep", "usleep", "nanosleep", "timing")):
            matching = self.query_by_technique("timing_side_channel_attack")
            _add_suggestion(
                "timing_side_channel",
                0.6,
                [p.challenge for p in matching] or ["wait"],
                ["auto_source_decode"],
                ["Character-by-character comparison with sleep-based timing oracle",
                 "Use median filtering to handle network jitter",
                 "May require 30-60 minutes of probing"],
            )

        # Rule: C++ / data structure challenges
        if any(kw in strings_lower for kw in ("linked_list", "bst", "tree", "vtable")):
            matching = self.query_by_technique("data_structure_simulation")
            _add_suggestion(
                "data_structure_simulation",
                0.6,
                [p.challenge for p in matching] or ["deathstar"],
                ["auto_c_source_eval", "auto_constraint_extract"],
                ["C++ class layout and virtual dispatch in assembly",
                 "Simulate data structure operations to derive key/flag"],
            )

        # Rule: WASM -> string extraction
        if "wasm" in file_type or "wasm" in language:
            matching = self.query_by_technique("WASM data section analysis")
            _add_suggestion(
                "wasm_analysis",
                0.7,
                [p.challenge for p in matching] or ["Wasm"],
                ["auto_source_decode", "auto_archive_search"],
                ["WASM challenges often have flags in data sections",
                 "Check for associated web assets (HTML, JS loaders)"],
            )

        # If no specific rules matched, provide generic XOR suggestion
        # (most common technique in the knowledge base)
        if not scores:
            xor_challenges = self.query_by_technique("xor")
            if xor_challenges:
                _add_suggestion(
                    "xor_decrypt",
                    0.3,
                    [p.challenge for p in xor_challenges[:3]],
                    ["auto_source_decode", "auto_xor_brute", "auto_constraint_extract"],
                    ["XOR is the most common cipher in RE challenges",
                     "Look for embedded ciphertext and key derivation patterns"],
                )

        # Sort by confidence descending
        ranked = sorted(scores.values(), key=lambda x: x["confidence"], reverse=True)
        return ranked

    def query_all(self) -> list[SolvePattern]:
        """Return all indexed patterns."""
        return list(self.patterns)

    def stats(self) -> dict[str, Any]:
        """Return aggregate statistics about the knowledge base."""
        if not self.patterns:
            return {
                "total_challenges": 0,
                "datasets": [],
                "categories": {},
                "constraint_types": {},
                "techniques": {},
                "avg_difficulty": 0,
                "avg_solve_time_seconds": 0,
                "deterministic_count": 0,
                "llm_required_count": 0,
            }

        categories: dict[str, int] = {}
        constraint_types: dict[str, int] = {}
        techniques: dict[str, int] = {}
        datasets: set[str] = set()
        difficulties: list[int] = []
        solve_times: list[int] = []
        deterministic = 0
        llm_required = 0

        for p in self.patterns:
            datasets.add(p.dataset)

            cat = p.category or "unknown"
            categories[cat] = categories.get(cat, 0) + 1

            if p.constraint_type:
                constraint_types[p.constraint_type] = constraint_types.get(p.constraint_type, 0) + 1

            for t in p.techniques:
                techniques[t] = techniques.get(t, 0) + 1

            if p.difficulty > 0:
                difficulties.append(p.difficulty)

            if p.solve_time_seconds > 0:
                solve_times.append(p.solve_time_seconds)

            if p.solve_method == "deterministic":
                deterministic += 1

            tax = p.taxonomy_data
            if tax.get("llm_required") is True or (
                isinstance(tax.get("automation"), dict) and tax["automation"].get("llm_required") is True
            ):
                llm_required += 1

        return {
            "total_challenges": len(self.patterns),
            "datasets": sorted(datasets),
            "categories": dict(sorted(categories.items())),
            "constraint_types": dict(sorted(constraint_types.items())),
            "techniques": dict(sorted(techniques.items(), key=lambda x: -x[1])),
            "avg_difficulty": round(sum(difficulties) / len(difficulties), 1) if difficulties else 0,
            "avg_solve_time_seconds": round(sum(solve_times) / len(solve_times)) if solve_times else 0,
            "deterministic_count": deterministic,
            "llm_required_count": llm_required,
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialize the knowledge base to a dict for JSON output."""
        return {
            "stats": self.stats(),
            "patterns": [
                {
                    "challenge": p.challenge,
                    "week": p.week,
                    "dataset": p.dataset,
                    "category": p.category,
                    "difficulty": p.difficulty,
                    "constraint_type": p.constraint_type,
                    "techniques": p.techniques,
                    "similar_to": p.similar_to,
                    "tools_used": p.tools_used,
                    "solve_time_seconds": p.solve_time_seconds,
                    "solve_method": p.solve_method,
                }
                for p in self.patterns
            ],
        }


# ── CLI entry point ─────────────────────────────────────────────────────────


def cli_main() -> None:
    """CLI entry point: kraken knowledge [--technique T] [--type T] [--similar NAME] [--suggest PATH] [--stats]."""
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        prog="kraken knowledge",
        description="Query the KRAKEN solve knowledge base.",
    )
    parser.add_argument("--solves-root", default="benchmarks", help="Root directory with solve artifacts")
    parser.add_argument("--technique", "-t", default="", help="Query by technique name (substring match)")
    parser.add_argument("--type", "-T", dest="constraint_type", default="", help="Query by constraint type")
    parser.add_argument("--similar", "-s", default="", help="Find challenges similar to NAME")
    parser.add_argument("--suggest", default="", help="Path to binary -- suggest approach based on triage info")
    parser.add_argument("--stats", action="store_true", help="Show aggregate statistics")
    parser.add_argument("--list", "-l", action="store_true", help="List all indexed challenges")
    parser.add_argument("--json", "-j", action="store_true", help="Output as JSON")

    args = parser.parse_args()

    kb = SolveKnowledgeBase(solves_root=args.solves_root)

    if not kb.patterns:
        print(f"No solve artifacts found under {args.solves_root}/", file=sys.stderr)
        sys.exit(1)

    output: Any = None

    if args.stats:
        output = kb.stats()

    elif args.technique:
        results = kb.query_by_technique(args.technique)
        if args.json:
            output = [
                {"challenge": p.challenge, "techniques": p.techniques, "constraint_type": p.constraint_type}
                for p in results
            ]
        else:
            if not results:
                print(f"No challenges found with technique matching '{args.technique}'")
                return
            print(f"Challenges using technique '{args.technique}' ({len(results)} found):\n")
            for p in results:
                print(f"  {p.challenge} ({p.dataset}/{p.week})")
                print(f"    Category: {p.category}")
                print(f"    Techniques: {', '.join(p.techniques)}")
                print(f"    Constraint type: {p.constraint_type}")
                if p.key_insights:
                    print(f"    Key insights: {p.key_insights[0]}")
                print()
            return

    elif args.constraint_type:
        results = kb.query_by_type(args.constraint_type)
        if args.json:
            output = [
                {"challenge": p.challenge, "constraint_type": p.constraint_type, "techniques": p.techniques}
                for p in results
            ]
        else:
            if not results:
                print(f"No challenges found with constraint type matching '{args.constraint_type}'")
                return
            print(f"Challenges with constraint type '{args.constraint_type}' ({len(results)} found):\n")
            for p in results:
                print(f"  {p.challenge}: {p.constraint_type}")
                print(f"    Techniques: {', '.join(p.techniques)}")
                print()
            return

    elif args.similar:
        results = kb.query_similar(args.similar)
        if args.json:
            output = [
                {"challenge": p.challenge, "techniques": p.techniques, "similar_to": p.similar_to}
                for p in results
            ]
        else:
            if not results:
                print(f"No challenges found similar to '{args.similar}'")
                return
            print(f"Challenges similar to '{args.similar}' ({len(results)} found):\n")
            for p in results:
                print(f"  {p.challenge} ({p.dataset}/{p.week})")
                print(f"    Techniques: {', '.join(p.techniques)}")
                print()
            return

    elif args.suggest:
        # Quick triage to get binary_info
        binary_path = Path(args.suggest)
        if not binary_path.exists():
            print(f"Binary not found: {args.suggest}", file=sys.stderr)
            sys.exit(1)

        import subprocess

        binary_info: dict[str, Any] = {}
        strings_list: list[str] = []

        # Basic file detection
        try:
            file_out = subprocess.run(
                ["file", str(binary_path)], capture_output=True, text=True, timeout=10
            )
            file_type = file_out.stdout.strip()
            binary_info["type"] = file_type
            binary_info["stripped"] = "stripped" in file_type
            binary_info["pie"] = "pie" in file_type.lower() or "shared object" in file_type.lower()
            if "Go" in file_type:
                binary_info["language"] = "go"
        except Exception:
            pass

        # Extract strings
        try:
            str_out = subprocess.run(
                ["strings", str(binary_path)], capture_output=True, text=True, timeout=10
            )
            strings_list = str_out.stdout.splitlines()[:500]
        except Exception:
            pass

        # Extract imports (nm -D for dynamic symbols)
        try:
            nm_out = subprocess.run(
                ["nm", "-D", str(binary_path)], capture_output=True, text=True, timeout=10
            )
            imports = []
            for line in nm_out.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[-2] == "U":
                    imports.append(parts[-1])
                elif len(parts) >= 1 and parts[0] == "U":
                    imports.append(parts[-1])
            binary_info["imports"] = imports
        except Exception:
            pass

        suggestions = kb.suggest_approach(binary_info=binary_info, strings=strings_list)
        if args.json:
            output = suggestions
        else:
            if not suggestions:
                print("No approach suggestions could be generated.")
                return
            print(f"Suggested approaches for {binary_path.name}:\n")
            for s in suggestions:
                conf = s["confidence"]
                print(f"  [{conf:.0%}] {s['technique']}")
                if s["similar_challenges"]:
                    print(f"       Similar: {', '.join(s['similar_challenges'])}")
                if s["suggested_tools"]:
                    print(f"       Tools: {', '.join(s['suggested_tools'])}")
                for insight in s["key_insights"][:2]:
                    print(f"       - {insight}")
                print()
            return

    elif args.list:
        if args.json:
            output = kb.to_dict()
        else:
            print(f"Indexed {len(kb.patterns)} challenges:\n")
            for p in kb.patterns:
                print(f"  {p.challenge} ({p.dataset}/{p.week}) -- {p.constraint_type or p.category}")
            print()
            return
    else:
        # Default: show stats
        output = kb.stats()

    if output is not None:
        if args.json or isinstance(output, dict):
            print(json.dumps(output, indent=2))
        else:
            print(output)
