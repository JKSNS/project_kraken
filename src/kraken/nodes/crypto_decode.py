"""Crypto decode specialist -- analyze and reverse crypto/encoding operations.

Enhanced with:
- Concrete crypto constant extraction from binary (S-boxes, IVs, keys from .rodata)
- OpenSSL function identification from PLT/GOT
- Section data extraction for encrypted sections
- Passes concrete data to solve engine instead of just LLM analysis
- Encoding chain detection (base64 -> hex -> xor sweeps)
- dlopen/dlsym pattern hints for dynamic library loading
"""
from __future__ import annotations

import base64
import json
import math
import re

from kraken.state import KrakenState
from kraken.models import direct_generate
from kraken.config import ModelConfig
from kraken.logging.structured import get_logger

log = get_logger(__name__)


async def _extract_crypto_info(binary_path: str, binary_info: dict) -> dict:
    """Extract concrete crypto data from the binary using deterministic tools."""
    crypto_data: dict = {
        "crypto_imports": [],
        "crypto_constants": [],
        "encrypted_sections": [],
        "potential_keys": [],
    }

    # Identify crypto-related imports from PLT/GOT
    imports = binary_info.get("imports", [])
    crypto_keywords = [
        "aes", "des", "rsa", "sha", "md5", "encrypt", "decrypt", "cipher",
        "EVP_", "OPENSSL", "BN_", "RAND_", "HMAC", "SSL_", "RC4",
    ]
    crypto_data["crypto_imports"] = [
        imp for imp in imports
        if any(kw.lower() in str(imp).lower() for kw in crypto_keywords)
    ]

    # Extract encrypted data from high-entropy custom sections
    try:
        from kraken.tools.dynamic import extract_encrypted_data
        result = await extract_encrypted_data(binary_path)

        if result.success and result.data:
            crypto_data["crypto_constants"] = result.data.get("crypto_constants", [])
            crypto_data["potential_keys"] = result.data.get("rodata_keys", [])[:5]
            crypto_data["encrypted_sections"] = [
                {
                    "name": name,
                    "size": info["size"],
                    "entropy": info["entropy"],
                    "hex_preview": info["hex_preview"],
                }
                for name, info in result.data.get("custom_section_data", {}).items()
                if info.get("is_high_entropy")
            ]
            # Include XOR candidates
            xor = result.data.get("xor_candidates", [])
            if xor:
                crypto_data["xor_results"] = xor
    except Exception as e:
        log.warning("crypto_extract_failed", error=str(e))

    # ── Encoding chain detection ─────────────────────────────────
    # Try sequential decoding on high-entropy strings
    strings = binary_info.get("strings_of_interest", [])
    if not strings:
        # Fall back to exports/imports as string source
        strings = []
    encoding_chains: list[dict] = []
    for s in strings[:50]:
        if len(s) < 12:
            continue
        chain: list[str] = []
        current = s

        # Layer 1: try base64
        try:
            dec = base64.b64decode(current)
            if len(dec) > 2:
                chain.append("base64")
                current = dec.hex() if not all(0x20 <= b <= 0x7E for b in dec) else dec.decode("ascii", errors="replace")
        except Exception:
            pass

        # Layer 1 alt: try hex
        if not chain and re.fullmatch(r"[0-9a-fA-F]+", current) and len(current) % 2 == 0:
            try:
                dec = bytes.fromhex(current)
                if len(dec) > 2:
                    chain.append("hex")
                    current = dec.decode("ascii", errors="replace") if all(0x20 <= b <= 0x7E for b in dec) else dec.hex()
            except Exception:
                pass

        # Layer 2: XOR sweep on decoded data (keys 1-255)
        if chain and isinstance(current, str) and len(current) >= 4:
            try:
                data = current.encode("latin-1") if isinstance(current, str) else current
                for key in range(1, 256):
                    xored = bytes(b ^ key for b in data)
                    if all(0x20 <= b <= 0x7E for b in xored):
                        chain.append(f"xor_{key:#04x}")
                        break
            except Exception:
                pass

        if chain:
            encoding_chains.append({
                "original": s[:60],
                "chain": chain,
            })

    if encoding_chains:
        crypto_data["encoding_chains"] = encoding_chains

    # ── dlopen/dlsym pattern detection ────────────────────────────
    all_imports = binary_info.get("imports", [])
    all_exports = binary_info.get("exports", [])
    dlopen_funcs = {"dlopen", "dlsym", "dlclose", "dlerror"}
    has_dlopen = any(
        fname in dlopen_funcs
        for fname in (str(f) for f in all_imports + all_exports)
    )
    if has_dlopen:
        crypto_data["dlopen_pattern"] = True
        # Check if custom sections with high entropy exist (likely encrypted libs)
        custom_sections = binary_info.get("custom_sections", [])
        encrypted_libs = [
            sec for sec in custom_sections
            if sec.get("is_high_entropy")
        ]
        if encrypted_libs:
            crypto_data["dlopen_encrypted_lib_hint"] = (
                f"Binary uses dlopen/dlsym and has {len(encrypted_libs)} high-entropy "
                f"custom section(s) that may be encrypted shared libraries. "
                f"Extract, decrypt, and load with ctypes."
            )

    return crypto_data


async def crypto_decode(state: KrakenState) -> dict:
    """Analyze crypto patterns in decompiled code and prepare solve strategy.

    Combines LLM analysis of decompiled code with deterministic extraction
    of crypto constants, keys, and encrypted section data.
    """
    from kraken.storage.artifact_store import get_artifact
    functions = get_artifact(state, "decompiled_functions", "decompiled_functions_handle")
    annotations = state.get("function_annotations", {})
    strings = state.get("strings_of_interest", [])
    binary_path = state.get("challenge_path", "")
    binary_info = state.get("binary_info", {})

    log.info("crypto_decode_start")

    # Extract concrete crypto data from binary (deterministic)
    crypto_data = await _extract_crypto_info(binary_path, binary_info)

    # Build analysis prompt with concrete data
    crypto_context = ""
    if crypto_data["crypto_imports"]:
        crypto_context += f"\n## Crypto Imports Found (from PLT/GOT)\n{json.dumps(crypto_data['crypto_imports'], indent=2)}\n"
    if crypto_data["crypto_constants"]:
        crypto_context += f"\n## Known Crypto Constants Detected\n{json.dumps(crypto_data['crypto_constants'], indent=2)}\n"
    if crypto_data.get("encrypted_sections"):
        crypto_context += f"\n## High-Entropy Sections (likely encrypted)\n{json.dumps(crypto_data['encrypted_sections'], indent=2)}\n"
    if crypto_data.get("potential_keys"):
        crypto_context += f"\n## Potential Keys Found in .rodata\n{json.dumps(crypto_data['potential_keys'][:5], indent=2)}\n"
    if crypto_data.get("xor_results"):
        crypto_context += f"\n## XOR Decryption Results\n{json.dumps(crypto_data['xor_results'], indent=2)}\n"

    prompt = f"""Analyze these decompiled functions from a CTF reverse engineering challenge.
Identify the cryptographic or encoding operations being performed.

## Decompiled Functions
{json.dumps({k: v[:2000] for k, v in list(functions.items())[:10]}, indent=2)}

## Strings Found in Binary
{json.dumps(strings[:30], indent=2)}

## LLM Annotations (advisory)
{json.dumps({k: v[:500] for k, v in list(annotations.items())[:10]}, indent=2)}
{crypto_context}
Identify:
1. What encoding/cipher is used (XOR, Caesar, RC4, AES, base64, custom)?
2. Where is the key stored or derived? (cite specific addresses or .rodata offsets)
3. Where is the ciphertext/encoded data? (cite specific sections or addresses)
4. What is the decryption/decoding algorithm?
5. If crypto constants were found, which algorithm do they correspond to?

Respond with JSON:
{{
    "algorithm": "name of algorithm",
    "key_source": "where the key comes from (address, constant, derived)",
    "key_value": "actual key bytes if found in .rodata (hex)",
    "data_source": "where encrypted/encoded data is (section name, address)",
    "data_hex": "first 64 bytes of encrypted data if available (hex)",
    "reverse_approach": "step-by-step how to reverse it",
    "notes": "additional observations"
}}"""

    cfg = ModelConfig()
    content = await direct_generate(prompt, "mid", cfg)

    # Parse response
    analysis = {}
    try:
        json_str = content
        if "```json" in content:
            json_str = content.split("```json")[1].split("```")[0]
        elif "```" in content:
            json_str = content.split("```")[1].split("```")[0]
        analysis = json.loads(json_str)
    except (json.JSONDecodeError, IndexError):
        analysis = {"raw_analysis": content}

    # Merge concrete crypto data into analysis
    analysis["concrete_crypto_data"] = crypto_data

    log.info("crypto_decode_complete",
             algorithm=analysis.get("algorithm", "unknown"),
             crypto_imports=len(crypto_data["crypto_imports"]),
             constants_found=len(crypto_data["crypto_constants"]),
             keys_found=len(crypto_data["potential_keys"]))

    # Build detailed strategy hypothesis with actionable info
    parts = [f"Crypto: {analysis.get('algorithm', 'unknown')}"]
    if analysis.get("reverse_approach"):
        parts.append(f"Approach: {analysis['reverse_approach'][:120]}")
    if analysis.get("key_value"):
        parts.append(f"Key found: {analysis['key_value'][:40]}")
    if analysis.get("data_source"):
        parts.append(f"Data in: {analysis['data_source']}")
    if crypto_data.get("dlopen_pattern"):
        parts.append("Binary loads external library via dlopen -- use ctypes to call functions directly")
    if crypto_data.get("encoding_chains"):
        chains = [" → ".join(c.get("chain", [])) for c in crypto_data["encoding_chains"][:2]]
        parts.append(f"Encoding chains: {'; '.join(chains)}")
    if crypto_data.get("xor_results"):
        xr = crypto_data["xor_results"][0]
        parts.append(f"XOR key={xr.get('key', '?')} → {xr.get('preview', '')[:50]}")
    if crypto_data.get("crypto_imports"):
        parts.append(f"Crypto imports: {', '.join(str(x) for x in crypto_data['crypto_imports'][:5])}")
    strategy = " | ".join(parts)

    return {
        "strategy_hypothesis": strategy,
        "angr_results": {
            **(state.get("angr_results", {})),
            "crypto_analysis": analysis,
        },
        "recent_actions": [{
            "action": "crypto_decode",
            "reasoning": f"Crypto analysis: {analysis.get('algorithm', 'unknown')}",
            "result_summary": json.dumps(analysis)[:500],
        }],
        "iteration_count": state.get("iteration_count", 0) + 1,
    }
