"""Generate deterministic feature vectors from challenge characteristics.

No ML model required -- features are handcrafted from challenge state fields.
Produces a 384-dimensional float vector suitable for cosine similarity search.

Feature layout (384 dims total):
  [  0.. 63] Binary info: architecture, protections, size, entropy
  [ 64..127] File types present in challenge
  [128..191] String patterns detected
  [192..223] Challenge type classification
  [224..287] Crypto / param indicators
  [288..319] Solve path & timing features
  [320..351] Decompilation signature features
  [352..383] Reserved / hash-based features
"""

from __future__ import annotations

import hashlib
import math
import os
import struct
from typing import Any


EMBEDDING_DIM = 384


def embed_challenge(state: dict[str, Any]) -> list[float]:
    """Generate a 384-dim feature vector from challenge state.

    The vector is fully deterministic: the same state dict always produces
    the same vector.  This enables exact deduplication and stable similarity
    rankings.
    """
    features = [0.0] * EMBEDDING_DIM

    # ------------------------------------------------------------------
    # Binary info features (dims 0-63)
    # ------------------------------------------------------------------
    binary_info = state.get("binary_info") or {}

    # Architecture one-hot (0-9)
    arch = str(binary_info.get("architecture", "") or binary_info.get("arch", "")).lower()
    _ARCH_MAP = {
        "x86-64": 0, "x86_64": 0, "amd64": 0,
        "x86": 1, "i386": 1, "i686": 1,
        "arm": 2, "aarch64": 3, "arm64": 3,
        "mips": 4, "mipsel": 4,
        "powerpc": 5, "ppc": 5,
        "riscv": 6,
        "sparc": 7,
        "wasm": 8,
        "avr": 9,
    }
    for key, idx in _ARCH_MAP.items():
        if key in arch:
            features[idx] = 1.0
            break

    # Protection flags (10-19)
    features[10] = 1.0 if binary_info.get("nx") else 0.0
    features[11] = 1.0 if binary_info.get("pie") else 0.0
    features[12] = 1.0 if binary_info.get("canary") else 0.0
    relro = str(binary_info.get("relro", "")).lower()
    features[13] = 1.0 if relro == "full" else (0.5 if relro == "partial" else 0.0)
    features[14] = 1.0 if binary_info.get("stripped") else 0.0
    features[15] = 1.0 if binary_info.get("static") else 0.0
    features[16] = 1.0 if binary_info.get("fortify") else 0.0

    # File format (20-29)
    file_type = str(binary_info.get("type", "") or binary_info.get("file_type", "")).lower()
    _FORMAT_MAP = {
        "elf": 20, "pe": 21, "mach-o": 22, "macho": 22,
        "java": 23, "class": 23, "jar": 23,
        "python": 24, ".pyc": 24,
        "dotnet": 25, ".net": 25, "cil": 25,
        "wasm": 26,
        "apk": 27,
        "script": 28,
        "shellcode": 29,
    }
    for key, idx in _FORMAT_MAP.items():
        if key in file_type:
            features[idx] = 1.0

    # Binary size buckets (30-39) -- logarithmic scale
    file_size = binary_info.get("size", 0) or 0
    if file_size > 0:
        log_size = math.log2(max(file_size, 1))
        # Buckets: <1K, 1-4K, 4-16K, 16-64K, 64-256K, 256K-1M, 1-4M, 4-16M, 16-64M, >64M
        bucket = min(int(log_size / 2.5), 9)
        features[30 + bucket] = 1.0

    # Entropy (40-44)
    entropy = binary_info.get("entropy", 0) or 0
    if entropy > 0:
        # Normalize entropy (0-8) to 0-1 range
        features[40] = min(entropy / 8.0, 1.0)
        features[41] = 1.0 if entropy > 7.0 else 0.0  # Packed/encrypted
        features[42] = 1.0 if entropy < 3.0 else 0.0  # Low entropy (text-heavy)

    # Section count features (45-49)
    sections = binary_info.get("sections", {})
    if isinstance(sections, dict):
        features[45] = min(len(sections) / 20.0, 1.0)
    elif isinstance(sections, list):
        features[45] = min(len(sections) / 20.0, 1.0)

    # Language detection (50-59)
    language = str(binary_info.get("language", "")).lower()
    _LANG_MAP = {
        "c": 50, "c++": 51, "cpp": 51, "go": 52, "rust": 53,
        "python": 54, "java": 55, "dotnet": 56, "c#": 56,
        "swift": 57, "nim": 58, "zig": 59,
    }
    for key, idx in _LANG_MAP.items():
        if key in language:
            features[idx] = 1.0

    # ------------------------------------------------------------------
    # File type features (dims 64-127)
    # ------------------------------------------------------------------
    challenge_files = state.get("challenge_files") or {}
    file_exts: set[str] = set()
    for name in challenge_files:
        _, ext = os.path.splitext(name)
        if ext:
            file_exts.add(ext.lower())

    _EXT_MAP = {
        ".py": 64, ".c": 65, ".js": 66, ".php": 67, ".rb": 68,
        ".pcap": 69, ".png": 70, ".jpg": 71, ".zip": 72, ".pdf": 73,
        ".elf": 74, ".exe": 75, ".apk": 76, ".jar": 77, ".wasm": 78,
        ".cap": 79, ".pcapng": 80, ".sh": 81, ".sql": 82, ".xml": 83,
        ".html": 84, ".css": 85, ".json": 86, ".yaml": 87, ".yml": 87,
        ".go": 88, ".rs": 89, ".java": 90, ".cs": 91, ".swift": 92,
        ".txt": 93, ".md": 94, ".csv": 95, ".log": 96,
        ".so": 97, ".dll": 98, ".dylib": 99,
        ".gz": 100, ".tar": 101, ".bz2": 102, ".7z": 103, ".rar": 104,
        ".bin": 105, ".dat": 106, ".db": 107, ".sqlite": 108,
        ".pem": 109, ".key": 110, ".crt": 111, ".der": 112,
        ".wav": 113, ".mp3": 114, ".flac": 115,
        ".bmp": 116, ".gif": 117, ".tiff": 118, ".svg": 119,
        ".pyc": 120, ".class": 121, ".o": 122, ".a": 123,
        ".dockerfile": 124, ".docker-compose": 125,
        ".toml": 126, ".ini": 127,
    }
    for ext, idx in _EXT_MAP.items():
        if ext in file_exts:
            features[idx] = 1.0

    # File count feature -- how many files in the challenge
    n_files = len(challenge_files)
    if n_files > 0:
        features[64] = max(features[64], min(n_files / 20.0, 1.0))  # Blend with .py flag

    # ------------------------------------------------------------------
    # String pattern features (dims 128-191)
    # ------------------------------------------------------------------
    strings = state.get("strings_of_interest") or []
    all_strings = " ".join(str(s) for s in strings).lower()

    _PATTERN_MAP = {
        128: "strcmp", 129: "memcmp", 130: "printf", 131: "scanf",
        132: "malloc", 133: "free", 134: "system", 135: "execve",
        136: "fork", 137: "ptrace", 138: "aes", 139: "rsa",
        140: "base64", 141: "xor", 142: "flag", 143: "password",
        144: "correct", 145: "wrong", 146: "secret", 147: "key",
        148: "encrypt", 149: "decrypt", 150: "hash", 151: "md5",
        152: "sha", 153: "random", 154: "srand", 155: "time",
        156: "socket", 157: "connect", 158: "send", 159: "recv",
        160: "read", 161: "write", 162: "open", 163: "close",
        164: "mmap", 165: "mprotect", 166: "signal", 167: "sigaction",
        168: "dlopen", 169: "dlsym", 170: "getenv", 171: "setuid",
        172: "chmod", 173: "chown", 174: "exec", 175: "popen",
        176: "strcpy", 177: "strcat", 178: "strlen", 179: "strstr",
        180: "memcpy", 181: "memmove", 182: "memset", 183: "calloc",
        184: "realloc", 185: "atoi", 186: "strtol", 187: "sscanf",
        188: "fgets", 189: "gets", 190: "puts", 191: "getchar",
    }
    for idx, pattern in _PATTERN_MAP.items():
        if pattern in all_strings:
            features[idx] = 1.0

    # ------------------------------------------------------------------
    # Challenge type features (dims 192-223)
    # ------------------------------------------------------------------
    _TYPE_MAP = {
        "constraint": 192, "crypto": 193, "dynamic": 194, "keygen": 195,
        "pwn": 196, "forensics": 197, "web": 198, "steg": 199,
        "misc": 200, "rev": 201, "scripting": 202, "dotnet": 203,
        "firmware": 204, "mobile": 205, "blockchain": 206, "osint": 207,
        "network": 208, "binary": 209, "heap": 210, "kernel": 211,
        "format_string": 212, "rop": 213, "shellcode": 214, "race": 215,
    }
    challenge_type = str(state.get("challenge_type", "")).lower()
    if challenge_type in _TYPE_MAP:
        features[_TYPE_MAP[challenge_type]] = 1.0

    # Category (may differ from challenge_type)
    category = str(state.get("category", "")).lower()
    if category in _TYPE_MAP and category != challenge_type:
        features[_TYPE_MAP[category]] = 0.5  # Half weight for category

    # Secondary types
    for st in (state.get("secondary_types") or []):
        st_lower = str(st).lower()
        if st_lower in _TYPE_MAP:
            features[_TYPE_MAP[st_lower]] = max(features[_TYPE_MAP[st_lower]], 0.3)

    # ------------------------------------------------------------------
    # Crypto / extracted param indicators (dims 224-287)
    # ------------------------------------------------------------------
    extracted_params = state.get("extracted_params") or {}

    # Crypto indicators from param extraction
    crypto_indicators = extracted_params.get("crypto_indicators") or []
    for i, indicator in enumerate(crypto_indicators[:32]):
        # Hash-based feature -- spreads indicators across the subspace
        h = hashlib.md5(str(indicator).encode()).digest()
        features[224 + i] = (h[0] + h[1] * 256) / 65535.0

    # Extracted param types (256-271)
    _PARAM_TYPES = {
        "ciphertext": 256, "key": 257, "iv": 258, "nonce": 259,
        "modulus": 260, "exponent": 261, "prime": 262, "generator": 263,
        "salt": 264, "rounds": 265, "block_size": 266, "mode": 267,
        "padding": 268, "mac": 269, "signature": 270, "certificate": 271,
    }
    for param_key in extracted_params:
        pk_lower = param_key.lower()
        for ptype, idx in _PARAM_TYPES.items():
            if ptype in pk_lower:
                features[idx] = 1.0

    # Constraint data presence (272-287)
    if extracted_params.get("constraints"):
        features[272] = 1.0
    if extracted_params.get("lookup_table") or extracted_params.get("sbox"):
        features[273] = 1.0
    if extracted_params.get("encoded_flag") or extracted_params.get("ciphertext"):
        features[274] = 1.0
    if extracted_params.get("comparison_values"):
        features[275] = 1.0
    if extracted_params.get("transformation_chain"):
        features[276] = 1.0
    if extracted_params.get("xor_key"):
        features[277] = 1.0
    if extracted_params.get("seed"):
        features[278] = 1.0
    if extracted_params.get("modular_arithmetic"):
        features[279] = 1.0

    # ------------------------------------------------------------------
    # Solve path & timing features (dims 288-319)
    # ------------------------------------------------------------------
    solve_path = state.get("solve_path") or []
    node_timings = state.get("node_timings") or []

    # Path length
    features[288] = min(len(solve_path) / 20.0, 1.0)

    # Node presence in solve path
    _NODE_MAP = {
        "triage": 289, "unpack": 290, "decompile": 291, "normalize": 292,
        "classify": 293, "specialist_fanout": 294, "param_extraction": 295,
        "tool_router": 296, "flag_validator": 297, "solve_engine": 298,
        "manager": 299, "context_compressor": 300,
    }
    for node in solve_path:
        if node in _NODE_MAP:
            features[_NODE_MAP[node]] = 1.0

    # Timing features
    total_time = sum(t.get("duration_s", 0) for t in node_timings)
    features[305] = min(total_time / 300.0, 1.0)  # Normalized to 5 min

    # Iteration count
    features[306] = min(state.get("iteration_count", 0) / 50.0, 1.0)

    # Number of strategies tried
    strategies = state.get("strategies_tried") or []
    features[307] = min(len(strategies) / 10.0, 1.0)

    # Elapsed seconds (from benchmark results)
    elapsed = state.get("elapsed_seconds", 0)
    if elapsed:
        features[308] = min(elapsed / 300.0, 1.0)

    # ------------------------------------------------------------------
    # Decompilation signature features (dims 320-351)
    # ------------------------------------------------------------------
    decompiled = state.get("decompiled_functions") or {}

    # Number of decompiled functions
    features[320] = min(len(decompiled) / 50.0, 1.0)

    # Function name pattern detection
    func_names = " ".join(decompiled.keys()).lower() if decompiled else ""
    _FUNC_PATTERNS = {
        321: "main", 322: "check", 323: "verify", 324: "encrypt",
        325: "decrypt", 326: "encode", 327: "decode", 328: "transform",
        329: "validate", 330: "compare", 331: "hash", 332: "init",
        333: "process", 334: "generate", 335: "compute", 336: "solve",
    }
    for idx, pattern in _FUNC_PATTERNS.items():
        if pattern in func_names:
            features[idx] = 1.0

    # Decompiled code size (total characters across all functions)
    total_code = sum(len(str(v)) for v in decompiled.values())
    features[340] = min(total_code / 50000.0, 1.0)

    # ------------------------------------------------------------------
    # Reserved / hash-based features (dims 352-383)
    # ------------------------------------------------------------------
    # Challenge description hash -- captures semantic similarity via
    # deterministic projection of the description string
    desc = state.get("challenge_description", "") or ""
    if desc:
        desc_hash = hashlib.sha256(desc.encode("utf-8")).digest()
        for i in range(16):
            features[352 + i] = desc_hash[i] / 255.0

    # Flag format hash
    flag_fmt = state.get("flag_format", "") or ""
    if flag_fmt:
        fmt_hash = hashlib.sha256(flag_fmt.encode("utf-8")).digest()
        for i in range(8):
            features[368 + i] = fmt_hash[i] / 255.0

    # Challenge ID hash (for deduplication detection)
    cid = state.get("challenge_id", "") or ""
    if cid:
        cid_hash = hashlib.sha256(cid.encode("utf-8")).digest()
        for i in range(8):
            features[376 + i] = cid_hash[i] / 255.0

    return features


def embed_challenge_compact(state: dict[str, Any]) -> list[float]:
    """Generate a compact 64-dim feature vector for tool performance indexing.

    Uses the most discriminating dimensions from the full 384-dim vector.
    """
    full = embed_challenge(state)

    # Select most informative dimensions:
    # arch (0-3), protections (10-14), format (20-22),
    # file types (64-73), string patterns (128-141),
    # challenge type (192-203), crypto (256-263),
    # solve path (288-296), decompiled (320-325)
    indices = (
        list(range(0, 4))       # 4: arch
        + list(range(10, 15))   # 5: protections
        + list(range(20, 23))   # 3: format
        + list(range(64, 74))   # 10: file types
        + list(range(128, 142)) # 14: key strings
        + list(range(192, 204)) # 12: challenge types
        + list(range(256, 264)) # 8: crypto params
        + list(range(288, 296)) # 8: solve path
    )
    return [full[i] for i in indices[:64]]
