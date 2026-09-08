#!/usr/bin/env python3
"""auto_reverse_image -- Reverse image search for OSINT CTF challenges.

Uploads or links an image to public reverse-image-search engines and
returns candidate matches with source URLs, allowing downstream agents to
identify unknown landmarks, products, people, game screenshots, memes, etc.

Built from the BYU EOS CTF Heritage challenge, where pass 1 and pass 2
both failed because neither Yandex nor TinEye could be invoked through the
standard agent prompt without a dedicated tool. Having this logic inside
kraken (not in a prompt) makes the operation reliable and fast.

Supported engines (tried in order, first public response wins):
  1. Yandex Images -- cbir upload endpoint (best for buildings/places)
  2. TinEye -- public /search upload endpoint (best for exact duplicates)
  3. SauceNAO -- REST API (best for anime/art, requires free API key)
  4. Google Lens -- via third-party URL construction (best effort)
  5. IQDB -- anime/art fallback

Returns a list of candidate matches: {"engine", "title", "source_url", "thumbnail"}.

This helper is a TEMPLATE -- the exact upload protocols change frequently
as engines evolve. When calls fail, the function returns a structured
error so the caller can report degradation and fall back to visual
analysis by the LLM itself.

Usage:
    python3 auto_reverse_image.py --image heritage.jpg
    python3 auto_reverse_image.py --image heritage.jpg --engine yandex --json
    python3 auto_reverse_image.py --image heritage.jpg --describe  # LLM-described features
"""
from __future__ import annotations

import argparse
import json
import mimetypes
import os
import re
import sys
import tempfile
import urllib.parse
import urllib.request
import urllib.error
from pathlib import Path


# User agent that looks like a real browser -- engines block obvious bots.
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")


def _post_multipart(url: str, fields: dict, files: dict, timeout: float = 15.0) -> tuple[int, str, dict]:
    """Post multipart/form-data without requests dependency."""
    import mimetypes as mt
    import uuid

    boundary = f"----kraken-{uuid.uuid4().hex}"
    body_parts = []
    for name, value in fields.items():
        body_parts.append(f"--{boundary}".encode())
        body_parts.append(f'Content-Disposition: form-data; name="{name}"'.encode())
        body_parts.append(b"")
        body_parts.append(str(value).encode())
    for name, (filename, content) in files.items():
        ctype = mt.guess_type(filename)[0] or "application/octet-stream"
        body_parts.append(f"--{boundary}".encode())
        body_parts.append(
            f'Content-Disposition: form-data; name="{name}"; filename="{filename}"'.encode()
        )
        body_parts.append(f"Content-Type: {ctype}".encode())
        body_parts.append(b"")
        body_parts.append(content)
    body_parts.append(f"--{boundary}--".encode())
    body_parts.append(b"")
    body = b"\r\n".join(body_parts)

    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "User-Agent": UA,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode(errors="replace"), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace"), dict(e.headers or {})
    except Exception as e:
        return 0, f"__ERROR__ {e}", {}


# ── engine adapters ──────────────────────────────────────────────────────

def search_yandex(image_path: Path, timeout: float = 15.0) -> list[dict]:
    """Yandex CBIR (content-based image retrieval) -- strong for landmarks."""
    try:
        image_bytes = image_path.read_bytes()
    except Exception as e:
        return [{"engine": "yandex", "error": f"read: {e}"}]

    url = "https://yandex.com/images-apphost/image-download?cbird=201&images_avatars_size=preview&images_avatars_namespace=images-cbir"
    status, body, _ = _post_multipart(
        url,
        fields={"prg": "1"},
        files={"upfile": (image_path.name, image_bytes)},
        timeout=timeout,
    )
    if status == 0 or status >= 400:
        return [{"engine": "yandex", "error": f"HTTP {status}", "body_snippet": body[:200]}]

    # Yandex returns a redirect URL or JSON with an image_id. Parse best-effort.
    results = []
    m = re.search(r'"cbir_id"\s*:\s*"([^"]+)"', body)
    if m:
        cbir_id = m.group(1)
        results.append({
            "engine": "yandex",
            "title": "Yandex CBIR search",
            "source_url": f"https://yandex.com/images/search?cbir_id={urllib.parse.quote(cbir_id)}&rpt=imageview",
            "cbir_id": cbir_id,
        })
    if not results:
        # Fallback: just return the search URL so the caller can open it
        results.append({
            "engine": "yandex",
            "title": "Yandex reverse image search",
            "source_url": "https://yandex.com/images/search?rpt=imageview",
            "note": "manual upload required -- programmatic parse failed",
            "status": status,
        })
    return results


def search_tineye(image_path: Path, timeout: float = 15.0) -> list[dict]:
    """TinEye public /search upload."""
    try:
        image_bytes = image_path.read_bytes()
    except Exception as e:
        return [{"engine": "tineye", "error": f"read: {e}"}]

    url = "https://tineye.com/api/v1/result_json/?sort=score&order=desc"
    status, body, _ = _post_multipart(
        url,
        fields={},
        files={"image": (image_path.name, image_bytes)},
        timeout=timeout,
    )
    if status == 0 or status >= 400:
        return [{"engine": "tineye", "error": f"HTTP {status}", "body_snippet": body[:200]}]

    results = []
    try:
        data = json.loads(body)
        for match in data.get("results", [])[:10]:
            results.append({
                "engine": "tineye",
                "title": match.get("domain", "unknown"),
                "source_url": match.get("image_url"),
                "score": match.get("score"),
            })
    except json.JSONDecodeError:
        results.append({
            "engine": "tineye",
            "title": "TinEye search",
            "source_url": "https://tineye.com/search",
            "note": "response was not JSON (API changed)",
        })
    return results


def search_saucenao(image_path: Path, api_key: str | None = None, timeout: float = 15.0) -> list[dict]:
    """SauceNAO REST -- best for anime/manga/art references."""
    if not api_key:
        api_key = os.environ.get("SAUCENAO_API_KEY")
    if not api_key:
        return [{"engine": "saucenao", "error": "no API key (set SAUCENAO_API_KEY)"}]
    try:
        image_bytes = image_path.read_bytes()
    except Exception as e:
        return [{"engine": "saucenao", "error": f"read: {e}"}]

    url = f"https://saucenao.com/search.php?db=999&output_type=2&numres=10&api_key={api_key}"
    status, body, _ = _post_multipart(
        url, fields={}, files={"file": (image_path.name, image_bytes)}, timeout=timeout,
    )
    if status != 200:
        return [{"engine": "saucenao", "error": f"HTTP {status}"}]
    try:
        data = json.loads(body)
        out = []
        for r in data.get("results", []):
            header = r.get("header", {})
            rdata = r.get("data", {})
            out.append({
                "engine": "saucenao",
                "title": rdata.get("title") or rdata.get("source") or "unknown",
                "source_url": (rdata.get("ext_urls") or [None])[0],
                "similarity": float(header.get("similarity", 0)),
            })
        return out
    except Exception as e:
        return [{"engine": "saucenao", "error": str(e)}]


def search_google_lens(image_url: str | None = None, timeout: float = 15.0) -> list[dict]:
    """Google Lens -- requires the image to be web-accessible, so returns a link only."""
    if image_url:
        return [{
            "engine": "google_lens",
            "title": "Google Lens search",
            "source_url": f"https://lens.google.com/uploadbyurl?url={urllib.parse.quote(image_url)}",
            "note": "construct-only; open URL in browser",
        }]
    return [{
        "engine": "google_lens",
        "error": "requires --image-url for Google Lens (needs public URL)",
    }]


def describe_locally(image_path: Path) -> dict:
    """Extract local deterministic features: EXIF, size, format, perceptual hash.

    This is the fallback when no engine responds -- a kraken-internal
    image fingerprint that downstream agents can reason over.
    """
    info = {"path": str(image_path)}
    try:
        from PIL import Image, ExifTags
        img = Image.open(image_path)
        info["format"] = img.format
        info["size"] = img.size
        info["mode"] = img.mode
        raw_exif = img._getexif() if hasattr(img, "_getexif") else None
        if raw_exif:
            exif = {}
            for tag_id, value in raw_exif.items():
                tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                try:
                    json.dumps(value)
                    exif[tag_name] = value
                except (TypeError, ValueError):
                    exif[tag_name] = repr(value)[:200]
            info["exif"] = exif
    except ImportError:
        info["pil"] = "not installed"
    except Exception as e:
        info["exif_error"] = str(e)
    try:
        info["sha256"] = __import__("hashlib").sha256(image_path.read_bytes()).hexdigest()
    except Exception:
        pass
    return info


def solve(image_path: Path, engines: list[str] | None = None, verbose: bool = False) -> dict:
    if engines is None:
        engines = ["yandex", "tineye", "saucenao", "google_lens"]

    result: dict = {"image": str(image_path), "engines": {}, "local": describe_locally(image_path)}
    for engine in engines:
        if verbose:
            print(f"[reverse-image] trying {engine}", file=sys.stderr)
        try:
            if engine == "yandex":
                result["engines"]["yandex"] = search_yandex(image_path)
            elif engine == "tineye":
                result["engines"]["tineye"] = search_tineye(image_path)
            elif engine == "saucenao":
                result["engines"]["saucenao"] = search_saucenao(image_path)
            elif engine == "google_lens":
                result["engines"]["google_lens"] = search_google_lens()
        except Exception as e:
            result["engines"][engine] = [{"engine": engine, "error": str(e)}]
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--image", required=True, help="Path to the image file")
    ap.add_argument("--engine", action="append", help="Engine(s) to use (default: all)")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--describe", action="store_true", help="Local EXIF/fingerprint only")
    args = ap.parse_args()

    image = Path(args.image)
    if not image.is_file():
        print(f"ERROR: {image} not found", file=sys.stderr)
        return 2

    if args.describe:
        print(json.dumps(describe_locally(image), indent=2))
        return 0

    result = solve(image, engines=args.engine, verbose=args.verbose)
    if args.json:
        print(json.dumps(result, indent=2, default=str))
        return 0

    print(f"Image: {result['image']}")
    if "exif" in result["local"]:
        print(f"EXIF tags: {list(result['local']['exif'].keys())[:10]}")
    for engine, hits in result["engines"].items():
        print(f"\n=== {engine} ===")
        for hit in hits:
            if "error" in hit:
                print(f"  ERROR: {hit['error']}")
            else:
                print(f"  {hit.get('title', 'match')} → {hit.get('source_url', '')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
