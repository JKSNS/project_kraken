"""Web specialist -- web application analysis and exploit strategy.

Handles web CTF challenges: XSS, SQLi, SSRF, SSTI, path traversal,
authentication bypass, and other OWASP-class vulnerabilities.
Deterministic tech stack detection + LLM-guided exploit strategy.
"""
from __future__ import annotations

import json
import re

from kraken.state import KrakenState
from kraken.models import direct_generate
from kraken.config import ModelConfig
from kraken.logging.structured import get_logger

log = get_logger(__name__)


def _detect_web_tech(
    challenge_files: dict, strings: list[str], description: str
) -> dict:
    """Deterministic web technology and vulnerability surface detection."""
    tech: dict = {
        "server_tech": [],
        "frameworks": [],
        "languages": [],
        "vuln_indicators": [],
        "endpoints": [],
        "auth_mechanisms": [],
        "input_points": [],
        "file_types": {},
    }

    all_text = description.lower()

    # Analyze challenge files
    for fname, finfo in challenge_files.items():
        ext = fname.rsplit(".", 1)[-1].lower() if "." in fname else ""
        tech["file_types"][ext] = tech["file_types"].get(ext, 0) + 1
        preview = str(finfo.get("content_preview", "")).lower()

        # Server technology detection
        if ext == "py":
            tech["languages"].append("python")
            if "flask" in preview or "from flask" in preview:
                tech["frameworks"].append("Flask")
            if "django" in preview:
                tech["frameworks"].append("Django")
            if "fastapi" in preview:
                tech["frameworks"].append("FastAPI")
            if "bottle" in preview:
                tech["frameworks"].append("Bottle")

        if ext == "js":
            tech["languages"].append("javascript")
            if "express" in preview:
                tech["frameworks"].append("Express.js")
            if "koa" in preview:
                tech["frameworks"].append("Koa")

        if ext == "php":
            tech["languages"].append("php")
            tech["frameworks"].append("PHP")

        if ext == "rb":
            tech["languages"].append("ruby")
            if "sinatra" in preview:
                tech["frameworks"].append("Sinatra")

        if ext in ("html", "htm"):
            tech["languages"].append("html")

        if ext in ("sql", "db", "sqlite"):
            tech["vuln_indicators"].append("database_files_exposed")

        # Vulnerability indicators in source
        if "eval(" in preview or "exec(" in preview:
            tech["vuln_indicators"].append("code_injection")
        if "render_template_string" in preview or "jinja" in preview:
            tech["vuln_indicators"].append("ssti_possible")
        if "sqlite" in preview or "execute(" in preview or "cursor" in preview:
            tech["vuln_indicators"].append("sql_injection_possible")
        if "innerHTML" in preview or "document.write" in preview:
            tech["vuln_indicators"].append("xss_dom")
        if "pickle.loads" in preview or "yaml.load" in preview:
            tech["vuln_indicators"].append("deserialization")
        if "os.system" in preview or "subprocess" in preview:
            tech["vuln_indicators"].append("command_injection")
        if "redirect" in preview or "url_for" in preview:
            tech["vuln_indicators"].append("open_redirect_possible")
        if "open(" in preview and ("filename" in preview or "path" in preview):
            tech["vuln_indicators"].append("path_traversal_possible")
        if "jwt" in preview or "token" in preview:
            tech["auth_mechanisms"].append("JWT")
        if "session" in preview or "cookie" in preview:
            tech["auth_mechanisms"].append("session_cookie")
        if "bcrypt" in preview or "hashlib" in preview:
            tech["auth_mechanisms"].append("password_hash")

        # Endpoint extraction from source
        route_patterns = [
            r"""@app\.(?:route|get|post)\s*\(\s*['"]([^'"]+)""",
            r"""app\.(?:get|post|put|delete)\s*\(\s*['"]([^'"]+)""",
            r"""router\.(?:get|post|put|delete)\s*\(\s*['"]([^'"]+)""",
        ]
        for pattern in route_patterns:
            for match in re.finditer(pattern, str(finfo.get("content_preview", ""))):
                tech["endpoints"].append(match.group(1))

    # Input points from description
    if "upload" in all_text:
        tech["input_points"].append("file_upload")
    if "login" in all_text or "register" in all_text:
        tech["input_points"].append("auth_form")
    if "search" in all_text or "query" in all_text:
        tech["input_points"].append("search_field")
    if "comment" in all_text or "post" in all_text:
        tech["input_points"].append("user_content")
    if "api" in all_text:
        tech["input_points"].append("api_endpoint")
    if "admin" in all_text:
        tech["input_points"].append("admin_panel")

    # Server hints from strings
    for s in strings:
        s_lower = s.lower()
        if "nginx" in s_lower:
            tech["server_tech"].append("nginx")
        if "apache" in s_lower:
            tech["server_tech"].append("apache")
        if "gunicorn" in s_lower or "werkzeug" in s_lower:
            tech["server_tech"].append("gunicorn/werkzeug")

    # Deduplicate
    for key in ("server_tech", "frameworks", "languages", "vuln_indicators",
                "endpoints", "auth_mechanisms", "input_points"):
        tech[key] = list(dict.fromkeys(tech[key]))

    return tech


async def web_specialist(state: KrakenState) -> dict:
    """Analyze web challenge for vulnerabilities and generate exploit strategy."""
    challenge_files = state.get("challenge_files", {})
    strings = state.get("strings_of_interest", [])
    description = state.get("challenge_description", "")
    remote_info = state.get("remote_info", {})

    log.info("web_specialist_start")

    # Deterministic tech detection
    web_tech = _detect_web_tech(challenge_files, strings, description)

    # Build source code context from challenge files
    source_previews = {}
    for fname, finfo in list(challenge_files.items())[:5]:
        preview = finfo.get("content_preview", "")
        if preview:
            source_previews[fname] = preview[:3000]

    host = remote_info.get("host", "localhost")
    port = remote_info.get("port", "")
    url_base = f"http://{host}:{port}" if port else f"http://{host}"

    prompt = f"""Analyze this web CTF challenge and develop an exploit strategy.

## Target: {url_base}
## Description: {description}

## Technology Stack
- Server: {web_tech['server_tech']}
- Frameworks: {web_tech['frameworks']}
- Languages: {web_tech['languages']}
- Auth: {web_tech['auth_mechanisms']}

## Vulnerability Indicators
{json.dumps(web_tech['vuln_indicators'], indent=2)}

## Endpoints Found
{json.dumps(web_tech['endpoints'], indent=2)}

## Input Points
{json.dumps(web_tech['input_points'], indent=2)}

## Source Code
{json.dumps(source_previews, indent=2)}

Identify:
1. The primary vulnerability class (SQLi, XSS, SSTI, SSRF, path traversal, etc.)
2. The specific exploit vector (which endpoint, which parameter)
3. Step-by-step exploit approach
4. Python exploit script approach (using requests library)

Respond with JSON:
{{
    "vuln_class": "sqli|xss|ssti|ssrf|path_traversal|command_injection|deserialization|auth_bypass|other",
    "target_endpoint": "/endpoint",
    "target_parameter": "param_name",
    "exploit_approach": "step-by-step description",
    "payload_example": "example payload",
    "script_hints": "what the solve script should do",
    "notes": "additional observations"
}}"""

    cfg = ModelConfig()
    content = await direct_generate(prompt, "mid", cfg)

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

    analysis["web_tech"] = web_tech

    log.info(
        "web_specialist_complete",
        frameworks=web_tech["frameworks"],
        vulns=web_tech["vuln_indicators"],
        vuln_class=analysis.get("vuln_class", "unknown"),
    )

    # Build strategy summary
    parts = [f"Web: {analysis.get('vuln_class', 'unknown')}"]
    if analysis.get("target_endpoint"):
        parts.append(f"Endpoint: {analysis['target_endpoint']}")
    if analysis.get("target_parameter"):
        parts.append(f"Param: {analysis['target_parameter']}")
    if web_tech["frameworks"]:
        parts.append(f"Framework: {', '.join(web_tech['frameworks'][:2])}")
    strategy = " | ".join(parts)

    return {
        "strategy_hypothesis": strategy,
        "angr_results": {
            **(state.get("angr_results", {})),
            "web_analysis": analysis,
        },
        "recent_actions": [{
            "action": "web_specialist",
            "reasoning": f"Web analysis: {analysis.get('vuln_class', 'unknown')}",
            "result_summary": strategy,
        }],
        "iteration_count": state.get("iteration_count", 0) + 1,
    }
