#!/usr/bin/env python3
"""auto_directory_scan -- Web directory and endpoint discovery for CTF challenges.

Capabilities:
  - Common path brute-force (/admin, /api, /flag, /robots.txt, /.git, etc.)
  - Backup file detection (.bak, .old, ~, .swp, .save)
  - Technology fingerprinting from headers, error pages, and content
  - API endpoint discovery (REST, GraphQL, Swagger/OpenAPI)
  - Virtual host discovery via Host header fuzzing
  - Git repository exposure detection and extraction
  - Source code leak detection (.git, .svn, .DS_Store)

Outputs EXTRACTED FLAG: <flag> on success.
"""
import argparse
import base64
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    from requests.exceptions import ConnectionError, ReadTimeout, Timeout
    _HAS_REQUESTS = True
except ImportError:
    print("[-] requests library required", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Common path wordlists
# ---------------------------------------------------------------------------

# Tier 1: Most likely to contain flags or sensitive info in CTF
PATHS_CTF_PRIORITY = [
    "/flag", "/flag.txt", "/flag.php", "/flag.html",
    "/flags", "/flags.txt",
    "/secret", "/secret.txt", "/secret.php",
    "/hidden", "/hidden.txt",
    "/admin", "/admin/", "/admin/flag", "/admin/index.php",
    "/admin.php", "/admin.html",
    "/login", "/login.php", "/login.html",
    "/api", "/api/", "/api/flag", "/api/v1/flag",
    "/api/v1/", "/api/v2/",
    "/console", "/debug", "/shell",
    "/source", "/src",
]

# Tier 2: Configuration and info disclosure
PATHS_CONFIG = [
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/.env", "/env", "/.env.bak", "/.env.old",
    "/config", "/config.php", "/config.py", "/config.json", "/config.yml",
    "/configuration.php", "/settings.py", "/settings.json",
    "/wp-config.php", "/wp-config.php.bak",
    "/web.config", "/web.xml",
    "/phpinfo.php", "/info.php", "/test.php",
    "/server-status", "/server-info",
    "/.htaccess", "/.htpasswd",
    "/package.json", "/composer.json",
    "/Makefile", "/Dockerfile", "/docker-compose.yml",
    "/Procfile", "/requirements.txt", "/Gemfile",
]

# Tier 3: Version control and IDE artifacts
PATHS_VCS = [
    "/.git/", "/.git/HEAD", "/.git/config",
    "/.git/index", "/.git/COMMIT_EDITMSG",
    "/.git/description", "/.git/logs/HEAD",
    "/.git/refs/heads/main", "/.git/refs/heads/master",
    "/.svn/", "/.svn/entries", "/.svn/wc.db",
    "/.hg/", "/.hg/hgrc",
    "/.DS_Store",
    "/.idea/", "/.vscode/",
    "/.editorconfig",
]

# Tier 4: Backup and development files
PATHS_BACKUP = [
    "/backup", "/backup/", "/backup.zip", "/backup.tar.gz", "/backup.sql",
    "/db.sql", "/dump.sql", "/database.sql",
    "/index.php.bak", "/index.php~", "/index.php.swp", "/index.php.save",
    "/index.php.old", "/index.php.orig",
    "/app.py.bak", "/server.py.bak", "/main.py.bak",
    "/.index.php.swp", "/._index.php",
    "/old/", "/bak/", "/save/",
    "/temp/", "/tmp/", "/test/",
    "/dev/", "/staging/",
]

# Tier 5: Common web app endpoints
PATHS_WEBAPP = [
    "/dashboard", "/profile", "/account", "/user",
    "/register", "/signup", "/auth",
    "/upload", "/uploads/", "/files/", "/static/",
    "/images/", "/img/", "/css/", "/js/",
    "/assets/", "/media/", "/download/",
    "/search", "/redirect",
    "/logout", "/reset", "/forgot",
    "/status", "/health", "/healthz", "/ping",
    "/version", "/about", "/help",
    "/error", "/404", "/500",
]

# Tier 6: API and GraphQL
PATHS_API = [
    "/graphql", "/graphiql", "/playground",
    "/graphql/console",
    "/swagger", "/swagger.json", "/swagger.yaml",
    "/api-docs", "/api-docs/", "/openapi.json",
    "/v1/", "/v2/", "/v3/",
    "/rest/", "/rpc/",
    "/api/users", "/api/admin", "/api/config",
    "/api/debug", "/api/status", "/api/health",
    "/api/login", "/api/register",
    "/actuator", "/actuator/env", "/actuator/health",
    "/actuator/beans", "/actuator/mappings",
    "/metrics", "/prometheus",
]

# Tier 7: Well-known and security
PATHS_WELLKNOWN = [
    "/.well-known/", "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/security.txt",
    "/humans.txt",
    "/favicon.ico",
    "/manifest.json",
    "/service-worker.js",
    "/sw.js",
]

# Technology-specific paths
PATHS_PHP = [
    "/index.php", "/admin.php", "/login.php",
    "/config.php", "/functions.php", "/includes/",
    "/wp-admin/", "/wp-login.php", "/wp-content/",
    "/xmlrpc.php", "/wp-json/",
    "/phpmyadmin/", "/pma/", "/mysql/",
    "/info.php", "/phpinfo.php", "/test.php",
]

PATHS_PYTHON = [
    "/app.py", "/server.py", "/main.py", "/wsgi.py",
    "/flask/", "/django/",
    "/__pycache__/", "/static/", "/templates/",
    "/manage.py", "/settings.py",
]

PATHS_NODEJS = [
    "/app.js", "/server.js", "/index.js",
    "/node_modules/", "/package.json", "/package-lock.json",
    "/.npmrc", "/yarn.lock",
]

ALL_PATHS = (
    PATHS_CTF_PRIORITY + PATHS_CONFIG + PATHS_VCS + PATHS_BACKUP +
    PATHS_WEBAPP + PATHS_API + PATHS_WELLKNOWN + PATHS_PHP +
    PATHS_PYTHON + PATHS_NODEJS
)

# Deduplicate preserving order
_seen_paths = set()
UNIQUE_PATHS = []
for p in ALL_PATHS:
    if p not in _seen_paths:
        _seen_paths.add(p)
        UNIQUE_PATHS.append(p)


# ---------------------------------------------------------------------------
# Flag extraction
# ---------------------------------------------------------------------------

def _extract_flags(text: str, prefix: str = "flag") -> list[str]:
    """Find all flag patterns in text."""
    if not text:
        return []
    patterns = [
        re.compile(rf'{re.escape(prefix)}\{{[A-Za-z0-9_\-\.]+\}}'),
        re.compile(r'[a-zA-Z_]{2,20}\{[^}]{3,100}\}'),
    ]
    flags = []
    seen = set()
    for pat in patterns:
        for m in pat.finditer(text):
            f = m.group(0)
            if f not in seen:
                seen.add(f)
                flags.append(f)
    return flags


# ---------------------------------------------------------------------------
# DirectoryScanner class
# ---------------------------------------------------------------------------

class DirectoryScanner:
    """Web directory and endpoint scanner."""

    def __init__(
        self,
        url: str,
        prefix: str = "flag",
        timeout: int = 10,
        proxy: str | None = None,
        threads: int = 10,
        wordlist: str | None = None,
        extensions: list[str] | None = None,
    ):
        self.base_url = url.rstrip("/")
        self.prefix = prefix
        self.timeout = timeout
        self.threads = threads
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers["User-Agent"] = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        )
        self.extensions = extensions or []
        self.wordlist = wordlist

        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass

        # Results
        self.found_paths: list[dict] = []
        self.found_flags: list[str] = []
        self.technology: dict[str, str] = {}

        # Baseline for 404 detection
        self._baseline_404_len = None
        self._baseline_404_code = None

    def _get(self, url: str) -> requests.Response | None:
        try:
            return self.session.get(url, timeout=self.timeout, allow_redirects=False)
        except (ConnectionError, Timeout, ReadTimeout, Exception):
            return None

    def _is_valid_response(self, resp: requests.Response) -> bool:
        """Determine if response is a real page vs soft-404."""
        if resp.status_code in (404, 410, 501):
            return False
        if resp.status_code in (301, 302, 303, 307, 308):
            return True  # Redirect is interesting
        if resp.status_code in (403,):
            return True  # Forbidden means it exists
        if resp.status_code in (200, 201):
            # Check for soft 404
            if self._baseline_404_len is not None:
                if abs(len(resp.text) - self._baseline_404_len) < 50:
                    return False
            return True
        if resp.status_code in (401,):
            return True  # Auth required means it exists
        return resp.status_code < 400

    def _calibrate_404(self) -> None:
        """Get baseline 404 response for soft-404 detection."""
        resp = self._get(self.base_url + "/kraken_nonexistent_path_42_xyzzy")
        if resp:
            self._baseline_404_code = resp.status_code
            self._baseline_404_len = len(resp.text)

    def _check_for_flags(self, text: str, context: str) -> str | None:
        """Check text for flags."""
        flags = _extract_flags(text, self.prefix)
        if flags:
            for f in flags:
                if f not in self.found_flags:
                    self.found_flags.append(f)
                    print(f"[+] FLAG FOUND at {context}: {f}")
            return flags[0]
        return None

    # -----------------------------------------------------------------------
    # Technology fingerprinting
    # -----------------------------------------------------------------------

    def fingerprint(self) -> None:
        """Identify web technologies from headers and content."""
        print("[*] Fingerprinting target...")
        resp = self._get(self.base_url)
        if resp is None:
            print("[-] Target unreachable")
            return

        # Headers
        server = resp.headers.get("Server", "")
        powered = resp.headers.get("X-Powered-By", "")
        content_type = resp.headers.get("Content-Type", "")

        if server:
            self.technology["server"] = server
            print(f"[*] Server: {server}")
        if powered:
            self.technology["powered_by"] = powered
            print(f"[*] X-Powered-By: {powered}")

        # Framework detection from headers
        for header in resp.headers:
            hl = header.lower()
            if "x-aspnet" in hl:
                self.technology["framework"] = "ASP.NET"
            elif "x-drupal" in hl:
                self.technology["framework"] = "Drupal"
            elif "x-wordpress" in hl:
                self.technology["framework"] = "WordPress"

        # Content-based detection
        body = resp.text[:5000]
        if "wp-content" in body or "wp-includes" in body:
            self.technology["cms"] = "WordPress"
            print("[*] CMS: WordPress")
        elif "Joomla" in body:
            self.technology["cms"] = "Joomla"
            print("[*] CMS: Joomla")
        elif "drupal" in body.lower():
            self.technology["cms"] = "Drupal"
            print("[*] CMS: Drupal")

        # Framework detection from error pages
        error_resp = self._get(self.base_url + "/kraken_trigger_error_42")
        if error_resp:
            error_text = error_resp.text.lower()
            if "flask" in error_text or "werkzeug" in error_text:
                self.technology["framework"] = "Flask"
                print("[*] Framework: Flask/Werkzeug")
            elif "django" in error_text:
                self.technology["framework"] = "Django"
                print("[*] Framework: Django")
            elif "express" in error_text:
                self.technology["framework"] = "Express.js"
                print("[*] Framework: Express.js")
            elif "laravel" in error_text or "symfony" in error_text:
                self.technology["framework"] = "Laravel/Symfony"
                print("[*] Framework: Laravel/Symfony")
            elif "spring" in error_text:
                self.technology["framework"] = "Spring"
                print("[*] Framework: Spring")
            elif "tomcat" in error_text:
                self.technology["server_detail"] = "Tomcat"
                print("[*] Server: Apache Tomcat")

        # Cookie-based detection
        for cookie_name in resp.cookies:
            cn = cookie_name.lower()
            if "phpsessid" in cn:
                self.technology["language"] = "PHP"
            elif "jsessionid" in cn:
                self.technology["language"] = "Java"
            elif "asp.net" in cn:
                self.technology["language"] = "ASP.NET"
            elif "connect.sid" in cn or "session" in cn:
                self.technology["language"] = "Node.js (likely)"

        # Check for flags in the response
        self._check_for_flags(resp.text, self.base_url)

    # -----------------------------------------------------------------------
    # Directory brute-force
    # -----------------------------------------------------------------------

    def _scan_path(self, path: str) -> dict | None:
        """Scan a single path and return result if interesting."""
        url = self.base_url + path
        resp = self._get(url)
        if resp is None:
            return None

        if not self._is_valid_response(resp):
            return None

        result = {
            "path": path,
            "url": url,
            "status": resp.status_code,
            "length": len(resp.text),
            "content_type": resp.headers.get("Content-Type", ""),
        }

        # Check for redirect
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location", "")
            result["redirect"] = location
            # Follow redirect to check for flags
            if location:
                redir_resp = self._get(location if location.startswith("http") else self.base_url + location)
                if redir_resp:
                    self._check_for_flags(redir_resp.text, f"{path} -> {location}")

        # Check for flags in response
        self._check_for_flags(resp.text, path)

        # Check response headers for flags
        for hv in resp.headers.values():
            self._check_for_flags(hv, f"{path} (header)")

        return result

    def scan_paths(self, paths: list[str] | None = None) -> None:
        """Scan multiple paths concurrently."""
        scan_list = paths or UNIQUE_PATHS

        # Add extension variants
        extended = list(scan_list)
        for ext in self.extensions:
            for path in scan_list:
                if not path.endswith("/") and "." not in path.split("/")[-1]:
                    extended.append(f"{path}.{ext}")

        # Load custom wordlist
        if self.wordlist and os.path.isfile(self.wordlist):
            try:
                with open(self.wordlist, "r", errors="replace") as f:
                    for line in f:
                        word = line.strip()
                        if word and not word.startswith("#"):
                            if not word.startswith("/"):
                                word = "/" + word
                            extended.append(word)
                print(f"[*] Loaded custom wordlist: {self.wordlist}")
            except Exception as e:
                print(f"[-] Error loading wordlist: {e}")

        # Deduplicate
        seen = set()
        unique = []
        for p in extended:
            if p not in seen:
                seen.add(p)
                unique.append(p)

        print(f"[*] Scanning {len(unique)} paths with {self.threads} threads...")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._scan_path, path): path for path in unique}
            done_count = 0
            for future in as_completed(futures):
                done_count += 1
                if done_count % 50 == 0:
                    print(f"[*] Progress: {done_count}/{len(unique)}")
                result = future.result()
                if result:
                    self.found_paths.append(result)
                    status = result["status"]
                    length = result["length"]
                    redir = result.get("redirect", "")
                    extra = f" -> {redir}" if redir else ""
                    print(f"[+] {status} {result['path']} ({length} bytes){extra}")

    # -----------------------------------------------------------------------
    # Git exposure detection
    # -----------------------------------------------------------------------

    def check_git_exposure(self) -> str | None:
        """Check for exposed .git directory and try to extract info."""
        print("[*] Checking for git repository exposure...")

        head_resp = self._get(self.base_url + "/.git/HEAD")
        if not head_resp or head_resp.status_code != 200:
            return None

        if "ref:" not in head_resp.text:
            return None

        print("[+] Git repository exposed!")
        ref = head_resp.text.strip()
        print(f"[*] HEAD: {ref}")

        # Try to read common git files
        git_files = [
            "/.git/config",
            "/.git/COMMIT_EDITMSG",
            "/.git/description",
            "/.git/logs/HEAD",
        ]

        for gf in git_files:
            resp = self._get(self.base_url + gf)
            if resp and resp.status_code == 200 and len(resp.text) > 5:
                print(f"[*] {gf}: {resp.text[:200]}")
                flag = self._check_for_flags(resp.text, gf)
                if flag:
                    return flag

        # Try to read the current commit
        ref_match = re.search(r'ref:\s*(.+)', ref)
        if ref_match:
            ref_path = ref_match.group(1).strip()
            resp = self._get(self.base_url + f"/.git/{ref_path}")
            if resp and resp.status_code == 200:
                commit_hash = resp.text.strip()
                print(f"[*] Current commit: {commit_hash}")

                # Try to read the commit object
                if len(commit_hash) == 40:
                    obj_path = f"/.git/objects/{commit_hash[:2]}/{commit_hash[2:]}"
                    resp = self._get(self.base_url + obj_path)
                    if resp and resp.status_code == 200:
                        print(f"[*] Commit object accessible (raw)")

        # Try to read refs for other branches/tags
        refs_paths = [
            "/.git/refs/heads/main", "/.git/refs/heads/master",
            "/.git/refs/heads/develop", "/.git/refs/heads/flag",
            "/.git/refs/tags/",
            "/.git/packed-refs",
        ]
        for rp in refs_paths:
            resp = self._get(self.base_url + rp)
            if resp and resp.status_code == 200 and len(resp.text.strip()) > 5:
                print(f"[*] {rp}: {resp.text.strip()[:100]}")
                flag = self._check_for_flags(resp.text, rp)
                if flag:
                    return flag

        return None

    # -----------------------------------------------------------------------
    # Robots.txt analysis
    # -----------------------------------------------------------------------

    def analyze_robots(self) -> str | None:
        """Parse robots.txt and follow disallowed paths."""
        resp = self._get(self.base_url + "/robots.txt")
        if not resp or resp.status_code != 200:
            return None

        print(f"[*] robots.txt found:\n{resp.text[:500]}")

        flag = self._check_for_flags(resp.text, "/robots.txt")
        if flag:
            return flag

        # Follow disallowed paths
        for m in re.finditer(r'(?:Disallow|Allow):\s*(.+)', resp.text, re.IGNORECASE):
            path = m.group(1).strip()
            if path and path != "/" and path != "*":
                dr = self._get(self.base_url + path)
                if dr and self._is_valid_response(dr):
                    print(f"[+] robots.txt path {path}: {dr.status_code}")
                    flag = self._check_for_flags(dr.text, f"robots.txt:{path}")
                    if flag:
                        return flag

        return None

    # -----------------------------------------------------------------------
    # Virtual host discovery
    # -----------------------------------------------------------------------

    def discover_vhosts(self, domain: str | None = None) -> str | None:
        """Discover virtual hosts via Host header fuzzing."""
        if not domain:
            from urllib.parse import urlparse
            parsed = urlparse(self.base_url)
            domain = parsed.hostname
            if not domain:
                return None

        print(f"[*] Testing virtual hosts for {domain}...")

        # Get baseline response
        baseline = self._get(self.base_url)
        if not baseline:
            return None
        baseline_len = len(baseline.text)

        vhost_prefixes = [
            "admin", "dev", "staging", "test", "api", "flag",
            "secret", "hidden", "internal", "private", "debug",
            "beta", "old", "new", "backup", "mail", "www2",
        ]

        for prefix in vhost_prefixes:
            vhost = f"{prefix}.{domain}"
            try:
                resp = self.session.get(
                    self.base_url,
                    headers={"Host": vhost},
                    timeout=self.timeout,
                    allow_redirects=False,
                )
                if abs(len(resp.text) - baseline_len) > 100:
                    print(f"[+] Virtual host found: {vhost} ({len(resp.text)} bytes)")
                    flag = self._check_for_flags(resp.text, f"vhost:{vhost}")
                    if flag:
                        return flag
            except Exception:
                continue

        return None

    # -----------------------------------------------------------------------
    # Main scan orchestration
    # -----------------------------------------------------------------------

    def full_scan(self) -> str | None:
        """Run complete directory scan workflow."""
        print(f"[*] Target: {self.base_url}")

        # Calibrate 404 detection
        self._calibrate_404()

        # Technology fingerprinting
        self.fingerprint()
        if self.found_flags:
            return self.found_flags[0]

        # Robots.txt
        flag = self.analyze_robots()
        if flag:
            return flag

        # Git exposure
        flag = self.check_git_exposure()
        if flag:
            return flag

        # Main directory scan
        self.scan_paths()
        if self.found_flags:
            return self.found_flags[0]

        # Virtual host discovery
        flag = self.discover_vhosts()
        if flag:
            return flag

        # Backup file variants for discovered pages
        backup_exts = [".bak", ".old", "~", ".swp", ".save", ".orig", ".tmp",
                       ".backup", ".1", ".copy"]
        backup_paths = []
        for result in self.found_paths:
            path = result["path"]
            if "." in path.split("/")[-1]:
                for ext in backup_exts:
                    backup_paths.append(path + ext)
                # Also try without extension
                base = path.rsplit(".", 1)[0]
                for ext in backup_exts:
                    backup_paths.append(base + ext)

        if backup_paths:
            print(f"[*] Scanning {len(backup_paths)} backup file variants...")
            self.scan_paths(backup_paths)
            if self.found_flags:
                return self.found_flags[0]

        return None


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Kraken Directory Scanner -- path brute-force, backup detection, tech fingerprinting",
    )
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--prefix", default="flag", help="Flag prefix (default: flag)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout (default: 10)")
    parser.add_argument("--threads", type=int, default=10, help="Concurrent threads (default: 10)")
    parser.add_argument("--proxy", default=None, help="HTTP proxy (http://127.0.0.1:8080)")
    parser.add_argument("--wordlist", default=None, help="Custom wordlist file")
    parser.add_argument("--extensions", default="", help="Comma-separated extensions to try (e.g., php,html,txt)")
    args = parser.parse_args()

    extensions = [e.strip().lstrip(".") for e in args.extensions.split(",") if e.strip()]

    scanner = DirectoryScanner(
        url=args.url,
        prefix=args.prefix,
        timeout=args.timeout,
        proxy=args.proxy,
        threads=args.threads,
        wordlist=args.wordlist,
        extensions=extensions,
    )

    flag = scanner.full_scan()

    # Summary
    print(f"\n{'='*60}")
    print(f"[*] Scan complete")
    print(f"[*] Found {len(scanner.found_paths)} accessible paths")
    print(f"[*] Technology: {json.dumps(scanner.technology)}")

    if scanner.found_paths:
        print("\n[*] Accessible paths:")
        for result in sorted(scanner.found_paths, key=lambda r: r["status"]):
            status = result["status"]
            length = result["length"]
            redir = result.get("redirect", "")
            extra = f" -> {redir}" if redir else ""
            print(f"    [{status}] {result['path']} ({length} bytes){extra}")

    if flag:
        print(f"\nEXTRACTED FLAG: {flag}")
        sys.exit(0)
    elif scanner.found_flags:
        print(f"\nEXTRACTED FLAG: {scanner.found_flags[0]}")
        sys.exit(0)
    else:
        print("\n[-] No flags found in directory scan", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
