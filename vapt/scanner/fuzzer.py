
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from requests.exceptions import RequestException

from vapt.utils.helpers import sanitize_target


DIR_WORDLIST = [
    "admin", "administrator", "admin-panel", "admin_panel", "admincp",
    "admin1", "admin2", "admin123", "adm", "backend",
    "control", "control-panel", "controlpanel", "cp", "cpanel",
    "dashboard", "dash", "management", "manage", "mgmt",
    "panel", "portal", "superadmin", "sysadmin", "webadmin",
    "login", "signin", "signup", "register", "auth", "authentication",
    "logout", "account", "accounts", "profile", "user", "users",
    "members", "member", "staff", "employee",
    "api", "api-v1", "api-v2", "api/v1", "api/v2",
    "rest", "restapi", "graphql", "gql", "soap", "rpc",
    "webhook", "webhooks", "callback",
    "dev", "development", "staging", "test", "testing",
    "debug", "debugger", "console", "shell", "terminal",
    "logs", "log", "logging", "trace", "profiler",
    "phpinfo", "info", "status", "health", "ping",
    "backup", "backups", "bak", "old", "archive", "archives",
    "temp", "tmp", "cache", "data", "database", "db",
    "sql", "dump", "export", "import",
    "config", "configuration", "conf", "settings", "env",
    "secret", "secrets", "credentials", "creds", "keys", "tokens",
    "private", "hidden", "internal",
    ".git", ".svn", ".hg", ".bzr",
    "src", "source", "build", "dist", "release", "app", "application",
    "public", "static", "assets", "media", "upload", "uploads", "files",
    "phpmyadmin", "pma", "phpmyadmin2", "mysql", "adminer",
    "wp-admin", "wp-login.php", "wp-content", "wordpress",
    "xmlrpc.php", "readme.html", "license.txt",
    "django-admin", "_admin", "admin/doc",
    "actuator", "spring", "console", "h2-console",
    "node_modules", ".env", "package.json",
    "docs", "documentation", "swagger", "openapi", "redoc",
    "api-docs", "swagger-ui", "swagger.json", "openapi.json",
    "aws", "azure", "gcp", "k8s", "kubernetes", "docker",
    "jenkins", "ci", "cd", "gitlab", "github", "bitbucket",
    "sonar", "jira", "confluence",
    "grafana", "kibana", "prometheus", "nagios", "zabbix",
    "monitor", "monitoring", "metrics", "datadog",
]

FILE_EXTENSIONS = [
    ".php", ".php.bak", ".php~", ".php.old",
    ".asp", ".aspx",
    ".jsp", ".jspx",
    ".do", ".action",
    ".html", ".htm",
    ".xml", ".json", ".yaml", ".yml",
    ".bak", ".backup", ".old", ".orig",
    ".zip", ".tar.gz", ".tgz", ".gz", ".7z",
    ".sql", ".db", ".sqlite",
    ".log", ".txt",
    ".config", ".conf", ".cfg",
    ".env", ".key", ".pem", ".crt",
]

HIGH_VALUE_FILES = [
    "/.git/HEAD", "/.git/config", "/.git/COMMIT_EDITMSG",
    "/.svn/entries", "/.svn/wc.db",
    "/.env", "/.env.local", "/.env.production",
    "/config.php", "/configuration.php", "/wp-config.php",
    "/web.config", "/appsettings.json", "/appsettings.Development.json",
    "/application.properties", "/application.yml",
    "/docker-compose.yml", "/docker-compose.yaml",
    "/Dockerfile", "/.dockerignore",
    "/Makefile", "/Gemfile", "/requirements.txt", "/package.json",
    "/phpinfo.php", "/info.php", "/server-status", "/server-info",
    "/.htpasswd", "/.htaccess",
    "/robots.txt", "/sitemap.xml", "/security.txt", "/.well-known/security.txt",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/backup.zip", "/backup.sql", "/backup.tar.gz", "/db.sql",
    "/dump.sql", "/database.sql",
]

PARAM_FUZZ_VALUES = [
    "0", "-1", "99999999", "null", "undefined", "true", "false",
    "%00", "%0a", "%09", "\\x00",
    "A" * 1000, "1" * 1000,
    "0.0", "-0", "2147483647", "2147483648", "-2147483648",
    "%s%s%s%s", "%d%d%d%d",
    "'", '"', "<", ">", ";", "|", "&",
    "1 OR 1=1",
    "[]", "{}", "[[]]",
    "\u0000", "\uFEFF",
]

ACCESSIBLE_STATUS = {200, 201, 206}
REDIRECT_STATUS = {301, 302, 307}


class Fuzzer:

    def __init__(
        self,
        timeout: int = 8,
        max_workers: int = 10,
        extensions: bool = True,
        safety_config: dict | None = None,
        session=None,
    ) -> None:
        self.timeout = timeout
        self.safety_config = safety_config or {}
        max_threads = self.safety_config.get("max_concurrent_threads")
        self.max_workers = min(max_workers, max_threads) if max_threads else max_workers
        self.extensions = extensions
        if session is not None:
            self.session = session
        else:
            self.session = requests.Session()
            self.session.verify = False
            self.session.headers.update({
                "User-Agent": "Mozilla/5.0 (compatible; VAPT-Scanner/2.0; ethical-scan)"
            })

    def run(self, target: str) -> dict[str, Any]:
        target = sanitize_target(target)
        base_url = target if target.startswith(("http://", "https://")) else f"https://{target}"

        results: dict[str, Any] = {
            "target": base_url,
            "category": "fuzzing",
            "paths_tested": 0,
            "findings": [],
        }

        paths = self._build_path_list()
        results["paths_tested"] = len(paths)

        findings = self._bruteforce(base_url, paths)
        results["findings"] += findings

        results["findings"] += self._idor_enum(base_url)

        return results


    def _build_path_list(self) -> list[str]:
        paths: list[str] = list(HIGH_VALUE_FILES)
        for word in DIR_WORDLIST:
            paths.append(f"/{word}")
            paths.append(f"/{word}/")
            if self.extensions:
                for ext in FILE_EXTENSIONS:
                    paths.append(f"/{word}{ext}")

        max_paths = self.safety_config.get("max_fuzz_paths")
        if max_paths and len(paths) > max_paths:
            paths = paths[:max_paths]

        return paths

    def _bruteforce(self, base_url: str, paths: list[str]) -> list[dict]:
        findings: list[dict] = []
        url_base = base_url.rstrip("/")

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            future_to_path = {
                pool.submit(self._probe, url_base + path): path
                for path in paths
            }
            for future in as_completed(future_to_path):
                path = future_to_path[future]
                result = future.result()
                if result:
                    findings.append(result)

        return findings

    def _probe(self, url: str) -> dict | None:
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)

            if resp.status_code not in ACCESSIBLE_STATUS:
                return None

            path = urlparse(url).path
            body = resp.text if resp.text else ""
            body_len = len(resp.content)

            if not self._is_real_content(path, body, body_len, resp):
                return None

            category, vuln_id, severity, cvss = self._classify_path(path, resp)

            request_raw = getattr(self.session, 'last_request', None) or f"GET {url} HTTP/1.1"
            response_raw = getattr(self.session, 'last_response', None) or f"HTTP/1.1 {resp.status_code}"
            body_preview = body[:500]

            return {
                "vuln_id": vuln_id,
                "category": category,
                "title": f"EXPOSED {path}",
                "description": (
                    f"Path {url} returned HTTP {resp.status_code} "
                    f"({body_len} bytes) with accessible content. {self._describe_path(path)}"
                ),
                "severity": severity,
                "cvss_score": cvss,
                "url": url,
                "status_code": resp.status_code,
                "size": body_len,
                "evidence": f"HTTP {resp.status_code} — {body_len} bytes accessible. Content preview: {body_preview[:300]}",
                "request": request_raw,
                "response": response_raw,
                "payload": path,
            }
        except RequestException:
            return None

    def _is_real_content(self, path: str, body: str, body_len: int,
                          resp: "requests.Response") -> bool:
        body_lower = body.lower()
        pl = path.lower()

        if body_len < 10:
            return False

        SOFT_404_PATTERNS = [
            "page not found", "404 not found", "not found",
            "the page you requested", "does not exist",
            "could not be found", "no longer available",
            "resource not found", "nothing here",
        ]
        if any(pat in body_lower for pat in SOFT_404_PATTERNS):
            if body_len < 2000:
                return False

        CDN_BLOCK_PATTERNS = [
            "access denied", "error from cloudfront",
            "attention required", "checking your browser",
            "please wait while", "just a moment",
            "reference #",
            "errors.edgesuite.net",
            "cloudflare", "incapsula",
        ]
        if any(pat in body_lower for pat in CDN_BLOCK_PATTERNS):
            return False

        FRAMEWORK_DEFAULT = [
            "welcome to nginx", "apache2 debian default page",
            "it works!", "iis windows server",
            "congratulations! your new website",
        ]
        if any(pat in body_lower for pat in FRAMEWORK_DEFAULT):
            return False

        if ".git/head" in pl:
            return "ref:" in body_lower or body.strip().startswith("ref:")

        if ".git/config" in pl:
            return "[core]" in body_lower or "[remote" in body_lower

        if pl.endswith(".env") or ".env." in pl:
            return bool(re.search(r'^[A-Z_]+=.+', body, re.MULTILINE))

        if any(ext in pl for ext in [".php", ".py", ".yml", ".yaml", ".json", ".xml"]):
            config_indicators = [
                "password", "secret", "key", "token", "database",
                "db_host", "api_key", "aws_", "private",
                "<?", "import ", "def ", "class ",
                "{", "[",
            ]
            return any(ind in body_lower for ind in config_indicators)

        if any(ext in pl for ext in [".sql", "dump"]):
            return any(kw in body_lower for kw in
                       ["create table", "insert into", "drop table", "alter table"])

        if any(ext in pl for ext in [".zip", ".tar.gz", ".tgz", ".7z", ".gz"]):
            return body_len > 100 and not body_lower.startswith("<!")

        if ".htpasswd" in pl:
            return bool(re.search(r'^\w+:\$', body, re.MULTILINE)) or ":" in body

        if ".htaccess" in pl:
            return any(d in body_lower for d in
                       ["rewriterule", "deny from", "allow from", "authtype", "require"])

        if "server-status" in pl or "server-info" in pl:
            return any(kw in body_lower for kw in
                       ["apache server status", "server version", "scoreboard",
                        "current time", "server uptime", "total accesses"])

        if any(term in pl for term in ["swagger", "openapi", "api-docs"]):
            return any(kw in body_lower for kw in
                       ['"swagger"', '"openapi"', '"paths"', '"info"'])

        if "actuator" in pl:
            return any(kw in body_lower for kw in
                       ['"status"', '"beans"', '"mappings"', '"env"', '"health"'])

        if "phpinfo" in pl or "info.php" in pl:
            return "php version" in body_lower or "phpinfo()" in body_lower

        if any(p in pl for p in ["admin", "panel", "dashboard", "management", "backend"]):
            admin_indicators = [
                "<form", "login", "password", "username",
                "sign in", "log in", "authentication",
                "dashboard", "admin panel",
            ]
            return any(ind in body_lower for ind in admin_indicators)

        if body_len < 100:
            return False

        return True

    @staticmethod
    def _status_label(code: int) -> str:
        return {
            200: "EXPOSED", 201: "EXPOSED", 206: "EXPOSED",
            301: "REDIRECT", 302: "REDIRECT", 307: "REDIRECT",
        }.get(code, str(code))

    @staticmethod
    def _classify_path(
        path: str, resp: requests.Response
    ) -> tuple[str, str, str, float]:
        pl = path.lower()
        body = resp.text.lower() if resp.text else ""

        if any(p in pl for p in [".git", ".svn", ".hg"]):
            return "exposed_file", "FUZZ-002", "critical", 9.1

        if any(p in pl for p in [".env", "secret", "credential", "creds", "private_key",
                                   ".key", ".pem", ".pfx", "password", "passwd"]):
            return "exposed_secret", "FUZZ-002", "critical", 9.1

        if any(p in pl for p in ["backup", ".bak", ".sql", "dump", ".zip",
                                   ".tar.gz", ".tgz", ".old", ".orig"]):
            return "exposed_file", "FUZZ-002", "high", 7.5

        if any(p in pl for p in ["admin", "administrator", "phpmyadmin", "adminer",
                                   "panel", "dashboard", "control", "management", "backend"]):
            return "exposed_admin_panel", "FUZZ-003", "high", 7.5

        if any(p in pl for p in ["debug", "console", "shell", "actuator", "h2-console",
                                   "phpinfo", "server-status", "server-info", "swagger",
                                   "graphiql", "_profiler"]):
            return "exposed_debug_endpoint", "FUZZ-001", "high", 7.5

        return "exposed_file", "FUZZ-001", "medium", 5.3

    @staticmethod
    def _describe_path(path: str) -> str:
        pl = path.lower()
        if ".git" in pl:
            return "Git repository may be downloadable — source code and credential exposure."
        if ".env" in pl:
            return "Environment file may expose DB credentials, API keys, and secrets."
        if any(p in pl for p in ["backup", ".bak", ".sql", "dump"]):
            return "Backup/dump file may expose full database or source code."
        if "admin" in pl or "phpmyadmin" in pl:
            return "Admin panel found — test for default/weak credentials."
        if "swagger" in pl or "openapi" in pl or "api-docs" in pl:
            return "API specification exposed — maps all endpoints and parameters."
        if "actuator" in pl:
            return "Spring Boot actuator exposed — may leak env vars, heapdump, or allow shutdown."
        if "debug" in pl or "console" in pl:
            return "Debug/console endpoint — may allow code execution."
        return "Unexpected resource found."


    def _idor_enum(self, base_url: str) -> list[dict]:
        findings: list[dict] = []
        idor_paths = [
            "/api/v1/users/{id}", "/api/v2/users/{id}", "/api/users/{id}",
            "/api/v1/orders/{id}", "/api/orders/{id}",
            "/api/v1/accounts/{id}", "/api/accounts/{id}",
            "/api/v1/files/{id}", "/api/files/{id}",
            "/api/v1/documents/{id}", "/api/documents/{id}",
            "/user/{id}", "/account/{id}", "/profile/{id}",
        ]
        test_ids = [1, 2, 3, 100, 1000]

        for path_template in idor_paths:
            responses: list[tuple[int, int, int]] = []
            for test_id in test_ids:
                url = base_url.rstrip("/") + path_template.format(id=test_id)
                try:
                    resp = self.session.get(url, timeout=self.timeout)
                    responses.append((test_id, resp.status_code, len(resp.content)))
                except RequestException:
                    pass

            ok_responses = [(i, s, b) for i, s, b in responses if s == 200]
            if len(ok_responses) >= 2:
                body_sizes = {b for _, _, b in ok_responses}
                if len(body_sizes) > 1:
                    example_url = base_url.rstrip("/") + path_template.format(id=1)
                    findings.append({
                        "vuln_id": "FUZZ-004",
                        "category": "access_control",
                        "title": f"IDOR — sequential ID enumeration at {path_template}",
                        "description": (
                            f"Endpoint {path_template} returns different objects for IDs "
                            f"{[i for i,_,_ in ok_responses]}. "
                            "No per-record access control — any authenticated user can access others' data."
                        ),
                        "severity": "high",
                        "cvss_score": 8.1,
                        "url": example_url,
                        "ids_tested": [i for i, _, _ in ok_responses],
                    })

        return findings
