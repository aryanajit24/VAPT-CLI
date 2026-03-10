from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any


SECRET_RULES: list[tuple[str, str, str]] = [
    (r"AKIA[A-Z0-9]{16}", "AWS Access Key", "critical"),
    (r"(?:aws_secret_access_key|AWS_SECRET)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})", "AWS Secret Key", "critical"),
    (r"AIza[a-zA-Z0-9_-]{35}", "Google API Key", "high"),
    (r"[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com", "Google OAuth Client ID", "medium"),
    (r"sk_live_[a-zA-Z0-9]{24,}", "Stripe Secret Key", "critical"),
    (r"pk_live_[a-zA-Z0-9]{24,}", "Stripe Publishable Key", "medium"),
    (r"rk_live_[a-zA-Z0-9]{24,}", "Stripe Restricted Key", "high"),
    (r"gh[ps]_[A-Za-z0-9_]{36,}", "GitHub Token", "critical"),
    (r"glpat-[A-Za-z0-9_-]{20,}", "GitLab Token", "critical"),
    (r"xox[bpors]-[0-9]{10,}-[a-zA-Z0-9-]+", "Slack Token", "critical"),
    (r"SG\.[a-zA-Z0-9_.-]{22,}\.[a-zA-Z0-9_.-]{22,}", "SendGrid API Key", "high"),
    (r"SK[a-f0-9]{32}", "Twilio API Key", "high"),
    (r"AC[a-f0-9]{32}", "Twilio Account SID", "medium"),
    (r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "Private Key", "critical"),
    (r"Bearer\s+eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+", "JWT Token", "high"),
    (r"(?:mongodb(?:\+srv)?://)[^\s'\"]+", "MongoDB Connection String", "critical"),
    (r"(?:postgres|mysql|mssql)://[^\s'\"]+", "Database Connection String", "critical"),
    (r"(?:redis|amqp)://[^\s'\"]+", "Service Connection String", "high"),
    (r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+", "JWT Token (standalone)", "high"),
    (r"(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})['\"]", "Hardcoded Password", "high"),
    (r"(?:secret|token|api_key|apikey|api-key)\s*[=:]\s*['\"]([a-zA-Z0-9_/+=.:-]{16,})['\"]", "Hardcoded Secret", "high"),
    (r"https?://[^/]*\.s3\.amazonaws\.com", "S3 Bucket URL", "medium"),
    (r"https?://storage\.googleapis\.com/[a-zA-Z0-9._-]+", "GCS Bucket URL", "medium"),
    (r"(?:heroku_api_key|HEROKU_API)\s*[=:]\s*['\"]?([a-f0-9-]{36})", "Heroku API Key", "critical"),
    (r"(?:DO_API_KEY|DIGITALOCEAN_TOKEN)\s*[=:]\s*['\"]?([a-f0-9]{64})", "DigitalOcean Token", "critical"),
]

SAST_RULES: list[dict[str, Any]] = [
    {
        "id": "CODE-001",
        "title": "SQL Injection (String Concatenation)",
        "pattern": r"""(?:execute|cursor\.execute|query|raw|rawQuery)\s*\(\s*[f'"].*(?:\+|\.format|\{)""",
        "languages": ["python", "java", "javascript", "php", "ruby"],
        "severity": "critical",
        "remediation": "Use parameterized queries or prepared statements instead of string concatenation.",
    },
    {
        "id": "CODE-002",
        "title": "Command Injection",
        "pattern": r"""(?:os\.system|os\.popen|subprocess\.call|subprocess\.Popen|subprocess\.run|exec|eval|child_process\.exec)\s*\(.*(?:\+|\.format|f['\"]|\{|\$)""",
        "languages": ["python", "javascript", "ruby", "php"],
        "severity": "critical",
        "remediation": "Use subprocess with argument lists. Never pass user input to shell commands.",
    },
    {
        "id": "CODE-003",
        "title": "Insecure Deserialization",
        "pattern": r"""(?:pickle\.loads?|yaml\.load\s*\([^)]*(?!Loader)|Marshal\.load|unserialize|readObject|JSON\.parse\([^)]*\beval\b)""",
        "languages": ["python", "ruby", "php", "java", "javascript"],
        "severity": "high",
        "remediation": "Use safe deserialization (yaml.safe_load, JSON). Never deserialize untrusted data.",
    },
    {
        "id": "CODE-004",
        "title": "Path Traversal",
        "pattern": r"""(?:open|read_file|File\.read|fopen|file_get_contents|readFile)\s*\(.*(?:request|params|input|query|args|user)""",
        "languages": ["python", "ruby", "php", "javascript", "java"],
        "severity": "high",
        "remediation": "Validate and sanitize file paths. Use allowlists for permitted directories.",
    },
    {
        "id": "CODE-005",
        "title": "Cross-Site Scripting (XSS) via Template",
        "pattern": r"""(?:\|safe\b|mark_safe|dangerouslySetInnerHTML|innerHTML\s*=|v-html\s*=|\{\{\{|\{!!|<%-)""",
        "languages": ["python", "javascript", "ruby", "php", "html"],
        "severity": "high",
        "remediation": "Use auto-escaping templates. Sanitize HTML output with DOMPurify or equivalent.",
    },
    {
        "id": "CODE-006",
        "title": "Weak Cryptography",
        "pattern": r"""(?:MD5|SHA1|DES|RC4|md5|sha1|des|rc4)\s*[\(.]""",
        "languages": ["python", "java", "javascript", "php", "ruby"],
        "severity": "medium",
        "remediation": "Use SHA-256+ for hashing, AES-256 for encryption. Use bcrypt/argon2 for passwords.",
    },
    {
        "id": "CODE-007",
        "title": "Hardcoded IP Address",
        "pattern": r"""\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b""",
        "languages": ["*"],
        "severity": "low",
        "remediation": "Move IP addresses to configuration files or environment variables.",
    },
    {
        "id": "CODE-008",
        "title": "Debug Code Left in Production",
        "pattern": r"""(?:console\.log|print\(|debugger;|binding\.pry|import\s+pdb|breakpoint\(\)|System\.out\.println)""",
        "languages": ["python", "javascript", "ruby", "java"],
        "severity": "low",
        "remediation": "Remove debug statements before deploying to production.",
    },
    {
        "id": "CODE-009",
        "title": "Insecure Random Number Generation",
        "pattern": r"""(?:Math\.random|random\.random|rand\(\)|srand\(|Random\(\)|SecureRandom\b.*\.nextInt\b)""",
        "languages": ["python", "javascript", "java", "ruby", "php"],
        "severity": "medium",
        "remediation": "Use cryptographically secure random: secrets module (Python), crypto.randomBytes (Node).",
    },
    {
        "id": "CODE-010",
        "title": "Server-Side Request Forgery (SSRF)",
        "pattern": r"""(?:requests\.get|urllib\.request|fetch|http\.get|curl_exec|HttpClient)\s*\(.*(?:request|params|input|query|args|user|url)""",
        "languages": ["python", "javascript", "php", "java", "ruby"],
        "severity": "high",
        "remediation": "Validate and restrict URLs. Block requests to internal/private IP ranges.",
    },
    {
        "id": "CODE-011",
        "title": "Missing CSRF Protection",
        "pattern": r"""(?:@csrf_exempt|csrf_protect\s*=\s*False|verify_csrf\s*=\s*false)""",
        "languages": ["python", "javascript", "ruby"],
        "severity": "medium",
        "remediation": "Enable CSRF protection on all state-changing endpoints.",
    },
    {
        "id": "CODE-012",
        "title": "Insecure File Upload",
        "pattern": r"""(?:\.save\(|move_uploaded_file|multer|FileUpload).*(?:(?!mime|content.?type|extension|whitelist|allowlist).)*$""",
        "languages": ["python", "javascript", "php", "java"],
        "severity": "high",
        "remediation": "Validate file extensions, MIME types, and content. Store uploads outside webroot.",
    },
    {
        "id": "CODE-013",
        "title": "Open Redirect",
        "pattern": r"""(?:redirect|location\.href|window\.location|res\.redirect)\s*[\(=].*(?:request|params|query|input|url|next|return)""",
        "languages": ["python", "javascript", "ruby", "php", "java"],
        "severity": "medium",
        "remediation": "Validate redirect URLs against an allowlist. Use relative paths only.",
    },
    {
        "id": "CODE-014",
        "title": "XML External Entity (XXE)",
        "pattern": r"""(?:XMLParser|SAXParser|DocumentBuilder|etree\.parse|xml\.sax|parseString)\s*\(""",
        "languages": ["python", "java", "php"],
        "severity": "high",
        "remediation": "Disable DTD processing and external entity resolution in XML parsers.",
    },
    {
        "id": "CODE-015",
        "title": "CORS Misconfiguration",
        "pattern": r"""(?:Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]?\*|allow_origins\s*=\s*\[?\s*['\"]?\*)""",
        "languages": ["python", "javascript", "java", "ruby", "php"],
        "severity": "medium",
        "remediation": "Restrict CORS origins to trusted domains. Never use wildcard with credentials.",
    },
]

LANGUAGE_EXTENSIONS: dict[str, list[str]] = {
    "python": [".py"],
    "javascript": [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
    "java": [".java"],
    "php": [".php", ".phtml"],
    "ruby": [".rb", ".erb"],
    "html": [".html", ".htm", ".jinja", ".jinja2", ".ejs", ".hbs"],
    "go": [".go"],
    "csharp": [".cs"],
}

FP_INDICATORS = [
    "example", "test", "sample", "dummy", "placeholder",
    "your_api_key", "xxx", "INSERT_", "CHANGE_ME", "<your",
    "mock", "fixture", "spec", "todo", "fixme",
]

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".tox", ".mypy_cache",
    "venv", ".venv", "env", ".env", "dist", "build", "egg-info",
    ".eggs", "vendor", "third_party", "migrations", ".next",
    ".nuxt", "coverage", ".pytest_cache", ".cache",
}

MAX_FILE_SIZE = 2_000_000


class CodeScanner:

    def __init__(self) -> None:
        self.findings: list[dict] = []

    def run(self, target: str) -> dict[str, Any]:
        target_path = Path(target)
        if not target_path.exists():
            return {"findings": [], "error": f"Path not found: {target}"}

        if target_path.is_file():
            self._scan_file(target_path)
        else:
            self._scan_directory(target_path)

        return {"findings": self.findings, "files_scanned": self._files_scanned}

    def _scan_directory(self, directory: Path) -> None:
        self._files_scanned = 0
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
            for filename in files:
                filepath = Path(root) / filename
                if filepath.stat().st_size > MAX_FILE_SIZE:
                    continue
                self._scan_file(filepath)

    def _scan_file(self, filepath: Path) -> None:
        if not hasattr(self, "_files_scanned"):
            self._files_scanned = 0

        try:
            content = filepath.read_text(errors="ignore")
        except OSError:
            return

        dep_names = {"requirements.txt", "package.json", "gemfile", "composer.json", "pom.xml"}
        if filepath.name.lower() in dep_names:
            self._files_scanned += 1
            self._scan_dependency_files(filepath, content)
            return

        ext = filepath.suffix.lower()
        language = self._detect_language(ext)
        if not language:
            return

        self._files_scanned += 1
        self._scan_secrets(content, filepath)
        self._scan_sast(content, filepath, language)
        self._scan_dependency_files(filepath, content)

    def _detect_language(self, ext: str) -> str | None:
        for lang, extensions in LANGUAGE_EXTENSIONS.items():
            if ext in extensions:
                return lang
        return None

    def _scan_secrets(self, content: str, filepath: Path) -> None:
        for pattern, secret_type, severity in SECRET_RULES:
            for match in re.finditer(pattern, content):
                matched_text = match.group(0)

                if any(fp in matched_text.lower() for fp in FP_INDICATORS):
                    continue

                line_num = content[:match.start()].count("\n") + 1
                context = self._get_line_context(content, line_num)

                if self._is_comment_or_test(context, filepath):
                    continue

                self.findings.append({
                    "vuln_id": "SECRET-001",
                    "title": f"{secret_type} Found in Source Code",
                    "severity": severity,
                    "cvss_score": {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.0}.get(severity, 0),
                    "category": "secret_detection",
                    "url": str(filepath),
                    "evidence": (
                        f"File: {filepath}\n"
                        f"Line: {line_num}\n"
                        f"Type: {secret_type}\n"
                        f"Match: {matched_text[:40]}{'...' if len(matched_text) > 40 else ''}\n"
                        f"Context:\n{context}"
                    ),
                    "remediation": (
                        f"Remove the {secret_type} from source code. "
                        "Use environment variables or a secrets manager. "
                        "Rotate the exposed credential immediately."
                    ),
                    "scanner": "codescan",
                    "confidence": 0.9,
                })

    def _scan_sast(self, content: str, filepath: Path, language: str) -> None:
        for rule in SAST_RULES:
            if language not in rule["languages"] and "*" not in rule["languages"]:
                continue

            for match in re.finditer(rule["pattern"], content, re.MULTILINE):
                line_num = content[:match.start()].count("\n") + 1
                context = self._get_line_context(content, line_num)

                if self._is_comment_or_test(context, filepath):
                    continue

                self.findings.append({
                    "vuln_id": rule["id"],
                    "title": rule["title"],
                    "severity": rule["severity"],
                    "cvss_score": {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.0}.get(rule["severity"], 0),
                    "category": "sast",
                    "url": str(filepath),
                    "evidence": (
                        f"File: {filepath}\n"
                        f"Line: {line_num}\n"
                        f"Rule: {rule['id']} — {rule['title']}\n"
                        f"Context:\n{context}"
                    ),
                    "remediation": rule["remediation"],
                    "scanner": "codescan",
                    "confidence": 0.75,
                })

    def _scan_dependency_files(self, filepath: Path, content: str) -> None:
        name = filepath.name.lower()
        dep_files = {
            "requirements.txt": self._check_python_deps,
            "package.json": self._check_npm_deps,
            "gemfile": self._check_ruby_deps,
            "composer.json": self._check_php_deps,
            "pom.xml": self._check_java_deps,
        }
        handler = dep_files.get(name)
        if handler:
            handler(content, filepath)

    def _check_python_deps(self, content: str, filepath: Path) -> None:
        insecure_versions = {
            "django": ("< 4.2", "CVE-2023-43665"),
            "flask": ("< 2.3.0", "CVE-2023-30861"),
            "requests": ("< 2.31.0", "CVE-2023-32681"),
            "urllib3": ("< 2.0.7", "CVE-2023-45803"),
            "cryptography": ("< 41.0.6", "CVE-2023-49083"),
            "pillow": ("< 10.2.0", "CVE-2023-50447"),
            "jinja2": ("< 3.1.3", "CVE-2024-22195"),
        }
        for line in content.splitlines():
            line = line.strip().lower()
            if not line or line.startswith("#"):
                continue
            pkg = re.split(r"[=<>!~]", line)[0].strip().replace("-", "").replace("_", "")
            for name, (ver_constraint, cve) in insecure_versions.items():
                if pkg == name.replace("-", "").replace("_", ""):
                    self.findings.append({
                        "vuln_id": "DEP-001",
                        "title": f"Potentially Vulnerable Dependency: {name}",
                        "severity": "medium",
                        "cvss_score": 5.0,
                        "category": "dependency",
                        "url": str(filepath),
                        "evidence": f"Package: {line}\nKnown vulnerable versions: {ver_constraint}\nReference: {cve}",
                        "remediation": f"Update {name} to the latest version. Check {cve} for details.",
                        "scanner": "codescan",
                        "confidence": 0.6,
                    })

    def _check_npm_deps(self, content: str, filepath: Path) -> None:
        try:
            import json
            data = json.loads(content)
        except (ValueError, ImportError):
            return

        all_deps = {}
        for key in ("dependencies", "devDependencies"):
            all_deps.update(data.get(key, {}))

        insecure = {
            "lodash": ("< 4.17.21", "CVE-2021-23337"),
            "axios": ("< 1.6.0", "CVE-2023-45857"),
            "express": ("< 4.18.2", "CVE-2022-24999"),
            "jsonwebtoken": ("< 9.0.0", "CVE-2022-23529"),
            "minimatch": ("< 3.0.5", "CVE-2022-3517"),
        }
        for pkg, version in all_deps.items():
            if pkg.lower() in insecure:
                ver_constraint, cve = insecure[pkg.lower()]
                self.findings.append({
                    "vuln_id": "DEP-002",
                    "title": f"Potentially Vulnerable npm Package: {pkg}",
                    "severity": "medium",
                    "cvss_score": 5.0,
                    "category": "dependency",
                    "url": str(filepath),
                    "evidence": f"Package: {pkg}@{version}\nKnown vulnerable: {ver_constraint}\nReference: {cve}",
                    "remediation": f"Run `npm audit` and update {pkg}. Check {cve} for details.",
                    "scanner": "codescan",
                    "confidence": 0.6,
                })

    def _check_ruby_deps(self, content: str, filepath: Path) -> None:
        if "rails" in content.lower() and re.search(r"gem\s+['\"]rails['\"].*['\"].*[45]\.", content):
            self.findings.append({
                "vuln_id": "DEP-003",
                "title": "Potentially Outdated Rails Version",
                "severity": "medium",
                "cvss_score": 5.0,
                "category": "dependency",
                "url": str(filepath),
                "evidence": "Older Rails version detected in Gemfile.",
                "remediation": "Update Rails to the latest stable version.",
                "scanner": "codescan",
                "confidence": 0.5,
            })

    def _check_php_deps(self, content: str, filepath: Path) -> None:
        try:
            import json
            data = json.loads(content)
        except (ValueError, ImportError):
            return

        deps = data.get("require", {})
        if "laravel/framework" in deps:
            self.findings.append({
                "vuln_id": "DEP-004",
                "title": "Review Laravel Version for Known Vulnerabilities",
                "severity": "low",
                "cvss_score": 2.0,
                "category": "dependency",
                "url": str(filepath),
                "evidence": f"Laravel: {deps['laravel/framework']}",
                "remediation": "Run `composer audit` to check for known vulnerabilities.",
                "scanner": "codescan",
                "confidence": 0.5,
            })

    def _check_java_deps(self, content: str, filepath: Path) -> None:
        dangerous = [
            ("log4j-core", "CVE-2021-44228", "critical"),
            ("spring-boot", "CVE-2022-22965", "critical"),
            ("jackson-databind", "CVE-2020-36518", "high"),
        ]
        for lib, cve, severity in dangerous:
            if lib in content.lower():
                self.findings.append({
                    "vuln_id": "DEP-005",
                    "title": f"Review {lib} for Known Vulnerabilities ({cve})",
                    "severity": severity,
                    "cvss_score": {"critical": 9.5, "high": 7.5}.get(severity, 5.0),
                    "category": "dependency",
                    "url": str(filepath),
                    "evidence": f"Dependency {lib} found in pom.xml. Reference: {cve}",
                    "remediation": f"Update {lib} to patched version. See {cve}.",
                    "scanner": "codescan",
                    "confidence": 0.7,
                })

    def _get_line_context(self, content: str, line_num: int, context_lines: int = 2) -> str:
        lines = content.splitlines()
        start = max(0, line_num - context_lines - 1)
        end = min(len(lines), line_num + context_lines)
        result = []
        for i in range(start, end):
            marker = ">>>" if i == line_num - 1 else "   "
            result.append(f"  {marker} {i + 1:4d} | {lines[i]}")
        return "\n".join(result)

    def _is_comment_or_test(self, context: str, filepath: Path) -> bool:
        path_str = str(filepath).lower()
        if any(d in path_str for d in ("/test", "/tests", "/spec", "/fixtures", "/__test__")):
            return True

        target_line = ""
        for line in context.splitlines():
            if line.strip().startswith(">>>"):
                target_line = line
                break

        stripped = target_line.lstrip(" >0123456789|")
        if stripped.lstrip().startswith(("#", "//", "/*", "*", "<!--", "'''", '"""')):
            return True

        return False
