
from __future__ import annotations

import re
import time
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from requests.exceptions import RequestException

from vapt.utils.helpers import sanitize_target


ACTUATOR_PATHS = [
    "/actuator", "/actuator/", "/actuator/health", "/actuator/health/",
    "/actuator/info", "/actuator/info/", "/actuator/env", "/actuator/env/",
    "/actuator/configprops", "/actuator/beans", "/actuator/mappings",
    "/actuator/metrics", "/actuator/prometheus", "/actuator/threaddump",
    "/actuator/heapdump", "/actuator/loggers", "/actuator/scheduledtasks",
    "/actuator/httptrace", "/actuator/caches", "/actuator/conditions",
    "/actuator/flyway", "/actuator/liquibase", "/actuator/sessions",
    "/actuator/shutdown",
    "/health", "/info", "/env", "/metrics", "/trace", "/dump", "/configprops",
    "/beans", "/mappings", "/autoconfig", "/conditions",
]

ACTUATOR_WAF_BYPASSES = [
    lambda p: p.rstrip("/") + "/",
    lambda p: "/" + p.lstrip("/"),
    lambda p: "/." + p,
    lambda p: p.replace("/", "%2f") if p.count("/") > 1 else p,
    lambda p: "/;" + p.lstrip("/"),
    lambda p: p[0] + p[1:].title() if len(p) > 1 else p,
]

CONFIG_FILES = [
    ("/.env", "INFRA-002"),
    ("/.env.production", "INFRA-002"),
    ("/.env.local", "INFRA-002"),
    ("/.env.development", "INFRA-002"),
    ("/.env.staging", "INFRA-002"),
    ("/.env.backup", "INFRA-002"),
    ("/config.json", "INFRA-002"),
    ("/config.yaml", "INFRA-002"),
    ("/config.yml", "INFRA-002"),
    ("/application.yml", "INFRA-002"),
    ("/application.properties", "INFRA-002"),
    ("/appsettings.json", "INFRA-002"),
    ("/settings.json", "INFRA-002"),
    ("/wp-config.php", "INFRA-002"),
    ("/configuration.php", "INFRA-002"),
    ("/web.config", "INFRA-002"),
    ("/docker-compose.yml", "INFRA-002"),
    ("/docker-compose.yaml", "INFRA-002"),
    ("/.docker-compose.yml", "INFRA-002"),
    ("/Dockerfile", "INFRA-002"),
    ("/.git/HEAD", "INFRA-003"),
    ("/.git/config", "INFRA-003"),
    ("/api/v1", "INFRA-004"),
    ("/apis", "INFRA-004"),
    ("/healthz", "INFRA-004"),
    ("/api/v1/pods", "INFRA-004"),
    ("/api/v1/secrets", "INFRA-004"),
    ("/api/v1/namespaces", "INFRA-004"),
]

ADMIN_PANELS = [
    ("/admin", "INFRA-007"),
    ("/admin/", "INFRA-007"),
    ("/administrator", "INFRA-007"),
    ("/wp-admin", "INFRA-007"),
    ("/console", "INFRA-007"),
    ("/management", "INFRA-007"),
    ("/manager", "INFRA-007"),
    ("/dashboard", "INFRA-007"),
    ("/grafana", "INFRA-007"),
    ("/grafana/login", "INFRA-007"),
    ("/kibana", "INFRA-007"),
    ("/kibana/app", "INFRA-007"),
    ("/jenkins", "INFRA-007"),
    ("/jenkins/login", "INFRA-007"),
    ("/portainer", "INFRA-007"),
    ("/traefik", "INFRA-007"),
    ("/traefik/dashboard", "INFRA-007"),
    ("/prometheus", "INFRA-009"),
    ("/prometheus/graph", "INFRA-009"),
    ("/alertmanager", "INFRA-009"),
    ("/metrics", "INFRA-009"),
    ("/n8n", "INFRA-013"),
    ("/n8n/", "INFRA-013"),
]

DEBUG_ENDPOINTS = [
    ("/phpinfo.php", "INFRA-010"),
    ("/info.php", "INFRA-010"),
    ("/test.php", "INFRA-010"),
    ("/_debug", "INFRA-010"),
    ("/__debug__", "INFRA-010"),
    ("/debug", "INFRA-010"),
    ("/debug/default/view", "INFRA-010"),
    ("/telescope", "INFRA-010"),
    ("/_profiler", "INFRA-010"),
    ("/_debugbar", "INFRA-010"),
    ("/elmah.axd", "INFRA-010"),
    ("/trace", "INFRA-010"),
    ("/server-status", "INFRA-010"),
    ("/server-info", "INFRA-010"),
    ("/.well-known/openid-configuration", "INFRA-010"),
]

DB_PANELS = [
    ("/phpmyadmin/", "INFRA-011"),
    ("/pma/", "INFRA-011"),
    ("/phpMyAdmin/", "INFRA-011"),
    ("/adminer.php", "INFRA-011"),
    ("/adminer/", "INFRA-011"),
    ("/dbadmin/", "INFRA-011"),
    ("/pgadmin/", "INFRA-011"),
    ("/mongoexpress/", "INFRA-011"),
    ("/mongo-express/", "INFRA-011"),
    ("/_utils", "INFRA-011"),
    ("/redis-commander/", "INFRA-011"),
]

BACKUP_FILES = [
    ("/backup.sql", "INFRA-015"),
    ("/dump.sql", "INFRA-015"),
    ("/db.sql", "INFRA-015"),
    ("/database.sql", "INFRA-015"),
    ("/backup.sql.gz", "INFRA-015"),
    ("/backup.tar.gz", "INFRA-015"),
    ("/backup.zip", "INFRA-015"),
    ("/site.tar.gz", "INFRA-015"),
    ("/data.json", "INFRA-015"),
    ("/export.csv", "INFRA-015"),
    ("/db_backup.tar.gz", "INFRA-015"),
]

CONFIG_INDICATORS = [
    r"DB_PASSWORD|DB_HOST|DATABASE_URL",
    r"SECRET_KEY|API_KEY|JWT_SECRET",
    r"AWS_ACCESS_KEY|AWS_SECRET",
    r"STRIPE_.*KEY|SENDGRID",
    r"REDIS_URL|MONGO_URI|POSTGRES",
    r"smtp|mail.*password",
]

GIT_HEAD_PATTERN = re.compile(r"ref:\s+refs/heads/")
GIT_CONFIG_PATTERN = re.compile(r"\[core\]|\[remote")

SPRING_ACTUATOR_PATTERN = re.compile(
    r'"status"\s*:\s*"UP"|"_links"|"activeProfiles"|"beans"|"contexts"',
    re.IGNORECASE,
)

PROMETHEUS_PATTERN = re.compile(
    r"^#\s*(HELP|TYPE)\s+\w+|^\w+\{.*\}\s+[\d.]+",
    re.MULTILINE,
)


class InfraScanner:

    def __init__(
        self,
        session: requests.Session | None = None,
        timeout: int = 10,
        safety_config: dict | None = None,
    ) -> None:
        self.session = session or requests.Session()
        self.timeout = timeout
        self.safety_config = safety_config or {}
        self.findings: list[dict] = []

    def run(self, target: str) -> dict[str, Any]:
        base = sanitize_target(target)
        if not base.startswith("http"):
            base = f"https://{base}"

        self._check_actuator(base)
        self._check_config_files(base)
        self._check_admin_panels(base)
        self._check_debug_endpoints(base)
        self._check_db_panels(base)
        self._check_backup_files(base)
        self._check_source_maps(base)
        self._check_feature_flags(base)

        return {"findings": self.findings}


    def _check_actuator(self, base: str) -> None:
        found_paths: set[str] = set()

        for path in ACTUATOR_PATHS:
            url = urljoin(base, path)
            try:
                resp = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=False)
                if resp.status_code == 200 and self._is_actuator_response(resp.text, path):
                    found_paths.add(path)
                    severity = self._actuator_severity(path)
                    self.findings.append(self._make_finding(
                        vuln_id="INFRA-001",
                        title=f"Spring Boot Actuator Exposed: {path}",
                        severity=severity,
                        url=url,
                        evidence=resp.text[:500],
                        category="infrastructure",
                        remediation=(
                            "Restrict actuator endpoints via management.endpoints.web.exposure.exclude=*. "
                            "Use Spring Security to require authentication for /actuator/**."
                        ),
                    ))
                elif resp.status_code == 403:
                    self._try_actuator_bypass(base, path, found_paths)
            except RequestException:
                continue

    def _try_actuator_bypass(self, base: str, path: str, found_paths: set) -> None:
        for bypass_fn in ACTUATOR_WAF_BYPASSES:
            try:
                bypassed = bypass_fn(path)
                if bypassed in found_paths or bypassed == path:
                    continue
                url = urljoin(base, bypassed)
                resp = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=False)
                if resp.status_code == 200 and self._is_actuator_response(resp.text, path):
                    found_paths.add(bypassed)
                    severity = self._actuator_severity(path)
                    if severity in ("low", "medium"):
                        severity = "high"
                    self.findings.append(self._make_finding(
                        vuln_id="INFRA-006",
                        title=f"WAF Bypass Exposes Actuator: {path} → {bypassed}",
                        severity=severity,
                        url=url,
                        evidence=f"Original path {path} returned 403. Bypass path {bypassed} returned 200.\n\n{resp.text[:500]}",
                        category="infrastructure",
                        remediation=(
                            "Fix path normalization in WAF rules. Block all actuator patterns including "
                            "trailing slashes, double slashes, and encoded paths. Apply server-side access "
                            "control as defense-in-depth."
                        ),
                    ))
                    break
            except RequestException:
                continue

    def _is_actuator_response(self, body: str, path: str) -> bool:
        if not body or len(body) < 5:
            return False

        if "health" in path:
            return '"status"' in body and ("UP" in body or "DOWN" in body)

        if "prometheus" in path or "metrics" in path:
            return bool(PROMETHEUS_PATTERN.search(body))

        if SPRING_ACTUATOR_PATTERN.search(body):
            return True

        if "heapdump" in path:
            return len(body) > 1000

        if any(x in path for x in ("env", "configprops", "beans", "mappings")):
            return "{" in body and "}" in body and len(body) > 50

        return False

    def _actuator_severity(self, path: str) -> str:
        critical = {"env", "configprops", "heapdump", "shutdown", "sessions"}
        high = {"prometheus", "beans", "mappings", "loggers", "httptrace", "threaddump"}
        medium = {"info", "metrics", "caches", "conditions", "flyway", "scheduledtasks"}

        endpoint = path.rstrip("/").split("/")[-1]
        if endpoint in critical:
            return "critical"
        if endpoint in high:
            return "high"
        if endpoint in medium:
            return "medium"
        return "low"


    def _check_config_files(self, base: str) -> None:
        for path, vuln_id in CONFIG_FILES:
            url = urljoin(base, path)
            try:
                resp = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=False)
                if resp.status_code != 200 or len(resp.text) < 10:
                    continue

                if vuln_id == "INFRA-003":
                    if "HEAD" in path and GIT_HEAD_PATTERN.search(resp.text):
                        self.findings.append(self._make_finding(
                            vuln_id="INFRA-003",
                            title="Exposed .git Directory — Source Code Disclosure",
                            severity="high",
                            url=url,
                            evidence=f"Response: {resp.text[:200]}",
                            category="infrastructure",
                            remediation="Block access to .git/ in web server config. Add .git to .htaccess deny rules.",
                        ))
                    elif "config" in path and GIT_CONFIG_PATTERN.search(resp.text):
                        self.findings.append(self._make_finding(
                            vuln_id="INFRA-003",
                            title="Exposed .git/config — Repository Details Disclosed",
                            severity="high",
                            url=url,
                            evidence=f"Response: {resp.text[:300]}",
                            category="infrastructure",
                        ))
                    continue

                if vuln_id == "INFRA-004":
                    if any(kw in resp.text for kw in ('"kind"', '"apiVersion"', '"items"', "pods", "namespaces")):
                        self.findings.append(self._make_finding(
                            vuln_id="INFRA-004",
                            title=f"Kubernetes API Exposed: {path}",
                            severity="critical",
                            url=url,
                            evidence=resp.text[:500],
                            category="infrastructure",
                            remediation="Enable RBAC. Disable anonymous auth. Use network policies to restrict API access.",
                        ))
                    continue

                if self._has_secrets(resp.text):
                    self.findings.append(self._make_finding(
                        vuln_id=vuln_id,
                        title=f"Exposed Configuration File With Secrets: {path}",
                        severity="critical",
                        url=url,
                        evidence=f"File contains secrets/credentials.\n\n{self._redact_secrets(resp.text[:500])}",
                        category="infrastructure",
                        remediation=(
                            "Remove file from web root. Block access in web server config. "
                            "Rotate all exposed credentials immediately."
                        ),
                    ))
                elif self._looks_like_config(resp.text, path):
                    self.findings.append(self._make_finding(
                        vuln_id=vuln_id,
                        title=f"Exposed Configuration File: {path}",
                        severity="medium",
                        url=url,
                        evidence=resp.text[:500],
                        category="infrastructure",
                    ))

            except RequestException:
                continue

    def _has_secrets(self, body: str) -> bool:
        for pattern in CONFIG_INDICATORS:
            if re.search(pattern, body, re.IGNORECASE):
                return True
        return False

    def _looks_like_config(self, body: str, path: str) -> bool:
        if ".env" in path:
            return "=" in body and not "<html" in body.lower()
        if any(path.endswith(ext) for ext in (".json", ".yaml", ".yml")):
            return body.strip().startswith(("{", "[", "---"))
        if path.endswith(".properties"):
            return "=" in body and not "<html" in body.lower()
        if "wp-config" in path:
            return "DB_" in body or "define(" in body
        if "Dockerfile" in path:
            return "FROM " in body
        return False

    def _redact_secrets(self, text: str) -> str:
        lines = []
        for line in text.split("\n"):
            if "=" in line:
                key, _, val = line.partition("=")
                if re.search(r"password|secret|key|token", key, re.IGNORECASE):
                    val = val[:3] + "***REDACTED***"
                lines.append(f"{key}={val}")
            else:
                lines.append(line)
        return "\n".join(lines)


    def _check_admin_panels(self, base: str) -> None:
        for path, vuln_id in ADMIN_PANELS:
            url = urljoin(base, path)
            try:
                resp = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
                if resp.status_code == 200 and len(resp.text) > 100:
                    if self._is_real_panel(resp.text, path):
                        title_map = {
                            "grafana": "Grafana Dashboard",
                            "kibana": "Kibana Dashboard",
                            "jenkins": "Jenkins CI/CD",
                            "portainer": "Portainer Container Manager",
                            "traefik": "Traefik Dashboard",
                            "prometheus": "Prometheus Metrics",
                            "alertmanager": "Alertmanager",
                            "n8n": "n8n Workflow Automation",
                        }
                        panel_name = "Admin Panel"
                        for key, name in title_map.items():
                            if key in path.lower():
                                panel_name = name
                                break

                        needs_auth = self._panel_needs_auth(resp.text)
                        severity = "medium" if needs_auth else "high"

                        self.findings.append(self._make_finding(
                            vuln_id=vuln_id,
                            title=f"Exposed {panel_name}: {path}" + (" (login required)" if needs_auth else " (no auth!)"),
                            severity=severity,
                            url=url,
                            evidence=f"Panel accessible at {url}. Auth required: {needs_auth}",
                            category="infrastructure",
                            remediation="Restrict access to management panels via IP allowlist or VPN. Require strong authentication.",
                        ))
            except RequestException:
                continue

    def _is_real_panel(self, body: str, path: str) -> bool:
        lower = body.lower()
        panel_indicators = [
            "grafana", "kibana", "jenkins", "portainer", "traefik",
            "prometheus", "alertmanager", "phpmyadmin", "adminer", "n8n",
            "login", "sign in", "dashboard", "admin", "management",
        ]
        return any(ind in lower for ind in panel_indicators)

    def _panel_needs_auth(self, body: str) -> bool:
        lower = body.lower()
        auth_indicators = ["login", "sign in", "password", "authenticate", "unauthorized"]
        return any(ind in lower for ind in auth_indicators)


    def _check_debug_endpoints(self, base: str) -> None:
        for path, vuln_id in DEBUG_ENDPOINTS:
            url = urljoin(base, path)
            try:
                resp = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=False)
                if resp.status_code == 200:
                    if self._is_debug_response(resp.text, path):
                        severity = "high" if "phpinfo" in path or "debug" in path else "medium"
                        self.findings.append(self._make_finding(
                            vuln_id=vuln_id,
                            title=f"Exposed Debug Endpoint: {path}",
                            severity=severity,
                            url=url,
                            evidence=resp.text[:500],
                            category="infrastructure",
                            remediation="Disable debug endpoints in production. Remove phpinfo files.",
                        ))
            except RequestException:
                continue

    def _is_debug_response(self, body: str, path: str) -> bool:
        if "phpinfo" in path or "info.php" in path:
            return "PHP Version" in body or "phpinfo()" in body
        if "debug" in path or "profiler" in path or "telescope" in path:
            return len(body) > 200 and not body.strip().startswith("<!DOCTYPE")
        if "server-status" in path:
            return "Apache" in body or "Server Status" in body
        return len(body) > 100


    def _check_db_panels(self, base: str) -> None:
        for path, vuln_id in DB_PANELS:
            url = urljoin(base, path)
            try:
                resp = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
                if resp.status_code == 200 and self._is_real_panel(resp.text, path):
                    self.findings.append(self._make_finding(
                        vuln_id=vuln_id,
                        title=f"Exposed Database Management Panel: {path}",
                        severity="high",
                        url=url,
                        evidence=f"Database admin panel accessible at {url}",
                        category="database",
                        remediation="Remove or restrict access to database management interfaces. Use IP allowlists.",
                    ))
            except RequestException:
                continue


    def _check_backup_files(self, base: str) -> None:
        for path, vuln_id in BACKUP_FILES:
            url = urljoin(base, path)
            try:
                resp = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=False, stream=True)
                if resp.status_code == 200:
                    content_type = resp.headers.get("content-type", "")
                    content_length = int(resp.headers.get("content-length", "0"))
                    if content_length > 1000 and "text/html" not in content_type:
                        self.findings.append(self._make_finding(
                            vuln_id=vuln_id,
                            title=f"Exposed Backup/Dump File: {path} ({content_length} bytes)",
                            severity="critical",
                            url=url,
                            evidence=f"File accessible: {url}\nSize: {content_length} bytes\nType: {content_type}",
                            category="infrastructure",
                            remediation="Remove backup files from web roots. Store backups in secure, non-web-accessible locations.",
                        ))
                resp.close()
            except RequestException:
                continue


    def _check_source_maps(self, base: str) -> None:
        try:
            resp = self.session.get(base, timeout=self.timeout, verify=False)
            if resp.status_code != 200:
                return

            js_urls = re.findall(r'(?:src|href)=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', resp.text)
            js_urls += re.findall(r'//# sourceMappingURL=(\S+)', resp.text)

            checked = set()
            for js_url in js_urls[:20]:
                if js_url.startswith("//"):
                    js_url = "https:" + js_url
                elif not js_url.startswith("http"):
                    js_url = urljoin(base, js_url)

                map_url = js_url.split("?")[0] + ".map"
                if map_url in checked:
                    continue
                checked.add(map_url)

                try:
                    map_resp = self.session.get(map_url, timeout=self.timeout, verify=False, allow_redirects=False)
                    if map_resp.status_code == 200 and self._is_source_map(map_resp.text):
                        size_kb = len(map_resp.text) / 1024
                        self.findings.append(self._make_finding(
                            vuln_id="INFRA-008",
                            title=f"Exposed Source Map ({size_kb:.0f}KB): {urlparse(map_url).path}",
                            severity="medium",
                            url=map_url,
                            evidence=f"Source map accessible at {map_url} ({size_kb:.0f}KB). Full client-side source code disclosed.",
                            category="infrastructure",
                            remediation="Remove source map files from production. Configure build tool to skip .map generation in production.",
                        ))
                except RequestException:
                    continue

        except RequestException:
            pass

    def _is_source_map(self, body: str) -> bool:
        return ('"version"' in body and '"sources"' in body) or ('"mappings"' in body)


    def _check_feature_flags(self, base: str) -> None:
        config_paths = [
            "/config.json", "/config.js", "/settings.json",
            "/app-config.json", "/env.json", "/runtime-config.json",
        ]

        for path in config_paths:
            url = urljoin(base, path)
            try:
                resp = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=False)
                if resp.status_code != 200:
                    continue

                body = resp.text
                ld_match = re.search(r'"(?:clientSideId|launchDarkly[^"]*)"[:\s]+"([a-f0-9]{24})"', body)
                if ld_match:
                    client_id = ld_match.group(1)
                    self.findings.append(self._make_finding(
                        vuln_id="INFRA-012",
                        title=f"LaunchDarkly Client Side ID Exposed: {client_id[:8]}...",
                        severity="medium",
                        url=url,
                        evidence=f"Client ID: {client_id}\nSource: {url}\n\nThis can be used to enumerate all feature flags.",
                        category="infrastructure",
                        remediation="LaunchDarkly client-side IDs are designed to be public, but enumerated flags may reveal internal feature names and business logic.",
                    ))

                if "FEATURE_FLAG" in body.upper() or "feature_toggle" in body.lower():
                    self.findings.append(self._make_finding(
                        vuln_id="INFRA-012",
                        title=f"Feature Flag Configuration Exposed: {path}",
                        severity="low",
                        url=url,
                        evidence=body[:500],
                        category="infrastructure",
                    ))

            except RequestException:
                continue


    def _make_finding(
        self,
        vuln_id: str,
        title: str,
        severity: str,
        url: str,
        evidence: str,
        category: str = "infrastructure",
        remediation: str = "",
    ) -> dict:
        cvss_map = {
            "critical": 9.5, "high": 7.5, "medium": 5.3, "low": 3.1, "info": 0.0,
        }
        return {
            "vuln_id": vuln_id,
            "title": title,
            "severity": severity,
            "cvss_score": cvss_map.get(severity, 0),
            "category": category,
            "url": url,
            "evidence": evidence,
            "remediation": remediation,
            "scanner": "infrascan",
            "confidence": 0.9,
        }
