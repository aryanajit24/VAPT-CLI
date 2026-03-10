
from __future__ import annotations

import re
import socket
import time
from typing import Any
from urllib.parse import urljoin

import requests
from requests.exceptions import RequestException

from vapt.utils.helpers import sanitize_target


DEFAULT_CREDS = {
    "mysql": [
        ("root", ""), ("root", "root"), ("root", "password"),
        ("root", "mysql"), ("root", "123456"), ("admin", "admin"),
    ],
    "postgres": [
        ("postgres", ""), ("postgres", "postgres"), ("postgres", "password"),
        ("admin", "admin"),
    ],
    "mongodb": [("admin", "admin"), ("root", "root")],
    "redis": [("", ""), ("", "redis")],
}


DB_PORTS = {
    3306: "mysql",
    5432: "postgres",
    27017: "mongodb",
    6379: "redis",
    9200: "elasticsearch",
    5984: "couchdb",
    9042: "cassandra",
    1433: "mssql",
    1521: "oracle",
    11211: "memcached",
    7474: "neo4j",
    8086: "influxdb",
    26257: "cockroachdb",
    8529: "arangodb",
    5601: "kibana",
    15672: "rabbitmq_mgmt",
    8161: "activemq",
}


SENSITIVE_INDEX_PATTERNS = [
    r"user", r"customer", r"account", r"auth", r"session",
    r"order", r"payment", r"card", r"credit", r"bank",
    r"patient", r"medical", r"health", r"insurance",
    r"employee", r"salary", r"hr", r"passport",
    r"email", r"phone", r"address", r"ssn",
    r"log", r"audit", r"metric",
]


class DatabaseScanner:

    def __init__(
        self,
        session: requests.Session | None = None,
        timeout: int = 5,
        safety_config: dict | None = None,
    ) -> None:
        self.session = session or requests.Session()
        self.timeout = timeout
        self.safety_config = safety_config or {}
        self.findings: list[dict] = []

    def run(self, target: str, ports: str = "") -> dict[str, Any]:
        host = self._extract_host(target)

        port_list = self._parse_ports(ports)
        if not port_list:
            port_list = list(DB_PORTS.keys())

        for port in port_list:
            if port in DB_PORTS:
                self._check_db_port(host, port, DB_PORTS[port])

        base = sanitize_target(target)
        if not base.startswith("http"):
            base = f"https://{base}"
        self._check_elasticsearch_http(base, host)
        self._check_couchdb_http(base, host)
        self._check_kibana_http(base, host)
        self._check_neo4j_http(base, host)
        self._check_rabbitmq_http(base, host)

        return {"findings": self.findings}

    def _extract_host(self, target: str) -> str:
        target = target.strip()
        if "://" in target:
            from urllib.parse import urlparse
            return urlparse(target).hostname or target
        if ":" in target:
            return target.split(":")[0]
        return target

    def _parse_ports(self, ports: str) -> list[int]:
        if not ports:
            return []
        result = []
        for part in ports.split(","):
            part = part.strip()
            if "-" in part:
                try:
                    start, end = part.split("-")
                    result.extend(range(int(start), int(end) + 1))
                except ValueError:
                    continue
            else:
                try:
                    result.append(int(part))
                except ValueError:
                    continue
        return result


    def _check_db_port(self, host: str, port: int, service: str) -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                banner = self._get_banner(sock, service)
                sock.close()

                if service == "redis":
                    self._check_redis(host, port)
                elif service == "mongodb":
                    self._check_mongodb(host, port)
                elif service == "memcached":
                    self._check_memcached(host, port)
                elif service == "elasticsearch":
                    self._check_elasticsearch_direct(host, port)
                elif service in ("mysql", "postgres", "mssql"):
                    self.findings.append(self._make_finding(
                        vuln_id="DB-001",
                        title=f"Exposed {service.upper()} Port ({port}/tcp)",
                        severity="high",
                        target=f"{host}:{port}",
                        evidence=f"Port {port} ({service}) is open and accepting connections.\nBanner: {banner or 'N/A'}",
                        category="database",
                        remediation=f"Restrict {service} access via firewall. Bind to 127.0.0.1 instead of 0.0.0.0.",
                    ))
                else:
                    self.findings.append(self._make_finding(
                        vuln_id="DB-001",
                        title=f"Exposed {service.upper()} Port ({port}/tcp)",
                        severity="medium",
                        target=f"{host}:{port}",
                        evidence=f"Port {port} ({service}) is open.\nBanner: {banner or 'N/A'}",
                        category="database",
                    ))
            else:
                sock.close()
        except (socket.error, OSError):
            pass

    def _get_banner(self, sock: socket.socket, service: str) -> str:
        try:
            if service in ("redis",):
                sock.send(b"PING\r\n")
            elif service in ("memcached",):
                sock.send(b"stats\r\n")
            elif service in ("elasticsearch", "couchdb"):
                sock.send(b"GET / HTTP/1.0\r\n\r\n")

            sock.settimeout(3)
            data = sock.recv(1024)
            return data.decode("utf-8", errors="replace").strip()[:200]
        except (socket.error, OSError):
            return ""


    def _check_redis(self, host: str, port: int) -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))

            sock.send(b"INFO server\r\n")
            resp = sock.recv(4096).decode("utf-8", errors="replace")

            if "redis_version" in resp:
                version = ""
                for line in resp.split("\n"):
                    if line.startswith("redis_version:"):
                        version = line.split(":")[1].strip()
                        break

                self.findings.append(self._make_finding(
                    vuln_id="DB-003",
                    title=f"Redis No Authentication ({host}:{port})",
                    severity="critical",
                    target=f"{host}:{port}",
                    evidence=f"Redis {version} accessible without authentication.\nINFO command returned server details.",
                    category="database",
                    remediation="Set requirepass in redis.conf. Bind to 127.0.0.1. Use TLS.",
                ))

                sock.send(b"CONFIG GET dir\r\n")
                config_resp = sock.recv(1024).decode("utf-8", errors="replace")
                if "dir" in config_resp.lower() or "$" in config_resp:
                    self.findings.append(self._make_finding(
                        vuln_id="DB-003",
                        title=f"Redis CONFIG Command Accessible — RCE Possible ({host}:{port})",
                        severity="critical",
                        target=f"{host}:{port}",
                        evidence=f"CONFIG GET dir returned: {config_resp[:200]}\nThis can be used for RCE via file write.",
                        category="database",
                        remediation="Disable dangerous commands via rename-command in redis.conf.",
                    ))

            elif "-NOAUTH" in resp or "Authentication required" in resp.lower():
                self.findings.append(self._make_finding(
                    vuln_id="DB-001",
                    title=f"Redis Exposed (auth required) ({host}:{port})",
                    severity="medium",
                    target=f"{host}:{port}",
                    evidence="Redis port open but authentication is required.",
                    category="database",
                ))

            sock.close()
        except (socket.error, OSError):
            pass


    def _check_mongodb(self, host: str, port: int) -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))

            sock.send(
                b"\x3a\x00\x00\x00"
                b"\x01\x00\x00\x00"
                b"\x00\x00\x00\x00"
                b"\xd4\x07\x00\x00"
                b"\x00\x00\x00\x00"
                b"admin.$cmd\x00"
                b"\x00\x00\x00\x00"
                b"\x01\x00\x00\x00"
                b"\x10\x00\x00\x00"
                b"\x10"
                b"isMaster\x00"
                b"\x01\x00\x00\x00"
                b"\x00"
            )

            resp = sock.recv(4096)
            resp_text = resp.decode("utf-8", errors="replace")

            if "ismaster" in resp_text.lower() or "maxWireVersion" in resp_text:
                self.findings.append(self._make_finding(
                    vuln_id="DB-002",
                    title=f"MongoDB Accessible Without Authentication ({host}:{port})",
                    severity="critical",
                    target=f"{host}:{port}",
                    evidence="MongoDB responds to isMaster without authentication.",
                    category="database",
                    remediation="Enable authentication: security.authorization: enabled in mongod.conf. Bind to 127.0.0.1.",
                ))

            sock.close()
        except (socket.error, OSError):
            pass


    def _check_memcached(self, host: str, port: int) -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))

            sock.send(b"stats\r\n")
            resp = sock.recv(4096).decode("utf-8", errors="replace")

            if "STAT" in resp:
                items = ""
                for line in resp.split("\n"):
                    if "curr_items" in line:
                        items = line.strip()
                        break

                self.findings.append(self._make_finding(
                    vuln_id="DB-010",
                    title=f"Memcached Open Access ({host}:{port})",
                    severity="high",
                    target=f"{host}:{port}",
                    evidence=f"Memcached stats accessible without auth. {items}",
                    category="database",
                    remediation="Bind memcached to 127.0.0.1. Use SASL authentication.",
                ))

            sock.close()
        except (socket.error, OSError):
            pass


    def _check_elasticsearch_direct(self, host: str, port: int) -> None:
        try:
            resp = self.session.get(
                f"http://{host}:{port}/",
                timeout=self.timeout, verify=False,
            )
            if resp.status_code == 200 and "cluster_name" in resp.text:
                data = resp.json()
                cluster = data.get("cluster_name", "unknown")
                version = data.get("version", {}).get("number", "unknown")

                self.findings.append(self._make_finding(
                    vuln_id="DB-004",
                    title=f"Elasticsearch Open Cluster ({cluster}, v{version})",
                    severity="critical",
                    target=f"{host}:{port}",
                    evidence=f"Cluster: {cluster}\nVersion: {version}\nNo authentication required.",
                    category="database",
                    remediation="Enable X-Pack security. Set up RBAC. Bind to internal network.",
                ))

                try:
                    idx_resp = self.session.get(
                        f"http://{host}:{port}/_cat/indices?format=json",
                        timeout=self.timeout, verify=False,
                    )
                    if idx_resp.status_code == 200:
                        indices = idx_resp.json() if isinstance(idx_resp.json(), list) else []
                        sensitive = []
                        for idx in indices:
                            name = idx.get("index", "")
                            for pattern in SENSITIVE_INDEX_PATTERNS:
                                if re.search(pattern, name, re.IGNORECASE):
                                    sensitive.append(name)
                                    break

                        if sensitive:
                            self.findings.append(self._make_finding(
                                vuln_id="DB-004",
                                title=f"Elasticsearch Sensitive Indices Exposed ({len(sensitive)} found)",
                                severity="critical",
                                target=f"{host}:{port}",
                                evidence=f"Sensitive indices:\n" + "\n".join(f"  - {s}" for s in sensitive[:20]),
                                category="database",
                            ))
                except (RequestException, ValueError):
                    pass

        except (RequestException, ValueError):
            pass


    def _check_elasticsearch_http(self, base: str, host: str) -> None:
        for port_suffix in ["", ":9200", ":9201"]:
            url = f"http://{host}{port_suffix}/"
            try:
                resp = self.session.get(url, timeout=self.timeout, verify=False)
                if resp.status_code == 200 and "cluster_name" in resp.text:
                    self._check_elasticsearch_direct(host, int(port_suffix.split(":")[1]) if port_suffix else 9200)
                    return
            except (RequestException, ValueError, IndexError):
                continue

    def _check_couchdb_http(self, base: str, host: str) -> None:
        for port in [5984, 6984]:
            url = f"http://{host}:{port}/"
            try:
                resp = self.session.get(url, timeout=self.timeout, verify=False)
                if resp.status_code == 200 and "couchdb" in resp.text.lower():
                    dbs_resp = self.session.get(
                        f"http://{host}:{port}/_all_dbs",
                        timeout=self.timeout, verify=False,
                    )
                    if dbs_resp.status_code == 200:
                        self.findings.append(self._make_finding(
                            vuln_id="DB-005",
                            title=f"CouchDB Open Access ({host}:{port})",
                            severity="critical",
                            target=f"{host}:{port}",
                            evidence=f"CouchDB accessible. Databases: {dbs_resp.text[:500]}",
                            category="database",
                            remediation="Enable authentication. Set admin party to false.",
                        ))
            except RequestException:
                continue

    def _check_kibana_http(self, base: str, host: str) -> None:
        for port in [5601]:
            url = f"http://{host}:{port}/"
            try:
                resp = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
                if resp.status_code == 200 and "kibana" in resp.text.lower():
                    self.findings.append(self._make_finding(
                        vuln_id="DB-006",
                        title=f"Kibana Dashboard Exposed ({host}:{port})",
                        severity="high",
                        target=f"{host}:{port}",
                        evidence="Kibana accessible without authentication.",
                        category="database",
                        remediation="Enable Kibana authentication via X-Pack or reverse proxy.",
                    ))
            except RequestException:
                continue

    def _check_neo4j_http(self, base: str, host: str) -> None:
        for port in [7474, 7473]:
            url = f"http://{host}:{port}/"
            try:
                resp = self.session.get(url, timeout=self.timeout, verify=False)
                if resp.status_code == 200 and ("neo4j" in resp.text.lower() or "browser" in resp.text.lower()):
                    self.findings.append(self._make_finding(
                        vuln_id="DB-006",
                        title=f"Neo4j Browser Exposed ({host}:{port})",
                        severity="high",
                        target=f"{host}:{port}",
                        evidence="Neo4j browser accessible.",
                        category="database",
                        remediation="Enable Neo4j native authentication. Restrict access via firewall.",
                    ))
            except RequestException:
                continue

    def _check_rabbitmq_http(self, base: str, host: str) -> None:
        url = f"http://{host}:15672/"
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=False)
            if resp.status_code == 200 and ("rabbitmq" in resp.text.lower() or "management" in resp.text.lower()):
                auth_resp = self.session.get(
                    f"http://{host}:15672/api/overview",
                    timeout=self.timeout, verify=False,
                    auth=("guest", "guest"),
                )
                if auth_resp.status_code == 200:
                    self.findings.append(self._make_finding(
                        vuln_id="DB-008",
                        title=f"RabbitMQ Default Credentials (guest/guest) ({host}:15672)",
                        severity="critical",
                        target=f"{host}:15672",
                        evidence="RabbitMQ management accessible with default guest/guest credentials.",
                        category="database",
                        remediation="Change default credentials. Delete guest user. Restrict management API access.",
                    ))
                else:
                    self.findings.append(self._make_finding(
                        vuln_id="DB-006",
                        title=f"RabbitMQ Management UI Exposed ({host}:15672)",
                        severity="medium",
                        target=f"{host}:15672",
                        evidence="RabbitMQ management accessible (auth required).",
                        category="database",
                    ))
        except RequestException:
            pass


    def _make_finding(
        self,
        vuln_id: str,
        title: str,
        severity: str,
        target: str,
        evidence: str,
        category: str = "database",
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
            "url": target,
            "evidence": evidence,
            "remediation": remediation,
            "scanner": "dbscan",
            "confidence": 0.9,
        }
