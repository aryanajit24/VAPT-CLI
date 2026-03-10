
from __future__ import annotations

import socket as _socket
from typing import Any

from vapt.utils.helpers import sanitize_target
from vapt.utils.validators import validate_port

DEFAULT_PORTS = (
    "21,22,23,25,53,80,110,135,139,143,389,443,445,"
    "1433,1521,2375,2376,3000,3306,3389,4848,5432,"
    "5900,5984,6379,7001,8080,8443,8888,9200,11211,27017,28017"
)

RISKY_PORTS: dict[int, tuple[str, str, float]] = {
    21:    ("FTP — unencrypted file transfer, often allows anonymous login", "high", 7.5),
    23:    ("Telnet — unencrypted remote shell, credentials sent as plaintext", "critical", 9.8),
    25:    ("SMTP — open relay risk, used for spam and phishing pivots", "medium", 5.3),
    110:   ("POP3 — unencrypted mail retrieval", "medium", 5.3),
    135:   ("MS RPC — used in many Windows privilege escalation chains", "high", 7.5),
    139:   ("NetBIOS — information disclosure and SMB relay attacks", "high", 7.5),
    143:   ("IMAP — unencrypted mail access", "medium", 5.3),
    389:   ("LDAP — potential for unauthenticated enumeration", "high", 7.5),
    445:   ("SMB — EternalBlue/WannaCry, ransomware vector, pass-the-hash", "critical", 9.8),
    1433:  ("MSSQL — database port exposed to internet", "high", 8.1),
    1521:  ("Oracle DB — database port exposed to internet", "high", 8.1),
    2375:  ("Docker API (unauthenticated) — full host compromise possible", "critical", 9.9),
    2376:  ("Docker TLS API — privilege escalation risk", "high", 8.1),
    3000:  ("Dev server likely exposed (Node/React/Grafana)", "medium", 5.3),
    3306:  ("MySQL — database port exposed to internet", "high", 8.1),
    3389:  ("RDP — BlueKeep, brute force, and credential stuffing target", "critical", 9.8),
    4848:  ("GlassFish admin — default admin:adminadmin credential", "critical", 9.8),
    5432:  ("PostgreSQL — database port exposed to internet", "high", 8.1),
    5900:  ("VNC — remote desktop, often no password", "critical", 9.8),
    5984:  ("CouchDB — admin party (no auth) by default", "critical", 9.8),
    6379:  ("Redis — no authentication by default, arbitrary code execution", "critical", 9.8),
    7001:  ("WebLogic — multiple RCE CVEs, default credentials", "critical", 9.8),
    8080:  ("HTTP alt — admin panel or dev server likely exposed", "medium", 5.3),
    8443:  ("HTTPS alt — admin panel likely exposed", "medium", 5.3),
    8888:  ("Jupyter Notebook — often no password, code execution", "critical", 9.8),
    9200:  ("Elasticsearch — no auth by default, data exposure", "critical", 9.8),
    11211: ("Memcached — no auth, amplification DDoS and data exposure", "high", 7.5),
    27017: ("MongoDB — no auth by default, full DB read/write", "critical", 9.8),
    28017: ("MongoDB REST API — full DB access", "critical", 9.8),
}

DEFAULT_CREDS: dict[int, list[tuple[str, str]]] = {
    21: [
        ("anonymous", "anonymous"),
        ("anonymous", ""),
        ("admin", "admin"),
        ("admin", ""),
        ("ftp", "ftp"),
        ("root", "root"),
        ("root", ""),
    ],
    3306: [
        ("root", ""),
        ("root", "root"),
        ("root", "password"),
        ("root", "toor"),
        ("admin", "admin"),
        ("mysql", "mysql"),
    ],
    5432: [
        ("postgres", "postgres"),
        ("postgres", ""),
        ("postgres", "password"),
        ("admin", "admin"),
    ],
    1433: [
        ("sa", ""),
        ("sa", "sa"),
        ("sa", "password"),
        ("sa", "Password1"),
        ("admin", "admin"),
    ],
    27017: [
        ("", ""),
    ],
    6379: [
        ("", ""),
    ],
    9200: [
        ("", ""),
    ],
    5984: [
        ("", ""),
    ],
    5900: [
        ("", ""),
    ],
    8888: [
        ("", ""),
    ],
}


class PortScanner:

    def __init__(self, timeout: int = 5) -> None:
        self.timeout = timeout

    def run(self, target: str, ports: str = DEFAULT_PORTS) -> dict[str, Any]:
        target = sanitize_target(target)
        ok, msg = validate_port(ports)
        if not ok:
            return {"target": target, "error": msg, "findings": []}

        open_ports = self._scan(target, ports)
        findings = self._analyse(target, open_ports)

        return {
            "target": target,
            "ports_scanned": ports,
            "open_ports": open_ports,
            "findings": findings,
        }


    def _scan(self, host: str, ports: str) -> list[dict[str, Any]]:
        try:
            import nmap
            nm = nmap.PortScanner()
            nm.scan(host, ports, arguments=f"-sV -T4 --host-timeout {self.timeout*2}s --script=banner")
            results = []
            for host_key in nm.all_hosts():
                for proto in nm[host_key].all_protocols():
                    for port, info in nm[host_key][proto].items():
                        if info["state"] == "open":
                            results.append({
                                "port": int(port),
                                "protocol": proto,
                                "state": info["state"],
                                "service": info.get("name", ""),
                                "product": info.get("product", ""),
                                "version": info.get("version", ""),
                                "banner": info.get("extrainfo", ""),
                            })
            return results
        except ImportError:
            return self._socket_scan(host, ports)
        except Exception as exc:
            return [{"error": str(exc)}]

    def _socket_scan(self, host: str, ports: str) -> list[dict[str, Any]]:
        results = []
        for port in self._parse_ports(ports):
            with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                try:
                    s.connect((host, port))
                    banner = ""
                    try:
                        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        raw = s.recv(1024)
                        banner = raw.decode("utf-8", errors="replace").strip()
                    except Exception:
                        pass
                    results.append({
                        "port": port,
                        "protocol": "tcp",
                        "state": "open",
                        "service": self._guess_service(port),
                        "banner": banner[:200],
                    })
                except (_socket.timeout, ConnectionRefusedError, OSError):
                    pass
        return results


    def _analyse(self, host: str, open_ports: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings = []
        for port_info in open_ports:
            if "error" in port_info:
                continue
            port = port_info.get("port", 0)
            if port in RISKY_PORTS:
                desc, sev, cvss = RISKY_PORTS[port]
                findings.append({
                    "vuln_id": "NET-001",
                    "category": "network",
                    "title": f"Risky port open: {port}/{port_info.get('service', 'tcp')}",
                    "description": desc,
                    "severity": sev,
                    "cvss_score": cvss,
                    "port": port,
                    "service": port_info.get("service", ""),
                    "version": port_info.get("version", ""),
                    "banner": port_info.get("banner", ""),
                })

            if port in DEFAULT_CREDS:
                cred_findings = self._test_default_creds(host, port, port_info)
                findings += cred_findings

        return findings


    def _test_default_creds(
        self, host: str, port: int, port_info: dict
    ) -> list[dict[str, Any]]:
        findings = []

        if port == 6379:
            findings += self._check_redis_noauth(host)
        elif port == 9200:
            findings += self._check_elasticsearch_noauth(host)
        elif port == 5984:
            findings += self._check_couchdb_noauth(host)
        elif port == 27017:
            findings += self._check_mongodb_noauth(host)
        elif port == 21:
            findings += self._check_ftp_default(host, port)
        elif port == 3306:
            findings += self._check_mysql_default(host, port)
        elif port == 5432:
            findings += self._check_postgres_default(host, port)
        elif port == 8888:
            findings += self._check_jupyter_noauth(host)

        return findings

    def _check_redis_noauth(self, host: str) -> list[dict]:
        try:
            with _socket.create_connection((host, 6379), timeout=self.timeout) as s:
                s.send(b"PING\r\n")
                resp = s.recv(64).decode("utf-8", errors="replace")
                if "+PONG" in resp:
                    return [self._net_finding(
                        "NET-004", "default_credentials",
                        "Redis: unauthenticated access (no password required)",
                        f"Redis on {host}:6379 responds to PING without authentication. "
                        "Full key-value store read/write — potential RCE via cron/SSH key write.",
                        "critical", 9.8, port=6379,
                    )]
        except Exception:
            pass
        return []

    def _check_elasticsearch_noauth(self, host: str) -> list[dict]:
        try:
            import requests
            resp = requests.get(f"http://{host}:9200/", timeout=self.timeout, verify=False)
            if resp.status_code == 200 and "cluster_name" in resp.text:
                return [self._net_finding(
                    "NET-004", "default_credentials",
                    "Elasticsearch: unauthenticated access",
                    f"Elasticsearch on {host}:9200 returned cluster info without authentication. "
                    "All indices and data may be readable/writable.",
                    "critical", 9.8, port=9200,
                )]
        except Exception:
            pass
        return []

    def _check_couchdb_noauth(self, host: str) -> list[dict]:
        try:
            import requests
            resp = requests.get(f"http://{host}:5984/_all_dbs", timeout=self.timeout, verify=False)
            if resp.status_code == 200:
                return [self._net_finding(
                    "NET-004", "default_credentials",
                    "CouchDB: admin party (no authentication)",
                    f"CouchDB on {host}:5984 returns /_all_dbs without credentials. "
                    "Full database read/write access.",
                    "critical", 9.8, port=5984,
                )]
        except Exception:
            pass
        return []

    def _check_mongodb_noauth(self, host: str) -> list[dict]:
        try:
            import requests
            resp = requests.get(f"http://{host}:28017/", timeout=self.timeout, verify=False)
            if resp.status_code == 200 and ("serverStatus" in resp.text or "databases" in resp.text):
                return [self._net_finding(
                    "NET-004", "default_credentials",
                    "MongoDB: unauthenticated REST API access",
                    f"MongoDB REST API on {host}:28017 accessible without credentials.",
                    "critical", 9.8, port=28017,
                )]
        except Exception:
            pass
        return []

    def _check_ftp_default(self, host: str, port: int) -> list[dict]:
        findings = []
        try:
            import ftplib
            for user, passwd in DEFAULT_CREDS.get(21, []):
                try:
                    ftp = ftplib.FTP(timeout=self.timeout)
                    ftp.connect(host, port)
                    ftp.login(user, passwd)
                    ftp.quit()
                    label = "anonymous" if user == "anonymous" else f"{user}:{passwd}"
                    vuln_id = "NET-004" if user == "anonymous" else "NET-003"
                    findings.append(self._net_finding(
                        vuln_id, "default_credentials",
                        f"FTP: {label} login accepted",
                        f"FTP on {host}:{port} accepted {label!r} credentials.",
                        "critical", 9.8, port=port,
                        username=user, password=passwd,
                    ))
                    return findings
                except ftplib.all_errors:
                    pass
        except Exception:
            pass
        return findings

    def _check_mysql_default(self, host: str, port: int) -> list[dict]:
        try:
            import importlib
            mysql = importlib.import_module("MySQLdb")
        except ImportError:
            try:
                import importlib
                mysql = importlib.import_module("pymysql")
            except ImportError:
                return []
        for user, passwd in DEFAULT_CREDS.get(3306, []):
            try:
                conn = mysql.connect(host=host, port=port, user=user, passwd=passwd,
                                     connect_timeout=self.timeout)
                conn.close()
                return [self._net_finding(
                    "NET-003", "default_credentials",
                    f"MySQL: default credential accepted ({user})",
                    f"MySQL on {host}:{port} accepted user='{user}' password='{passwd}'",
                    "critical", 9.8, port=port, username=user, password=passwd,
                )]
            except Exception:
                pass
        return []

    def _check_postgres_default(self, host: str, port: int) -> list[dict]:
        try:
            import psycopg2
        except ImportError:
            return []
        for user, passwd in DEFAULT_CREDS.get(5432, []):
            try:
                conn = psycopg2.connect(host=host, port=port, user=user,
                                        password=passwd, connect_timeout=self.timeout,
                                        dbname="postgres")
                conn.close()
                return [self._net_finding(
                    "NET-003", "default_credentials",
                    f"PostgreSQL: default credential accepted ({user})",
                    f"PostgreSQL on {host}:{port} accepted user='{user}' password='{passwd}'",
                    "critical", 9.8, port=port, username=user, password=passwd,
                )]
            except Exception:
                pass
        return []

    def _check_jupyter_noauth(self, host: str) -> list[dict]:
        try:
            import requests
            resp = requests.get(f"http://{host}:8888/api/kernels", timeout=self.timeout, verify=False)
            if resp.status_code == 200:
                return [self._net_finding(
                    "NET-006", "default_credentials",
                    "Jupyter Notebook: unauthenticated code execution",
                    f"Jupyter on {host}:8888 allows unauthenticated access. "
                    "An attacker can execute arbitrary Python code on the server.",
                    "critical", 9.8, port=8888,
                )]
        except Exception:
            pass
        return []


    @staticmethod
    def _parse_ports(ports_str: str) -> list[int]:
        result = []
        for segment in ports_str.split(","):
            segment = segment.strip()
            if "-" in segment:
                lo, hi = segment.split("-", 1)
                result.extend(range(int(lo), int(hi) + 1))
            else:
                try:
                    result.append(int(segment))
                except ValueError:
                    pass
        return result

    @staticmethod
    def _guess_service(port: int) -> str:
        well_known = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 110: "pop3", 143: "imap",
            389: "ldap", 443: "https", 445: "smb", 3306: "mysql",
            3389: "rdp", 5432: "postgresql", 6379: "redis",
            8080: "http-alt", 8443: "https-alt", 9200: "elasticsearch",
            27017: "mongodb",
        }
        return well_known.get(port, "unknown")

    @staticmethod
    def _net_finding(
        vuln_id: str, category: str, title: str,
        description: str, severity: str, cvss_score: float,
        **extra: Any,
    ) -> dict[str, Any]:
        d = {
            "vuln_id": vuln_id, "category": category, "title": title,
            "description": description, "severity": severity, "cvss_score": cvss_score,
        }
        d.update(extra)
        return d
