
from __future__ import annotations

import re
import time
from typing import Any

import requests
from rich.console import Console

console = Console()


TAKEOVER_FINGERPRINTS: list[dict[str, Any]] = [
    {"service": "AWS S3",
     "cname": [".s3.amazonaws.com", ".s3-website"],
     "pattern": re.compile(r"NoSuchBucket|The specified bucket does not exist", re.I)},
    {"service": "GitHub Pages",
     "cname": [".github.io"],
     "pattern": re.compile(r"There isn't a GitHub Pages site here", re.I)},
    {"service": "Heroku",
     "cname": [".herokuapp.com", ".herokussl.com"],
     "pattern": re.compile(r"No such app|no-such-app|herokucdn\.com/error-pages", re.I)},
    {"service": "Shopify",
     "cname": [".myshopify.com"],
     "pattern": re.compile(r"Sorry, this shop is currently unavailable", re.I)},
    {"service": "Fastly",
     "cname": [".fastly.net", ".fastssl.net"],
     "pattern": re.compile(r"Fastly error: unknown domain", re.I)},
    {"service": "Pantheon",
     "cname": [".pantheonsite.io"],
     "pattern": re.compile(r"The gods are wise, but do not know", re.I)},
    {"service": "Tumblr",
     "cname": [".tumblr.com"],
     "pattern": re.compile(r"There's nothing here|Whatever you were looking for", re.I)},
    {"service": "Zendesk",
     "cname": [".zendesk.com"],
     "pattern": re.compile(r"Help Center Closed|this help center no longer exists", re.I)},
    {"service": "Azure",
     "cname": [".azurewebsites.net", ".cloudapp.azure.com", ".trafficmanager.net"],
     "pattern": re.compile(r"404 Web Site not found|does not exist", re.I)},
    {"service": "Surge.sh",
     "cname": [".surge.sh"],
     "pattern": re.compile(r"project not found", re.I)},
]


class CloudScanner:

    def __init__(
        self,
        target: str,
        session: requests.Session | None = None,
        timeout: int = 10,
    ) -> None:
        self.target = target.rstrip("/")
        self.session = session or requests.Session()
        self.session.headers.setdefault(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        )
        self.timeout = timeout
        self.findings: list[dict] = []
        self.domain = re.sub(r"https?://", "", self.target).split("/")[0]
        self.domain_base = self.domain.split(".")[0]

    def run(self) -> list[dict]:
        checks = [
            ("S3 Bucket Exposure", self._check_s3_buckets),
            ("Azure Blob Storage", self._check_azure_blobs),
            ("GCP Storage", self._check_gcp_buckets),
            ("Firebase Database", self._check_firebase),
            ("Cloud Metadata (SSRF)", self._check_metadata_endpoints),
            ("Subdomain Takeover", self._check_subdomain_takeover),
            ("DigitalOcean Spaces", self._check_do_spaces),
            ("Cloud Admin Panels", self._check_cloud_panels),
        ]

        for name, check_func in checks:
            try:
                check_func()
            except Exception as exc:
                console.print(f"  [dim]Cloud check '{name}' error: {exc}[/dim]")

        return self.findings


    def _check_s3_buckets(self) -> None:
        bucket_guesses = [
            self.domain_base,
            f"{self.domain_base}-backup",
            f"{self.domain_base}-backups",
            f"{self.domain_base}-dev",
            f"{self.domain_base}-staging",
            f"{self.domain_base}-prod",
            f"{self.domain_base}-assets",
            f"{self.domain_base}-media",
            f"{self.domain_base}-static",
            f"{self.domain_base}-uploads",
            f"{self.domain_base}-data",
            f"{self.domain_base}-logs",
            f"{self.domain_base}-public",
            f"{self.domain_base}-private",
            f"{self.domain_base}-internal",
            f"{self.domain_base}-test",
            f"{self.domain_base}-files",
            f"www.{self.domain_base}",
            f"cdn.{self.domain_base}",
            self.domain,
        ]

        for bucket in bucket_guesses:
            url = f"https://{bucket}.s3.amazonaws.com/"
            try:
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code == 200 and "<ListBucketResult" in resp.text:
                    self.findings.append({
                        "vuln_id": "CLOUD-001",
                        "title": f"AWS S3 Bucket Publicly Listable: {bucket}",
                        "severity": "Critical",
                        "category": "cloud",
                        "url": url,
                        "evidence": resp.text[:500],
                        "remediation": "Disable public listing via S3 bucket policy. Enable 'Block Public Access' settings.",
                    })
                elif resp.status_code == 403:
                    acl_url = f"{url}?acl"
                    try:
                        acl_resp = self.session.get(acl_url, timeout=self.timeout)
                        if acl_resp.status_code == 200:
                            self.findings.append({
                                "vuln_id": "CLOUD-002",
                                "title": f"AWS S3 Bucket ACL Exposed: {bucket}",
                                "severity": "High",
                                "category": "cloud",
                                "url": acl_url,
                                "evidence": acl_resp.text[:500],
                                "remediation": "Restrict S3 bucket ACL read permissions.",
                            })
                    except requests.RequestException:
                        pass
            except requests.RequestException:
                continue
            time.sleep(0.2)


    def _check_azure_blobs(self) -> None:
        containers = [
            self.domain_base,
            f"{self.domain_base}backup",
            f"{self.domain_base}dev",
            f"{self.domain_base}prod",
            f"{self.domain_base}data",
        ]

        for container in containers:
            url = f"https://{container}.blob.core.windows.net/?comp=list"
            try:
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code == 200 and "<EnumerationResults" in resp.text:
                    self.findings.append({
                        "vuln_id": "CLOUD-003",
                        "title": f"Azure Blob Storage Publicly Listable: {container}",
                        "severity": "Critical",
                        "category": "cloud",
                        "url": url,
                        "evidence": resp.text[:500],
                        "remediation": "Disable anonymous access on Azure Blob containers.",
                    })
            except requests.RequestException:
                continue
            time.sleep(0.2)


    def _check_gcp_buckets(self) -> None:
        bucket_names = [
            self.domain_base,
            f"{self.domain_base}-backup",
            f"{self.domain_base}-staging",
            f"{self.domain_base}-prod",
        ]

        for bucket in bucket_names:
            url = f"https://storage.googleapis.com/{bucket}/"
            try:
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code == 200 and ("<ListBucketResult" in resp.text or "Contents" in resp.text):
                    self.findings.append({
                        "vuln_id": "CLOUD-004",
                        "title": f"GCP Storage Bucket Publicly Listable: {bucket}",
                        "severity": "Critical",
                        "category": "cloud",
                        "url": url,
                        "evidence": resp.text[:500],
                        "remediation": "Restrict GCP bucket to authorized users only.",
                    })
            except requests.RequestException:
                continue
            time.sleep(0.2)


    def _check_firebase(self) -> None:
        firebase_names = [
            self.domain_base,
            f"{self.domain_base}-app",
            f"{self.domain_base}-prod",
            f"{self.domain_base}-default-rtdb",
        ]

        for name in firebase_names:
            url = f"https://{name}.firebaseio.com/.json"
            try:
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code == 200 and resp.text.strip() != "null":
                    self.findings.append({
                        "vuln_id": "CLOUD-005",
                        "title": f"Firebase Database Publicly Readable: {name}",
                        "severity": "Critical",
                        "category": "cloud",
                        "url": url,
                        "evidence": resp.text[:500],
                        "remediation": "Add Firebase Realtime Database rules to restrict read/write access.",
                    })
            except requests.RequestException:
                continue
            time.sleep(0.2)


    def _check_metadata_endpoints(self) -> None:
        from vapt.engine.payloads import SSRF_URLS, SSRF_PARAMS, SSRF_INDICATORS

        base = self.target

        for param in SSRF_PARAMS[:8]:
            for meta_url in [
                "http://169.254.169.254/latest/meta-data/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            ]:
                test_url = f"{base}?{param}={meta_url}"
                try:
                    resp = self.session.get(test_url, timeout=self.timeout)
                    if SSRF_INDICATORS.search(resp.text):
                        self.findings.append({
                            "vuln_id": "CLOUD-006",
                            "title": f"Cloud Metadata Accessible via SSRF ({param})",
                            "severity": "Critical",
                            "category": "cloud",
                            "url": test_url,
                            "evidence": resp.text[:500],
                            "remediation": "Block internal IP ranges in server-side requests. Upgrade to IMDSv2 on AWS.",
                        })
                        return
                except requests.RequestException:
                    continue


    def _check_subdomain_takeover(self) -> None:
        try:
            import dns.resolver
        except ImportError:
            return

        subdomains_to_check = [
            f"www.{self.domain}",
            f"blog.{self.domain}",
            f"shop.{self.domain}",
            f"store.{self.domain}",
            f"app.{self.domain}",
            f"api.{self.domain}",
            f"mail.{self.domain}",
            f"dev.{self.domain}",
            f"staging.{self.domain}",
            f"test.{self.domain}",
            f"cdn.{self.domain}",
            f"docs.{self.domain}",
            f"help.{self.domain}",
            f"support.{self.domain}",
            f"status.{self.domain}",
        ]

        for subdomain in subdomains_to_check:
            try:
                answers = dns.resolver.resolve(subdomain, "CNAME")
                for rdata in answers:
                    cname = str(rdata.target).rstrip(".")
                    for fp in TAKEOVER_FINGERPRINTS:
                        if any(cname.endswith(suffix) for suffix in fp["cname"]):
                            try:
                                resp = self.session.get(
                                    f"http://{subdomain}",
                                    timeout=self.timeout,
                                    allow_redirects=True,
                                )
                                if fp["pattern"].search(resp.text):
                                    self.findings.append({
                                        "vuln_id": "CLOUD-007",
                                        "title": f"Subdomain Takeover: {subdomain} → {fp['service']}",
                                        "severity": "High",
                                        "category": "cloud",
                                        "url": f"http://{subdomain}",
                                        "evidence": f"CNAME: {cname}, Response: {resp.text[:200]}",
                                        "remediation": f"Remove dangling CNAME or reclaim the {fp['service']} resource.",
                                    })
                            except requests.RequestException:
                                self.findings.append({
                                    "vuln_id": "CLOUD-007",
                                    "title": f"Possible Subdomain Takeover: {subdomain} → {fp['service']}",
                                    "severity": "Medium",
                                    "category": "cloud",
                                    "url": f"http://{subdomain}",
                                    "evidence": f"CNAME: {cname}, Connection failed (likely unclaimed)",
                                    "remediation": f"Remove dangling CNAME or reclaim the {fp['service']} resource.",
                                })
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                    dns.resolver.NoNameservers, Exception):
                continue


    def _check_do_spaces(self) -> None:
        regions = ["nyc3", "sfo3", "ams3", "sgp1", "fra1"]
        names = [self.domain_base, f"{self.domain_base}-assets"]

        for name in names:
            for region in regions:
                url = f"https://{name}.{region}.digitaloceanspaces.com/"
                try:
                    resp = self.session.get(url, timeout=self.timeout)
                    if resp.status_code == 200 and "<ListBucketResult" in resp.text:
                        self.findings.append({
                            "vuln_id": "CLOUD-008",
                            "title": f"DigitalOcean Space Publicly Listable: {name} ({region})",
                            "severity": "High",
                            "category": "cloud",
                            "url": url,
                            "evidence": resp.text[:500],
                            "remediation": "Set the Space to private and use signed URLs for access.",
                        })
                except requests.RequestException:
                    continue
                time.sleep(0.1)


    def _check_cloud_panels(self) -> None:
        endpoints = [
            ("/api/v1", "Kubernetes", re.compile(r'"kind":\s*"APIResourceList"', re.I)),
            ("/api/v1/namespaces", "Kubernetes", re.compile(r'"kind":\s*"NamespaceList"', re.I)),
            ("/healthz", "Kubernetes", re.compile(r"^ok$")),
            ("/v2/_catalog", "Docker Registry", re.compile(r'"repositories"', re.I)),
            ("/version", "Docker", re.compile(r'"ApiVersion"', re.I)),
            ("/v1/catalog/services", "Consul", re.compile(r'consul', re.I)),
            ("/v2/keys", "etcd", re.compile(r'"action"|"node"', re.I)),
            ("/api/org", "Grafana", re.compile(r'"id".*"name"', re.I)),
            ("/api/dashboards/home", "Grafana", re.compile(r'"dashboard"', re.I)),
            ("/api/v1/targets", "Prometheus", re.compile(r'"activeTargets"', re.I)),
            ("/api/json", "Jenkins", re.compile(r'"_class".*"hudson', re.I)),
        ]

        for path, service, pattern in endpoints:
            url = f"{self.target}{path}"
            try:
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code == 200 and pattern.search(resp.text[:2000]):
                    self.findings.append({
                        "vuln_id": "CLOUD-009",
                        "title": f"Exposed {service} API: {path}",
                        "severity": "High",
                        "category": "cloud",
                        "url": url,
                        "evidence": resp.text[:500],
                        "remediation": f"Restrict access to {service} API behind authentication and firewall rules.",
                    })
            except requests.RequestException:
                continue
            time.sleep(0.1)
