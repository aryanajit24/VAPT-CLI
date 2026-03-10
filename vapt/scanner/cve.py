
from __future__ import annotations

import re
from typing import Any

import requests
from requests.exceptions import RequestException

from vapt.utils.helpers import sanitize_target

KNOWN_VULNS: list[tuple[str, str, str, str, float]] = [
    (r"Apache/2\.4\.(4[0-9]|[0-3][0-9]) ", "Apache HTTP Server <2.4.50", "CVE-2021-41773", "critical", 9.8),
    (r"Apache/2\.4\.(4[0-9]) ",             "Apache HTTP Server 2.4.49",  "CVE-2021-42013", "critical", 9.8),
    (r"nginx/1\.(1[0-7]\.|[0-9]\.) ",       "Nginx <1.18.0",             "CVE-2019-9511",  "high",     7.5),
    (r"OpenSSH[/_]([0-6]\.|7\.[0-6])",      "OpenSSH <7.7",              "CVE-2018-15473", "medium",   5.3),
    (r"PHP/([4-6]\.|7\.[0-3]\.)",           "PHP <7.4",                  "CVE-2019-11043", "critical", 9.8),
    (r"WordPress/([0-4]\.|5\.[0-7]\.)",     "WordPress <5.8",            "CVE-2021-29447", "high",     7.5),
    (r"IIS/([0-9]\.|10\.[0-9])",            "IIS",                       "CVE-2017-7269",  "critical", 9.8),
    (r"Tomcat/([0-8]\.|9\.[0-9]\.[0-4])",   "Apache Tomcat <9.0.50",     "CVE-2021-33037", "medium",   5.3),
]

BANNER_PRODUCTS: list[tuple[str, str]] = [
    (r"Apache/(?P<ver>[\d.]+)",   "apache http_server"),
    (r"nginx/(?P<ver>[\d.]+)",    "nginx"),
    (r"OpenSSH[/_](?P<ver>[\d.]+)", "openssh"),
    (r"PHP/(?P<ver>[\d.]+)",      "php"),
    (r"Tomcat/(?P<ver>[\d.]+)",   "tomcat"),
    (r"IIS/(?P<ver>[\d.]+)",      "iis"),
]


class CVEScanner:

    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, timeout: int = 10) -> None:
        self.timeout = timeout


    def run(self, target: str) -> dict[str, Any]:
        target = sanitize_target(target)
        base_url = target if target.startswith(("http://", "https://")) else f"https://{target}"

        results: dict[str, Any] = {
            "target": base_url,
            "category": "cve",
            "banners": {},
            "findings": [],
        }

        banners = self._collect_banners(base_url)
        results["banners"] = banners

        results["findings"] = self._match_cves(banners)

        nvd_findings = self._nvd_lookup(banners)
        existing_cves = {f.get("cve_ids") for f in results["findings"]}
        for nf in nvd_findings:
            if nf.get("cve_ids") not in existing_cves:
                results["findings"].append(nf)

        return results


    def _collect_banners(self, url: str) -> dict[str, str]:
        banners: dict[str, str] = {}
        urls_to_try = [url]
        if url.startswith("https://"):
            urls_to_try.append(url.replace("https://", "http://"))

        for try_url in urls_to_try:
            try:
                resp = requests.get(
                    try_url, timeout=self.timeout, verify=False, allow_redirects=True,
                )
                for hdr in ("Server", "X-Powered-By", "Via"):
                    val = resp.headers.get(hdr, "")
                    if val:
                        banners[hdr] = val
                break
            except RequestException:
                continue
        return banners


    def _match_cves(self, banners: dict[str, str]) -> list[dict[str, Any]]:
        findings = []
        banner_blob = " ".join(banners.values())

        for pattern, product, cve, severity, cvss in KNOWN_VULNS:
            if re.search(pattern, banner_blob, re.IGNORECASE):
                findings.append({
                    "vuln_id": "CVE-001",
                    "category": "cve",
                    "title": f"Known CVE in {product}",
                    "description": (
                        f"Server banner matches a known vulnerable version of {product}.  "
                        f"Primary CVE: {cve}."
                    ),
                    "severity": severity,
                    "cvss_score": cvss,
                    "cve_ids": cve,
                    "product": product,
                    "banner": banner_blob[:200],
                })

        return findings


    def _nvd_lookup(self, banners: dict[str, str]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        banner_blob = " ".join(banners.values())

        for pattern, keyword in BANNER_PRODUCTS:
            m = re.search(pattern, banner_blob, re.IGNORECASE)
            if not m:
                continue

            version = m.group("ver")
            search_term = f"{keyword} {version}"
            cves = self._query_nvd(search_term)

            for cve_item in cves[:5]:
                cve_id = cve_item.get("cve", {}).get("id", "")
                metrics = cve_item.get("cve", {}).get("metrics", {})

                cvss_score = 0.0
                severity = "medium"
                for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    metric_list = metrics.get(metric_key, [])
                    if metric_list:
                        cvss_data = metric_list[0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore", 0.0)
                        severity = self._cvss_to_severity(cvss_score)
                        break

                desc_data = cve_item.get("cve", {}).get("descriptions", [])
                description = next(
                    (d["value"] for d in desc_data if d.get("lang") == "en"),
                    "No description available.",
                )

                findings.append({
                    "vuln_id": "CVE-001",
                    "category": "cve",
                    "title": f"{cve_id} — {keyword} {version}",
                    "description": description[:500],
                    "severity": severity,
                    "cvss_score": cvss_score,
                    "cve_ids": cve_id,
                    "product": f"{keyword} {version}",
                    "source": "NVD",
                })

        return findings

    def _query_nvd(self, keyword: str) -> list[dict]:
        params: dict[str, str] = {"keywordSearch": keyword, "resultsPerPage": "5"}

        api_key = self._load_api_key("nvd_api_key")
        headers: dict[str, str] = {}
        if api_key:
            headers["apiKey"] = api_key

        try:
            resp = requests.get(
                self.NVD_API_URL, params=params, headers=headers, timeout=self.timeout,
            )
            if resp.status_code != 200:
                return []
            return resp.json().get("vulnerabilities", [])
        except Exception:
            return []


    @staticmethod
    def _cvss_to_severity(score: float) -> str:
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score >= 0.1:
            return "low"
        return "info"

    @staticmethod
    def _load_api_key(key_name: str) -> str | None:
        try:
            from vapt.config import ConfigManager
            return ConfigManager().get(key_name)
        except Exception:
            return None
