
from __future__ import annotations

import re
from typing import Any

import dns.resolver
import requests

from vapt.utils.helpers import resolve_host, sanitize_target


class ReconScanner:

    def __init__(self, timeout: int = 10) -> None:
        self.timeout = timeout


    def run(self, target: str) -> dict[str, Any]:
        target = sanitize_target(target)
        results: dict[str, Any] = {
            "target": target,
            "category": "recon",
            "dns": {},
            "whois_summary": {},
            "subdomains": [],
            "technologies": [],
            "ct_subdomains": [],
            "shodan": {},
            "securitytrails": {},
            "emails": [],
            "findings": [],
        }

        results["dns"] = self._dns_enum(target)
        results["whois_summary"] = self._whois_lookup(target)
        results["subdomains"] = self._subdomain_bruteforce(target)
        results["technologies"] = self._detect_technologies(target)

        results["ct_subdomains"] = self._crtsh_subdomains(target)
        results["shodan"] = self._shodan_lookup(target)
        results["securitytrails"] = self._securitytrails_subdomains(target)
        results["emails"] = self._hunterio_emails(target)

        all_subs = set(results["subdomains"]) | set(results["ct_subdomains"])
        if results["securitytrails"].get("subdomains"):
            all_subs |= set(results["securitytrails"]["subdomains"])
        results["subdomains"] = sorted(all_subs)

        if results["shodan"].get("ports") and len(results["shodan"]["ports"]) > 10:
            results["findings"].append({
                "vuln_id": "OSINT-001",
                "category": "osint",
                "title": f"Excessive open ports found via Shodan ({len(results['shodan']['ports'])})",
                "description": "Shodan reports a large number of open ports on this host.",
                "severity": "medium",
                "cvss_score": 5.3,
            })

        return results


    def _dns_enum(self, host: str) -> dict[str, Any]:
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
        dns_info: dict[str, list[str]] = {}

        resolver = dns.resolver.Resolver()
        resolver.lifetime = float(self.timeout)

        for rtype in record_types:
            try:
                answers = resolver.resolve(host, rtype)
                dns_info[rtype] = [str(r) for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                dns_info[rtype] = []
            except Exception:
                dns_info[rtype] = []

        return dns_info


    def _whois_lookup(self, host: str) -> dict[str, Any]:
        try:
            import whois

            w = whois.whois(host)
            return {
                "registrar": str(w.registrar or ""),
                "creation_date": str(w.creation_date or ""),
                "expiration_date": str(w.expiration_date or ""),
                "name_servers": w.name_servers or [],
                "status": w.status or [],
            }
        except Exception:
            return {}


    def _subdomain_bruteforce(self, host: str) -> list[str]:
        wordlist = [
            "www", "mail", "ftp", "admin", "vpn", "portal", "api",
            "dev", "staging", "test", "blog", "shop", "remote", "cdn",
            "git", "ci", "jenkins", "monitor", "status", "docs",
        ]
        found: list[str] = []
        for sub in wordlist:
            candidate = f"{sub}.{host}"
            ips = resolve_host(candidate, timeout=float(self.timeout))
            if ips:
                found.append(candidate)
        return found


    def _detect_technologies(self, host: str) -> list[str]:
        techs: list[str] = []
        for scheme in ("https", "http"):
            try:
                url = f"{scheme}://{host}"
                resp = requests.get(
                    url, timeout=self.timeout, allow_redirects=True, verify=False,
                )
                for hdr in ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"):
                    val = resp.headers.get(hdr, "")
                    if val:
                        techs.append(f"{hdr}: {val}")
                break
            except requests.RequestException:
                continue
        return techs


    def _crtsh_subdomains(self, host: str) -> list[str]:
        url = f"https://crt.sh/?q=%25.{host}&output=json"
        try:
            resp = requests.get(url, timeout=self.timeout)
            if resp.status_code != 200:
                return []
            entries = resp.json()
            names: set[str] = set()
            for entry in entries:
                for field in ("common_name", "name_value"):
                    raw = entry.get(field, "")
                    for name in raw.split("\n"):
                        name = name.strip().lstrip("*.")
                        if name.endswith(f".{host}") or name == host:
                            names.add(name.lower())
            return sorted(names)
        except Exception:
            return []


    def _shodan_lookup(self, target: str) -> dict[str, Any]:
        api_key = self._load_api_key("shodan_api_key")
        if not api_key:
            return {}

        try:
            ips = resolve_host(target, timeout=float(self.timeout))
            ip = ips[0] if ips else target

            url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
            resp = requests.get(url, timeout=self.timeout)
            if resp.status_code != 200:
                return {"error": f"Shodan API returned {resp.status_code}"}
            data = resp.json()
            return {
                "ip": data.get("ip_str"),
                "os": data.get("os"),
                "ports": data.get("ports", []),
                "vulns": data.get("vulns", []),
                "hostnames": data.get("hostnames", []),
                "org": data.get("org"),
                "isp": data.get("isp"),
                "country": data.get("country_name"),
                "last_update": data.get("last_update"),
            }
        except Exception as exc:
            return {"error": str(exc)}


    def _securitytrails_subdomains(self, target: str) -> dict[str, Any]:
        api_key = self._load_api_key("securitytrails_api_key")
        if not api_key:
            return {}

        try:
            url = f"https://api.securitytrails.com/v1/domain/{target}/subdomains"
            headers = {"APIKEY": api_key, "Accept": "application/json"}
            resp = requests.get(url, headers=headers, timeout=self.timeout)
            if resp.status_code != 200:
                return {"error": f"SecurityTrails returned {resp.status_code}"}
            data = resp.json()
            subs = [f"{s}.{target}" for s in data.get("subdomains", [])]
            return {"subdomains": subs, "count": len(subs)}
        except Exception as exc:
            return {"error": str(exc)}


    def _hunterio_emails(self, target: str) -> list[dict[str, str]]:
        api_key = self._load_api_key("hunterio_api_key")
        if not api_key:
            return []

        try:
            url = f"https://api.hunter.io/v2/domain-search?domain={target}&api_key={api_key}"
            resp = requests.get(url, timeout=self.timeout)
            if resp.status_code != 200:
                return []
            data = resp.json().get("data", {})
            emails = [
                {"email": e["value"], "type": e.get("type", ""), "confidence": e.get("confidence", 0)}
                for e in data.get("emails", [])
            ]
            return emails
        except Exception:
            return []


    @staticmethod
    def _load_api_key(key_name: str) -> str | None:
        try:
            from vapt.config import ConfigManager
            cfg = ConfigManager()
            return cfg.get(key_name)
        except Exception:
            return None
