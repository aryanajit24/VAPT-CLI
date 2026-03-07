"""Subdomain takeover detection scanner."""

from __future__ import annotations

import socket
from typing import Any

import dns.resolver
import requests
from requests.exceptions import RequestException

from vapt.utils.helpers import sanitize_target

# Service fingerprints: domain_suffix → (service_name, response_fingerprints, nxdomain_vulnerable)
TAKEOVER_FINGERPRINTS: dict[str, tuple[str, list[str], bool]] = {
    "github.io": ("GitHub Pages", [
        "there isn't a github pages site here",
        "for root urls (like http://example.com/) you must provide an index.html file",
    ], True),
    "herokuapp.com": ("Heroku", [
        "heroku | no such app", "no such app",
        "there is no app configured at that hostname",
    ], False),
    "s3.amazonaws.com": ("AWS S3", [
        "nosuchbucket", "the specified bucket does not exist",
    ], True),
    "s3-website": ("AWS S3 Website", [
        "nosuchbucket", "the specified bucket does not exist",
    ], True),
    "azurewebsites.net": ("Azure App Service", [
        "error 404 - web app not found",
    ], False),
    "cloudapp.net": ("Azure Cloud", [
        "error 404", "not found",
    ], True),
    "trafficmanager.net": ("Azure Traffic Mgr", [
        "404 not found",
    ], True),
    "blob.core.windows.net": ("Azure Blob", [
        "the specified container does not exist",
        "blobnotfound",
    ], True),
    "zendesk.com": ("Zendesk", [
        "help center closed",
    ], False),
    "shopify.com": ("Shopify", [
        "sorry, this shop is currently unavailable",
    ], False),
    "fastly.net": ("Fastly", [
        "fastly error: unknown domain",
    ], False),
    "netlify.app": ("Netlify", [
        "not found - request id",
    ], True),
    "netlify.com": ("Netlify", [
        "not found - request id",
    ], True),
    "surge.sh": ("Surge", [
        "project not found",
    ], True),
    "ghost.io": ("Ghost", [
        "the thing you were looking for is no longer here",
    ], False),
    "pantheon.io": ("Pantheon", [
        "the gods are wise", "404 unknown site",
    ], False),
    "readme.io": ("ReadMe", [
        "project doesnt exist",
    ], False),
    "bitbucket.io": ("Bitbucket", [
        "repository not found",
    ], True),
    "wordpress.com": ("WordPress.com", [
        "do you want to register",
    ], False),
    "tumblr.com": ("Tumblr", [
        "there's nothing here",
        "whatever you were looking for doesn't currently exist",
    ], True),
    "fly.dev": ("Fly.io", [
        "404 not found",
    ], True),
    "vercel.app": ("Vercel", [
        "404: not_found",
    ], True),
    "unbouncepages.com": ("Unbounce", [
        "the requested url was not found on this server",
    ], False),
    "cloudfront.net": ("CloudFront", [
        "bad request",
    ], True),
    "elasticbeanstalk.com": ("AWS Elastic Beanstalk", [
        "404 not found",
    ], True),
    "uservoice.com": ("UserVoice", [
        "this uservoice subdomain is currently available",
    ], False),
    "helpscoutdocs.com": ("HelpScout", [
        "no settings were found for this company",
    ], False),
    "cargocollective.com": ("Cargo", [
        "404 not found",
    ], True),
    "feedpress.me": ("FeedPress", [
        "the feed has not been found",
    ], True),
    "freshdesk.com": ("Freshdesk", [
        "may not be configured properly",
    ], False),
    "helpjuice.com": ("HelpJuice", [
        "we could not find what you're looking for",
    ], False),
    "ngrok.io": ("ngrok", [
        "tunnel .* not found",
        "3200",
    ], True),
    "statuspage.io": ("Statuspage", [
        "you are being redirected", "statuspage.io",
    ], False),
    "tictail.com": ("Tictail", [
        "to claim it, visit",
    ], True),
    "tilda.ws": ("Tilda", [
        "please renew your subscription",
    ], False),
    "webflow.io": ("Webflow", [
        "the page you are looking for doesn't exist",
    ], True),
}


class SubdomainTakeoverScanner:
    """Check a list of subdomains for dangling CNAME / takeover risk."""

    def __init__(self, timeout: int = 8, session: Any = None) -> None:
        self.timeout = timeout
        if session is not None:
            self.session = session
        else:
            self.session = requests.Session()
            self.session.verify = False
            self.session.headers.update({
                "User-Agent": "Mozilla/5.0 (compatible; VAPT-Scanner/5.0)"
            })

    def run(
        self, target: str, subdomains: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Check target and all provided subdomains for takeover risk.

        Args:
            target: The main domain (e.g. "example.com")
            subdomains: List of subdomains to check. If None, only checks target.
        """
        target = sanitize_target(target)
        hosts_to_check = [target]
        if subdomains:
            hosts_to_check.extend(subdomains)
        # Deduplicate
        hosts_to_check = list(dict.fromkeys(hosts_to_check))

        result: dict[str, Any] = {
            "target": target,
            "category": "subdomain_takeover",
            "subdomains_checked": len(hosts_to_check),
            "findings": [],
        }

        for host in hosts_to_check:
            findings = self._check_host(host)
            result["findings"].extend(findings)

        return result

    def _check_host(self, host: str) -> list[dict]:
        """Check a single host for dangling CNAME."""
        findings: list[dict] = []

        # Step 1: DNS lookup for CNAME
        cname = self._get_cname(host)
        if not cname:
            return findings

        # Step 2: Match CNAME to known takeover-vulnerable services
        for domain_suffix, (svc_name, fingerprints, nxdomain_vuln) in TAKEOVER_FINGERPRINTS.items():
            if not cname.endswith(domain_suffix):
                continue

            # Step 3: Check if the CNAME target resolves
            cname_resolves = self._resolves(cname)

            # If CNAME doesn't resolve and service is NXDOMAIN-vulnerable → likely takeover
            if not cname_resolves and nxdomain_vuln:
                findings.append(self._make_finding(
                    host, cname, svc_name,
                    "critical", 9.3,
                    f"CNAME target {cname} does NOT resolve (NXDOMAIN). "
                    f"{svc_name} service appears completely unclaimed.",
                    "NXDOMAIN — service unclaimed",
                ))
                continue

            # Step 4: HTTP check for service fingerprints
            for scheme in ("https", "http"):
                url = f"{scheme}://{host}"
                try:
                    resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                    body = resp.text.lower()
                    for fp in fingerprints:
                        if fp in body:
                            findings.append(self._make_finding(
                                host, cname, svc_name,
                                "critical", 9.3,
                                f"Fingerprint match: '{fp}'. "
                                f"{svc_name} service appears unclaimed.",
                                f"HTTP {resp.status_code} — fingerprint: '{fp}'\nBody: {resp.text[:300]}",
                            ))
                            break
                    else:
                        # No fingerprint but suspicious status
                        if resp.status_code in (404, 410) and len(resp.content) < 200:
                            findings.append(self._make_finding(
                                host, cname, svc_name,
                                "high", 8.1,
                                f"CNAME → {svc_name}, HTTP {resp.status_code} with minimal content. "
                                f"Verify manually if takeover is possible.",
                                f"HTTP {resp.status_code} — {len(resp.content)} bytes",
                            ))
                    break  # One scheme is enough
                except RequestException:
                    # Connection failure = strong takeover signal
                    findings.append(self._make_finding(
                        host, cname, svc_name,
                        "high", 8.1,
                        f"Connection to {host} failed. CNAME → {svc_name}. "
                        f"Service may be unclaimed.",
                        f"Connection failed to {scheme}://{host}",
                    ))
                    break

        return findings

    def _get_cname(self, host: str) -> str | None:
        """Resolve CNAME record for host."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = float(self.timeout)
            answers = resolver.resolve(host, "CNAME")
            for rdata in answers:
                return str(rdata.target).rstrip(".")
        except Exception:
            return None

    def _resolves(self, host: str) -> bool:
        """Check if a hostname resolves to any IP."""
        try:
            socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            return True
        except (socket.gaierror, OSError):
            return False

    @staticmethod
    def _make_finding(
        host: str, cname: str, svc_name: str,
        severity: str, cvss: float,
        description: str, evidence_detail: str,
    ) -> dict[str, Any]:
        return {
            "vuln_id": "WEB-013",
            "category": "subdomain_takeover",
            "title": f"Subdomain takeover: {host} → {svc_name}",
            "description": (
                f"{host} has a CNAME pointing to {cname} ({svc_name}). {description} "
                f"An attacker can register on {svc_name} and serve arbitrary content "
                f"on {host}, enabling cookie theft, credential phishing, and malware delivery."
            ),
            "severity": severity,
            "cvss_score": cvss,
            "scanner": "SubdomainTakeoverScanner",
            "url": f"https://{host}",
            "evidence": (
                f"Subdomain: {host}\n"
                f"CNAME: {cname}\n"
                f"Service: {svc_name}\n"
                f"{evidence_detail}"
            ),
            "cname": cname,
            "service": svc_name,
        }
