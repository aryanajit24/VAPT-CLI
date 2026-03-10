
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import requests

from rich.console import Console

console = Console()

SESSION_STORE = Path.home() / ".vapt" / "sessions"


class SessionManager:

    def __init__(self):
        self.sessions: dict[str, requests.Session] = {}
        self.tokens: dict[str, dict[str, Any]] = {}
        SESSION_STORE.mkdir(parents=True, exist_ok=True)

    def create_session(
        self,
        name: str,
        auth_type: str = "bearer",
        credentials: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        proxy: str | None = None,
    ) -> requests.Session:
        session = requests.Session()
        session.verify = False
        session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
        })

        if proxy:
            session.proxies = {"http": proxy, "https": proxy}

        if headers:
            session.headers.update(headers)

        if cookies:
            for k, v in cookies.items():
                session.cookies.set(k, v)

        if credentials:
            if auth_type == "bearer":
                token = credentials.get("token", "")
                session.headers["Authorization"] = f"Bearer {token}"
                self.tokens[name] = {"type": "bearer", "token": token, "expires": 0}

            elif auth_type == "basic":
                from requests.auth import HTTPBasicAuth
                session.auth = HTTPBasicAuth(
                    credentials.get("username", ""),
                    credentials.get("password", ""),
                )

            elif auth_type == "api_key":
                key_name = credentials.get("header", "X-API-Key")
                key_value = credentials.get("key", "")
                session.headers[key_name] = key_value

            elif auth_type == "form":
                login_url = credentials.get("login_url", "")
                payload = credentials.get("payload", {})
                resp = session.post(login_url, data=payload, timeout=15)
                if resp.ok:
                    console.print(f"  [green]Login successful for {name}[/green]")
                else:
                    console.print(f"  [red]Login failed for {name}: {resp.status_code}[/red]")

            elif auth_type == "oauth2":
                token_url = credentials.get("token_url", "")
                client_id = credentials.get("client_id", "")
                client_secret = credentials.get("client_secret", "")
                scope = credentials.get("scope", "")
                resp = session.post(token_url, data={
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "scope": scope,
                }, timeout=15)
                if resp.ok:
                    token_data = resp.json()
                    access_token = token_data.get("access_token", "")
                    session.headers["Authorization"] = f"Bearer {access_token}"
                    self.tokens[name] = {
                        "type": "oauth2",
                        "token": access_token,
                        "refresh_token": token_data.get("refresh_token"),
                        "expires": time.time() + token_data.get("expires_in", 3600),
                        "token_url": token_url,
                        "client_id": client_id,
                        "client_secret": client_secret,
                    }
                    console.print(f"  [green]OAuth2 token obtained for {name}[/green]")

        self.sessions[name] = session
        self._save_session(name)
        return session

    def get_session(self, name: str) -> requests.Session | None:
        if name in self.sessions:
            self._refresh_if_needed(name)
            return self.sessions[name]
        return self._load_session(name)

    def _refresh_if_needed(self, name: str) -> None:
        token_info = self.tokens.get(name)
        if not token_info:
            return
        if token_info["type"] != "oauth2":
            return
        if time.time() < token_info.get("expires", 0) - 60:
            return

        session = self.sessions[name]
        resp = session.post(token_info["token_url"], data={
            "grant_type": "refresh_token",
            "refresh_token": token_info.get("refresh_token", ""),
            "client_id": token_info.get("client_id", ""),
            "client_secret": token_info.get("client_secret", ""),
        }, timeout=15)

        if resp.ok:
            data = resp.json()
            new_token = data.get("access_token", "")
            session.headers["Authorization"] = f"Bearer {new_token}"
            token_info["token"] = new_token
            token_info["expires"] = time.time() + data.get("expires_in", 3600)
            if data.get("refresh_token"):
                token_info["refresh_token"] = data["refresh_token"]
            self._save_session(name)

    def _save_session(self, name: str) -> None:
        session = self.sessions.get(name)
        if not session:
            return
        data = {
            "headers": dict(session.headers),
            "cookies": dict(session.cookies),
            "tokens": self.tokens.get(name, {}),
        }
        path = SESSION_STORE / f"{name}.json"
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _load_session(self, name: str) -> requests.Session | None:
        path = SESSION_STORE / f"{name}.json"
        if not path.exists():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        session = requests.Session()
        session.verify = False
        session.headers.update(data.get("headers", {}))
        for k, v in data.get("cookies", {}).items():
            session.cookies.set(k, v)
        self.tokens[name] = data.get("tokens", {})
        self.sessions[name] = session
        self._refresh_if_needed(name)
        return session

    def dual_session_test(
        self,
        url: str,
        session_a: str = "user_a",
        session_b: str = "user_b",
    ) -> list[dict[str, Any]]:
        findings = []
        sa = self.get_session(session_a)
        sb = self.get_session(session_b)
        if not sa or not sb:
            return findings

        try:
            resp_a = sa.get(url, timeout=10)
            resp_b = sb.get(url, timeout=10)
        except Exception:
            return findings

        if resp_a.status_code == 200 and resp_b.status_code == 200:
            if resp_a.text == resp_b.text and len(resp_a.text) > 100:
                findings.append({
                    "type": "idor",
                    "severity": "high",
                    "confidence": "high",
                    "title": f"Potential IDOR: Same data returned for different users at {url}",
                    "url": url,
                    "evidence": (
                        f"User A and User B received identical responses "
                        f"({len(resp_a.text)} bytes). This may indicate "
                        f"broken access control."
                    ),
                })
        elif resp_a.status_code == 200 and resp_b.status_code in (200, 201):
            if resp_b.status_code == 200 and "admin" in url.lower():
                findings.append({
                    "type": "privilege_escalation",
                    "severity": "critical",
                    "confidence": "medium",
                    "title": f"Potential Privilege Escalation at {url}",
                    "url": url,
                    "evidence": (
                        f"Low-privilege user (session B) can access admin "
                        f"endpoint. Status: {resp_b.status_code}"
                    ),
                })

        return findings

    def list_sessions(self) -> list[str]:
        return [p.stem for p in SESSION_STORE.glob("*.json")]

    def delete_session(self, name: str) -> None:
        self.sessions.pop(name, None)
        self.tokens.pop(name, None)
        path = SESSION_STORE / f"{name}.json"
        if path.exists():
            path.unlink()
