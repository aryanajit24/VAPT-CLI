"""Authentication helper for injecting credentials into scan requests."""

from __future__ import annotations

import re
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from requests.exceptions import RequestException


class AuthManager:
    """Create and maintain authenticated HTTP sessions for scanners."""

    def __init__(
        self,
        method: str = "none",
        token: str | None = None,
        cookies: dict[str, str] | None = None,
        credentials: dict[str, str] | None = None,
        login_url: str | None = None,
        oauth_token_url: str | None = None,
        oauth_client_id: str | None = None,
        oauth_client_secret: str | None = None,
        custom_headers: dict[str, str] | None = None,
        timeout: int = 10,
    ) -> None:
        """
        Parameters
        ----------
        method : str
            One of: none, bearer, cookie, form, basic, digest, oauth2, header
        token : str
            Bearer / API token value
        cookies : dict
            Manual cookies to inject  {"session": "abc123"}
        credentials : dict
            {"username": "admin", "password": "pass"}
        login_url : str
            URL of the login page (for form-based auth)
        """
        self.method = method.lower()
        self.token = token
        self.cookies = cookies or {}
        self.credentials = credentials or {}
        self.login_url = login_url
        self.oauth_token_url = oauth_token_url
        self.oauth_client_id = oauth_client_id
        self.oauth_client_secret = oauth_client_secret
        self.custom_headers = custom_headers or {}
        self.timeout = timeout
        self._session: requests.Session | None = None

    def get_session(self) -> requests.Session:
        """Return an authenticated requests.Session ready for scanning."""
        if self._session is not None:
            return self._session

        session = requests.Session()
        session.verify = False
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; VAPT-Scanner/2.0; ethical-scan)"
        })

        if self.method == "bearer":
            self._setup_bearer(session)
        elif self.method == "cookie":
            self._setup_cookies(session)
        elif self.method == "form":
            self._setup_form_login(session)
        elif self.method == "basic":
            self._setup_basic(session)
        elif self.method == "digest":
            self._setup_digest(session)
        elif self.method == "oauth2":
            self._setup_oauth2(session)
        elif self.method == "header":
            self._setup_custom_headers(session)
        # "none" = no auth

        # Always apply custom headers on top
        if self.custom_headers:
            session.headers.update(self.custom_headers)

        self._session = session
        return session

    def is_authenticated(self) -> bool:
        """Check whether we're using any auth method."""
        return self.method != "none"

    def describe(self) -> str:
        """Return a human-readable description of the auth method."""
        descs = {
            "none": "No authentication",
            "bearer": "Bearer token",
            "cookie": f"Manual cookies ({len(self.cookies)} cookies)",
            "form": f"Form login at {self.login_url}",
            "basic": f"HTTP Basic ({self.credentials.get('username', '?')})",
            "digest": f"HTTP Digest ({self.credentials.get('username', '?')})",
            "oauth2": "OAuth2 client credentials",
            "header": f"Custom headers ({len(self.custom_headers)} headers)",
        }
        return descs.get(self.method, f"Unknown ({self.method})")


    def _setup_bearer(self, session: requests.Session) -> None:
        if not self.token:
            return
        # Handle both "Bearer xyz" and raw "xyz"
        token_val = self.token
        if not token_val.lower().startswith("bearer "):
            token_val = f"Bearer {token_val}"
        session.headers["Authorization"] = token_val


    def _setup_cookies(self, session: requests.Session) -> None:
        for name, value in self.cookies.items():
            session.cookies.set(name, value)


    def _setup_form_login(self, session: requests.Session) -> None:
        """
        Auto-detect login form, fill credentials, submit, and capture
        the session cookie. This handles the majority of web app logins.
        """
        if not self.login_url:
            return

        try:
            # 1. GET the login page
            resp = session.get(self.login_url, timeout=self.timeout)
            soup = BeautifulSoup(resp.text, "html.parser")

            # 2. Find the login form (first POST form with a password field)
            form = None
            for f in soup.find_all("form"):
                if f.find("input", {"type": "password"}):
                    form = f
                    break

            if form is None:
                # Fallback: try the first form
                form = soup.find("form")

            if form is None:
                return

            # 3. Extract form action and all fields
            action = urljoin(self.login_url, form.get("action") or self.login_url)
            method = (form.get("method") or "post").lower()

            data: dict[str, str] = {}
            for inp in form.find_all(["input", "select", "textarea"]):
                name = inp.get("name")
                if not name:
                    continue
                inp_type = (inp.get("type") or "text").lower()
                value = inp.get("value", "")

                if inp_type == "password":
                    data[name] = self.credentials.get("password", "")
                elif inp_type == "email" or _is_username_field(name):
                    data[name] = self.credentials.get("username", "")
                elif inp_type == "hidden":
                    # CSRF tokens, etc. — keep the original value
                    data[name] = value
                elif inp_type == "submit":
                    data[name] = value or "Login"
                else:
                    data[name] = value

            # 4. Override with explicit credential keys if field names match
            if "username" in self.credentials:
                for key in data:
                    if _is_username_field(key):
                        data[key] = self.credentials["username"]
            if "password" in self.credentials:
                for key in data:
                    if _is_password_field(key):
                        data[key] = self.credentials["password"]

            # 5. Submit
            if method == "post":
                session.post(action, data=data, timeout=self.timeout,
                             allow_redirects=True)
            else:
                session.get(action, params=data, timeout=self.timeout,
                            allow_redirects=True)

            # Session cookies are now captured in the session object

        except RequestException:
            pass


    def _setup_basic(self, session: requests.Session) -> None:
        username = self.credentials.get("username", "")
        password = self.credentials.get("password", "")
        session.auth = (username, password)


    def _setup_digest(self, session: requests.Session) -> None:
        from requests.auth import HTTPDigestAuth
        username = self.credentials.get("username", "")
        password = self.credentials.get("password", "")
        session.auth = HTTPDigestAuth(username, password)


    def _setup_oauth2(self, session: requests.Session) -> None:
        if not self.oauth_token_url:
            return
        try:
            resp = requests.post(
                self.oauth_token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.oauth_client_id or "",
                    "client_secret": self.oauth_client_secret or "",
                },
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                token = resp.json().get("access_token", "")
                if token:
                    session.headers["Authorization"] = f"Bearer {token}"
        except Exception:
            pass


    def _setup_custom_headers(self, session: requests.Session) -> None:
        session.headers.update(self.custom_headers)


_USERNAME_NAMES = re.compile(
    r"(user|login|email|account|name|uid|identifier)", re.IGNORECASE
)
_PASSWORD_NAMES = re.compile(
    r"(pass|pwd|secret|credential)", re.IGNORECASE
)


def _is_username_field(name: str) -> bool:
    return bool(_USERNAME_NAMES.search(name))


def _is_password_field(name: str) -> bool:
    return bool(_PASSWORD_NAMES.search(name))
