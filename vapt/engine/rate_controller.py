
from __future__ import annotations

import random
import time
import threading
from collections import deque
from dataclasses import dataclass, field
from typing import Any

import requests


@dataclass
class RateProfile:
    name: str
    base_delay: float
    jitter: float
    burst_size: int
    burst_pause: float
    backoff_multiplier: float
    max_delay: float


PROFILES: dict[str, RateProfile] = {
    "aggressive": RateProfile("aggressive", 0.1, 0.05, 50, 1.0, 1.5, 5.0),
    "normal":     RateProfile("normal",     0.5, 0.2,  20, 2.0, 2.0, 10.0),
    "polite":     RateProfile("polite",     1.5, 0.5,  10, 5.0, 2.0, 30.0),
    "stealth":    RateProfile("stealth",    3.0, 1.5,   5, 10.0, 2.5, 60.0),
}

_WAF_BODY_MARKERS = [
    "just a moment", "attention required", "access denied",
    "captcha", "cf-browser-verification", "blocked by",
    "rate limit", "too many requests", "request blocked",
]

_USER_AGENTS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
]


class RateController:

    def __init__(
        self,
        profile: str = "normal",
        proxies: list[str] | None = None,
        rotate_ua: bool = False,
        required_headers: dict[str, str] | None = None,
    ) -> None:
        if profile not in PROFILES:
            profile = "normal"
        self._profile = PROFILES[profile]
        self._proxies = list(proxies) if proxies else []
        self._proxy_idx = 0
        self._rotate_ua = rotate_ua
        self._required_headers = required_headers or {}

        self._domain_locks: dict[str, threading.Lock] = {}
        self._domain_counters: dict[str, int] = {}
        self._domain_delays: dict[str, float] = {}
        self._domain_last: dict[str, float] = {}
        self._global_lock = threading.Lock()

        self.total_requests = 0
        self.total_blocked = 0
        self.total_backoffs = 0
        self._history: deque[dict] = deque(maxlen=500)

    def _domain_of(self, url: str) -> str:
        from urllib.parse import urlparse
        return urlparse(url).hostname or "unknown"

    def _get_lock(self, domain: str) -> threading.Lock:
        with self._global_lock:
            if domain not in self._domain_locks:
                self._domain_locks[domain] = threading.Lock()
                self._domain_counters[domain] = 0
                self._domain_delays[domain] = self._profile.base_delay
                self._domain_last[domain] = 0.0
            return self._domain_locks[domain]

    def _next_proxy(self) -> dict | None:
        if not self._proxies:
            return None
        proxy = self._proxies[self._proxy_idx % len(self._proxies)]
        self._proxy_idx += 1
        return {"http": proxy, "https": proxy}

    def _build_headers(self, extra: dict | None = None) -> dict:
        headers: dict[str, str] = {}
        if self._rotate_ua:
            headers["User-Agent"] = random.choice(_USER_AGENTS)
        headers.update(self._required_headers)
        if extra:
            headers.update(extra)
        return headers

    def _is_waf_block(self, response: requests.Response) -> bool:
        if response.status_code in (403, 429, 503, 529):
            body_lower = response.text[:2000].lower()
            for marker in _WAF_BODY_MARKERS:
                if marker in body_lower:
                    return True
            if response.status_code == 429:
                return True
        return False

    def _apply_backoff(self, domain: str) -> None:
        cur = self._domain_delays.get(domain, self._profile.base_delay)
        new_delay = min(cur * self._profile.backoff_multiplier, self._profile.max_delay)
        self._domain_delays[domain] = new_delay
        self.total_backoffs += 1

    def _reset_delay(self, domain: str) -> None:
        self._domain_delays[domain] = self._profile.base_delay

    def request(
        self,
        method: str,
        url: str,
        session: requests.Session | None = None,
        headers: dict | None = None,
        max_retries: int = 3,
        **kwargs: Any,
    ) -> requests.Response | None:
        domain = self._domain_of(url)
        lock = self._get_lock(domain)

        merged_headers = self._build_headers(headers)

        for attempt in range(max_retries):
            with lock:
                now = time.monotonic()
                delay = self._domain_delays.get(domain, self._profile.base_delay)
                jitter = random.uniform(-self._profile.jitter, self._profile.jitter)
                wait = max(0, delay + jitter - (now - self._domain_last.get(domain, 0)))
                if wait > 0:
                    time.sleep(wait)

                self._domain_counters[domain] = self._domain_counters.get(domain, 0) + 1
                if self._domain_counters[domain] >= self._profile.burst_size:
                    time.sleep(self._profile.burst_pause)
                    self._domain_counters[domain] = 0

                self._domain_last[domain] = time.monotonic()

            sess = session or requests.Session()
            proxy = self._next_proxy()
            req_kwargs: dict[str, Any] = {
                "headers": merged_headers,
                "timeout": kwargs.pop("timeout", 15),
                "verify": kwargs.pop("verify", False),
                "allow_redirects": kwargs.pop("allow_redirects", True),
            }
            if proxy:
                req_kwargs["proxies"] = proxy
            req_kwargs.update(kwargs)

            try:
                resp = sess.request(method, url, **req_kwargs)
                self.total_requests += 1
                self._history.append({
                    "url": url, "status": resp.status_code,
                    "time": time.time(), "attempt": attempt,
                })

                if self._is_waf_block(resp):
                    self.total_blocked += 1
                    self._apply_backoff(domain)
                    backoff_wait = self._domain_delays[domain]
                    time.sleep(backoff_wait)
                    continue

                self._reset_delay(domain)
                return resp

            except requests.exceptions.RequestException:
                self._apply_backoff(domain)
                time.sleep(self._domain_delays.get(domain, 1.0))
                continue

        return None

    def get(self, url: str, **kwargs: Any) -> requests.Response | None:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> requests.Response | None:
        return self.request("POST", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> requests.Response | None:
        return self.request("HEAD", url, **kwargs)

    def stats(self) -> dict[str, Any]:
        return {
            "total_requests": self.total_requests,
            "total_blocked": self.total_blocked,
            "total_backoffs": self.total_backoffs,
            "profile": self._profile.name,
            "domains_tracked": len(self._domain_locks),
            "current_delays": dict(self._domain_delays),
        }
