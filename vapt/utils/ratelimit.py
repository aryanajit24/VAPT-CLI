"""Rate limiting and stealth session management."""

from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass, field
from typing import Any

import requests


# Stealth profiles


@dataclass
class StealthProfile:
    """Preset combination of rate limiting and evasion settings."""
    name: str
    requests_per_second: float
    jitter_range: tuple[float, float]  # (min_extra_delay, max_extra_delay)
    rotate_user_agent: bool
    randomize_headers: bool
    max_concurrent: int
    backoff_multiplier: float  # Multiply delay on 429/503


PROFILES: dict[str, StealthProfile] = {
    "aggressive": StealthProfile(
        name="Aggressive",
        requests_per_second=50.0,
        jitter_range=(0.0, 0.02),
        rotate_user_agent=False,
        randomize_headers=False,
        max_concurrent=50,
        backoff_multiplier=1.5,
    ),
    "normal": StealthProfile(
        name="Normal",
        requests_per_second=10.0,
        jitter_range=(0.01, 0.1),
        rotate_user_agent=True,
        randomize_headers=False,
        max_concurrent=20,
        backoff_multiplier=2.0,
    ),
    "polite": StealthProfile(
        name="Polite",
        requests_per_second=3.0,
        jitter_range=(0.1, 0.5),
        rotate_user_agent=True,
        randomize_headers=True,
        max_concurrent=5,
        backoff_multiplier=3.0,
    ),
    "stealth": StealthProfile(
        name="Stealth",
        requests_per_second=1.0,
        jitter_range=(0.5, 2.0),
        rotate_user_agent=True,
        randomize_headers=True,
        max_concurrent=2,
        backoff_multiplier=5.0,
    ),
}


# Rate Limiter


class RateLimiter:
    """
    Thread-safe adaptive rate limiter.

    Usage:
        limiter = RateLimiter(profile="stealth")
        with limiter:
            response = session.get(url)
        limiter.record_response(response)
    """

    def __init__(
        self,
        profile: str | StealthProfile = "normal",
        requests_per_second: float | None = None,
    ) -> None:
        if isinstance(profile, str):
            self.profile = PROFILES.get(profile, PROFILES["normal"])
        else:
            self.profile = profile

        # Allow override of RPS
        self._base_rps = requests_per_second or self.profile.requests_per_second
        self._current_delay = 1.0 / self._base_rps
        self._lock = threading.Lock()
        self._last_request_time = 0.0
        self._backoff_active = False
        self._backoff_until = 0.0

        # Stats
        self._total_requests = 0
        self._total_throttled = 0
        self._total_backoffs = 0
        self._start_time = time.time()

    def __enter__(self) -> "RateLimiter":
        self.wait()
        return self

    def __exit__(self, *args: Any) -> None:
        pass

    def wait(self) -> None:
        """Block until it's safe to send the next request."""
        with self._lock:
            now = time.time()

            if self._backoff_active and now < self._backoff_until:
                sleep_time = self._backoff_until - now
                self._total_throttled += 1
            else:
                self._backoff_active = False
                elapsed = now - self._last_request_time
                min_interval = self._current_delay
                if elapsed < min_interval:
                    sleep_time = min_interval - elapsed
                else:
                    sleep_time = 0.0

            # Add jitter
            jitter_min, jitter_max = self.profile.jitter_range
            jitter = random.uniform(jitter_min, jitter_max)
            sleep_time += jitter

        if sleep_time > 0:
            time.sleep(sleep_time)

        with self._lock:
            self._last_request_time = time.time()
            self._total_requests += 1

    def record_response(self, response: requests.Response) -> None:
        """
        Adapt rate based on response. Backs off on 429 (Too Many Requests)
        or 503 (Service Unavailable).
        """
        if response.status_code in (429, 503):
            with self._lock:
                self._total_backoffs += 1

                # Check for Retry-After header
                retry_after = response.headers.get("Retry-After")
                if retry_after:
                    try:
                        wait_secs = float(retry_after)
                    except ValueError:
                        wait_secs = 30.0
                else:
                    wait_secs = self._current_delay * self.profile.backoff_multiplier

                self._current_delay *= self.profile.backoff_multiplier
                self._backoff_active = True
                self._backoff_until = time.time() + wait_secs

        elif response.status_code == 200:
            # Gradually recover from backoff
            with self._lock:
                base_delay = 1.0 / self._base_rps
                if self._current_delay > base_delay:
                    self._current_delay = max(
                        base_delay,
                        self._current_delay * 0.9,
                    )

    @property
    def stats(self) -> dict[str, Any]:
        """Return rate limiter statistics."""
        elapsed = time.time() - self._start_time
        return {
            "total_requests": self._total_requests,
            "total_throttled": self._total_throttled,
            "total_backoffs": self._total_backoffs,
            "elapsed_seconds": round(elapsed, 2),
            "effective_rps": round(self._total_requests / max(elapsed, 0.001), 2),
            "current_delay": round(self._current_delay, 4),
            "profile": self.profile.name,
        }


# Stealth Session — requests.Session wrapper with built-in throttling


class StealthSession:
    """
    A drop-in wrapper around requests.Session with automatic rate limiting.

    Usage:
        ss = StealthSession(profile="stealth")
        resp = ss.get("https://target.com/path")
        # Rate limiting + UA rotation happens automatically
    """

    def __init__(
        self,
        profile: str = "normal",
        session: requests.Session | None = None,
        requests_per_second: float | None = None,
    ) -> None:
        self.session = session or requests.Session()
        self.limiter = RateLimiter(profile=profile, requests_per_second=requests_per_second)
        self.profile = PROFILES.get(profile, PROFILES["normal"])

        from vapt.engine.waf import USER_AGENTS
        self._user_agents = list(USER_AGENTS)
        random.shuffle(self._user_agents)
        self._ua_index = 0

    def _prepare_headers(self, kwargs: dict) -> dict:
        """Inject stealth headers into request kwargs."""
        headers = kwargs.get("headers", {}) or {}

        if self.profile.rotate_user_agent:
            headers.setdefault("User-Agent", self._user_agents[self._ua_index % len(self._user_agents)])
            self._ua_index += 1

        if self.profile.randomize_headers:
            headers.setdefault("Accept-Language", random.choice([
                "en-US,en;q=0.9", "en-GB,en;q=0.5", "de-DE,de;q=0.9", "fr-FR,fr;q=0.9",
            ]))
            # Randomize X-Forwarded-For to confuse IP-based blocking
            headers["X-Forwarded-For"] = (
                f"{random.randint(1,254)}.{random.randint(0,254)}"
                f".{random.randint(0,254)}.{random.randint(1,254)}"
            )

        kwargs["headers"] = headers
        return kwargs

    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        """Send a rate-limited request."""
        kwargs = self._prepare_headers(kwargs)
        self.limiter.wait()
        resp = self.session.request(method, url, **kwargs)
        self.limiter.record_response(resp)
        return resp

    def get(self, url: str, **kwargs: Any) -> requests.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> requests.Response:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> requests.Response:
        return self.request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> requests.Response:
        return self.request("DELETE", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> requests.Response:
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs: Any) -> requests.Response:
        return self.request("OPTIONS", url, **kwargs)

    @property
    def cookies(self) -> requests.cookies.RequestsCookieJar:
        return self.session.cookies

    @cookies.setter
    def cookies(self, value: requests.cookies.RequestsCookieJar) -> None:
        self.session.cookies = value

    @property
    def headers(self) -> dict:
        return self.session.headers

    @property
    def stats(self) -> dict[str, Any]:
        return self.limiter.stats
