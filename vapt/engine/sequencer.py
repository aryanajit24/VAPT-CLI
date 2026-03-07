"""Token randomness analyzer — Burp Sequencer replacement."""

from __future__ import annotations

import math
import statistics
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, Optional

import requests


@dataclass
class SequencerResult:
    """Results from token randomness analysis."""

    sample_size: int = 0
    entropy_per_char: float = 0.0
    max_entropy: float = 0.0
    entropy_ratio: float = 0.0
    chi_squared: float = 0.0
    chi_squared_p_approx: float = 0.0
    monobit_ratio: float = 0.0
    runs_score: float = 0.0
    block_frequency_score: float = 0.0
    char_distribution: dict[str, int] = field(default_factory=dict)
    overall_score: float = 0.0
    rating: str = "unknown"
    warnings: list[str] = field(default_factory=list)
    tokens: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "sample_size": self.sample_size,
            "entropy_per_char": round(self.entropy_per_char, 4),
            "max_entropy": round(self.max_entropy, 4),
            "entropy_ratio": round(self.entropy_ratio, 4),
            "chi_squared": round(self.chi_squared, 4),
            "monobit_ratio": round(self.monobit_ratio, 4),
            "runs_score": round(self.runs_score, 4),
            "overall_score": round(self.overall_score, 2),
            "rating": self.rating,
            "warnings": self.warnings,
        }


class Sequencer:
    """Collect tokens from an endpoint and analyze their randomness."""

    def __init__(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: Optional[dict] = None,
        data: Optional[str] = None,
        token_extractor: Optional[Callable[[requests.Response], str]] = None,
        extract_from: str = "header",
        extract_name: str = "Set-Cookie",
        extract_regex: Optional[str] = None,
        sample_size: int = 200,
        delay: float = 0.0,
        timeout: int = 10,
        verify_ssl: bool = False,
    ):
        self.url = url
        self.method = method.upper()
        self.headers = headers or {}
        self.data = data
        self.token_extractor = token_extractor
        self.extract_from = extract_from
        self.extract_name = extract_name
        self.extract_regex = extract_regex
        self.sample_size = sample_size
        self.delay = delay
        self.timeout = timeout
        self.verify_ssl = verify_ssl

    def _extract_token(self, resp: requests.Response) -> Optional[str]:
        if self.token_extractor:
            return self.token_extractor(resp)

        import re

        if self.extract_from == "header":
            value = resp.headers.get(self.extract_name, "")
            if self.extract_regex:
                match = re.search(self.extract_regex, value)
                return match.group(1) if match and match.groups() else (match.group() if match else None)
            return value if value else None

        if self.extract_from == "body":
            text = resp.text
            if self.extract_regex:
                match = re.search(self.extract_regex, text)
                return match.group(1) if match and match.groups() else (match.group() if match else None)
            return text.strip() if text.strip() else None

        if self.extract_from == "cookie":
            return resp.cookies.get(self.extract_name)

        return None

    def collect(self, progress_callback: Optional[Callable[[int, int], None]] = None) -> list[str]:
        tokens: list[str] = []
        session = requests.Session()
        session.verify = self.verify_ssl

        for i in range(self.sample_size):
            try:
                if self.method == "POST":
                    resp = session.post(
                        self.url, headers=self.headers, data=self.data, timeout=self.timeout
                    )
                else:
                    resp = session.get(self.url, headers=self.headers, timeout=self.timeout)

                token = self._extract_token(resp)
                if token:
                    tokens.append(token)

                if progress_callback:
                    progress_callback(i + 1, self.sample_size)

                if self.delay > 0:
                    time.sleep(self.delay)

            except requests.RequestException:
                continue

        return tokens

    def analyze(self, tokens: Optional[list[str]] = None) -> SequencerResult:
        if tokens is None:
            tokens = self.collect()

        result = SequencerResult(sample_size=len(tokens), tokens=tokens)
        if len(tokens) < 10:
            result.rating = "insufficient_data"
            result.warnings.append(f"Only {len(tokens)} tokens collected, need at least 10")
            return result

        result.entropy_per_char = self._shannon_entropy(tokens)
        result.max_entropy = self._max_entropy(tokens)
        result.entropy_ratio = result.entropy_per_char / result.max_entropy if result.max_entropy > 0 else 0
        result.char_distribution = self._char_distribution(tokens)
        result.chi_squared, result.chi_squared_p_approx = self._chi_squared_test(tokens)
        result.monobit_ratio = self._monobit_test(tokens)
        result.runs_score = self._runs_test(tokens)
        result.block_frequency_score = self._block_frequency_test(tokens)

        scores = [
            result.entropy_ratio * 100,
            max(0, 100 - abs(result.chi_squared_p_approx - 50)),
            result.monobit_ratio * 100,
            result.runs_score * 100,
            result.block_frequency_score * 100,
        ]
        result.overall_score = statistics.mean(scores)

        if result.overall_score >= 85:
            result.rating = "excellent"
        elif result.overall_score >= 70:
            result.rating = "good"
        elif result.overall_score >= 50:
            result.rating = "fair"
        elif result.overall_score >= 30:
            result.rating = "poor"
        else:
            result.rating = "critical"

        if result.entropy_ratio < 0.6:
            result.warnings.append("Low entropy: tokens may be predictable")
        if result.chi_squared_p_approx < 5 or result.chi_squared_p_approx > 95:
            result.warnings.append("Character distribution is not uniform")
        if result.monobit_ratio < 0.4 or result.monobit_ratio > 0.6:
            result.warnings.append("Bit frequency is biased")

        unique_ratio = len(set(tokens)) / len(tokens)
        if unique_ratio < 0.95:
            result.warnings.append(f"Duplicate tokens detected: {(1-unique_ratio)*100:.1f}% collision rate")

        lengths = [len(t) for t in tokens]
        if len(set(lengths)) > 1:
            result.warnings.append(f"Inconsistent token lengths: {min(lengths)}-{max(lengths)}")

        return result

    @staticmethod
    def _shannon_entropy(tokens: list[str]) -> float:
        combined = "".join(tokens)
        if not combined:
            return 0.0
        freq = Counter(combined)
        length = len(combined)
        return -sum((c / length) * math.log2(c / length) for c in freq.values())

    @staticmethod
    def _max_entropy(tokens: list[str]) -> float:
        combined = "".join(tokens)
        unique_chars = len(set(combined))
        return math.log2(unique_chars) if unique_chars > 1 else 1.0

    @staticmethod
    def _char_distribution(tokens: list[str]) -> dict[str, int]:
        return dict(Counter("".join(tokens)).most_common(50))

    @staticmethod
    def _chi_squared_test(tokens: list[str]) -> tuple[float, float]:
        combined = "".join(tokens)
        if not combined:
            return 0.0, 50.0

        freq = Counter(combined)
        num_categories = len(freq)
        expected = len(combined) / num_categories

        chi_sq = sum((observed - expected) ** 2 / expected for observed in freq.values())

        df = num_categories - 1
        if df <= 0:
            return chi_sq, 50.0

        mean_chi = df
        std_chi = math.sqrt(2 * df) if df > 0 else 1
        z = (chi_sq - mean_chi) / std_chi if std_chi > 0 else 0
        p_approx = 50 + 50 * math.erf(-z / math.sqrt(2))
        p_approx = max(0, min(100, p_approx))

        return chi_sq, p_approx

    @staticmethod
    def _monobit_test(tokens: list[str]) -> float:
        combined = "".join(tokens)
        if not combined:
            return 0.5

        bit_string = "".join(format(ord(c), "08b") for c in combined)
        ones = bit_string.count("1")
        return ones / len(bit_string) if bit_string else 0.5

    @staticmethod
    def _runs_test(tokens: list[str]) -> float:
        combined = "".join(tokens)
        if len(combined) < 2:
            return 1.0

        bit_string = "".join(format(ord(c), "08b") for c in combined)
        n = len(bit_string)
        ones = bit_string.count("1")
        pi = ones / n

        if abs(pi - 0.5) >= 2 / math.sqrt(n):
            return 0.0

        runs = 1
        for i in range(1, n):
            if bit_string[i] != bit_string[i - 1]:
                runs += 1

        expected_runs = 1 + 2 * n * pi * (1 - pi)
        std_runs = math.sqrt(2 * n * pi * (1 - pi))
        if std_runs == 0:
            return 0.0

        z = abs(runs - expected_runs) / std_runs
        score = max(0, 1 - z / 3)
        return score

    @staticmethod
    def _block_frequency_test(tokens: list[str], block_size: int = 8) -> float:
        combined = "".join(tokens)
        if not combined:
            return 1.0

        bit_string = "".join(format(ord(c), "08b") for c in combined)
        n = len(bit_string)
        num_blocks = n // block_size
        if num_blocks == 0:
            return 1.0

        proportions = []
        for i in range(num_blocks):
            block = bit_string[i * block_size : (i + 1) * block_size]
            proportions.append(block.count("1") / block_size)

        chi_sq = 4 * block_size * sum((p - 0.5) ** 2 for p in proportions)
        expected = num_blocks
        deviation = abs(chi_sq - expected) / expected if expected > 0 else 0
        score = max(0, 1 - deviation)
        return score
