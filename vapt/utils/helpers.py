"""
Utility helpers — the Swiss-army knife of VAPT CLI.

Small, focused functions that don't belong to any one module but are
used everywhere: ID generation, timestamp formatting, URL extraction,
network resolution, hashing, and more.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import socket
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse


def generate_scan_id() -> str:
    """Return a unique scan identifier."""
    return str(uuid.uuid4())


def utcnow() -> datetime:
    """Return current UTC datetime (timezone-aware)."""
    return datetime.now(tz=timezone.utc)


def sanitize_target(target: str) -> str:
    """
    Clean up a user-supplied target string.

    People paste all kinds of things — full URLs, trailing whitespace,
    "https://" when they meant the host name.  This function strips
    that noise and returns a clean hostname/IP.
    """
    target = target.strip()
    parsed = urlparse(target)
    if parsed.scheme in ("http", "https", "ftp"):
        # Extract host from URL
        return parsed.netloc or parsed.path
    return target


def is_private_ip(ip: str) -> bool:
    """Return True if the IP address is in a private/reserved range."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def resolve_host(host: str, timeout: float = 5.0) -> list[str]:
    """Resolve a hostname to IP addresses.  Returns [] on failure."""
    try:
        socket.setdefaulttimeout(timeout)
        results = socket.getaddrinfo(host, None)
        # Deduplicate — getaddrinfo often returns the same IP multiple times
        return list({r[4][0] for r in results})
    except (socket.gaierror, socket.timeout, OSError):
        return []


def sha256_file(path: str) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def flatten_dict(d: dict[str, Any], parent_key: str = "", sep: str = ".") -> dict[str, Any]:
    """Recursively flatten a nested dict into dot-notation keys.

    Example: {"a": {"b": 1}} → {"a.b": 1}
    """
    items: list[tuple[str, Any]] = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def truncate(text: str, max_length: int = 200) -> str:
    """Truncate text to max_length characters."""
    if len(text) <= max_length:
        return text
    return text[: max_length - 3] + "..."


def safe_int(value: Any, default: int = 0) -> int:
    """Convert value to int, returning default on failure."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def extract_urls(text: str) -> list[str]:
    """Extract all HTTP/HTTPS URLs from a text string."""
    pattern = r"https?://[^\s\"'<>]+"
    return re.findall(pattern, text)


def format_timestamp(dt: datetime | None = None) -> str:
    """Format a datetime as ISO-8601 string. Uses utcnow if not provided."""
    if dt is None:
        dt = utcnow()
    return dt.isoformat()
