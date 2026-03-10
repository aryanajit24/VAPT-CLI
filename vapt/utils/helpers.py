
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
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


def sanitize_target(target: str) -> str:
    target = target.strip()
    parsed = urlparse(target)
    if parsed.scheme in ("http", "https", "ftp"):
        return parsed.netloc or parsed.path
    return target


def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def resolve_host(host: str, timeout: float = 5.0) -> list[str]:
    try:
        socket.setdefaulttimeout(timeout)
        results = socket.getaddrinfo(host, None)
        return list({r[4][0] for r in results})
    except (socket.gaierror, socket.timeout, OSError):
        return []


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def flatten_dict(d: dict[str, Any], parent_key: str = "", sep: str = ".") -> dict[str, Any]:
    items: list[tuple[str, Any]] = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def truncate(text: str, max_length: int = 200) -> str:
    if len(text) <= max_length:
        return text
    return text[: max_length - 3] + "..."


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def extract_urls(text: str) -> list[str]:
    pattern = r"https?://[^\s\"'<>]+"
    return re.findall(pattern, text)


def format_timestamp(dt: datetime | None = None) -> str:
    if dt is None:
        dt = utcnow()
    return dt.isoformat()
