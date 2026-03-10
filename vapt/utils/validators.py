
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse


def validate_target(target: str) -> tuple[bool, str]:
    target = target.strip()
    if not target:
        return False, "Target must not be empty."

    if target.startswith(("http://", "https://")):
        try:
            parsed = urlparse(target)
            if not parsed.netloc:
                return False, f"Invalid URL (no host): {target}"
            return True, target
        except ValueError as exc:
            return False, str(exc)

    if "/" in target:
        try:
            ipaddress.ip_network(target, strict=False)
            return True, target
        except ValueError:
            pass

    try:
        ipaddress.ip_address(target)
        return True, target
    except ValueError:
        pass

    hostname_re = re.compile(
        r"^(?=.{1,253}$)"
        r"(?!-)[A-Za-z0-9\-]{1,63}(?<!-)"
        r"(\.(?!-)[A-Za-z0-9\-]{1,63}(?<!-))*$"
    )
    if hostname_re.match(target):
        return True, target

    return False, f"Invalid target: '{target}'. Provide a hostname, IP, CIDR, or URL."


def validate_port(port: str | int) -> tuple[bool, str]:
    port_s = str(port).strip()

    if "-" in port_s:
        parts = port_s.split("-", 1)
        try:
            lo, hi = int(parts[0]), int(parts[1])
            if 1 <= lo <= hi <= 65535:
                return True, port_s
            return False, f"Port range out of bounds: {port_s}"
        except ValueError:
            return False, f"Invalid port range: {port_s}"

    if "," in port_s:
        for p in port_s.split(","):
            ok, msg = validate_port(p.strip())
            if not ok:
                return False, msg
        return True, port_s

    try:
        p = int(port_s)
        if 1 <= p <= 65535:
            return True, port_s
        return False, f"Port out of range (1-65535): {p}"
    except ValueError:
        return False, f"Invalid port: {port_s!r}"


def validate_email(email: str) -> bool:
    pattern = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
    return bool(pattern.match(email.strip()))


def validate_report_format(fmt: str) -> tuple[bool, str]:
    allowed = {"pdf", "html", "json"}
    normalized = fmt.strip().lower()
    if normalized in allowed:
        return True, normalized
    return False, f"Unsupported format '{fmt}'. Choose from: {', '.join(sorted(allowed))}."


def sanitize_filename(name: str) -> str:
    return re.sub(r"[^\w.\-]", "_", name)
