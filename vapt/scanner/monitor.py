
from __future__ import annotations

import json
import ssl
import socket
import time
from datetime import datetime, timezone
from typing import Any, Callable

from vapt.scanner.portscan import PortScanner
from vapt.scanner.webscan import WebScanner
from vapt.utils.helpers import format_timestamp, sanitize_target


class Monitor:

    def __init__(
        self,
        target: str,
        interval: int = 300,
        on_change: Callable[[dict[str, Any]], None] | None = None,
        timeout: int = 10,
    ) -> None:
        self.target = sanitize_target(target)
        self.interval = interval
        self.on_change = on_change or (lambda d: None)
        self.timeout = timeout
        self._port_scanner = PortScanner(timeout=timeout)
        self._web_scanner = WebScanner(timeout=timeout)
        self._baseline: dict[str, Any] | None = None


    def _snapshot(self) -> dict[str, Any]:
        port_result = self._port_scanner.run(self.target)
        web_result = self._web_scanner.run(self.target)

        snapshot: dict[str, Any] = {
            "timestamp": format_timestamp(),
            "open_ports": {p["port"] for p in port_result.get("open_ports", [])},
            "finding_count": (
                len(port_result.get("findings", []))
                + len(web_result.get("findings", []))
            ),
            "status_code": web_result.get("status_code"),
            "ssl_days_left": self._check_ssl_days(self.target),
        }
        return snapshot

    def _check_ssl_days(self, host: str) -> int | None:
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(
                socket.create_connection((host, 443), timeout=self.timeout),
                server_hostname=host,
            ) as s:
                cert = s.getpeercert()
            if not cert:
                return None
            not_after = cert.get("notAfter", "")
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            return (expiry - datetime.now(timezone.utc)).days
        except Exception:
            return None


    def _diff(
        self, before: dict[str, Any], after: dict[str, Any]
    ) -> dict[str, Any] | None:
        changes: dict[str, Any] = {}

        new_ports = after["open_ports"] - before["open_ports"]
        closed_ports = before["open_ports"] - after["open_ports"]
        if new_ports:
            changes["new_open_ports"] = sorted(new_ports)
        if closed_ports:
            changes["newly_closed_ports"] = sorted(closed_ports)

        if before["status_code"] != after["status_code"]:
            changes["status_code_changed"] = {
                "from": before["status_code"],
                "to": after["status_code"],
            }

        delta = after["finding_count"] - before["finding_count"]
        if delta > 0:
            changes["new_findings_delta"] = delta

        ssl_days = after.get("ssl_days_left")
        if ssl_days is not None and ssl_days <= 30:
            changes["ssl_expiring_soon"] = f"{ssl_days} days left"

        return changes if changes else None


    def _persist_snapshot(self, snapshot: dict[str, Any], changes: dict[str, Any] | None) -> None:
        try:
            from vapt.database.db import get_session, init_db
            from vapt.database.models import MonitorHistory

            init_db()
            session = get_session()

            serialisable_snapshot = {
                **snapshot,
                "open_ports": sorted(snapshot["open_ports"]),
            }

            record = MonitorHistory(
                target=self.target,
                scanned_at=datetime.now(timezone.utc),
                snapshot=json.dumps(serialisable_snapshot),
                changes=json.dumps(changes) if changes else None,
            )
            session.add(record)
            session.commit()
            session.close()
        except Exception:
            pass


    def run_once(self) -> dict[str, Any]:
        snap = self._snapshot()
        self._persist_snapshot(snap, None)
        return snap

    def start(self, max_iterations: int | None = None) -> None:
        self._baseline = self._snapshot()
        self._persist_snapshot(self._baseline, None)
        iteration = 0

        while True:
            time.sleep(self.interval)
            current = self._snapshot()
            changes = self._diff(self._baseline, current)

            self._persist_snapshot(current, changes)

            if changes:
                alert = {
                    "target": self.target,
                    "detected_at": current["timestamp"],
                    "changes": changes,
                }
                self.on_change(alert)
                self._baseline = current

            iteration += 1
            if max_iterations is not None and iteration >= max_iterations:
                break
