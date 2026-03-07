"""SQLite storage for intercepted proxy flows."""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class Flow:
    """Single HTTP request/response pair."""

    id: int = 0
    timestamp: float = 0.0
    method: str = ""
    url: str = ""
    host: str = ""
    path: str = ""
    request_headers: dict = field(default_factory=dict)
    request_body: bytes = b""
    status_code: int = 0
    response_headers: dict = field(default_factory=dict)
    response_body: bytes = b""
    response_time: float = 0.0
    tls: bool = False
    content_type: str = ""
    notes: str = ""
    tags: str = ""
    intercepted: bool = False


class ProxyStorage:
    """Persistent storage for proxy flows using SQLite."""

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            db_dir = Path.home() / ".vapt"
            db_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(db_dir / "proxy.db")
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self) -> None:
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                method TEXT NOT NULL,
                url TEXT NOT NULL,
                host TEXT NOT NULL DEFAULT '',
                path TEXT NOT NULL DEFAULT '',
                request_headers TEXT NOT NULL DEFAULT '{}',
                request_body BLOB DEFAULT x'',
                status_code INTEGER DEFAULT 0,
                response_headers TEXT NOT NULL DEFAULT '{}',
                response_body BLOB DEFAULT x'',
                response_time REAL DEFAULT 0.0,
                tls INTEGER DEFAULT 0,
                content_type TEXT DEFAULT '',
                notes TEXT DEFAULT '',
                tags TEXT DEFAULT '',
                intercepted INTEGER DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_flows_host ON flows(host);
            CREATE INDEX IF NOT EXISTS idx_flows_method ON flows(method);
            CREATE INDEX IF NOT EXISTS idx_flows_status ON flows(status_code);
            CREATE INDEX IF NOT EXISTS idx_flows_timestamp ON flows(timestamp);

            CREATE TABLE IF NOT EXISTS repeater (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                flow_id INTEGER,
                method TEXT NOT NULL,
                url TEXT NOT NULL,
                headers TEXT NOT NULL DEFAULT '{}',
                body BLOB DEFAULT x'',
                created_at REAL NOT NULL,
                FOREIGN KEY (flow_id) REFERENCES flows(id)
            );
        """)
        self.conn.commit()

    def save_flow(self, flow: Flow) -> int:
        if flow.timestamp == 0:
            flow.timestamp = time.time()
        cursor = self.conn.execute(
            """INSERT INTO flows (timestamp, method, url, host, path,
               request_headers, request_body, status_code, response_headers,
               response_body, response_time, tls, content_type, notes, tags, intercepted)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                flow.timestamp, flow.method, flow.url, flow.host, flow.path,
                json.dumps(flow.request_headers), flow.request_body,
                flow.status_code, json.dumps(flow.response_headers),
                flow.response_body, flow.response_time,
                1 if flow.tls else 0, flow.content_type,
                flow.notes, flow.tags, 1 if flow.intercepted else 0,
            ),
        )
        self.conn.commit()
        flow.id = cursor.lastrowid
        return flow.id

    def update_response(self, flow_id: int, status_code: int, headers: dict,
                        body: bytes, response_time: float) -> None:
        content_type = headers.get("content-type", headers.get("Content-Type", ""))
        self.conn.execute(
            """UPDATE flows SET status_code=?, response_headers=?, response_body=?,
               response_time=?, content_type=? WHERE id=?""",
            (status_code, json.dumps(headers), body, response_time, content_type, flow_id),
        )
        self.conn.commit()

    def get_flow(self, flow_id: int) -> Optional[Flow]:
        row = self.conn.execute("SELECT * FROM flows WHERE id=?", (flow_id,)).fetchone()
        if not row:
            return None
        return self._row_to_flow(row)

    def get_flows(
        self,
        limit: int = 500,
        offset: int = 0,
        host: Optional[str] = None,
        method: Optional[str] = None,
        status: Optional[int] = None,
        search: Optional[str] = None,
        content_type: Optional[str] = None,
    ) -> list[Flow]:
        conditions = []
        params: list = []

        if host:
            conditions.append("host LIKE ?")
            params.append(f"%{host}%")
        if method:
            conditions.append("method = ?")
            params.append(method.upper())
        if status:
            conditions.append("status_code = ?")
            params.append(status)
        if search:
            conditions.append("(url LIKE ? OR notes LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%"])
        if content_type:
            conditions.append("content_type LIKE ?")
            params.append(f"%{content_type}%")

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        query = f"SELECT * FROM flows {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = self.conn.execute(query, params).fetchall()
        return [self._row_to_flow(r) for r in rows]

    def get_flow_count(self) -> int:
        row = self.conn.execute("SELECT COUNT(*) FROM flows").fetchone()
        return row[0] if row else 0

    def delete_flow(self, flow_id: int) -> None:
        self.conn.execute("DELETE FROM flows WHERE id=?", (flow_id,))
        self.conn.commit()

    def clear_flows(self) -> None:
        self.conn.execute("DELETE FROM flows")
        self.conn.commit()

    def add_note(self, flow_id: int, note: str) -> None:
        self.conn.execute("UPDATE flows SET notes=? WHERE id=?", (note, flow_id))
        self.conn.commit()

    def add_tag(self, flow_id: int, tag: str) -> None:
        row = self.conn.execute("SELECT tags FROM flows WHERE id=?", (flow_id,)).fetchone()
        if row:
            existing = row[0]
            tags = f"{existing},{tag}" if existing else tag
            self.conn.execute("UPDATE flows SET tags=? WHERE id=?", (tags, flow_id))
            self.conn.commit()

    def save_to_repeater(self, flow_id: int, name: str) -> int:
        flow = self.get_flow(flow_id)
        if not flow:
            raise ValueError(f"Flow {flow_id} not found")
        cursor = self.conn.execute(
            "INSERT INTO repeater (name, flow_id, method, url, headers, body, created_at) VALUES (?,?,?,?,?,?,?)",
            (name, flow_id, flow.method, flow.url,
             json.dumps(flow.request_headers), flow.request_body, time.time()),
        )
        self.conn.commit()
        return cursor.lastrowid

    def get_repeater_items(self) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM repeater ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]

    def export_flows(self, path: str, flow_ids: Optional[list[int]] = None) -> int:
        if flow_ids:
            placeholders = ",".join("?" * len(flow_ids))
            rows = self.conn.execute(f"SELECT * FROM flows WHERE id IN ({placeholders})", flow_ids).fetchall()
        else:
            rows = self.conn.execute("SELECT * FROM flows ORDER BY timestamp").fetchall()

        flows = []
        for r in rows:
            f = self._row_to_flow(r)
            flows.append({
                "id": f.id, "timestamp": f.timestamp, "method": f.method,
                "url": f.url, "host": f.host, "status_code": f.status_code,
                "request_headers": f.request_headers,
                "request_body": f.request_body.decode("utf-8", errors="replace"),
                "response_headers": f.response_headers,
                "response_body": f.response_body.decode("utf-8", errors="replace"),
                "response_time": f.response_time, "tls": f.tls,
            })

        Path(path).write_text(json.dumps(flows, indent=2))
        return len(flows)

    def _row_to_flow(self, row: sqlite3.Row) -> Flow:
        return Flow(
            id=row["id"],
            timestamp=row["timestamp"],
            method=row["method"],
            url=row["url"],
            host=row["host"],
            path=row["path"],
            request_headers=json.loads(row["request_headers"]),
            request_body=bytes(row["request_body"]) if row["request_body"] else b"",
            status_code=row["status_code"],
            response_headers=json.loads(row["response_headers"]),
            response_body=bytes(row["response_body"]) if row["response_body"] else b"",
            response_time=row["response_time"],
            tls=bool(row["tls"]),
            content_type=row["content_type"],
            notes=row["notes"],
            tags=row["tags"],
            intercepted=bool(row["intercepted"]),
        )

    def close(self) -> None:
        self.conn.close()
