"""Interactive security testing TUI built with Textual."""

from __future__ import annotations

import json
import time
import threading
from typing import Optional

from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    RichLog,
    Select,
    Static,
    TabbedContent,
    TabPane,
    TextArea,
)

from vapt.proxy.server import CertificateAuthority, ProxyServer, replay_request
from vapt.proxy.storage import Flow, ProxyStorage
from vapt.utils.codec import Codec


class ProxyTab(Container):
    """Proxy traffic viewer with filtering."""

    def compose(self) -> ComposeResult:
        with Horizontal(id="proxy-controls"):
            yield Button("Start Proxy", id="proxy-start", variant="success")
            yield Button("Stop Proxy", id="proxy-stop", variant="error", disabled=True)
            yield Input(placeholder="Filter: host, method, or URL...", id="proxy-filter")
            yield Button("Clear", id="proxy-clear", variant="warning")
            yield Button("Export", id="proxy-export", variant="default")
        yield DataTable(id="proxy-table")
        with Horizontal(id="proxy-detail"):
            with Vertical(id="proxy-req-panel"):
                yield Label("Request", classes="panel-title")
                yield TextArea(id="proxy-request", read_only=True, language="http")
            with Vertical(id="proxy-resp-panel"):
                yield Label("Response", classes="panel-title")
                yield TextArea(id="proxy-response", read_only=True, language="http")

    def on_mount(self) -> None:
        table = self.query_one("#proxy-table", DataTable)
        table.add_columns("#", "Method", "Host", "Path", "Status", "Length", "Time")
        table.cursor_type = "row"


class RepeaterTab(Container):
    """Manual request editor and sender."""

    def compose(self) -> ComposeResult:
        with Horizontal(id="repeater-controls"):
            yield Input(placeholder="URL (e.g., https://example.com/api)", id="repeater-url")
            yield Select(
                [(m, m) for m in ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]],
                value="GET",
                id="repeater-method",
            )
            yield Button("Send", id="repeater-send", variant="success")
        with Horizontal(id="repeater-panels"):
            with Vertical(id="repeater-req-panel"):
                yield Label("Request Headers & Body", classes="panel-title")
                yield TextArea(
                    "User-Agent: VAPT-CLI/9.0\nAccept: */*\n\n",
                    id="repeater-req-editor",
                    language="http",
                )
            with Vertical(id="repeater-resp-panel"):
                yield Label("Response", classes="panel-title")
                yield TextArea(id="repeater-resp-view", read_only=True, language="http")
        yield Label("", id="repeater-status")


class IntruderTab(Container):
    """Fuzzing configuration and results."""

    def compose(self) -> ComposeResult:
        with Vertical(id="intruder-config"):
            with Horizontal():
                yield Input(placeholder="Target URL with §markers§", id="intruder-url")
                yield Select(
                    [("Sniper", "sniper"), ("Battering Ram", "battering_ram"),
                     ("Pitchfork", "pitchfork"), ("Cluster Bomb", "cluster_bomb")],
                    value="sniper",
                    id="intruder-mode",
                )
            with Horizontal():
                yield Select(
                    [("SQLi", "sqli"), ("XSS", "xss"), ("Path Traversal", "traversal"),
                     ("SSTI", "ssti"), ("NoSQL", "nosql"), ("Commands", "commands"),
                     ("Common Passwords", "common_passwords"), ("IDOR Numbers", "idor")],
                    value="sqli",
                    id="intruder-payload-set",
                )
                yield Button("Start Attack", id="intruder-start", variant="error")
                yield Button("Stop", id="intruder-stop", variant="warning", disabled=True)
        yield DataTable(id="intruder-table")
        yield RichLog(id="intruder-log", wrap=True, max_lines=500)

    def on_mount(self) -> None:
        table = self.query_one("#intruder-table", DataTable)
        table.add_columns("#", "Payload", "Status", "Length", "Time", "Notes")
        table.cursor_type = "row"


class CodecTab(Container):
    """Encoder/decoder utility."""

    def compose(self) -> ComposeResult:
        with Vertical(id="codec-layout"):
            yield Label("Input", classes="panel-title")
            yield TextArea(id="codec-input", language="text")
            with Horizontal(id="codec-buttons"):
                yield Button("Base64 Enc", id="codec-b64e")
                yield Button("Base64 Dec", id="codec-b64d")
                yield Button("URL Enc", id="codec-urle")
                yield Button("URL Dec", id="codec-urld")
                yield Button("Hex Enc", id="codec-hexe")
                yield Button("Hex Dec", id="codec-hexd")
            with Horizontal(id="codec-buttons2"):
                yield Button("HTML Enc", id="codec-htmle")
                yield Button("HTML Dec", id="codec-htmld")
                yield Button("JWT Dec", id="codec-jwtd")
                yield Button("Hash ID", id="codec-hashid")
                yield Button("Smart Decode", id="codec-smart")
                yield Button("MD5", id="codec-md5")
                yield Button("SHA256", id="codec-sha256")
            yield Label("Output", classes="panel-title")
            yield TextArea(id="codec-output", read_only=True, language="text")


CSS = """
Screen {
    background: $surface;
}
#proxy-controls, #repeater-controls {
    height: 3;
    dock: top;
    padding: 0 1;
}
#proxy-controls Button, #repeater-controls Button {
    margin: 0 1;
}
#proxy-controls Input, #repeater-controls Input {
    width: 1fr;
}
#proxy-table, #intruder-table {
    height: 1fr;
    max-height: 50%;
}
#proxy-detail, #repeater-panels {
    height: 1fr;
}
#proxy-req-panel, #proxy-resp-panel,
#repeater-req-panel, #repeater-resp-panel {
    width: 1fr;
    padding: 0 1;
}
.panel-title {
    text-style: bold;
    color: $accent;
    padding: 0 1;
}
#intruder-config {
    height: auto;
    max-height: 6;
    padding: 0 1;
}
#intruder-config Horizontal {
    height: 3;
}
#intruder-config Input {
    width: 1fr;
}
#intruder-log {
    height: auto;
    max-height: 8;
    border-top: solid $accent;
}
#codec-layout {
    padding: 1;
}
#codec-input, #codec-output {
    height: 1fr;
}
#codec-buttons, #codec-buttons2 {
    height: 3;
    align: center middle;
}
#codec-buttons Button, #codec-buttons2 Button {
    margin: 0 1;
}
#repeater-status {
    dock: bottom;
    height: 1;
    padding: 0 1;
    color: $text-muted;
}
"""


class VAPTApp(App):
    """VAPT CLI Interactive Security Testing Console."""

    TITLE = "VAPT CLI — Security Testing Console"
    CSS = CSS
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("1", "tab_proxy", "Proxy", show=True),
        Binding("2", "tab_repeater", "Repeater", show=True),
        Binding("3", "tab_intruder", "Intruder", show=True),
        Binding("4", "tab_codec", "Codec", show=True),
    ]

    def __init__(self, proxy_port: int = 8080, **kwargs):
        super().__init__(**kwargs)
        self.proxy_port = proxy_port
        self.storage = ProxyStorage()
        self.ca = CertificateAuthority()
        self.proxy: Optional[ProxyServer] = None
        self._refresh_timer = None

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent(initial="proxy"):
            with TabPane("Proxy", id="proxy"):
                yield ProxyTab()
            with TabPane("Repeater", id="repeater"):
                yield RepeaterTab()
            with TabPane("Intruder", id="intruder"):
                yield IntruderTab()
            with TabPane("Codec", id="codec"):
                yield CodecTab()
        yield Footer()

    def action_tab_proxy(self) -> None:
        self.query_one(TabbedContent).active = "proxy"

    def action_tab_repeater(self) -> None:
        self.query_one(TabbedContent).active = "repeater"

    def action_tab_intruder(self) -> None:
        self.query_one(TabbedContent).active = "intruder"

    def action_tab_codec(self) -> None:
        self.query_one(TabbedContent).active = "codec"

    # ── Proxy handlers ───────────────────────────────────────

    @on(Button.Pressed, "#proxy-start")
    def start_proxy(self) -> None:
        if self.proxy and self.proxy.running:
            return
        self.proxy = ProxyServer(
            host="127.0.0.1",
            port=self.proxy_port,
            storage=self.storage,
            ca=self.ca,
            verbose=False,
        )
        self.proxy.start(background=True)
        self.query_one("#proxy-start", Button).disabled = True
        self.query_one("#proxy-stop", Button).disabled = False
        self.notify(f"Proxy started on 127.0.0.1:{self.proxy_port}")
        self._start_refresh()

    @on(Button.Pressed, "#proxy-stop")
    def stop_proxy(self) -> None:
        if self.proxy:
            self.proxy.stop()
            self.proxy = None
        self.query_one("#proxy-start", Button).disabled = False
        self.query_one("#proxy-stop", Button).disabled = True
        self.notify("Proxy stopped")

    @on(Button.Pressed, "#proxy-clear")
    def clear_proxy(self) -> None:
        self.storage.clear_flows()
        table = self.query_one("#proxy-table", DataTable)
        table.clear()
        self.notify("Flows cleared")

    @on(Button.Pressed, "#proxy-export")
    def export_proxy(self) -> None:
        path = "./vapt-proxy-export.json"
        count = self.storage.export_flows(path)
        self.notify(f"Exported {count} flows to {path}")

    @on(DataTable.RowSelected, "#proxy-table")
    def proxy_row_selected(self, event: DataTable.RowSelected) -> None:
        row_key = event.row_key
        if row_key is None:
            return
        try:
            flow_id = int(str(row_key.value))
        except (ValueError, TypeError):
            return
        flow = self.storage.get_flow(flow_id)
        if not flow:
            return
        req_text = f"{flow.method} {flow.path} HTTP/1.1\n"
        for k, v in flow.request_headers.items():
            req_text += f"{k}: {v}\n"
        if flow.request_body:
            req_text += f"\n{flow.request_body.decode('utf-8', errors='replace')}"
        self.query_one("#proxy-request", TextArea).load_text(req_text)

        resp_text = f"HTTP/1.1 {flow.status_code}\n"
        for k, v in flow.response_headers.items():
            resp_text += f"{k}: {v}\n"
        if flow.response_body:
            body = flow.response_body.decode("utf-8", errors="replace")
            resp_text += f"\n{body[:5000]}"
        self.query_one("#proxy-response", TextArea).load_text(resp_text)

    def _start_refresh(self) -> None:
        self.set_interval(2.0, self._refresh_proxy_table)

    def _refresh_proxy_table(self) -> None:
        if not self.proxy or not self.proxy.running:
            return
        table = self.query_one("#proxy-table", DataTable)
        filter_text = self.query_one("#proxy-filter", Input).value.strip()

        flows = self.storage.get_flows(
            limit=200,
            search=filter_text if filter_text else None,
        )

        if len(flows) != table.row_count:
            table.clear()
            for flow in reversed(flows):
                table.add_row(
                    str(flow.id),
                    flow.method,
                    flow.host,
                    flow.path[:50],
                    str(flow.status_code),
                    str(len(flow.response_body)),
                    f"{flow.response_time:.0f}ms" if flow.response_time else "-",
                    key=str(flow.id),
                )

    # ── Repeater handlers ────────────────────────────────────

    @on(Button.Pressed, "#repeater-send")
    @work(thread=True)
    def send_repeater(self) -> None:
        url = self.query_one("#repeater-url", Input).value.strip()
        if not url:
            self.notify("Enter a URL first", severity="warning")
            return

        method_select = self.query_one("#repeater-method", Select)
        method = str(method_select.value) if method_select.value else "GET"
        editor = self.query_one("#repeater-req-editor", TextArea)
        raw_text = editor.text

        headers = {}
        body = b""
        lines = raw_text.split("\n")
        body_start = False
        body_lines = []
        for line in lines:
            if body_start:
                body_lines.append(line)
            elif line.strip() == "":
                body_start = True
            elif ": " in line:
                k, v = line.split(": ", 1)
                headers[k.strip()] = v.strip()

        if body_lines:
            body = "\n".join(body_lines).encode()

        flow = Flow(method=method, url=url, host=url.split("//")[-1].split("/")[0],
                     request_headers=headers, request_body=body, tls=url.startswith("https"))

        start = time.time()
        result = replay_request(flow)
        elapsed = time.time() - start

        resp_text = f"HTTP/1.1 {result.status_code}\n"
        for k, v in result.response_headers.items():
            resp_text += f"{k}: {v}\n"
        if result.response_body:
            resp_body = result.response_body.decode("utf-8", errors="replace")
            resp_text += f"\n{resp_body[:10000]}"

        self.call_from_thread(
            self.query_one("#repeater-resp-view", TextArea).load_text, resp_text
        )
        self.call_from_thread(
            self._update_repeater_status,
            f"Status: {result.status_code} | Length: {len(result.response_body)} | Time: {elapsed:.3f}s"
        )

    def _update_repeater_status(self, text: str) -> None:
        self.query_one("#repeater-status", Label).update(text)

    # ── Intruder handlers ────────────────────────────────────

    @on(Button.Pressed, "#intruder-start")
    @work(thread=True)
    def start_intruder(self) -> None:
        from vapt.engine.intruder import BUILTIN_PAYLOADS, Intruder, IntruderConfig

        url = self.query_one("#intruder-url", Input).value.strip()
        if not url:
            self.notify("Enter a target URL with §markers§", severity="warning")
            return

        mode_select = self.query_one("#intruder-mode", Select)
        attack_type = str(mode_select.value) if mode_select.value else "sniper"
        payload_select = self.query_one("#intruder-payload-set", Select)
        payload_name = str(payload_select.value) if payload_select.value else "sqli"

        payload_list = BUILTIN_PAYLOADS.get(payload_name, [])
        marker = "§"
        positions = []
        i = 0
        while i < len(url):
            start = url.find(marker, i)
            if start == -1:
                break
            end = url.find(marker, start + 1)
            if end == -1:
                break
            positions.append(url[start + 1:end])
            i = end + 1

        config = IntruderConfig(
            base_url=url,
            positions=positions,
            payloads=[payload_list],
            attack_type=attack_type,
            threads=10,
        )

        self.call_from_thread(self._toggle_intruder_buttons, True)
        table = self.query_one("#intruder-table", DataTable)
        self.call_from_thread(table.clear)
        log = self.query_one("#intruder-log", RichLog)
        self.call_from_thread(log.clear)
        self.call_from_thread(log.write, f"Starting {attack_type} attack with {len(payload_list)} payloads...")

        intruder = Intruder(config)
        count = 0

        def on_progress(current, total, result):
            nonlocal count
            count += 1
            self.call_from_thread(
                table.add_row,
                str(count), result.payload[:40], str(result.status_code),
                str(result.content_length), f"{result.response_time:.2f}s",
                "; ".join(result.notes) if result.notes else "",
            )
            if result.interesting:
                self.call_from_thread(
                    log.write, f"[bold red]INTERESTING:[/] {result.payload} → {result.status_code} ({'; '.join(result.notes)})"
                )

        results = intruder.run(progress_callback=on_progress)
        summary = intruder.summary()

        self.call_from_thread(
            log.write,
            f"\nDone: {summary['total_requests']} requests, "
            f"{summary['interesting_count']} interesting, "
            f"{summary['error_count']} errors"
        )
        self.call_from_thread(self._toggle_intruder_buttons, False)

    @on(Button.Pressed, "#intruder-stop")
    def stop_intruder(self) -> None:
        self.notify("Attack stopped")
        self._toggle_intruder_buttons(False)

    def _toggle_intruder_buttons(self, running: bool) -> None:
        self.query_one("#intruder-start", Button).disabled = running
        self.query_one("#intruder-stop", Button).disabled = not running

    # ── Codec handlers ───────────────────────────────────────

    def _codec_op(self, operation: str) -> None:
        input_area = self.query_one("#codec-input", TextArea)
        output_area = self.query_one("#codec-output", TextArea)
        data = input_area.text.strip()
        if not data:
            return

        try:
            ops = {
                "b64e": lambda d: Codec.encode_base64(d),
                "b64d": lambda d: Codec.decode_base64(d),
                "urle": lambda d: Codec.encode_url(d),
                "urld": lambda d: Codec.decode_url(d),
                "hexe": lambda d: Codec.encode_hex(d),
                "hexd": lambda d: Codec.decode_hex(d),
                "htmle": lambda d: Codec.encode_html(d),
                "htmld": lambda d: Codec.decode_html(d),
                "jwtd": lambda d: json.dumps(Codec.decode_jwt(d), indent=2),
                "hashid": lambda d: ", ".join(Codec.identify_hash(d)),
                "smart": lambda d: json.dumps(Codec.smart_decode(d), indent=2, default=str),
                "md5": lambda d: Codec.hash_string(d, "md5"),
                "sha256": lambda d: Codec.hash_string(d, "sha256"),
            }
            result = ops[operation](data)
            output_area.load_text(result)
        except Exception as exc:
            output_area.load_text(f"Error: {exc}")

    @on(Button.Pressed, "#codec-b64e")
    def codec_b64e(self) -> None: self._codec_op("b64e")
    @on(Button.Pressed, "#codec-b64d")
    def codec_b64d(self) -> None: self._codec_op("b64d")
    @on(Button.Pressed, "#codec-urle")
    def codec_urle(self) -> None: self._codec_op("urle")
    @on(Button.Pressed, "#codec-urld")
    def codec_urld(self) -> None: self._codec_op("urld")
    @on(Button.Pressed, "#codec-hexe")
    def codec_hexe(self) -> None: self._codec_op("hexe")
    @on(Button.Pressed, "#codec-hexd")
    def codec_hexd(self) -> None: self._codec_op("hexd")
    @on(Button.Pressed, "#codec-htmle")
    def codec_htmle(self) -> None: self._codec_op("htmle")
    @on(Button.Pressed, "#codec-htmld")
    def codec_htmld(self) -> None: self._codec_op("htmld")
    @on(Button.Pressed, "#codec-jwtd")
    def codec_jwtd(self) -> None: self._codec_op("jwtd")
    @on(Button.Pressed, "#codec-hashid")
    def codec_hashid(self) -> None: self._codec_op("hashid")
    @on(Button.Pressed, "#codec-smart")
    def codec_smart(self) -> None: self._codec_op("smart")
    @on(Button.Pressed, "#codec-md5")
    def codec_md5(self) -> None: self._codec_op("md5")
    @on(Button.Pressed, "#codec-sha256")
    def codec_sha256(self) -> None: self._codec_op("sha256")

    def on_unmount(self) -> None:
        if self.proxy and self.proxy.running:
            self.proxy.stop()


def launch_tui(proxy_port: int = 8080) -> None:
    """Launch the interactive TUI."""
    app = VAPTApp(proxy_port=proxy_port)
    app.run()
