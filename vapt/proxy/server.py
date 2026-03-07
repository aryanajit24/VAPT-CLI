"""HTTP/HTTPS intercepting proxy server with SSL MITM."""

from __future__ import annotations

import io
import logging
import os
import re
import socket
import ssl
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from vapt.proxy.storage import Flow, ProxyStorage

logger = logging.getLogger(__name__)

_BUFFER = 65536
_HTTP_NEWLINE = b"\r\n"
_HTTP_HEADER_END = b"\r\n\r\n"


class CertificateAuthority:
    """Generates a root CA and per-host certificates for SSL interception."""

    def __init__(self, ca_dir: Optional[str] = None):
        if ca_dir is None:
            ca_dir = str(Path.home() / ".vapt" / "ca")
        self.ca_dir = Path(ca_dir)
        self.ca_dir.mkdir(parents=True, exist_ok=True)
        self.ca_key_path = self.ca_dir / "ca.key"
        self.ca_cert_path = self.ca_dir / "ca.pem"
        self._cert_cache: dict[str, tuple[str, str]] = {}
        self._lock = threading.Lock()
        self.ca_key: rsa.RSAPrivateKey
        self.ca_cert: x509.Certificate
        self._ensure_ca()

    def _ensure_ca(self) -> None:
        if self.ca_key_path.exists() and self.ca_cert_path.exists():
            key_pem = self.ca_key_path.read_bytes()
            cert_pem = self.ca_cert_path.read_bytes()
            self.ca_key = serialization.load_pem_private_key(key_pem, password=None)
            self.ca_cert = x509.load_pem_x509_certificate(cert_pem)
            return

        self.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "VAPT CLI Proxy CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VAPT CLI"),
        ])
        now = datetime.now(timezone.utc)
        self.ca_cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self.ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_cert_sign=True, crl_sign=True,
                    content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .sign(self.ca_key, hashes.SHA256())
        )

        self.ca_key_path.write_bytes(
            self.ca_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        self.ca_cert_path.write_bytes(self.ca_cert.public_bytes(serialization.Encoding.PEM))

    def get_cert_for_host(self, hostname: str) -> tuple[str, str]:
        with self._lock:
            if hostname in self._cert_cache:
                return self._cert_cache[hostname]

        host_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(timezone.utc)

        san_names = [x509.DNSName(hostname)]
        if not hostname.startswith("*."):
            san_names.append(x509.DNSName(f"*.{hostname}"))

        host_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
            .issuer_name(self.ca_cert.subject)
            .public_key(host_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName(san_names), critical=False)
            .sign(self.ca_key, hashes.SHA256())
        )

        cert_dir = self.ca_dir / "certs"
        cert_dir.mkdir(exist_ok=True)
        safe_name = re.sub(r"[^\w.-]", "_", hostname)
        cert_path = cert_dir / f"{safe_name}.pem"
        key_path = cert_dir / f"{safe_name}.key"

        cert_path.write_bytes(host_cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            host_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )

        paths = (str(cert_path), str(key_path))
        with self._lock:
            self._cert_cache[hostname] = paths
        return paths

    def get_ssl_context(self, hostname: str) -> ssl.SSLContext:
        cert_path, key_path = self.get_cert_for_host(hostname)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx

    @property
    def ca_cert_pem(self) -> str:
        return self.ca_cert_path.read_text()


def _parse_request_line(data: bytes) -> tuple[str, str, str]:
    first_line = data.split(_HTTP_NEWLINE, 1)[0].decode("utf-8", errors="replace")
    parts = first_line.split(" ", 2)
    if len(parts) == 3:
        return parts[0], parts[1], parts[2]
    if len(parts) == 2:
        return parts[0], parts[1], "HTTP/1.1"
    return "GET", "/", "HTTP/1.1"


def _parse_headers(data: bytes) -> dict[str, str]:
    headers: dict[str, str] = {}
    header_section = data.split(_HTTP_HEADER_END, 1)[0]
    lines = header_section.split(_HTTP_NEWLINE)
    for line in lines[1:]:
        decoded = line.decode("utf-8", errors="replace")
        if ": " in decoded:
            key, value = decoded.split(": ", 1)
            headers[key] = value
    return headers


def _get_content_length(headers: dict[str, str]) -> int:
    for key in ("Content-Length", "content-length"):
        if key in headers:
            try:
                return int(headers[key])
            except ValueError:
                pass
    return 0


def _recv_full_request(sock: socket.socket, timeout: float = 10.0) -> bytes:
    sock.settimeout(timeout)
    data = b""
    try:
        while _HTTP_HEADER_END not in data:
            chunk = sock.recv(_BUFFER)
            if not chunk:
                break
            data += chunk

        if _HTTP_HEADER_END in data:
            header_end = data.index(_HTTP_HEADER_END) + len(_HTTP_HEADER_END)
            headers = _parse_headers(data[:header_end])
            content_length = _get_content_length(headers)
            body_received = len(data) - header_end
            while body_received < content_length:
                chunk = sock.recv(min(_BUFFER, content_length - body_received))
                if not chunk:
                    break
                data += chunk
                body_received += len(chunk)
    except socket.timeout:
        pass
    return data


def _recv_full_response(sock: socket.socket, timeout: float = 30.0) -> bytes:
    sock.settimeout(timeout)
    data = b""
    try:
        while _HTTP_HEADER_END not in data:
            chunk = sock.recv(_BUFFER)
            if not chunk:
                break
            data += chunk

        if _HTTP_HEADER_END not in data:
            return data

        header_end = data.index(_HTTP_HEADER_END) + len(_HTTP_HEADER_END)
        headers = _parse_headers(data[:header_end])

        if "Transfer-Encoding" in headers and "chunked" in headers.get("Transfer-Encoding", "").lower():
            while not data.endswith(b"0\r\n\r\n"):
                chunk = sock.recv(_BUFFER)
                if not chunk:
                    break
                data += chunk
        else:
            content_length = _get_content_length(headers)
            if content_length > 0:
                body_received = len(data) - header_end
                while body_received < content_length:
                    chunk = sock.recv(min(_BUFFER, content_length - body_received))
                    if not chunk:
                        break
                    data += chunk
                    body_received += len(chunk)
            else:
                try:
                    while True:
                        chunk = sock.recv(_BUFFER)
                        if not chunk:
                            break
                        data += chunk
                except socket.timeout:
                    pass
    except socket.timeout:
        pass
    return data


def _build_raw_request(method: str, path: str, headers: dict, body: bytes = b"") -> bytes:
    lines = [f"{method} {path} HTTP/1.1"]
    for k, v in headers.items():
        if k.lower() not in ("proxy-connection", "proxy-authorization"):
            lines.append(f"{k}: {v}")
    raw = _HTTP_NEWLINE.join(line.encode() for line in lines) + _HTTP_HEADER_END
    if body:
        raw += body
    return raw


def _parse_response_status(data: bytes) -> int:
    first_line = data.split(_HTTP_NEWLINE, 1)[0].decode("utf-8", errors="replace")
    parts = first_line.split(" ", 2)
    if len(parts) >= 2:
        try:
            return int(parts[1])
        except ValueError:
            pass
    return 0


class ProxyFilter:
    """Filter rules for intercepting specific traffic."""

    def __init__(
        self,
        include_domains: Optional[list[str]] = None,
        exclude_domains: Optional[list[str]] = None,
        include_methods: Optional[list[str]] = None,
        include_content_types: Optional[list[str]] = None,
        exclude_extensions: Optional[list[str]] = None,
    ):
        self.include_domains = include_domains
        self.exclude_domains = exclude_domains or []
        self.include_methods = [m.upper() for m in include_methods] if include_methods else None
        self.include_content_types = include_content_types
        self.exclude_extensions = exclude_extensions or [
            ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css",
            ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3",
        ]

    def should_capture(self, method: str, url: str, host: str) -> bool:
        if self.include_domains:
            if not any(d in host for d in self.include_domains):
                return False
        if any(d in host for d in self.exclude_domains):
            return False
        if self.include_methods and method.upper() not in self.include_methods:
            return False
        path = urlparse(url).path.lower()
        if any(path.endswith(ext) for ext in self.exclude_extensions):
            return False
        return True


class ProxyServer:
    """Thread-based HTTP/HTTPS intercepting proxy with SSL MITM."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        storage: Optional[ProxyStorage] = None,
        ca: Optional[CertificateAuthority] = None,
        proxy_filter: Optional[ProxyFilter] = None,
        intercept_requests: bool = False,
        intercept_responses: bool = False,
        on_request: Optional[Callable[[Flow], Optional[Flow]]] = None,
        on_response: Optional[Callable[[Flow], Optional[Flow]]] = None,
        max_workers: int = 50,
        verbose: bool = False,
    ):
        self.host = host
        self.port = port
        self.storage = storage or ProxyStorage()
        self.ca = ca or CertificateAuthority()
        self.proxy_filter = proxy_filter or ProxyFilter()
        self.intercept_requests = intercept_requests
        self.intercept_responses = intercept_responses
        self.on_request = on_request
        self.on_response = on_response
        self.max_workers = max_workers
        self.verbose = verbose

        self._server_socket: Optional[socket.socket] = None
        self._executor: Optional[ThreadPoolExecutor] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self.flow_count = 0
        self._flow_lock = threading.Lock()

    @property
    def running(self) -> bool:
        return self._running

    @property
    def ca_cert_path(self) -> str:
        return str(self.ca.ca_cert_path)

    def start(self, background: bool = False) -> None:
        self._running = True
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self.host, self.port))
        self._server_socket.listen(100)
        self._server_socket.settimeout(1.0)
        self._executor = ThreadPoolExecutor(max_workers=self.max_workers)

        if background:
            self._thread = threading.Thread(target=self._accept_loop, daemon=True)
            self._thread.start()
        else:
            self._accept_loop()

    def stop(self) -> None:
        self._running = False
        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                pass
        if self._executor:
            self._executor.shutdown(wait=False)

    def _accept_loop(self) -> None:
        while self._running:
            try:
                client_sock, addr = self._server_socket.accept()
                self._executor.submit(self._handle_client, client_sock)
            except socket.timeout:
                continue
            except OSError:
                break

    def _handle_client(self, client_sock: socket.socket) -> None:
        try:
            client_sock.settimeout(10.0)
            data = b""
            while _HTTP_NEWLINE not in data:
                chunk = client_sock.recv(_BUFFER)
                if not chunk:
                    client_sock.close()
                    return
                data += chunk

            while _HTTP_HEADER_END not in data:
                chunk = client_sock.recv(_BUFFER)
                if not chunk:
                    break
                data += chunk

            method, target, version = _parse_request_line(data)

            if method == "CONNECT":
                self._handle_connect(client_sock, target)
            else:
                self._handle_http(client_sock, data, method, target)
        except Exception as exc:
            if self.verbose:
                logger.debug("Client handler error: %s", exc)
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def _handle_connect(self, client_sock: socket.socket, target: str) -> None:
        host, _, port_str = target.partition(":")
        port = int(port_str) if port_str else 443

        client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        ssl_ctx = self.ca.get_ssl_context(host)
        try:
            tls_client = ssl_ctx.wrap_socket(client_sock, server_side=True)
        except ssl.SSLError as exc:
            if self.verbose:
                logger.debug("SSL handshake failed for %s: %s", host, exc)
            return

        try:
            request_data = _recv_full_request(tls_client, timeout=10.0)
            if not request_data:
                tls_client.close()
                return

            method, path, version = _parse_request_line(request_data)
            req_headers = _parse_headers(request_data)
            url = f"https://{host}{path}"
            body_start = request_data.find(_HTTP_HEADER_END)
            req_body = request_data[body_start + len(_HTTP_HEADER_END):] if body_start >= 0 else b""

            if not self.proxy_filter.should_capture(method, url, host):
                self._tunnel_passthrough(tls_client, host, port, request_data)
                return

            flow = Flow(
                method=method, url=url, host=host, path=path,
                request_headers=req_headers, request_body=req_body, tls=True,
            )

            if self.on_request:
                modified = self.on_request(flow)
                if modified:
                    flow = modified

            server_ctx = ssl.create_default_context()
            server_ctx.check_hostname = False
            server_ctx.verify_mode = ssl.CERT_NONE
            server_sock = socket.create_connection((host, port), timeout=15)
            tls_server = server_ctx.wrap_socket(server_sock, server_hostname=host)

            forward_headers = dict(req_headers)
            forward_headers.setdefault("Host", host)
            forward_data = _build_raw_request(method, path, forward_headers, req_body)

            start_time = time.time()
            tls_server.sendall(forward_data)
            response_data = _recv_full_response(tls_server)
            elapsed = time.time() - start_time

            tls_server.close()

            if response_data:
                status = _parse_response_status(response_data)
                resp_headers = _parse_headers(response_data)
                resp_body_start = response_data.find(_HTTP_HEADER_END)
                resp_body = response_data[resp_body_start + len(_HTTP_HEADER_END):] if resp_body_start >= 0 else b""

                flow.status_code = status
                flow.response_headers = resp_headers
                flow.response_body = resp_body
                flow.response_time = elapsed
                flow.content_type = resp_headers.get("Content-Type", resp_headers.get("content-type", ""))

                if self.on_response:
                    modified = self.on_response(flow)
                    if modified:
                        flow = modified

                self.storage.save_flow(flow)
                with self._flow_lock:
                    self.flow_count += 1

                tls_client.sendall(response_data)

            tls_client.close()

        except Exception as exc:
            if self.verbose:
                logger.debug("HTTPS handler error for %s: %s", target, exc)
            try:
                tls_client.close()
            except Exception:
                pass

    def _tunnel_passthrough(self, tls_client, host: str, port: int, request_data: bytes) -> None:
        try:
            server_ctx = ssl.create_default_context()
            server_ctx.check_hostname = False
            server_ctx.verify_mode = ssl.CERT_NONE
            server_sock = socket.create_connection((host, port), timeout=15)
            tls_server = server_ctx.wrap_socket(server_sock, server_hostname=host)
            tls_server.sendall(request_data)
            response = _recv_full_response(tls_server)
            tls_server.close()
            if response:
                tls_client.sendall(response)
        except Exception:
            pass

    def _handle_http(self, client_sock: socket.socket, data: bytes, method: str, url: str) -> None:
        parsed = urlparse(url)
        host = parsed.netloc or parsed.hostname or ""
        port = parsed.port or 80
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"

        req_headers = _parse_headers(data)
        body_start = data.find(_HTTP_HEADER_END)
        req_body = data[body_start + len(_HTTP_HEADER_END):] if body_start >= 0 else b""

        content_length = _get_content_length(req_headers)
        while len(req_body) < content_length:
            chunk = client_sock.recv(min(_BUFFER, content_length - len(req_body)))
            if not chunk:
                break
            req_body += chunk

        if not self.proxy_filter.should_capture(method, url, host):
            return

        flow = Flow(
            method=method, url=url, host=host, path=path,
            request_headers=req_headers, request_body=req_body, tls=False,
        )

        if self.on_request:
            modified = self.on_request(flow)
            if modified:
                flow = modified

        try:
            actual_host = host.split(":")[0] if ":" in host else host
            actual_port = int(host.split(":")[1]) if ":" in host else port
            server_sock = socket.create_connection((actual_host, actual_port), timeout=15)

            forward_headers = dict(req_headers)
            forward_headers.setdefault("Host", host)
            forward_data = _build_raw_request(method, path, forward_headers, req_body)

            start_time = time.time()
            server_sock.sendall(forward_data)
            response_data = _recv_full_response(server_sock)
            elapsed = time.time() - start_time
            server_sock.close()

            if response_data:
                status = _parse_response_status(response_data)
                resp_headers = _parse_headers(response_data)
                resp_body_start = response_data.find(_HTTP_HEADER_END)
                resp_body = response_data[resp_body_start + len(_HTTP_HEADER_END):] if resp_body_start >= 0 else b""

                flow.status_code = status
                flow.response_headers = resp_headers
                flow.response_body = resp_body
                flow.response_time = elapsed
                flow.content_type = resp_headers.get("Content-Type", resp_headers.get("content-type", ""))

                if self.on_response:
                    modified = self.on_response(flow)
                    if modified:
                        flow = modified

                self.storage.save_flow(flow)
                with self._flow_lock:
                    self.flow_count += 1

                client_sock.sendall(response_data)

        except Exception as exc:
            error_resp = (
                b"HTTP/1.1 502 Bad Gateway\r\n"
                b"Content-Type: text/plain\r\n"
                b"Connection: close\r\n\r\n"
                b"VAPT Proxy: upstream connection failed\r\n"
            )
            try:
                client_sock.sendall(error_resp)
            except Exception:
                pass
            if self.verbose:
                logger.debug("HTTP handler error: %s", exc)


def replay_request(flow: Flow, timeout: int = 15, verify_ssl: bool = False) -> Flow:
    """Replay a captured request and return a new Flow with the response."""
    import requests as req_lib

    headers = dict(flow.request_headers)
    headers.pop("Host", None)
    headers.pop("Content-Length", None)

    try:
        start = time.time()
        resp = req_lib.request(
            method=flow.method,
            url=flow.url,
            headers=headers,
            data=flow.request_body if flow.request_body else None,
            timeout=timeout,
            verify=verify_ssl,
            allow_redirects=False,
        )
        elapsed = time.time() - start

        return Flow(
            method=flow.method,
            url=flow.url,
            host=flow.host,
            path=flow.path,
            request_headers=flow.request_headers,
            request_body=flow.request_body,
            status_code=resp.status_code,
            response_headers=dict(resp.headers),
            response_body=resp.content,
            response_time=elapsed,
            tls=flow.tls,
            content_type=resp.headers.get("Content-Type", ""),
        )
    except Exception as exc:
        return Flow(
            method=flow.method, url=flow.url, host=flow.host,
            notes=f"Replay failed: {exc}",
        )
