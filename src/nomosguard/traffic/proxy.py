"""Loopback MITM proxy that records deterministic traffic evidence.

The proxy is intentionally small and explicit: one HTTPS request per CONNECT
tunnel, a bounded body, a fixed parser, a ledger append, a rule-engine decision,
and then either forwarding or a 403. It never invokes a model and never treats
an unobserved request as benign.

Every captured request is appended to the caller's ``EvidenceLedger`` before any
upstream connection is attempted. The ledger supplies the UTC timestamp,
sequence number, previous hash and entry hash; the claim payload supplies the
payload SHA-256, the classification and the masked findings. A blocked request
is still evidence: an attempt is not erased by refusing it.
"""

from __future__ import annotations

import contextlib
import http.client
import json
import socket
import socketserver
import ssl
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO, Self

from ..constants import CLAIM_KIND_TRAFFIC_REQUEST, traffic_policy
from ..gate import Decision, PolicyGate
from ..ledger import Claim, EvidenceLedger
from ..rules import RuleEngine
from .certs import CertificateAuthority, CertificateError
from .classify import (
    TrafficClassification,
    TrafficRequest,
    build_claim_payload,
    classify_request,
)

MAX_BODY_BYTES = 16 * 1024 * 1024
MAX_HEADER_BYTES = 64 * 1024
_HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-connection",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
    }
)


class ProxyError(RuntimeError):
    """A captured request could not be parsed or forwarded safely."""


@dataclass
class Capture:
    request: TrafficRequest
    classification: TrafficClassification
    payload: dict[str, Any]
    seq: int
    entry_hash: str
    decision: str
    policy_rule: str
    blocked: bool
    reasons: tuple[str, ...] = field(default_factory=tuple)


def _read_until(rfile: BinaryIO, marker: bytes, limit: int, *, what: str) -> bytes:
    data = b""
    while marker not in data:
        chunk = rfile.read(1)
        if not chunk:
            return data
        data += chunk
        if len(data) > limit:
            raise ProxyError(f"{what} exceeds {limit} bytes")
    return data


def _read_exact(rfile: BinaryIO, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = rfile.read(remaining)
        if not chunk:
            raise ProxyError("request body ended before Content-Length")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_chunked(rfile: BinaryIO) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        line = rfile.readline(1024)
        if not line:
            raise ProxyError("chunked body ended before the final chunk")
        size_text = line.split(b";", 1)[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError as exc:
            raise ProxyError("invalid chunk size") from exc
        if size == 0:
            while True:
                trailer = rfile.readline(MAX_HEADER_BYTES)
                if not trailer or trailer in (b"\r\n", b"\n"):
                    return b"".join(chunks)
        total += size
        if total > MAX_BODY_BYTES:
            raise ProxyError(f"request body exceeds {MAX_BODY_BYTES} bytes")
        chunks.append(_read_exact(rfile, size))
        terminator = rfile.read(2)
        if terminator != b"\r\n":
            raise ProxyError("invalid chunk terminator")


def _parse_http_request(rfile: BinaryIO) -> tuple[str, str, dict[str, str], bytes] | None:
    head = _read_until(rfile, b"\r\n\r\n", MAX_HEADER_BYTES, what="request headers")
    if not head:
        return None
    lines = head[:-4].decode("latin-1").split("\r\n")
    if not lines or not lines[0]:
        raise ProxyError("empty request line")
    parts = lines[0].split(" ")
    if len(parts) != 3:
        raise ProxyError("malformed request line")
    method, path, _version = parts
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            raise ProxyError("malformed request header")
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()

    transfer_encoding = headers.get("transfer-encoding", "").lower()
    if "chunked" in transfer_encoding:
        body = _read_chunked(rfile)
    elif "content-length" in headers:
        try:
            length = int(headers["content-length"])
        except ValueError as exc:
            raise ProxyError("invalid Content-Length") from exc
        if length < 0:
            raise ProxyError("negative Content-Length")
        if length > MAX_BODY_BYTES:
            raise ProxyError(f"request body exceeds {MAX_BODY_BYTES} bytes")
        body = _read_exact(rfile, length)
    else:
        body = b""
    return method, path, headers, body


def _split_authority(authority: str) -> tuple[str, int]:
    value = authority.strip()
    if not value:
        raise ProxyError("empty CONNECT authority")
    if value.startswith("["):
        end = value.find("]")
        if end < 0:
            raise ProxyError("malformed IPv6 authority")
        host = value[1:end]
        rest = value[end + 1:]
        try:
            port = int(rest[1:]) if rest.startswith(":") and rest[1:] else 443
        except ValueError as exc:
            raise ProxyError("invalid CONNECT port") from exc
    elif ":" in value:
        host, port_text = value.rsplit(":", 1)
        try:
            port = int(port_text)
        except ValueError as exc:
            raise ProxyError("invalid CONNECT port") from exc
    else:
        host, port = value, 443
    if not host:
        raise ProxyError("empty CONNECT host")
    if not 0 < port < 65536:
        raise ProxyError("CONNECT port out of range")
    return host, port


def _host_header(host: str, port: int) -> str:
    rendered = f"[{host}]" if ":" in host else host
    return rendered if port == 443 else f"{rendered}:{port}"


class _ProxyServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        handler: type[socketserver.BaseRequestHandler],
        owner: TrafficProxy,
    ) -> None:
        self.owner = owner
        super().__init__(address, handler)


class _ProxyHandler(socketserver.BaseRequestHandler):
    server: _ProxyServer

    def handle(self) -> None:
        owner = self.server.owner
        try:
            rfile = self.request.makefile("rb")
            try:
                raw = _read_until(
                    rfile, b"\r\n\r\n", MAX_HEADER_BYTES, what="CONNECT headers"
                )
            finally:
                rfile.close()
            if not raw:
                return
            first = raw.split(b"\r\n", 1)[0].decode("latin-1")
            parts = first.split(" ")
            if len(parts) != 3 or parts[0].upper() != "CONNECT":
                self.request.sendall(
                    b"HTTP/1.1 405 Method Not Allowed\r\n"
                    b"Content-Length: 0\r\nConnection: close\r\n\r\n"
                )
                return
            host, port = _split_authority(parts[1])
            issued = owner.ca.issue(host)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(issued.cert_path), str(issued.key_path))
            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            with context.wrap_socket(self.request, server_side=True) as tls:
                owner.serve_tunnel(tls, host, port)
        except (ProxyError, CertificateError, ssl.SSLError, OSError, ValueError):
            # A malformed tunnel gets a closed connection, never a guessed
            # success. The proxy remains available for the next request.
            return
        finally:
            with contextlib.suppress(OSError):
                self.request.close()


class TrafficProxy:
    """A loopback HTTPS proxy with fixed classification and ledger evidence."""

    def __init__(
        self,
        ca: CertificateAuthority,
        *,
        listen_host: str = "127.0.0.1",
        listen_port: int = 0,
        ledger: EvidenceLedger | None = None,
        ledger_path: str | Path | None = None,
        enforcement: bool = False,
        session_id: str = "",
        upstream_map: Mapping[str, tuple[str, int]] | None = None,
        upstream_ca: str | Path | None = None,
    ) -> None:
        self.ca = ca
        self.ledger = ledger if ledger is not None else EvidenceLedger()
        self.ledger_path = Path(ledger_path) if ledger_path is not None else None
        self.enforcement = bool(enforcement)
        self.session_id = session_id
        self.upstream_map = dict(upstream_map or {})
        self.upstream_ca = Path(upstream_ca) if upstream_ca is not None else None
        rules, gate_rules = traffic_policy(self.enforcement)
        self.engine = RuleEngine(rules=rules)
        self.engine.add_facts_from_ledger(self.ledger)
        self.gate = PolicyGate(policy_rules=gate_rules, fallback=Decision.BLOCK)
        self.lock = threading.Lock()
        self.listen_host = listen_host
        self.listen_port = listen_port
        self._server: _ProxyServer | None = None
        self._thread: threading.Thread | None = None
        self.captures: list[Capture] = []
        self.last_upstream_error = ""

    @property
    def port(self) -> int:
        if self._server is None:
            return 0
        return int(self._server.server_address[1])

    def start(self) -> int:
        if self._server is not None:
            raise ProxyError("proxy is already running")
        self.ca.ensure()
        self._server = _ProxyServer((self.listen_host, self.listen_port), _ProxyHandler, self)
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="nomosguard-watch-proxy", daemon=True
        )
        self._thread.start()
        return self.port

    def stop(self) -> None:
        server = self._server
        if server is None:
            return
        server.shutdown()
        server.server_close()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=5)
        self._server = None
        self._thread = None

    def __enter__(self) -> Self:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # -- per-request path -----------------------------------------------------

    def serve_tunnel(self, tls: ssl.SSLSocket, host: str, port: int) -> None:
        rfile = tls.makefile("rb")
        try:
            parsed = _parse_http_request(rfile)
            if parsed is None:
                return
            method, path, headers, body = parsed
            request = TrafficRequest(
                method=method,
                host=host,
                port=port,
                path=path,
                headers=headers,
                body=body,
            )
            classification = classify_request(request)
            payload = build_claim_payload(
                request, classification, session_id=self.session_id
            )
            capture = self.record(request, classification, payload)
            if capture.blocked:
                response = self._json_response(
                    403,
                    {
                        "error": "blocked by nomosguard traffic policy",
                        "class": classification.classification,
                        "policy_rule": capture.policy_rule,
                    },
                )
                tls.sendall(response)
                return
            try:
                response = self.forward(request, headers, body)
            except (OSError, http.client.HTTPException, ssl.SSLError, ProxyError) as exc:
                self.last_upstream_error = str(exc)
                response = self._json_response(502, {"error": "upstream request failed"})
            tls.sendall(response)
        finally:
            with contextlib.suppress(OSError):
                rfile.close()

    def record(
        self,
        request: TrafficRequest,
        classification: TrafficClassification,
        payload: dict[str, Any],
    ) -> Capture:
        evidence = (
            f"watch proxy observed {request.method} https://{request.host.lower()}"
            f"{payload['path']} ({classification.classification})"
        )
        with self.lock:
            entry = self.ledger.append(
                Claim(kind=CLAIM_KIND_TRAFFIC_REQUEST, payload=payload, evidence=evidence)
            )
            self.engine.add_facts_from_ledger(self.ledger)
            self.engine.derive()
            decision = self.gate.evaluate_with_fallback(self.engine)
            decision_name = str(decision.get("decision", Decision.BLOCK.value))
            rule = str(decision.get("policy_rule", "FALLBACK"))
            blocked = self.enforcement and decision_name in {
                Decision.BLOCK.value,
                Decision.ISOLATE_HOST.value,
                Decision.REVOKE_ACCESS.value,
                Decision.ESCALATE.value,
            }
            capture = Capture(
                request=request,
                classification=classification,
                payload=payload,
                seq=entry.seq,
                entry_hash=entry.entry_hash,
                decision=decision_name,
                policy_rule=rule,
                blocked=blocked,
                reasons=classification.reasons,
            )
            self.captures.append(capture)
            if self.ledger_path is not None:
                self.ledger.save(self.ledger_path)
        return capture

    def forward(
        self, request: TrafficRequest, headers: dict[str, str], body: bytes
    ) -> bytes:
        connect_host, connect_port = self.upstream_map.get(
            request.host.lower(), (request.host, request.port)
        )
        context = ssl.create_default_context(
            cafile=str(self.upstream_ca) if self.upstream_ca is not None else None
        )
        raw_socket = socket.create_connection((connect_host, connect_port), timeout=20)
        upstream = context.wrap_socket(raw_socket, server_hostname=request.host)
        connection = http.client.HTTPConnection(request.host, request.port, timeout=20)
        connection.sock = upstream
        try:
            connection.putrequest(
                request.method,
                request.path,
                skip_host=True,
                skip_accept_encoding=True,
            )
            for name, value in headers.items():
                if name in _HOP_BY_HOP or name in {"host", "content-length"}:
                    continue
                connection.putheader(name, value)
            connection.putheader("Host", _host_header(request.host, request.port))
            # The watched body has already been decoded (chunked or
            # Content-Length); the upstream gets one unambiguous length.
            if body or "content-length" in headers:
                connection.putheader("Content-Length", str(len(body)))
            connection.endheaders(body if body else None)
            response = connection.getresponse()
            data = response.read()
            lines = [f"HTTP/1.1 {response.status} {response.reason}\r\n"]
            for name, value in response.getheaders():
                if name.lower() in _HOP_BY_HOP or name.lower() == "content-length":
                    continue
                lines.append(f"{name}: {value}\r\n")
            lines.append(f"Content-Length: {len(data)}\r\n")
            lines.append("Connection: close\r\n\r\n")
            return "".join(lines).encode("latin-1") + data
        finally:
            with contextlib.suppress(OSError):
                connection.close()
            upstream.close()

    @staticmethod
    def _json_response(status: int, payload: dict[str, Any]) -> bytes:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        head = (
            f"HTTP/1.1 {status} Error\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        )
        return head.encode("latin-1") + body
