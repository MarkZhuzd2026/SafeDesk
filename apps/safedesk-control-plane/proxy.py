"""Per-sandbox egress proxy: allowlist + SSRF guard + broker-mediated credential injection.

REQ-NW-001..009, 013..015. HTTPS goes through CONNECT only for allowlisted hosts
(tunnel content is not decrypted); plaintext HTTP is proxied with header inspection
so brokered placeholders can be swapped for real values host-side.
"""
from __future__ import annotations

import base64
import http.client
import json
import select
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

BLOCKED_CIDRS = [
    ("0.0.0.0", 8), ("10.0.0.0", 8), ("127.0.0.0", 8), ("169.254.0.0", 16),
    ("172.16.0.0", 12), ("192.168.0.0", 16), ("100.64.0.0", 10),
]
BLOCKED_HOSTS = {"localhost", "metadata.google.internal", "metadata.aws.internal"}
METADATA_IPS = {"169.254.169.254", "100.100.100.200"}


def _ip_in_cidr(ip: str, base: str, bits: int) -> bool:
    try:
        host = int.from_bytes(socket.inet_aton(ip), "big")
        net = int.from_bytes(socket.inet_aton(base), "big")
        shift = 32 - bits
        return (host >> shift) == (net >> shift)
    except OSError:
        return False


def resolve_host(host: str) -> list[str]:
    try:
        return [info[4][0] for info in socket.getaddrinfo(host, None)]
    except OSError:
        return []


def is_blocked_host(host: str) -> tuple[bool, str]:
    """REQ-NW-002/003/004: hard-deny private/loopback/link-local/metadata targets,
    including DNS names that resolve to such addresses."""
    name = (host or "").strip().lower().split(":")[0]
    if not name:
        return True, "目标主机为空"
    if name in BLOCKED_HOSTS or name in METADATA_IPS:
        return True, "目标为回环/元数据端点，默认拒绝"
    ips = resolve_host(name)
    for ip in ips:
        if ip in METADATA_IPS or ip.startswith("fd00:ec2") or ip == "::1":
            return True, "目标解析到元数据/回环地址，默认拒绝"
        if any(_ip_in_cidr(ip, base, bits) for base, bits in BLOCKED_CIDRS):
            return True, "目标解析到私网地址，默认拒绝"
    return False, ""


class EgressPolicy:
    def __init__(self, allowed: list[str] | None, injections: dict[str, dict] | None = None):
        self.allowed = {h.strip().lower() for h in (allowed or []) if str(h).strip()}
        self.injections = injections or {}  # placeholder -> {value, hosts}

    def allows(self, host: str) -> bool:
        host = (host or "").strip().lower().split(":")[0]
        if host in self.allowed:
            return True
        return any(p.startswith("*.") and (host == p[2:] or host.endswith(p[1:])) for p in self.allowed)

    @staticmethod
    def _hosts_allow(target: str, hosts: list[str]) -> bool:
        target = (target or "").strip().lower().split(":")[0]
        for pattern in hosts:
            if pattern.startswith("*.") and (target == pattern[2:] or target.endswith(pattern[1:])):
                return True
            if pattern == target:
                return True
        return False

    def inject_headers(self, host: str, headers: dict) -> tuple[dict, str | None]:
        """Swap placeholders for real values when the destination permits (REQ-NW-007 + BR-005).

        Returns (new_headers, blocked_reason)."""
        result = {}
        for key, value in headers.items():
            entry = self.injections.get(value)
            if entry is None:
                result[key] = value
                continue
            if not self._hosts_allow(host, entry.get("hosts", [])):
                return {}, f"凭据不允许发送到 {host}"
            result[key] = entry["value"]
        return result, None


class ProxyRuntime:
    """Sandbox registrations plus the allow/block decision event sink."""

    def __init__(self):
        self._lock = threading.Lock()
        self._registrations: dict[str, dict] = {}
        self._events: list[dict] = []
        self.on_event = None  # optional callback(level, action, detail)

    def register(self, sandbox_id: str, token: str, policy: EgressPolicy) -> None:
        with self._lock:
            self._registrations[sandbox_id] = {"token": token, "policy": policy, "paused": False}

    def unregister(self, sandbox_id: str) -> None:
        with self._lock:
            self._registrations.pop(sandbox_id, None)

    def set_paused(self, sandbox_id: str, paused: bool) -> None:
        with self._lock:
            entry = self._registrations.get(sandbox_id)
            if entry:
                entry["paused"] = paused

    def lookup(self, sandbox_id: str, token: str) -> dict | None:
        with self._lock:
            entry = self._registrations.get(sandbox_id)
            if entry and entry["token"] == token:
                return entry
            return None

    def record(self, level: str, detail: str) -> None:
        with self._lock:
            self._events.insert(0, {"level": level, "action": "网络决策", "detail": detail})
            del self._events[200:]
        if self.on_event:
            try:
                self.on_event(level, detail)
            except Exception:
                pass

    def snapshot_events(self) -> list[dict]:
        with self._lock:
            return list(self._events)


def _parse_proxy_auth(header: str) -> tuple[str, str] | None:
    if not header.startswith("Basic "):
        return None
    try:
        raw = base64.b64decode(header[6:]).decode("utf-8")
        sandbox_id, token = raw.split(":", 1)
        return sandbox_id, token
    except (ValueError, UnicodeDecodeError):
        return None


def make_handler(runtime: ProxyRuntime):
    HOP_HEADERS = {"proxy-authorization", "proxy-connection", "connection", "content-length", "host", "transfer-encoding"}

    class EgressHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):  # quiet
            return

        def _auth(self):
            pair = _parse_proxy_auth(self.headers.get("Proxy-Authorization", ""))
            if not pair:
                self._deny(407, "缺少代理鉴权")
                return None
            entry = runtime.lookup(*pair)
            if entry is None:
                self._deny(407, "代理鉴权失败")
                return None
            if entry.get("paused"):
                self._deny(403, "沙箱已暂停，外联冻结")
                return None
            return entry

        def _deny(self, status: int, reason: str):
            runtime.record("block", f"{self.command} {self.path[:120]} 被拒绝：{reason}")
            body = json.dumps({"error": "egress denied", "reason": reason}, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_CONNECT(self):
            entry = self._auth()
            if entry is None:
                return
            host, _, port = self.path.partition(":")
            if port != "443":
                self._deny(403, "仅允许白名单 443 隧道")
                return
            blocked, reason = is_blocked_host(host)
            if blocked:
                self._deny(403, reason)
                return
            if not entry["policy"].allows(host):
                self._deny(403, "目标不在白名单")
                return
            try:
                upstream = socket.create_connection((host, 443), timeout=10)
            except OSError:
                self.send_error(502, "Bad Gateway")
                return
            self.send_response(200, "Connection Established")
            self.end_headers()
            runtime.record("allow", f"CONNECT {host}:443 放行（隧道不解密）")
            self.connection.setblocking(False)
            upstream.setblocking(False)
            try:
                peers = {self.connection: upstream, upstream: self.connection}
                live = True
                while live:
                    readable, _, _ = select.select(list(peers), [], [], 60)
                    if not readable:
                        break
                    for sock in readable:
                        try:
                            data = sock.recv(65536)
                        except OSError:
                            live = False
                            break
                        if not data:
                            live = False
                            break
                        try:
                            peers[sock].sendall(data)
                        except OSError:
                            live = False
                            break
            finally:
                upstream.close()

        def _forward(self):
            entry = self._auth()
            if entry is None:
                return
            target = urlsplit(self.path)
            host = target.hostname or ""
            if not host:
                self._deny(400, "请求必须为绝对 URI")
                return
            blocked, reason = is_blocked_host(host)
            if blocked:
                self._deny(403, reason)
                return
            if not entry["policy"].allows(host):
                self._deny(403, "目标不在白名单")
                return
            headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP_HEADERS}
            headers["Host"] = target.netloc
            headers, inject_error = entry["policy"].inject_headers(host, headers)
            if inject_error:
                self._deny(403, inject_error)
                return
            body = b""
            size = int(self.headers.get("Content-Length", "0") or 0)
            if size:
                body = self.rfile.read(size)
            port = target.port or (443 if target.scheme == "https" else 80)
            cls = http.client.HTTPSConnection if target.scheme == "https" else http.client.HTTPConnection
            conn = cls(host, port, timeout=30)
            path = f"{target.path or '/'}{'?' + target.query if target.query else ''}"
            try:
                conn.request(self.command, path, body=body or None, headers=headers)
                resp = conn.getresponse()
                data = resp.read()
                self.send_response(resp.status)
                for key, value in resp.getheaders():
                    if key.lower() in ("transfer-encoding", "connection", "keep-alive"):
                        continue
                    if key.lower() == "content-length":
                        continue
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                runtime.record("allow", f"{self.command} {host} 放行")
            except OSError:
                self.send_error(502, "Bad Gateway")
            finally:
                conn.close()

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _forward

        def do_HEAD(self):
            self._forward()

    return EgressHandler


def serve(runtime: ProxyRuntime, host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    """Start the egress proxy on a background thread (REQ-NW-013 via /healthz)."""
    handler = make_handler(runtime)

    class HealthHandler(handler):
        def do_GET(self):  # healthz shortcut before auth
            if self.path == "/healthz":
                body = json.dumps({"ok": True, "service": "safedesk-egress-proxy"}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            super().do_GET()

    server = ThreadingHTTPServer((host, port), HealthHandler)
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True).start()
    return server
