#!/usr/bin/env python3
"""SafeDesk control plane: standard-library deployment server for restricted hosts."""
from __future__ import annotations

import json
import os
import re
import ssl
import threading
from datetime import datetime, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

from auth import AuthStore
from policy import ALLOWED_AGENTS, POLICIES, compile_manifest

ROOT = Path(__file__).resolve().parent
STATIC_ROOT = ROOT / "static"
DATA_DIR = Path(os.environ["SAFEDESK_DATA_DIR"]) if os.getenv("SAFEDESK_DATA_DIR") else ROOT / "data"
DATA_FILE = Path(os.environ["SAFEDESK_DATA_FILE"]) if os.getenv("SAFEDESK_DATA_FILE") else DATA_DIR / "sandboxes.json"
LOCK = threading.Lock()
AUTH_ENABLED = os.getenv("SAFEDESK_AUTH", "1") != "0"
AUTH = AuthStore(DATA_DIR)
EVENTS = [
    {"id": "evt-001", "level": "info", "action": "策略编译", "detail": "policy/balanced 已签名并下发至本地执行器", "at": "2026-10-23T10:12:00.000Z"},
    {"id": "evt-002", "level": "allow", "action": "凭据代签", "detail": "github-read 通过 Host Credential Broker 注入 Authorization 头", "at": "2026-10-23T10:14:00.000Z"},
    {"id": "evt-003", "level": "block", "action": "外联拦截", "detail": "沙箱请求 untrusted.example 被默认拒绝", "at": "2026-10-23T10:17:00.000Z"},
]


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_sandboxes() -> list[dict]:
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not DATA_FILE.exists():
        DATA_FILE.write_text("[]\n", encoding="utf-8")
    return json.loads(DATA_FILE.read_text(encoding="utf-8"))


def save_sandboxes(sandboxes: list[dict]) -> None:
    DATA_FILE.write_text(json.dumps(sandboxes, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def security_event(level: str, action: str, detail: str, actor: str | None = None) -> None:
    EVENTS.insert(0, {"id": str(uuid4()), "level": level, "action": action, "detail": detail, "actor": actor, "at": iso_now()})
    del EVENTS[40:]


def safe_name(value: object) -> str:
    return re.sub(r"[^\w\u4e00-\u9fff-]", "-", str(value or "").strip())[:48]


def visible_sandboxes(user: dict | None) -> list[dict]:
    items = load_sandboxes()
    if not AUTH_ENABLED or (user and user.get("role") == "admin"):
        return items
    owner = user["id"] if user else ""
    return [item for item in items if item.get("ownerId") == owner]


class ApiHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC_ROOT), **kwargs)

    def send_json(self, status: int, body: dict) -> None:
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def body(self) -> dict:
        size = int(self.headers.get("Content-Length", "0"))
        try:
            return json.loads(self.rfile.read(size) or b"{}")
        except json.JSONDecodeError as error:
            raise ValueError("请求体不是合法 JSON") from error

    def bearer(self) -> str | None:
        header = self.headers.get("Authorization", "")
        if header.startswith("Bearer "):
            return header[7:].strip() or None
        return None

    def current_user(self) -> dict | None:
        if not AUTH_ENABLED:
            return {"id": "local-dev", "role": "admin", "displayName": "本地开发", "provider": "disabled"}
        with LOCK:
            return AUTH.session_user(self.bearer())

    def require_user(self) -> dict | None:
        user = self.current_user()
        if not user:
            self.send_json(401, {"error": "请先登录"})
            return None
        return user

    def require_admin(self) -> dict | None:
        user = self.require_user()
        if user is None:
            return None
        if user.get("role") != "admin":
            self.send_json(403, {"error": "仅管理员可以执行此操作"})
            return None
        return user

    def can_access(self, user: dict, sandbox: dict) -> bool:
        return user.get("role") == "admin" or sandbox.get("ownerId") == user["id"]

    def do_GET(self) -> None:
        if self.path == "/api/auth/config":
            self.send_json(200, AUTH.public_config())
            return
        if urlsplit(self.path).path == "/api/auth/wechat/poll":
            ticket = (parse_qs(urlsplit(self.path).query).get("ticket") or [""])[0]
            with LOCK:
                self.send_json(200, AUTH.poll_wechat(ticket))
            return
        if self.path == "/api/auth/me":
            user = self.current_user()
            if not user:
                self.send_json(401, {"error": "请先登录"})
                return
            self.send_json(200, {"user": AUTH.public_user(user) if AUTH_ENABLED else user, "authEnabled": AUTH_ENABLED})
            return
        if self.path == "/api/bootstrap":
            user = self.require_user()
            if user is None:
                return
            with LOCK:
                self.send_json(200, {
                    "user": AUTH.public_user(user) if AUTH_ENABLED else user,
                    "policies": list(POLICIES.values()),
                    "agents": [{"id": key, **value} for key, value in ALLOWED_AGENTS.items()],
                    "sandboxes": visible_sandboxes(user),
                    "securityEvents": EVENTS if user.get("role") == "admin" else [],
                })
            return
        if self.path == "/api/sandboxes":
            user = self.require_user()
            if user is None:
                return
            with LOCK:
                self.send_json(200, {"sandboxes": visible_sandboxes(user)})
            return
        if self.path == "/api/events":
            user = self.require_admin()
            if user is None:
                return
            self.send_json(200, {"events": EVENTS})
            return
        match = re.fullmatch(r"/api/sandboxes/(sbx-[\w-]+)/manifest", self.path)
        if match:
            user = self.require_user()
            if user is None:
                return
            with LOCK:
                sandbox = next((item for item in load_sandboxes() if item["id"] == match.group(1)), None)
                if not sandbox or not self.can_access(user, sandbox):
                    self.send_json(404, {"error": "未找到沙箱"})
                else:
                    self.send_json(200, {"manifest": compile_manifest(sandbox)})
            return
        if self.path.startswith("/api/"):
            self.send_json(404, {"error": "Not found"})
            return
        super().do_GET()

    def do_POST(self) -> None:
        if self.path == "/api/auth/phone/send":
            try:
                payload = self.body()
                with LOCK:
                    self.send_json(200, AUTH.send_phone_otp(str(payload.get("phone", "")).strip()))
            except ValueError as error:
                self.send_json(400, {"error": str(error)})
            return
        if self.path == "/api/auth/phone/verify":
            try:
                payload = self.body()
                with LOCK:
                    self.send_json(200, AUTH.verify_phone_otp(str(payload.get("phone", "")).strip(), str(payload.get("token", "")).strip()))
            except ValueError as error:
                self.send_json(400, {"error": str(error)})
            return
        if self.path == "/api/auth/wechat/start":
            with LOCK:
                self.send_json(200, AUTH.start_wechat())
            return
        if self.path == "/api/auth/wechat/confirm":
            try:
                payload = self.body()
                with LOCK:
                    self.send_json(200, AUTH.confirm_wechat(str(payload.get("ticket", "")).strip()))
            except ValueError as error:
                self.send_json(400, {"error": str(error)})
            return
        if self.path == "/api/auth/admin/login":
            try:
                payload = self.body()
                with LOCK:
                    self.send_json(200, AUTH.login_admin(str(payload.get("username", "")).strip(), str(payload.get("password", ""))))
            except ValueError as error:
                self.send_json(400, {"error": str(error)})
            return
        if self.path == "/api/auth/logout":
            with LOCK:
                AUTH.revoke(self.bearer())
            self.send_json(200, {"ok": True})
            return
        if self.path == "/api/sandboxes":
            user = self.require_user()
            if user is None:
                return
            try:
                payload = self.body()
                policy_id = str(payload.get("policyId", "balanced"))
                agent = str(payload.get("agent", "claude-code"))
                workspace = str(payload.get("workspace", "")).strip()
                if policy_id not in POLICIES:
                    self.send_json(400, {"error": "未知策略"}); return
                if agent not in ALLOWED_AGENTS:
                    self.send_json(400, {"error": "仅支持 Claude Code、Codex 或 DSH"}); return
                if not workspace.startswith("/"):
                    self.send_json(400, {"error": "工作区必须为绝对路径"}); return
                sandbox = {
                    "id": f"sbx-{uuid4().hex[:8]}", "name": safe_name(payload.get("name")) or f"agent-{agent}",
                    "agent": agent, "policyId": policy_id, "workspace": workspace,
                    "packages": list(payload.get("packages") or ["wasmer/bash@latest"])[:8],
                    "credentials": list(payload.get("credentials") or [])[:8],
                    "mcpServers": list(payload.get("mcpServers") or [])[:12],
                    "status": "pending_approval", "createdAt": iso_now(),
                    "ownerId": user["id"], "ownerName": user.get("displayName") or user.get("username") or user["id"],
                }
                with LOCK:
                    sandboxes = load_sandboxes(); sandboxes.insert(0, sandbox); save_sandboxes(sandboxes)
                    security_event("info", "创建待审批沙箱", f"{sandbox['name']} 使用 {POLICIES[policy_id]['label']} 策略", user["id"])
                self.send_json(201, {"sandbox": sandbox, "manifest": compile_manifest(sandbox)})
            except ValueError as error:
                self.send_json(400, {"error": str(error)})
            return
        match = re.fullmatch(r"/api/sandboxes/(sbx-[\w-]+)/(approve|terminate)", self.path)
        if not match:
            self.send_json(404, {"error": "Not found"}); return
        sandbox_id, action = match.groups()
        user = self.require_admin() if action == "approve" else self.require_user()
        if user is None:
            return
        with LOCK:
            sandboxes = load_sandboxes()
            sandbox = next((item for item in sandboxes if item["id"] == sandbox_id), None)
            if not sandbox or not self.can_access(user, sandbox):
                self.send_json(404, {"error": "未找到沙箱"}); return
            if action == "approve":
                if sandbox["status"] != "pending_approval":
                    self.send_json(409, {"error": "沙箱不是待审批状态"}); return
                sandbox["status"] = "running"; sandbox["startedAt"] = iso_now(); sandbox["approvedBy"] = user["id"]
                security_event("allow", "人工审批", f"{sandbox['name']} 已启动；凭据仅由主机 Broker 按策略代签", user["id"])
            else:
                if sandbox["status"] == "terminated":
                    self.send_json(409, {"error": "沙箱已终止"}); return
                sandbox["status"] = "terminated"; sandbox["terminatedAt"] = iso_now(); sandbox["terminatedBy"] = user["id"]
                security_event("block", "终止沙箱", f"{sandbox['name']} 已终止，短期会话凭据失效", user["id"])
            save_sandboxes(sandboxes)
            self.send_json(200, {"sandbox": sandbox})

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def log_message(self, format: str, *args) -> None:
        return


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8022"))
    host = os.getenv("HOST", "0.0.0.0")
    cert = os.getenv("SAFEDESK_TLS_CERT")
    key = os.getenv("SAFEDESK_TLS_KEY")
    server = ThreadingHTTPServer((host, port), ApiHandler)
    scheme = "http"
    if cert and key:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        scheme = "https"
    print(f"SafeDesk control plane listening on {scheme}://{host}:{port}")
    server.serve_forever()
