#!/usr/bin/env python3
"""SafeDesk control plane: standard-library deployment server for restricted hosts."""
from __future__ import annotations

import json
import os
import re
import threading
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from uuid import uuid4

from policy import ALLOWED_AGENTS, POLICIES, compile_manifest

ROOT = Path(__file__).resolve().parent
STATIC_ROOT = ROOT / "static"
DATA_FILE = ROOT / "data" / "sandboxes.json"
LOCK = threading.Lock()
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


def security_event(level: str, action: str, detail: str) -> None:
    EVENTS.insert(0, {"id": str(uuid4()), "level": level, "action": action, "detail": detail, "at": iso_now()})
    del EVENTS[40:]


def safe_name(value: object) -> str:
    return re.sub(r"[^\w\u4e00-\u9fff-]", "-", str(value or "").strip())[:48]


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

    def do_GET(self) -> None:
        if self.path == "/api/bootstrap":
            with LOCK:
                self.send_json(200, {"policies": list(POLICIES.values()), "agents": [{"id": key, **value} for key, value in ALLOWED_AGENTS.items()], "sandboxes": load_sandboxes(), "securityEvents": EVENTS})
            return
        if self.path == "/api/sandboxes":
            with LOCK:
                self.send_json(200, {"sandboxes": load_sandboxes()})
            return
        if self.path == "/api/events":
            self.send_json(200, {"events": EVENTS})
            return
        match = re.fullmatch(r"/api/sandboxes/(sbx-[\w-]+)/manifest", self.path)
        if match:
            with LOCK:
                sandbox = next((item for item in load_sandboxes() if item["id"] == match.group(1)), None)
                if not sandbox:
                    self.send_json(404, {"error": "未找到沙箱"})
                else:
                    self.send_json(200, {"manifest": compile_manifest(sandbox)})
            return
        if self.path.startswith("/api/"):
            self.send_json(404, {"error": "Not found"})
            return
        super().do_GET()

    def do_POST(self) -> None:
        if self.path == "/api/sandboxes":
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
                }
                with LOCK:
                    sandboxes = load_sandboxes(); sandboxes.insert(0, sandbox); save_sandboxes(sandboxes)
                    security_event("info", "创建待审批沙箱", f"{sandbox['name']} 使用 {POLICIES[policy_id]['label']} 策略")
                self.send_json(201, {"sandbox": sandbox, "manifest": compile_manifest(sandbox)})
            except ValueError as error:
                self.send_json(400, {"error": str(error)})
            return
        match = re.fullmatch(r"/api/sandboxes/(sbx-[\w-]+)/(approve|terminate)", self.path)
        if not match:
            self.send_json(404, {"error": "Not found"}); return
        sandbox_id, action = match.groups()
        with LOCK:
            sandboxes = load_sandboxes()
            sandbox = next((item for item in sandboxes if item["id"] == sandbox_id), None)
            if not sandbox:
                self.send_json(404, {"error": "未找到沙箱"}); return
            if action == "approve":
                if sandbox["status"] != "pending_approval":
                    self.send_json(409, {"error": "沙箱不是待审批状态"}); return
                sandbox["status"] = "running"; sandbox["startedAt"] = iso_now()
                security_event("allow", "人工审批", f"{sandbox['name']} 已启动；凭据仅由主机 Broker 按策略代签")
            else:
                if sandbox["status"] == "terminated":
                    self.send_json(409, {"error": "沙箱已终止"}); return
                sandbox["status"] = "terminated"; sandbox["terminatedAt"] = iso_now()
                security_event("block", "终止沙箱", f"{sandbox['name']} 已终止，短期会话凭据失效")
            save_sandboxes(sandboxes)
            self.send_json(200, {"sandbox": sandbox})


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8022"))
    host = os.getenv("HOST", "0.0.0.0")
    print(f"SafeDesk control plane listening on http://{host}:{port}")
    ThreadingHTTPServer((host, port), ApiHandler).serve_forever()
