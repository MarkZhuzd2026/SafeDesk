"""SafeDesk control plane end-to-end suite (auth enabled).

E2E-01  admin login -> forced password change -> old session revoked -> relogin
E2E-02  phone OTP full flow (send, resend throttle, wrong code, right code)
E2E-03  wechat QR flow (start -> poll pending -> confirm -> poll confirmed)
E2E-04  unauthenticated requests -> 401; logout -> 401 afterwards
E2E-05  per-user data isolation vs admin-wide visibility
E2E-06  full sandbox lifecycle: create -> approve -> pause -> resume -> terminate
E2E-07  concurrent sandbox quota -> 409 once maxConcurrent reached
E2E-08  credential broker: masked listing, manifest/data file never leak secrets
E2E-09  egress proxy: auth, SSRF guard, allowlist, pause freeze
E2E-10  audit history persistence (audit.jsonl + history query + non-admin 403)

Run: python3 -m unittest test.test_e2e -v
"""
from __future__ import annotations

import base64
import http.client
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Local test traffic must never go through a proxy configured via *_PROXY env vars.
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class E2EBase(unittest.TestCase):
    """Spins up server.py once with SAFEDESK_AUTH=1 and an isolated data dir."""

    @classmethod
    def setUpClass(cls):
        cls.data_dir = Path(tempfile.mkdtemp(prefix="safedesk-e2e-"))
        cls.port = free_port()
        cls.proxy_port = free_port()
        cls.base = f"http://127.0.0.1:{cls.port}"
        env = {
            **os.environ,
            "PORT": str(cls.port),
            "HOST": "127.0.0.1",
            "SAFEDESK_DATA_DIR": str(cls.data_dir),
            "SAFEDESK_AUTH": "1",
            "SAFEDESK_DEMO": "1",
            "SAFEDESK_EGRESS_PROXY_PORT": str(cls.proxy_port),
        }
        cls.server = subprocess.Popen(
            [sys.executable, "server.py"],
            cwd=ROOT,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for _ in range(60):
            try:
                cls.request("GET", "/api/auth/config")
                break
            except OSError:
                time.sleep(0.1)
        else:
            cls.tearDownClass()
            raise RuntimeError("server did not start")

    @classmethod
    def tearDownClass(cls):
        cls.server.terminate()
        try:
            cls.server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            cls.server.kill()
        shutil.rmtree(cls.data_dir, ignore_errors=True)

    # -- helpers -----------------------------------------------------------

    @classmethod
    def request(cls, method: str, path: str, body=None, token: str | None = None):
        payload = None
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if body is not None:
            payload = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(cls.base + path, data=payload, headers=headers, method=method)
        try:
            with OPENER.open(request, timeout=8) as response:
                return response.status, json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read() or b"{}")

    @classmethod
    def admin_login(cls, password: str = "SafeDesk@Admin") -> tuple[int, dict]:
        return cls.request("POST", "/api/auth/admin/login", {"username": "admin", "password": password})

    @classmethod
    def phone_login(cls, phone: str) -> str:
        status, sent = cls.request("POST", "/api/auth/phone/send", {"phone": phone})
        assert status == 200 and sent.get("demoCode"), (status, sent)
        status, session = cls.request("POST", "/api/auth/phone/verify", {"phone": phone, "token": sent["demoCode"]})
        assert status == 200, (status, session)
        return session["token"]

    @classmethod
    def create_sandbox(cls, token: str, **overrides):
        payload = {
            "name": "e2e-box",
            "agent": "codex",
            "policyId": "review",
            "workspace": "/tmp/e2e-project",
            "credentials": [],
            "mcpServers": [],
        }
        payload.update(overrides)
        return cls.request("POST", "/api/sandboxes", payload, token=token)

    @classmethod
    def sandboxes_on_disk(cls) -> list[dict]:
        return json.loads((cls.data_dir / "sandboxes.json").read_text(encoding="utf-8"))

    @classmethod
    def users_on_disk(cls) -> list[dict]:
        return json.loads((cls.data_dir / "users.json").read_text(encoding="utf-8"))

    @classmethod
    def proxy_request(cls, method: str, target: str, auth: str | None = None) -> int:
        conn = http.client.HTTPConnection("127.0.0.1", cls.proxy_port, timeout=8)
        headers = {"Proxy-Authorization": f"Basic {auth}"} if auth else {}
        conn.request(method, target, headers=headers)
        try:
            response = conn.getresponse()
            response.read()
            return response.status
        finally:
            conn.close()


class TestE2E01AdminPasswordFlow(E2EBase):
    """E2E-01: admin login -> mustChangePassword -> change -> old sessions die -> relogin."""

    def test_e2e_01(self):
        status, session1 = self.admin_login()
        self.assertEqual(status, 200)
        self.assertTrue(session1["user"]["mustChangePassword"], "默认密码登录必须标记强制改密")
        token1 = session1["token"]

        status, session2 = self.admin_login()
        self.assertEqual(status, 200)
        token2 = session2["token"]

        # 错误当前密码 / 弱新密码都被拒绝
        status, _ = self.request("POST", "/api/auth/password", {"currentPassword": "wrong", "newPassword": "NewPassw0rd!"}, token=token1)
        self.assertEqual(status, 400)
        status, _ = self.request("POST", "/api/auth/password", {"currentPassword": "SafeDesk@Admin", "newPassword": "short"}, token=token1)
        self.assertEqual(status, 400)
        status, _ = self.request("POST", "/api/auth/password", {"currentPassword": "SafeDesk@Admin", "newPassword": "SafeDesk@Admin"}, token=token1)
        self.assertEqual(status, 400, "不允许继续用默认密码")

        status, changed = self.request(
            "POST", "/api/auth/password",
            {"currentPassword": "SafeDesk@Admin", "newPassword": "E2E-NewPassw0rd"},
            token=token1,
        )
        self.assertEqual(status, 200)
        self.assertTrue(changed["ok"])
        self.assertFalse(changed["user"]["mustChangePassword"])

        # 落盘：users.json 已更新且不再标记强制改密
        admin_record = next(u for u in self.users_on_disk() if u.get("username") == "admin")
        self.assertFalse(admin_record["mustChangePassword"])
        self.assertIn("passwordChangedAt", admin_record)

        # 其他会话被吊销，仅当前会话保留
        status, _ = self.request("GET", "/api/auth/me", token=token2)
        self.assertEqual(status, 401, "改密后其他会话必须失效")
        status, me = self.request("GET", "/api/auth/me", token=token1)
        self.assertEqual(status, 200)
        self.assertFalse(me["user"]["mustChangePassword"])

        # 旧密码登录失败，新密码登录成功
        status, _ = self.admin_login()
        self.assertEqual(status, 400)
        status, relogin = self.admin_login(password="E2E-NewPassw0rd")
        self.assertEqual(status, 200)
        self.assertFalse(relogin["user"]["mustChangePassword"])


class TestE2E02PhoneOtp(E2EBase):
    """E2E-02: phone OTP send -> throttle -> wrong code -> right code -> session."""

    def test_e2e_02(self):
        phone = "13900000001"
        status, sent = self.request("POST", "/api/auth/phone/send", {"phone": "12345"})
        self.assertEqual(status, 400, "非手机号必须 400")

        status, sent = self.request("POST", "/api/auth/phone/send", {"phone": phone})
        self.assertEqual(status, 200)
        self.assertIn("demoCode", sent, "演示模式必须回显验证码")

        status, _ = self.request("POST", "/api/auth/phone/send", {"phone": phone})
        self.assertEqual(status, 400, "60 秒内重复发送必须被限频")

        status, _ = self.request("POST", "/api/auth/phone/verify", {"phone": phone, "token": "000000"})
        self.assertTrue(status == 400, "错误验证码必须 400")

        status, session = self.request("POST", "/api/auth/phone/verify", {"phone": phone, "token": sent["demoCode"]})
        self.assertEqual(status, 200)
        self.assertEqual(session["user"]["role"], "user")
        self.assertEqual(session["user"]["provider"], "phone")
        self.assertIn("****", session["user"]["displayName"])

        status, me = self.request("GET", "/api/auth/me", token=session["token"])
        self.assertEqual(status, 200)
        self.assertEqual(me["user"]["id"], f"phone-{phone}")

        # 验证码一次性：已消费的 code 不可再次使用
        status, _ = self.request("POST", "/api/auth/phone/verify", {"phone": phone, "token": sent["demoCode"]})
        self.assertEqual(status, 400)


class TestE2E03WechatQr(E2EBase):
    """E2E-03: wechat QR start -> poll pending -> confirm -> poll confirmed -> token."""

    def test_e2e_03(self):
        status, started = self.request("POST", "/api/auth/wechat/start")
        self.assertEqual(status, 200)
        ticket = started["ticket"]
        self.assertGreater(started["expiresIn"], 0)

        status, poll = self.request("GET", f"/api/auth/wechat/poll?ticket={ticket}")
        self.assertEqual(status, 200)
        self.assertEqual(poll["status"], "pending")

        status, _ = self.request("POST", "/api/auth/wechat/confirm", {"ticket": "bogus-ticket"})
        self.assertEqual(status, 400)

        status, confirmed = self.request("POST", "/api/auth/wechat/confirm", {"ticket": ticket})
        self.assertEqual(status, 200)
        self.assertTrue(confirmed["ok"])

        status, poll = self.request("GET", f"/api/auth/wechat/poll?ticket={ticket}")
        self.assertEqual(status, 200)
        self.assertEqual(poll["status"], "confirmed")
        self.assertIn("token", poll)
        self.assertEqual(poll["user"]["provider"], "wechat")

        # ticket 一次性消费
        status, again = self.request("GET", f"/api/auth/wechat/poll?ticket={ticket}")
        self.assertEqual(status, 200)
        self.assertEqual(again["status"], "expired")

        status, me = self.request("GET", "/api/auth/me", token=poll["token"])
        self.assertEqual(status, 200)
        self.assertTrue(me["user"]["id"].startswith("wechat-"))

        # 企业微信同款链路
        status, started = self.request("POST", "/api/auth/wecom/start")
        self.assertEqual(status, 200)
        status, _ = self.request("POST", "/api/auth/wecom/confirm", {"ticket": started["ticket"]})
        self.assertEqual(status, 200)
        status, poll = self.request("GET", f"/api/auth/wecom/poll?ticket={started['ticket']}")
        self.assertEqual(poll["status"], "confirmed")
        self.assertEqual(poll["user"]["provider"], "wecom")


class TestE2E04AuthGate(E2EBase):
    """E2E-04: protected endpoints reject anonymous callers; logout invalidates the token."""

    def test_e2e_04(self):
        for method, path in [
            ("GET", "/api/bootstrap"),
            ("GET", "/api/sandboxes"),
            ("GET", "/api/overview"),
            ("GET", "/api/events"),
            ("GET", "/api/credentials"),
            ("POST", "/api/sandboxes"),
            ("POST", "/api/settings"),
        ]:
            body = {} if method == "POST" else None
            status, _ = self.request(method, path, body)
            self.assertEqual(status, 401, f"{method} {path}")

        # 伪造 token 同样是 401
        status, _ = self.request("GET", "/api/bootstrap", token="forged-token")
        self.assertEqual(status, 401)

        token = self.phone_login("13900000002")
        status, _ = self.request("GET", "/api/bootstrap", token=token)
        self.assertEqual(status, 200)

        status, out = self.request("POST", "/api/auth/logout", token=token)
        self.assertEqual(status, 200)
        self.assertTrue(out["ok"])
        status, _ = self.request("GET", "/api/bootstrap", token=token)
        self.assertEqual(status, 401, "注销后 token 必须失效")


class TestE2E05DataIsolation(E2EBase):
    """E2E-05: a user only sees their own sandboxes; admin sees everything."""

    def test_e2e_05(self):
        alice = self.phone_login("13900000003")
        bob = self.phone_login("13900000004")
        _, admin = self.admin_login()
        admin_token = admin["token"]

        status, created = self.create_sandbox(alice, name="alice-secret-box")
        self.assertEqual(status, 201)
        sandbox_id = created["sandbox"]["id"]
        self.assertEqual(created["sandbox"]["ownerId"], "phone-13900000003")

        status, listing = self.request("GET", "/api/sandboxes", token=bob)
        self.assertEqual(status, 200)
        self.assertFalse(any(item["id"] == sandbox_id for item in listing["sandboxes"]), "B 用户不得看到 A 用户的沙箱")

        status, _ = self.request("GET", f"/api/sandboxes/{sandbox_id}/manifest", token=bob)
        self.assertEqual(status, 404, "跨用户访问沙箱清单必须 404")

        status, _ = self.request("POST", f"/api/sandboxes/{sandbox_id}/pause", token=bob)
        self.assertEqual(status, 404, "跨用户操作沙箱必须 404")

        status, listing = self.request("GET", "/api/sandboxes", token=admin_token)
        self.assertEqual(status, 200)
        self.assertTrue(any(item["id"] == sandbox_id for item in listing["sandboxes"]), "管理员必须看到全部沙箱")

        status, detail = self.request("GET", f"/api/sandboxes/{sandbox_id}", token=admin_token)
        self.assertEqual(status, 200)
        self.assertEqual(detail["sandbox"]["id"], sandbox_id)


class TestE2E06Lifecycle(E2EBase):
    """E2E-06: create -> approve -> running -> pause -> resume -> terminate, with events."""

    def test_e2e_06(self):
        owner = self.phone_login("13900000005")
        _, admin = self.admin_login()
        admin_token = admin["token"]

        status, created = self.create_sandbox(owner, name="e2e-lifecycle", policyId="balanced")
        self.assertEqual(status, 201)
        sandbox_id = created["sandbox"]["id"]
        self.assertEqual(created["sandbox"]["status"], "pending_approval")

        # 审批/拒绝仅限管理员
        status, _ = self.request("POST", f"/api/sandboxes/{sandbox_id}/approve", token=owner)
        self.assertEqual(status, 403)
        status, _ = self.request("POST", f"/api/sandboxes/{sandbox_id}/reject", token=owner)
        self.assertEqual(status, 403)

        # 未运行时不能暂停/恢复
        status, _ = self.request("POST", f"/api/sandboxes/{sandbox_id}/pause", token=owner)
        self.assertEqual(status, 409)
        status, _ = self.request("POST", f"/api/sandboxes/{sandbox_id}/resume", token=owner)
        self.assertEqual(status, 409)

        status, approved = self.request("POST", f"/api/sandboxes/{sandbox_id}/approve", token=admin_token)
        self.assertEqual(status, 200)
        self.assertEqual(approved["sandbox"]["status"], "running")
        self.assertIn("startedAt", approved["sandbox"])
        self.assertEqual(approved["sandbox"]["approvedBy"], "admin")

        # 重复审批 -> 409
        status, _ = self.request("POST", f"/api/sandboxes/{sandbox_id}/approve", token=admin_token)
        self.assertEqual(status, 409)

        # 运行中的沙箱进程真实存在（dry-run sleep 或 wasmer）
        stored = next(s for s in self.sandboxes_on_disk() if s["id"] == sandbox_id)
        self.assertIn("runtime", stored)
        self.assertGreater(stored["runtime"]["pid"], 0)

        status, paused = self.request("POST", f"/api/sandboxes/{sandbox_id}/pause", token=owner)
        self.assertEqual(status, 200)
        self.assertEqual(paused["sandbox"]["status"], "paused")
        self.assertEqual(paused["sandbox"]["pausedBy"], "phone-13900000005")

        status, resumed = self.request("POST", f"/api/sandboxes/{sandbox_id}/resume", token=owner)
        self.assertEqual(status, 200)
        self.assertEqual(resumed["sandbox"]["status"], "running")

        status, terminated = self.request("POST", f"/api/sandboxes/{sandbox_id}/terminate", token=owner)
        self.assertEqual(status, 200)
        self.assertEqual(terminated["sandbox"]["status"], "terminated")

        # 终止是终态
        status, _ = self.request("POST", f"/api/sandboxes/{sandbox_id}/terminate", token=owner)
        self.assertEqual(status, 409)
        status, _ = self.request("POST", f"/api/sandboxes/{sandbox_id}/approve", token=admin_token)
        self.assertEqual(status, 409)

        # 生命周期事件齐全且含暂停/恢复/终止
        status, events = self.request("GET", "/api/events", token=admin_token)
        self.assertEqual(status, 200)
        actions = [e["action"] for e in events["events"]]
        for expected in ("创建待审批沙箱", "人工审批", "暂停沙箱", "恢复沙箱", "终止沙箱"):
            self.assertIn(expected, actions)


class TestE2E07Quota(E2EBase):
    """E2E-07: maxConcurrent quota blocks extra live sandboxes with 409."""

    def test_e2e_07(self):
        _, admin = self.admin_login()
        admin_token = admin["token"]

        _, original = self.request("GET", "/api/settings", token=admin_token)
        saved = dict(original["settings"])
        try:
            status, updated = self.request("POST", "/api/settings", {**saved, "maxConcurrent": 1}, token=admin_token)
            self.assertEqual(status, 200)
            self.assertEqual(updated["settings"]["maxConcurrent"], 1)

            user = self.phone_login("13900000006")
            status, first = self.create_sandbox(user, name="quota-one")
            self.assertEqual(status, 201)
            status, second = self.create_sandbox(user, name="quota-two")
            self.assertEqual(status, 409, "超额创建必须 409")
            self.assertIn("上限", second["error"])

            # 管理员不受配额限制
            status, _ = self.create_sandbox(admin_token, name="quota-admin")
            self.assertEqual(status, 201)

            # 终止后配额释放
            sandbox_id = first["sandbox"]["id"]
            status, _ = self.request("POST", f"/api/sandboxes/{sandbox_id}/terminate", token=user)
            self.assertEqual(status, 200)
            status, _ = self.create_sandbox(user, name="quota-three")
            self.assertEqual(status, 201, "终止后应恢复可创建")
        finally:
            self.request("POST", "/api/settings", saved, token=admin_token)


class TestE2E08CredentialBroker(E2EBase):
    """E2E-08: secrets stay on the host — masked lists, no plaintext anywhere downstream."""

    SECRET = "ghp_e2e_super_secret_token_987"

    def test_e2e_08(self):
        _, admin = self.admin_login()
        admin_token = admin["token"]

        status, _ = self.request("POST", "/api/credentials", {"name": "github-e2e", "value": self.SECRET, "allowedHosts": []}, token=admin_token)
        self.assertEqual(status, 400, "没有目的地白名单必须 400")

        status, registered = self.request(
            "POST", "/api/credentials",
            {"name": "github-e2e", "value": self.SECRET, "allowedHosts": ["api.github.com"]},
            token=admin_token,
        )
        self.assertEqual(status, 200)
        self.assertNotIn(self.SECRET, json.dumps(registered), "注册响应不得回显明文")

        status, listing = self.request("GET", "/api/credentials", token=admin_token)
        self.assertEqual(status, 200)
        entry = next(item for item in listing["credentials"] if item["name"] == "github-e2e")
        self.assertTrue(entry["masked"].startswith("ghp_"), "掩码应保留前缀")
        self.assertNotIn(self.SECRET, entry["masked"])
        self.assertEqual(entry["allowedHosts"], ["api.github.com"])

        # 普通用户拿不到凭据列表
        user = self.phone_login("13900000007")
        status, _ = self.request("GET", "/api/credentials", token=user)
        self.assertEqual(status, 403)
        status, _ = self.request("POST", "/api/credentials", {"name": "x", "value": "y", "allowedHosts": ["a.b"]}, token=user)
        self.assertEqual(status, 403)

        # 创建使用凭据的沙箱：响应与磁盘文件都不得出现明文
        status, created = self.create_sandbox(user, name="broker-e2e", credentials=["github-e2e"])
        self.assertEqual(status, 201)
        payload = json.dumps(created, ensure_ascii=False)
        self.assertNotIn(self.SECRET, payload, "沙箱创建响应不得包含明文凭据")
        self.assertIn("{{SD_CRED_", payload, "环境变量必须是占位符")

        sandbox_id = created["sandbox"]["id"]
        status, manifest = self.request("GET", f"/api/sandboxes/{sandbox_id}/manifest", token=user)
        self.assertNotIn(self.SECRET, json.dumps(manifest, ensure_ascii=False), "启动清单不得包含明文凭据")
        self.assertFalse(manifest["manifest"]["credentialBroker"]["exposedValues"])

        disk_body = (self.data_dir / "sandboxes.json").read_text(encoding="utf-8")
        self.assertNotIn(self.SECRET, disk_body, "数据文件不得落入明文凭据")


class TestE2E09EgressProxy(E2EBase):
    """E2E-09: egress proxy auth, SSRF guard, allowlist, pause freeze."""

    def test_e2e_09(self):
        _, admin = self.admin_login()
        admin_token = admin["token"]

        _, cred = self.request(
            "POST", "/api/credentials",
            {"name": "github-proxy-e2e", "value": "ghp_proxy_secret", "allowedHosts": ["api.github.test"]},
            token=admin_token,
        )
        status, created = self.create_sandbox(
            admin_token, name="proxy-e2e", policyId="balanced", credentials=["github-proxy-e2e"],
        )
        self.assertEqual(status, 201)
        sandbox_id = created["sandbox"]["id"]
        status, _ = self.request("POST", f"/api/sandboxes/{sandbox_id}/approve", token=admin_token)
        self.assertEqual(status, 200)

        stored = next(s for s in self.sandboxes_on_disk() if s["id"] == sandbox_id)
        token = stored.get("egressToken")
        self.assertTrue(token, "审批后必须生成 egressToken")
        auth = base64.b64encode(f"{sandbox_id}:{token}".encode()).decode()

        try:
            # 无鉴权 / 错鉴权 -> 407
            self.assertEqual(self.proxy_request("GET", "http://api.github.test/"), 407)
            wrong = base64.b64encode(f"{sandbox_id}:wrong".encode()).decode()
            self.assertEqual(self.proxy_request("GET", "http://api.github.test/", auth=wrong), 407)

            # SSRF：回环/元数据端点硬拒绝
            self.assertEqual(self.proxy_request("CONNECT", "localhost:443", auth), 403)
            self.assertEqual(self.proxy_request("CONNECT", "127.0.0.1:443", auth), 403)
            self.assertEqual(self.proxy_request("GET", "http://169.254.169.254/latest", auth), 403)

            # 仅允许 443 隧道
            self.assertEqual(self.proxy_request("CONNECT", "example.com:80", auth), 403)

            # 白名单外的公网目标 -> 403
            code = self.proxy_request("GET", "http://untrusted.invalid/", auth)
            self.assertEqual(code, 403)

            # 白名单内目标：鉴权与策略全部通过，上游不可达 -> 502
            code = self.proxy_request("GET", "http://api.github.test/user", auth)
            self.assertEqual(code, 502, "白名单内目标应通过策略检查，失败应在上游连接阶段")

            # 暂停期间外联冻结
            status, _ = self.request("POST", f"/api/sandboxes/{sandbox_id}/pause", token=admin_token)
            self.assertEqual(status, 200)
            self.assertEqual(self.proxy_request("GET", "http://api.github.test/user", auth), 403)
            status, _ = self.request("POST", f"/api/sandboxes/{sandbox_id}/resume", token=admin_token)
            self.assertEqual(status, 200)
            self.assertEqual(self.proxy_request("GET", "http://api.github.test/user", auth), 502, "恢复后重新走到上游连接")

            # 代理健康检查可匿名
            conn = http.client.HTTPConnection("127.0.0.1", self.proxy_port, timeout=5)
            conn.request("GET", "/healthz")
            resp = conn.getresponse()
            body = json.loads(resp.read())
            conn.close()
            self.assertEqual(resp.status, 200)
            self.assertTrue(body["ok"])
        finally:
            self.request("POST", f"/api/sandboxes/{sandbox_id}/terminate", token=admin_token)


class TestE2E10AuditHistory(E2EBase):
    """E2E-10: audit log persists to audit.jsonl and serves history queries to admins only."""

    def test_e2e_10(self):
        _, admin = self.admin_login()
        admin_token = admin["token"]

        marker = "audit-marker-e2e-10"
        status, created = self.create_sandbox(admin_token, name=marker)
        self.assertEqual(status, 201)
        sandbox_id = created["sandbox"]["id"]
        status, _ = self.request("POST", f"/api/sandboxes/{sandbox_id}/terminate", token=admin_token)
        self.assertEqual(status, 200)

        # 文件落盘可检索
        audit_file = self.data_dir / "audit.jsonl"
        self.assertTrue(audit_file.exists())
        lines = [json.loads(line) for line in audit_file.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertTrue(any(marker in str(line.get("detail", "")) for line in lines), "audit.jsonl 必须记录本次操作")
        self.assertTrue(all("at" in line and "action" in line for line in lines))

        # history 查询：分页 + 关键字过滤 + 最新在前
        status, history = self.request("GET", "/api/events?history=1&limit=50", token=admin_token)
        self.assertEqual(status, 200)
        self.assertGreater(history["size"], 0)
        ats = [e["at"] for e in history["events"]]
        self.assertEqual(ats, sorted(ats, reverse=True), "历史事件必须最新在前")
        self.assertTrue(any(marker in str(e.get("detail", "")) for e in history["events"]))

        status, filtered = self.request("GET", f"/api/events?history=1&q={marker}", token=admin_token)
        self.assertEqual(status, 200)
        self.assertGreaterEqual(len(filtered["events"]), 2, "创建 + 终止两条事件")
        self.assertTrue(all(marker in e["detail"] for e in filtered["events"]))

        status, paged = self.request("GET", f"/api/events?history=1&q={marker}&limit=1&offset=1", token=admin_token)
        self.assertEqual(status, 200)
        self.assertEqual(len(paged["events"]), 1, "分页参数必须生效")

        # 非管理员无权查看任何事件
        user = self.phone_login("13900000008")
        status, _ = self.request("GET", "/api/events", token=user)
        self.assertEqual(status, 403)
        status, _ = self.request("GET", "/api/events?history=1", token=user)
        self.assertEqual(status, 403)


if __name__ == "__main__":
    unittest.main()
