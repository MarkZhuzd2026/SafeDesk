"""Auth and tenant isolation tests for the Python control plane."""
from __future__ import annotations

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
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class AuthApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data_dir = Path(tempfile.mkdtemp(prefix="safedesk-auth-"))
        cls.port = free_port()
        cls.base = f"http://127.0.0.1:{cls.port}"
        env = {
            **os.environ,
            "PORT": str(cls.port),
            "SAFEDESK_DATA_DIR": str(cls.data_dir),
            "SAFEDESK_DATA_FILE": str(cls.data_dir / "sandboxes.json"),
            "SAFEDESK_AUTH": "1",
            "SAFEDESK_DEMO": "1",
            "SAFEDESK_ADMIN_USERNAME": "admin",
            "SAFEDESK_ADMIN_PASSWORD": "SafeDesk@Admin",
        }
        cls.server = subprocess.Popen(
            [sys.executable, "server.py"],
            cwd=ROOT,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for _ in range(50):
            try:
                cls.request("GET", "/api/auth/config")
                break
            except OSError:
                time.sleep(0.1)
        else:
            cls.tearDownClass()
            raise RuntimeError("auth server did not start")

    @classmethod
    def tearDownClass(cls):
        cls.server.terminate()
        cls.server.wait(timeout=5)
        shutil.rmtree(cls.data_dir, ignore_errors=True)

    @classmethod
    def request(cls, method: str, path: str, body=None, token: str | None = None):
        payload = None
        headers = {}
        if body is not None:
            payload = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(cls.base + path, data=payload, headers=headers, method=method)
        try:
            with OPENER.open(request, timeout=5) as response:
                return response.status, json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read() or b"{}")

    def test_bootstrap_requires_login(self):
        status, data = self.request("GET", "/api/bootstrap")
        self.assertEqual(status, 401)
        self.assertIn("登录", data["error"])

    def test_admin_login_and_approval(self):
        status, login = self.request("POST", "/api/auth/admin/login", {"username": "admin", "password": "SafeDesk@Admin"})
        self.assertEqual(status, 200)
        self.assertEqual(login["user"]["role"], "admin")
        token = login["token"]
        status, created = self.request("POST", "/api/sandboxes", {
            "name": "admin-box",
            "agent": "codex",
            "policyId": "review",
            "workspace": "/tmp/admin",
        }, token)
        self.assertEqual(status, 201)
        status, approved = self.request("POST", f"/api/sandboxes/{created['sandbox']['id']}/approve", token=token)
        self.assertEqual(status, 200)
        self.assertEqual(approved["sandbox"]["status"], "running")

    def test_phone_user_cannot_approve_or_see_others(self):
        _, sent = self.request("POST", "/api/auth/phone/send", {"phone": "13800138000"})
        _, verify = self.request("POST", "/api/auth/phone/verify", {"phone": "13800138000", "token": sent["demoCode"]})
        user_token = verify["token"]
        _, created = self.request("POST", "/api/sandboxes", {
            "name": "user-box",
            "agent": "dsh",
            "policyId": "balanced",
            "workspace": "/tmp/user",
        }, user_token)
        status, _ = self.request("POST", f"/api/sandboxes/{created['sandbox']['id']}/approve", token=user_token)
        self.assertEqual(status, 403)
        status, _ = self.request("GET", "/api/events", token=user_token)
        self.assertEqual(status, 403)
        _, other_sent = self.request("POST", "/api/auth/phone/send", {"phone": "13900139000"})
        _, other = self.request("POST", "/api/auth/phone/verify", {"phone": "13900139000", "token": other_sent["demoCode"]})
        _, visible = self.request("GET", "/api/sandboxes", token=other["token"])
        self.assertFalse(any(item["id"] == created["sandbox"]["id"] for item in visible["sandboxes"]))

    def test_invalid_phone_is_rejected_locally(self):
        status, data = self.request("POST", "/api/auth/phone/send", {"phone": "1380013800"})
        self.assertEqual(status, 400)
        self.assertEqual(data["error"], "请输入正确的 11 位手机号")

    def test_wechat_qr_becomes_user_session(self):
        _, started = self.request("POST", "/api/auth/wechat/start")
        status, _ = self.request("POST", "/api/auth/wechat/confirm", {"ticket": started["ticket"]})
        self.assertEqual(status, 200)
        _, polled = self.request("GET", f"/api/auth/wechat/poll?ticket={started['ticket']}")
        self.assertEqual(polled["status"], "confirmed")
        self.assertEqual(polled["user"]["provider"], "wechat")
        self.assertEqual(polled["user"]["role"], "user")


if __name__ == "__main__":
    unittest.main()
