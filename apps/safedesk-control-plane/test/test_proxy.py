"""Tests for the per-sandbox egress proxy (REQ-NW-001..009, 013, 014)."""
from __future__ import annotations

import base64
import http.client
import http.server
import json
import socket
import sys
import tempfile
import threading
import unittest
import unittest.mock
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import proxy as proxy_module  # noqa: E402
from privacy import alias_profile  # noqa: E402
from proxy import EgressPolicy, ProxyRuntime, is_blocked_host, serve  # noqa: E402


class EchoHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = (self.headers.get("Authorization", "") + "|" + self.path).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        return


class BlockedHostTest(unittest.TestCase):
    def test_private_and_metadata_blocked(self):
        self.assertTrue(is_blocked_host("127.0.0.1")[0])
        self.assertTrue(is_blocked_host("localhost")[0])
        self.assertTrue(is_blocked_host("169.254.169.254")[0])
        self.assertTrue(is_blocked_host("192.168.1.1")[0])
        self.assertTrue(is_blocked_host("")[0])

    def test_public_host_allowed(self):
        with unittest.mock.patch.object(proxy_module, "resolve_host", return_value=["93.184.216.34"]):
            self.assertFalse(is_blocked_host("api.github.com")[0])

    def test_dns_rebinding_to_private_blocked(self):
        with unittest.mock.patch.object(proxy_module, "resolve_host", return_value=["10.0.0.9"]):
            blocked, reason = is_blocked_host("evil-dns-rebind.example")
            self.assertTrue(blocked)
            self.assertIn("私网", reason)


class PolicyTest(unittest.TestCase):
    def test_allowlist_and_wildcard(self):
        policy = EgressPolicy(["api.github.com", "*.example.com"])
        self.assertTrue(policy.allows("api.github.com"))
        self.assertTrue(policy.allows("deep.example.com"))
        self.assertFalse(policy.allows("evil.org"))

    def test_injection_only_for_allowed_hosts(self):
        policy = EgressPolicy(["api.github.com"], {"{{SD_CRED_sbx_tok}}": {"value": "ghp_real", "hosts": ["api.github.com"]}})
        headers, error = policy.inject_headers("api.github.com", {"Authorization": "{{SD_CRED_sbx_tok}}"})
        self.assertIsNone(error)
        self.assertEqual(headers["Authorization"], "ghp_real")
        _, error = policy.inject_headers("evil.org", {"Authorization": "{{SD_CRED_sbx_tok}}"})
        self.assertIn("不允许", error)


class ProxyRuntimeTest(unittest.TestCase):
    ORIGIN_HOST = "pub.test"

    def setUp(self):
        self.runtime = ProxyRuntime()
        self.runtime.register("sbx-proxy01", "tok-secret", EgressPolicy(
            [self.ORIGIN_HOST],
            {"{{SD_CRED_sbx-proxy01_x}}": {"value": "ghp_injected", "hosts": [self.ORIGIN_HOST]}},
        ))
        self.proxy = serve(self.runtime, "127.0.0.1", 0)
        self.proxy_port = self.proxy.server_port
        self.origin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), EchoHandler)
        threading.Thread(target=self.origin.serve_forever, daemon=True).start()
        self.origin_port = self.origin.server_port
        # Public DNS check passes; actual connect rerouted to the local echo origin.
        self.dns_patch = unittest.mock.patch.object(proxy_module, "resolve_host", return_value=["93.184.216.34"])
        self.dns_patch.start()
        real_connect = socket.create_connection

        def rerouted(address, *args, **kwargs):
            host, port = address
            if host == self.ORIGIN_HOST and port == self.origin_port:
                return real_connect(("127.0.0.1", self.origin_port), *args, **kwargs)
            return real_connect(address, *args, **kwargs)

        self.conn_patch = unittest.mock.patch("socket.create_connection", side_effect=rerouted)
        self.conn_patch.start()

    def tearDown(self):
        self.conn_patch.stop()
        self.dns_patch.stop()
        self.proxy.shutdown()
        self.origin.shutdown()

    def raw_get(self, path: str, auth: str | None = "sbx-proxy01:tok-secret", headers: dict | None = None) -> tuple[int, bytes]:
        conn = http.client.HTTPConnection("127.0.0.1", self.proxy_port, timeout=5)
        all_headers = {}
        if auth:
            all_headers["Proxy-Authorization"] = "Basic " + base64.b64encode(auth.encode()).decode()
        all_headers.update(headers or {})
        conn.request("GET", f"http://{self.ORIGIN_HOST}:{self.origin_port}{path}", headers=all_headers)
        resp = conn.getresponse()
        body = resp.read()
        status = resp.status
        conn.close()
        return status, body

    def test_healthz(self):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.proxy_port}/healthz", timeout=5) as resp:
            self.assertEqual(resp.status, 200)

    def test_allowlisted_host_passes_with_auth(self):
        status, body = self.raw_get("/ok")
        self.assertEqual(status, 200)
        self.assertIn(b"|/ok", body)
        self.assertTrue(any(event["level"] == "allow" for event in self.runtime.snapshot_events()))

    def test_anonymous_request_rejected_407(self):
        status, _ = self.raw_get("/nope", auth=None)
        self.assertEqual(status, 407)

    def test_wrong_token_rejected(self):
        status, _ = self.raw_get("/nope", auth="sbx-proxy01:wrong")
        self.assertEqual(status, 407)

    def test_paused_sandbox_frozen(self):
        self.runtime.set_paused("sbx-proxy01", True)
        status, body = self.raw_get("/frozen")
        self.assertEqual(status, 403)
        self.assertIn(b"egress denied", body)
        self.runtime.set_paused("sbx-proxy01", False)

    def test_placeholder_injected_host_side(self):
        status, body = self.raw_get("/inject", headers={"Authorization": "{{SD_CRED_sbx-proxy01_x}}"})
        self.assertEqual(status, 200)
        self.assertTrue(body.startswith(b"ghp_injected|/inject"))

    def test_block_events_recorded(self):
        self.raw_get("/x", auth=None)
        self.assertTrue(any(event["level"] == "block" for event in self.runtime.snapshot_events()))


class MeituanOrderHandler(http.server.BaseHTTPRequestHandler):
    """Mock 美团平台：回显收到的 JSON 体和别名头。"""

    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(size) if size else b""
        body = json.dumps({
            "body": raw.decode("utf-8"),
            "aliasHeader": self.headers.get("X-Safedesk-Alias-Id"),
            "auth": self.headers.get("Authorization"),
        }).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        return


class PrivacyCurtainProxyTest(unittest.TestCase):
    """外卖隐私下单场景：平台只见沙箱别名，真实姓名/手机号/银行卡不出沙箱。"""

    ORIGIN_HOST = "meituan.demo.local"

    def setUp(self):
        self.runtime = ProxyRuntime()
        self.runtime.register("sbx-takeout", "tok-order", EgressPolicy(
            [self.ORIGIN_HOST],
            {"{{SD_CRED_sbx-takeout_pay}}": {"value": "pay-token-real-9f81", "hosts": [self.ORIGIN_HOST]}},
            alias_profile("sbx-takeout"),
        ))
        self.proxy = serve(self.runtime, "127.0.0.1", 0)
        self.proxy_port = self.proxy.server_port
        self.origin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), MeituanOrderHandler)
        threading.Thread(target=self.origin.serve_forever, daemon=True).start()
        self.origin_port = self.origin.server_port
        self.dns_patch = unittest.mock.patch.object(proxy_module, "resolve_host", return_value=["93.184.216.34"])
        self.dns_patch.start()
        real_connect = socket.create_connection

        def rerouted(address, *args, **kwargs):
            host, port = address
            if host == self.ORIGIN_HOST and port == self.origin_port:
                return real_connect(("127.0.0.1", self.origin_port), *args, **kwargs)
            return real_connect(address, *args, **kwargs)

        self.conn_patch = unittest.mock.patch("socket.create_connection", side_effect=rerouted)
        self.conn_patch.start()

    def tearDown(self):
        self.conn_patch.stop()
        self.dns_patch.stop()
        self.proxy.shutdown()
        self.origin.shutdown()

    def post_order(self, payload: bytes, headers: dict | None = None) -> tuple[int, dict]:
        conn = http.client.HTTPConnection("127.0.0.1", self.proxy_port, timeout=5)
        all_headers = {
            "Proxy-Authorization": "Basic " + base64.b64encode(b"sbx-takeout:tok-order").decode(),
            "Content-Type": "application/json",
            "Content-Length": str(len(payload)),
        }
        all_headers.update(headers or {})
        conn.request("POST", f"http://{self.ORIGIN_HOST}:{self.origin_port}/api/v1/order", body=payload, headers=all_headers)
        resp = conn.getresponse()
        data = json.loads(resp.read() or b"{}")
        conn.close()
        return resp.status, data

    def test_platform_sees_alias_only_no_real_pii(self):
        real = {
            "name": "张伟",
            "phone": "13812345678",
            "address": "滨江路88号春天花园3栋1201",
            "cardNo": "4111111111111111",
            "items": [{"name": "黄焖鸡米饭", "count": 1}],
            "note": "电话 13812345678 联系",
        }
        status, echoed = self.post_order(json.dumps(real, ensure_ascii=False).encode("utf-8"))
        self.assertEqual(status, 200)
        body = echoed["body"]
        self.assertNotIn("张伟", body)
        self.assertNotIn("13812345678", body)
        self.assertNotIn("春天花园", body)
        self.assertNotIn("4111111111111111", body)
        alias = alias_profile("sbx-takeout")
        self.assertIn(alias["phone"], body)
        self.assertIn(alias["address"], body)
        self.assertIn("黄焖鸡米饭", body)
        self.assertEqual(echoed["aliasHeader"], alias["aliasId"])
        self.assertTrue(any("脱敏" in event["detail"] for event in self.runtime.snapshot_events()))

    def test_payment_token_injected_only_for_meituan(self):
        status, echoed = self.post_order(
            json.dumps({"orderId": "A123"}).encode("utf-8"),
            headers={"Authorization": "{{SD_CRED_sbx-takeout_pay}}"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(echoed["auth"], "pay-token-real-9f81")


if __name__ == "__main__":
    unittest.main()


class CtripBookingHandler(http.server.BaseHTTPRequestHandler):
    """Mock 携程平台：回显收到的 JSON 体与别名头。"""

    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(size) if size else b""
        body = json.dumps({"body": raw.decode("utf-8"), "aliasHeader": self.headers.get("X-Safedesk-Alias-Id")}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        return


TRIP_NAME_PH = "{{SD_TRV_sbx-trip_traveller-li_name_ab123456}}"
TRIP_ID_PH = "{{SD_TRV_sbx-trip_traveller-li_idCard_ab123456}}"
TRIP_PHONE_PH = "{{SD_TRV_sbx-trip_traveller-li_phone_ab123456}}"
TRIP_PAY_PH = "{{SD_CRED_sbx-trip_pay}}"


class CtripCurtainProxyTest(unittest.TestCase):
    """携程订票场景：实名出票字段只在白名单域上被代理解析，沙箱内只有占位符。"""

    ORIGIN_HOST = "api.ctrip.demo.local"

    def setUp(self):
        self.runtime = ProxyRuntime()
        self.runtime.register("sbx-trip", "tok-trip", EgressPolicy(
            [self.ORIGIN_HOST],
            {
                TRIP_NAME_PH: {"value": "李雷", "hosts": [self.ORIGIN_HOST]},
                TRIP_ID_PH: {"value": "110101199003071234", "hosts": [self.ORIGIN_HOST]},
                TRIP_PHONE_PH: {"value": "13812345678", "hosts": [self.ORIGIN_HOST]},
                TRIP_PAY_PH: {"value": "pay-token-ctrip-7f20", "hosts": [self.ORIGIN_HOST]},
            },
            alias_profile("sbx-trip"),
        ))
        self.runtime.register("sbx-trip-bad", "tok-bad", EgressPolicy(
            [self.ORIGIN_HOST],
            {TRIP_NAME_PH: {"value": "李雷", "hosts": ["other.not-allowed"]}},
        ))
        self.proxy = serve(self.runtime, "127.0.0.1", 0)
        self.proxy_port = self.proxy.server_port
        self.origin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), CtripBookingHandler)
        threading.Thread(target=self.origin.serve_forever, daemon=True).start()
        self.origin_port = self.origin.server_port
        self.dns_patch = unittest.mock.patch.object(proxy_module, "resolve_host", return_value=["93.184.216.34"])
        self.dns_patch.start()
        real_connect = socket.create_connection

        def rerouted(address, *args, **kwargs):
            host, port = address
            if host == self.ORIGIN_HOST and port == self.origin_port:
                return real_connect(("127.0.0.1", self.origin_port), *args, **kwargs)
            return real_connect(address, *args, **kwargs)

        self.conn_patch = unittest.mock.patch("socket.create_connection", side_effect=rerouted)
        self.conn_patch.start()

    def tearDown(self):
        self.conn_patch.stop()
        self.dns_patch.stop()
        self.proxy.shutdown()
        self.origin.shutdown()

    def post_booking(self, payload: dict, auth: str = "sbx-trip:tok-trip", extra_headers: dict | None = None) -> tuple[int, dict]:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        conn = http.client.HTTPConnection("127.0.0.1", self.proxy_port, timeout=5)
        headers = {
            "Proxy-Authorization": "Basic " + base64.b64encode(auth.encode()).decode(),
            "Content-Type": "application/json",
            "Content-Length": str(len(raw)),
        }
        headers.update(extra_headers or {})
        conn.request("POST", f"http://{self.ORIGIN_HOST}:{self.origin_port}/openapi/book", body=raw, headers=headers)
        resp = conn.getresponse()
        text = resp.read().decode("utf-8", "replace")
        conn.close()
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = {"errorBody": text}
        return resp.status, data

    def test_treveler_placeholders_resolved_host_side(self):
        payload = {
            "traveler": {"name": TRIP_NAME_PH, "idCard": TRIP_ID_PH, "phone": TRIP_PHONE_PH},
            "note": "紧急电话 13812345678 别漏接",
            "route": "北京-上海 CA1837",
        }
        status, echoed = self.post_booking(payload, extra_headers={"Authorization": TRIP_PAY_PH})
        self.assertEqual(status, 200)
        body = json.loads(echoed["body"])
        traveler = body["traveler"]
        self.assertEqual(traveler["name"], "李雷")
        self.assertEqual(traveler["idCard"], "110101199003071234")
        self.assertEqual(traveler["phone"], "13812345678")
        self.assertNotIn("SD_TRV", echoed["body"])
        self.assertIn("[*手机号*]", body["note"])
        self.assertNotIn("13812345678", body["note"])
        self.assertEqual(body["route"], payload["route"])
        self.assertEqual(echoed["aliasHeader"], alias_profile("sbx-trip")["aliasId"])

    def test_body_placeholder_blocked_for_other_hosts(self):
        status, echoed = self.post_booking(
            {"traveler": {"name": TRIP_NAME_PH}}, auth="sbx-trip-bad:tok-bad")
        self.assertEqual(status, 403)
        self.assertIn("egress denied", json.dumps(echoed))
        self.assertTrue(any("不允许" in event["detail"] for event in self.runtime.snapshot_events()))


if __name__ == "__main__":
    unittest.main()
