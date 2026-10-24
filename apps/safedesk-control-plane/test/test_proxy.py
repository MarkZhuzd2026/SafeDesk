"""Tests for the per-sandbox egress proxy (REQ-NW-001..009, 013, 014)."""
from __future__ import annotations

import base64
import http.client
import http.server
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


if __name__ == "__main__":
    unittest.main()
