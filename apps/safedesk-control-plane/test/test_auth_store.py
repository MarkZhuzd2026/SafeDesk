"""Unit tests for AuthStore: OTP, WeChat QR, admin login, sessions."""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

os.environ["SAFEDESK_DEMO"] = "1"
os.environ["SAFEDESK_OTP_ECHO"] = "1"
os.environ["SAFEDESK_ADMIN_USERNAME"] = "admin"
os.environ["SAFEDESK_ADMIN_PASSWORD"] = "SafeDesk@Admin"
os.environ["SAFEDESK_ADMIN_PHONES"] = "13800000000"

from auth import AuthStore  # noqa: E402


class AuthStoreTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data_dir = Path(tempfile.mkdtemp(prefix="safedesk-authstore-"))
        cls.store = AuthStore(cls.data_dir)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.data_dir, ignore_errors=True)

    def test_public_config(self):
        config = self.store.public_config()
        self.assertEqual(config["methods"], ["phone", "wechat", "wecom", "admin"])
        self.assertEqual(config["wechatMode"], "local-qr")
        self.assertEqual(config["wecomMode"], "local-qr")
        self.assertTrue(config["demo"])
        self.assertEqual(config["adminUsername"], "admin")
        self.assertTrue(config["wecomReady"])

    def test_admin_is_seeded_with_hashed_password(self):
        admin = self.store.user_by_id("admin")
        self.assertEqual(admin["role"], "admin")
        self.assertIn("$", admin["passwordHash"])
        self.assertNotEqual(admin["passwordHash"], "SafeDesk@Admin")

    def test_password_round_trip(self):
        stored = self.store.hash_password("correct-horse")
        self.assertTrue(self.store.verify_password("correct-horse", stored))
        self.assertFalse(self.store.verify_password("wrong-battery", stored))

    def test_password_rejects_malformed_hash(self):
        self.assertFalse(self.store.verify_password("x", ""))
        self.assertFalse(self.store.verify_password("x", "nosalt"))

    def test_public_user_strips_hash(self):
        published = self.store.public_user(self.store.user_by_id("admin"))
        self.assertEqual(published["role"], "admin")
        self.assertNotIn("passwordHash", published)

    def test_public_user_none(self):
        self.assertIsNone(self.store.public_user(None))

    def test_login_admin_success(self):
        session = self.store.login_admin("admin", "SafeDesk@Admin")
        self.assertTrue(session["token"])
        self.assertEqual(session["user"]["role"], "admin")

    def test_login_admin_wrong_password(self):
        with self.assertRaises(ValueError):
            self.store.login_admin("admin", "wrong")

    def test_login_admin_unknown_user(self):
        with self.assertRaises(ValueError):
            self.store.login_admin("root", "SafeDesk@Admin")

    def test_session_user_live_and_bogus(self):
        session = self.store.login_admin("admin", "SafeDesk@Admin")
        self.assertEqual(self.store.session_user(session["token"])["id"], "admin")
        self.assertIsNone(self.store.session_user("not-a-token"))
        self.assertIsNone(self.store.session_user(None))

    def test_revoke_invalidates_token(self):
        session = self.store.login_admin("admin", "SafeDesk@Admin")
        self.store.revoke(session["token"])
        self.assertIsNone(self.store.session_user(session["token"]))

    def test_revoke_missing_is_noop(self):
        self.store.revoke(None)
        self.store.revoke("missing")

    def test_otp_rejects_invalid_phones(self):
        for phone in ["1380013800", "23800138000", ""]:
            with self.assertRaises(ValueError):
                self.store.send_phone_otp(phone)

    def test_otp_echoes_demo_code(self):
        sent = self.store.send_phone_otp("13900000001")
        self.assertTrue(sent["ok"])
        self.assertEqual(sent["ttlSeconds"], 300)
        self.assertRegex(sent["demoCode"], r"^\d{6}$")

    def test_otp_rate_limit(self):
        self.store.send_phone_otp("13900000002")
        with self.assertRaises(ValueError):
            self.store.send_phone_otp("13900000002")

    def test_verify_before_send(self):
        with self.assertRaises(ValueError):
            self.store.verify_phone_otp("13900000003", "000000")

    def test_verify_wrong_code(self):
        self.store.send_phone_otp("13900000004")
        with self.assertRaises(ValueError):
            self.store.verify_phone_otp("13900000004", "000000")

    def test_verify_lockout(self):
        phone = "13900000005"
        self.store.send_phone_otp(phone)
        for _ in range(5):
            with self.assertRaises(ValueError):
                self.store.verify_phone_otp(phone, "000000")
        with self.assertRaises(ValueError) as ctx:
            self.store.verify_phone_otp(phone, "000000")
        self.assertIn("次数过多", str(ctx.exception))

    def test_verify_creates_masked_user(self):
        phone = "13900000006"
        sent = self.store.send_phone_otp(phone)
        session = self.store.verify_phone_otp(phone, sent["demoCode"])
        self.assertEqual(session["user"]["role"], "user")
        self.assertEqual(session["user"]["provider"], "phone")
        self.assertEqual(session["user"]["displayName"], "139****0006")

    def test_verify_promotes_admin_phone(self):
        phone = "13800000000"
        self.store.otp.pop(phone, None)
        sent = self.store.send_phone_otp(phone)
        session = self.store.verify_phone_otp(phone, sent["demoCode"])
        self.assertEqual(session["user"]["role"], "admin")

    def test_verify_expired_code(self):
        phone = "13900000007"
        self.store.send_phone_otp(phone)
        pending = self.store.otp[phone]
        pending["expiresAt"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
        with self.assertRaises(ValueError):
            self.store.verify_phone_otp(phone, pending["code"])

    def test_wechat_start(self):
        started = self.store.start_wechat()
        self.assertTrue(started["ticket"])
        self.assertEqual(started["expiresIn"], 180)

    def test_wechat_poll_pending_confirmed_expired(self):
        started = self.store.start_wechat()
        self.assertEqual(self.store.poll_wechat(started["ticket"])["status"], "pending")
        self.store.confirm_wechat(started["ticket"])
        confirmed = self.store.poll_wechat(started["ticket"])
        self.assertEqual(confirmed["status"], "confirmed")
        self.assertEqual(confirmed["user"]["provider"], "wechat")
        self.assertEqual(self.store.poll_wechat(started["ticket"])["status"], "expired")

    def test_wechat_poll_unknown(self):
        self.assertEqual(self.store.poll_wechat("missing")["status"], "expired")

    def test_wechat_poll_timed_out(self):
        started = self.store.start_wechat()
        self.store.wechat[started["ticket"]]["expiresAt"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
        self.assertEqual(self.store.poll_wechat(started["ticket"])["status"], "expired")

    def test_wechat_confirm_missing(self):
        with self.assertRaises(ValueError):
            self.store.confirm_wechat("missing")

    def test_wechat_confirm_expired(self):
        started = self.store.start_wechat()
        self.store.wechat[started["ticket"]]["expiresAt"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
        with self.assertRaises(ValueError):
            self.store.confirm_wechat(started["ticket"])

    def test_wecom_start(self):
        started = self.store.start_wecom()
        self.assertTrue(started["ticket"])
        self.assertEqual(started["expiresIn"], 180)
        self.assertIn("企业微信", started["confirmHint"])

    def test_wecom_poll_pending_confirmed_expired(self):
        started = self.store.start_wecom()
        self.assertEqual(self.store.poll_wecom(started["ticket"])["status"], "pending")
        self.store.confirm_wecom(started["ticket"])
        confirmed = self.store.poll_wecom(started["ticket"])
        self.assertEqual(confirmed["status"], "confirmed")
        self.assertEqual(confirmed["user"]["provider"], "wecom")
        self.assertEqual(self.store.poll_wecom(started["ticket"])["status"], "expired")

    def test_wecom_poll_unknown(self):
        self.assertEqual(self.store.poll_wecom("missing")["status"], "expired")

    def test_wecom_confirm_missing(self):
        with self.assertRaises(ValueError):
            self.store.confirm_wecom("missing")

    def test_wecom_confirm_expired(self):
        started = self.store.start_wecom()
        self.store.wecom[started["ticket"]]["expiresAt"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
        with self.assertRaises(ValueError):
            self.store.confirm_wecom(started["ticket"])

    def test_upsert_updates_in_place(self):
        self.store._upsert_user({"id": "u-upsert", "role": "user", "displayName": "A"})
        self.store._upsert_user({"id": "u-upsert", "role": "user", "displayName": "B"})
        self.assertEqual(self.store.user_by_id("u-upsert")["displayName"], "B")


if __name__ == "__main__":
    unittest.main()
