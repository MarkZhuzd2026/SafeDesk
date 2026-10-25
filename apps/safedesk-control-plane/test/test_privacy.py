"""Tests for the privacy curtain: alias identity + PII redaction (外卖隐私下单场景)."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from privacy import alias_profile, anonymize_order_fields, looks_like_bank_card, redact_pii  # noqa: E402


REAL_PHONE = "13812345678"
REAL_ID = "110101199003071234"
REAL_CARD = "4111111111111111"  # passes Luhn (经典测试卡号)
REAL_EMAIL = "wuyeliang@example.com"
REAL_NAME = "张伟"


class AliasProfileTest(unittest.TestCase):
    def test_deterministic_per_sandbox(self):
        first = alias_profile("sbx-abc1234")
        second = alias_profile("sbx-abc1234")
        self.assertEqual(first, second)

    def test_distinct_between_sandboxes(self):
        self.assertNotEqual(alias_profile("sbx-a1")["aliasId"], alias_profile("sbx-a2")["aliasId"])

    def test_alias_shape(self):
        alias = alias_profile("sbx-abc1234")
        self.assertRegex(alias["aliasId"], r"^sf-[0-9a-f]{8}$")
        self.assertTrue(alias["name"].startswith("访客-"))
        self.assertRegex(alias["phone"], r"^138\d{8}$")
        self.assertIn("自提柜", alias["address"])

    def test_alias_does_not_contain_real_identity(self):
        alias = alias_profile("sbx-abc1234")
        for field in ("name", "phone", "address"):
            self.assertNotIn(REAL_PHONE, alias[field])
            self.assertNotIn(REAL_NAME, alias[field])


class RedactPiiTest(unittest.TestCase):
    def test_phone_redacted(self):
        text, hits = redact_pii(f"收货人电话 {REAL_PHONE} 勿扰")
        self.assertNotIn(REAL_PHONE, text)
        self.assertIn("phone", hits)

    def test_idcard_redacted(self):
        text, hits = redact_pii(f"实名认证 {REAL_ID}")
        self.assertNotIn(REAL_ID, text)
        self.assertIn("idcard", hits)

    def test_bank_card_redacted_with_luhn(self):
        text, hits = redact_pii(f"卡号 {REAL_CARD}")
        self.assertNotIn(REAL_CARD, text)
        self.assertIn("card", hits)

    def test_non_card_long_numbers_kept(self):
        text, hits = redact_pii("订单号 1234567890123")
        self.assertIn("1234567890123", text)
        self.assertNotIn("card", hits)

    def test_luhn_helper(self):
        self.assertTrue(looks_like_bank_card(REAL_CARD))
        self.assertFalse(looks_like_bank_card("1234567890123"))
        self.assertFalse(looks_like_bank_card("123"))

    def test_email_redacted(self):
        text, hits = redact_pii(f"联系 {REAL_EMAIL}")
        self.assertNotIn(REAL_EMAIL, text)
        self.assertIn("email", hits)

    def test_clean_text_passes_through(self):
        text, hits = redact_pii("黄焖鸡米饭大份微辣")
        self.assertEqual(text, "黄焖鸡米饭大份微辣")
        self.assertEqual(hits, [])


class AnonymizeOrderFieldsTest(unittest.TestCase):
    def test_identity_fields_swapped_to_alias(self):
        alias = alias_profile("sbx-takeout1")
        payload = {
            "name": REAL_NAME,
            "phone": REAL_PHONE,
            "address": "滨江路88号春天花园3栋1201",
            "items": [{"name": "黄焖鸡米饭", "count": 1}],
            "note": "电话 13812345678 联系",
        }
        result, swaps = anonymize_order_fields(payload, alias)
        self.assertEqual(result["name"], alias["name"])
        self.assertEqual(result["phone"], alias["phone"])
        self.assertEqual(result["address"], alias["address"])
        self.assertEqual(result["items"], payload["items"])
        self.assertNotIn(REAL_PHONE, result["note"])
        self.assertTrue({"name→alias", "phone→alias", "address→alias"} <= set(swaps))

    def test_payment_fields_dropped(self):
        payload = {"name": "x", "cardNo": REAL_CARD, "cvv": "123"}
        result, swaps = anonymize_order_fields(payload, alias_profile("sbx-takeout1"))
        self.assertNotIn("cardNo", result)
        self.assertNotIn("cvv", result)
        self.assertIn("payment-fields-dropped", swaps)

    def test_non_dict_passes_through(self):
        result, swaps = anonymize_order_fields("body", alias_profile("sbx-x1"))
        self.assertEqual(result, "body")
        self.assertEqual(swaps, [])


if __name__ == "__main__":
    unittest.main()
