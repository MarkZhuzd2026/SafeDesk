"""Tests for the traveler card registry (携程公务出行场景)."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from travelers import MAX_TRAVELERS_PER_SANDBOX, TRAVELER_FIELDS, TravelerRegistry  # noqa: E402

CARD = {
    "handle": "traveller-li",
    "name": "李雷",
    "idCard": "110101199003071234",
    "phone": "13812345678",
    "passport": "E12345678",
    "allowedHosts": ["api.ctrip.demo.local"],
}


def sandbox(tmp_id="sbx-trip01", **overrides):
    item = {"id": tmp_id, "travelerCards": ["traveller-li"], "status": "running"}
    item.update(overrides)
    return item


class TravelerRegistryTest(unittest.TestCase):
    def setUp(self):
        suffix = next(tempfile._get_candidate_names())
        self.dir = Path(tempfile.gettempdir()) / f"safedesk-travelers-{suffix}"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.registry = TravelerRegistry(self.dir / "travelers.json")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_register_masks_and_persists(self):
        card = self.registry.register(handle=CARD["handle"], name=CARD["name"], id_card=CARD["idCard"], phone=CARD["phone"], allowed_hosts=CARD["allowedHosts"], passport=CARD.get("passport"))
        self.assertEqual(card["phone"], "138****5678")
        self.assertEqual(card["name"], "李*")
        self.assertTrue(card["idCard"].startswith("1101"))
        self.assertTrue(card["idCard"].endswith("34"))
        self.assertNotIn("110101199003071234", card["idCard"])
        reloaded = TravelerRegistry(self.dir / "travelers.json")
        listed = reloaded.list_masked()
        self.assertEqual(listed[0]["phone"], "138****5678")
        mode = (self.dir / "travelers.json").stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_validation_errors(self):
        with self.assertRaises(ValueError):
            self.registry.register("x", "李雷", CARD["idCard"], CARD["phone"], CARD["allowedHosts"])
        with self.assertRaises(ValueError):
            self.registry.register("traveller-li", "李雷", "123", CARD["phone"], CARD["allowedHosts"])
        with self.assertRaises(ValueError):
            self.registry.register("traveller-li", "李雷", CARD["idCard"], "12345", CARD["allowedHosts"])
        with self.assertRaises(ValueError):
            self.registry.register("traveller-li", "李雷", CARD["idCard"], CARD["phone"], [])

    def test_upsert_and_remove(self):
        self.registry.register(handle=CARD["handle"], name=CARD["name"], id_card=CARD["idCard"], phone=CARD["phone"], allowed_hosts=CARD["allowedHosts"], passport=CARD.get("passport"))
        card = self.registry.register(handle="traveller-li", name="李雷", id_card=CARD["idCard"], phone=CARD["phone"], allowed_hosts=["api.ctrip.demo.local"], passport=None)
        self.assertIsNone(card["passport"])
        self.assertTrue(self.registry.remove("traveller-li"))
        self.assertFalse(self.registry.remove("traveller-li"))

    def test_placeholders_cover_all_fields(self):
        self.registry.register(handle=CARD["handle"], name=CARD["name"], id_card=CARD["idCard"], phone=CARD["phone"], allowed_hosts=CARD["allowedHosts"], passport=CARD.get("passport"))
        mapping = self.registry.issue_placeholders(sandbox())
        fields = mapping["traveller-li"]
        for field in TRAVELER_FIELDS:
            self.assertTrue(fields[field].startswith("{{SD_TRV_sbx-trip01_traveller-li_%s_" % field))

    def test_placeholders_quota_and_repeatable(self):
        names = [f"traveller-{idx}" for idx in range(MAX_TRAVELERS_PER_SANDBOX + 2)]
        mapping = self.registry.issue_placeholders(sandbox(travelerCards=names))
        self.assertEqual(len(mapping), MAX_TRAVELERS_PER_SANDBOX)

    def test_resolve_injections_only_with_real_values(self):
        self.registry.register(handle=CARD["handle"], name=CARD["name"], id_card=CARD["idCard"], phone=CARD["phone"], allowed_hosts=CARD["allowedHosts"], passport=CARD.get("passport"))
        sbx = sandbox()
        sbx["travelerPlaceholders"] = self.registry.issue_placeholders(sbx)
        injections = self.registry.resolve_injections(sbx)
        name_ph = sbx["travelerPlaceholders"]["traveller-li"]["name"]
        id_ph = sbx["travelerPlaceholders"]["traveller-li"]["idCard"]
        self.assertEqual(injections[name_ph]["value"], "李雷")
        self.assertEqual(injections[id_ph]["value"], CARD["idCard"])
        self.assertEqual(injections[name_ph]["hosts"], CARD["allowedHosts"])

    def test_resolve_skips_unknown_handle(self):
        self.registry.register(handle=CARD["handle"], name=CARD["name"], id_card=CARD["idCard"], phone=CARD["phone"], allowed_hosts=CARD["allowedHosts"], passport=CARD.get("passport"))
        sbx = sandbox()
        sbx["travelerPlaceholders"] = {"ghost": {"name": "{{SD_TRV_x}}", "idCard": "{{SD_TRV_y}}"}}
        self.assertEqual(self.registry.resolve_injections(sbx), {})


if __name__ == "__main__":
    unittest.main()
