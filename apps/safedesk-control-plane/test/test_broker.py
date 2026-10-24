"""Tests for the host credential broker (REQ-BR-001..011, 013)."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from broker import CredentialBroker, MAX_CREDENTIALS_PER_SANDBOX, PLACEHOLDER_PREFIX  # noqa: E402


def sandbox(tmp_id: str = "sbx-broker01", **overrides) -> dict:
    item = {"id": tmp_id, "credentials": ["github-read"], "status": "running"}
    item.update(overrides)
    return item


class CredentialBrokerTest(unittest.TestCase):
    def setUp(self):
        suffix = next(tempfile._get_candidate_names())
        self.dir = Path(tempfile.gettempdir()) / f"safedesk-broker-{suffix}"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.broker = CredentialBroker(self.dir / "credentials.json")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_put_masks_value_and_persists(self):
        entry = self.broker.put("github-read", "ghp_secretvalue123456", ["api.github.com"])
        self.assertEqual(entry["masked"], "ghp_****")
        self.assertNotIn("ghp_secretvalue123456", entry["masked"])
        reloaded = CredentialBroker(self.dir / "credentials.json")
        listed = reloaded.list_masked()
        self.assertEqual(listed[0]["masked"], "ghp_****")
        mode = (self.dir / "credentials.json").stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_short_masks(self):
        self.assertEqual(self.broker._mask("abc"), "****")
        self.assertEqual(self.broker._mask(""), "****")

    def test_put_requires_host_allowlist(self):
        with self.assertRaises(ValueError):
            self.broker.put("github-read", "secret", [])

    def test_placeholders_are_unique_per_sandbox(self):
        first = self.broker.issue_placeholders(sandbox("sbx-a1"))
        second = self.broker.issue_placeholders(sandbox("sbx-a1"))
        self.assertTrue(first["github-read"].startswith(PLACEHOLDER_PREFIX))
        self.assertNotEqual(first["github-read"], second["github-read"])

    def test_placeholders_respect_quota(self):
        names = [f"cred-{idx}" for idx in range(MAX_CREDENTIALS_PER_SANDBOX + 4)]
        mapping = self.broker.issue_placeholders(sandbox(credentials=names))
        self.assertEqual(len(mapping), MAX_CREDENTIALS_PER_SANDBOX)

    def test_resolve_returns_value_for_allowed_host(self):
        self.broker.put("github-read", "ghp_secretvalue123456", ["api.github.com"])
        value = self.broker.resolve(sandbox(), "github-read", "api.github.com")
        self.assertEqual(value, "ghp_secretvalue123456")

    def test_resolve_denies_unlisted_host(self):
        self.broker.put("github-read", "ghp_secretvalue123456", ["api.github.com"])
        self.assertIsNone(self.broker.resolve(sandbox(), "github-read", "evil.example.com"))

    def test_resolve_denies_when_paused_or_terminated(self):
        self.broker.put("github-read", "ghp_secretvalue123456", ["api.github.com"])
        self.assertIsNone(self.broker.resolve(sandbox(status="paused"), "github-read", "api.github.com"))
        self.assertIsNone(self.broker.resolve(sandbox(status="terminated"), "github-read", "api.github.com"))

    def test_resolve_denies_ungranted_capability(self):
        self.broker.put("github-read", "ghp_secretvalue123456", ["api.github.com"])
        self.assertIsNone(self.broker.resolve(sandbox(credentials=["other"]), "github-read", "api.github.com"))

    def test_wildcard_host_matching(self):
        self.assertTrue(CredentialBroker.host_allowed("api.example.com", ["*.example.com"]))
        self.assertTrue(CredentialBroker.host_allowed("example.com", ["*.example.com"]))
        self.assertFalse(CredentialBroker.host_allowed("notexample.com", ["*.example.com"]))

    def test_remove_and_rotate(self):
        self.broker.put("github-read", "ghp_secretvalue123456", ["api.github.com"])
        before = self.broker.get("github-read")["digest"]
        rotated = self.broker.rotate("github-read", "ghp_newsecret778899")
        self.assertEqual(rotated["masked"], "ghp_****")
        self.assertNotEqual(before, self.broker.get("github-read")["digest"])
        self.assertTrue(self.broker.remove("github-read"))
        self.assertFalse(self.broker.remove("github-read"))
        with self.assertRaises(ValueError):
            self.broker.rotate("github-read", "x")


if __name__ == "__main__":
    unittest.main()
