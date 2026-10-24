"""Tests for the append-only audit log (REQ-AU-001/002/003)."""
from __future__ import annotations

import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from audit import AuditLog  # noqa: E402


def event(idx: int, at: str = "2026-10-24T10:00:00.000Z", **overrides) -> dict:
    item = {"id": f"evt-{idx}", "level": "info", "action": "测试事件", "detail": f"detail-{idx}", "actor": "admin", "at": at}
    item.update(overrides)
    return item


class AuditLogTest(unittest.TestCase):
    def setUp(self):
        suffix = next(tempfile._get_candidate_names())
        self.dir = Path(tempfile.gettempdir()) / f"safedesk-audit-{suffix}"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.log = AuditLog(self.dir / "audit.jsonl", retention_days=30)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_append_and_load_round_trip(self):
        self.log.append(event(1))
        self.log.append(event(2))
        loaded = self.log.load()
        self.assertEqual([item["id"] for item in loaded], ["evt-1", "evt-2"])

    def test_file_is_private(self):
        self.log.append(event(1))
        mode = self.log.path.stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_prune_drops_old_events(self):
        now = datetime.now(timezone.utc)
        old = (now - timedelta(days=40)).isoformat().replace("+00:00", "Z")
        fresh = (now - timedelta(days=1)).isoformat().replace("+00:00", "Z")
        self.log.append(event(1, at=old))
        self.log.append(event(2, at=fresh))
        removed = self.log.prune(now=now)
        self.assertEqual(removed, 1)
        self.assertEqual([item["id"] for item in self.log.load()], ["evt-2"])

    def test_query_newest_first_with_filters(self):
        for idx in range(5):
            level = "block" if idx % 2 == 0 else "allow"
            self.log.append(event(idx, level=level))
        result = self.log.query(level="block")
        self.assertEqual([item["id"] for item in result], ["evt-4", "evt-2", "evt-0"])

    def test_query_limit_and_offset(self):
        for idx in range(10):
            self.log.append(event(idx))
        page1 = self.log.query(limit=3)
        page2 = self.log.query(limit=3, offset=3)
        self.assertEqual(len(page1), 3)
        self.assertEqual(len(page2), 3)
        self.assertNotEqual(page1[0]["id"], page2[0]["id"])

    def test_query_keyword_matches_detail(self):
        self.log.append(event(1, detail="凭据 github-read 代签"))
        self.log.append(event(2, detail="外联拦截"))
        result = self.log.query(keyword="github")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["id"], "evt-1")


if __name__ == "__main__":
    unittest.main()
