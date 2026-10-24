"""Append-only audit log with pagination and retention pruning (REQ-AU-001/002/003)."""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path


class AuditLog:
    def __init__(self, path: Path, retention_days: int = 30):
        self.path = Path(path)
        self.retention_days = int(retention_days or 30)
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("", encoding="utf-8")
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def append(self, event: dict) -> None:
        line = json.dumps(event, ensure_ascii=False)
        with self._lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")

    def load(self) -> list[dict]:
        with self._lock:
            if not self.path.exists():
                return []
            events = []
            for line in self.path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            return events

    def prune(self, now: datetime | None = None) -> int:
        """Drop events older than retention_days. Returns removed count."""
        now = now or datetime.now(timezone.utc)
        cutoff = now.timestamp() - self.retention_days * 86400
        kept, removed = [], 0
        for event in self.load():
            keep = True
            try:
                at = datetime.fromisoformat(str(event.get("at", "")).replace("Z", "+00:00"))
                keep = at.timestamp() >= cutoff
            except ValueError:
                pass
            if keep:
                kept.append(event)
            else:
                removed += 1
        if removed:
            body = "\n".join(json.dumps(item, ensure_ascii=False) for item in kept)
            with self._lock:
                self.path.write_text(body + ("\n" if kept else ""), encoding="utf-8")
        return removed

    def query(self, keyword: str = "", level: str = "", action: str = "",
              since: str | None = None, limit: int | None = None, offset: int = 0) -> list[dict]:
        events = self.load()
        events.reverse()  # newest first
        keyword = (keyword or "").strip().lower()
        result = []
        for event in events:
            if keyword and keyword not in " ".join(
                str(event.get(field, "")) for field in ("action", "detail", "actor")
            ).lower():
                continue
            if level and event.get("level") != level:
                continue
            if action and event.get("action") != action:
                continue
            if since and str(event.get("at", "")) < str(since):
                continue
            result.append(event)
        if offset:
            result = result[offset:]
        if limit is not None:
            result = result[: max(0, int(limit))]
        return result
