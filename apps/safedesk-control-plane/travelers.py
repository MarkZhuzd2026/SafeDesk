"""Traveler card registry (携程公务出行场景).

Real traveler identity (name / id card / passport / phone) lives host-side.
The sandbox only sees placeholders; the egress proxy resolves them to the real
values strictly for the allowlisted ticketing host. The platform can issue the
(legally mandatory) real-name ticket without ever seeing the employee's
account, history, or payment channel.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import threading
from pathlib import Path

HANDLE_RE = re.compile(r"^[\w-]{3,32}$")
IDCARD_RE = re.compile(r"^\d{17}[\dXx]$")
PHONE_RE = re.compile(r"^1[3-9]\d{9}$")
PASSPORT_RE = re.compile(r"^[A-Za-z0-9]{5,20}$")
TRAVELER_FIELDS = ("name", "idCard", "passport", "phone")
MAX_TRAVELERS_PER_SANDBOX = 4


class TravelerRegistry:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("[]\n", encoding="utf-8")
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def _load(self) -> list[dict]:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []

    def _save(self, items: list[dict]) -> None:
        self.path.write_text(json.dumps(items, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    @staticmethod
    def _masked(card: dict) -> dict:
        name = card.get("name", "")
        id_card = card.get("idCard", "")
        phone = card.get("phone", "")
        passport = card.get("passport") or None
        return {
            "handle": card["handle"],
            "name": f"{name[:1]}*" if len(name) > 1 else name,
            "idCard": f"{id_card[:4]}{'*' * 10}{id_card[-2:]}" if len(id_card) >= 8 else "****",
            "phone": f"{phone[:3]}****{phone[-4:]}" if len(phone) == 11 else "****",
            "passport": f"{passport[:3]}******" if passport else None,
            "allowedHosts": card.get("allowedHosts", []),
        }

    def register(self, handle: str, name: str, id_card: str, phone: str,
                 allowed_hosts: list[str], passport: str | None = None) -> dict:
        handle = (handle or "").strip()
        if not HANDLE_RE.match(handle):
            raise ValueError("handle 需为 3-32 位字母数字下划线")
        if not name or not name.strip():
            raise ValueError("姓名不能为空")
        if not IDCARD_RE.match(id_card or ""):
            raise ValueError("身份证号格式不正确")
        if not PHONE_RE.match(phone or ""):
            raise ValueError("手机号格式不正确")
        if passport is not None and passport and not PASSPORT_RE.match(passport):
            raise ValueError("护照号格式不正确")
        hosts = [str(host).strip().lower() for host in (allowed_hosts or []) if str(host).strip()]
        if not hosts:
            raise ValueError("必须声明至少一个允许的目的地主机")
        card = {
            "handle": handle, "name": name.strip(), "idCard": id_card, "phone": phone,
            "passport": passport or "", "allowedHosts": hosts,
        }
        with self._lock:
            items = [item for item in self._load() if item["handle"] != handle]
            items.append(card)
            self._save(items)
        return self._masked(card)

    def list_masked(self) -> list[dict]:
        with self._lock:
            return [self._masked(card) for card in self._load()]

    def get(self, handle: str) -> dict | None:
        """Internal lookup with real values. Host-side use only."""
        with self._lock:
            return next((card for card in self._load() if card["handle"] == handle), None)

    def remove(self, handle: str) -> bool:
        with self._lock:
            items = self._load()
            pruned = [card for card in items if card["handle"] != handle]
            if len(pruned) == len(items):
                return False
            self._save(pruned)
        return True

    def issue_placeholders(self, sandbox: dict) -> dict:
        """Per-sandbox traveler placeholders, e.g. {{SD_TRV_sbx-1_traveller-li_name_ab12cd34}}."""
        mapping = {}
        for handle in list(sandbox.get("travelerCards") or [])[:MAX_TRAVELERS_PER_SANDBOX]:
            slot = secrets.token_hex(4)
            mapping[handle] = {
                field: f"{{{{SD_TRV_{sandbox['id']}_{handle}_{field}_{slot}}}}}"
                for field in TRAVELER_FIELDS
            }
        return mapping

    def resolve_injections(self, sandbox: dict) -> dict:
        """Placeholder -> {value, hosts} map for the egress proxy (approve time)."""
        injections = {}
        for handle, fields in (sandbox.get("travelerPlaceholders") or {}).items():
            card = self.get(handle)
            if not card:
                continue
            for field, placeholder in fields.items():
                value = card.get(field)
                if value:
                    injections[placeholder] = {"value": value, "hosts": card.get("allowedHosts", [])}
        return injections
