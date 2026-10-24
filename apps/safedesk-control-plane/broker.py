"""Host-side credential broker: placeholders in sandbox, real values never leave the host (REQ-BR-001..011, 013)."""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
from pathlib import Path

PLACEHOLDER_PREFIX = "{{SD_CRED_"
MAX_CREDENTIALS_PER_SANDBOX = 8


class CredentialBroker:
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
    def _mask(value: str) -> str:
        value = value or ""
        return f"{value[:4]}****" if len(value) > 4 else "****"

    @staticmethod
    def _digest(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def put(self, name: str, value: str, allowed_hosts: list[str]) -> dict:
        name = (name or "").strip()
        if not name or not value:
            raise ValueError("凭据名称与值不能为空")
        hosts = [str(host).strip().lower() for host in (allowed_hosts or []) if str(host).strip()]
        if not hosts:
            raise ValueError("必须声明至少一个允许的目的地主机")
        with self._lock:
            items = self._load()
            item = next((entry for entry in items if entry["name"] == name), None)
            if item is None:
                item = {"name": name}
                items.append(item)
            item["value"] = value
            item["allowedHosts"] = hosts
            item["digest"] = self._digest(value)
            self._save(items)
        return {"name": name, "allowedHosts": hosts, "masked": self._mask(value)}

    def list_masked(self) -> list[dict]:
        with self._lock:
            return [
                {"name": item["name"], "allowedHosts": item.get("allowedHosts", []), "masked": self._mask(item.get("value", ""))}
                for item in self._load()
            ]

    def get(self, name: str) -> dict | None:
        """Internal lookup with the real value. Host-side use only."""
        with self._lock:
            return next((item for item in self._load() if item["name"] == name), None)

    def remove(self, name: str) -> bool:
        with self._lock:
            items = self._load()
            pruned = [item for item in items if item["name"] != name]
            if len(pruned) == len(items):
                return False
            self._save(pruned)
        return True

    def rotate(self, name: str, new_value: str) -> dict:
        item = self.get(name)
        if not item:
            raise ValueError("未知凭据")
        return self.put(name, new_value, item.get("allowedHosts", []))

    def issue_placeholders(self, sandbox: dict) -> dict:
        """Issue unguessable per-sandbox placeholders for granted capabilities (REQ-BR-003/011/013)."""
        mapping = {}
        for name in list(sandbox.get("credentials") or [])[:MAX_CREDENTIALS_PER_SANDBOX]:
            mapping[name] = f"{PLACEHOLDER_PREFIX}{sandbox['id']}_{secrets.token_hex(8)}}}"
        return mapping

    @staticmethod
    def host_allowed(target: str, allowed_hosts: list[str]) -> bool:
        target = (target or "").strip().lower().split(":")[0]
        for pattern in allowed_hosts or []:
            pattern = pattern.strip().lower()
            if pattern.startswith("*.") and (target == pattern[2:] or target.endswith(pattern[1:])):
                return True
            if pattern == target:
                return True
        return False

    def resolve(self, sandbox: dict, capability: str, destination_host: str) -> str | None:
        """Return the secret only when the sandbox is running, the capability is granted,
        and the destination is allowlisted (REQ-BR-004/005/006)."""
        if sandbox.get("status") != "running":
            return None
        if capability not in list(sandbox.get("credentials") or []):
            return None
        item = self.get(capability)
        if not item:
            return None
        if not self.host_allowed(destination_host, item.get("allowedHosts", [])):
            return None
        return item.get("value")
