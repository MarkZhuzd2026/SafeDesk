"""Local authentication for SafeDesk when cloud login is not bound.

Supports phone OTP, WeChat QR, WeCom QR, and a seeded admin account.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

PHONE_RE = re.compile(r"^1\d{10}$")
PBKDF2_ROUNDS = 120_000
SESSION_DAYS = 7
OTP_TTL_SECONDS = 300
OTP_RESEND_SECONDS = 60
WECHAT_TTL_SECONDS = 180
WECOM_TTL_SECONDS = 180
DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "SafeDesk@Admin"
MIN_PASSWORD_LENGTH = 8

LOCK = threading.Lock()


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class AuthStore:
    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.users_file = data_dir / "users.json"
        self.sessions_file = data_dir / "sessions.json"
        self.otp: dict[str, dict] = {}
        self.wechat: dict[str, dict] = {}
        self.wecom: dict[str, dict] = {}
        self.demo = os.getenv("SAFEDESK_DEMO", "1") != "0"
        self.otp_echo = os.getenv("SAFEDESK_OTP_ECHO", "0") == "1" or self.demo
        self.admin_username = os.getenv("SAFEDESK_ADMIN_USERNAME", DEFAULT_ADMIN_USERNAME)
        self.admin_password = os.getenv("SAFEDESK_ADMIN_PASSWORD", DEFAULT_ADMIN_PASSWORD)
        self.admin_phones = {
            item.strip()
            for item in os.getenv("SAFEDESK_ADMIN_PHONES", "").split(",")
            if item.strip()
        }
        data_dir.mkdir(parents=True, exist_ok=True)
        self._ensure_admin()

    def public_config(self) -> dict:
        return {
            "methods": ["phone", "wechat", "wecom", "admin"],
            "wechatMode": "local-qr",
            "wecomMode": "local-qr",
            "demo": self.demo,
            "adminUsername": self.admin_username,
            "wecomReady": True,
            "passwordMinLength": MIN_PASSWORD_LENGTH,
        }

    def _load(self, path: Path, default):
        if not path.exists():
            path.write_text(json.dumps(default, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return json.loads(path.read_text(encoding="utf-8"))

    def _save(self, path: Path, payload) -> None:
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    def users(self) -> list[dict]:
        return self._load(self.users_file, [])

    def sessions(self) -> list[dict]:
        return self._load(self.sessions_file, [])

    def save_users(self, users: list[dict]) -> None:
        self._save(self.users_file, users)

    def save_sessions(self, sessions: list[dict]) -> None:
        self._save(self.sessions_file, sessions)

    def hash_password(self, password: str, salt: str | None = None) -> str:
        salt = salt or secrets.token_hex(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), PBKDF2_ROUNDS).hex()
        return f"{salt}${digest}"

    def verify_password(self, password: str, stored: str) -> bool:
        try:
            salt, digest = stored.split("$", 1)
        except ValueError:
            return False
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), PBKDF2_ROUNDS).hex()
        return hmac.compare_digest(candidate, digest)

    def public_user(self, user: dict | None) -> dict | None:
        if not user:
            return None
        return {
            "id": user["id"],
            "role": user["role"],
            "provider": user.get("provider", "admin"),
            "displayName": user.get("displayName") or user.get("username") or "用户",
            "phone": user.get("phone"),
            "username": user.get("username"),
            "mustChangePassword": bool(user.get("mustChangePassword")),
            "canChangePassword": user.get("role") == "admin" and bool(user.get("passwordHash")),
        }

    def _ensure_admin(self) -> None:
        with LOCK:
            users = self.users()
            admin = next((item for item in users if item.get("username") == self.admin_username), None)
            if admin is None:
                users.append({
                    "id": "admin",
                    "username": self.admin_username,
                    "role": "admin",
                    "provider": "admin",
                    "displayName": "管理员",
                    "passwordHash": self.hash_password(self.admin_password),
                    "mustChangePassword": self.admin_password == DEFAULT_ADMIN_PASSWORD,
                    "createdAt": iso_now(),
                })
                self.save_users(users)
                return
            admin["role"] = "admin"
            admin["provider"] = "admin"
            admin.setdefault("mustChangePassword", self.verify_password(DEFAULT_ADMIN_PASSWORD, admin.get("passwordHash", "")))
            self.save_users(users)

    def _upsert_user(self, user: dict) -> dict:
        users = self.users()
        existing = next((item for item in users if item["id"] == user["id"]), None)
        if existing:
            existing.update(user)
            user = existing
        else:
            user.setdefault("createdAt", iso_now())
            users.append(user)
        self.save_users(users)
        return user

    def create_session(self, user: dict) -> dict:
        token = secrets.token_urlsafe(32)
        expires = datetime.now(timezone.utc) + timedelta(days=SESSION_DAYS)
        sessions = [item for item in self.sessions() if _parse_iso(item["expiresAt"]) > datetime.now(timezone.utc)]
        sessions.append({
            "token": token,
            "userId": user["id"],
            "role": user["role"],
            "createdAt": iso_now(),
            "expiresAt": expires.isoformat().replace("+00:00", "Z"),
        })
        self.save_sessions(sessions)
        return {"token": token, "expiresAt": expires.isoformat().replace("+00:00", "Z"), "user": self.public_user(user)}

    def user_by_id(self, user_id: str) -> dict | None:
        return next((item for item in self.users() if item["id"] == user_id), None)

    def session_user(self, token: str | None) -> dict | None:
        if not token:
            return None
        now = datetime.now(timezone.utc)
        sessions = self.sessions()
        record = next((item for item in sessions if item["token"] == token), None)
        if not record or _parse_iso(record["expiresAt"]) <= now:
            return None
        return self.user_by_id(record["userId"])

    def revoke(self, token: str | None) -> None:
        if not token:
            return
        self.save_sessions([item for item in self.sessions() if item["token"] != token])

    def send_phone_otp(self, phone: str) -> dict:
        if not PHONE_RE.match(phone):
            raise ValueError("请输入正确的 11 位手机号")
        now = datetime.now(timezone.utc)
        pending = self.otp.get(phone)
        if pending and _parse_iso(pending["sentAt"]) + timedelta(seconds=OTP_RESEND_SECONDS) > now:
            raise ValueError("验证码发送过于频繁，请稍后再试")
        code = f"{secrets.randbelow(1_000_000):06d}"
        self.otp[phone] = {
            "code": code,
            "verificationId": secrets.token_urlsafe(12),
            "sentAt": iso_now(),
            "expiresAt": (now + timedelta(seconds=OTP_TTL_SECONDS)).isoformat().replace("+00:00", "Z"),
            "attempts": 0,
        }
        result = {"ok": True, "verificationId": self.otp[phone]["verificationId"], "ttlSeconds": OTP_TTL_SECONDS}
        if self.otp_echo:
            result["demoCode"] = code
        return result

    def verify_phone_otp(self, phone: str, token: str) -> dict:
        if not PHONE_RE.match(phone):
            raise ValueError("请输入正确的 11 位手机号")
        pending = self.otp.get(phone)
        if not pending:
            raise ValueError("请先获取当前手机号的验证码")
        if _parse_iso(pending["expiresAt"]) <= datetime.now(timezone.utc):
            self.otp.pop(phone, None)
            raise ValueError("验证码已过期，请重新获取")
        pending["attempts"] += 1
        if pending["attempts"] > 5:
            self.otp.pop(phone, None)
            raise ValueError("验证码错误次数过多，请重新获取")
        if not hmac.compare_digest(str(token).strip(), pending["code"]):
            raise ValueError("验证码不正确")
        self.otp.pop(phone, None)
        role = "admin" if phone in self.admin_phones else "user"
        user = self._upsert_user({
            "id": f"phone-{phone}",
            "role": role,
            "provider": "phone",
            "phone": phone,
            "displayName": f"{phone[:3]}****{phone[-4:]}",
        })
        return self.create_session(user)

    def start_wechat(self) -> dict:
        ticket = secrets.token_urlsafe(16)
        self.wechat[ticket] = {
            "status": "pending",
            "createdAt": iso_now(),
            "expiresAt": (datetime.now(timezone.utc) + timedelta(seconds=WECHAT_TTL_SECONDS)).isoformat().replace("+00:00", "Z"),
        }
        return {"ticket": ticket, "expiresIn": WECHAT_TTL_SECONDS, "confirmHint": "本地演示：使用同一浏览器确认二维码"}

    def poll_wechat(self, ticket: str) -> dict:
        record = self.wechat.get(ticket)
        if not record:
            return {"status": "expired"}
        if _parse_iso(record["expiresAt"]) <= datetime.now(timezone.utc):
            self.wechat.pop(ticket, None)
            return {"status": "expired"}
        if record["status"] != "confirmed":
            return {"status": "pending"}
        session = record.get("session")
        self.wechat.pop(ticket, None)
        return {"status": "confirmed", **session}

    def confirm_wechat(self, ticket: str) -> dict:
        record = self.wechat.get(ticket)
        if not record:
            raise ValueError("二维码已失效，请刷新后重试")
        if _parse_iso(record["expiresAt"]) <= datetime.now(timezone.utc):
            self.wechat.pop(ticket, None)
            raise ValueError("二维码已过期，请刷新后重试")
        openid = f"wx-{ticket[:8]}"
        user = self._upsert_user({
            "id": f"wechat-{openid}",
            "role": "user",
            "provider": "wechat",
            "wechatOpenId": openid,
            "displayName": "微信用户",
        })
        session = self.create_session(user)
        record["status"] = "confirmed"
        record["session"] = session
        return {"ok": True}

    def start_wecom(self) -> dict:
        ticket = secrets.token_urlsafe(16)
        self.wecom[ticket] = {
            "status": "pending",
            "createdAt": iso_now(),
            "expiresAt": (datetime.now(timezone.utc) + timedelta(seconds=WECOM_TTL_SECONDS)).isoformat().replace("+00:00", "Z"),
        }
        return {
            "ticket": ticket,
            "expiresIn": WECOM_TTL_SECONDS,
            "confirmHint": "企业微信演示：同一浏览器确认本地工单后进入企业身份。不读取个人微信或企业通讯录。",
        }

    def poll_wecom(self, ticket: str) -> dict:
        record = self.wecom.get(ticket)
        if not record:
            return {"status": "expired"}
        if _parse_iso(record["expiresAt"]) <= datetime.now(timezone.utc):
            self.wecom.pop(ticket, None)
            return {"status": "expired"}
        if record["status"] != "confirmed":
            return {"status": "pending"}
        session = record.get("session")
        self.wecom.pop(ticket, None)
        return {"status": "confirmed", **session}

    def confirm_wecom(self, ticket: str) -> dict:
        record = self.wecom.get(ticket)
        if not record:
            raise ValueError("企业微信二维码已失效，请刷新后重试")
        if _parse_iso(record["expiresAt"]) <= datetime.now(timezone.utc):
            self.wecom.pop(ticket, None)
            raise ValueError("企业微信二维码已过期，请刷新后重试")
        member = f"member-{ticket[:8]}"
        user = self._upsert_user({
            "id": f"wecom-{member}",
            "role": "user",
            "provider": "wecom",
            "displayName": "企业微信用户",
        })
        session = self.create_session(user)
        record["status"] = "confirmed"
        record["session"] = session
        return {"ok": True}

    def login_admin(self, username: str, password: str) -> dict:
        user = next((item for item in self.users() if item.get("username") == username and item.get("role") == "admin"), None)
        if not user or not self.verify_password(password, user.get("passwordHash", "")):
            raise ValueError("管理员账号或密码不正确")
        return self.create_session(user)

    def _validate_new_password(self, password: str) -> str:
        value = str(password or "")
        if len(value) < MIN_PASSWORD_LENGTH:
            raise ValueError(f"新密码至少 {MIN_PASSWORD_LENGTH} 位")
        if value.strip() != value or " " in value:
            raise ValueError("新密码不能包含空格")
        if value == DEFAULT_ADMIN_PASSWORD:
            raise ValueError("请不要继续使用默认密码")
        return value

    def change_password(self, user: dict, current_password: str, new_password: str, keep_token: str | None = None) -> dict:
        if not user or user.get("role") != "admin" or not user.get("passwordHash"):
            raise ValueError("仅管理员账户可以修改密码")
        if not self.verify_password(str(current_password or ""), user.get("passwordHash", "")):
            raise ValueError("当前密码不正确")
        next_password = self._validate_new_password(new_password)
        if self.verify_password(next_password, user.get("passwordHash", "")):
            raise ValueError("新密码不能与当前密码相同")
        users = self.users()
        record = next((item for item in users if item["id"] == user["id"]), None)
        if not record:
            raise ValueError("未找到管理员账户")
        record["passwordHash"] = self.hash_password(next_password)
        record["mustChangePassword"] = False
        record["passwordChangedAt"] = iso_now()
        self.save_users(users)
        sessions = [item for item in self.sessions() if keep_token and item.get("token") == keep_token]
        self.save_sessions(sessions)
        return {"ok": True, "user": self.public_user(record)}
