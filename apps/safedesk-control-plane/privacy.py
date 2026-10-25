"""Privacy curtain: per-sandbox pseudonymous identity + PII redaction (外卖隐私下单场景).

The sandbox never holds the user's real name/phone/address/payment data.
Outbound traffic is scrubbed by the egress proxy; the platform only ever sees
the sandbox's deterministic alias, so neither orders nor payments can be tied
back to a real person by the provider.
"""
from __future__ import annotations

import hashlib
import re

PHONE_RE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")
IDCARD_RE = re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
CARD_RE = re.compile(r"(?<!\d)\d{13,19}(?!\d)")
NAME_KEYS = {"name", "receiver", "customer", "buyer", "consignee", "联系人", "收货人", "联系人姓名", "真实姓名"}
PHONE_KEYS = {"phone", "mobile", "tel", "telephone", "contactPhone", "联系电话", "手机号"}
ADDRESS_KEYS = {"address", "addr", "addrDetail", "收货地址", "详细地址", "门牌号"}
CARD_KEYS = {"cardNo", "cardNumber", "bankCard", "银行卡", "卡号"}
SECRET_KEYS = {"password", "pwd", "secret", "cvv", "cvc"}

REDACTION_TAGS = {
    "phone": "[*手机号*]",
    "idcard": "[*证件号*]",
    "card": "[*银行卡号*]",
    "email": "[*邮箱*]",
}


def _luhn(digits: str) -> bool:
    total = 0
    parity = len(digits) % 2
    for index, char in enumerate(digits):
        digit = int(char)
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def looks_like_bank_card(text: str) -> bool:
    digits = re.sub(r"\D", "", text)
    return 13 <= len(digits) <= 19 and _luhn(digits)


def alias_profile(sandbox_id: str) -> dict:
    """Deterministic per-sandbox pseudonymous identity; stable across resume."""
    digest = hashlib.sha256(str(sandbox_id).encode("utf-8")).hexdigest()
    phone_digits = int(digest[:10], 16) % 10_000_0000
    cabinet = chr(ord("A") + int(digest[10:12], 16) % 26)
    locker = int(digest[12:16], 16) % 90 + 10
    return {
        "aliasId": f"sf-{digest[16:24]}",
        "name": f"访客-{digest[24:28].upper()}",
        "phone": f"138{phone_digits:08d}",
        "address": f"SafeDesk 智能自提柜{cabinet}{locker}",
        "note": "牵线用沙箱别名；真实姓名/手机号/地址不出沙箱",
    }


def redact_pii(text: str) -> tuple[str, list[str]]:
    """Replace PII patterns in free text. Returns (redacted_text, hit_tags)."""
    hits: list[str] = []

    def phone_sub(match):
        hits.append("phone")
        return REDACTION_TAGS["phone"]

    def idcard_sub(match):
        hits.append("idcard")
        return REDACTION_TAGS["idcard"]

    def card_sub(match):
        digits = match.group(0)
        if looks_like_bank_card(digits):
            hits.append("card")
            return REDACTION_TAGS["card"]
        return digits

    def email_sub(match):
        hits.append("email")
        return REDACTION_TAGS["email"]

    value = PHONE_RE.sub(phone_sub, text)
    value = IDCARD_RE.sub(idcard_sub, value)
    value = CARD_RE.sub(card_sub, value)
    value = EMAIL_RE.sub(email_sub, value)
    return value, hits


def anonymize_order_fields(payload: dict, alias: dict) -> tuple[dict, list[str]]:
    """Rewrite identity fields of an order-like dict to the sandbox alias.
    Returns (new_payload, swap_tags). Redaction runs first so the alias
    values themselves are never re-redacted."""
    if not isinstance(payload, dict):
        return payload, []
    result = dict(payload)
    swaps: list[str] = []
    for key, value in result.items():
        if isinstance(value, str):
            redacted, hits = redact_pii(value)
            if hits:
                result[key] = redacted
                swaps.extend(hits)

    def swap(keys: set[str], replacement: str, tag: str) -> None:
        for key in list(result.keys()):
            if key in keys and result.get(key):
                if result[key] != replacement:
                    result[key] = replacement
                    swaps.append(tag)

    swap(NAME_KEYS, alias["name"], "name→alias")
    swap(PHONE_KEYS, alias["phone"], "phone→alias")
    swap(ADDRESS_KEYS, alias["address"], "address→alias")
    for key in list(result.keys()):
        if key in CARD_KEYS or key in SECRET_KEYS:
            result.pop(key, None)
            swaps.append("payment-fields-dropped")
    return result, swaps
