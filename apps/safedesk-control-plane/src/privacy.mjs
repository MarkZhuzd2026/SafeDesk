import { createHash } from 'node:crypto';

/** Privacy curtain: per-sandbox pseudonymous identity + PII redaction (外卖隐私下单场景). */
const PHONE_RE = /(?<!\d)1[3-9]\d{9}(?!\d)/g;
const IDCARD_RE = /(?<!\d)\d{17}[\dXx](?!\d)/g;
const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
const CARD_RE = /(?<!\d)\d{13,19}(?!\d)/g;

const NAME_KEYS = new Set(['name', 'receiver', 'customer', 'buyer', 'consignee', '联系人', '收货人', '联系人姓名', '真实姓名']);
const PHONE_KEYS = new Set(['phone', 'mobile', 'tel', 'telephone', 'contactPhone', '联系电话', '手机号']);
const ADDRESS_KEYS = new Set(['address', 'addr', 'addrDetail', '收货地址', '详细地址', '门牌号']);
const CARD_KEYS = new Set(['cardNo', 'cardNumber', 'bankCard', '银行卡', '卡号']);
const SECRET_KEYS = new Set(['password', 'pwd', 'secret', 'cvv', 'cvc']);

const REDACTION_TAGS = {
  phone: '[*手机号*]',
  idcard: '[*证件号*]',
  card: '[*银行卡号*]',
  email: '[*邮箱*]',
};

function luhn(digits) {
  let total = 0;
  const parity = digits.length % 2;
  for (let index = 0; index < digits.length; index += 1) {
    let digit = Number(digits[index]);
    if (index % 2 === parity) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    total += digit;
  }
  return total % 10 === 0;
}

export function looksLikeBankCard(text) {
  const digits = String(text).replace(/\D/g, '');
  return digits.length >= 13 && digits.length <= 19 && luhn(digits);
}

export function aliasProfile(sandboxId) {
  const digest = createHash('sha256').update(String(sandboxId)).digest('hex');
  const phoneDigits = parseInt(digest.slice(0, 10), 16) % 1_0000_0000;
  const cabinet = String.fromCharCode('A'.charCodeAt(0) + (parseInt(digest.slice(10, 12), 16) % 26));
  const locker = (parseInt(digest.slice(12, 16), 16) % 90) + 10;
  return {
    aliasId: `sf-${digest.slice(16, 24)}`,
    name: `访客-${digest.slice(24, 28).toUpperCase()}`,
    phone: `138${String(phoneDigits).padStart(8, '0')}`,
    address: `SafeDesk 智能自提柜${cabinet}${locker}`,
    note: '牵线用沙箱别名；真实姓名/手机号/地址不出沙箱',
  };
}

export function redactPii(text) {
  const hits = [];
  let value = String(text);
  value = value.replace(PHONE_RE, () => { hits.push('phone'); return REDACTION_TAGS.phone; });
  value = value.replace(IDCARD_RE, () => { hits.push('idcard'); return REDACTION_TAGS.idcard; });
  value = value.replace(CARD_RE, (matched) => {
    if (looksLikeBankCard(matched)) {
      hits.push('card');
      return REDACTION_TAGS.card;
    }
    return matched;
  });
  value = value.replace(EMAIL_RE, () => { hits.push('email'); return REDACTION_TAGS.email; });
  return [value, hits];
}

export function anonymizeOrderFields(payload, alias) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return [payload, []];
  const result = { ...payload };
  const swaps = [];
  // Redaction runs first so the alias values themselves are never re-redacted.
  for (const [key, value] of Object.entries(result)) {
    if (typeof value === 'string') {
      const [redacted, hits] = redactPii(value);
      if (hits.length) {
        result[key] = redacted;
        swaps.push(...hits);
      }
    }
  }
  const swap = (keys, replacement, tag) => {
    for (const key of Object.keys(result)) {
      if (keys.has(key) && result[key]) {
        if (result[key] !== replacement) {
          result[key] = replacement;
          swaps.push(tag);
        }
      }
    }
  };
  swap(NAME_KEYS, alias.name, 'name→alias');
  swap(PHONE_KEYS, alias.phone, 'phone→alias');
  swap(ADDRESS_KEYS, alias.address, 'address→alias');
  for (const key of Object.keys(result)) {
    if (CARD_KEYS.has(key) || SECRET_KEYS.has(key)) {
      delete result[key];
      swaps.push('payment-fields-dropped');
    }
  }
  return [result, swaps];
}
