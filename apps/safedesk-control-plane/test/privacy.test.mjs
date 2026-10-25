import test from 'node:test';
import assert from 'node:assert/strict';

import { aliasProfile, anonymizeOrderFields, looksLikeBankCard, redactPii } from '../src/privacy.mjs';

const REAL_PHONE = '13812345678';
const REAL_ID = '110101199003071234';
const REAL_CARD = '4111111111111111';
const REAL_EMAIL = 'wuyeliang@example.com';
const REAL_NAME = '张伟';

test('alias profile is deterministic per sandbox and distinct between sandboxes', () => {
  const first = aliasProfile('sbx-abc1234');
  assert.deepEqual(first, aliasProfile('sbx-abc1234'));
  assert.notEqual(aliasProfile('sbx-a1').aliasId, aliasProfile('sbx-a2').aliasId);
});

test('alias shape and anonymity', () => {
  const alias = aliasProfile('sbx-abc1234');
  assert.match(alias.aliasId, /^sf-[0-9a-f]{8}$/);
  assert.ok(alias.name.startsWith('访客-'));
  assert.match(alias.phone, /^138\d{8}$/);
  assert.match(alias.address, /自提柜/);
  assert.ok(!alias.phone.includes(REAL_PHONE));
  assert.ok(!alias.name.includes(REAL_NAME));
});

test('phone redacted', () => {
  const [text, hits] = redactPii(`收货人电话 ${REAL_PHONE} 勿扰`);
  assert.ok(!text.includes(REAL_PHONE));
  assert.ok(hits.includes('phone'));
});

test('idcard redacted', () => {
  const [text, hits] = redactPii(`实名认证 ${REAL_ID}`);
  assert.ok(!text.includes(REAL_ID));
  assert.ok(hits.includes('idcard'));
});

test('bank card redacted when luhn passes', () => {
  const [text, hits] = redactPii(`卡号 ${REAL_CARD}`);
  assert.ok(!text.includes(REAL_CARD));
  assert.ok(hits.includes('card'));
});

test('non-card long numbers kept', () => {
  const [text, hits] = redactPii('订单号 1234567890123');
  assert.ok(text.includes('1234567890123'));
  assert.ok(!hits.includes('card'));
});

test('luhn helper', () => {
  assert.ok(looksLikeBankCard(REAL_CARD));
  assert.ok(!looksLikeBankCard('1234567890123'));
});

test('email redacted', () => {
  const [text, hits] = redactPii(`联系 ${REAL_EMAIL}`);
  assert.ok(!text.includes(REAL_EMAIL));
  assert.ok(hits.includes('email'));
});

test('clean text passes through', () => {
  const [text, hits] = redactPii('黄焖鸡米饭大份微辣');
  assert.equal(text, '黄焖鸡米饭大份微辣');
  assert.deepEqual(hits, []);
});

test('identity fields swapped to alias, items preserved', () => {
  const alias = aliasProfile('sbx-takeout1');
  const payload = {
    name: REAL_NAME,
    phone: REAL_PHONE,
    address: '滨江路88号春天花园3栋1201',
    items: [{ name: '黄焖鸡米饭', count: 1 }],
    note: `电话 ${REAL_PHONE} 联系`,
  };
  const [result, swaps] = anonymizeOrderFields(payload, alias);
  assert.equal(result.name, alias.name);
  assert.equal(result.phone, alias.phone);
  assert.equal(result.address, alias.address);
  assert.deepEqual(result.items, payload.items);
  assert.ok(!result.note.includes(REAL_PHONE));
  assert.ok(swaps.includes('name→alias'));
  assert.ok(swaps.includes('phone→alias'));
  assert.ok(swaps.includes('address→alias'));
});

test('payment fields dropped', () => {
  const [result, swaps] = anonymizeOrderFields({ name: 'x', cardNo: REAL_CARD, cvv: '123' }, aliasProfile('sbx-takeout1'));
  assert.ok(!('cardNo' in result));
  assert.ok(!('cvv' in result));
  assert.ok(swaps.includes('payment-fields-dropped'));
});
