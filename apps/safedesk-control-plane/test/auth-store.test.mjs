import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuthStore } from '../src/auth.mjs';

let dataDir;
let store;

test.before(async () => {
  dataDir = await mkdtemp(join(tmpdir(), 'safedesk-authstore-'));
  process.env.SAFEDESK_DEMO = '1';
  process.env.SAFEDESK_OTP_ECHO = '1';
  process.env.SAFEDESK_ADMIN_USERNAME = 'admin';
  process.env.SAFEDESK_ADMIN_PASSWORD = 'SafeDesk@Admin';
  process.env.SAFEDESK_ADMIN_PHONES = '13800000000';
  store = new AuthStore(dataDir);
  await store.ready;
});

test.after(async () => {
  await rm(dataDir, { recursive: true, force: true });
});

test('publicConfig advertises phone, wechat and admin login', () => {
  const config = store.publicConfig();
  assert.deepEqual(config.methods, ['phone', 'wechat', 'wecom', 'admin']);
  assert.equal(config.wechatMode, 'local-qr');
  assert.equal(config.wecomMode, 'local-qr');
  assert.equal(config.demo, true);
  assert.equal(config.adminUsername, 'admin');
  assert.equal(config.wecomReady, true);
});

test('ensureAdmin seeds a hashed admin account', async () => {
  const users = JSON.parse(await readFile(join(dataDir, 'users.json'), 'utf8'));
  const admin = users.find((item) => item.username === 'admin');
  assert.ok(admin);
  assert.equal(admin.role, 'admin');
  assert.ok(admin.passwordHash.includes('$'));
  assert.notEqual(admin.passwordHash, 'SafeDesk@Admin');
});

test('hashPassword and verifyPassword round-trip', () => {
  const stored = store.hashPassword('correct-horse');
  assert.equal(store.verifyPassword('correct-horse', stored), true);
  assert.equal(store.verifyPassword('wrong-battery', stored), false);
});

test('verifyPassword rejects malformed hashes', () => {
  assert.equal(store.verifyPassword('x', ''), false);
  assert.equal(store.verifyPassword('x', 'nosalt'), false);
});

test('publicUser strips the password hash', async () => {
  const admin = await store.userById('admin');
  const published = store.publicUser(admin);
  assert.equal(published.role, 'admin');
  assert.equal('passwordHash' in published, false);
});

test('publicUser returns null for missing users', () => {
  assert.equal(store.publicUser(null), null);
});

test('loginAdmin succeeds with the seeded password', async () => {
  const session = await store.loginAdmin('admin', 'SafeDesk@Admin');
  assert.ok(session.token);
  assert.equal(session.user.role, 'admin');
  assert.ok(Date.parse(session.expiresAt) > Date.now());
});

test('loginAdmin rejects a wrong password', async () => {
  await assert.rejects(() => store.loginAdmin('admin', 'wrong'), { statusCode: 400 });
});

test('loginAdmin rejects an unknown username', async () => {
  await assert.rejects(() => store.loginAdmin('root', 'SafeDesk@Admin'), { statusCode: 400 });
});

test('sessionUser resolves a live token and ignores a bogus one', async () => {
  const session = await store.loginAdmin('admin', 'SafeDesk@Admin');
  const user = await store.sessionUser(session.token);
  assert.equal(user.id, 'admin');
  assert.equal(await store.sessionUser('not-a-token'), null);
  assert.equal(await store.sessionUser(null), null);
});

test('revoke invalidates a session token', async () => {
  const session = await store.loginAdmin('admin', 'SafeDesk@Admin');
  await store.revoke(session.token);
  assert.equal(await store.sessionUser(session.token), null);
});

test('revoke is a no-op for a missing token', async () => {
  await store.revoke(null);
  await store.revoke('missing');
});

test('sendPhoneOtp rejects a non-mainland number', () => {
  assert.throws(() => store.sendPhoneOtp('1380013800'), { statusCode: 400 });
  assert.throws(() => store.sendPhoneOtp('23800138000'), { statusCode: 400 });
  assert.throws(() => store.sendPhoneOtp(''), { statusCode: 400 });
});

test('sendPhoneOtp echoes a six-digit demo code', () => {
  const sent = store.sendPhoneOtp('13900000001');
  assert.equal(sent.ok, true);
  assert.equal(sent.ttlSeconds, 300);
  assert.match(sent.demoCode, /^\d{6}$/);
  assert.ok(sent.verificationId);
});

test('sendPhoneOtp rate-limits resend within 60 seconds', () => {
  store.sendPhoneOtp('13900000002');
  assert.throws(() => store.sendPhoneOtp('13900000002'), { statusCode: 400, message: /过于频繁/ });
});

test('verifyPhoneOtp rejects before a code is sent', async () => {
  await assert.rejects(() => store.verifyPhoneOtp('13900000003', '000000'), { statusCode: 400 });
});

test('verifyPhoneOtp rejects an incorrect code', async () => {
  store.sendPhoneOtp('13900000004');
  await assert.rejects(() => store.verifyPhoneOtp('13900000004', '000000'), { statusCode: 400, message: /不正确/ });
});

test('verifyPhoneOtp locks out after too many failures', async () => {
  const phone = '13900000005';
  store.sendPhoneOtp(phone);
  for (let i = 0; i < 5; i += 1) {
    try { await store.verifyPhoneOtp(phone, '000000'); } catch {}
  }
  await assert.rejects(() => store.verifyPhoneOtp(phone, '000000'), { message: /次数过多/ });
});

test('verifyPhoneOtp creates a user session and masks the phone', async () => {
  const phone = '13900000006';
  const sent = store.sendPhoneOtp(phone);
  const session = await store.verifyPhoneOtp(phone, sent.demoCode);
  assert.equal(session.user.role, 'user');
  assert.equal(session.user.provider, 'phone');
  assert.equal(session.user.displayName, '139****0006');
  assert.ok(session.token);
});

test('verifyPhoneOtp promotes configured admin phones', async () => {
  const phone = '13800000000';
  store.otp.delete(phone);
  const sent = store.sendPhoneOtp(phone);
  const session = await store.verifyPhoneOtp(phone, sent.demoCode);
  assert.equal(session.user.role, 'admin');
});

test('verifyPhoneOtp rejects an expired code', async () => {
  const phone = '13900000007';
  store.sendPhoneOtp(phone);
  const pending = store.otp.get(phone);
  pending.expiresAt = new Date(Date.now() - 1000).toISOString();
  await assert.rejects(() => store.verifyPhoneOtp(phone, pending.code), { message: /过期/ });
});

test('startWechat issues a pending ticket', () => {
  const started = store.startWechat();
  assert.ok(started.ticket);
  assert.equal(started.expiresIn, 180);
});

test('pollWechat reports pending then confirmed then expired', async () => {
  const started = store.startWechat();
  assert.equal((await store.pollWechat(started.ticket)).status, 'pending');
  await store.confirmWechat(started.ticket);
  const confirmed = await store.pollWechat(started.ticket);
  assert.equal(confirmed.status, 'confirmed');
  assert.equal(confirmed.user.provider, 'wechat');
  assert.equal(confirmed.user.role, 'user');
  assert.equal((await store.pollWechat(started.ticket)).status, 'expired');
});

test('pollWechat reports expired for an unknown ticket', async () => {
  assert.equal((await store.pollWechat('missing')).status, 'expired');
});

test('pollWechat reports expired for a timed-out ticket', async () => {
  const started = store.startWechat();
  store.wechat.get(started.ticket).expiresAt = new Date(Date.now() - 1000).toISOString();
  assert.equal((await store.pollWechat(started.ticket)).status, 'expired');
});

test('confirmWechat rejects a missing ticket', async () => {
  await assert.rejects(() => store.confirmWechat('missing'), { statusCode: 400 });
});

test('confirmWechat rejects an expired ticket', async () => {
  const started = store.startWechat();
  store.wechat.get(started.ticket).expiresAt = new Date(Date.now() - 1000).toISOString();
  await assert.rejects(() => store.confirmWechat(started.ticket), { message: /过期/ });
});

test('startWecom issues a pending ticket', () => {
  const started = store.startWecom();
  assert.ok(started.ticket);
  assert.equal(started.expiresIn, 180);
  assert.match(started.confirmHint, /企业微信/);
});

test('pollWecom reports pending then confirmed then expired', async () => {
  const started = store.startWecom();
  assert.equal((await store.pollWecom(started.ticket)).status, 'pending');
  await store.confirmWecom(started.ticket);
  const confirmed = await store.pollWecom(started.ticket);
  assert.equal(confirmed.status, 'confirmed');
  assert.equal(confirmed.user.provider, 'wecom');
  assert.equal(confirmed.user.role, 'user');
  assert.equal(confirmed.user.displayName, '企业微信用户');
  assert.equal((await store.pollWecom(started.ticket)).status, 'expired');
});

test('pollWecom reports expired for an unknown ticket', async () => {
  assert.equal((await store.pollWecom('missing')).status, 'expired');
});

test('confirmWecom rejects a missing ticket', async () => {
  await assert.rejects(() => store.confirmWecom('missing'), { statusCode: 400 });
});

test('confirmWecom rejects an expired ticket', async () => {
  const started = store.startWecom();
  store.wecom.get(started.ticket).expiresAt = new Date(Date.now() - 1000).toISOString();
  await assert.rejects(() => store.confirmWecom(started.ticket), { message: /过期/ });
});

test('upsertUser updates an existing record in place', async () => {
  const first = await store.upsertUser({ id: 'u-upsert', role: 'user', displayName: 'A' });
  const second = await store.upsertUser({ id: 'u-upsert', role: 'user', displayName: 'B' });
  assert.equal(first.id, second.id);
  assert.equal((await store.userById('u-upsert')).displayName, 'B');
});
