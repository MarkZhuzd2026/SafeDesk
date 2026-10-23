import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { createServer as createNetServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

function freePort() {
  return new Promise((resolve, reject) => {
    const probe = createNetServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });
}

let port;
let base;
let dataDir;
let child;

async function waitForServer() {
  for (let i = 0; i < 50; i += 1) {
    try {
      const response = await fetch(`${base}/api/auth/config`);
      if (response.ok) return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error('auth server did not start');
}

async function request(path, { method = 'GET', body, token } = {}) {
  const headers = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (token) headers.Authorization = `Bearer ${token}`;
  const response = await fetch(`${base}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { response, data: await response.json() };
}

test.before(async () => {
  port = await freePort();
  base = `http://127.0.0.1:${port}`;
  dataDir = await mkdtemp(join(tmpdir(), 'safedesk-auth-'));
  child = spawn(process.execPath, ['server.mjs'], {
    cwd: new URL('..', import.meta.url),
    env: {
      ...process.env,
      PORT: String(port),
      SAFEDESK_DATA_DIR: dataDir,
      SAFEDESK_DATA_FILE: join(dataDir, 'sandboxes.json'),
      SAFEDESK_AUTH: '1',
      SAFEDESK_DEMO: '1',
      SAFEDESK_ADMIN_USERNAME: 'admin',
      SAFEDESK_ADMIN_PASSWORD: 'SafeDesk@Admin',
    },
    stdio: 'ignore',
  });
  await waitForServer();
});

test.after(async () => {
  child.kill();
  await rm(dataDir, { recursive: true, force: true });
});

test('protected APIs require a session', async () => {
  const { response } = await request('/api/bootstrap');
  assert.equal(response.status, 401);
});

test('admin account can sign in and approve sandboxes', async () => {
  const login = await request('/api/auth/admin/login', { method: 'POST', body: { username: 'admin', password: 'SafeDesk@Admin' } });
  assert.equal(login.response.status, 200);
  assert.equal(login.data.user.role, 'admin');
  const token = login.data.token;

  const created = await request('/api/sandboxes', {
    method: 'POST',
    token,
    body: { name: 'admin-box', agent: 'codex', policyId: 'review', workspace: '/tmp/admin' },
  });
  assert.equal(created.response.status, 201);
  const approved = await request(`/api/sandboxes/${created.data.sandbox.id}/approve`, { method: 'POST', token });
  assert.equal(approved.response.status, 200);
  assert.equal(approved.data.sandbox.status, 'running');
});

test('phone OTP login is isolated from other users and cannot approve', async () => {
  const send = await request('/api/auth/phone/send', { method: 'POST', body: { phone: '13800138000' } });
  assert.equal(send.response.status, 200);
  assert.match(send.data.demoCode, /^\d{6}$/);
  const verify = await request('/api/auth/phone/verify', { method: 'POST', body: { phone: '13800138000', token: send.data.demoCode } });
  assert.equal(verify.response.status, 200);
  assert.equal(verify.data.user.role, 'user');
  const userToken = verify.data.token;

  const created = await request('/api/sandboxes', {
    method: 'POST',
    token: userToken,
    body: { name: 'user-box', agent: 'dsh', policyId: 'balanced', workspace: '/tmp/user' },
  });
  assert.equal(created.response.status, 201);

  const forbidden = await request(`/api/sandboxes/${created.data.sandbox.id}/approve`, { method: 'POST', token: userToken });
  assert.equal(forbidden.response.status, 403);

  const events = await request('/api/events', { token: userToken });
  assert.equal(events.response.status, 403);

  const otherSend = await request('/api/auth/phone/send', { method: 'POST', body: { phone: '13900139000' } });
  const other = await request('/api/auth/phone/verify', { method: 'POST', body: { phone: '13900139000', token: otherSend.data.demoCode } });
  const otherView = await request('/api/sandboxes', { token: other.data.token });
  assert.equal(otherView.response.status, 200);
  assert.equal(otherView.data.sandboxes.some((item) => item.id === created.data.sandbox.id), false);
});

test('rejects invalid mainland phone numbers before sending OTP', async () => {
  const { response, data } = await request('/api/auth/phone/send', { method: 'POST', body: { phone: '1380013800' } });
  assert.equal(response.status, 400);
  assert.equal(data.error, '请输入正确的 11 位手机号');
});

test('wechat QR ticket can be confirmed into a user session', async () => {
  const started = await request('/api/auth/wechat/start', { method: 'POST' });
  assert.equal(started.response.status, 200);
  const confirmed = await request('/api/auth/wechat/confirm', { method: 'POST', body: { ticket: started.data.ticket } });
  assert.equal(confirmed.response.status, 200);
  const polled = await request(`/api/auth/wechat/poll?ticket=${started.data.ticket}`);
  assert.equal(polled.data.status, 'confirmed');
  assert.equal(polled.data.user.provider, 'wechat');
  assert.equal(polled.data.user.role, 'user');
});
