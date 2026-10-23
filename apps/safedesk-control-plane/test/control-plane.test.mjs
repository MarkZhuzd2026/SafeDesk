import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
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
let dataFile;
let child;

async function waitForServer() {
  for (let i = 0; i < 50; i += 1) {
    try { const response = await fetch(`${base}/api/bootstrap`); if (response.ok) return; } catch {}
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error('server did not start');
}

async function postJson(path, body) {
  return fetch(`${base}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });
}

async function createSandbox(overrides = {}) {
  const response = await postJson('/api/sandboxes', {
    name: 'audit-run',
    agent: 'codex',
    policyId: 'review',
    workspace: '/tmp/project',
    credentials: ['github-read'],
    mcpServers: ['github'],
    ...overrides,
  });
  return { response, data: await response.json() };
}

test.before(async () => {
  port = await freePort();
  base = `http://127.0.0.1:${port}`;
  dataDir = await mkdtemp(join(tmpdir(), 'safedesk-test-'));
  dataFile = join(dataDir, 'sandboxes.json');
  child = spawn(process.execPath, ['server.mjs'], {
    cwd: new URL('..', import.meta.url),
    env: { ...process.env, PORT: String(port), SAFEDESK_DATA_FILE: dataFile },
    stdio: 'ignore',
  });
  await waitForServer();
});

test.after(async () => {
  child.kill();
  await rm(dataDir, { recursive: true, force: true });
});

test('GET /api/bootstrap returns policy catalog, agents and seeded security events', async () => {
  const response = await fetch(`${base}/api/bootstrap`);
  assert.equal(response.status, 200);
  const data = await response.json();
  assert.deepEqual(data.policies.map((p) => p.id).sort(), ['balanced', 'build', 'review']);
  assert.deepEqual(data.agents.map((a) => a.id).sort(), ['claude-code', 'codex', 'dsh']);
  assert.ok(Array.isArray(data.sandboxes));
  assert.ok(data.securityEvents.length >= 3);
  assert.ok(data.securityEvents.some((e) => e.level === 'block'));
});

test('creates a pending sandbox without accepting secrets', async () => {
  const { response, data } = await createSandbox();
  assert.equal(response.status, 201);
  assert.equal(data.sandbox.status, 'pending_approval');
  assert.equal(data.sandbox.id, data.manifest.id);
  assert.equal(data.manifest.credentialBroker.exposedValues, false);
  assert.equal(data.manifest.filesystem.mode, 'ro');
  assert.equal(data.manifest.runtime.network, 'disabled');
  assert.match(data.sandbox.id, /^sbx-[\w-]+$/);
});

test('rejects unknown policy, unknown agent and relative workspace path', async () => {
  for (const overrides of [
    { policyId: 'everything-allowed' },
    { agent: 'gpt-shell' },
    { workspace: 'relative/project' },
  ]) {
    const { response } = await createSandbox(overrides);
    assert.equal(response.status, 400, JSON.stringify(overrides));
  }
});

test('rejects a malformed JSON body with 400 instead of crashing', async () => {
  const response = await postJson('/api/sandboxes', '{not-json');
  assert.equal(response.status, 400);
  const data = await response.json();
  assert.match(data.error, /JSON/);
});

test('sanitizes sandbox names and falls back to a default when empty', async () => {
  const { data } = await createSandbox({ name: 'my <script> box 测试' });
  assert.equal(data.sandbox.name, 'my--script--box-测试');

  const fallback = await createSandbox({ name: '   ' });
  assert.equal(fallback.data.sandbox.name, 'agent-codex');
});

test('applies defaults and caps list lengths', async () => {
  const { response, data } = await postJson('/api/sandboxes', { workspace: '/tmp/defaults' }).then(async (r) => ({ response: r, data: await r.json() }));
  assert.equal(response.status, 201);
  assert.equal(data.sandbox.agent, 'claude-code');
  assert.equal(data.sandbox.policyId, 'balanced');
  assert.deepEqual(data.sandbox.packages, ['wasmer/bash@latest']);

  const many = await createSandbox({
    packages: Array.from({ length: 12 }, (_, i) => `pkg-${i}`),
    credentials: Array.from({ length: 12 }, (_, i) => `cred-${i}`),
    mcpServers: Array.from({ length: 15 }, (_, i) => `mcp-${i}`),
  });
  assert.equal(many.data.sandbox.packages.length, 8);
  assert.equal(many.data.sandbox.credentials.length, 8);
  assert.equal(many.data.sandbox.mcpServers.length, 12);
});

test('persists created sandboxes to the data file', async () => {
  const { data } = await createSandbox({ name: 'persisted' });
  const stored = JSON.parse(await readFile(dataFile, 'utf8'));
  assert.ok(stored.some((item) => item.id === data.sandbox.id));
});

test('approve transitions pending sandbox to running, and only once', async () => {
  const { data } = await createSandbox({ name: 'approve-me' });
  const id = data.sandbox.id;

  const approved = await postJson(`/api/sandboxes/${id}/approve`);
  assert.equal(approved.status, 200);
  const approvedData = await approved.json();
  assert.equal(approvedData.sandbox.status, 'running');
  assert.ok(approvedData.sandbox.startedAt);

  const again = await postJson(`/api/sandboxes/${id}/approve`);
  assert.equal(again.status, 409);
});

test('terminate transitions to terminated and blocks further lifecycle actions', async () => {
  const { data } = await createSandbox({ name: 'terminate-me' });
  const id = data.sandbox.id;

  const terminated = await postJson(`/api/sandboxes/${id}/terminate`);
  assert.equal(terminated.status, 200);
  const terminatedData = await terminated.json();
  assert.equal(terminatedData.sandbox.status, 'terminated');
  assert.ok(terminatedData.sandbox.terminatedAt);

  assert.equal((await postJson(`/api/sandboxes/${id}/terminate`)).status, 409);
  assert.equal((await postJson(`/api/sandboxes/${id}/approve`)).status, 409);
});

test('serves the launch manifest for an existing sandbox', async () => {
  const { data } = await createSandbox({ name: 'manifest-me', policyId: 'build' });
  const response = await fetch(`${base}/api/sandboxes/${data.sandbox.id}/manifest`);
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.manifest.id, data.sandbox.id);
  assert.equal(body.manifest.runtime.network, 'allowlist');
  assert.equal(body.manifest.filesystem.mode, 'ephemeral');
  assert.equal(body.manifest.credentialBroker.exposedValues, false);
});

test('returns 404 for unknown sandbox ids and 405 for wrong methods on actions', async () => {
  for (const action of ['approve', 'terminate', 'manifest']) {
    const response = await postJson(`/api/sandboxes/sbx-missing/${action}`);
    assert.equal(response.status, 404, action);
  }
  const missing = await fetch(`${base}/api/sandboxes/sbx-missing/manifest`);
  assert.equal(missing.status, 404);

  const { data } = await createSandbox({ name: 'method-check' });
  const wrongMethod = await fetch(`${base}/api/sandboxes/${data.sandbox.id}/approve`);
  assert.equal(wrongMethod.status, 405);
});

test('records lifecycle operations in the security event log', async () => {
  const { data } = await createSandbox({ name: 'eventful' });
  await postJson(`/api/sandboxes/${data.sandbox.id}/approve`);
  const response = await fetch(`${base}/api/events`);
  const body = await response.json();
  assert.ok(body.events.some((e) => e.action === '人工审批'));
  assert.ok(body.events.some((e) => e.action === '创建待审批沙箱'));
  assert.ok(body.events.length <= 40, 'event log is capped');
});

test('serves the console page and does not leak files outside the static root', async () => {
  const index = await fetch(`${base}/`);
  assert.equal(index.status, 200);
  assert.match(index.headers.get('content-type'), /text\/html/);

  for (const path of ['/../server.mjs', '/%2e%2e/server.mjs', '/..%2fserver.mjs']) {
    const response = await fetch(`${base}${path}`);
    assert.notEqual(response.status, 200, `${path} must not be readable`);
    if (response.status === 200) return;
    const body = await response.text();
    assert.ok(!body.includes('compileManifest'), `${path} leaked server source`);
  }
});
