import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';

const port = 18022;
const child = spawn(process.execPath, ['server.mjs'], {
  cwd: new URL('..', import.meta.url),
  env: { ...process.env, PORT: String(port) },
  stdio: 'ignore',
});

async function waitForServer() {
  for (let i = 0; i < 30; i += 1) {
    try { const response = await fetch(`http://127.0.0.1:${port}/api/bootstrap`); if (response.ok) return; } catch {}
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error('server did not start');
}

test.before(async () => { await waitForServer(); });
test.after(() => { child.kill(); });

test('creates a pending sandbox without accepting secrets', async () => {
  const response = await fetch(`http://127.0.0.1:${port}/api/sandboxes`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'audit-run', agent: 'codex', policyId: 'review', workspace: '/tmp/project', credentials: ['github-read'], mcpServers: ['github'] }),
  });
  assert.equal(response.status, 201);
  const data = await response.json();
  assert.equal(data.sandbox.status, 'pending_approval');
  assert.equal(data.manifest.credentialBroker.exposedValues, false);
  assert.equal(data.manifest.filesystem.mode, 'ro');
  assert.equal(data.manifest.runtime.network, 'disabled');
});

test('rejects a workspace that is not an absolute path', async () => {
  const response = await fetch(`http://127.0.0.1:${port}/api/sandboxes`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'bad-path', agent: 'dsh', policyId: 'balanced', workspace: 'relative/project' }),
  });
  assert.equal(response.status, 400);
});
