import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';

import { AuditLog } from '../src/audit.mjs';

const makeEvent = (idx, at = '2026-10-24T10:00:00.000Z', overrides = {}) => ({
  id: `evt-${idx}`, level: 'info', action: '测试事件', detail: `detail-${idx}`, actor: 'admin', at, ...overrides,
});

function makeLog() {
  const dir = mkdtempSync(join(tmpdir(), 'safedesk-audit-'));
  return { dir, log: new AuditLog(join(dir, 'audit.jsonl'), 30) };
}

test('append and load round trip', async () => {
  const { dir, log } = makeLog();
  await log.append(makeEvent(1));
  await log.append(makeEvent(2));
  const loaded = await log.load();
  assert.deepEqual(loaded.map((item) => item.id), ['evt-1', 'evt-2']);
  rmSync(dir, { recursive: true, force: true });
});

test('file is private 0600', async () => {
  const { dir, log } = makeLog();
  await log.append(makeEvent(1));
  const { statSync } = await import('node:fs');
  assert.equal(statSync(log.path).mode & 0o777, 0o600);
  rmSync(dir, { recursive: true, force: true });
});

test('prune drops old events', async () => {
  const { dir, log } = makeLog();
  const now = new Date();
  const old = new Date(now.getTime() - 40 * 86400 * 1000).toISOString();
  const fresh = new Date(now.getTime() - 86400 * 1000).toISOString();
  await log.append(makeEvent(1, old));
  await log.append(makeEvent(2, fresh));
  const removed = await log.prune(now);
  assert.equal(removed, 1);
  assert.deepEqual((await log.load()).map((item) => item.id), ['evt-2']);
  rmSync(dir, { recursive: true, force: true });
});

test('query newest first with level filter', async () => {
  const { dir, log } = makeLog();
  for (let idx = 0; idx < 5; idx += 1) {
    await log.append(makeEvent(idx, '2026-10-24T10:00:00.000Z', { level: idx % 2 === 0 ? 'block' : 'allow' }));
  }
  const result = await log.query({ level: 'block' });
  assert.deepEqual(result.map((item) => item.id), ['evt-4', 'evt-2', 'evt-0']);
  rmSync(dir, { recursive: true, force: true });
});

test('query limit and offset paginate', async () => {
  const { dir, log } = makeLog();
  for (let idx = 0; idx < 10; idx += 1) await log.append(makeEvent(idx));
  const page1 = await log.query({ limit: 3 });
  const page2 = await log.query({ limit: 3, offset: 3 });
  assert.equal(page1.length, 3);
  assert.equal(page2.length, 3);
  assert.notEqual(page1[0].id, page2[0].id);
  rmSync(dir, { recursive: true, force: true });
});

test('query keyword matches detail', async () => {
  const { dir, log } = makeLog();
  await log.append(makeEvent(1, '2026-10-24T10:00:00.000Z', { detail: '凭据 github-read 代签' }));
  await log.append(makeEvent(2, '2026-10-24T10:01:00.000Z', { detail: '外联拦截' }));
  const result = await log.query({ keyword: 'github' });
  assert.equal(result.length, 1);
  assert.equal(result[0].id, 'evt-1');
  rmSync(dir, { recursive: true, force: true });
});
