import test from 'node:test';
import assert from 'node:assert/strict';
import { allowedAgents, compileManifest, policies, secretPaths } from '../src/policy.mjs';

function sampleSandbox(overrides = {}) {
  return {
    id: 'sbx-test1234',
    name: 'unit-test',
    agent: 'claude-code',
    policyId: 'balanced',
    workspace: '/srv/work/demo',
    packages: ['wasmer/bash@latest'],
    credentials: ['github-read'],
    mcpServers: ['github'],
    status: 'pending_approval',
    createdAt: '2026-10-23T00:00:00.000Z',
    ...overrides,
  };
}

test('policy catalog exposes the three expected policies', () => {
  assert.deepEqual(Object.keys(policies).sort(), ['balanced', 'build', 'review']);
  for (const policy of Object.values(policies)) {
    assert.ok(policy.label, `policy ${policy.id} has a label`);
    assert.ok(policy.maxCpu > 0 && policy.maxMemoryMb > 0, `policy ${policy.id} has resource limits`);
  }
});

test('agent catalog only allows Claude Code, Codex and DSH', () => {
  assert.deepEqual(Object.keys(allowedAgents).sort(), ['claude-code', 'codex', 'dsh']);
});

test('compileManifest maps the balanced policy correctly', () => {
  const manifest = compileManifest(sampleSandbox());
  assert.equal(manifest.apiVersion, 'safedesk.io/v1');
  assert.equal(manifest.kind, 'SandboxLaunchPlan');
  assert.equal(manifest.id, 'sbx-test1234');
  assert.equal(manifest.runtime.provider, 'wasmer');
  assert.equal(manifest.runtime.network, 'brokered');
  assert.equal(manifest.runtime.volume, '/srv/work/demo:/workspace');
  assert.deepEqual(manifest.runtime.packages, ['wasmer/bash@latest']);
  assert.equal(manifest.filesystem.mode, 'rw');
  assert.equal(manifest.enforcement.approval, 'destructive');
  assert.equal(manifest.enforcement.maxCpu, 2);
  assert.equal(manifest.enforcement.maxMemoryMb, 4096);
  assert.equal(manifest.enforcement.audit, 'append-only');
});

test('compileManifest maps the review policy to read-only and no network', () => {
  const manifest = compileManifest(sampleSandbox({ policyId: 'review' }));
  assert.equal(manifest.filesystem.mode, 'ro');
  assert.equal(manifest.runtime.network, 'disabled');
  assert.equal(manifest.enforcement.approval, 'all_writes');
});

test('compileManifest maps the build policy to ephemeral workspace and allowlist egress', () => {
  const manifest = compileManifest(sampleSandbox({ policyId: 'build' }));
  assert.equal(manifest.filesystem.mode, 'ephemeral');
  assert.equal(manifest.runtime.network, 'allowlist');
  assert.equal(manifest.enforcement.maxCpu, 4);
  assert.equal(manifest.enforcement.maxMemoryMb, 8192);
});

test('compileManifest resolves the agent entrypoint command', () => {
  for (const [agent, expected] of [['claude-code', 'claude'], ['codex', 'codex'], ['dsh', 'dsh']]) {
    const manifest = compileManifest(sampleSandbox({ agent }));
    assert.equal(manifest.agent.type, agent);
    assert.equal(manifest.agent.command, expected);
  }
});

test('credential broker is enabled but never exposes secret values', () => {
  const manifest = compileManifest(sampleSandbox());
  assert.equal(manifest.credentialBroker.enabled, true);
  assert.equal(manifest.credentialBroker.exposedValues, false);
  assert.deepEqual(manifest.credentialBroker.profiles, ['github-read']);
});

test('secret paths are always part of the manifest and cover common secret files', () => {
  const manifest = compileManifest(sampleSandbox());
  assert.deepEqual(manifest.filesystem.secretPaths, secretPaths);
  for (const expected of ['/.env', '/.ssh/**', '/.aws/**', '/.npmrc']) {
    assert.ok(secretPaths.includes(expected), `secretPaths covers ${expected}`);
  }
});

test('mcp gateway restricts servers to the sandbox allowlist', () => {
  const manifest = compileManifest(sampleSandbox({ mcpServers: ['github', 'ci'] }));
  assert.equal(manifest.mcpGateway.enabled, true);
  assert.equal(manifest.mcpGateway.transport, 'streamable-http');
  assert.deepEqual(manifest.mcpGateway.allowedServers, ['github', 'ci']);
});
