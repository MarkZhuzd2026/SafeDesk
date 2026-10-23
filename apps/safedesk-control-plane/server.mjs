import { createServer } from 'node:http';
import { readFile, writeFile, mkdir, stat } from 'node:fs/promises';
import { join, normalize, extname } from 'node:path';
import { randomUUID } from 'node:crypto';
import { allowedAgents, compileManifest, policies } from './src/policy.mjs';

const PORT = Number(process.env.PORT ?? 8022);
const HOST = process.env.HOST ?? '0.0.0.0';
const root = new URL('.', import.meta.url).pathname;
const staticRoot = join(root, 'static');
const dataFile = join(root, 'data', 'sandboxes.json');

const securityEvents = [
  { id: 'evt-001', level: 'info', action: '策略编译', detail: 'policy/balanced 已签名并下发至本地执行器', at: '2026-10-23T10:12:00.000Z' },
  { id: 'evt-002', level: 'allow', action: '凭据代签', detail: 'github-read 通过 Host Credential Broker 注入 Authorization 头', at: '2026-10-23T10:14:00.000Z' },
  { id: 'evt-003', level: 'block', action: '外联拦截', detail: '沙箱请求 untrusted.example 被默认拒绝', at: '2026-10-23T10:17:00.000Z' },
];

async function ensureStore() {
  await mkdir(join(root, 'data'), { recursive: true });
  try { await stat(dataFile); } catch { await writeFile(dataFile, '[]\n'); }
}

async function loadSandboxes() {
  await ensureStore();
  return JSON.parse(await readFile(dataFile, 'utf8'));
}

async function saveSandboxes(items) {
  await writeFile(dataFile, JSON.stringify(items, null, 2) + '\n');
}

function json(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(body));
}

async function readBody(req) {
  let body = '';
  for await (const chunk of req) body += chunk;
  try { return JSON.parse(body || '{}'); } catch { throw new Error('请求体不是合法 JSON'); }
}

function event(level, action, detail) {
  securityEvents.unshift({ id: randomUUID(), level, action, detail, at: new Date().toISOString() });
  securityEvents.splice(40);
}

function safeName(name) {
  return String(name ?? '').trim().replace(/[^\w\u4e00-\u9fa5-]/g, '-').slice(0, 48);
}

async function api(req, res, pathname) {
  if (req.method === 'GET' && pathname === '/api/bootstrap') {
    const sandboxes = await loadSandboxes();
    return json(res, 200, { policies: Object.values(policies), agents: Object.entries(allowedAgents).map(([id, item]) => ({ id, ...item })), sandboxes, securityEvents });
  }
  if (req.method === 'GET' && pathname === '/api/sandboxes') return json(res, 200, { sandboxes: await loadSandboxes() });
  if (req.method === 'GET' && pathname === '/api/events') return json(res, 200, { events: securityEvents });
  if (req.method === 'POST' && pathname === '/api/sandboxes') {
    const input = await readBody(req);
    const policyId = String(input.policyId ?? 'balanced');
    const agent = String(input.agent ?? 'claude-code');
    if (!policies[policyId]) return json(res, 400, { error: '未知策略' });
    if (!allowedAgents[agent]) return json(res, 400, { error: '仅支持 Claude Code、Codex 或 DSH' });
    const workspace = String(input.workspace ?? '').trim();
    if (!workspace.startsWith('/')) return json(res, 400, { error: '工作区必须为绝对路径' });
    const sandbox = {
      id: `sbx-${randomUUID().slice(0, 8)}`,
      name: safeName(input.name) || `agent-${agent}`,
      agent, policyId, workspace,
      packages: Array.isArray(input.packages) && input.packages.length ? input.packages.slice(0, 8) : ['wasmer/bash@latest'],
      credentials: Array.isArray(input.credentials) ? input.credentials.slice(0, 8) : [],
      mcpServers: Array.isArray(input.mcpServers) ? input.mcpServers.slice(0, 12) : [],
      status: 'pending_approval', createdAt: new Date().toISOString(),
    };
    const sandboxes = await loadSandboxes();
    sandboxes.unshift(sandbox);
    await saveSandboxes(sandboxes);
    event('info', '创建待审批沙箱', `${sandbox.name} 使用 ${policies[policyId].label} 策略`);
    return json(res, 201, { sandbox, manifest: compileManifest(input, sandbox) });
  }
  const match = pathname.match(/^\/api\/sandboxes\/(sbx-[\w-]+)\/(approve|terminate|manifest)$/);
  if (match) {
    const [, id, action] = match;
    const sandboxes = await loadSandboxes();
    const sandbox = sandboxes.find((item) => item.id === id);
    if (!sandbox) return json(res, 404, { error: '未找到沙箱' });
    if (action === 'manifest' && req.method === 'GET') return json(res, 200, { manifest: compileManifest({}, sandbox) });
    if (req.method !== 'POST') return json(res, 405, { error: 'Method not allowed' });
    if (action === 'approve') {
      if (sandbox.status !== 'pending_approval') return json(res, 409, { error: '沙箱不是待审批状态' });
      sandbox.status = 'running'; sandbox.startedAt = new Date().toISOString();
      event('allow', '人工审批', `${sandbox.name} 已启动；凭据仅由主机 Broker 按策略代签`);
    }
    if (action === 'terminate') {
      if (sandbox.status === 'terminated') return json(res, 409, { error: '沙箱已终止' });
      sandbox.status = 'terminated'; sandbox.terminatedAt = new Date().toISOString();
      event('block', '终止沙箱', `${sandbox.name} 已终止，短期会话凭据失效`);
    }
    await saveSandboxes(sandboxes);
    return json(res, 200, { sandbox });
  }
  return json(res, 404, { error: 'Not found' });
}

const mime = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.json': 'application/json; charset=utf-8' };
const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);
    if (url.pathname.startsWith('/api/')) return await api(req, res, url.pathname);
    const requested = url.pathname === '/' ? '/index.html' : url.pathname;
    const target = normalize(join(staticRoot, requested));
    if (!target.startsWith(staticRoot)) return json(res, 403, { error: 'Forbidden' });
    const content = await readFile(target);
    res.writeHead(200, { 'Content-Type': mime[extname(target)] ?? 'application/octet-stream', 'Cache-Control': 'no-store' });
    res.end(content);
  } catch (error) {
    json(res, error.code === 'ENOENT' ? 404 : 500, { error: error.message });
  }
});

server.listen(PORT, HOST, () => console.log(`SafeDesk control plane listening on http://${HOST}:${PORT}`));
