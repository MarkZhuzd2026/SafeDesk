import { createServer } from 'node:http';
import { readFile, writeFile, mkdir, stat } from 'node:fs/promises';
import { join, normalize, extname, dirname } from 'node:path';
import { randomUUID } from 'node:crypto';
import { allowedAgents, compileManifest, policies } from './src/policy.mjs';
import { AuthStore } from './src/auth.mjs';
import { defaultSettings, defaultTemplates, catalog, enrichSandbox, filterEvents, filterSandboxes, mergeSettings, overview as productOverview, riskFor } from './src/product.mjs';

const PORT = Number(process.env.PORT ?? 8022);
const HOST = process.env.HOST ?? '0.0.0.0';
const AUTH_ENABLED = process.env.SAFEDESK_AUTH !== '0';
const root = new URL('.', import.meta.url).pathname;
const staticRoot = join(root, 'static');
const dataDir = process.env.SAFEDESK_DATA_DIR ?? join(root, 'data');
const dataFile = process.env.SAFEDESK_DATA_FILE ?? join(dataDir, 'sandboxes.json');
const settingsFile = join(dataDir, 'settings.json');
const auth = new AuthStore(dataDir);

const securityEvents = [
  { id: 'evt-001', level: 'info', action: '策略编译', detail: 'policy/balanced 已签名并下发至本地执行器', at: '2026-10-23T10:12:00.000Z' },
  { id: 'evt-002', level: 'allow', action: '凭据代签', detail: 'github-read 通过 Host Credential Broker 注入 Authorization 头', at: '2026-10-23T10:14:00.000Z' },
  { id: 'evt-003', level: 'block', action: '外联拦截', detail: '沙箱请求 untrusted.example 被默认拒绝', at: '2026-10-23T10:17:00.000Z' },
];

async function ensureStore() {
  await mkdir(dirname(dataFile), { recursive: true });
  try { await stat(dataFile); } catch { await writeFile(dataFile, '[]\n'); }
}

async function loadSandboxes() {
  await ensureStore();
  return JSON.parse(await readFile(dataFile, 'utf8'));
}

async function saveSandboxes(items) {
  await writeFile(dataFile, JSON.stringify(items, null, 2) + '\n');
}

async function loadSettings() {
  await mkdir(dataDir, { recursive: true });
  try {
    return mergeSettings(JSON.parse(await readFile(settingsFile, 'utf8')));
  } catch {
    const settings = mergeSettings(defaultSettings);
    await writeFile(settingsFile, `${JSON.stringify(settings, null, 2)}\n`);
    return settings;
  }
}

async function saveSettings(input) {
  const settings = mergeSettings(input);
  await writeFile(settingsFile, `${JSON.stringify(settings, null, 2)}\n`);
  return settings;
}

function json(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(body));
}

async function readBody(req) {
  let body = '';
  for await (const chunk of req) body += chunk;
  try { return JSON.parse(body || '{}'); } catch { throw Object.assign(new Error('请求体不是合法 JSON'), { statusCode: 400 }); }
}

function event(level, action, detail, actor) {
  securityEvents.unshift({ id: randomUUID(), level, action, detail, actor, at: new Date().toISOString() });
  securityEvents.splice(40);
}

function safeName(name) {
  return String(name ?? '').trim().replace(/[^\w\u4e00-\u9fa5-]/g, '-').slice(0, 48);
}

function bearer(req) {
  const header = req.headers.authorization || '';
  return header.startsWith('Bearer ') ? header.slice(7).trim() || null : null;
}

async function currentUser(req) {
  if (!AUTH_ENABLED) return { id: 'local-dev', role: 'admin', displayName: '本地开发', provider: 'disabled' };
  await auth.ready;
  return auth.sessionUser(bearer(req));
}

function visibleSandboxes(items, user) {
  if (!AUTH_ENABLED || user?.role === 'admin') return items;
  return items.filter((item) => item.ownerId === user?.id);
}

function canAccess(user, sandbox) {
  return user.role === 'admin' || sandbox.ownerId === user.id;
}

function queryTicket(url) {
  return url.searchParams.get('ticket') || '';
}

async function api(req, res, url) {
  const pathname = url.pathname;
  if (req.method === 'GET' && pathname === '/api/auth/config') return json(res, 200, auth.publicConfig());
  if (req.method === 'GET' && pathname === '/api/auth/wechat/poll') {
    await auth.ready;
    return json(res, 200, await auth.pollWechat(queryTicket(url)));
  }
  if (req.method === 'GET' && pathname === '/api/auth/wecom/poll') {
    await auth.ready;
    return json(res, 200, await auth.pollWecom(queryTicket(url)));
  }
  if (req.method === 'POST' && pathname === '/api/auth/phone/send') {
    try {
      const input = await readBody(req);
      return json(res, 200, auth.sendPhoneOtp(String(input.phone || '').trim()));
    } catch (error) {
      return json(res, error.statusCode ?? 400, { error: error.message });
    }
  }
  if (req.method === 'POST' && pathname === '/api/auth/phone/verify') {
    try {
      const input = await readBody(req);
      await auth.ready;
      return json(res, 200, await auth.verifyPhoneOtp(String(input.phone || '').trim(), String(input.token || '').trim()));
    } catch (error) {
      return json(res, error.statusCode ?? 400, { error: error.message });
    }
  }
  if (req.method === 'POST' && pathname === '/api/auth/wechat/start') {
    await auth.ready;
    return json(res, 200, auth.startWechat());
  }
  if (req.method === 'POST' && pathname === '/api/auth/wechat/confirm') {
    try {
      const input = await readBody(req);
      await auth.ready;
      return json(res, 200, await auth.confirmWechat(String(input.ticket || '').trim()));
    } catch (error) {
      return json(res, error.statusCode ?? 400, { error: error.message });
    }
  }
  if (req.method === 'POST' && pathname === '/api/auth/wecom/start') {
    await auth.ready;
    return json(res, 200, auth.startWecom());
  }
  if (req.method === 'POST' && pathname === '/api/auth/wecom/confirm') {
    try {
      const input = await readBody(req);
      await auth.ready;
      return json(res, 200, await auth.confirmWecom(String(input.ticket || '').trim()));
    } catch (error) {
      return json(res, error.statusCode ?? 400, { error: error.message });
    }
  }
  if (req.method === 'POST' && pathname === '/api/auth/admin/login') {
    try {
      const input = await readBody(req);
      await auth.ready;
      return json(res, 200, await auth.loginAdmin(String(input.username || '').trim(), String(input.password || '')));
    } catch (error) {
      return json(res, error.statusCode ?? 400, { error: error.message });
    }
  }
  if (req.method === 'POST' && pathname === '/api/auth/logout') {
    await auth.ready;
    await auth.revoke(bearer(req));
    return json(res, 200, { ok: true });
  }

  const user = await currentUser(req);
  if (pathname === '/api/auth/me') {
    if (!user) return json(res, 401, { error: '请先登录' });
    return json(res, 200, { user: AUTH_ENABLED ? auth.publicUser(user) : user, authEnabled: AUTH_ENABLED });
  }
  if (!user) return json(res, 401, { error: '请先登录' });

  if (req.method === 'GET' && pathname === '/api/bootstrap') {
    const sandboxes = visibleSandboxes(await loadSandboxes(), user).map(enrichSandbox);
    const events = user.role === 'admin' ? securityEvents : [];
    return json(res, 200, {
      user: AUTH_ENABLED ? auth.publicUser(user) : user,
      overview: productOverview(sandboxes, securityEvents, user),
      catalog: catalog(),
      templates: defaultTemplates,
      settings: await loadSettings(),
      policies: Object.values(policies),
      agents: Object.entries(allowedAgents).map(([id, item]) => ({ id, ...item })),
      sandboxes,
      securityEvents: events,
    });
  }
  if (req.method === 'GET' && pathname === '/api/overview') {
    const sandboxes = visibleSandboxes(await loadSandboxes(), user);
    return json(res, 200, { overview: productOverview(sandboxes, securityEvents, user) });
  }
  if (req.method === 'GET' && pathname === '/api/catalog') return json(res, 200, catalog());
  if (req.method === 'GET' && pathname === '/api/templates') return json(res, 200, { templates: defaultTemplates });
  if (req.method === 'GET' && pathname === '/api/settings') return json(res, 200, { settings: await loadSettings() });
  if (req.method === 'GET' && pathname === '/api/sandboxes') {
    return json(res, 200, { sandboxes: filterSandboxes(visibleSandboxes(await loadSandboxes(), user), Object.fromEntries(url.searchParams)) });
  }
  if (req.method === 'GET' && pathname === '/api/events') {
    if (user.role !== 'admin') return json(res, 403, { error: '仅管理员可以执行此操作' });
    return json(res, 200, { events: filterEvents(securityEvents, Object.fromEntries(url.searchParams)) });
  }
  if (req.method === 'POST' && pathname === '/api/sandboxes') {
    let input;
    try { input = await readBody(req); } catch (error) { return json(res, error.statusCode ?? 400, { error: error.message }); }
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
      purpose: String(input.purpose || '').trim().slice(0, 160),
      notes: String(input.notes || '').trim().slice(0, 240),
      risk: riskFor(policyId),
      status: 'pending_approval', createdAt: new Date().toISOString(),
      ownerId: user.id, ownerName: user.displayName || user.username || user.id,
    };
    const settings = await loadSettings();
    const sandboxes = await loadSandboxes();
    const running = sandboxes.filter((item) => ['running', 'paused', 'pending_approval'].includes(item.status) && (user.role === 'admin' || item.ownerId === user.id)).length;
    if (user.role !== 'admin' && running >= Number(settings.maxConcurrent || 8)) return json(res, 409, { error: '已达到并发沙箱上限' });
    sandboxes.unshift(sandbox);
    await saveSandboxes(sandboxes);
    event('info', '创建待审批沙箱', `${sandbox.name} 使用 ${policies[policyId].label} 策略`, user.id);
    return json(res, 201, { sandbox: enrichSandbox(sandbox), manifest: compileManifest(sandbox) });
  }
  if (pathname === '/api/settings' && req.method === 'POST') {
    if (user.role !== 'admin') return json(res, 403, { error: '仅管理员可以执行此操作' });
    let input;
    try { input = await readBody(req); } catch (error) { return json(res, error.statusCode ?? 400, { error: error.message }); }
    const settings = await saveSettings(input);
    event('info', '更新组织设置', `${settings.orgName} 已保存并发上限 ${settings.maxConcurrent}`, user.id);
    return json(res, 200, { settings });
  }
  const match = pathname.match(/^\/api\/sandboxes\/(sbx-[\w-]+)\/(approve|reject|pause|resume|terminate|manifest|activity)$/);
  if (match) {
    const [, id, action] = match;
    if (['approve', 'reject'].includes(action) && user.role !== 'admin') return json(res, 403, { error: '仅管理员可以执行此操作' });
    const sandboxes = await loadSandboxes();
    const sandbox = sandboxes.find((item) => item.id === id);
    if (!sandbox || !canAccess(user, sandbox)) return json(res, 404, { error: '未找到沙箱' });
    if (action === 'manifest' && req.method === 'GET') return json(res, 200, { manifest: compileManifest(sandbox) });
    if (action === 'activity' && req.method === 'GET') return json(res, 200, { events: securityEvents.filter((item) => String(item.detail || '').includes(sandbox.name)) });
    if (req.method !== 'POST') return json(res, 405, { error: 'Method not allowed' });
    let input = {};
    try { input = await readBody(req); } catch (error) { return json(res, error.statusCode ?? 400, { error: error.message }); }
    if (action === 'approve') {
      if (sandbox.status !== 'pending_approval') return json(res, 409, { error: '沙箱不是待审批状态' });
      sandbox.status = 'running'; sandbox.startedAt = new Date().toISOString(); sandbox.approvedBy = user.id;
      event('allow', '人工审批', `${sandbox.name} 已启动；凭据仅由主机 Broker 按策略代签`, user.id);
    }
    if (action === 'reject') {
      if (sandbox.status !== 'pending_approval') return json(res, 409, { error: '沙箱不是待审批状态' });
      sandbox.status = 'rejected'; sandbox.rejectedAt = new Date().toISOString(); sandbox.rejectedBy = user.id;
      sandbox.rejectReason = String(input.reason || '不符合安全策略').trim().slice(0, 160);
      event('block', '拒绝启动', `${sandbox.name} 被拒绝：${sandbox.rejectReason}`, user.id);
    }
    if (action === 'pause') {
      if (sandbox.status !== 'running') return json(res, 409, { error: '仅运行中的沙箱可以暂停' });
      sandbox.status = 'paused'; sandbox.pausedAt = new Date().toISOString(); sandbox.pausedBy = user.id;
      event('info', '暂停沙箱', `${sandbox.name} 已暂停，外联和会话凭据冻结`, user.id);
    }
    if (action === 'resume') {
      if (sandbox.status !== 'paused') return json(res, 409, { error: '仅暂停中的沙箱可以恢复' });
      sandbox.status = 'running'; sandbox.resumedAt = new Date().toISOString(); sandbox.resumedBy = user.id;
      event('allow', '恢复沙箱', `${sandbox.name} 已恢复运行`, user.id);
    }
    if (action === 'terminate') {
      if (sandbox.status === 'terminated') return json(res, 409, { error: '沙箱已终止' });
      sandbox.status = 'terminated'; sandbox.terminatedAt = new Date().toISOString(); sandbox.terminatedBy = user.id;
      event('block', '终止沙箱', `${sandbox.name} 已终止，短期会话凭据失效`, user.id);
    }
    await saveSandboxes(sandboxes);
    return json(res, 200, { sandbox: enrichSandbox(sandbox) });
  }
  return json(res, 404, { error: 'Not found' });
}

const mime = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.json': 'application/json; charset=utf-8' };
const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);
    if (url.pathname.startsWith('/api/')) return await api(req, res, url);
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
