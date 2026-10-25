import dns from 'node:dns/promises';
import http from 'node:http';
import net from 'node:net';

import { anonymizeOrderFields, redactPii } from './privacy.mjs';

/** Per-sandbox egress proxy: allowlist + SSRF guard + broker-mediated credential injection (REQ-NW-001..009, 013, 014). */
export const BLOCKED_CIDRS = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.168.0.0', 16], ['100.64.0.0', 10],
];
export const BLOCKED_HOSTS = new Set(['localhost', 'metadata.google.internal', 'metadata.aws.internal']);
export const METADATA_IPS = new Set(['169.254.169.254', '100.100.100.200']);

const ipToLong = (ip) => ip.split('.').reduce((acc, part) => ((acc << 8) + Number(part)) >>> 0, 0);

function ipInCidr(ip, base, bits) {
  try {
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return (ipToLong(ip) & mask) === (ipToLong(base) & mask);
  } catch {
    return false;
  }
}

export async function resolveHost(host) {
  try {
    return (await dns.lookup(host, { all: true })).map((record) => record.address);
  } catch {
    return [];
  }
}

/** REQ-NW-002/003/004: hard-deny private/loopback/link-local/metadata targets, incl. DNS rebinding. */
export async function isBlockedHost(host, resolver = resolveHost) {
  const name = String(host || '').trim().toLowerCase().split(':')[0];
  if (!name) return [true, '目标主机为空'];
  if (BLOCKED_HOSTS.has(name) || METADATA_IPS.has(name)) return [true, '目标为回环/元数据端点，默认拒绝'];
  for (const ip of await resolver(name)) {
    if (METADATA_IPS.has(ip) || ip.startsWith('fd00:ec2') || ip === '::1') return [true, '目标解析到元数据/回环地址，默认拒绝'];
    if (BLOCKED_CIDRS.some(([base, bits]) => ipInCidr(ip, base, bits))) return [true, '目标解析到私网地址，默认拒绝'];
  }
  return [false, ''];
}

export class EgressPolicy {
  constructor(allowed = [], injections = {}, alias = null) {
    this.allowed = new Set((allowed || []).map((host) => String(host).trim().toLowerCase()).filter(Boolean));
    this.injections = injections || {};
    this.alias = alias || null;
  }

  allows(host) {
    const name = String(host || '').trim().toLowerCase().split(':')[0];
    if (this.allowed.has(name)) return true;
    for (const pattern of this.allowed) {
      if (pattern.startsWith('*.') && (name === pattern.slice(2) || name.endsWith(pattern.slice(1)))) return true;
    }
    return false;
  }

  static _hostsAllow(target, hosts) {
    const host = String(target || '').trim().toLowerCase().split(':')[0];
    return (hosts || []).some((pattern) => {
      if (pattern.startsWith('*.') && (host === pattern.slice(2) || host.endsWith(pattern.slice(1)))) return true;
      return pattern === host;
    });
  }

  injectHeaders(host, headers) {
    const result = {};
    for (const [key, value] of Object.entries(headers)) {
      const entry = this.injections[value];
      if (!entry) { result[key] = value; continue; }
      if (!EgressPolicy._hostsAllow(host, entry.hosts || [])) {
        return [{}, `凭据不允许发送到 ${host}`];
      }
      result[key] = entry.value;
    }
    return [result, null];
  }
}

export class ProxyRuntime {
  constructor() {
    this._registrations = new Map();
    this._events = [];
    this.onEvent = null;
  }

  register(sandboxId, token, policy) {
    this._registrations.set(sandboxId, { token, policy, paused: false });
  }

  unregister(sandboxId) {
    this._registrations.delete(sandboxId);
  }

  setPaused(sandboxId, paused) {
    const entry = this._registrations.get(sandboxId);
    if (entry) entry.paused = paused;
  }

  lookup(sandboxId, token) {
    const entry = this._registrations.get(sandboxId);
    return entry && entry.token === token ? entry : null;
  }

  record(level, detail) {
    this._events.unshift({ level, action: '网络决策', detail });
    this._events.splice(200);
    if (this.onEvent) {
      try { this.onEvent(level, detail); } catch { /* sink failure must not break proxying */ }
    }
  }

  snapshotEvents() {
    return [...this._events];
  }
}

const HOP_HEADERS = new Set(['proxy-authorization', 'proxy-connection', 'connection', 'content-length', 'host', 'transfer-encoding']);

function deny(runtime, req, res, status, reason) {
  runtime.record('block', `${req.method} ${String(req.url).slice(0, 120)} 被拒绝：${reason}`);
  const body = JSON.stringify({ error: 'egress denied', reason });
  res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}

function authEntry(runtime, req) {
  const header = String(req.headers['proxy-authorization'] || '');
  if (!header.startsWith('Basic ')) return null;
  let raw;
  try {
    raw = Buffer.from(header.slice(6), 'base64').toString('utf8');
  } catch {
    return null;
  }
  const idx = raw.indexOf(':');
  if (idx < 0) return null;
  return runtime.lookup(raw.slice(0, idx), raw.slice(idx + 1));
}

export function serve(runtime, host = '127.0.0.1', port = 0, options = {}) {
  const resolveTarget = options.resolveHost || resolveHost;
  const connectTarget = options.connectTarget || null;
  const server = http.createServer(async (req, res) => {
    try {
      if (req.method === 'GET' && req.url === '/healthz') {
        const body = JSON.stringify({ ok: true, service: 'safedesk-egress-proxy' });
        res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
        res.end(body);
        return;
      }
      const entry = authEntry(runtime, req);
      if (!entry) return deny(runtime, req, res, 407, req.headers['proxy-authorization'] ? '代理鉴权失败' : '缺少代理鉴权');
      if (entry.paused) return deny(runtime, req, res, 403, '沙箱已暂停，外联冻结');
      const target = new URL(req.url);
      const hostName = target.hostname;
      if (!hostName) return deny(runtime, req, res, 400, '请求必须为绝对 URI');
      const [blocked, reason] = await isBlockedHost(hostName, resolveTarget);
      if (blocked) return deny(runtime, req, res, 403, reason);
      if (!entry.policy.allows(hostName)) return deny(runtime, req, res, 403, '目标不在白名单');
      const headers = {};
      for (const [key, value] of Object.entries(req.headers)) {
        if (HOP_HEADERS.has(key.toLowerCase())) continue;
        headers[key] = value;
      }
      headers.host = target.host;
      const [injected, injectError] = entry.policy.injectHeaders(hostName, headers);
      if (injectError) return deny(runtime, req, res, 403, injectError);
      const port = Number(target.port || 80);
      const outboundTarget = connectTarget ? connectTarget(hostName, port) : { host: hostName, port };
      let body;
      if (entry.policy.alias) {
        const chunks = [];
        for await (const chunk of req) chunks.push(chunk);
        const rawBody = Buffer.concat(chunks);
        let headerHits = 0;
        for (const key of Object.keys(injected)) {
          const [redacted, hits] = redactPii(String(injected[key]));
          injected[key] = redacted;
          headerHits += hits.length;
        }
        injected['x-safedesk-alias-id'] = entry.policy.alias.aliasId;
        let totalHits = headerHits;
        if (rawBody.length) {
          const contentType = String(req.headers['content-type'] || '').toLowerCase();
          const text = rawBody.toString('utf8');
          if (contentType.includes('json')) {
            try {
              const [payload, swaps] = anonymizeOrderFields(JSON.parse(text), entry.policy.alias);
              body = Buffer.from(JSON.stringify(payload), 'utf8');
              totalHits += swaps.length;
            } catch {
              const [redacted, hits] = redactPii(text);
              body = Buffer.from(redacted, 'utf8');
              totalHits += hits.length;
            }
          } else {
            const [redacted, hits] = redactPii(text);
            body = Buffer.from(redacted, 'utf8');
            totalHits += hits.length;
          }
        }
        if (totalHits) runtime.record('info', `${req.method} ${hostName} 个人信息脱敏 ${totalHits} 项`);
        if (body !== undefined) injected['content-length'] = String(body.length);
      }
      return new Promise((resolveOutbound) => {
        const outbound = http.request({
          host: outboundTarget.host,
          port: outboundTarget.port,
          method: req.method,
          path: `${target.pathname || '/'}${target.search || ''}`,
          headers: injected,
        }, (upstream) => {
          res.writeHead(upstream.statusCode ?? 502, upstream.headers);
          upstream.pipe(res);
          res.on('close', resolveOutbound);
        });
        outbound.on('error', () => {
          res.writeHead(502);
          res.end('Bad Gateway');
          resolveOutbound();
        });
        res.on('finish', () => runtime.record('allow', `${req.method} ${hostName} 放行`));
        if (body) outbound.write(body);
        else req.pipe(outbound);
        outbound.end();
      });
    } catch (error) {
      if (!res.headersSent) deny(runtime, req, res, 400, '请求必须为绝对 URI');
      return undefined;
    }
  });

  server.on('connect', async (req, client, head) => {
    const [hostName, port = ''] = String(req.url || '').split(':');
    const entry = authEntry(runtime, req);
    const rejectConnect = (status, reason) => {
      runtime.record('block', `CONNECT ${req.url} 被拒绝：${reason}`);
      client.write(`HTTP/1.1 ${status} Egress Denied\r\n\r\n`);
      client.destroy();
    };
    if (!entry) return rejectConnect(407, '代理鉴权失败');
    if (entry.paused) return rejectConnect(403, '沙箱已暂停，外联冻结');
    if (port !== '443') return rejectConnect(403, '仅允许白名单 443 隧道');
    const [blocked, reason] = await isBlockedHost(hostName, resolveTarget);
    if (blocked) return rejectConnect(403, reason);
    if (!entry.policy.allows(hostName)) return rejectConnect(403, '目标不在白名单');
    const outbound = connectTarget ? connectTarget(hostName, 443) : { host: hostName, port: 443 };
    const upstream = net.connect(outbound.port, outbound.host, () => {
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head && head.length) upstream.write(head);
      upstream.pipe(client);
      client.pipe(upstream);
    });
    upstream.on('error', () => client.destroy());
    client.on('error', () => upstream.destroy());
    runtime.record('allow', `CONNECT ${hostName}:443 放行（隧道不解密）`);
    return undefined;
  });

  server.listen(port, host);
  return server;
}
