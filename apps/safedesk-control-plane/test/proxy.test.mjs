import http from 'node:http';
import test from 'node:test';
import assert from 'node:assert/strict';

import { aliasProfile } from '../src/privacy.mjs';
import { EgressPolicy, ProxyRuntime, isBlockedHost, serve } from '../src/proxy.mjs';

const echoHandler = (req, res) => {
  const body = `${req.headers.authorization ?? ''}|${req.url}`;
  res.writeHead(200, { 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
};

function listen(server, host = '127.0.0.1', port = 0) {
  return new Promise((resolve) => {
    if (server.listening) return resolve(server.address().port);
    server.listen(port, host, () => resolve(server.address().port));
  });
}

test('blocked host guard covers private, loopback, metadata', async () => {
  assert.equal((await isBlockedHost('127.0.0.1'))[0], true);
  assert.equal((await isBlockedHost('localhost'))[0], true);
  assert.equal((await isBlockedHost('169.254.169.254'))[0], true);
  assert.equal((await isBlockedHost('192.168.1.1'))[0], true);
  assert.equal((await isBlockedHost(''))[0], true);
});

test('public host passes with resolver override', async () => {
  const [blocked] = await isBlockedHost('api.github.com', async () => ['93.184.216.34']);
  assert.equal(blocked, false);
});

test('DNS rebinding to private address is blocked', async () => {
  const [blocked, reason] = await isBlockedHost('evil-dns-rebind.example', async () => ['10.0.0.9']);
  assert.equal(blocked, true);
  assert.match(reason, /私网/);
});

test('policy allowlist and wildcard', () => {
  const policy = new EgressPolicy(['api.github.com', '*.example.com']);
  assert.ok(policy.allows('api.github.com'));
  assert.ok(policy.allows('deep.example.com'));
  assert.ok(!policy.allows('evil.org'));
});

test('injection only for allowed hosts', () => {
  const policy = new EgressPolicy(['api.github.com'], { '{{SD_CRED_sbx_tok}}': { value: 'ghp_real', hosts: ['api.github.com'] } });
  const [headers, error] = policy.injectHeaders('api.github.com', { Authorization: '{{SD_CRED_sbx_tok}}' });
  assert.equal(error, null);
  assert.equal(headers.Authorization, 'ghp_real');
  const [, blockError] = policy.injectHeaders('evil.org', { Authorization: '{{SD_CRED_sbx_tok}}' });
  assert.match(blockError, /不允许/);
});

function rawGet(proxyPort, path, { auth = 'sbx-proxy01:tok-secret', headers = {}, originPort, originHost = 'pub.test' }) {
  return new Promise((resolve, reject) => {
    const request = http.request({
      host: '127.0.0.1', port: proxyPort,
      method: 'GET',
      path: `http://${originHost}:${originPort}${path}`,
      headers: {
        ...(auth ? { 'Proxy-Authorization': `Basic ${Buffer.from(auth).toString('base64')}` } : {}),
        ...headers,
      },
    }, (res) => {
      let data = Buffer.alloc(0);
      res.on('data', (chunk) => { data = Buffer.concat([data, chunk]); });
      res.on('end', () => resolve({ status: res.statusCode, body: data }));
    });
    request.on('error', reject);
    request.end();
  });
}

async function withProxyRuntime(testFn) {
  const runtime = new ProxyRuntime();
  runtime.register('sbx-proxy01', 'tok-secret', new EgressPolicy(
    ['pub.test'],
    { '{{SD_CRED_sbx-proxy01_x}}': { value: 'ghp_injected', hosts: ['pub.test'] } },
  ));
  const origin = http.createServer(echoHandler);
  const originPort = await listen(origin);
  const proxy = serve(runtime, '127.0.0.1', 0, {
    resolveHost: async () => ['93.184.216.34'],
    connectTarget: (hostName, port) => (hostName === 'pub.test' ? { host: '127.0.0.1', port: originPort } : { host: hostName, port }),
  });
  const proxyPort = await listen(proxy);
  try {
    await testFn({ runtime, proxyPort, originPort });
  } finally {
    await new Promise((resolveFn) => proxy.close(resolveFn));
    await new Promise((resolveFn) => origin.close(resolveFn));
  }
}

test('healthz responds', async () => {
  await withProxyRuntime(async ({ proxyPort }) => {
    const response = await new Promise((resolve, reject) => {
      http.get({ host: '127.0.0.1', port: proxyPort, path: '/healthz' }, (res) => {
        res.resume();
        res.on('end', () => resolve(res.statusCode));
      }).on('error', reject);
    });
    assert.equal(response, 200);
  });
});

test('allowlisted host passes with auth and records allow event', async () => {
  await withProxyRuntime(async ({ runtime, proxyPort, originPort }) => {
    const { status, body } = await rawGet(proxyPort, '/ok', { originPort });
    assert.equal(status, 200);
    assert.match(body.toString(), /\|\/ok/);
    assert.ok(runtime.snapshotEvents().some((event) => event.level === 'allow'));
  });
});

test('anonymous request rejected with 407', async () => {
  await withProxyRuntime(async ({ proxyPort, originPort }) => {
    const { status } = await rawGet(proxyPort, '/nope', { auth: null, originPort });
    assert.equal(status, 407);
  });
});

test('wrong token rejected', async () => {
  await withProxyRuntime(async ({ proxyPort, originPort }) => {
    const { status } = await rawGet(proxyPort, '/nope', { auth: 'sbx-proxy01:wrong', originPort });
    assert.equal(status, 407);
  });
});

test('paused sandbox frozen', async () => {
  await withProxyRuntime(async ({ runtime, proxyPort, originPort }) => {
    runtime.setPaused('sbx-proxy01', true);
    const { status, body } = await rawGet(proxyPort, '/frozen', { originPort });
    assert.equal(status, 403);
    assert.match(body.toString(), /egress denied/);
    runtime.setPaused('sbx-proxy01', false);
  });
});

test('placeholder injected host-side', async () => {
  await withProxyRuntime(async ({ proxyPort, originPort }) => {
    const { status, body } = await rawGet(proxyPort, '/inject', { originPort, headers: { Authorization: '{{SD_CRED_sbx-proxy01_x}}' } });
    assert.equal(status, 200);
    assert.match(body.toString(), /^ghp_injected\|\/inject/);
  });
});

test('block events recorded for anonymous attempts', async () => {
  await withProxyRuntime(async ({ runtime, proxyPort, originPort }) => {
    await rawGet(proxyPort, '/x', { auth: null, originPort });
    assert.ok(runtime.snapshotEvents().some((event) => event.level === 'block'));
  });
});

const meituanHandler = (req, res) => {
  const chunks = [];
  req.on('data', (chunk) => chunks.push(chunk));
  req.on('end', () => {
    const body = JSON.stringify({
      body: Buffer.concat(chunks).toString('utf8'),
      aliasHeader: req.headers['x-safedesk-alias-id'] ?? null,
      auth: req.headers['authorization'] ?? null,
    });
    res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
    res.end(body);
  });
};

function rawPost(proxyPort, path, { auth = 'sbx-takeout:tok-order', payload, originHost, originPort, headers = {} }) {
  return new Promise((resolve, reject) => {
    const request = http.request({
      host: '127.0.0.1', port: proxyPort,
      method: 'POST',
      path: `http://${originHost}:${originPort}${path}`,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
        ...(auth ? { 'Proxy-Authorization': `Basic ${Buffer.from(auth).toString('base64')}` } : {}),
        ...headers,
      },
    }, (res) => {
      let data = Buffer.alloc(0);
      res.on('data', (chunk) => { data = Buffer.concat([data, chunk]); });
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(data.toString() || '{}') }));
    });
    request.on('error', reject);
    request.end(payload);
  });
}

async function withMeituanProxy(testFn) {
  const runtime = new ProxyRuntime();
  runtime.register('sbx-takeout', 'tok-order', new EgressPolicy(
    ['meituan.demo.local'],
    { '{{SD_CRED_sbx-takeout_pay}}': { value: 'pay-token-real-9f81', hosts: ['meituan.demo.local'] } },
    aliasProfile('sbx-takeout'),
  ));
  const origin = http.createServer(meituanHandler);
  const originPort = await listen(origin);
  const proxy = serve(runtime, '127.0.0.1', 0, {
    resolveHost: async () => ['93.184.216.34'],
    connectTarget: (hostName, port) => (hostName === 'meituan.demo.local' ? { host: '127.0.0.1', port: originPort } : { host: hostName, port }),
  });
  const proxyPort = await listen(proxy);
  try {
    await testFn({ runtime, proxyPort, originPort });
  } finally {
    await new Promise((resolveFn) => proxy.close(resolveFn));
    await new Promise((resolveFn) => origin.close(resolveFn));
  }
}

test('platform sees alias only, no real PII (外卖隐私下单)', async () => {
  await withMeituanProxy(async ({ runtime, proxyPort, originPort }) => {
    const real = {
      name: '张伟',
      phone: '13812345678',
      address: '滨江路88号春天花园3栋1201',
      cardNo: '4111111111111111',
      items: [{ name: '黄焖鸡米饭', count: 1 }],
      note: '电话 13812345678 联系',
    };
    const { status, body: echoed } = await rawPost(proxyPort, '/api/v1/order', {
      payload: JSON.stringify(real),
      originHost: 'meituan.demo.local',
      originPort,
    });
    assert.equal(status, 200);
    assert.ok(!echoed.body.includes('张伟'));
    assert.ok(!echoed.body.includes('13812345678'));
    assert.ok(!echoed.body.includes('春天花园'));
    assert.ok(!echoed.body.includes('4111111111111111'));
    const alias = aliasProfile('sbx-takeout');
    assert.ok(echoed.body.includes(alias.phone));
    assert.ok(echoed.body.includes(alias.address));
    assert.ok(echoed.body.includes('黄焖鸡米饭'));
    assert.equal(echoed.aliasHeader, alias.aliasId);
    assert.ok(runtime.snapshotEvents().some((event) => event.detail.includes('脱敏')));
  });
});

test('payment token injected only for meituan allowlisted host', async () => {
  await withMeituanProxy(async ({ proxyPort, originPort }) => {
    const { status, body: echoed } = await rawPost(proxyPort, '/api/v1/order', {
      payload: JSON.stringify({ orderId: 'A123' }),
      originHost: 'meituan.demo.local',
      originPort,
      headers: { Authorization: '{{SD_CRED_sbx-takeout_pay}}' },
    });
    assert.equal(status, 200);
    assert.equal(echoed.auth, 'pay-token-real-9f81');
  });
});

const ctripHandler = (req, res) => {
  const chunks = [];
  req.on('data', (chunk) => chunks.push(chunk));
  req.on('end', () => {
    const body = JSON.stringify({
      body: Buffer.concat(chunks).toString('utf8'),
      aliasHeader: req.headers['x-safedesk-alias-id'] ?? null,
    });
    res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
    res.end(body);
  });
};

const TRIP_NAME_PH = '{{SD_TRV_sbx-trip_traveller-li_name_ab123456}}';
const TRIP_ID_PH = '{{SD_TRV_sbx-trip_traveller-li_idCard_ab123456}}';
const TRIP_PHONE_PH = '{{SD_TRV_sbx-trip_traveller-li_phone_ab123456}}';
const TRIP_PAY_PH = '{{SD_CRED_sbx-trip_pay}}';

async function withCtripProxy(testFn) {
  const runtime = new ProxyRuntime();
  runtime.register('sbx-trip', 'tok-trip', new EgressPolicy(
    ['api.ctrip.demo.local'],
    {
      [TRIP_NAME_PH]: { value: '李雷', hosts: ['api.ctrip.demo.local'] },
      [TRIP_ID_PH]: { value: '110101199003071234', hosts: ['api.ctrip.demo.local'] },
      [TRIP_PHONE_PH]: { value: '13812345678', hosts: ['api.ctrip.demo.local'] },
      [TRIP_PAY_PH]: { value: 'pay-token-ctrip-7f20', hosts: ['api.ctrip.demo.local'] },
    },
    aliasProfile('sbx-trip'),
  ));
  runtime.register('sbx-trip-bad', 'tok-bad', new EgressPolicy(
    ['api.ctrip.demo.local'],
    { [TRIP_NAME_PH]: { value: '李雷', hosts: ['other.not-allowed'] } },
  ));
  const origin = http.createServer(ctripHandler);
  const originPort = await listen(origin);
  const proxy = serve(runtime, '127.0.0.1', 0, {
    resolveHost: async () => ['93.184.216.34'],
    connectTarget: (hostName, port) => (hostName === 'api.ctrip.demo.local' ? { host: '127.0.0.1', port: originPort } : { host: hostName, port }),
  });
  const proxyPort = await listen(proxy);
  try {
    await testFn({ runtime, proxyPort, originPort });
  } finally {
    await new Promise((resolveFn) => proxy.close(resolveFn));
    await new Promise((resolveFn) => origin.close(resolveFn));
  }
}

function rawBooking(proxyPort, payload, { auth = 'sbx-trip:tok-trip', originPort, extraHeaders = {} }) {
  const raw = JSON.stringify(payload);
  return new Promise((resolve, reject) => {
    const request = http.request({
      host: '127.0.0.1', port: proxyPort,
      method: 'POST',
      path: `http://api.ctrip.demo.local:${originPort}/openapi/book`,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(raw),
        'Proxy-Authorization': `Basic ${Buffer.from(auth).toString('base64')}`,
        ...extraHeaders,
      },
    }, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        let parsed;
        try { parsed = JSON.parse(data); } catch { parsed = { errorBody: data }; }
        resolve({ status: res.statusCode, body: parsed });
      });
    });
    request.on('error', reject);
    request.end(raw);
  });
}

test('traveler placeholders resolved host-side at allowlisted ticketing host (携程订票)', async () => {
  await withCtripProxy(async ({ proxyPort, originPort }) => {
    const payload = {
      traveler: { name: TRIP_NAME_PH, idCard: TRIP_ID_PH, phone: TRIP_PHONE_PH },
      note: '紧急电话 13812345678 别漏接',
      route: '北京-上海 CA1837',
    };
    const { status, body: echoed } = await rawBooking(proxyPort, payload, {
      originPort,
      extraHeaders: { Authorization: TRIP_PAY_PH },
    });
    assert.equal(status, 200);
    const body = JSON.parse(echoed.body);
    assert.equal(body.traveler.name, '李雷');
    assert.equal(body.traveler.idCard, '110101199003071234');
    assert.equal(body.traveler.phone, '13812345678');
    assert.ok(!echoed.body.includes('SD_TRV'));
    assert.ok(body.note.includes('[*手机号*]'));
    assert.ok(!body.note.includes('13812345678'));
    assert.equal(body.route, payload.route);
    assert.equal(echoed.aliasHeader, aliasProfile('sbx-trip').aliasId);
  });
});

test('body placeholder blocked when destination is not allowlisted', async () => {
  await withCtripProxy(async ({ runtime, proxyPort, originPort }) => {
    const { status, body } = await rawBooking(proxyPort, { traveler: { name: TRIP_NAME_PH } }, {
      auth: 'sbx-trip-bad:tok-bad',
      originPort,
    });
    assert.equal(status, 403);
    assert.match(JSON.stringify(body), /egress denied/);
    assert.ok(runtime.snapshotEvents().some((event) => event.detail.includes('不允许')));
  });
});
