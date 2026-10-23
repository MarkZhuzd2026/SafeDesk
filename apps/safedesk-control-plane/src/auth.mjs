import { pbkdf2Sync, randomBytes, randomInt, timingSafeEqual } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';

const PHONE_RE = /^1\d{10}$/;
const PBKDF2_ROUNDS = 120000;
const SESSION_DAYS = 7;
const OTP_TTL_SECONDS = 300;
const OTP_RESEND_SECONDS = 60;
const WECHAT_TTL_SECONDS = 180;
const DEFAULT_ADMIN_USERNAME = 'admin';
const DEFAULT_ADMIN_PASSWORD = 'SafeDesk@Admin';

function isoNow() {
  return new Date().toISOString();
}

function parseIso(value) {
  return new Date(value);
}

export class AuthStore {
  constructor(dataDir) {
    this.dataDir = dataDir;
    this.usersFile = join(dataDir, 'users.json');
    this.sessionsFile = join(dataDir, 'sessions.json');
    this.otp = new Map();
    this.wechat = new Map();
    this.demo = process.env.SAFEDESK_DEMO !== '0';
    this.otpEcho = process.env.SAFEDESK_OTP_ECHO === '1' || this.demo;
    this.adminUsername = process.env.SAFEDESK_ADMIN_USERNAME || DEFAULT_ADMIN_USERNAME;
    this.adminPassword = process.env.SAFEDESK_ADMIN_PASSWORD || DEFAULT_ADMIN_PASSWORD;
    this.adminPhones = new Set((process.env.SAFEDESK_ADMIN_PHONES || '').split(',').map((item) => item.trim()).filter(Boolean));
    this.ready = this.ensureAdmin();
  }

  publicConfig() {
    return {
      methods: ['phone', 'wechat', 'admin'],
      wechatMode: 'local-qr',
      demo: this.demo,
      adminUsername: this.adminUsername,
    };
  }

  async load(path, fallback) {
    await mkdir(dirname(path), { recursive: true });
    try {
      return JSON.parse(await readFile(path, 'utf8'));
    } catch {
      await writeFile(path, `${JSON.stringify(fallback, null, 2)}\n`);
      return fallback;
    }
  }

  async save(path, payload) {
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, `${JSON.stringify(payload, null, 2)}\n`);
  }

  users() {
    return this.load(this.usersFile, []);
  }

  sessions() {
    return this.load(this.sessionsFile, []);
  }

  hashPassword(password, salt = randomBytes(16).toString('hex')) {
    const digest = pbkdf2Sync(password, salt, PBKDF2_ROUNDS, 32, 'sha256').toString('hex');
    return `${salt}$${digest}`;
  }

  verifyPassword(password, stored) {
    const [salt, digest] = String(stored || '').split('$');
    if (!salt || !digest) return false;
    const candidate = pbkdf2Sync(password, salt, PBKDF2_ROUNDS, 32, 'sha256').toString('hex');
    const a = Buffer.from(candidate, 'hex');
    const b = Buffer.from(digest, 'hex');
    return a.length === b.length && timingSafeEqual(a, b);
  }

  publicUser(user) {
    if (!user) return null;
    return {
      id: user.id,
      role: user.role,
      provider: user.provider || 'admin',
      displayName: user.displayName || user.username || '用户',
      phone: user.phone,
      username: user.username,
    };
  }

  async ensureAdmin() {
    const users = await this.users();
    const hashed = this.hashPassword(this.adminPassword);
    const existing = users.find((item) => item.username === this.adminUsername);
    if (!existing) {
      users.push({
        id: 'admin',
        username: this.adminUsername,
        role: 'admin',
        provider: 'admin',
        displayName: '管理员',
        passwordHash: hashed,
        createdAt: isoNow(),
      });
    } else {
      existing.passwordHash = hashed;
      existing.role = 'admin';
      existing.provider = 'admin';
    }
    await this.save(this.usersFile, users);
  }

  async upsertUser(user) {
    const users = await this.users();
    const existing = users.find((item) => item.id === user.id);
    if (existing) Object.assign(existing, user);
    else {
      user.createdAt = user.createdAt || isoNow();
      users.push(user);
    }
    await this.save(this.usersFile, users);
    return existing || user;
  }

  async createSession(user) {
    const token = randomBytes(32).toString('base64url');
    const expires = new Date(Date.now() + SESSION_DAYS * 86400000);
    const sessions = (await this.sessions()).filter((item) => parseIso(item.expiresAt) > new Date());
    sessions.push({
      token,
      userId: user.id,
      role: user.role,
      createdAt: isoNow(),
      expiresAt: expires.toISOString(),
    });
    await this.save(this.sessionsFile, sessions);
    return { token, expiresAt: expires.toISOString(), user: this.publicUser(user) };
  }

  async userById(userId) {
    return (await this.users()).find((item) => item.id === userId) || null;
  }

  async sessionUser(token) {
    if (!token) return null;
    const record = (await this.sessions()).find((item) => item.token === token);
    if (!record || parseIso(record.expiresAt) <= new Date()) return null;
    return this.userById(record.userId);
  }

  async revoke(token) {
    if (!token) return;
    await this.save(this.sessionsFile, (await this.sessions()).filter((item) => item.token !== token));
  }

  sendPhoneOtp(phone) {
    if (!PHONE_RE.test(phone)) throw Object.assign(new Error('请输入正确的 11 位手机号'), { statusCode: 400 });
    const pending = this.otp.get(phone);
    if (pending && Date.now() - new Date(pending.sentAt).getTime() < OTP_RESEND_SECONDS * 1000) {
      throw Object.assign(new Error('验证码发送过于频繁，请稍后再试'), { statusCode: 400 });
    }
    const code = String(randomInt(0, 1_000_000)).padStart(6, '0');
    this.otp.set(phone, {
      code,
      verificationId: randomBytes(9).toString('base64url'),
      sentAt: isoNow(),
      expiresAt: new Date(Date.now() + OTP_TTL_SECONDS * 1000).toISOString(),
      attempts: 0,
    });
    const result = { ok: true, verificationId: this.otp.get(phone).verificationId, ttlSeconds: OTP_TTL_SECONDS };
    if (this.otpEcho) result.demoCode = code;
    return result;
  }

  async verifyPhoneOtp(phone, token) {
    if (!PHONE_RE.test(phone)) throw Object.assign(new Error('请输入正确的 11 位手机号'), { statusCode: 400 });
    const pending = this.otp.get(phone);
    if (!pending) throw Object.assign(new Error('请先获取当前手机号的验证码'), { statusCode: 400 });
    if (parseIso(pending.expiresAt) <= new Date()) {
      this.otp.delete(phone);
      throw Object.assign(new Error('验证码已过期，请重新获取'), { statusCode: 400 });
    }
    pending.attempts += 1;
    if (pending.attempts > 5) {
      this.otp.delete(phone);
      throw Object.assign(new Error('验证码错误次数过多，请重新获取'), { statusCode: 400 });
    }
    const a = Buffer.from(String(token).trim());
    const b = Buffer.from(pending.code);
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      throw Object.assign(new Error('验证码不正确'), { statusCode: 400 });
    }
    this.otp.delete(phone);
    const user = await this.upsertUser({
      id: `phone-${phone}`,
      role: this.adminPhones.has(phone) ? 'admin' : 'user',
      provider: 'phone',
      phone,
      displayName: `${phone.slice(0, 3)}****${phone.slice(-4)}`,
    });
    return this.createSession(user);
  }

  startWechat() {
    const ticket = randomBytes(12).toString('base64url');
    this.wechat.set(ticket, {
      status: 'pending',
      createdAt: isoNow(),
      expiresAt: new Date(Date.now() + WECHAT_TTL_SECONDS * 1000).toISOString(),
    });
    return { ticket, expiresIn: WECHAT_TTL_SECONDS, confirmHint: '本地演示：使用同一浏览器确认二维码' };
  }

  async pollWechat(ticket) {
    const record = this.wechat.get(ticket);
    if (!record) return { status: 'expired' };
    if (parseIso(record.expiresAt) <= new Date()) {
      this.wechat.delete(ticket);
      return { status: 'expired' };
    }
    if (record.status !== 'confirmed') return { status: 'pending' };
    const session = record.session;
    this.wechat.delete(ticket);
    return { status: 'confirmed', ...session };
  }

  async confirmWechat(ticket) {
    const record = this.wechat.get(ticket);
    if (!record) throw Object.assign(new Error('二维码已失效，请刷新后重试'), { statusCode: 400 });
    if (parseIso(record.expiresAt) <= new Date()) {
      this.wechat.delete(ticket);
      throw Object.assign(new Error('二维码已过期，请刷新后重试'), { statusCode: 400 });
    }
    const openid = `wx-${ticket.slice(0, 8)}`;
    const user = await this.upsertUser({
      id: `wechat-${openid}`,
      role: 'user',
      provider: 'wechat',
      wechatOpenId: openid,
      displayName: '微信用户',
    });
    record.status = 'confirmed';
    record.session = await this.createSession(user);
    return { ok: true };
  }

  async loginAdmin(username, password) {
    const user = (await this.users()).find((item) => item.username === username && item.role === 'admin');
    if (!user || !this.verifyPassword(password, user.passwordHash)) {
      throw Object.assign(new Error('管理员账号或密码不正确'), { statusCode: 400 });
    }
    return this.createSession(user);
  }
}
