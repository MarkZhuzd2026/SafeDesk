import { randomBytes } from 'node:crypto';
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';

/** Traveler card registry (携程公务出行场景) — real identity host-side, placeholders in sandbox. */
const HANDLE_RE = /^[\w-]{3,32}$/;
const IDCARD_RE = /^\d{17}[\dXx]$/;
const PHONE_RE = /^1[3-9]\d{9}$/;
const PASSPORT_RE = /^[A-Za-z0-9]{5,20}$/;
export const TRAVELER_FIELDS = ['name', 'idCard', 'passport', 'phone'];
export const MAX_TRAVELERS_PER_SANDBOX = 4;

export class TravelerRegistry {
  constructor(path) {
    this.path = path;
    this._chain = this._init();
  }

  async _init() {
    await mkdir(dirname(this.path), { recursive: true });
    try {
      await readFile(this.path, 'utf8');
    } catch {
      await writeFile(this.path, '[]\n');
    }
    try { await chmod(this.path, 0o600); } catch { /* best effort */ }
  }

  async _load() {
    try { return JSON.parse(await readFile(this.path, 'utf8')); } catch { return []; }
  }

  async _save(items) {
    await writeFile(this.path, `${JSON.stringify(items, null, 2)}\n`);
    try { await chmod(this.path, 0o600); } catch { /* best effort */ }
  }

  static _masked(card) {
    const name = card.name || '';
    const idCard = card.idCard || '';
    const phone = card.phone || '';
    const passport = card.passport || null;
    return {
      handle: card.handle,
      name: name.length > 1 ? `${name.slice(0, 1)}*` : name,
      idCard: idCard.length >= 8 ? `${idCard.slice(0, 4)}${'*'.repeat(10)}${idCard.slice(-2)}` : '****',
      phone: phone.length === 11 ? `${phone.slice(0, 3)}****${phone.slice(-4)}` : '****',
      passport: passport ? `${passport.slice(0, 3)}******` : null,
      allowedHosts: card.allowedHosts || [],
    };
  }

  async register(handle, name, idCard, phone, allowedHosts, passport = null) {
    const trimmed = String(handle || '').trim();
    if (!HANDLE_RE.test(trimmed)) throw new Error('handle 需为 3-32 位字母数字下划线');
    if (!name || !String(name).trim()) throw new Error('姓名不能为空');
    if (!IDCARD_RE.test(idCard || '')) throw new Error('身份证号格式不正确');
    if (!PHONE_RE.test(phone || '')) throw new Error('手机号格式不正确');
    if (passport && !PASSPORT_RE.test(passport)) throw new Error('护照号格式不正确');
    const hosts = (allowedHosts || []).map((host) => String(host).trim().toLowerCase()).filter(Boolean);
    if (!hosts.length) throw new Error('必须声明至少一个允许的目的地主机');
    const card = {
      handle: trimmed, name: String(name).trim(), idCard, phone,
      passport: passport || '', allowedHosts: hosts,
    };
    this._chain = this._chain.then(async () => {
      const items = (await this._load()).filter((item) => item.handle !== trimmed);
      items.push(card);
      await this._save(items);
    });
    await this._chain;
    return TravelerRegistry._masked(card);
  }

  async listMasked() {
    await this._chain;
    return (await this._load()).map((card) => TravelerRegistry._masked(card));
  }

  /** Internal lookup with real values. Host-side use only. */
  async get(handle) {
    await this._chain;
    return (await this._load()).find((card) => card.handle === handle) ?? null;
  }

  async remove(handle) {
    let removed = false;
    this._chain = this._chain.then(async () => {
      const items = await this._load();
      const pruned = items.filter((card) => card.handle !== handle);
      removed = pruned.length !== items.length;
      if (removed) await this._save(pruned);
    });
    await this._chain;
    return removed;
  }

  issuePlaceholders(sandbox) {
    const mapping = {};
    for (const handle of (sandbox.travelerCards || []).slice(0, MAX_TRAVELERS_PER_SANDBOX)) {
      const slot = randomBytes(4).toString('hex');
      mapping[handle] = Object.fromEntries(
        TRAVELER_FIELDS.map((field) => [field, `{{SD_TRV_${sandbox.id}_${handle}_${field}_${slot}}}`]),
      );
    }
    return mapping;
  }

  async resolveInjections(sandbox) {
    const injections = {};
    for (const [handle, fields] of Object.entries(sandbox.travelerPlaceholders || {})) {
      const card = await this.get(handle);
      if (!card) continue;
      for (const [field, placeholder] of Object.entries(fields)) {
        if (card[field]) {
          injections[placeholder] = { value: card[field], hosts: card.allowedHosts || [] };
        }
      }
    }
    return injections;
  }
}
