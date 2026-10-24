import { createHash, randomBytes } from 'node:crypto';
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';

/** Host-side credential broker: placeholders in sandbox, real values never leave the host (REQ-BR-001..011, 013). */
export const PLACEHOLDER_PREFIX = '{{SD_CRED_';
export const MAX_CREDENTIALS_PER_SANDBOX = 8;

export class CredentialBroker {
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

  static mask(value) {
    const raw = String(value || '');
    return raw.length > 4 ? `${raw.slice(0, 4)}****` : '****';
  }

  static digest(value) {
    return createHash('sha256').update(String(value)).digest('hex');
  }

  async put(name, value, allowedHosts = []) {
    const trimmed = String(name || '').trim();
    if (!trimmed || !value) throw new Error('凭据名称与值不能为空');
    const hosts = (allowedHosts || []).map((host) => String(host).trim().toLowerCase()).filter(Boolean);
    if (!hosts.length) throw new Error('必须声明至少一个允许的目的地主机');
    this._chain = this._chain.then(async () => {
      const items = await this._load();
      let item = items.find((entry) => entry.name === trimmed);
      if (!item) { item = { name: trimmed }; items.push(item); }
      item.value = String(value);
      item.allowedHosts = hosts;
      item.digest = CredentialBroker.digest(value);
      await this._save(items);
    });
    await this._chain;
    return { name: trimmed, allowedHosts: hosts, masked: CredentialBroker.mask(value) };
  }

  async listMasked() {
    await this._chain;
    return (await this._load()).map((item) => ({ name: item.name, allowedHosts: item.allowedHosts || [], masked: CredentialBroker.mask(item.value) }));
  }

  /** Internal lookup with the real value. Host-side use only. */
  async get(name) {
    await this._chain;
    return (await this._load()).find((item) => item.name === name) ?? null;
  }

  async remove(name) {
    let removed = false;
    this._chain = this._chain.then(async () => {
      const items = await this._load();
      const pruned = items.filter((item) => item.name !== name);
      removed = pruned.length !== items.length;
      if (removed) await this._save(pruned);
    });
    await this._chain;
    return removed;
  }

  async rotate(name, newValue) {
    const item = await this.get(name);
    if (!item) throw new Error('未知凭据');
    return this.put(name, newValue, item.allowedHosts || []);
  }

  issuePlaceholders(sandbox) {
    const mapping = {};
    for (const name of (sandbox.credentials || []).slice(0, MAX_CREDENTIALS_PER_SANDBOX)) {
      mapping[name] = `${PLACEHOLDER_PREFIX}${sandbox.id}_${randomBytes(8).toString('hex')}}}`;
    }
    return mapping;
  }

  static hostAllowed(target, allowedHosts = []) {
    const host = String(target || '').trim().toLowerCase().split(':')[0];
    return (allowedHosts || []).some((pattern) => {
      const raw = String(pattern || '').trim().toLowerCase();
      if (raw.startsWith('*.')) return host === raw.slice(2) || host.endsWith(raw.slice(1));
      return raw === host;
    });
  }

  async resolve(sandbox, capability, destinationHost) {
    if (sandbox.status !== 'running') return null;
    if (!(sandbox.credentials || []).includes(capability)) return null;
    const item = await this.get(capability);
    if (!item) return null;
    if (!CredentialBroker.hostAllowed(destinationHost, item.allowedHosts || [])) return null;
    return item.value ?? null;
  }
}
