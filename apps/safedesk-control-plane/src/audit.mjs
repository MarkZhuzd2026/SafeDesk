import { appendFile, chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';

/** Append-only audit log with pagination and retention pruning (REQ-AU-001/002/003). */
export class AuditLog {
  constructor(path, retentionDays = 30) {
    this.path = path;
    this.retentionDays = Number(retentionDays || 30);
    this._chain = this._init();
  }

  async _init() {
    await mkdir(dirname(this.path), { recursive: true });
    try {
      await readFile(this.path, 'utf8');
    } catch {
      await writeFile(this.path, '');
    }
    try { await chmod(this.path, 0o600); } catch { /* best effort */ }
  }

  append(event) {
    this._chain = this._chain.then(() => appendFile(this.path, `${JSON.stringify(event)}\n`));
    return this._chain;
  }

  async load() {
    await this._chain;
    const raw = await readFile(this.path, 'utf8');
    return raw
      .split('\n')
      .map((line) => { try { return JSON.parse(line); } catch { return null; } })
      .filter(Boolean);
  }

  async prune(now = new Date()) {
    const cutoff = now.getTime() / 1000 - this.retentionDays * 86400;
    const events = await this.load();
    const kept = [];
    let removed = 0;
    for (const event of events) {
      const at = Date.parse(event.at ?? '');
      if (Number.isNaN(at) || at / 1000 >= cutoff) kept.push(event);
      else removed += 1;
    }
    if (removed) {
      this._chain = this._chain.then(() => writeFile(this.path, `${kept.map((item) => JSON.stringify(item)).join('\n')}${kept.length ? '\n' : ''}`));
      await this._chain;
    }
    return removed;
  }

  async query({ keyword = '', level = '', action = '', since = null, limit = null, offset = 0 } = {}) {
    const events = (await this.load()).reverse();
    const needle = String(keyword || '').trim().toLowerCase();
    let result = events.filter((event) => {
      if (needle && ![event.action ?? '', event.detail ?? '', event.actor ?? ''].join(' ').toLowerCase().includes(needle)) return false;
      if (level && event.level !== level) return false;
      if (action && event.action !== action) return false;
      if (since && String(event.at ?? '') < String(since)) return false;
      return true;
    });
    if (offset) result = result.slice(offset);
    if (limit != null) result = result.slice(0, Math.max(0, Number(limit)));
    return result;
  }
}
