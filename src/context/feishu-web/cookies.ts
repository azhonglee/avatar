import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

/**
 * RFC 6265 recording cookie jar with strict Feishu host allowlist and atomic 0600 credential store.
 * Cookies are private session material and must never be logged or passed to LLM prompts.
 */

export interface CookieRecord {
  name: string;
  value: string;
  domain: string;
  path: string;
  host_only?: boolean;
  expires_at?: string;
}

export interface WebLogin {
  cookies: CookieRecord[];
  owner_id: string;
  owner_name: string;
  /** 每次扫码登录生成的唯一会话代际标识，用于区分登出或重新登录，防止旧常驻进程覆盖新凭据 */
  session_id?: string;
  updated_at?: string;
}

export function isAllowedFeishuHost(host: string, extraAllowed?: Iterable<string>): boolean {
  const h = host.trim().toLowerCase();
  if (!h) return false;
  if (h === "feishu.cn" || h.endsWith(".feishu.cn") || h === "larkoffice.com" || h.endsWith(".larkoffice.com")) {
    return true;
  }
  if (extraAllowed) {
    for (const allowed of extraAllowed) {
      const a = allowed.trim().toLowerCase();
      if (a && (h === a || h.endsWith(`.${a}`))) return true;
    }
  }
  return false;
}

/** RFC 6265 §5.1.4 default-path algorithm. */
export function defaultCookiePath(urlPath: string): string {
  if (!urlPath || !urlPath.startsWith("/")) return "/";
  const last = urlPath.lastIndexOf("/");
  return last <= 0 ? "/" : urlPath.slice(0, last);
}

function domainMatches(host: string, domain: string, hostOnly: boolean): boolean {
  const h = host.toLowerCase();
  const d = domain.toLowerCase();
  if (hostOnly) return h === d;
  return h === d || h.endsWith(`.${d}`);
}

function pathMatches(reqPath: string, cookiePath: string): boolean {
  const p = reqPath || "/";
  if (p === cookiePath) return true;
  if (!p.startsWith(cookiePath)) return false;
  return cookiePath.endsWith("/") || p[cookiePath.length] === "/";
}

function isExpired(record: CookieRecord, nowMs: number): boolean {
  if (!record.expires_at) return false;
  const ts = Date.parse(record.expires_at);
  return Number.isFinite(ts) && ts <= nowMs;
}

interface ParsedSetCookie {
  name: string;
  value: string;
  domain: string;
  path: string;
  maxAge?: number;
  expires?: number;
}

export function parseSetCookieHeader(header: string): ParsedSetCookie | undefined {
  const parts = header.split(";");
  const first = parts[0]?.trim();
  if (!first) return undefined;
  const eq = first.indexOf("=");
  if (eq <= 0) return undefined;
  const name = first.slice(0, eq).trim();
  const value = first.slice(eq + 1).trim();
  if (!name) return undefined;

  let domain = "";
  let cookiePath = "";
  let maxAge: number | undefined;
  let expires: number | undefined;

  for (let i = 1; i < parts.length; i++) {
    const raw = parts[i].trim();
    if (!raw) continue;
    const idx = raw.indexOf("=");
    const attrName = (idx >= 0 ? raw.slice(0, idx) : raw).trim().toLowerCase();
    const attrVal = idx >= 0 ? raw.slice(idx + 1).trim() : "";
    if (attrName === "domain") {
      domain = attrVal.replace(/^\.+/, "").toLowerCase();
    } else if (attrName === "path") {
      cookiePath = attrVal;
    } else if (attrName === "max-age") {
      if (/^-?\d+$/.test(attrVal)) maxAge = Number(attrVal);
    } else if (attrName === "expires") {
      const ts = Date.parse(attrVal);
      if (Number.isFinite(ts)) expires = ts;
    }
  }

  return { name, value, domain, path: cookiePath, maxAge, expires };
}

export class RecordingCookieJar {
  private readonly values = new Map<string, CookieRecord>();
  private readonly extraAllowed?: Set<string>;

  constructor(extraAllowedHosts?: Iterable<string>) {
    if (extraAllowedHosts) {
      this.extraAllowed = new Set([...extraAllowedHosts].map((h) => h.trim().toLowerCase()).filter(Boolean));
    }
  }

  static fromRecords(cookies: CookieRecord[], extraAllowedHosts?: Iterable<string>, nowMs = Date.now()): RecordingCookieJar {
    const jar = new RecordingCookieJar(extraAllowedHosts);
    for (const c of cookies) {
      const domain = c.domain.replace(/^\.+/, "").toLowerCase();
      if (!c.name || !isAllowedFeishuHost(domain, jar.extraAllowed)) {
        throw new Error(`个人 Web 凭据包含非法 Cookie 域名：${c.domain || "(空)"}`);
      }
      if (isExpired(c, nowMs)) continue;
      const normalized: CookieRecord = {
        name: c.name,
        value: c.value,
        domain,
        path: c.path && c.path.startsWith("/") ? c.path : "/",
        ...(c.host_only ? { host_only: true } : {}),
        ...(c.expires_at ? { expires_at: c.expires_at } : {}),
      };
      jar.values.set(jar.keyOf(normalized), normalized);
    }
    return jar;
  }

  private keyOf(c: Pick<CookieRecord, "domain" | "path" | "name">): string {
    return `${c.domain}\0${c.path}\0${c.name}`;
  }

  /** Record Set-Cookie headers from one response, enforcing host allowlist and RFC 6265 scope. */
  setFromHeaders(requestUrl: URL, setCookieHeaders: string[] | string | undefined, nowMs = Date.now()): void {
    if (!setCookieHeaders) return;
    const host = requestUrl.hostname.toLowerCase();
    if (!isAllowedFeishuHost(host, this.extraAllowed)) return;
    const list = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
    for (const raw of list) {
      const parsed = parseSetCookieHeader(raw);
      if (!parsed) continue;
      const hostOnly = !parsed.domain;
      const domain = hostOnly ? host : parsed.domain;
      if (!hostOnly) {
        if (!isAllowedFeishuHost(domain, this.extraAllowed)) continue;
        if (host !== domain && !host.endsWith(`.${domain}`)) continue;
      }
      const scopePath = parsed.path && parsed.path.startsWith("/") ? parsed.path : defaultCookiePath(requestUrl.pathname);
      let expiresMs: number | undefined;
      if (parsed.maxAge !== undefined) {
        expiresMs = parsed.maxAge <= 0 ? 0 : nowMs + parsed.maxAge * 1000;
      } else if (parsed.expires !== undefined) {
        expiresMs = parsed.expires;
      }
      const remove = (parsed.maxAge !== undefined && parsed.maxAge <= 0) || (expiresMs !== undefined && expiresMs <= nowMs);
      const record: CookieRecord = {
        name: parsed.name,
        value: parsed.value,
        domain,
        path: scopePath,
        ...(hostOnly ? { host_only: true } : {}),
        ...(expiresMs && expiresMs > nowMs ? { expires_at: new Date(expiresMs).toISOString() } : {}),
      };
      const key = this.keyOf(record);
      if (remove) this.values.delete(key);
      else this.values.set(key, record);
    }
  }

  /** Return all non-expired matching cookies sorted by longest path first (RFC 6265 §5.4). */
  matching(requestUrl: URL, nowMs = Date.now()): CookieRecord[] {
    const host = requestUrl.hostname.toLowerCase();
    if (!isAllowedFeishuHost(host, this.extraAllowed)) return [];
    const reqPath = requestUrl.pathname || "/";
    const out: CookieRecord[] = [];
    for (const [key, rec] of this.values) {
      if (isExpired(rec, nowMs)) {
        this.values.delete(key);
        continue;
      }
      if (domainMatches(host, rec.domain, !!rec.host_only) && pathMatches(reqPath, rec.path)) {
        out.push(rec);
      }
    }
    out.sort((a, b) => b.path.length - a.path.length || a.name.localeCompare(b.name));
    return out;
  }

  cookieHeader(requestUrl: URL, nowMs = Date.now()): string {
    return this.matching(requestUrl, nowMs)
      .map((c) => `${c.name}=${c.value}`)
      .join("; ");
  }

  cookieValue(requestUrl: URL, name: string, nowMs = Date.now()): string {
    return this.matching(requestUrl, nowMs).find((c) => c.name === name)?.value ?? "";
  }

  /** Deterministic snapshot of live non-expired cookies for durable persistence. */
  records(nowMs = Date.now()): CookieRecord[] {
    const keys: string[] = [];
    for (const [key, rec] of this.values) {
      if (isExpired(rec, nowMs)) {
        this.values.delete(key);
        continue;
      }
      keys.push(key);
    }
    keys.sort();
    return keys.map((k) => ({ ...this.values.get(k)! }));
  }
}

export function hasSessionCookie(cookies: CookieRecord[]): boolean {
  return cookies.some((c) => c.name === "session" && c.value.length > 0);
}

/** Atomic 0600 JSON store for the owner's personal Feishu Web session. */
export class WebLoginStore {
  readonly file: string;

  constructor(dataDir: string, filename = "feishu-web.json") {
    this.file = path.join(dataDir, filename);
  }

  exists(): boolean {
    return fs.existsSync(this.file);
  }

  load(): WebLogin | undefined {
    if (!fs.existsSync(this.file)) return undefined;
    try {
      const parsed = JSON.parse(fs.readFileSync(this.file, "utf8")) as Partial<WebLogin>;
      if (!parsed || typeof parsed !== "object" || !Array.isArray(parsed.cookies) || typeof parsed.owner_id !== "string" || !parsed.owner_id) {
        return undefined;
      }
      return {
        cookies: parsed.cookies,
        owner_id: parsed.owner_id,
        owner_name: typeof parsed.owner_name === "string" ? parsed.owner_name : "",
        session_id: typeof parsed.session_id === "string" && parsed.session_id ? parsed.session_id : undefined,
        updated_at: typeof parsed.updated_at === "string" ? parsed.updated_at : undefined,
      };
    } catch {
      return undefined;
    }
  }

  currentSessionId(): string | undefined {
    return this.load()?.session_id;
  }

  private withLock<T>(fn: () => T): T {
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    const lockFile = `${this.file}.lock`;
    const deadline = Date.now() + 5_000;
    let lockFd: number | undefined;
    while (lockFd === undefined) {
      try {
        lockFd = fs.openSync(lockFile, "wx", 0o600);
      } catch (e) {
        const code = (e as NodeJS.ErrnoException).code;
        if (code !== "EEXIST") throw e;
        try {
          const st = fs.statSync(lockFile);
          if (Date.now() - st.mtimeMs > 30_000) {
            fs.rmSync(lockFile, { force: true });
            continue;
          }
        } catch {
          continue;
        }
        if (Date.now() >= deadline) throw new Error(`等待个人 Web 凭据文件锁超时：${lockFile}`);
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 15);
      }
    }
    try {
      fs.writeFileSync(lockFd, `${process.pid}\n`, "utf8");
      return fn();
    } finally {
      try {
        fs.closeSync(lockFd);
      } catch {
        // ignore close failure
      }
      fs.rmSync(lockFile, { force: true });
    }
  }

  private writeUnlocked(login: WebLogin): WebLogin {
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    const tmp = path.join(path.dirname(this.file), `.${path.basename(this.file)}.${process.pid}.${Date.now()}.tmp`);
    const payload: WebLogin = {
      owner_id: login.owner_id,
      owner_name: login.owner_name,
      session_id: login.session_id || crypto.randomUUID(),
      cookies: login.cookies,
      updated_at: new Date().toISOString(),
    };
    let fd: number | undefined;
    try {
      fd = fs.openSync(tmp, "w", 0o600);
      fs.writeFileSync(fd, JSON.stringify(payload, null, 2) + "\n", "utf8");
      fs.fsyncSync(fd);
      fs.closeSync(fd);
      fd = undefined;
      fs.chmodSync(tmp, 0o600);
      fs.renameSync(tmp, this.file);
    } catch (e) {
      if (fd !== undefined) {
        try {
          fs.closeSync(fd);
        } catch {
          // ignore close failure
        }
      }
      fs.rmSync(tmp, { force: true });
      throw e;
    }
    return payload;
  }

  save(login: WebLogin): WebLogin {
    return this.withLock(() => this.writeUnlocked(login));
  }

  /**
   * 跨进程加锁核验：仅当磁盘上的凭据文件仍然存在且属于同一会话代际（session_id + owner_id）时才写回轮换后的 Cookie。
   * 若已被 `web-logout` 清除或已被新一次 `web-login` 覆盖，返回 false 且绝不覆写。
   */
  saveIfSessionMatches(login: WebLogin): boolean {
    return this.withLock(() => {
      const current = this.load();
      if (!current) return false;
      if (current.owner_id !== login.owner_id) return false;
      if (current.session_id && login.session_id && current.session_id !== login.session_id) return false;
      if (current.session_id && !login.session_id) return false;
      this.writeUnlocked({ ...login, session_id: current.session_id ?? login.session_id });
      return true;
    });
  }

  clear(): void {
    this.withLock(() => {
      fs.rmSync(this.file, { force: true });
    });
  }
}
