import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

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
  /** 可选：若飞书资料接口返回 open_id，用于与 config.yaml 的 owner.open_id 做强身份绑定核验 */
  owner_open_id?: string;
  /** 每次扫码登录生成的唯一会话代际标识，用于区分登出或重新登录，防止旧常驻进程覆盖新凭据 */
  session_id?: string;
  /** 同会话代际内的单调递增 Cookie 版本号，防止多进程并发轮换 Cookie 时互相回滚 */
  cookie_version?: number;
  updated_at?: string;
}

export interface CookieDelta {
  upserts: CookieRecord[];
  deletes: string[];
  /** 每个发生变更的 Cookie 键在本客户端修改前的基准值（null 表示此前不存在），用于 3-way 冲突检测 */
  baseValues?: Record<string, string | null>;
}

/** 发起 HTTP 请求前捕获的 Cookie 罐代际快照，用于识别在途期间被磁盘同步轮换过的同键 Cookie */
export interface CookieSnapshot {
  generation: number;
  values: Map<string, string>;
}

export type WebLoginInspectResult =
  | { status: "ok"; login: WebLogin }
  | { status: "missing" | "missing_key" | "plaintext_rejected" | "invalid"; login?: undefined };

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
  private readonly dirtyUpserts = new Map<string, CookieRecord>();
  private readonly dirtyDeletes = new Set<string>();
  private readonly dirtyBaseValues = new Map<string, string | null>();
  private readonly extraAllowed?: Set<string>;
  private syncGeneration = 0;

  constructor(extraAllowedHosts?: Iterable<string>) {
    if (extraAllowedHosts) {
      this.extraAllowed = new Set([...extraAllowedHosts].map((h) => h.trim().toLowerCase()).filter(Boolean));
    }
  }

  /** 捕获请求发出时刻的 Cookie 代际与各键快照，防止请求在途期间 syncFromDisk() 轮换的 Cookie 被陈旧响应覆写 */
  snapshot(): CookieSnapshot {
    const snap = new Map<string, string>();
    for (const [k, v] of this.values) snap.set(k, v.value);
    return { generation: this.syncGeneration, values: snap };
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

  /** Record Set-Cookie headers from one response, enforcing host allowlist, RFC 6265 scope, and request-time snapshot conflict checks. */
  setFromHeaders(
    requestUrl: URL,
    setCookieHeaders: string[] | string | undefined,
    nowMs = Date.now(),
    requestSnapshot?: CookieSnapshot,
  ): boolean {
    if (!setCookieHeaders) return false;
    const host = requestUrl.hostname.toLowerCase();
    if (!isAllowedFeishuHost(host, this.extraAllowed)) return false;
    const list = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
    let applied = false;
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
      if (requestSnapshot && requestSnapshot.generation !== this.syncGeneration) {
        const sentBase = requestSnapshot.values.get(key) ?? null;
        const curVal = this.values.get(key)?.value ?? null;
        // 请求在途期间磁盘同步已轮换了该 Cookie：拒绝用陈旧响应覆盖较新的轮换值
        if (curVal !== sentBase) continue;
        if (!this.dirtyBaseValues.has(key)) this.dirtyBaseValues.set(key, sentBase);
      } else if (!this.dirtyBaseValues.has(key)) {
        const base = requestSnapshot ? (requestSnapshot.values.get(key) ?? null) : (this.values.get(key)?.value ?? null);
        this.dirtyBaseValues.set(key, base);
      }
      if (remove) {
        this.values.delete(key);
        this.dirtyUpserts.delete(key);
        this.dirtyDeletes.add(key);
      } else {
        this.values.set(key, record);
        this.dirtyDeletes.delete(key);
        this.dirtyUpserts.set(key, { ...record });
      }
      applied = true;
    }
    return applied;
  }

  /** 读取自上次持久化以来本客户端实际收到的 Set-Cookie 增量及基准值，用于同会话多进程 3-way 冲突检测与合并 */
  peekDelta(): CookieDelta {
    const baseValues: Record<string, string | null> = {};
    for (const [k, v] of this.dirtyBaseValues) baseValues[k] = v;
    return {
      upserts: [...this.dirtyUpserts.values()].map((c) => ({ ...c })),
      deletes: [...this.dirtyDeletes],
      baseValues,
    };
  }

  clearDelta(): void {
    this.dirtyUpserts.clear();
    this.dirtyDeletes.clear();
    this.dirtyBaseValues.clear();
  }

  /**
   * 用磁盘上更新版本的同会话 Cookie 快照刷新内存罐：
   *   - 默认（刚完成持久化后调用）清空本地增量；
   *   - `preservePendingDelta: true`（后台 watcher 同步磁盘更新时调用）将本进程尚未落盘的增量按 `dirtyBaseValues` 做 3-way 合并：
   *     若磁盘未改该键则保留本进程刚轮换的新 Cookie（避免重定向途中的 session 轮换被无关 Cookie 同步回滚），同键冲突则采纳磁盘更新值。
   */
  syncFromRecords(cookies: CookieRecord[], nowMs = Date.now(), opts: { preservePendingDelta?: boolean } = {}): void {
    const next = new Map<string, CookieRecord>();
    for (const c of cookies) {
      const domain = c.domain.replace(/^\.+/, "").toLowerCase();
      if (!c.name || !isAllowedFeishuHost(domain, this.extraAllowed)) continue;
      if (isExpired(c, nowMs)) continue;
      const normalized: CookieRecord = {
        name: c.name,
        value: c.value,
        domain,
        path: c.path && c.path.startsWith("/") ? c.path : "/",
        ...(c.host_only ? { host_only: true } : {}),
        ...(c.expires_at ? { expires_at: c.expires_at } : {}),
      };
      next.set(this.keyOf(normalized), normalized);
    }
    if (opts.preservePendingDelta) {
      const survivingUpserts = new Map<string, CookieRecord>();
      const survivingDeletes = new Set<string>();
      const survivingBases = new Map<string, string | null>();

      for (const key of this.dirtyDeletes) {
        const diskVal = next.get(key)?.value ?? null;
        const baseVal = this.dirtyBaseValues.get(key);
        if (baseVal !== undefined && diskVal === baseVal) {
          next.delete(key);
          survivingDeletes.add(key);
          survivingBases.set(key, baseVal);
        }
      }
      for (const [key, rec] of this.dirtyUpserts) {
        if (isExpired(rec, nowMs)) continue;
        const diskVal = next.get(key)?.value ?? null;
        const baseVal = this.dirtyBaseValues.get(key);
        if (baseVal !== undefined && diskVal === baseVal) {
          next.set(key, { ...rec });
          survivingUpserts.set(key, { ...rec });
          survivingBases.set(key, baseVal);
        }
      }

      this.values.clear();
      for (const [k, v] of next) this.values.set(k, v);
      this.syncGeneration++;
      this.dirtyUpserts.clear();
      for (const [k, v] of survivingUpserts) this.dirtyUpserts.set(k, v);
      this.dirtyDeletes.clear();
      for (const k of survivingDeletes) this.dirtyDeletes.add(k);
      this.dirtyBaseValues.clear();
      for (const [k, v] of survivingBases) this.dirtyBaseValues.set(k, v);
      return;
    }

    this.values.clear();
    for (const [k, v] of next) this.values.set(k, v);
    this.syncGeneration++;
    this.clearDelta();
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

interface EncryptedEnvelope {
  v: 1;
  alg: "aes-256-gcm";
  iv: string;
  tag: string;
  ciphertext: string;
}

function resolveEncryptionKey(): Buffer | undefined {
  const envKey = process.env.PA_FEISHU_WEB_KEY?.trim();
  if (envKey) return crypto.createHash("sha256").update(envKey, "utf8").digest();
  const credDir = process.env.CREDENTIALS_DIRECTORY?.trim();
  if (credDir) {
    const keyFile = path.join(credDir, "feishu-web-key");
    try {
      const raw = fs.readFileSync(keyFile, "utf8").trim();
      if (raw) return crypto.createHash("sha256").update(raw, "utf8").digest();
    } catch {
      // key file absent
    }
  }
  return undefined;
}

function isEncryptedEnvelope(v: unknown): v is EncryptedEnvelope {
  if (!v || typeof v !== "object") return false;
  const o = v as Record<string, unknown>;
  return o.v === 1 && o.alg === "aes-256-gcm" && typeof o.iv === "string" && typeof o.tag === "string" && typeof o.ciphertext === "string";
}

function encryptPayload(plaintext: string, key: Buffer): EncryptedEnvelope {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return {
    v: 1,
    alg: "aes-256-gcm",
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    ciphertext: ciphertext.toString("base64"),
  };
}

function decryptPayload(env: EncryptedEnvelope, key: Buffer): string {
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(env.iv, "base64"));
  decipher.setAuthTag(Buffer.from(env.tag, "base64"));
  const plain = Buffer.concat([decipher.update(Buffer.from(env.ciphertext, "base64")), decipher.final()]);
  return plain.toString("utf8");
}

/**
 * Atomic 0600 encrypted credential store for the owner's personal Feishu Web session.
 *   - 强制使用 AES-256-GCM 静态加密（密钥来自 `PA_FEISHU_WEB_KEY` 或 systemd `CREDENTIALS_DIRECTORY/feishu-web-key`），
 *     绝不以明文将可复用会话 Cookie 写入磁盘（所有子模型 harness 均自动剥离该密钥）；
 *   - 缺少密钥时拒绝写入或降级覆盖既有加密凭据；
 *   - 支持通过 `PA_FEISHU_WEB_CRED_FILE` 将凭据存放在工作区外；
 *   - 跨进程互斥复用 Node 22 内置 SQLite (`BEGIN IMMEDIATE`) 的内核级 POSIX 文件锁，崩溃由操作系统自动原子释放，无陈旧锁竞态。
 */
export class WebLoginStore {
  readonly file: string;
  readonly lockFile: string;
  private readonly lockTimeoutMs: number;

  constructor(dataDir: string, filename = "feishu-web.json", lockTimeoutMs = 5_000) {
    const external = process.env.PA_FEISHU_WEB_CRED_FILE?.trim();
    this.file = external ? path.resolve(external) : path.join(dataDir, filename);
    this.lockFile = `${this.file}.lock.db`;
    this.lockTimeoutMs = Math.max(100, Math.trunc(lockTimeoutMs));
  }

  static hasEncryptionKey(): boolean {
    return resolveEncryptionKey() !== undefined;
  }

  exists(): boolean {
    return fs.existsSync(this.file);
  }

  private hasExistingEncryptedFile(): boolean {
    if (!fs.existsSync(this.file)) return false;
    try {
      const rawJson = JSON.parse(fs.readFileSync(this.file, "utf8")) as unknown;
      return isEncryptedEnvelope(rawJson);
    } catch {
      return false;
    }
  }

  inspect(): WebLoginInspectResult {
    if (!fs.existsSync(this.file)) return { status: "missing" };
    let rawJson: unknown;
    try {
      rawJson = JSON.parse(fs.readFileSync(this.file, "utf8")) as unknown;
    } catch {
      return { status: "invalid" };
    }
    if (!isEncryptedEnvelope(rawJson)) {
      return { status: "plaintext_rejected" };
    }
    const key = resolveEncryptionKey();
    if (!key) {
      return { status: "missing_key" };
    }
    try {
      const parsed = JSON.parse(decryptPayload(rawJson, key)) as Partial<WebLogin>;
      if (!parsed || typeof parsed !== "object" || !Array.isArray(parsed.cookies) || typeof parsed.owner_id !== "string" || !parsed.owner_id) {
        return { status: "invalid" };
      }
      return {
        status: "ok",
        login: {
          cookies: parsed.cookies,
          owner_id: parsed.owner_id,
          owner_name: typeof parsed.owner_name === "string" ? parsed.owner_name : "",
          owner_open_id: typeof parsed.owner_open_id === "string" && parsed.owner_open_id ? parsed.owner_open_id : undefined,
          session_id: typeof parsed.session_id === "string" && parsed.session_id ? parsed.session_id : undefined,
          cookie_version: typeof parsed.cookie_version === "number" && Number.isFinite(parsed.cookie_version) ? parsed.cookie_version : 1,
          updated_at: typeof parsed.updated_at === "string" ? parsed.updated_at : undefined,
        },
      };
    } catch {
      return { status: "invalid" };
    }
  }

  load(): WebLogin | undefined {
    const res = this.inspect();
    return res.status === "ok" ? res.login : undefined;
  }

  currentSessionId(): string | undefined {
    return this.load()?.session_id;
  }

  /**
   * 跨进程原子文件锁（复用 Node 22 内置 SQLite `BEGIN IMMEDIATE` 的内核级 POSIX 文件锁）：
   *   - 持锁进程异常退出（含 SIGKILL）时由操作系统内核原子释放，不存在陈旧锁清理竞态；
   *   - 锁文件权限固定 0600 且永不 unlink 避免 inode 错配；
   *   - 若锁文件不可读/权限错误立即抛错，不会空转阻塞事件循环；
   *   - 竞争等待严格受 `lockTimeoutMs`（默认 5000ms）约束。
   */
  private withLock<T>(fn: () => T): T {
    const dir = path.dirname(this.file);
    fs.mkdirSync(dir, { recursive: true });
    if (!fs.existsSync(this.lockFile)) {
      const fd = fs.openSync(this.lockFile, "a", 0o600);
      fs.closeSync(fd);
    }
    const db = new DatabaseSync(this.lockFile);
    let locked = false;
    try {
      db.exec(`PRAGMA busy_timeout = ${this.lockTimeoutMs}`);
      db.exec("BEGIN IMMEDIATE");
      locked = true;
      return fn();
    } finally {
      if (locked) {
        try {
          db.exec("ROLLBACK");
        } catch {
          // ignore
        }
      }
      db.close();
    }
  }

  private writeUnlocked(login: WebLogin, cookieVersion: number): WebLogin {
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    const key = resolveEncryptionKey();
    if (!key) {
      if (this.hasExistingEncryptedFile()) {
        throw new Error(
          "检测到已有加密的个人 Web 凭据文件，但当前环境缺少解密密钥（PA_FEISHU_WEB_KEY 或 CREDENTIALS_DIRECTORY/feishu-web-key），拒绝降级覆盖",
        );
      }
      throw new Error(
        "保存个人 Web 凭据必须配置静态加密密钥（设置环境变量 PA_FEISHU_WEB_KEY 或通过 systemd LoadCredential 提供 CREDENTIALS_DIRECTORY/feishu-web-key），禁止明文写入磁盘",
      );
    }
    const tmp = path.join(path.dirname(this.file), `.${path.basename(this.file)}.${process.pid}.${Date.now()}.tmp`);
    const payload: WebLogin = {
      owner_id: login.owner_id,
      owner_name: login.owner_name,
      ...(login.owner_open_id ? { owner_open_id: login.owner_open_id } : {}),
      session_id: login.session_id || crypto.randomUUID(),
      cookie_version: cookieVersion,
      cookies: login.cookies,
      updated_at: new Date().toISOString(),
    };
    const serialized = JSON.stringify(encryptPayload(JSON.stringify(payload), key), null, 2) + "\n";
    let fd: number | undefined;
    try {
      fd = fs.openSync(tmp, "w", 0o600);
      fs.writeFileSync(fd, serialized, "utf8");
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
    return this.withLock(() => this.writeUnlocked(login, 1));
  }

  /** 在持跨进程凭据文件锁期间执行自定义校验并原子写入，用于串行化工作区绑定核验与凭据替换 */
  commitWithLock<T>(fn: (write: (login: WebLogin) => WebLogin) => T): T {
    return this.withLock(() => fn((login) => this.writeUnlocked(login, 1)));
  }

  /**
   * 跨进程加锁核验并按 3-way 版本合并：
   *   - 若磁盘凭据已被 web-logout 删除或已被新一次 web-login（不同 session_id / owner_id）替换，返回 null 且绝不覆写；
   *   - 若同会话内另一进程已写入更高版本 Cookie：对每个变更的键核对其基准值（delta.baseValues）；
   *     * 若磁盘上该键未被其他进程改动（无冲突），合入该键变更；
   *     * 若磁盘上该键已被其他进程轮换（同键冲突），保留磁盘最新值绝不回滚，并返回最新磁盘快照供本进程同步。
   */
  saveIfSessionMatches(login: WebLogin, delta?: CookieDelta): WebLogin | null {
    return this.withLock(() => {
      const current = this.load();
      if (!current) return null;
      if (current.owner_id !== login.owner_id) return null;
      if (current.session_id && login.session_id && current.session_id !== login.session_id) return null;
      if (current.session_id && !login.session_id) return null;

      const curVer = current.cookie_version ?? 1;
      const baseVer = login.cookie_version ?? curVer;
      const hasDelta = !!delta && (delta.upserts.length > 0 || delta.deletes.length > 0);

      if (curVer > baseVer) {
        if (!hasDelta) return current;
        const merged = new Map<string, CookieRecord>();
        const keyOf = (c: Pick<CookieRecord, "domain" | "path" | "name">) =>
          `${c.domain.replace(/^\.+/, "").toLowerCase()}\0${c.path || "/"}\0${c.name}`;
        for (const c of current.cookies) merged.set(keyOf(c), c);
        const baseValues = delta.baseValues ?? {};
        let appliedNonConflicting = false;

        for (const k of delta.deletes) {
          const curVal = merged.get(k)?.value ?? null;
          const baseVal = k in baseValues ? baseValues[k] : undefined;
          // 仅当磁盘当前值仍等于本客户端修改前的基准值才应用删除，否则保留其他进程写入的新值
          if (baseVal !== undefined && curVal === baseVal) {
            merged.delete(k);
            appliedNonConflicting = true;
          }
        }
        for (const c of delta.upserts) {
          const k = keyOf(c);
          const curVal = merged.get(k)?.value ?? null;
          const baseVal = k in baseValues ? baseValues[k] : undefined;
          // 同键已被其他进程轮换（curVal !== baseVal）：绝不用陈旧响应覆盖更新后的 Cookie
          if (baseVal === undefined || curVal !== baseVal) continue;
          merged.set(k, c);
          appliedNonConflicting = true;
        }
        if (!appliedNonConflicting) return current;
        return this.writeUnlocked(
          {
            ...current,
            owner_name: login.owner_name || current.owner_name,
            owner_open_id: login.owner_open_id || current.owner_open_id,
            cookies: [...merged.values()],
          },
          curVer + 1,
        );
      }

      if (delta && !hasDelta && login.owner_name === current.owner_name && (!login.owner_open_id || login.owner_open_id === current.owner_open_id)) {
        return current;
      }

      return this.writeUnlocked(
        {
          ...login,
          owner_open_id: login.owner_open_id || current.owner_open_id,
          session_id: current.session_id ?? login.session_id,
        },
        curVer + 1,
      );
    });
  }

  clear(): void {
    this.withLock(() => {
      fs.rmSync(this.file, { force: true });
    });
  }
}
