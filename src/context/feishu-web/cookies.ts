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

const MAX_COOKIE_DATE_MS = 8_640_000_000_000_000;

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

  /** 复制当前内存 Cookie 视图供单次请求的重定向跳暂存叠算使用，保留 syncGeneration 以便校验并发轮换冲突，且不修改共享活罐 */
  clone(): RecordingCookieJar {
    const copy = new RecordingCookieJar(this.extraAllowed);
    copy.syncGeneration = this.syncGeneration;
    for (const [k, v] of this.values) copy.values.set(k, { ...v });
    return copy;
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
    selfWrittenKeys?: Set<string>,
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
        if (parsed.maxAge <= 0) {
          expiresMs = 0;
        } else {
          const rawExp = nowMs + parsed.maxAge * 1000;
          expiresMs = Number.isFinite(rawExp) ? Math.min(rawExp, MAX_COOKIE_DATE_MS) : MAX_COOKIE_DATE_MS;
        }
      } else if (parsed.expires !== undefined && Number.isFinite(parsed.expires)) {
        expiresMs = parsed.expires <= 0 ? 0 : Math.min(parsed.expires, MAX_COOKIE_DATE_MS);
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
      if (requestSnapshot && requestSnapshot.generation !== this.syncGeneration && !selfWrittenKeys?.has(key)) {
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
      selfWrittenKeys?.add(key);
      applied = true;
    }
    return applied;
  }

  /**
   * 批量提交单次请求各重定向跳暂存的 Set-Cookie 变更：
   *   - 同请求多跳连续更新同一 Cookie 时经 selfWritten 放行后续跳；
   *   - 与并发 syncFromRecords() 发生冲突的键保留磁盘较新轮换值，无关并发轮换完全保留。
   */
  applyStaged(
    entries: { url: URL; headers: string[] | string; nowMs: number; snapshot: CookieSnapshot }[],
  ): boolean {
    const selfWritten = new Set<string>();
    let applied = false;
    for (const e of entries) {
      if (this.setFromHeaders(e.url, e.headers, e.nowMs, e.snapshot, selfWritten)) {
        applied = true;
      }
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
export interface PendingCommitKvStore {
  get(k: string): string | undefined;
  set(k: string, v: string): void;
  db?: DatabaseSync;
}

/**
 * 原子条件清除工作区共享的 pending_cred_commit 标记：
 * 仅当当前 SQLite 标记仍对应本次安装的 file 与 session_id 时才清除，
 * 避免两条使用不同凭据路径的并发 web-login 互相抹除对方的未完成暂存提交标记。
 */
export function clearPendingCommitMarkerIfMatches(
  store: PendingCommitKvStore,
  pendingKey: string,
  expected: { file: string; sessionId: string; rawMarker?: string },
): boolean {
  const expectedFile = path.resolve(expected.file);
  const expectedSid = expected.sessionId;
  const matches = (raw: string | undefined): boolean => {
    const t = (raw ?? "").trim();
    if (!t) return false;
    if (expected.rawMarker !== undefined && t === expected.rawMarker.trim()) return true;
    try {
      const obj = JSON.parse(t) as Record<string, unknown>;
      const f = typeof obj.file === "string" ? path.resolve(obj.file) : "";
      const sid = typeof obj.session_id === "string" ? obj.session_id : "";
      return !!f && f === expectedFile && sid === expectedSid;
    } catch {
      return false;
    }
  };

  if (store.db) {
    store.db.exec("BEGIN IMMEDIATE");
    try {
      const cur = store.get(pendingKey);
      if (!matches(cur)) {
        store.db.exec("COMMIT");
        return false;
      }
      store.set(pendingKey, "");
      store.db.exec("COMMIT");
      return true;
    } catch (err) {
      try {
        store.db.exec("ROLLBACK");
      } catch {
        // ignore
      }
      throw err;
    }
  }
  if (!matches(store.get(pendingKey))) return false;
  store.set(pendingKey, "");
  return true;
}

/**
 * 同步父目录元数据，确保 rename 在掉电后也持久化到目录项（某些平台不支持目录 fsync 时安全忽略）
 */
function fsyncDir(dirPath: string): void {
  try {
    const fd = fs.openSync(dirPath, "r");
    try {
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    // 部分文件系统或平台不支持目录 fsync，尽力持久化
  }
}

export class WebLoginStore {
  readonly file: string;
  readonly lockFile: string;
  readonly stagedFile: string;
  /** 是否通过 PA_FEISHU_WEB_CRED_FILE 指向外部可能跨工作区共享的凭据文件 */
  readonly isExternal: boolean;
  private readonly lockTimeoutMs: number;

  constructor(dataDir: string, filename = "feishu-web.json", lockTimeoutMs = 5_000) {
    const external = process.env.PA_FEISHU_WEB_CRED_FILE?.trim();
    this.isExternal = !!external;
    this.file = external ? path.resolve(external) : path.join(dataDir, filename);
    this.lockFile = `${this.file}.lock.db`;
    // 多个 data_dir 指向同一个外部 PA_FEISHU_WEB_CRED_FILE 时，按工作区 dataDir 隔离各自暂存文件，
    // 避免工作区 B 启动/查状态时误删工作区 A 崩溃尚未 rename 的已提交暂存凭据
    const wsTag = crypto.createHash("sha256").update(path.resolve(dataDir)).digest("hex").slice(0, 12);
    this.stagedFile = external ? `${this.file}.${wsTag}.staged` : `${this.file}.staged`;
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

  inspectPath(targetFile: string): WebLoginInspectResult {
    if (!fs.existsSync(targetFile)) return { status: "missing" };
    let rawJson: unknown;
    try {
      rawJson = JSON.parse(fs.readFileSync(targetFile, "utf8")) as unknown;
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

  inspect(): WebLoginInspectResult {
    return this.inspectPath(this.file);
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

  private writeTargetUnlocked(targetPath: string, login: WebLogin, cookieVersion: number): WebLogin {
    fs.mkdirSync(path.dirname(targetPath), { recursive: true });
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
    const tmp = path.join(path.dirname(targetPath), `.${path.basename(targetPath)}.${process.pid}.${Date.now()}.tmp`);
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
      fs.renameSync(tmp, targetPath);
      fsyncDir(path.dirname(targetPath));
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

  private writeUnlocked(login: WebLogin, cookieVersion: number): WebLogin {
    return this.writeTargetUnlocked(this.file, login, cookieVersion);
  }

  save(login: WebLogin): WebLogin {
    return this.withLock(() => this.writeUnlocked(login, 1));
  }

  /** 在持跨进程凭据文件锁期间执行自定义校验并原子写入，用于串行化工作区绑定核验与凭据替换 */
  commitWithLock<T>(fn: (write: (login: WebLogin) => WebLogin) => T): T {
    return this.withLock(() => fn((login) => this.writeUnlocked(login, 1)));
  }

  private snapshotLiveFileUnlocked(): { sha256: string; sessionId: string } {
    if (!fs.existsSync(this.file)) return { sha256: "", sessionId: "" };
    let sha256 = "";
    try {
      sha256 = crypto.createHash("sha256").update(fs.readFileSync(this.file)).digest("hex");
    } catch {
      sha256 = "";
    }
    const cur = this.load();
    return { sha256, sessionId: cur?.session_id ?? "" };
  }

  /**
   * 两阶段可恢复暂存提交（跨进程锁保护）：
   *   1. `stage(login)` 记录当前现网凭据代际（`prevFileSha256` / `prevSessionId`）并将新加密凭据 fsync 到 `<file>.staged`，暂不覆盖现网 `<file>`；
   *   2. 调用方在 SQLite 事务内写入绑定与 pending 标记（含 `prev_file_sha256` / `prev_session_id`）并 COMMIT；
   *   3. SQLite COMMIT 成功后调用 `commitFile()` 原子 rename `<file>.staged -> <file>`；
   *   4. 若 SQLite 回滚则调用 `abortFile()` 清理暂存文件，旧凭据纹丝不动；
   *   5. 若进程在 COMMIT 与 rename 之间崩溃，后续 `reconcilePendingCommit()` 会在锁内比对现网代际：
   *      仅当现网文件仍处于暂存前的同一代际时补全 rename，若共享文件已被其他工作区安装更新会话则丢弃陈旧暂存文件而不覆盖。
   */
  stageWithLock<T>(
    fn: (
      stage: (login: WebLogin) => {
        payload: WebLogin;
        prevFileSha256: string;
        prevSessionId: string;
        commitFile: () => void;
        abortFile: () => void;
      },
    ) => T,
  ): T {
    return this.withLock(() =>
      fn((login) => {
        const prev = this.snapshotLiveFileUnlocked();
        const payload = this.writeTargetUnlocked(this.stagedFile, login, 1);
        return {
          payload,
          prevFileSha256: prev.sha256,
          prevSessionId: prev.sessionId,
          commitFile: () => {
            fs.renameSync(this.stagedFile, this.file);
            fsyncDir(path.dirname(this.file));
          },
          abortFile: () => {
            fs.rmSync(this.stagedFile, { force: true });
          },
        };
      }),
    );
  }

  /**
   * 崩溃恢复协调（严格绑定目标凭据文件路径、session_id 与暂存前现网代际）：
   *   - 若 pending 标记指向另一个凭据路径（例如常驻进程用了 PA_FEISHU_WEB_CRED_FILE 而交互 CLI 用默认路径），直接忽略不清除标记也不删他人暂存文件；
   *   - 若 pending 标记绑定本路径：先在锁内核对现网文件是否已被其他工作区/更新登录替换；
   *     * 仅当现网文件仍与 `prev_file_sha256` 一致（或非外部共享文件同旧会话）时补全 rename；
   *     * 若现网已安装更新会话，直接清理陈旧 `.staged` 并清除过期 pending 标记，绝不覆盖更新会话；
   *   - 若 SQLite 无 pending 标记且本路径残留孤儿 `.staged`，安全清理。
   */
  reconcilePendingCommit(
    store: PendingCommitKvStore,
    pendingKey: string,
  ): void {
    const parsePending = (
      raw: string | undefined,
    ):
      | {
          file?: string;
          staged_file?: string;
          owner_id?: string;
          session_id?: string;
          prev_file_sha256?: string;
          prev_session_id?: string;
          at?: number;
        }
      | undefined => {
      const t = (raw ?? "").trim();
      if (!t) return undefined;
      try {
        const obj = JSON.parse(t) as Record<string, unknown>;
        return {
          file: typeof obj.file === "string" ? obj.file : undefined,
          staged_file: typeof obj.staged_file === "string" ? obj.staged_file : undefined,
          owner_id: typeof obj.owner_id === "string" ? obj.owner_id : undefined,
          session_id: typeof obj.session_id === "string" ? obj.session_id : undefined,
          prev_file_sha256: typeof obj.prev_file_sha256 === "string" ? obj.prev_file_sha256 : undefined,
          prev_session_id: typeof obj.prev_session_id === "string" ? obj.prev_session_id : undefined,
          at: typeof obj.at === "number" && Number.isFinite(obj.at) ? obj.at : undefined,
        };
      } catch {
        return {};
      }
    };

    const initialPending = parsePending(store.get(pendingKey));
    if (initialPending?.file && path.resolve(initialPending.file) !== path.resolve(this.file)) {
      return;
    }
    const legacyStagedFile = `${this.file}.staged`;
    const initialStagedPath = initialPending?.staged_file
      ? path.resolve(initialPending.staged_file)
      : fs.existsSync(this.stagedFile)
        ? this.stagedFile
        : legacyStagedFile;
    const hasStaged = fs.existsSync(this.stagedFile) || (!!initialPending && fs.existsSync(initialStagedPath));
    if (!initialPending && !hasStaged) return;
    try {
      this.withLock(() => {
        const rawPendingNow = store.get(pendingKey);
        const pendingNow = parsePending(rawPendingNow);
        if (pendingNow?.file && path.resolve(pendingNow.file) !== path.resolve(this.file)) {
          return;
        }
        const resolvedSelfStaged = path.resolve(this.stagedFile);
        const resolvedLegacyStaged = path.resolve(legacyStagedFile);
        const stagedPath = pendingNow?.staged_file
          ? path.resolve(pendingNow.staged_file)
          : fs.existsSync(this.stagedFile)
            ? resolvedSelfStaged
            : resolvedLegacyStaged;
        const stagedNow = fs.existsSync(stagedPath);
        if (pendingNow) {
          let resolved = false;
          const liveSnap = this.snapshotLiveFileUnlocked();
          const cur = this.load();
          const alreadyInstalled =
            !!cur &&
            (!pendingNow.owner_id || cur.owner_id === pendingNow.owner_id) &&
            (!pendingNow.session_id || cur.session_id === pendingNow.session_id);
          if (alreadyInstalled) {
            if (stagedNow && (stagedPath === resolvedSelfStaged || stagedPath === resolvedLegacyStaged)) {
              fs.rmSync(stagedPath, { force: true });
            }
            resolved = true;
          } else if (stagedNow && (stagedPath === resolvedSelfStaged || stagedPath === resolvedLegacyStaged)) {
            let supersededByNewerLive = false;
            if (pendingNow.prev_file_sha256 !== undefined) {
              const matchesExactPrev = liveSnap.sha256 === pendingNow.prev_file_sha256;
              const matchesLocalOldSession =
                !this.isExternal &&
                !!pendingNow.prev_session_id &&
                !!liveSnap.sessionId &&
                liveSnap.sessionId === pendingNow.prev_session_id;
              if (!matchesExactPrev && !matchesLocalOldSession) {
                supersededByNewerLive = true;
              }
            } else if (this.isExternal && cur) {
              // 兼容旧版未记录 prev_file_sha256 的 pending 标记：共享外部文件上若现网已存在不同会话且时间不早于 pending，绝不覆写
              const curUpdatedMs = cur.updated_at ? Date.parse(cur.updated_at) : NaN;
              if (
                pendingNow.session_id &&
                cur.session_id &&
                cur.session_id !== pendingNow.session_id &&
                (!pendingNow.at || !Number.isFinite(curUpdatedMs) || curUpdatedMs >= pendingNow.at)
              ) {
                supersededByNewerLive = true;
              }
            }
            if (supersededByNewerLive) {
              // 共享凭据文件已由更新登录接管：仅清理当前工作区过期的暂存文件并消除挂起标记，绝不覆盖现网会话
              fs.rmSync(stagedPath, { force: true });
              resolved = true;
            } else {
              fs.renameSync(stagedPath, this.file);
              fsyncDir(path.dirname(this.file));
              resolved = true;
            }
          }
          if (resolved) {
            clearPendingCommitMarkerIfMatches(store, pendingKey, {
              file: pendingNow.file || this.file,
              sessionId: pendingNow.session_id ?? "",
              rawMarker: rawPendingNow,
            });
          }
        } else if (fs.existsSync(this.stagedFile)) {
          // 仅清理严格归属本工作区路径的孤儿暂存文件，绝不触碰共享外部路径下其他工作区的暂存登录
          fs.rmSync(this.stagedFile, { force: true });
        }
      });
    } catch {
      // 锁暂时不可用时留待下次读取/启动继续协调
    }
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

  /** 在跨进程文件锁保护下按当前磁盘会话代际条件删除现网与暂存凭据，避免并发 web-login 新提交的会话被登出误删 */
  clearIf(
    shouldDelete: (current: WebLoginInspectResult, staged: WebLoginInspectResult) => { removeFile: boolean; removeStaged: boolean },
  ): { fileRemoved: boolean; stagedRemoved: boolean } {
    return this.withLock(() => {
      const curRes = this.inspectPath(this.file);
      const stagedRes = this.inspectPath(this.stagedFile);
      const decision = shouldDelete(curRes, stagedRes);
      let stagedRemoved = false;
      let fileRemoved = false;
      if (decision.removeStaged && fs.existsSync(this.stagedFile)) {
        fs.rmSync(this.stagedFile, { force: true });
        stagedRemoved = true;
      }
      if (decision.removeFile && fs.existsSync(this.file)) {
        fs.rmSync(this.file, { force: true });
        fileRemoved = true;
      }
      if (stagedRemoved || fileRemoved) {
        fsyncDir(path.dirname(this.file));
      }
      return { fileRemoved, stagedRemoved };
    });
  }

  clear(): void {
    this.withLock(() => {
      fs.rmSync(this.stagedFile, { force: true });
      fs.rmSync(this.file, { force: true });
    });
  }
}
