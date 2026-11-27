import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { Cookie, CookieJar, defaultPath } from "tough-cookie";

/**
 * RFC 6265 recording cookie jar backed by `tough-cookie` with strict Feishu host allowlist
 * and an atomic 0600 AES-256-GCM encrypted credential store.
 * Cookies are private session material and must never be logged or passed to LLM prompts.
 */

const MAX_COOKIE_DATE_MS = 8_640_000_000_000_000;

export interface CookieRecord {
  name: string;
  value: string;
  domain: string;
  path: string;
  host_only?: boolean;
  secure?: boolean;
  http_only?: boolean;
  expires_at?: string;
}

export interface WebLogin {
  cookies: CookieRecord[];
  owner_id: string;
  owner_name: string;
  /** 可选：若飞书资料接口返回 open_id，用于与 config.yaml 的 owner.open_id 做核验 */
  owner_open_id?: string;
  /** 每次扫码登录生成的唯一会话标识，防止运行中的常驻进程在 web-logout 或重新登录后回写旧凭据 */
  session_id?: string;
  updated_at?: string;
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

/** RFC 6265 §5.1.4 default-path algorithm (delegated to `tough-cookie`). */
export function defaultCookiePath(urlPath: string): string {
  return defaultPath(urlPath);
}

function cookieExpiryMs(c: Cookie): number {
  const ms = c.expiryTime();
  return ms === undefined ? Infinity : ms;
}

function toCookieRecord(c: Cookie): CookieRecord {
  const exp = cookieExpiryMs(c);
  return {
    name: c.key,
    value: c.value,
    domain: (c.domain ?? "").replace(/^\.+/, "").toLowerCase(),
    path: c.path && c.path.startsWith("/") ? c.path : "/",
    ...(c.hostOnly ? { host_only: true } : {}),
    ...(c.secure ? { secure: true } : {}),
    ...(c.httpOnly ? { http_only: true } : {}),
    ...(Number.isFinite(exp) && exp > 0 ? { expires_at: new Date(exp).toISOString() } : {}),
  };
}

function createJar(): CookieJar {
  return new CookieJar(undefined, { allowSpecialUseDomain: true, rejectPublicSuffixes: true });
}

export class RecordingCookieJar {
  private readonly jar: CookieJar;
  private readonly extraAllowed?: Set<string>;
  private dirty = false;

  constructor(extraAllowedHosts?: Iterable<string>, jar?: CookieJar) {
    this.jar = jar ?? createJar();
    if (extraAllowedHosts) {
      this.extraAllowed = new Set([...extraAllowedHosts].map((h) => h.trim().toLowerCase()).filter(Boolean));
    }
  }

  static fromRecords(cookies: CookieRecord[], extraAllowedHosts?: Iterable<string>, nowMs = Date.now()): RecordingCookieJar {
    const out = new RecordingCookieJar(extraAllowedHosts);
    for (const c of cookies) {
      const domain = c.domain.replace(/^\.+/, "").toLowerCase();
      if (!c.name || !isAllowedFeishuHost(domain, out.extraAllowed)) {
        throw new Error(`个人 Web 凭据包含非法 Cookie 域名：${c.domain || "(空)"}`);
      }
      let expires: Date | "Infinity" = "Infinity";
      if (c.expires_at) {
        const ts = Date.parse(c.expires_at);
        if (Number.isFinite(ts)) {
          if (ts <= nowMs) continue;
          expires = new Date(Math.min(ts, MAX_COOKIE_DATE_MS));
        }
      }
      const cookiePath = c.path && c.path.startsWith("/") ? c.path : "/";
      const cookie = new Cookie({
        key: c.name,
        value: c.value,
        domain,
        path: cookiePath,
        hostOnly: !!c.host_only,
        secure: !!c.secure,
        httpOnly: !!c.http_only,
        expires,
        creation: new Date(nowMs),
      });
      // Restore directly via tough-cookie's store so hostOnly and path semantics remain exact.
      out.jar.store.putCookie(cookie, () => undefined);
    }
    return out;
  }

  /** Deep-copy this cookie jar (used for per-request staged redirect hops without mutating live state). */
  clone(): RecordingCookieJar {
    const serialized = this.jar.serializeSync();
    const copy = serialized ? CookieJar.fromJSON(serialized) : createJar();
    return new RecordingCookieJar(this.extraAllowed, copy);
  }

  hasDirtyUpdates(): boolean {
    return this.dirty;
  }

  clearDirty(): void {
    this.dirty = false;
  }

  /** Record Set-Cookie headers from one response, enforcing Feishu host allowlist and RFC 6265 scope. */
  setFromHeaders(requestUrl: URL, setCookieHeaders: string[] | string | undefined, nowMs = Date.now()): boolean {
    if (!setCookieHeaders) return false;
    const host = requestUrl.hostname.toLowerCase();
    if (!isAllowedFeishuHost(host, this.extraAllowed)) return false;
    const list = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
    let applied = false;

    for (const raw of list) {
      const parsed = Cookie.parse(raw);
      if (!parsed || !parsed.key) continue;

      // Enforce Feishu domain allowlist before passing to tough-cookie
      if (parsed.domain) {
        const targetDomain = parsed.domain.replace(/^\.+/, "").toLowerCase();
        if (!isAllowedFeishuHost(targetDomain, this.extraAllowed)) continue;
      }

      // Normalize Max-Age into an explicit absolute expires timestamp relative to nowMs
      // so both live clocks and deterministic tests expire identically.
      if (typeof parsed.maxAge === "number") {
        if (parsed.maxAge <= 0) {
          parsed.expires = new Date(0);
        } else {
          const rawExp = nowMs + parsed.maxAge * 1000;
          parsed.expires = new Date(Number.isFinite(rawExp) ? Math.min(rawExp, MAX_COOKIE_DATE_MS) : MAX_COOKIE_DATE_MS);
        }
        parsed.maxAge = null;
      } else if (parsed.expires instanceof Date) {
        const ms = parsed.expires.getTime();
        if (!Number.isFinite(ms)) parsed.expires = "Infinity";
        else if (ms <= 0) parsed.expires = new Date(0);
        else if (ms > MAX_COOKIE_DATE_MS) parsed.expires = new Date(MAX_COOKIE_DATE_MS);
      }

      try {
        const stored = this.jar.setCookieSync(parsed, requestUrl.toString(), { now: new Date(nowMs), ignoreError: false });
        if (stored) {
          this.dirty = true;
          applied = true;
        }
      } catch {
        // Rejected by RFC 6265 / public suffix list / domain mismatch
      }
    }
    return applied;
  }

  /** Commit staged Set-Cookie hops onto this live jar (only called on non-401/403 responses). */
  applyStaged(entries: { url: URL; headers: string[] | string; nowMs: number }[]): boolean {
    let applied = false;
    for (const e of entries) {
      if (this.setFromHeaders(e.url, e.headers, e.nowMs)) applied = true;
    }
    return applied;
  }

  /** Return all non-expired matching cookies sorted by longest path first (RFC 6265 §5.4). */
  matching(requestUrl: URL, nowMs = Date.now()): CookieRecord[] {
    const host = requestUrl.hostname.toLowerCase();
    if (!isAllowedFeishuHost(host, this.extraAllowed)) return [];
    const cookies = this.jar.getCookiesSync(requestUrl.toString(), { expire: false, sort: true });
    const out: CookieRecord[] = [];
    for (const c of cookies) {
      if (cookieExpiryMs(c) <= nowMs) continue;
      out.push(toCookieRecord(c));
    }
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

  /** Snapshot of all live non-expired cookies for durable persistence. */
  records(nowMs = Date.now()): CookieRecord[] {
    const serialized = this.jar.serializeSync();
    if (!serialized) return [];
    const out: CookieRecord[] = [];
    for (const raw of serialized.cookies) {
      const c = Cookie.fromJSON(raw);
      if (!c || !c.key || !c.domain) continue;
      if (cookieExpiryMs(c) <= nowMs) continue;
      out.push(toCookieRecord(c));
    }
    return out;
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
    try {
      const raw = fs.readFileSync(path.join(credDir, "feishu-web-key"), "utf8").trim();
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
  return Buffer.concat([decipher.update(Buffer.from(env.ciphertext, "base64")), decipher.final()]).toString("utf8");
}

/**
 * Atomic 0600 AES-256-GCM encrypted store for the owner's personal Feishu Web session.
 * Requires `PA_FEISHU_WEB_KEY` or systemd `CREDENTIALS_DIRECTORY/feishu-web-key` so session cookies
 * are never written to disk in plaintext.
 */
export class WebLoginStore {
  readonly file: string;

  constructor(dataDir: string, filename = "feishu-web.json") {
    const external = process.env.PA_FEISHU_WEB_CRED_FILE?.trim();
    this.file = external ? path.resolve(external) : path.join(dataDir, filename);
  }

  static hasEncryptionKey(): boolean {
    return resolveEncryptionKey() !== undefined;
  }

  exists(): boolean {
    return fs.existsSync(this.file);
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
    if (!key) return { status: "missing_key" };
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

  save(login: WebLogin): WebLogin {
    const key = resolveEncryptionKey();
    if (!key) {
      throw new Error(
        "保存个人 Web 凭据必须配置加密密钥（设置环境变量 PA_FEISHU_WEB_KEY 或通过 systemd LoadCredential 提供 CREDENTIALS_DIRECTORY/feishu-web-key），拒绝明文写入磁盘",
      );
    }
    const dir = path.dirname(this.file);
    fs.mkdirSync(dir, { recursive: true });
    const tmp = path.join(dir, `.${path.basename(this.file)}.${process.pid}.${Date.now()}.tmp`);
    const payload: WebLogin = {
      owner_id: login.owner_id,
      owner_name: login.owner_name,
      ...(login.owner_open_id ? { owner_open_id: login.owner_open_id } : {}),
      session_id: login.session_id || crypto.randomUUID(),
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
          // ignore close error
        }
      }
      fs.rmSync(tmp, { force: true });
      throw e;
    }
    return payload;
  }

  /**
   * 仅当磁盘凭据仍存在且属于同一会话（同 owner_id 与 session_id）时才持久化轮换后的 Cookie，
   * 防止 `pa context web-logout` 或重新登录后被运行中的常驻进程回写旧凭据。
   */
  saveIfSessionMatches(login: WebLogin): WebLogin | null {
    // 与 clear() 共用文件锁：检查与写回之间不能插入 web-logout，否则会把已登出的凭据写回磁盘
    return this.withLock(() => {
      const current = this.load();
      if (!current) return null;
      if (current.owner_id !== login.owner_id) return null;
      if (current.session_id && current.session_id !== login.session_id) return null;
      return this.save({
        ...login,
        owner_open_id: login.owner_open_id || current.owner_open_id,
        session_id: current.session_id ?? login.session_id,
      });
    });
  }

  clear(): void {
    this.withLock(() => fs.rmSync(this.file, { force: true }));
  }

  /** 跨进程互斥（O_EXCL 锁文件）；持有超过 10 秒的锁视为进程崩溃遗留，直接清除 */
  private withLock<T>(fn: () => T): T {
    const lock = `${this.file}.lock`;
    fs.mkdirSync(path.dirname(lock), { recursive: true });
    const deadline = Date.now() + 10_000;
    for (;;) {
      try {
        fs.closeSync(fs.openSync(lock, "wx", 0o600));
        break;
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
        try {
          if (Date.now() - fs.statSync(lock).mtimeMs > 10_000) fs.rmSync(lock, { force: true });
        } catch {
          // 锁刚被释放，重试即可
        }
        if (Date.now() > deadline) throw new Error(`等待个人 Web 凭据文件锁超时：${lock}`);
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20);
      }
    }
    try {
      return fn();
    } finally {
      fs.rmSync(lock, { force: true });
    }
  }
}
