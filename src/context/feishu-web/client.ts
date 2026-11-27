import crypto from "node:crypto";
import {
  authenticatedHeaders,
  loadWebMetadata,
  readNativeProfile,
  resolveEndpoints,
  type WebEndpoints,
} from "./auth.ts";
import { RecordingCookieJar, type CookieDelta, type WebLogin } from "./cookies.ts";
import { fetchWithJar, WEB_USER_AGENT, WebHttpError } from "./http.ts";
import { MAX_WIRE_BYTES, parseProto, ProtoWriter } from "./proto.ts";
import {
  ACCESS_KEY_SALT,
  CHAT_KIND_P2P,
  CMD_CHAT_MODE,
  CMD_HEARTBEAT,
  CMD_HISTORY,
  CMD_PUSH_PACKET,
  CMD_READ_MESSAGE,
  CMD_SEND_MESSAGE,
  decodeChatRecord,
  decodeFrame,
  decodeMessage,
  encodeAckFrame,
  encodeFrame,
  encodeHistoryWindowPayload,
  encodePacket,
  encodeReplyPacket,
  isGroupChat,
  replyInThread,
  unwrapGatewayPayload,
  USER_SENDER_TYPE,
  WEB_APP_ID,
  WEB_LARK_VERSION,
  WEB_SDK_VERSION,
  type ChatMeta,
  type RichSegment,
  type WebMessage,
} from "./wire.ts";
import { BinaryWebSocket } from "./ws.ts";

/**
 * Feishu personal Web session client:
 *   - Gateway protobuf RPCs: readMessage, readChat, readContext, sendReply, sendVerifiedReply
 *   - Frontier WSS push supervisor: heartbeat (25s), idle timeout (75s), profile keepalive (30m),
 *     cookie rotation observer, exponential backoff (1s..30s), 3-denial threshold before needs_login,
 *     and backpressure ACK (ACK sent ONLY after durable onMessage succeeds).
 */

export type ListenerState =
  | "idle"
  | "connecting"
  | "listening"
  | "publication_blocked"
  | "reverifying"
  | "reconnecting"
  | "needs_login"
  | "stopped";

export class SessionNeedsLoginError extends WebHttpError {
  constructor(message: string, status?: number, cause?: unknown) {
    super("credential_denied", message, status, cause);
    this.name = "SessionNeedsLoginError";
  }
}

/** 服务端成功返回 CMD 8 响应但明确不包含目标消息 ID（消息已删除/不可见），用于与网络/解码等瞬态读取故障区分 */
export class MessageNotFoundError extends Error {
  readonly messageId: string;
  constructor(id: string) {
    super(`无法回读个人消息：${id}`);
    this.name = "MessageNotFoundError";
    this.messageId = id;
  }
}

export interface FeishuWebClientOptions {
  endpoints?: Partial<WebEndpoints>;
  /**
   * 收到可信会话确认 / Cookie 轮换时回调：
   *   - 返回 false / null 表示本地凭据已被登出或替换为新会话，客户端应停止继续使用当前会话；
   *   - 返回合并后的 WebLogin 对象时，客户端据此同步最新 cookie_version 与磁盘快照（防止多进程互相回滚 Cookie）。
   */
  onSessionConfirmed?: (login: WebLogin, delta: CookieDelta) => WebLogin | boolean | null | void;
  heartbeatIntervalMs?: number;
  socketIdleTimeoutMs?: number;
  keepaliveIntervalMs?: number;
  reconnectBaseMs?: number;
  reconnectCeilingMs?: number;
  sessionDenialThreshold?: number;
  sessionDenialRetryMs?: number;
  sessionHealthyAfterMs?: number;
  chatCacheTtlMs?: number;
  maxQueueBytes?: number;
  verifyOwnerMaxAttempts?: number;
  verifyOwnerRetryMs?: number;
}

export interface VerifiedReplyInput {
  chatId: string;
  messageId: string;
  rootId?: string;
  text: string;
  /** Deterministic idempotency key (32 hex chars). Reusing the same CID prevents duplicate sends. */
  cid: string;
  signal?: AbortSignal;
}

export interface VerifiedReplyResult {
  replyId: string;
  rootId: string;
  parentId: string;
  threadId: string;
  verified: boolean;
}

const DEFAULT_HEARTBEAT_MS = 25_000;
const DEFAULT_KEEPALIVE_MS = 30 * 60_000;
const DEFAULT_RECONNECT_BASE_MS = 1_000;
const DEFAULT_RECONNECT_CEILING_MS = 30_000;
const DEFAULT_DENIAL_THRESHOLD = 3;
const DEFAULT_DENIAL_RETRY_MS = 30_000;
const DEFAULT_CHAT_CACHE_TTL_MS = 10 * 60_000;
const MAX_HISTORY_WINDOWS = 10;

function randomRequestId(): string {
  return crypto.randomBytes(16).toString("hex");
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new WebHttpError("aborted", "已中止"));
      return;
    }
    const onAbort = () => {
      clearTimeout(t);
      reject(new WebHttpError("aborted", "已中止"));
    };
    const t = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

function isCredentialDenied(err: unknown): boolean {
  return err instanceof WebHttpError && err.code === "credential_denied";
}

function isAborted(err: unknown): boolean {
  return err instanceof WebHttpError && err.code === "aborted";
}

class SessionRetryPolicy {
  private delayMs: number;
  private denials = 0;
  private readonly baseMs: number;
  private readonly ceilingMs: number;
  private readonly denialThreshold: number;
  private readonly denialRetryMs: number;

  constructor(baseMs: number, ceilingMs: number, denialThreshold: number, denialRetryMs: number) {
    this.baseMs = baseMs;
    this.delayMs = baseMs;
    this.ceilingMs = ceilingMs;
    this.denialThreshold = denialThreshold;
    this.denialRetryMs = denialRetryMs;
  }

  markHealthy(): void {
    this.denials = 0;
    this.delayMs = this.baseMs;
  }

  next(err: unknown): { state: ListenerState; waitMs: number; giveUp: boolean } {
    if (isCredentialDenied(err)) {
      this.denials++;
      if (this.denials >= this.denialThreshold) {
        return { state: "needs_login", waitMs: 0, giveUp: true };
      }
      return { state: "reverifying", waitMs: this.denialRetryMs, giveUp: false };
    }
    // 非鉴权类错误中断「连续」鉴权拒绝计数，避免偶发 401 + 多次网络抖动误判为登出
    this.denials = 0;
    const waitMs = this.delayMs;
    this.delayMs = Math.min(this.delayMs * 2, this.ceilingMs);
    return { state: "reconnecting", waitMs, giveUp: false };
  }
}

export class UnusableOriginalMessageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UnusableOriginalMessageError";
  }
}

/** 统一判定一条个人 Web 消息是否满足可入库/可回复的基本正文与发送者条件（用户消息、有效会话类型、未标记 unsupported、非空正文） */
export function isUsableWebMessage(m: WebMessage): boolean {
  return (
    !!m.id &&
    !!m.conversationId &&
    !m.unsupported &&
    (m.conversationKind === "group" || m.conversationKind === "dm") &&
    m.senderType === USER_SENDER_TYPE &&
    !!m.text.trim()
  );
}

export class FeishuWebClient {
  private readonly endpoints: WebEndpoints;
  private readonly jar: RecordingCookieJar;
  private readonly opts: Required<
    Pick<
      FeishuWebClientOptions,
      | "heartbeatIntervalMs"
      | "socketIdleTimeoutMs"
      | "keepaliveIntervalMs"
      | "reconnectBaseMs"
      | "reconnectCeilingMs"
      | "sessionDenialThreshold"
      | "sessionDenialRetryMs"
      | "sessionHealthyAfterMs"
      | "chatCacheTtlMs"
    >
  >;
  private readonly maxQueueBytes?: number;
  private onSessionConfirmed?: (login: WebLogin, delta: CookieDelta) => WebLogin | boolean | null | void;
  private ownerId: string;
  private ownerName: string;
  private ownerOpenId?: string;
  private readonly sessionId?: string;
  private cookieVersion: number;
  private deviceId = "";
  private appKey = "";
  private readonly chatCache = new Map<string, { meta: ChatMeta; expiresAt: number }>();

  private constructor(jar: RecordingCookieJar, login: WebLogin, options: FeishuWebClientOptions = {}) {
    this.endpoints = resolveEndpoints(options.endpoints);
    this.jar = jar;
    this.ownerId = login.owner_id;
    this.ownerName = login.owner_name;
    this.ownerOpenId = login.owner_open_id;
    this.sessionId = login.session_id;
    this.cookieVersion = login.cookie_version ?? 1;
    this.onSessionConfirmed = options.onSessionConfirmed;
    this.maxQueueBytes = options.maxQueueBytes;
    const heartbeat = options.heartbeatIntervalMs ?? DEFAULT_HEARTBEAT_MS;
    this.opts = {
      heartbeatIntervalMs: heartbeat,
      socketIdleTimeoutMs: options.socketIdleTimeoutMs ?? heartbeat * 3,
      keepaliveIntervalMs: options.keepaliveIntervalMs ?? DEFAULT_KEEPALIVE_MS,
      reconnectBaseMs: options.reconnectBaseMs ?? DEFAULT_RECONNECT_BASE_MS,
      reconnectCeilingMs: options.reconnectCeilingMs ?? DEFAULT_RECONNECT_CEILING_MS,
      sessionDenialThreshold: options.sessionDenialThreshold ?? DEFAULT_DENIAL_THRESHOLD,
      sessionDenialRetryMs: options.sessionDenialRetryMs ?? DEFAULT_DENIAL_RETRY_MS,
      sessionHealthyAfterMs: options.sessionHealthyAfterMs ?? heartbeat,
      chatCacheTtlMs: options.chatCacheTtlMs ?? DEFAULT_CHAT_CACHE_TTL_MS,
    };
  }

  /** Connect an approved login, verify owner identity (persisting any rotated cookies immediately), and load Web SDK metadata. */
  static async connect(
    login: WebLogin,
    options: FeishuWebClientOptions = {},
    signal?: AbortSignal,
  ): Promise<FeishuWebClient> {
    const ep = resolveEndpoints(options.endpoints);
    const jar = RecordingCookieJar.fromRecords(login.cookies, ep.extraAllowedHosts);
    const client = new FeishuWebClient(jar, login, options);
    // 首次建连的 verifyOwner 若在返回瞬时 5xx / 不可解析响应 / 传输抖动前已轮换 Set-Cookie，
    // 保留同一本地 jar 进行有界重试（但仍不落盘直至 owner 身份核验成功），避免丢弃新 Cookie 后下次重连触发 needs_login。
    const maxAttempts = Math.max(1, options.verifyOwnerMaxAttempts ?? 3);
    const retryBaseMs = Math.max(0, options.verifyOwnerRetryMs ?? 250);
    await client.verifyOwnerWithTransientRetry(maxAttempts, retryBaseMs, signal);
    if (!client.notifySessionConfirmed()) {
      throw new WebHttpError("aborted", "本地凭据已被登出或更新");
    }
    let meta: Awaited<ReturnType<typeof loadWebMetadata>>;
    try {
      meta = await loadWebMetadata(jar, ep, { signal });
    } catch (err) {
      // verifyOwner 已确认会话归属；若 loadWebMetadata 遭遇 5xx/缺 appKey 前收到了 Set-Cookie 轮换，
      // 须立即落盘已验证会话的新增 Cookie，避免重连回退到已失效的旧磁盘 Cookie
      if (!(err instanceof WebHttpError && err.code === "credential_denied")) {
        client.flushVerifiedCookieDeltaBestEffort();
      }
      throw err;
    }
    client.deviceId = meta.deviceId;
    client.appKey = meta.appKey;
    if (!client.notifySessionConfirmed()) {
      throw new WebHttpError("aborted", "本地凭据已被登出或更新");
    }
    return client;
  }

  owner(): { id: string; name: string } {
    return { id: this.ownerId, name: this.ownerName };
  }

  currentSessionId(): string | undefined {
    return this.sessionId;
  }

  currentCookieVersion(): number {
    return this.cookieVersion;
  }

  private refreshDeviceIdFromJar(): void {
    const messengerUrl = new URL(this.endpoints.messengerUrl);
    const accountsUrl = new URL(this.endpoints.accountsOrigin + "/");
    const latest =
      this.jar.cookieValue(messengerUrl, "passport_web_did") ||
      this.jar.cookieValue(accountsUrl, "passport_web_did");
    if (latest) this.deviceId = latest;
  }

  /** 同步磁盘上更新版本的同会话 Cookie（保留本客户端在途未落盘且不冲突的轮换 Cookie，防止被无关更新回滚） */
  syncFromDisk(login: WebLogin): void {
    if (login.owner_id !== this.ownerId) return;
    if (this.sessionId && login.session_id && login.session_id !== this.sessionId) return;
    const nextVer = login.cookie_version ?? 1;
    if (nextVer <= this.cookieVersion) return;
    this.jar.syncFromRecords(login.cookies, Date.now(), { preservePendingDelta: true });
    this.cookieVersion = nextVer;
    this.refreshDeviceIdFromJar();
    if (login.owner_name) this.ownerName = login.owner_name;
    if (login.owner_open_id) this.ownerOpenId = login.owner_open_id;
  }

  /** Live snapshot including any cookies rotated by Feishu since login. */
  session(): WebLogin {
    return {
      owner_id: this.ownerId,
      owner_name: this.ownerName,
      ...(this.ownerOpenId ? { owner_open_id: this.ownerOpenId } : {}),
      ...(this.sessionId ? { session_id: this.sessionId } : {}),
      cookie_version: this.cookieVersion,
      cookies: this.jar.records(),
      updated_at: new Date().toISOString(),
    };
  }

  setSessionObserver(cb: ((login: WebLogin, delta: CookieDelta) => WebLogin | boolean | null | void) | undefined): void {
    this.onSessionConfirmed = cb;
  }

  private hasPendingCookieDelta(): boolean {
    const d = this.jar.peekDelta();
    return d.upserts.length > 0 || d.deletes.length > 0;
  }

  /** 对已验证会话在遭遇瞬时非鉴权错误（如 5xx、网关解码异常、票据异常）前落盘已收到的 Set-Cookie 轮换，避免短生命周期客户端丢失新 Cookie */
  private flushVerifiedCookieDeltaBestEffort(): void {
    if (!this.hasPendingCookieDelta()) return;
    try {
      this.notifySessionConfirmed();
    } catch {
      // 保留原始非鉴权错误，不吞掉上游失败信息
    }
  }

  private notifySessionConfirmed(): boolean {
    if (!this.onSessionConfirmed) {
      this.jar.clearDelta();
      return true;
    }
    const delta = this.jar.peekDelta();
    let res: WebLogin | boolean | null | void;
    try {
      res = this.onSessionConfirmed(this.session(), delta);
    } catch (err) {
      // 保留未落盘增量以便重试，并对外显式暴露持久化失败（绝不把 Cookie 原文写入错误信息）
      throw new WebHttpError(
        "transport",
        "持久化个人 Web 轮换后的会话凭据失败（凭据文件被锁定、缺少密钥或不可写）",
        undefined,
        err instanceof Error ? err.name : undefined,
      );
    }
    if (res === false || res === null) return false;
    if (res && typeof res === "object") {
      this.cookieVersion = res.cookie_version ?? this.cookieVersion;
      this.jar.syncFromRecords(res.cookies);
      this.refreshDeviceIdFromJar();
    } else {
      this.jar.clearDelta();
    }
    return true;
  }

  async verifyOwner(signal?: AbortSignal): Promise<void> {
    await this.verifyOwnerOnce(signal);
    if (this.hasPendingCookieDelta()) {
      if (!this.notifySessionConfirmed()) {
        throw new WebHttpError("aborted", "本地凭据已被登出或更新");
      }
    }
  }

  private async verifyOwnerOnce(signal?: AbortSignal): Promise<void> {
    const profile = await readNativeProfile(this.jar, this.endpoints, { signal });
    if (profile.id !== this.ownerId) {
      throw new WebHttpError("credential_denied", "当前个人 Web 账号与已授权账号不一致");
    }
    if (profile.name) this.ownerName = profile.name;
    if (profile.openId) this.ownerOpenId = profile.openId;
  }

  private async verifyOwnerWithTransientRetry(
    maxAttempts: number,
    retryBaseMs: number,
    signal?: AbortSignal,
  ): Promise<void> {
    for (let attempt = 1; ; attempt++) {
      try {
        await this.verifyOwnerOnce(signal);
        return;
      } catch (err) {
        if (signal?.aborted) throw err;
        const isTransient =
          !(err instanceof WebHttpError) ||
          (err.code !== "credential_denied" && err.code !== "aborted");
        if (!isTransient || attempt >= maxAttempts) {
          throw err;
        }
        if (retryBaseMs > 0) {
          await sleep(retryBaseMs * attempt, signal);
        }
      }
    }
  }

  // ───────── Gateway RPCs ─────────

  async gateway(
    command: number,
    payload: Uint8Array | undefined,
    opts: {
      cid?: string;
      packet?: Buffer;
      signal?: AbortSignal;
      deferCookiePersist?: boolean;
      allowEmptyPayload?: boolean;
    } = {},
  ): Promise<Buffer> {
    const cid = opts.cid || randomRequestId();
    const packet = opts.packet ?? encodePacket(command, payload, cid);
    const headers = authenticatedHeaders(this.jar, this.endpoints, this.endpoints.gatewayUrl, {
      "Content-Type": "application/x-protobuf",
      "X-Appid": WEB_APP_ID,
      "X-Command": String(command),
      "X-Command-Version": WEB_SDK_VERSION,
      "X-Source": "web",
      "X-Web-Version": WEB_SDK_VERSION,
      "X-Request-Id": cid,
      "X-Lgw-Os-Type": "1",
      "X-Lgw-Terminal-Type": "2",
      Origin: this.endpoints.messengerOrigin,
      Referer: `${this.endpoints.messengerOrigin}/`,
    });
    const res = await fetchWithJar(this.jar, {
      method: "POST",
      url: this.endpoints.gatewayUrl,
      headers,
      body: packet,
      signal: opts.signal,
      allowInsecureHttp: this.endpoints.allowInsecureHttp,
      extraAllowedHosts: this.endpoints.extraAllowedHosts,
    });
    if (res.status === 401 || res.status === 403) {
      throw new WebHttpError("credential_denied", `个人 Web 网关鉴权失败 (HTTP ${res.status})`, res.status);
    }
    if (res.status !== 200) {
      this.flushVerifiedCookieDeltaBestEffort();
      throw new WebHttpError("http_error", `个人 Web 网关请求被拒绝 (HTTP ${res.status})`, res.status);
    }
    let unpacked: Buffer;
    try {
      unpacked = unwrapGatewayPayload(res.body, { allowEmptyPayload: opts.allowEmptyPayload });
    } catch (err) {
      this.flushVerifiedCookieDeltaBestEffort();
      throw err;
    }
    if (!opts.deferCookiePersist && (res.cookiesUpdated || this.hasPendingCookieDelta())) {
      if (!this.notifySessionConfirmed()) {
        throw new WebHttpError("aborted", "本地凭据已被登出或更新");
      }
    }
    return unpacked;
  }

  /** 将此前延迟（如发回复先落库回执）的待持久化轮换 Cookie 立即刷盘；若会话已被吊销/取代则立即中止后续请求 */
  flushPendingCookies(): void {
    if (this.hasPendingCookieDelta()) {
      if (!this.notifySessionConfirmed()) {
        throw new WebHttpError("aborted", "本地凭据已被登出或更新");
      }
    }
  }

  /** Fetch one native message by its numeric message ID (command 8). */
  async readMessage(id: string, signal?: AbortSignal): Promise<WebMessage> {
    const req = new ProtoWriter().str(1, id).finish();
    // Protobuf 中空的 GetMessagesByIdsResponse 载荷合法编码为 0 字节（位于非空且 status=0 的网关包内），表示确认未查到该消息
    const data = await this.gateway(CMD_READ_MESSAGE, req, { signal, allowEmptyPayload: true });
    const fields = parseProto(data, MAX_WIRE_BYTES);
    for (const entry of fields.allBytes(1)) {
      const pair = parseProto(entry, MAX_WIRE_BYTES);
      if (pair.str(1) === id) {
        return decodeMessage(pair.bytes(2), this.ownerId);
      }
    }
    throw new MessageNotFoundError(id);
  }

  /** Read conversation name, kind, and topic mode (command 64), with TTL caching. */
  async readChat(chatId: string, opts: { signal?: AbortSignal; force?: boolean } = {}): Promise<ChatMeta> {
    const now = Date.now();
    if (!opts.force) {
      const cached = this.chatCache.get(chatId);
      if (cached && cached.expiresAt > now) return cached.meta;
    }
    const req = new ProtoWriter().str(1, chatId).finish();
    const data = await this.gateway(CMD_CHAT_MODE, req, { signal: opts.signal });
    const fields = parseProto(data, MAX_WIRE_BYTES);
    for (const entry of fields.allBytes(1)) {
      const pair = parseProto(entry, MAX_WIRE_BYTES);
      if (pair.str(1) === chatId) {
        const meta = decodeChatRecord(pair.bytes(2), chatId);
        this.chatCache.set(chatId, { meta, expiresAt: now + this.opts.chatCacheTtlMs });
        return meta;
      }
    }
    throw new Error(`无法读取个人会话信息：${chatId}`);
  }

  /**
   * Read bounded conversation history strictly before an anchor message (command 43 / 8).
   * For topic/reply messages, resolves root & quoted parent; for top-level messages, fetches recent positions.
   */
  async readContext(
    anchor: Pick<WebMessage, "id" | "conversationId" | "rootId" | "parentId" | "threadId" | "position" | "createdAtMs">,
    opts: { limit?: number; signal?: AbortSignal } = {},
  ): Promise<WebMessage[]> {
    const limit = Math.max(1, Math.min(50, opts.limit ?? 20));
    const matches = (m: WebMessage): boolean => {
      if (!m.id || m.id === anchor.id || m.conversationId !== anchor.conversationId) return false;
      if (!m.createdAtMs || (anchor.createdAtMs && m.createdAtMs > anchor.createdAtMs)) return false;
      if (!m.text.trim() && m.resources.length === 0) return false;
      if (anchor.rootId) {
        return m.id === anchor.rootId || (m.id === anchor.parentId && m.rootId === anchor.rootId);
      }
      return m.position < anchor.position;
    };

    const readWindow = async (startPos: number, maxCount: number): Promise<WebMessage[]> => {
      const collected: WebMessage[] = [];
      let pos = startPos;
      for (let page = 0; page < MAX_HISTORY_WINDOWS && pos > 0 && collected.length < maxCount; page++) {
        const next = Math.max(0, pos - maxCount);
        const payload = encodeHistoryWindowPayload(anchor.conversationId, pos, next);
        const raw = await this.gateway(CMD_HISTORY, payload, { signal: opts.signal });
        const resp = parseProto(raw, MAX_WIRE_BYTES);
        for (const entry of resp.allBytes(1)) {
          try {
            const pair = parseProto(entry, MAX_WIRE_BYTES);
            const m = decodeMessage(pair.bytes(2), this.ownerId);
            if (matches(m)) collected.push(m);
          } catch {
            // One undecodable historical entry must not abort remaining context
          }
        }
        pos = next;
      }
      return collected;
    };

    let msgs: WebMessage[] = [];
    if (anchor.threadId || anchor.rootId) {
      const wanted = new Set<string>();
      for (const id of [anchor.rootId, anchor.parentId]) {
        if (id && id !== anchor.id) wanted.add(id);
      }
      for (const id of [...wanted]) {
        try {
          const m = await this.readMessage(id, opts.signal);
          if (matches(m)) {
            msgs.push(m);
            wanted.delete(id);
          }
        } catch {
          // fall back to window scan if direct read fails
        }
      }
      if (wanted.size > 0 && anchor.position > 0) {
        try {
          const win = await readWindow(anchor.position, limit);
          for (const m of win) {
            if (wanted.has(m.id)) {
              msgs.push(m);
              wanted.delete(m.id);
            }
          }
        } catch {
          // best effort
        }
      }
    } else if (anchor.position > 0) {
      msgs = await readWindow(anchor.position, limit);
    }

    const dedup = new Map<string, WebMessage>();
    for (const m of msgs) dedup.set(m.id, m);
    return [...dedup.values()].sort((a, b) => a.createdAtMs - b.createdAtMs).slice(-limit);
  }

  /** Send a text reply once with a deterministic CID (command 5), preserving both root and selected parent IDs. */
  async sendReply(
    chatId: string,
    rootId: string,
    cid: string,
    segments: RichSegment[],
    inThread: boolean,
    signal?: AbortSignal,
    parentId = rootId,
    opts?: { deferCookiePersist?: boolean },
  ): Promise<WebMessage> {
    const packet = encodeReplyPacket(chatId, rootId, cid, segments, inThread, parentId);
    const data = await this.gateway(CMD_SEND_MESSAGE, undefined, {
      cid,
      packet,
      signal,
      deferCookiePersist: opts?.deferCookiePersist,
    });
    const resp = parseProto(data, MAX_WIRE_BYTES);
    const created = decodeMessage(resp.bytes(1), this.ownerId);
    if (!created.id) {
      throw new Error("个人 Web 回复未返回消息 ID");
    }
    return created;
  }

  /** Independent readback verification for an already-created reply ID. */
  async verifyReplyReadback(params: {
    replyId: string;
    chatId: string;
    rootId: string;
    parentId: string;
    cid: string;
    text: string;
    threaded: boolean;
    signal?: AbortSignal;
  }): Promise<VerifiedReplyResult> {
    const normalizeText = (s: string) => s.replace(/\r\n/g, "\n").trim();
    const expectedText = normalizeText(params.text);
    const readback = await this.readMessage(params.replyId, params.signal);
    const verified =
      readback.id === params.replyId &&
      readback.senderType === USER_SENDER_TYPE &&
      readback.actorId === this.ownerId &&
      readback.conversationId === params.chatId &&
      readback.rootId === params.rootId &&
      readback.parentId === params.parentId &&
      readback.cid === params.cid &&
      (!params.threaded || (!!readback.threadId && !readback.sendToChat)) &&
      normalizeText(readback.text) === expectedText;
    if (!verified) {
      throw new Error("个人 Web 回复回读校验未通过（消息身份、父消息或正文不一致）");
    }
    return {
      replyId: readback.id,
      rootId: params.rootId,
      parentId: params.parentId,
      threadId: readback.threadId,
      verified: true,
    };
  }

  /**
   * Verified personal reply (used only after explicit human confirmation of a draft):
   *   1. Pre-send check: reads the original message to confirm it still exists in the expected chat.
   *   2. Reads chat kind & mode to determine explicit thread reply flag.
   *   3. Sends ONCE with fixed CID, preserving both rootId and selected parentId.
   *   4. Independent readback check verifying owner, chat, root, parent, CID, and text.
   */
  async sendVerifiedReply(
    input: VerifiedReplyInput & { requireMentionOwnerId?: string },
    hooks?: {
      onBeforeSend?: (meta: { rootId: string; parentId: string; threaded: boolean; original: WebMessage; chat: ChatMeta }) => Promise<void> | void;
      onCreated?: (meta: { replyId: string; rootId: string; parentId: string; threaded: boolean }) => void;
    },
  ): Promise<VerifiedReplyResult> {
    const normalizeText = (s: string) => s.replace(/\r\n/g, "\n").trim();
    const text = normalizeText(input.text);
    if (!text) throw new Error("回复内容不能为空");
    const original = await this.readMessage(input.messageId, input.signal);
    if (original.conversationId !== input.chatId) {
      throw new Error("原消息所属会话与草稿目标不一致，拒绝发送");
    }
    if (!isUsableWebMessage(original)) {
      throw new UnusableOriginalMessageError("实时回读原消息已不可用（可能已被撤回、编辑为空或转为不支持类型），已中止发送");
    }
    if (input.requireMentionOwnerId) {
      const liveAtMe =
        original.actorId !== input.requireMentionOwnerId &&
        original.mentions.some((m) => m.id === input.requireMentionOwnerId);
      if (!liveAtMe) {
        throw new Error("实时回读原消息已不再 @本人（可能已被编辑移除 @mention），已中止发送");
      }
    }
    const actualRoot = original.rootId || original.id;
    const actualParent = original.id;
    if (input.rootId && input.rootId !== actualRoot) {
      throw new Error("原消息根话题与草稿记录不一致，拒绝发送");
    }
    // 发包前强制实时查询群模式（不走 10 分钟缓存），防止群模式变更后错用 thread 标志
    const chat = await this.readChat(input.chatId, { signal: input.signal, force: true });
    const group = isGroupChat(chat.kind);
    if (!group && chat.kind !== CHAT_KIND_P2P) {
      throw new Error(`不支持的个人会话类型：${chat.kind}`);
    }
    const inThread = replyInThread(chat.kind, chat.mode);
    const threaded = group || inThread;
    await hooks?.onBeforeSend?.({ rootId: actualRoot, parentId: actualParent, threaded, original, chat });
    // 发包响应可能同时携带新消息 ID 与 Cookie 轮换：先让 onCreated 把 replyId 持久化为 created，
    // 再尝试刷盘轮换后的 Cookie，确保即使 Cookie 落盘报错也不会让已发送消息滞留在 sending 态而无法回读恢复。
    const created = await this.sendReply(input.chatId, actualRoot, input.cid, [{ text }], inThread, input.signal, actualParent, {
      deferCookiePersist: true,
    });
    hooks?.onCreated?.({ replyId: created.id, rootId: actualRoot, parentId: actualParent, threaded });
    this.flushPendingCookies();

    return this.verifyReplyReadback({
      replyId: created.id,
      chatId: input.chatId,
      rootId: actualRoot,
      parentId: actualParent,
      cid: input.cid,
      text,
      threaded,
      signal: input.signal,
    });
  }

  // ───────── Frontier WSS Push Listener ─────────

  async buildSocketUrl(signal?: AbortSignal): Promise<string> {
    this.refreshDeviceIdFromJar();
    for (let attempt = 0; attempt < 2; attempt++) {
      const requestedDeviceId = this.deviceId;
      const url = `${this.endpoints.ticketUrl}?local_device_id=${encodeURIComponent(requestedDeviceId)}`;
      const res = await fetchWithJar(this.jar, {
        method: "GET",
        url,
        headers: authenticatedHeaders(this.jar, this.endpoints, url),
        signal,
        allowInsecureHttp: this.endpoints.allowInsecureHttp,
        extraAllowedHosts: this.endpoints.extraAllowedHosts,
      });
      if (res.status === 401 || res.status === 403) {
        throw new WebHttpError("credential_denied", `获取长连接票据鉴权失败 (HTTP ${res.status})`, res.status);
      }
      if (res.status !== 200) {
        this.flushVerifiedCookieDeltaBestEffort();
        throw new WebHttpError("http_error", `获取长连接票据失败 (HTTP ${res.status})`, res.status);
      }
      let parsed: { code?: number; ticket?: string };
      try {
        parsed = JSON.parse(res.body.toString("utf8")) as typeof parsed;
      } catch {
        this.flushVerifiedCookieDeltaBestEffort();
        throw new WebHttpError("http_error", "长连接票据响应不可解析");
      }
      if (typeof parsed.code === "number" && parsed.code !== 0) {
        this.flushVerifiedCookieDeltaBestEffort();
        throw new WebHttpError("http_error", `长连接票据服务返回异常 (code=${parsed.code})`);
      }
      if (!parsed.ticket) {
        this.flushVerifiedCookieDeltaBestEffort();
        throw new WebHttpError("http_error", "长连接票据暂不可用");
      }
      if (res.cookiesUpdated || this.hasPendingCookieDelta()) {
        if (!this.notifySessionConfirmed()) {
          throw new WebHttpError("aborted", "本地凭据已被登出或更新");
        }
      }
      this.refreshDeviceIdFromJar();
      // 若票据响应或并发磁盘同步轮换了 passport_web_did，用最新 deviceId 重新申请一次匹配票据；
      // 最终 access_key 与 WebSocket URL 始终使用与该票据严格对应的同一个 deviceId
      if (this.deviceId && this.deviceId !== requestedDeviceId && attempt === 0) {
        continue;
      }
      const effectiveDeviceId = requestedDeviceId;
      const accessKey = crypto
        .createHash("md5")
        .update(`2${this.appKey}${effectiveDeviceId}${ACCESS_KEY_SALT}`)
        .digest("hex");

      const wsUrl = new URL(this.endpoints.websocketUrl);
      const params: [string, string][] = [
        ["aid", "1"],
        ["fpid", "2"],
        ["ticket", parsed.ticket],
        ["device_id", effectiveDeviceId],
        ["access_key", accessKey],
        ["request_id", randomRequestId()],
        ["accept_encoding", "gzip"],
        ["sdk_version", WEB_SDK_VERSION],
        ["version_code", WEB_SDK_VERSION],
        ["type", "sdk_main"],
        ["terminal_type", "2"],
        ["lark_version", WEB_LARK_VERSION],
        ["net_status", "5"],
        ["lark_env", "online"],
      ];
      for (const [k, v] of params) wsUrl.searchParams.set(k, v);
      return wsUrl.toString();
    }
    throw new WebHttpError("http_error", "长连接票据设备标识持续变化，暂不可用");
  }

  /**
   * Run the persistent Frontier WSS listener loop until `signal` aborts or 3 consecutive
   * credential denials confirm sign-out (`needs_login`).
   */
  async listen(params: {
    signal: AbortSignal;
    onMessage: (msg: WebMessage) => Promise<void> | void;
    shouldDeliverInvalid?: (msg: WebMessage) => boolean;
    onState?: (state: ListenerState, detail?: string) => void;
    onWarn?: (message: string) => void;
  }): Promise<void> {
    const retry = new SessionRetryPolicy(
      this.opts.reconnectBaseMs,
      this.opts.reconnectCeilingMs,
      this.opts.sessionDenialThreshold,
      this.opts.sessionDenialRetryMs,
    );
    const report = (state: ListenerState, detail?: string) => {
      try {
        params.onState?.(state, detail);
      } catch {
        // ignore observer failure
      }
    };

    while (!params.signal.aborted) {
      report("connecting");
      let listeningSince = 0;
      const observeState = (s: ListenerState, detail?: string) => {
        if (s === "listening" && !listeningSince) listeningSince = Date.now();
        report(s, detail);
      };

      try {
        await this.listenOnce(params.signal, params.onMessage, observeState, params.onWarn, params.shouldDeliverInvalid);
        if (params.signal.aborted) break;
      } catch (err) {
        if (params.signal.aborted || isAborted(err)) break;
        if (listeningSince && Date.now() - listeningSince >= this.opts.sessionHealthyAfterMs) {
          retry.markHealthy();
        }
        const decision = retry.next(err);
        const msg = err instanceof Error ? err.message : String(err);
        report(decision.state, msg);
        if (decision.giveUp) {
          throw new SessionNeedsLoginError(msg, err instanceof WebHttpError ? err.status : undefined, err);
        }
        try {
          await sleep(decision.waitMs, params.signal);
        } catch {
          break;
        }
      }
    }
    report("stopped");
  }

  private async listenOnce(
    outerSignal: AbortSignal,
    onMessage: (msg: WebMessage) => Promise<void> | void,
    onState: (state: ListenerState, detail?: string) => void,
    onWarn?: (message: string) => void,
    shouldDeliverInvalid?: (msg: WebMessage) => boolean,
  ): Promise<void> {
    await this.verifyOwner(outerSignal);
    if (!this.notifySessionConfirmed()) {
      throw new WebHttpError("aborted", "本地凭据已被登出或更新");
    }
    const wsAddress = await this.buildSocketUrl(outerSignal);

    const ws = await BinaryWebSocket.dial(wsAddress, {
      headers: {
        "User-Agent": WEB_USER_AGENT,
        Origin: this.endpoints.messengerOrigin,
      },
      maxQueueBytes: this.maxQueueBytes,
      signal: outerSignal,
    });

    const loopCtrl = new AbortController();
    const onOuterAbort = () => {
      loopCtrl.abort();
      ws.close();
    };
    outerSignal.addEventListener("abort", onOuterAbort, { once: true });

    // Heartbeat loop (25s)
    const hbTimer = setInterval(() => {
      const hbFrame = encodeFrame(encodePacket(CMD_HEARTBEAT, undefined, ""));
      void ws.writeBinary(hbFrame, 15_000, loopCtrl.signal).catch(() => {
        ws.close();
      });
    }, this.opts.heartbeatIntervalMs);
    hbTimer.unref?.();

    // Session keepalive loop (30m): touches profile so rotated cookies are persisted,
    // and escalates definitive credential denials or owner mismatches out of the socket loop.
    let keepaliveFatal: Error | null = null;
    const kaTimer = setInterval(() => {
      void readNativeProfile(this.jar, this.endpoints, { signal: loopCtrl.signal })
        .then((p) => {
          if (p.id !== this.ownerId) {
            keepaliveFatal = new WebHttpError("credential_denied", "保活核验发现个人 Web 账号与已授权账号不一致");
            ws.close();
            return;
          }
          if (p.name) this.ownerName = p.name;
          try {
            if (!this.notifySessionConfirmed()) {
              keepaliveFatal = new WebHttpError("aborted", "本地凭据已被登出或更新");
              ws.close();
            }
          } catch (persistErr) {
            onWarn?.(persistErr instanceof Error ? persistErr.message : "保活持久化个人 Web 会话凭据失败");
            keepaliveFatal = persistErr instanceof Error ? persistErr : new WebHttpError("transport", "保活持久化个人 Web 会话凭据失败");
            ws.close();
          }
        })
        .catch((err: unknown) => {
          if (isCredentialDenied(err)) {
            keepaliveFatal = err as Error;
            ws.close();
          }
        });
    }, this.opts.keepaliveIntervalMs);
    kaTimer.unref?.();

    let publicationBlocked = false;
    let malformedReported = false;

    try {
      onState("listening");
      while (!loopCtrl.signal.aborted) {
        const frame = await ws.read(this.opts.socketIdleTimeoutMs, loopCtrl.signal);
        if (keepaliveFatal) throw keepaliveFatal;
        if (frame.kind !== "binary") continue;

        let packet: ReturnType<typeof decodeFrame>;
        try {
          packet = decodeFrame(frame.data);
        } catch (err) {
          if (!malformedReported) {
            malformedReported = true;
            onWarn?.(`忽略畸形个人 Web 推送帧：${err instanceof Error ? err.message : String(err)}`);
          }
          // Malformed frames remain unacknowledged without tearing down the healthy socket
          continue;
        }
        malformedReported = false;

        if (packet.uint(3) === CMD_PUSH_PACKET) {
          const delivered = await this.handlePush(
            packet.bytes(5),
            loopCtrl.signal,
            onMessage,
            onWarn,
            shouldDeliverInvalid,
          );
          if (!delivered) {
            if (!publicationBlocked) {
              publicationBlocked = true;
              onState("publication_blocked", "消息写入本地存储失败，暂缓 ACK 等待重试");
            }
            // Backpressure: do NOT acknowledge when persistence failed!
            continue;
          }
          if (publicationBlocked) {
            publicationBlocked = false;
            onState("listening");
          }
        }

        const sid = packet.str(1);
        if (sid) {
          await ws.writeBinary(encodeAckFrame(sid), 15_000, loopCtrl.signal);
        }
      }
      if (keepaliveFatal) throw keepaliveFatal;
    } catch (err) {
      if (keepaliveFatal) throw keepaliveFatal;
      throw err;
    } finally {
      clearInterval(hbTimer);
      clearInterval(kaTimer);
      outerSignal.removeEventListener("abort", onOuterAbort);
      loopCtrl.abort();
      ws.close();
    }
  }

  private async handlePush(
    payload: Buffer,
    signal: AbortSignal,
    onMessage: (msg: WebMessage) => Promise<void> | void,
    onWarn?: (message: string) => void,
    shouldDeliverInvalid?: (msg: WebMessage) => boolean,
  ): Promise<boolean> {
    let push: ReturnType<typeof parseProto>;
    try {
      push = parseProto(payload, MAX_WIRE_BYTES);
    } catch (err) {
      onWarn?.(`推送载荷解析失败：${err instanceof Error ? err.message : String(err)}`);
      return false;
    }

    let rejected = false;
    for (const entry of push.allBytes(1)) {
      if (signal.aborted) return false;
      let msg: WebMessage;
      try {
        const pair = parseProto(entry, MAX_WIRE_BYTES);
        msg = decodeMessage(pair.bytes(2), this.ownerId);
      } catch (err) {
        // One undecodable message entry must neither starve siblings nor stall ACK forever
        onWarn?.(`跳过无法解码的个人消息：${err instanceof Error ? err.message : String(err)}`);
        continue;
      }
      if (msg.unsupported || (!msg.text.trim() && msg.resources.length === 0)) {
        // 允许已知活跃消息的空正文/不支持类型编辑推送透传给上层以撤回本地旧正文，同时继续过滤全新无效推送
        if (!shouldDeliverInvalid?.(msg)) continue;
      }
      try {
        await onMessage(msg);
      } catch (err) {
        if (signal.aborted) return false;
        onWarn?.(`个人消息落库失败（将不 ACK）：${err instanceof Error ? err.message : String(err)}`);
        rejected = true;
      }
    }
    return !rejected;
  }
}
