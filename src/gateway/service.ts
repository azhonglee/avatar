import crypto from "node:crypto";
import { EventEmitter } from "node:events";
import type { GatewayConfig } from "./config.ts";
import {
  FeishuWebClient,
  GatewayError,
  isUsableWebMessage,
  MessageNotFoundError,
  SessionNeedsLoginError,
  UnusableOriginalMessageError,
  WebHttpError,
  WebLoginStore,
  type FeishuWebClientOptions,
  type ListenerState,
  type VerifiedReplyResult,
  type WebLogin,
  type WebMessage,
} from "./feishu-web/index.ts";
import {
  CID_RE,
  GatewayHttpError,
  MAX_CONTEXT_LIMIT,
  MAX_REPLY_TEXT_BYTES,
  type GatewayContextRequest,
  type GatewayContextResponse,
  type GatewayEvent,
  type GatewayHealth,
  type GatewayMessagePayload,
  type GatewayReplyRequest,
  type GatewayStatus,
} from "./protocol.ts";
import type { GatewayPersistedState, GatewayStore } from "./store.ts";

/**
 * 飞书个人 Web 独立网关核心服务。
 *
 * 职责边界：
 *   - 独占 AES-256-GCM 加密会话凭据（WebLoginStore）与 Frontier WSS 长连接；
 *   - 强制执行网关侧 deny_chats 黑名单（客户端不可覆盖），先落独立 SQLite 缓存再向飞书 ACK；
 *   - 实时向已订阅的 SSE 消费者广播增量事件与状态变化；
 *   - 仅当 allow_reply=true 且调用方持有独立 reply_token 时，才执行带网关侧 cid 幂等账本与独立回读确认的回复。
 */

export const GATEWAY_BOUND_OWNER_KEY = "bound_owner_id";
const CRED_WATCH_INTERVAL_MS = 3_000;
const PRUNE_INTERVAL_MS = 3_600_000;

export interface GatewayServiceOptions {
  clientOptions?: FeishuWebClientOptions;
  watchIntervalMs?: number;
  pruneIntervalMs?: number;
  onLog?: (level: "info" | "warn" | "error", msg: string, data?: Record<string, unknown>) => void;
}

function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function normalizeChatName(name: string): string {
  return name.trim().replace(/^私聊[：:]\s*/, "").trim();
}

function hashReplyText(text: string): string {
  return crypto.createHash("sha256").update(text.replace(/\r\n/g, "\n").trim(), "utf8").digest("hex");
}

function isDefinitiveNonCreationError(err: unknown): boolean {
  if (err instanceof WebHttpError && err.status !== undefined) return [400, 401, 403, 404].includes(err.status);
  if (err instanceof GatewayError) return !err.emptyPayload && typeof err.status === "number" && err.status !== 0;
  return false;
}

function waitAbortable(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal.aborted) return resolve();
    const onAbort = () => {
      clearTimeout(t);
      resolve();
    };
    const t = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    t.unref?.();
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

/** 核验登录账号与当前网关数据目录的绑定关系，避免误扫他人账号污染网关缓存。 */
export function verifyLoginForGateway(store: GatewayStore, login: WebLogin, opts: { forceSwitch?: boolean } = {}): void {
  const bound = (store.getKv(GATEWAY_BOUND_OWNER_KEY) ?? "").trim();
  if (bound && bound !== login.owner_id && !opts.forceSwitch) {
    throw new Error(
      `当前网关已绑定个人 Web 账号 ${bound}，与本次登录账号 ${login.owner_id} 不一致；如确需切换请追加 --force-switch-account`,
    );
  }
}

export class FeishuGatewayService {
  readonly cfg: GatewayConfig;
  readonly store: GatewayStore;
  readonly loginStore: WebLoginStore;
  private readonly opts: GatewayServiceOptions;
  private readonly emitter = new EventEmitter();
  private readonly inFlightCids = new Set<string>();
  private client: FeishuWebClient | undefined;
  private stopCtrl: AbortController | undefined;
  private pruneTimer: NodeJS.Timeout | undefined;
  private state: GatewayPersistedState;

  constructor(cfg: GatewayConfig, store: GatewayStore, opts: GatewayServiceOptions = {}) {
    this.cfg = cfg;
    this.store = store;
    this.opts = opts;
    this.loginStore = new WebLoginStore(cfg.dataDir);
    this.emitter.setMaxListeners(128);
    const saved = this.store.loadState();
    const login = this.loginStore.load();
    this.state = saved ?? {
      state: "idle",
      owner_id: login?.owner_id ?? "",
      owner_name: login?.owner_name ?? "",
      since: 0,
      last_message_at: null,
      last_error: "",
    };
  }

  private log(level: "info" | "warn" | "error", msg: string, data?: Record<string, unknown>): void {
    if (this.opts.onLog) {
      this.opts.onLog(level, msg, data);
      return;
    }
    const line = JSON.stringify({ t: new Date().toISOString(), level, service: "feishu-gateway", msg, ...(data ?? {}) });
    process.stderr.write(line + "\n");
  }

  onEvent(listener: (ev: GatewayEvent) => void): () => void {
    this.emitter.on("event", listener);
    return () => this.emitter.off("event", listener);
  }

  onStatus(listener: (st: GatewayStatus) => void): () => void {
    this.emitter.on("status", listener);
    return () => this.emitter.off("status", listener);
  }

  private persistState(patch: Partial<GatewayPersistedState>): void {
    this.state = { ...this.state, ...patch };
    try {
      this.store.saveState(this.state);
    } catch {
      // ignore storage failure while reporting state
    }
    this.emitter.emit("status", this.status());
  }

  private sessionKeyOf(login: WebLogin | undefined): string {
    if (!login) return "";
    return `${login.owner_id}:${login.session_id ?? ""}`;
  }

  hasDenyRules(): boolean {
    return this.cfg.deny_chats.some((r) => r.trim().length > 0);
  }

  /** 网关侧不可被客户端绕过的黑名单判定（支持原生 ID、pw_chat:<id> 与群名/私聊名关键字）。 */
  isDeniedChat(chatId: string, chatName: string): boolean {
    const ids = new Set([chatId, `pw_chat:${chatId}`]);
    const normChat = normalizeChatName(chatName);
    for (const raw of this.cfg.deny_chats) {
      const rule = raw.trim();
      if (!rule) continue;
      if (ids.has(rule)) return true;
      if (!chatName) continue;
      if (chatName.includes(rule)) return true;
      const normRule = normalizeChatName(rule);
      if (normRule && normChat === normRule) return true;
    }
    return false;
  }

  status(): GatewayStatus {
    const inspected = this.loginStore.inspect();
    const login = inspected.status === "ok" ? inspected.login : undefined;
    const stats = this.store.seqStats();
    let state = this.state.state;
    let lastError = this.state.last_error;

    if (!login) {
      if (inspected.status === "missing_key") {
        state = "needs_login";
        lastError = "缺少解密密钥（FEISHU_GW_KEY / PA_FEISHU_WEB_KEY 或 CREDENTIALS_DIRECTORY/feishu-gw-key）";
      } else if (inspected.status === "plaintext_rejected") {
        state = "needs_login";
        lastError = "检测到未加密旧凭据文件，请设置密钥后在网关侧重新执行 feishu-gateway login";
      } else if (inspected.status === "invalid") {
        state = "needs_login";
        lastError = "加密凭据解密失败或已损坏，请核对加密密钥或在网关侧重新执行 feishu-gateway login";
      } else if (state === "idle") {
        state = "needs_login";
      }
    }

    return {
      state,
      logged_in: !!login,
      credential_status: inspected.status,
      owner_id: login?.owner_id || this.state.owner_id,
      owner_name: login?.owner_name || this.state.owner_name,
      since: this.state.since,
      last_message_at: this.state.last_message_at,
      last_error: lastError,
      allow_reply: this.cfg.allow_reply,
      min_seq: stats.min_seq,
      latest_seq: stats.latest_seq,
      cached_events: stats.cached_events,
    };
  }

  health(): GatewayHealth {
    const st = this.status();
    return {
      ok: true,
      state: st.state,
      logged_in: st.logged_in,
      latest_seq: st.latest_seq,
      allow_reply: st.allow_reply,
    };
  }

  async verifyStatus(signal?: AbortSignal): Promise<GatewayStatus> {
    const inspected = this.loginStore.inspect();
    if (inspected.status !== "ok") {
      const st = this.status();
      throw new GatewayHttpError(409, `credential_${inspected.status}`, st.last_error || "尚未完成个人 Web 扫码登录", true, st);
    }
    try {
      verifyLoginForGateway(this.store, inspected.login);
    } catch (e) {
      throw new GatewayHttpError(409, "account_mismatch", errMsg(e), true, this.status());
    }
    try {
      const client = await FeishuWebClient.connect(
        inspected.login,
        {
          ...this.opts.clientOptions,
          onSessionConfirmed: (updated) => this.loginStore.saveIfSessionMatches(updated) ?? false,
        },
        signal,
      );
      const owner = client.owner();
      this.persistState({ owner_id: owner.id, owner_name: owner.name });
      return { ...this.status(), owner_id: owner.id, owner_name: owner.name, verified: true };
    } catch (e) {
      const permanent = e instanceof SessionNeedsLoginError;
      throw new GatewayHttpError(503, permanent ? "needs_login" : "verify_failed", errMsg(e), permanent, this.status());
    }
  }

  start(): { stop(): void } {
    this.stop();
    const ctrl = new AbortController();
    this.stopCtrl = ctrl;
    void this.runSupervisor(ctrl.signal);
    const pruneMs = this.opts.pruneIntervalMs ?? PRUNE_INTERVAL_MS;
    this.pruneTimer = setInterval(() => {
      try {
        const res = this.store.prune(this.cfg.retention_days, this.cfg.delivery_retention_days);
        if (res.events > 0 || res.deliveries > 0) {
          this.log("info", "已清理过期网关缓存", res);
        }
      } catch (e) {
        this.log("warn", "清理网关缓存失败", { err: errMsg(e) });
      }
    }, pruneMs);
    this.pruneTimer.unref?.();
    return { stop: () => this.stop() };
  }

  stop(): void {
    this.stopCtrl?.abort();
    this.stopCtrl = undefined;
    if (this.pruneTimer) {
      clearInterval(this.pruneTimer);
      this.pruneTimer = undefined;
    }
    this.client = undefined;
  }

  private async runSupervisor(signal: AbortSignal): Promise<void> {
    const watchMs = this.opts.watchIntervalMs ?? CRED_WATCH_INTERVAL_MS;
    let connectDelayMs = 2_000;
    let connectDenials = 0;
    let failedSessionKey = "";

    const handleState = (next: ListenerState, detail = "") => {
      this.persistState({
        state: next,
        owner_id: this.client?.owner().id ?? this.state.owner_id,
        owner_name: this.client?.owner().name ?? this.state.owner_name,
        since: Date.now(),
        last_error: next === "listening" || next === "stopped" ? "" : detail,
      });
    };

    while (!signal.aborted) {
      const inspected = this.loginStore.inspect();
      const login = inspected.status === "ok" ? inspected.login : undefined;
      const curKey = this.sessionKeyOf(login);

      if (!login) {
        const msg =
          inspected.status === "missing_key"
            ? "缺少加密密钥（FEISHU_GW_KEY / PA_FEISHU_WEB_KEY 或 CREDENTIALS_DIRECTORY/feishu-gw-key）"
            : inspected.status === "plaintext_rejected"
              ? "检测到明文凭据文件，请配置密钥并运行 `feishu-gateway login`"
              : inspected.status === "invalid"
                ? "加密凭据解密失败或已损坏，请核对加密密钥或重新运行 `feishu-gateway login`"
                : "尚未完成个人 Web 扫码登录，请运行 `feishu-gateway login`";
        if (this.state.state !== "needs_login" || this.state.last_error !== msg) {
          handleState("needs_login", msg);
        }
        await waitAbortable(watchMs, signal);
        continue;
      }

      if (failedSessionKey && curKey === failedSessionKey) {
        await waitAbortable(watchMs, signal);
        continue;
      }
      failedSessionKey = "";

      try {
        verifyLoginForGateway(this.store, login);
      } catch (err) {
        failedSessionKey = curKey;
        handleState("needs_login", errMsg(err));
        await waitAbortable(watchMs, signal);
        continue;
      }

      const sessionCtrl = new AbortController();
      const onOuterAbort = () => sessionCtrl.abort();
      signal.addEventListener("abort", onOuterAbort, { once: true });

      const watchTimer = setInterval(() => {
        if (sessionCtrl.signal.aborted) return;
        const latest = this.loginStore.load();
        if (this.sessionKeyOf(latest) !== curKey) {
          sessionCtrl.abort();
        }
      }, watchMs);
      watchTimer.unref?.();

      try {
        handleState("connecting");
        const client = await FeishuWebClient.connect(
          login,
          {
            ...this.opts.clientOptions,
            onSessionConfirmed: (updated) => this.loginStore.saveIfSessionMatches(updated) ?? false,
          },
          sessionCtrl.signal,
        );
        this.client = client;
        if (!this.store.getKv(GATEWAY_BOUND_OWNER_KEY)) {
          this.store.setKv(GATEWAY_BOUND_OWNER_KEY, client.owner().id);
        }
        connectDelayMs = 2_000;
        connectDenials = 0;
        this.log("info", "飞书个人 Web 网关已连接", { owner_id: client.owner().id, owner_name: client.owner().name });

        await client.listen({
          signal: sessionCtrl.signal,
          onMessage: async (msg) => {
            await this.handleMessage(msg, client, sessionCtrl.signal);
          },
          shouldDeliverInvalid: (msg) => !!msg.id && this.store.hasKnownMessage(msg.id),
          onState: handleState,
          onWarn: (m) => this.log("warn", m),
        });
      } catch (err) {
        if (signal.aborted) return;
        this.client = undefined;
        if (sessionCtrl.signal.aborted) continue;

        const msg = errMsg(err);
        if (err instanceof SessionNeedsLoginError) {
          failedSessionKey = curKey;
          handleState("needs_login", msg);
          await waitAbortable(watchMs, signal);
        } else if (err instanceof WebHttpError && err.code === "credential_denied") {
          connectDenials++;
          if (connectDenials >= 3) {
            failedSessionKey = curKey;
            handleState("needs_login", msg);
            await waitAbortable(watchMs, signal);
          } else {
            handleState("reverifying", msg);
            await waitAbortable(30_000, signal);
          }
        } else {
          handleState("reconnecting", msg);
          await waitAbortable(connectDelayMs, signal);
          connectDelayMs = Math.min(connectDelayMs * 2, 30_000);
        }
      } finally {
        clearInterval(watchTimer);
        signal.removeEventListener("abort", onOuterAbort);
        this.client = undefined;
      }
    }
    handleState("stopped");
  }

  /**
   * 处理飞书长连接推送：
   *   - 严格先按网关 deny_chats 过滤（命中则直接丢弃并 ACK，绝不入库）；
   *   - 落库 gw_events 事务提交后再返回（保留飞书背压 ACK）；
   *   - 撤回/清空消息时擦除历史正文并广播 delete 墓碑事件。
   */
  async handleMessage(msg: WebMessage, client?: FeishuWebClient, signal?: AbortSignal): Promise<GatewayEvent | null> {
    if (!msg.id) return null;

    if (msg.unsupported || (!msg.text.trim() && msg.resources.length === 0)) {
      if (!this.store.hasKnownMessage(msg.id)) return null;
      const ev = this.store.appendDelete(msg.id, msg.conversationId);
      this.emitter.emit("event", ev);
      return ev;
    }

    if (this.isDeniedChat(msg.conversationId, "")) return null;

    let chatName = "";
    if (client && msg.conversationKind) {
      try {
        chatName = (await client.readChat(msg.conversationId, { signal })).name.trim();
      } catch (err) {
        if (this.hasDenyRules()) {
          throw new Error(`查询会话名称失败，无法核对网关排除规则，暂不确认该消息：${errMsg(err)}`);
        }
      }
    }
    if (!chatName) {
      chatName = this.store.getChatName(msg.conversationId);
    }
    if (this.isDeniedChat(msg.conversationId, chatName)) return null;

    const ownerId = client?.owner().id || this.state.owner_id || msg.ownerId;
    const ownerName = client?.owner().name || this.state.owner_name;
    const payload: GatewayMessagePayload = {
      id: msg.id,
      conversationId: msg.conversationId,
      conversationKind: msg.conversationKind,
      chatName,
      actorId: msg.actorId,
      senderType: msg.senderType,
      text: msg.text.trim(),
      rootId: msg.rootId,
      parentId: msg.parentId,
      threadId: msg.threadId,
      position: msg.position,
      createdAtMs: msg.createdAtMs || Date.now(),
      mentions: msg.mentions,
      resources: msg.resources,
      ownerId,
      ownerName,
    };

    const ev = this.store.appendMessage(payload);
    this.persistState({ last_message_at: Date.now() });
    this.emitter.emit("event", ev);
    return ev;
  }

  /** 只读上下文补读：受网关 deny_chats 强制约束，仅返回有界历史消息。 */
  async readContext(req: GatewayContextRequest, signal?: AbortSignal): Promise<GatewayContextResponse> {
    const anchor = req?.anchor;
    if (!anchor || typeof anchor.id !== "string" || !anchor.id || typeof anchor.conversationId !== "string" || !anchor.conversationId) {
      throw new GatewayHttpError(400, "invalid_request", "缺少有效的 anchor.id 或 anchor.conversationId", true);
    }
    if (this.isDeniedChat(anchor.conversationId, "")) {
      throw new GatewayHttpError(403, "chat_denied", `会话 ${anchor.conversationId} 已被网关排除`, true);
    }
    const client = this.client;
    if (!client) {
      throw new GatewayHttpError(503, "offline", "网关当前未连接飞书个人 Web 长连接", false);
    }
    let chatName = this.store.getChatName(anchor.conversationId);
    try {
      const meta = await client.readChat(anchor.conversationId, { signal });
      if (meta.name.trim()) {
        chatName = meta.name.trim();
        this.store.upsertChat(anchor.conversationId, chatName);
      }
    } catch (err) {
      if (this.hasDenyRules()) {
        throw new GatewayHttpError(503, "chat_lookup_failed", `查询会话名称失败，无法核对网关排除规则：${errMsg(err)}`, false);
      }
    }
    if (this.isDeniedChat(anchor.conversationId, chatName)) {
      throw new GatewayHttpError(403, "chat_denied", `会话「${chatName || anchor.conversationId}」已被网关排除`, true);
    }

    const limit = Math.max(1, Math.min(MAX_CONTEXT_LIMIT, Math.floor(req.limit ?? 15)));
    const history = await client.readContext(anchor, { limit, signal });
    const owner = client.owner();
    const messages: GatewayMessagePayload[] = [];
    for (const m of history) {
      if (!(isUsableWebMessage(m) || (m.id && m.text.trim()))) continue;
      if (this.isDeniedChat(m.conversationId, chatName)) continue;
      messages.push({
        id: m.id,
        conversationId: m.conversationId,
        conversationKind: m.conversationKind,
        chatName,
        actorId: m.actorId,
        senderType: m.senderType,
        text: m.text.trim(),
        rootId: m.rootId,
        parentId: m.parentId,
        threadId: m.threadId,
        position: m.position,
        createdAtMs: m.createdAtMs || Date.now(),
        mentions: m.mentions,
        resources: m.resources,
        ownerId: owner.id,
        ownerName: owner.name,
      });
    }
    return {
      owner_id: owner.id,
      owner_name: owner.name,
      chat_name: chatName,
      messages,
    };
  }

  /**
   * 受控个人 Web 回复（仅允许经独立 reply_token 调用）：
   *   - 网关侧独立持久化 sending / created / verified 状态机（按固定 cid 防跨进程重发）；
   *   - 强制校验 allow_reply 开关与网关 deny_chats；
   *   - 发送前核验原消息可用，发送后独立回读核验。
   */
  async sendReply(req: GatewayReplyRequest, signal?: AbortSignal): Promise<VerifiedReplyResult> {
    if (!req || typeof req.chat_id !== "string" || !req.chat_id.trim()) {
      throw new GatewayHttpError(400, "invalid_request", "缺少有效的 chat_id", true);
    }
    if (typeof req.message_id !== "string" || !req.message_id.trim()) {
      throw new GatewayHttpError(400, "invalid_request", "缺少有效的 message_id", true);
    }
    if (typeof req.text !== "string" || !req.text.trim()) {
      throw new GatewayHttpError(400, "invalid_request", "回复正文不能为空", true);
    }
    if (Buffer.byteLength(req.text, "utf8") > MAX_REPLY_TEXT_BYTES) {
      throw new GatewayHttpError(400, "text_too_large", `回复正文超过上限（${MAX_REPLY_TEXT_BYTES} 字节）`, true);
    }
    if (typeof req.cid !== "string" || !CID_RE.test(req.cid)) {
      throw new GatewayHttpError(400, "invalid_cid", "cid 格式无效（需 8-128 位字母/数字/._:-）", true);
    }

    const textHash = hashReplyText(req.text);
    const prev = this.store.getDelivery(req.cid);
    if (prev) {
      if (prev.chat_id !== req.chat_id || prev.text_hash !== textHash) {
        throw new GatewayHttpError(409, "cid_mismatch", `幂等键 ${req.cid} 已被其他会话或正文占用，拒绝复发`, true);
      }
      if (prev.status === "verified") {
        return {
          replyId: prev.reply_id,
          rootId: prev.root_id,
          parentId: prev.parent_id,
          threadId: prev.thread_id,
          verified: true,
        };
      }
      if (prev.status === "sending") {
        throw new GatewayHttpError(
          409,
          "ambiguous_delivery",
          "上次个人 Web 发送结果不明确（对方可能已经收到），为避免重复发送已停止自动重试；请先在飞书核实",
          true,
        );
      }
    }

    const readbackOnly = prev?.status === "created" && !!prev.reply_id;
    if (!readbackOnly && !this.cfg.allow_reply) {
      throw new GatewayHttpError(403, "reply_disabled", "网关未开启回复权限（需在 gateway.yaml 中设置 allow_reply: true）", true);
    }
    if (!readbackOnly && this.isDeniedChat(req.chat_id, "")) {
      throw new GatewayHttpError(403, "chat_denied", `目标会话 ${req.chat_id} 已被网关排除，拒绝发送个人 Web 回复`, true);
    }

    if (this.inFlightCids.has(req.cid)) {
      throw new GatewayHttpError(409, "delivery_in_flight", `幂等键 ${req.cid} 正在处理中，请稍后重试`, false);
    }
    this.inFlightCids.add(req.cid);
    try {
      let client = this.client;
      if (!client) {
        const inspected = this.loginStore.inspect();
        if (inspected.status !== "ok") {
          const msg =
            inspected.status === "missing_key"
              ? "网关缺少凭据解密密钥（FEISHU_GW_KEY / PA_FEISHU_WEB_KEY）"
              : inspected.status === "invalid"
                ? "网关凭据解密失败或已损坏，请核对密钥或重新执行 feishu-gateway login"
                : "网关尚未登录个人 Web，请先在网关侧执行 feishu-gateway login";
          throw new GatewayHttpError(503, "needs_login", msg, true);
        }
        try {
          verifyLoginForGateway(this.store, inspected.login);
        } catch (e) {
          throw new GatewayHttpError(409, "account_mismatch", errMsg(e), true);
        }
        try {
          client = await FeishuWebClient.connect(
            inspected.login,
            {
              ...this.opts.clientOptions,
              onSessionConfirmed: (updated) => this.loginStore.saveIfSessionMatches(updated) ?? false,
            },
            signal,
          );
        } catch (e) {
          if (e instanceof SessionNeedsLoginError) {
            throw new GatewayHttpError(503, "needs_login", errMsg(e), true);
          }
          throw new GatewayHttpError(502, "gateway_connect_failed", errMsg(e), false);
        }
      }

      if (readbackOnly && prev) {
        const res = await client.verifyReplyReadback({
          replyId: prev.reply_id,
          chatId: prev.chat_id,
          rootId: prev.root_id,
          parentId: prev.parent_id,
          cid: req.cid,
          text: req.text,
          threaded: prev.threaded,
        });
        this.store.saveDelivery({
          ...prev,
          status: "verified",
          thread_id: res.threadId,
          updated_at: Date.now(),
        });
        return res;
      }

      let entered = false;
      let created = false;
      let res: VerifiedReplyResult;
      try {
        res = await client.sendVerifiedReply(
          {
            chatId: req.chat_id,
            messageId: req.message_id,
            rootId: req.root_id,
            text: req.text,
            cid: req.cid,
          },
          {
            onBeforeSend: ({ chat, rootId, parentId, threaded }) => {
              if (this.isDeniedChat(req.chat_id, chat.name)) {
                throw new GatewayHttpError(403, "chat_denied", `目标会话「${chat.name || req.chat_id}」已被网关排除，拒绝发送个人 Web 回复`, true);
              }
              this.store.saveDelivery({
                cid: req.cid,
                status: "sending",
                reply_id: "",
                chat_id: req.chat_id,
                root_id: rootId,
                parent_id: parentId,
                threaded,
                thread_id: "",
                text_hash: textHash,
                updated_at: Date.now(),
              });
              entered = true;
            },
            onCreated: ({ replyId, rootId, parentId, threaded }) => {
              created = true;
              this.store.saveDelivery({
                cid: req.cid,
                status: "created",
                reply_id: replyId,
                chat_id: req.chat_id,
                root_id: rootId,
                parent_id: parentId,
                threaded,
                thread_id: "",
                text_hash: textHash,
                updated_at: Date.now(),
              });
            },
          },
        );
      } catch (err) {
        if (err instanceof GatewayHttpError) throw err;
        if (entered && !created) {
          if (isDefinitiveNonCreationError(err)) {
            this.store.deleteDelivery(req.cid);
            throw new GatewayHttpError(502, "upstream_rejected", errMsg(err), false);
          }
          throw new GatewayHttpError(
            409,
            "ambiguous_delivery",
            `个人 Web 发送结果不明确（对方可能已经收到），为避免重复发送已停止自动重试；请先在飞书核实（原错误：${errMsg(err)}）`,
            true,
          );
        }
        if (!entered && (err instanceof UnusableOriginalMessageError || err instanceof MessageNotFoundError)) {
          throw new GatewayHttpError(422, "unusable_original", errMsg(err), true);
        }
        if (err instanceof SessionNeedsLoginError) {
          throw new GatewayHttpError(503, "needs_login", errMsg(err), true);
        }
        throw new GatewayHttpError(502, "reply_failed", errMsg(err), false);
      }

      this.store.saveDelivery({
        cid: req.cid,
        status: "verified",
        reply_id: res.replyId,
        chat_id: req.chat_id,
        root_id: res.rootId,
        parent_id: res.parentId,
        threaded: res.threadId !== "",
        thread_id: res.threadId,
        text_hash: textHash,
        updated_at: Date.now(),
      });
      return res;
    } finally {
      this.inFlightCids.delete(req.cid);
    }
  }
}
