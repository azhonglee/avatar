import type { App } from "../app.ts";
import type { CtxPersonalWebStatus } from "../api/types.ts";
import { errMsg, log } from "../util.ts";
import {
  FeishuWebClient,
  GatewayError,
  isUsableWebMessage,
  SessionNeedsLoginError,
  USER_SENDER_TYPE,
  WebHttpError,
  WebLoginStore,
  type FeishuWebClientOptions,
  type ListenerState,
  type VerifiedReplyResult,
  type WebLogin,
  type WebMessage,
} from "./feishu-web/index.ts";
import { isRealConvName, type ContextStore, type Obs } from "./store.ts";

/**
 * 个人 Web 协议桥接层：把 FeishuWebClient 的实时推送接入 Working Context。
 *
 * 职责：
 *   1. 管理 AES-256-GCM 加密的 0600 凭据文件（<dataDir>/feishu-web.json）与长连接生命周期；
 *   2. 收到推送后先持久化到 ctx_obs 再返回（保留背压 ACK：落库失败绝不 ACK）；
 *   3. 严格执行群排除（groups_deny / muted）与范围过滤，支持撤回/清空消息同步删除本地观测；
 *   4. 对「真实 @本人」与「对方私聊」按会话防抖后触发单会话快通道（不等 10 分钟定时周期）；
 *   5. 仅在用户显式确认草稿后，才按需经个人 Web 协议执行带发送前核验、幂等回执与独立回读确认的回复。
 */

export const BOUND_OWNER_KV_KEY = "ctx.personal_web.bound_owner_id";
const STATE_KV_KEY = "ctx.personal_web.state";
const SPOKEN_GROUPS_KV_KEY = "ctx.personal_web.spoken_groups";
const DELIVERY_KV_PREFIX = "ctx.pw_delivery.";
const CRED_WATCH_INTERVAL_MS = 3_000;

export type FastAnchor = Pick<
  WebMessage,
  "id" | "conversationId" | "rootId" | "parentId" | "threadId" | "position" | "createdAtMs"
>;

export interface FastTrigger {
  conv: string;
  conv_name: string;
  trigger_obs_id: string;
  anchor: FastAnchor;
}

interface PersistedState {
  state: ListenerState;
  owner_id: string;
  owner_name: string;
  since: number;
  last_message_at: number | null;
  last_error: string;
}

interface DeliveryRecord {
  /** sending：已开始发包但结果未知（可能已送达），不得自动重发 */
  status: "sending" | "created" | "verified";
  replyId: string;
  chatId: string;
  rootId: string;
  parentId: string;
  threaded: boolean;
  threadId?: string;
  updatedAt: number;
}

export interface PersonalWebBridgeHooks {
  onFastTrigger: (t: FastTrigger) => void;
  onReconnect: () => void;
  onNeedsLogin: (reason: string) => void;
  clientOptions?: FeishuWebClientOptions;
  /** 仅测试覆盖：控制凭据文件变更轮询周期 */
  watchIntervalMs?: number;
}

/** 核验个人 Web 登录账号与当前工作区的绑定关系（防误登他人账号覆盖工作区上下文）。 */
export function verifyLoginForWorkspace(app: App, login: WebLogin, opts: { forceSwitch?: boolean } = {}): void {
  const cfgOpenId = app.cfg.owner.open_id.trim();
  // open_id 按应用区分：网页端拿到的 open_id 属于飞书网页应用，与 lark-cli 自建应用下的值天然不同，只能作提示，不能据此拒绝
  if (cfgOpenId && login.owner_open_id && login.owner_open_id !== cfgOpenId) {
    log("warn", "个人 Web 资料返回的 open_id 与 config.yaml 的 owner.open_id 不同（open_id 按应用区分，可能属正常）", {
      web_open_id: login.owner_open_id,
      owner_open_id: cfgOpenId,
    });
  }
  const bound = (app.store.get(BOUND_OWNER_KV_KEY) ?? "").trim();
  if (bound && bound !== login.owner_id && !opts.forceSwitch) {
    throw new Error(
      `当前工作区已绑定个人 Web 账号 ${bound}，与本次登录账号 ${login.owner_id} 不一致；如确需切换请追加 --force-switch-account`,
    );
  }
}

export class PersonalWebBridge {
  private readonly app: App;
  private readonly store: ContextStore;
  private readonly hooks: PersonalWebBridgeHooks;
  readonly loginStore: WebLoginStore;
  private client: FeishuWebClient | undefined;
  private stopCtrl: AbortController | undefined;
  private readonly debounceTimers = new Map<string, NodeJS.Timeout>();
  private state: PersistedState;

  constructor(app: App, store: ContextStore, hooks: PersonalWebBridgeHooks) {
    this.app = app;
    this.store = store;
    this.hooks = hooks;
    this.loginStore = new WebLoginStore(app.cfg.dataDir);
    const saved = this.loadSavedState();
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

  private get cfg() {
    return this.app.cfg;
  }

  private loadSavedState(): PersistedState | undefined {
    const raw = this.app.store.get(STATE_KV_KEY);
    if (!raw) return undefined;
    try {
      return JSON.parse(raw) as PersistedState;
    } catch {
      return undefined;
    }
  }

  private persistState(patch: Partial<PersistedState>): void {
    this.state = { ...this.state, ...patch };
    try {
      this.app.store.set(STATE_KV_KEY, JSON.stringify(this.state));
    } catch {
      // ignore storage errors while reporting state
    }
  }

  status(): CtxPersonalWebStatus {
    const inspected = this.loginStore.inspect();
    const login = inspected.status === "ok" ? inspected.login : undefined;
    const saved = this.loadSavedState() ?? this.state;
    const enabled = this.cfg.context.personal_web.enabled;
    const loggedIn = !!login;
    let state = saved.state;
    let lastError = saved.last_error;
    if (!enabled) {
      state = "idle";
    } else if (!loggedIn) {
      if (inspected.status === "missing_key") {
        state = "needs_login";
        lastError = lastError || "缺少解密密钥（PA_FEISHU_WEB_KEY 或 CREDENTIALS_DIRECTORY/feishu-web-key）";
      } else if (inspected.status === "plaintext_rejected") {
        state = "needs_login";
        lastError = lastError || "检测到未加密的旧凭据文件，请设置密钥后重新执行 pa context web-login";
      } else if (state === "idle") {
        state = "needs_login";
      }
    }
    return {
      enabled,
      logged_in: loggedIn,
      state,
      owner_id: login?.owner_id || saved.owner_id,
      owner_name: login?.owner_name || saved.owner_name,
      last_message_at: saved.last_message_at,
      last_error: lastError,
    };
  }

  /** 启动个人 Web 长连接监听（异步后台运行，不阻塞常驻进程启动）。 */
  start(): { stop(): void } {
    if (!this.cfg.context.personal_web.enabled) return { stop: () => undefined };
    this.stop();
    const ctrl = new AbortController();
    this.stopCtrl = ctrl;
    void this.runSupervisor(ctrl.signal);
    return { stop: () => this.stop() };
  }

  stop(): void {
    this.stopCtrl?.abort();
    this.stopCtrl = undefined;
    this.client = undefined;
    for (const timer of this.debounceTimers.values()) clearTimeout(timer);
    this.debounceTimers.clear();
  }

  private sessionKeyOf(login: WebLogin | undefined): string {
    if (!login) return "";
    return `${login.owner_id}:${login.session_id ?? ""}`;
  }

  private async runSupervisor(signal: AbortSignal): Promise<void> {
    const watchMs = this.hooks.watchIntervalMs ?? CRED_WATCH_INTERVAL_MS;
    let connectDelayMs = 2_000;
    let connectDenials = 0;
    let wasDegraded = false;
    let everConnected = false;
    let failedSessionKey = "";

    const handleState = (next: ListenerState, detail = "") => {
      if (next === "reconnecting" || next === "reverifying") wasDegraded = true;
      if (next === "listening") {
        if (wasDegraded && everConnected) {
          wasDegraded = false;
          this.hooks.onReconnect();
        }
        everConnected = true;
      }
      this.persistState({
        state: next,
        owner_id: this.client?.owner().id ?? this.state.owner_id,
        owner_name: this.client?.owner().name ?? this.state.owner_name,
        since: Date.now(),
        last_error: next === "listening" || next === "stopped" ? "" : detail,
      });
      if (next === "needs_login") {
        this.hooks.onNeedsLogin(detail || "个人 Web 会话已失效，请重新扫码登录");
      }
    };

    while (!signal.aborted) {
      const inspected = this.loginStore.inspect();
      const login = inspected.status === "ok" ? inspected.login : undefined;
      const curKey = this.sessionKeyOf(login);

      if (!login) {
        const msg =
          inspected.status === "missing_key"
            ? "缺少个人 Web 凭据解密密钥（请配置 PA_FEISHU_WEB_KEY 或 CREDENTIALS_DIRECTORY/feishu-web-key）"
            : inspected.status === "plaintext_rejected"
              ? "检测到明文凭据文件，请配置密钥并重新运行 `pa context web-login`"
              : "尚未完成个人 Web 扫码登录，请运行 `pa context web-login`";
        if (this.state.state !== "needs_login" || this.state.last_error !== msg) {
          handleState("needs_login", msg);
        }
        await waitAbortable(watchMs, signal);
        continue;
      }

      // 若同一失效会话尚未被重新扫码替换，静默等待磁盘出现新会话而不刷屏重连
      if (failedSessionKey && curKey === failedSessionKey) {
        await waitAbortable(watchMs, signal);
        continue;
      }
      failedSessionKey = "";

      try {
        verifyLoginForWorkspace(this.app, login);
      } catch (err) {
        failedSessionKey = curKey;
        handleState("needs_login", errMsg(err));
        await waitAbortable(watchMs, signal);
        continue;
      }

      const sessionCtrl = new AbortController();
      const onOuterAbort = () => sessionCtrl.abort();
      signal.addEventListener("abort", onOuterAbort, { once: true });

      // 轻量监控凭据是否被 `web-logout` 删除或被新一次 `web-login` 替换
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
            ...this.hooks.clientOptions,
            onSessionConfirmed: (updated) => {
              const saved = this.loginStore.saveIfSessionMatches(updated);
              if (!saved) return false;
              if (saved.owner_name && !this.app.store.get("ctx.owner_name")) {
                this.app.store.set("ctx.owner_name", saved.owner_name);
              }
              return saved;
            },
          },
          sessionCtrl.signal,
        );
        this.client = client;
        if (!this.app.store.get(BOUND_OWNER_KV_KEY)) {
          this.app.store.set(BOUND_OWNER_KV_KEY, client.owner().id);
        }
        connectDelayMs = 2_000;
        connectDenials = 0;
        if (client.owner().name && !this.app.store.get("ctx.owner_name")) {
          this.app.store.set("ctx.owner_name", client.owner().name);
        }
        log("info", "个人 Web 通道已连接", { owner_id: client.owner().id, owner_name: client.owner().name });

        await client.listen({
          signal: sessionCtrl.signal,
          onMessage: (msg) => this.handleMessage(msg, client, sessionCtrl.signal),
          shouldDeliverInvalid: (msg) => !!msg.id && !!this.store.obs(`pw:${msg.id}`),
          onState: handleState,
          onWarn: (m) => log("warn", m),
        });
      } catch (err) {
        if (signal.aborted) return;
        this.client = undefined;
        // 本地登出/重新登录触发的主动中断：直接进入下一轮加载新状态
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

  private botAllowed(text: string): boolean {
    return this.cfg.context.bot_allow.some((p) => {
      try {
        return new RegExp(p, "i").test(text.slice(0, 300));
      } catch {
        return text.includes(p);
      }
    });
  }

  /** 同一会话在两个通道下的 ID：原生 ID、pw_chat: 前缀形式，以及跨通道匹配记下的开放平台 oc_ ID */
  private chatIds(chatId: string): Set<string> {
    const open = this.store.pwAlias("chat", chatId);
    return new Set([chatId, `pw_chat:${chatId}`, ...(open ? [open] : [])]);
  }

  /** lark-cli 通道记下的 oc_ 群 ID → 群名，用来把按 oc_ ID 写的规则对上个人 Web 会话 */
  private openGroupName(openChatId: string): string {
    try {
      const spoken = JSON.parse(this.app.store.get("ctx.spoken_groups") ?? "{}") as Record<string, { name?: string }>;
      return String(spoken[openChatId]?.name ?? "");
    } catch {
      return "";
    }
  }

  /** 规则项 r 是否指向这个会话：ID 相等，或群名包含关键字，或 r 是 oc_ ID 且其已知群名与会话名一致 */
  private ruleMatches(r: string, ids: Set<string>, chatName: string): boolean {
    if (!r) return false;
    if (ids.has(r)) return true;
    if (!chatName) return false;
    if (chatName.includes(r)) return true;
    return r.startsWith("oc_") && this.openGroupName(r) === chatName;
  }

  isDeniedChat(chatId: string, chatName: string): boolean {
    const ids = this.chatIds(chatId);
    if (this.cfg.context.groups_deny.some((d) => this.ruleMatches(d, ids, chatName))) return true;
    const muted = this.store.mutedConvs();
    return muted.some((m) => ids.has(m.conv) || (!!chatName && m.name === chatName));
  }

  /** 是否存在要靠会话名才能判定的排除或静音规则（查不到会话名时据此决定是否放行） */
  private hasNameBasedExclusions(): boolean {
    return this.cfg.context.groups_deny.some(Boolean) || this.store.mutedConvs().length > 0;
  }

  private loadSpokenGroups(): Set<string> {
    const raw = this.app.store.get(SPOKEN_GROUPS_KV_KEY);
    if (!raw) return new Set();
    try {
      const arr = JSON.parse(raw) as unknown;
      return new Set(Array.isArray(arr) ? arr.filter((x): x is string => typeof x === "string") : []);
    } catch {
      return new Set();
    }
  }

  private markSpokenGroup(chatId: string): void {
    const set = this.loadSpokenGroups();
    if (set.has(chatId)) return;
    set.add(chatId);
    const trimmed = [...set].slice(-500);
    this.app.store.set(SPOKEN_GROUPS_KV_KEY, JSON.stringify(trimmed));
  }

  private isGroupInScope(chatId: string, chatName: string, isAtMe: boolean): boolean {
    if (isAtMe) return true;
    const ids = this.chatIds(chatId);
    const inAllow = this.cfg.context.groups_allow.some((a) => this.ruleMatches(a, ids, chatName));
    if (this.cfg.context.groups === "allowlist") return inAllow;
    return inAllow || this.loadSpokenGroups().has(chatId);
  }

  /**
   * 将单条个人 Web 推送消息落库，并对「@我」和「对方私聊」触发防抖快通道。
   * 抛出异常时外层 `FeishuWebClient` 不会发送 ACK，确保背压不丢消息。
   */
  async handleMessage(msg: WebMessage, client?: FeishuWebClient, signal?: AbortSignal): Promise<void> {
    const obsId = `pw:${msg.id}`;
    // 已知消息被撤回/编辑为空/转为不支持类型：删除本地旧观测
    if (msg.unsupported || (!msg.text.trim() && msg.resources.length === 0)) {
      this.store.deleteObs(obsId);
      return;
    }

    const ownerId = client?.owner().id || this.state.owner_id;
    const ownerName = this.app.store.get("ctx.owner_name") || client?.owner().name || this.state.owner_name || "我";
    const isMe = !!ownerId && msg.actorId === ownerId;
    const isHuman = msg.senderType === USER_SENDER_TYPE;
    const text = msg.text.trim();

    if (!isHuman && !this.botAllowed(text)) return;

    // 群和私聊都查会话名（私聊的会话名即对方姓名），排除/静音规则和姓名展示都要用
    let chatName = "";
    if (client && msg.conversationKind) {
      try {
        chatName = (await client.readChat(msg.conversationId, { signal })).name.trim();
      } catch (err) {
        // 查不到名称时无法判断是否命中按名称的排除/静音规则：抛出以不 ACK，等重投后再判断，绝不按“未命中”放行
        if (this.hasNameBasedExclusions()) {
          throw new Error(`查询会话名称失败，无法核对排除规则，暂不处理该消息：${errMsg(err)}`);
        }
      }
    }
    if (this.isDeniedChat(msg.conversationId, chatName)) return;

    const isAtMe = !isMe && !!ownerId && msg.mentions.some((m) => m.id === ownerId);
    if (msg.conversationKind === "group") {
      if (isMe) this.markSpokenGroup(msg.conversationId);
      else if (!this.isGroupInScope(msg.conversationId, chatName, isAtMe)) return;
    }

    const conv = `pw_chat:${msg.conversationId}`;
    const actorName = isMe ? ownerName : this.actorDisplayName(msg.actorId, msg.conversationKind, chatName);
    const convName =
      chatName || (msg.conversationKind === "dm" ? `私聊：${isMe ? "本人" : actorName}` : `群聊(${msg.conversationId.slice(-6)})`);
    const kind = !isHuman ? "bot" : isMe ? "mine" : isAtMe ? "at_me" : msg.conversationKind === "dm" ? "p2p" : "group";

    const obs: Obs = {
      id: obsId,
      source: "im",
      kind,
      conv,
      conv_name: convName,
      actor_id: msg.actorId,
      actor_name: actorName,
      is_me: isMe,
      time: msg.createdAtMs || Date.now(),
      text: text.slice(0, 2000),
      url: "",
      meta: {
        transport: "personal_web",
        native_message_id: msg.id,
        native_chat_id: msg.conversationId,
        native_root_id: msg.rootId || msg.id,
        native_parent_id: msg.parentId,
        thread_id: msg.threadId,
        position: msg.position,
        chat_type: msg.conversationKind === "dm" ? "p2p" : "group",
        sender_type: isHuman ? "user" : "app",
        at_me: isAtMe,
        mentions: msg.mentions,
        resources: msg.resources,
      },
    };

    const inserted = this.store.addObs([obs]);
    this.persistState({ last_message_at: Date.now() });

    const pwCfg = this.cfg.context.personal_web;
    const shouldFastLane =
      inserted > 0 &&
      pwCfg.fast_lane &&
      this.cfg.context.understand &&
      !isMe &&
      isHuman &&
      (isAtMe || msg.conversationKind === "dm");

    if (!shouldFastLane) return;

    const trigger: FastTrigger = {
      conv,
      conv_name: convName,
      trigger_obs_id: obs.id,
      anchor: {
        id: msg.id,
        conversationId: msg.conversationId,
        rootId: msg.rootId,
        parentId: msg.parentId,
        threadId: msg.threadId,
        position: msg.position,
        createdAtMs: msg.createdAtMs,
      },
    };
    this.scheduleFastLane(trigger);
  }

  /** 对方姓名：跨通道匹配记下的姓名；私聊里对方发的消息用会话名（即对方姓名）；都没有才退回原生 ID */
  private actorDisplayName(actorId: string, kind: WebMessage["conversationKind"], chatName: string): string {
    return this.store.pwAlias("actor", actorId) || (kind === "dm" && isRealConvName(chatName) ? chatName : actorId);
  }

  private scheduleFastLane(trigger: FastTrigger): void {
    const prev = this.debounceTimers.get(trigger.conv);
    if (prev) clearTimeout(prev);
    const delay = this.cfg.context.personal_web.debounce_ms;
    if (delay <= 0) {
      this.hooks.onFastTrigger(trigger);
      return;
    }
    const timer = setTimeout(() => {
      this.debounceTimers.delete(trigger.conv);
      this.hooks.onFastTrigger(trigger);
    }, delay);
    timer.unref?.();
    this.debounceTimers.set(trigger.conv, timer);
  }

  /** 快通道理解前补读该会话的历史背景消息（最多 15 条，标记为已处理背景，不重复提取旧噪音）。 */
  async hydrateContext(anchor: FastAnchor, conv: string, convName: string, signal?: AbortSignal): Promise<number> {
    if (!this.client) return 0;
    const existing = this.store.convObs(conv, Date.now() - 24 * 3_600_000, 6);
    if (existing.length >= 5) return 0;
    try {
      const history = await this.client.readContext(anchor, { limit: 15, signal });
      if (!history.length) return 0;
      const ownerId = this.client.owner().id;
      const ownerName = this.app.store.get("ctx.owner_name") || this.client.owner().name || "我";
      const bg: Obs[] = history
        .filter((m) => isUsableWebMessage(m) || (m.id && m.text.trim()))
        .map((m) => {
          const isMe = m.actorId === ownerId;
          return {
            id: `pw:${m.id}`,
            source: "im",
            kind: m.senderType !== USER_SENDER_TYPE ? "bot" : isMe ? "mine" : m.conversationKind === "dm" ? "p2p" : "group",
            conv,
            conv_name: convName,
            actor_id: m.actorId,
            actor_name: isMe ? ownerName : this.actorDisplayName(m.actorId, m.conversationKind, convName),
            is_me: isMe,
            time: m.createdAtMs || Date.now(),
            text: m.text.trim().slice(0, 2000),
            url: "",
            meta: {
              transport: "personal_web",
              native_message_id: m.id,
              native_chat_id: m.conversationId,
              native_root_id: m.rootId || m.id,
              native_parent_id: m.parentId,
              thread_id: m.threadId,
              position: m.position,
              chat_type: m.conversationKind === "dm" ? "p2p" : "group",
              sender_type: m.senderType === USER_SENDER_TYPE ? "user" : "app",
              background: true,
            },
          };
        });
      return this.store.addBackgroundObs(bg);
    } catch (e) {
      log("warn", "快通道补读会话背景失败（继续理解当前消息）", { conv, err: errMsg(e) });
      return 0;
    }
  }

  private loadDelivery(cid: string): DeliveryRecord | undefined {
    const raw = this.app.store.get(`${DELIVERY_KV_PREFIX}${cid}`);
    if (!raw) return undefined;
    try {
      return JSON.parse(raw) as DeliveryRecord;
    } catch {
      return undefined;
    }
  }

  private saveDelivery(cid: string, rec: DeliveryRecord): void {
    this.app.store.set(`${DELIVERY_KV_PREFIX}${cid}`, JSON.stringify(rec));
  }

  /**
   * 确认草稿后的个人 Web 回复：
   *   - 校验 send_replies 开关、凭据与群排除策略；
   *   - 基于固定 cid 做幂等回执（若上次已发出但未完成回读，重试时直接回读核验绝不重复发送）；
   *   - 发送前核验原消息可用性，发送后独立回读核验。
   */
  async sendVerifiedReply(args: {
    chat_id: string;
    message_id: string;
    root_id?: string;
    text: string;
    cid: string;
  }): Promise<VerifiedReplyResult> {
    const prev = this.loadDelivery(args.cid);
    if (prev?.status === "verified") {
      return {
        replyId: prev.replyId,
        rootId: prev.rootId,
        parentId: prev.parentId,
        threadId: prev.threadId ?? "",
        verified: true,
      };
    }

    if (prev?.status === "sending") {
      throw new Error("上次个人 Web 发送结果不明确（对方可能已经收到），为避免重复发送已停止自动重试；请先在飞书核实");
    }
    // 已发出只差回读核验的回复不需要发送权限，关掉 send_replies 后仍可完成确认
    const readbackOnly = prev?.status === "created" && !!prev.replyId;
    if (!readbackOnly && !this.cfg.context.personal_web.send_replies) {
      throw new Error("未开启个人 Web 回复（需在配置中设置 context.personal_web.send_replies: true）");
    }

    let client = this.client;
    if (!client) {
      const login = this.loginStore.load();
      if (!login) throw new Error("个人 Web 未登录，请先运行 `pa context web-login`");
      verifyLoginForWorkspace(this.app, login);
      client = await FeishuWebClient.connect(login, {
        ...this.hooks.clientOptions,
        onSessionConfirmed: (updated) => this.loginStore.saveIfSessionMatches(updated) ?? false,
      });
    }

    // 上次已成功发包但回读中断：直接走回读核验，绝不二次发包
    if (readbackOnly && prev) {
      const res = await client.verifyReplyReadback({
        replyId: prev.replyId,
        chatId: prev.chatId,
        rootId: prev.rootId,
        parentId: prev.parentId,
        cid: args.cid,
        text: args.text,
        threaded: prev.threaded,
      });
      this.saveDelivery(args.cid, { ...prev, status: "verified", threadId: res.threadId, updatedAt: Date.now() });
      return res;
    }

    let entered = false;
    let created = false;
    let res: VerifiedReplyResult;
    try {
      res = await client.sendVerifiedReply(
        {
          chatId: args.chat_id,
          messageId: args.message_id,
          rootId: args.root_id,
          text: args.text,
          cid: args.cid,
        },
        {
          onBeforeSend: ({ chat, rootId, parentId, threaded }) => {
            if (this.isDeniedChat(args.chat_id, chat.name)) {
              throw new Error(`目标会话「${chat.name || args.chat_id}」已被排除或静音，拒绝发送个人 Web 回复`);
            }
            // 发包前先记 sending：之后若结果不明（超时、断线、进程被杀），重试会停在这里而不是再发一次
            this.saveDelivery(args.cid, { status: "sending", replyId: "", chatId: args.chat_id, rootId, parentId, threaded, updatedAt: Date.now() });
            entered = true;
          },
          onCreated: ({ replyId, rootId, parentId, threaded }) => {
            created = true;
            this.saveDelivery(args.cid, {
              status: "created",
              replyId,
              chatId: args.chat_id,
              rootId,
              parentId,
              threaded,
              updatedAt: Date.now(),
            });
          },
        },
      );
    } catch (err) {
      // 只有服务端明确拒绝（未创建消息）才撤销 sending 允许重试；结果不明时保留 sending
      if (entered && !created && isDefinitiveNonCreationError(err)) this.app.store.set(`${DELIVERY_KV_PREFIX}${args.cid}`, "");
      throw err;
    }
    this.saveDelivery(args.cid, {
      status: "verified",
      replyId: res.replyId,
      chatId: args.chat_id,
      rootId: res.rootId,
      parentId: res.parentId,
      threaded: res.threadId !== "",
      threadId: res.threadId,
      updatedAt: Date.now(),
    });
    return res;
  }
}

/** 请求被服务端明确拒绝（因此确定没有创建消息）的错误；超时、断线、5xx、空载荷都不算 */
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
