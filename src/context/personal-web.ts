import type { App } from "../app.ts";
import type { CtxPersonalWebStatus } from "../api/types.ts";
import { errMsg, log } from "../util.ts";
import {
  FeishuWebClient,
  USER_SENDER_TYPE,
  WebHttpError,
  WebLoginStore,
  type FeishuWebClientOptions,
  type ListenerState,
  type VerifiedReplyResult,
  type WebMessage,
} from "./feishu-web/index.ts";
import type { ContextStore, Obs } from "./store.ts";

/**
 * 个人 Web 协议桥接层：把 FeishuWebClient 的实时推送接入 Working Context。
 *
 * 职责：
 *   1. 管理 0600 凭据文件（<dataDir>/feishu-web.json）与长连接生命周期；
 *   2. 收到推送后先持久化到 ctx_obs 再返回（保留背压 ACK：落库失败绝不 ACK）；
 *   3. 对「真实 @本人」与「对方私聊」按会话防抖后触发单会话快通道（不等 10 分钟定时周期）；
 *   4. 快通道理解前按需通过 readContext 补读当前会话 / 话题锚点背景；
 *   5. 仅在用户显式确认草稿后，才按需经个人 Web 协议执行带回读校验的回复。
 */

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

export interface PersonalWebBridgeHooks {
  onFastTrigger: (t: FastTrigger) => void;
  onReconnect: () => void;
  onNeedsLogin: (reason: string) => void;
  clientOptions?: FeishuWebClientOptions;
}

const STATE_KV_KEY = "ctx.personal_web.state";

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
    const login = this.loginStore.load();
    const saved = this.loadSavedState() ?? this.state;
    const enabled = this.cfg.context.personal_web.enabled;
    const loggedIn = !!login;
    let state = saved.state;
    if (!enabled) state = "idle";
    else if (!loggedIn && state === "idle") state = "needs_login";
    return {
      enabled,
      logged_in: loggedIn,
      state,
      owner_id: login?.owner_id || saved.owner_id,
      owner_name: login?.owner_name || saved.owner_name,
      last_message_at: saved.last_message_at,
      last_error: saved.last_error,
    };
  }

  /** 启动个人 Web 长连接监听（异步后台运行，不阻塞常驻进程启动）。 */
  start(): { stop(): void } {
    if (!this.cfg.context.personal_web.enabled) return { stop: () => undefined };
    this.stop();

    const login = this.loginStore.load();
    if (!login) {
      const msg = "尚未完成个人 Web 扫码登录，请运行 `pa context web-login`";
      this.persistState({ state: "needs_login", owner_id: "", owner_name: "", since: Date.now(), last_error: msg });
      log("warn", "个人 Web 通道未启动：缺少登录凭据", { file: this.loginStore.file });
      return { stop: () => this.stop() };
    }

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

  private async runSupervisor(signal: AbortSignal): Promise<void> {
    let connectDelayMs = 2_000;
    let connectDenials = 0;
    let wasDegraded = false;
    let everConnected = false;

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
      const login = this.loginStore.load();
      if (!login) {
        handleState("needs_login", "缺少个人 Web 登录凭据，请运行 `pa context web-login`");
        return;
      }

      try {
        handleState("connecting");
        const client = await FeishuWebClient.connect(
          login,
          {
            ...this.hooks.clientOptions,
            onSessionConfirmed: (updated) => {
              this.loginStore.save(updated);
              if (updated.owner_name && !this.app.store.get("ctx.owner_name")) {
                this.app.store.set("ctx.owner_name", updated.owner_name);
              }
            },
          },
          signal,
        );
        this.client = client;
        connectDelayMs = 2_000;
        connectDenials = 0;
        if (client.owner().name && !this.app.store.get("ctx.owner_name")) {
          this.app.store.set("ctx.owner_name", client.owner().name);
        }
        log("info", "个人 Web 通道已连接", { owner_id: client.owner().id, owner_name: client.owner().name });

        await client.listen({
          signal,
          onMessage: (msg) => this.handleMessage(msg, client),
          onState: handleState,
          onWarn: (m) => log("warn", m),
        });
        return;
      } catch (err) {
        if (signal.aborted) return;
        this.client = undefined;
        const msg = errMsg(err);
        if (err instanceof WebHttpError && err.code === "credential_denied") {
          connectDenials++;
          if (connectDenials >= 3) {
            handleState("needs_login", msg);
            return;
          }
          handleState("reverifying", msg);
          await waitAbortable(30_000, signal);
        } else {
          handleState("reconnecting", msg);
          await waitAbortable(connectDelayMs, signal);
          connectDelayMs = Math.min(connectDelayMs * 2, 30_000);
        }
      }
    }
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

  private isDeniedChat(chatId: string, chatName: string): boolean {
    if (this.cfg.context.groups_deny.some((d) => d && (chatId === d || `pw_chat:${chatId}` === d || (chatName && chatName.includes(d))))) {
      return true;
    }
    const muted = this.store.mutedConvs();
    return muted.some((m) => m.conv === `pw_chat:${chatId}` || (chatName && m.name === chatName));
  }

  /**
   * 将单条个人 Web 推送消息落库，并在命中「真实 @本人 / 对方私聊」时触发防抖快通道。
   * 同步返回前已完成 SQLite 写入；如落库抛错，上层不会发 ACK。
   */
  async handleMessage(msg: WebMessage, client?: FeishuWebClient): Promise<void> {
    if (!msg.id || !msg.conversationId || msg.unsupported) return;
    const text = msg.text.trim();
    if (!text) return;

    const activeClient = client ?? this.client;
    const ownerId = msg.ownerId || activeClient?.owner().id || this.loginStore.load()?.owner_id || "";
    const isMe = !!ownerId && msg.actorId === ownerId;
    const isHuman = msg.senderType === USER_SENDER_TYPE;

    // 机器人消息沿用与 lark-cli 相同的 bot_allow 过滤规则
    if (!isHuman && !this.botAllowed(text)) return;

    let chatName = "";
    if (msg.conversationKind === "group" && activeClient) {
      try {
        chatName = (await activeClient.readChat(msg.conversationId)).name;
      } catch {
        // 群名查询失败不阻塞消息入库
      }
    }
    if (this.isDeniedChat(msg.conversationId, chatName)) return;

    const isAtMe = !isMe && isHuman && !!ownerId && msg.mentions.some((m) => m.id === ownerId);
    const conv = `pw_chat:${msg.conversationId}`;
    const convName =
      msg.conversationKind === "dm"
        ? `私聊：${isMe ? msg.conversationId : msg.actorId || msg.conversationId}`
        : chatName || `群聊(${msg.conversationId})`;

    const obs: Obs = {
      id: `pw:${msg.id}`,
      source: "im",
      kind: !isHuman ? "bot" : isMe ? "mine" : msg.conversationKind === "dm" ? "p2p" : isAtMe ? "at_me" : "group",
      conv,
      conv_name: convName,
      actor_id: msg.actorId,
      actor_name: isMe ? this.app.store.get("ctx.owner_name") || activeClient?.owner().name || "我" : msg.actorId,
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
        .filter((m) => m.id && m.text.trim())
        .map((m) => {
          const isMe = m.actorId === ownerId;
          return {
            id: `pw:${m.id}`,
            source: "im",
            kind: m.senderType !== USER_SENDER_TYPE ? "bot" : isMe ? "mine" : m.conversationKind === "dm" ? "p2p" : "group",
            conv,
            conv_name: convName,
            actor_id: m.actorId,
            actor_name: isMe ? ownerName : m.actorId,
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

  /** 确认草稿后的个人 Web 回复：复用在线客户端或按需建立已验签连接，发送前核验原消息 + 发送后独立回读确认。 */
  async sendVerifiedReply(args: {
    chat_id: string;
    message_id: string;
    root_id?: string;
    text: string;
    cid: string;
  }): Promise<VerifiedReplyResult> {
    if (!this.cfg.context.personal_web.send_replies) {
      throw new Error("未开启个人 Web 回复（需在配置中设置 context.personal_web.send_replies: true）");
    }
    let client = this.client;
    if (!client) {
      const login = this.loginStore.load();
      if (!login) throw new Error("个人 Web 未登录，请先运行 `pa context web-login`");
      client = await FeishuWebClient.connect(login, {
        ...this.hooks.clientOptions,
        onSessionConfirmed: (updated) => this.loginStore.save(updated),
      });
    }
    return client.sendVerifiedReply({
      chatId: args.chat_id,
      messageId: args.message_id,
      rootId: args.root_id,
      text: args.text,
      cid: args.cid,
    });
  }
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
