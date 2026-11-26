import { createHash } from "node:crypto";
import type { App } from "../app.ts";
import type { CtxPersonalWebStatus } from "../api/types.ts";
import { errMsg, log } from "../util.ts";
import {
  FeishuWebClient,
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
import { norm, type ContextStore, type Obs } from "./store.ts";

/**
 * 个人 Web 协议桥接层：把 FeishuWebClient 的实时推送接入 Working Context。
 *
 * 职责：
 *   1. 管理 0600 凭据文件（<dataDir>/feishu-web.json）与长连接生命周期，支持热感知 web-logout / 重新 web-login；
 *   2. 严格遵守 context.sources.im、context.groups（spoken / allowlist）、groups_deny、ctx_mute_conv 与 bot_allow 边界；
 *   3. 收到推送后先持久化到 ctx_obs 再返回（保留背压 ACK：落库失败或排除检查失败绝不 ACK）；
 *   4. 对「真实 @本人」与「对方私聊」按会话防抖后触发单会话快通道（不等 10 分钟定时周期）；
 *   5. 快通道理解前按需通过 readContext 补读背景（同样过 bot_allow 过滤，标为 background_only）；
 *   6. 仅在用户显式确认草稿后，才按需经个人 Web 协议执行带持久化 CID 状态机与独立回读校验的回复。
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

interface DeliveryRecord {
  cid: string;
  chat_id: string;
  message_id: string;
  root_id: string;
  parent_id: string;
  text_hash: string;
  threaded: boolean;
  state: "sending" | "created" | "verified";
  reply_id?: string;
  updated_at: number;
}

export interface PersonalWebBridgeHooks {
  onFastTrigger: (t: FastTrigger) => void;
  onReconnect: () => void;
  onNeedsLogin: (reason: string) => void;
  clientOptions?: FeishuWebClientOptions;
  /** 检查磁盘凭据变更（登出 / 重新登录）的间隔，默认 5000ms */
  credentialWatchIntervalMs?: number;
}

const STATE_KV_KEY = "ctx.personal_web.state";
export const BOUND_OWNER_KV_KEY = "ctx.personal_web.bound_owner_id";
const ACTIVE_STATES = new Set<ListenerState>(["listening", "connecting", "reconnecting", "reverifying", "publication_blocked"]);
const DAY_MS = 86_400_000;

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

  /** 判断常驻监听当前是否真实在线（本进程在跑，或 daemon.heartbeat 在 60 秒内活跃） */
  private isDaemonLive(now = Date.now()): boolean {
    if (this.stopCtrl && !this.stopCtrl.signal.aborted) return true;
    const hb = this.app.store.get("daemon.heartbeat");
    if (!hb) return false;
    const ms = Number(hb.slice(hb.lastIndexOf("|") + 1));
    return Number.isFinite(ms) && now - ms < 60_000;
  }

  status(now = Date.now()): CtxPersonalWebStatus {
    const login = this.loginStore.load();
    const saved = this.loadSavedState() ?? this.state;
    const enabled = this.cfg.context.personal_web.enabled;
    const loggedIn = !!login;
    let state: string = saved.state;
    if (!enabled) {
      state = "idle";
    } else if (!loggedIn) {
      state = "needs_login";
    } else if (ACTIVE_STATES.has(saved.state) && !this.isDaemonLive(now)) {
      state = "stopped";
    }
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

  private validateBoundOwner(login: WebLogin): void {
    const bound = this.app.store.get(BOUND_OWNER_KV_KEY);
    if (bound && bound !== login.owner_id) {
      throw new SessionNeedsLoginError(
        `个人 Web 凭据账号 (${login.owner_id}) 与当前工作区已绑定的账号 (${bound}) 不一致，请重新运行 pa context web-login`,
      );
    }
  }

  private sessionKeyOf(login: WebLogin | undefined): string {
    if (!login) return "";
    return `${login.owner_id}:${login.session_id ?? ""}`;
  }

  /** 阻塞等待直到磁盘凭据发生有效变化（新登录 / 换新 session_id）或收到中止信号 */
  private async waitForCredentialChange(lastFailedKey: string, signal: AbortSignal): Promise<void> {
    const interval = this.hooks.credentialWatchIntervalMs ?? 5_000;
    while (!signal.aborted) {
      await waitAbortable(interval, signal);
      if (signal.aborted) return;
      const cur = this.loginStore.load();
      const key = this.sessionKeyOf(cur);
      if (cur && key !== lastFailedKey) return;
    }
  }

  private async runSupervisor(signal: AbortSignal): Promise<void> {
    let connectDelayMs = 2_000;
    let connectDenials = 0;
    let wasDegraded = false;
    let everConnected = false;
    const watchInterval = this.hooks.credentialWatchIntervalMs ?? 5_000;

    const handleState = (next: ListenerState, detail = "", notifyLogin = true) => {
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
        owner_id: this.client?.owner().id ?? this.loginStore.load()?.owner_id ?? "",
        owner_name: this.client?.owner().name ?? this.loginStore.load()?.owner_name ?? "",
        since: Date.now(),
        last_error: next === "listening" || next === "stopped" ? "" : detail,
      });
      if (next === "needs_login" && notifyLogin) {
        this.hooks.onNeedsLogin(detail || "个人 Web 会话已失效，请重新扫码登录");
      }
    };

    while (!signal.aborted) {
      const login = this.loginStore.load();
      if (!login) {
        const msg = "尚未完成个人 Web 扫码登录，请运行 `pa context web-login`";
        handleState("needs_login", msg, false);
        log("warn", "个人 Web 通道等待登录凭据", { file: this.loginStore.file });
        await this.waitForCredentialChange("", signal);
        continue;
      }

      const activeKey = this.sessionKeyOf(login);
      try {
        this.validateBoundOwner(login);
      } catch (err) {
        const msg = errMsg(err);
        handleState("needs_login", msg, true);
        await this.waitForCredentialChange(activeKey, signal);
        continue;
      }

      // 为本次会话建立独立 AbortController：当磁盘凭据被 web-logout 删除或被新 web-login 替换时立刻断开旧连接
      const sessionCtrl = new AbortController();
      const onOuterAbort = () => sessionCtrl.abort();
      signal.addEventListener("abort", onOuterAbort, { once: true });
      let invalidatedByDisk = false;
      const credWatcher = setInterval(() => {
        const latest = this.loginStore.load();
        if (!latest || this.sessionKeyOf(latest) !== activeKey) {
          invalidatedByDisk = true;
          sessionCtrl.abort();
        }
      }, watchInterval);
      credWatcher.unref?.();

      try {
        handleState("connecting");
        const client = await FeishuWebClient.connect(
          login,
          {
            ...this.hooks.clientOptions,
            onSessionConfirmed: (updated) => {
              const saved = this.loginStore.saveIfSessionMatches(updated);
              if (!saved) {
                invalidatedByDisk = true;
                sessionCtrl.abort();
                return false;
              }
              if (updated.owner_name && !this.app.store.get("ctx.owner_name")) {
                this.app.store.set("ctx.owner_name", updated.owner_name);
              }
              return true;
            },
          },
          sessionCtrl.signal,
        );
        if (invalidatedByDisk || sessionCtrl.signal.aborted) continue;

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
          onMessage: (msg) => this.handleMessage(msg, client),
          onState: (s, d) => handleState(s, d, true),
          onWarn: (m) => log("warn", m),
        });
      } catch (err) {
        if (signal.aborted) break;
        this.client = undefined;
        if (invalidatedByDisk) {
          log("info", "检测到个人 Web 凭据已登出或更新，正在重新同步会话状态");
          continue;
        }
        const msg = errMsg(err);
        if (err instanceof SessionNeedsLoginError) {
          // listener 内部已完成 3 次核验并进入 needs_login：停止用失效凭据重试，静候新的 web-login
          handleState("needs_login", msg, false);
          await this.waitForCredentialChange(activeKey, signal);
          connectDenials = 0;
          connectDelayMs = 2_000;
          continue;
        }
        if (err instanceof WebHttpError && err.code === "credential_denied") {
          connectDenials++;
          if (connectDenials >= 3) {
            handleState("needs_login", msg, true);
            await this.waitForCredentialChange(activeKey, signal);
            connectDenials = 0;
            connectDelayMs = 2_000;
            continue;
          }
          handleState("reverifying", msg);
          await waitAbortable(30_000, sessionCtrl.signal);
        } else {
          handleState("reconnecting", msg);
          await waitAbortable(connectDelayMs, sessionCtrl.signal);
          connectDelayMs = Math.min(connectDelayMs * 2, 30_000);
        }
      } finally {
        clearInterval(credWatcher);
        signal.removeEventListener("abort", onOuterAbort);
        this.client = undefined;
      }
    }
    this.persistState({ state: "stopped", since: Date.now(), last_error: "" });
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

  private hasExclusionRules(): boolean {
    return this.cfg.context.groups_deny.some((d) => !!d.trim()) || this.store.mutedConvs().length > 0;
  }

  private isDeniedChat(ids: string[], names: string[]): boolean {
    const cleanIds = ids.filter(Boolean);
    const cleanNames = names.filter(Boolean);
    for (const d of this.cfg.context.groups_deny) {
      if (!d) continue;
      if (cleanIds.some((id) => id === d)) return true;
      if (cleanNames.some((name) => name.includes(d))) return true;
    }
    for (const id of cleanIds) {
      if (this.store.isConvMuted(id, cleanNames[0] ?? "")) return true;
    }
    for (const name of cleanNames) {
      if (this.store.isConvMuted(cleanIds[0] ?? "", name)) return true;
    }
    return false;
  }

  private loadSpokenGroups(): Record<string, { name: string; at: number }> {
    try {
      return JSON.parse(this.app.store.get("ctx.spoken_groups") ?? "{}") as Record<string, { name: string; at: number }>;
    } catch {
      return {};
    }
  }

  private recordSpokenGroup(pwConv: string, openConv: string | undefined, chatName: string, at: number): void {
    const spoken = this.loadSpokenGroups();
    const key = openConv || pwConv;
    const cur = spoken[key];
    if (!cur || at > cur.at) spoken[key] = { name: chatName || cur?.name || "", at };
    const cutoff = Date.now() - this.cfg.context.lookback_days * DAY_MS;
    for (const [k, v] of Object.entries(spoken)) {
      if (v.at < cutoff) delete spoken[k];
    }
    this.app.store.set("ctx.spoken_groups", JSON.stringify(spoken));
  }

  private isGroupInScope(chatId: string, pwConv: string, openConvs: string[], chatName: string): boolean {
    const allIds = new Set([chatId, pwConv, ...openConvs].filter(Boolean));
    const normName = chatName ? norm(chatName) : "";
    if (this.cfg.context.groups === "allowlist") {
      return this.cfg.context.groups_allow.some(
        (allow) => allow && (allIds.has(allow) || (chatName && chatName.includes(allow))),
      );
    }
    // spoken 模式：在回看窗口内我发过言的群
    const spoken = this.loadSpokenGroups();
    const cutoff = Date.now() - this.cfg.context.lookback_days * DAY_MS;
    for (const [k, v] of Object.entries(spoken)) {
      if (v.at < cutoff) continue;
      if (allIds.has(k)) return true;
      if (normName && v.name && norm(v.name) === normName) return true;
    }
    return false;
  }

  /**
   * 将单条个人 Web 推送消息按采集范围与排除规则校验后落库，并在命中「真实 @本人 / 对方私聊」时触发防抖快通道。
   * 同步返回前已完成 SQLite 写入；如排除检查依赖 readChat 且失败，或落库抛错，上层绝不发送 ACK。
   */
  async handleMessage(msg: WebMessage, client?: FeishuWebClient): Promise<void> {
    if (!this.cfg.context.sources.im) return;
    if (!msg.id || !msg.conversationId || msg.unsupported) return;
    const text = msg.text.trim();
    if (!text) return;

    const activeClient = client ?? this.client;
    const ownerId = msg.ownerId || activeClient?.owner().id || this.loginStore.load()?.owner_id || "";
    const isMe = !!ownerId && msg.actorId === ownerId;
    const isHuman = msg.senderType === USER_SENDER_TYPE;

    // 机器人消息沿用与 lark-cli 相同的 bot_allow 过滤规则
    if (!isHuman && !this.botAllowed(text)) return;

    const pwConv = `pw_chat:${msg.conversationId}`;
    const alias = this.store.convAlias(pwConv);
    let chatName = alias?.conv_name || "";
    if (msg.conversationKind === "group" && activeClient) {
      try {
        const fetched = (await activeClient.readChat(msg.conversationId)).name;
        if (fetched) chatName = fetched;
      } catch (err) {
        // 若配置了排除/静音规则且当前未知群名，绝不 fail-open 放行，交由背压暂缓 ACK
        if (!chatName && this.hasExclusionRules()) {
          throw new Error(`查询群名称失败，为避免漏判排除规则暂缓入库：${errMsg(err)}`);
        }
      }
    }

    const spokenByName = chatName
      ? Object.entries(this.loadSpokenGroups())
          .filter(([k, v]) => !k.startsWith("pw_chat:") && v.name && norm(v.name) === norm(chatName))
          .map(([k]) => k)
      : [];
    const openConvs = alias?.open_conv
      ? [alias.open_conv]
      : chatName
        ? [...new Set([...this.store.findOpenConvsByName(chatName), ...spokenByName])]
        : [];
    // 若仅有一个精确同名的开放平台会话且尚未建别名，先建立别名（共享历史与排除规则）
    if (!alias && openConvs.length === 1 && chatName) {
      this.store.linkConvAlias(pwConv, openConvs[0], chatName);
    }

    const convName =
      msg.conversationKind === "dm"
        ? alias?.conv_name || `私聊：${isMe ? msg.conversationId : msg.actorId || msg.conversationId}`
        : chatName || `群聊(${msg.conversationId})`;

    // 跨双 ID（数字 ID、pw_chat:*、oc_*）和名称检查禁用/静音规则
    const denyIds = [msg.conversationId, pwConv, ...openConvs, ...(msg.conversationKind === "dm" ? [msg.actorId] : [])];
    const denyNames = [chatName, alias?.conv_name ?? "", convName];
    if (this.isDeniedChat(denyIds, denyNames)) return;

    const isAtMe = !isMe && isHuman && !!ownerId && msg.mentions.some((m) => m.id === ownerId);

    // 遵守 context.groups（spoken / allowlist）采集范围：私聊、@我、我发的消息始终采集，其余群消息必须命中范围
    if (msg.conversationKind === "group") {
      if (isMe) {
        this.recordSpokenGroup(pwConv, alias?.open_conv ?? (openConvs.length === 1 ? openConvs[0] : undefined), chatName, msg.createdAtMs || Date.now());
      } else if (!isAtMe && !this.isGroupInScope(msg.conversationId, pwConv, openConvs, chatName)) {
        return;
      }
    }

    const obs: Obs = {
      id: `pw:${msg.id}`,
      source: "im",
      kind: !isHuman ? "bot" : isMe ? "mine" : msg.conversationKind === "dm" ? "p2p" : isAtMe ? "at_me" : "group",
      conv: pwConv,
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
      conv: pwConv,
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

  private fireFastTrigger(trigger: FastTrigger): void {
    try {
      this.hooks.onFastTrigger(trigger);
    } catch (err) {
      log("warn", "快通道入队失败，待处理观测仍保留供下轮周期处理", {
        conv: trigger.conv,
        obs: trigger.trigger_obs_id,
        err: errMsg(err),
      });
    }
  }

  private scheduleFastLane(trigger: FastTrigger): void {
    const key = this.store.canonicalConv(trigger.conv);
    const prev = this.debounceTimers.get(key);
    if (prev) clearTimeout(prev);
    const delay = this.cfg.context.personal_web.debounce_ms;
    if (delay <= 0) {
      this.fireFastTrigger(trigger);
      return;
    }
    const timer = setTimeout(() => {
      this.debounceTimers.delete(key);
      this.fireFastTrigger(trigger);
    }, delay);
    timer.unref?.();
    this.debounceTimers.set(key, timer);
  }

  /** 快通道理解前补读该会话的历史背景消息（同样受 bot_allow 过滤，标为 background_only）。 */
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
        .filter((m) => m.id && m.text.trim() && (m.senderType === USER_SENDER_TYPE || this.botAllowed(m.text)))
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

  private loadDelivery(cid: string): DeliveryRecord | undefined {
    const raw = this.app.store.get(`pw.delivery.${cid}`);
    if (!raw) return undefined;
    try {
      return JSON.parse(raw) as DeliveryRecord;
    } catch {
      return undefined;
    }
  }

  private saveDelivery(rec: DeliveryRecord): void {
    this.app.store.set(`pw.delivery.${rec.cid}`, JSON.stringify(rec));
  }

  /**
   * 确认草稿后的个人 Web 回复：
   *   - 发送前核验磁盘凭据仍然有效且属于已绑定账号（防止 web-logout 后仍复用缓存客户端）；
   *   - 按固定 CID 持久化发送状态机（sending → created → verified）：
   *     * 已 verified：幂等成功不重发；
   *     * 已 created（有 reply_id）：仅补跑独立回读核验，绝不重发；
   *     * 停留在 sending（上次发包结果不明）：拒绝盲目重发，避免群里出现两条重复消息。
   */
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
    const diskLogin = this.loginStore.load();
    if (!diskLogin) throw new Error("个人 Web 未登录或已登出，请先运行 `pa context web-login`");
    this.validateBoundOwner(diskLogin);

    let client = this.client;
    if (client && (client.owner().id !== diskLogin.owner_id || (diskLogin.session_id && client.currentSessionId() !== diskLogin.session_id))) {
      client = undefined;
    }
    if (!client) {
      client = await FeishuWebClient.connect(diskLogin, {
        ...this.hooks.clientOptions,
        onSessionConfirmed: (updated) => this.loginStore.saveIfSessionMatches(updated),
      });
    }

    const normalizedText = args.text.replace(/\r\n/g, "\n").trim();
    const textHash = createHash("sha256").update(normalizedText).digest("hex");
    const prev = this.loadDelivery(args.cid);
    if (prev) {
      if (prev.chat_id !== args.chat_id || prev.message_id !== args.message_id || prev.text_hash !== textHash) {
        throw new Error("个人 Web 回复幂等键（CID）与草稿内容冲突，拒绝发送");
      }
      if (prev.state === "verified" && prev.reply_id) {
        return { replyId: prev.reply_id, rootId: prev.root_id, parentId: prev.parent_id, threadId: "", verified: true };
      }
      if (prev.state === "created" && prev.reply_id) {
        const verified = await client.verifyReplyReadback({
          replyId: prev.reply_id,
          chatId: prev.chat_id,
          rootId: prev.root_id,
          parentId: prev.parent_id,
          cid: prev.cid,
          text: normalizedText,
          threaded: prev.threaded,
        });
        this.saveDelivery({ ...prev, state: "verified", updated_at: Date.now() });
        return verified;
      }
      if (prev.state === "sending") {
        throw new Error("上次个人 Web 发送结果不明确（对方可能已收到），为避免重复发送已中止重试；请先在飞书核实后再决定是否修改重发");
      }
    }

    const res = await client.sendVerifiedReply(
      {
        chatId: args.chat_id,
        messageId: args.message_id,
        rootId: args.root_id,
        text: normalizedText,
        cid: args.cid,
      },
      {
        onBeforeSend: ({ rootId, parentId, threaded }) => {
          this.saveDelivery({
            cid: args.cid,
            chat_id: args.chat_id,
            message_id: args.message_id,
            root_id: rootId,
            parent_id: parentId,
            text_hash: textHash,
            threaded,
            state: "sending",
            updated_at: Date.now(),
          });
        },
        onCreated: ({ replyId, rootId, parentId, threaded }) => {
          this.saveDelivery({
            cid: args.cid,
            chat_id: args.chat_id,
            message_id: args.message_id,
            root_id: rootId,
            parent_id: parentId,
            text_hash: textHash,
            threaded,
            state: "created",
            reply_id: replyId,
            updated_at: Date.now(),
          });
        },
      },
    );

    const latest = this.loadDelivery(args.cid);
    if (latest) this.saveDelivery({ ...latest, state: "verified", reply_id: res.replyId, updated_at: Date.now() });
    return res;
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

/**
 * 扫码登录落盘前校验工作区账号绑定：
 *   1. 若本工作区已绑定过其他原生飞书账号 ID，拒绝覆盖（防止不同账号的私聊与回复混进同一图谱），除非显式传 forceSwitch。
 *   2. 对比 lark-cli 当前登录用户姓名（或已记录的 ctx.owner_name），不一致时拒绝保存，除非显式传 allowNameMismatch。
 */
export async function verifyWorkspaceOwnerBinding(
  app: App,
  login: WebLogin,
  opts: { forceSwitch?: boolean; allowNameMismatch?: boolean } = {},
): Promise<void> {
  const loginStore = new WebLoginStore(app.cfg.dataDir);
  const boundId = app.store.get(BOUND_OWNER_KV_KEY) || loginStore.load()?.owner_id || "";
  if (boundId && boundId !== login.owner_id && !opts.forceSwitch) {
    throw new Error(
      `本工作区已绑定个人 Web 账号 ${boundId}，但本次扫码账号为 ${login.owner_id}（${login.owner_name || "无昵称"}）。` +
        "为防止混入他人私聊并以错误身份回复，已拒绝保存；若确需更换账号，请先清理数据目录或追加 --force-switch-account。",
    );
  }
  let expectedName = app.store.get("ctx.owner_name") ?? "";
  if (!expectedName) {
    try {
      const st = await app.lark.authStatus();
      const ids = (st.identities ?? {}) as Record<string, { userName?: string; user_name?: string } | undefined>;
      expectedName = String(ids.user?.userName ?? ids.user?.user_name ?? "");
    } catch {
      // lark-cli 暂不可用时仅依赖已绑定的 owner_id 校验
    }
  }
  if (expectedName && login.owner_name && norm(expectedName) !== norm(login.owner_name) && !opts.allowNameMismatch) {
    throw new Error(
      `本次扫码账号「${login.owner_name}」（ID: ${login.owner_id}）与当前工作区主人「${expectedName}」(${app.cfg.owner.open_id || "未初始化"}) 不一致，已拒绝保存。` +
        "请确认手机飞书登录的是本人账号；如确为同一账号昵称差异，可追加 --allow-name-mismatch 重试。",
    );
  }
}
