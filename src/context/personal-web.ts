import { createHash } from "node:crypto";
import type { App } from "../app.ts";
import type { CtxPersonalWebStatus } from "../api/types.ts";
import { extractOwnerOpenId } from "../lark.ts";
import { deepFind, errMsg, log } from "../util.ts";
import type { NativePollingExclusions } from "./connectors.ts";
import {
  CHAT_KIND_P2P,
  FeishuWebClient,
  GatewayError,
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
import { norm, obsRevision, type ContextStore, type Obs } from "./store.ts";

/**
 * 个人 Web 协议桥接层：把 FeishuWebClient 的实时推送接入 Working Context。
 *
 * 职责：
 *   1. 管理 0600 凭据文件（<dataDir>/feishu-web.json）与长连接生命周期，支持跨进程版本合并 Cookie、热感知登出/重登/绑定变更；
 *   2. 严格遵守 context.sources.im、context.groups（按传输分区 + max_groups）、groups_deny、ctx_mute_conv；
 *      - 仅处理个人用户消息（senderType === USER_SENDER_TYPE）；机器人消息统一由 lark-cli 轮询通道按真实 sender.name 走 bot_allow；
 *      - 开放平台 oc_* 排除/静音规则独立经 lark-cli `im chats get` 实时解析，解析失败时对未命中项按 fail-closed 暂缓入库；
 *      - 原生 pw_chat:* 排除/静音规则同样同步给 lark-cli 兜底轮询与理解门控，防止换通道漏入模型；
 *      - 先按纯本地规则筛掉范围外群，再按需调用 readChat，避免无关群消息拖慢串行推送与私聊 ACK；
 *   3. 收到推送后先持久化到 ctx_obs 再返回（保留背压 ACK：落库失败或排除检查无法确认时绝不 ACK）；
 *   4. 对「真实 @本人」与「对方私聊」按会话防抖后触发单会话快通道（不等 10 分钟定时周期）；
 *   5. 快通道理解前仅对处于采集范围且账号一致的会话补读背景，对回复/话题触发显式补齐缺失的 root/parent 锚点；
 *   6. 仅在用户显式确认草稿后，才按需经个人 Web 协议执行绑定原确认账号、带发包前二次核验与独立回读校验的回复。
 */

export type FastAnchor = Pick<
  WebMessage,
  "id" | "conversationId" | "rootId" | "parentId" | "threadId" | "position" | "createdAtMs"
>;

export interface FastTrigger {
  conv: string;
  conv_name: string;
  trigger_obs_id: string;
  text_hash: string;
  anchor: FastAnchor;
}

interface PersistedState {
  state: ListenerState;
  owner_id: string;
  owner_name: string;
  session_id?: string;
  since: number;
  last_message_at: number | null;
  last_error: string;
}

interface DeliveryRecord {
  cid: string;
  owner_id: string;
  chat_id: string;
  message_id: string;
  root_id: string;
  parent_id: string;
  text_hash: string;
  threaded: boolean;
  state: "sending" | "rejected" | "created" | "verified";
  reply_id?: string;
  updated_at: number;
}

interface OpenChatExclusionMeta {
  name: string;
  chatType: "group" | "p2p" | "unknown";
  expiresAt: number;
}

export interface PersonalWebBridgeHooks {
  onFastTrigger: (t: FastTrigger) => void;
  onReconnect: () => void;
  onNeedsLogin: (reason: string) => void;
  clientOptions?: FeishuWebClientOptions;
  /** 检查磁盘凭据变更（登出 / 重新登录 / Cookie 版本更新 / 绑定变更）的间隔，默认 5000ms */
  credentialWatchIntervalMs?: number;
}

const STATE_KV_KEY = "ctx.personal_web.state";
export const BOUND_OWNER_KV_KEY = "ctx.personal_web.bound_owner_id";
export function pwSpokenGroupsKey(ownerId: string): string {
  return `ctx.pw_spoken_groups.${ownerId}`;
}
const ACTIVE_STATES = new Set<ListenerState>(["listening", "connecting", "reconnecting", "reverifying", "publication_blocked"]);
const DAY_MS = 86_400_000;
const OC_EXCLUSION_TTL_MS = 10 * 60_000;

export class PersonalWebBridge {
  private readonly app: App;
  private readonly store: ContextStore;
  private readonly hooks: PersonalWebBridgeHooks;
  readonly loginStore: WebLoginStore;
  private client: FeishuWebClient | undefined;
  private stopCtrl: AbortController | undefined;
  private readonly debounceTimers = new Map<string, NodeJS.Timeout>();
  private readonly ocExclusionCache = new Map<string, OpenChatExclusionMeta>();
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
      session_id: login?.session_id ?? "",
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
    const staleSavedSession =
      loggedIn &&
      saved.state === "needs_login" &&
      ((!!login.session_id && saved.session_id !== login.session_id) ||
        (!!saved.owner_id && saved.owner_id !== login.owner_id));

    let state: string = staleSavedSession ? "stopped" : saved.state;
    let lastError = staleSavedSession ? "" : saved.last_error;
    if (!enabled) {
      state = "idle";
      lastError = "";
    } else if (!loggedIn) {
      state = "needs_login";
    } else if (ACTIVE_STATES.has(state as ListenerState) && !this.isDaemonLive(now)) {
      state = "stopped";
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

  private validateBoundOwner(login: WebLogin): void {
    const bound = this.app.store.get(BOUND_OWNER_KV_KEY);
    if (bound && bound !== login.owner_id) {
      throw new SessionNeedsLoginError(
        `个人 Web 凭据账号 (${login.owner_id}) 与当前工作区已绑定的账号 (${bound}) 不一致，请重新运行 pa context web-login`,
      );
    }
  }

  /** 同时包含磁盘凭据代际与工作区绑定键，确保 `--force-switch-account` 完成绑定写入后立即唤醒休眠中的监听 */
  private watchedStateKey(login: WebLogin | undefined): string {
    const bound = this.app.store.get(BOUND_OWNER_KV_KEY) ?? "";
    if (!login) return `none|${bound}`;
    return `${login.owner_id}:${login.session_id ?? ""}|${bound}`;
  }

  private sessionKeyOf(login: WebLogin | undefined): string {
    if (!login) return "";
    return `${login.owner_id}:${login.session_id ?? ""}`;
  }

  /** 阻塞等待直到磁盘凭据或工作区账号绑定发生变化，或收到中止信号 */
  private async waitForCredentialChange(lastFailedStateKey: string, signal: AbortSignal): Promise<void> {
    const interval = this.hooks.credentialWatchIntervalMs ?? 5_000;
    while (!signal.aborted) {
      await waitAbortable(interval, signal);
      if (signal.aborted) return;
      const cur = this.loginStore.load();
      if (cur && this.watchedStateKey(cur) !== lastFailedStateKey) return;
    }
  }

  private async runSupervisor(signal: AbortSignal): Promise<void> {
    let connectDelayMs = 2_000;
    let connectDenials = 0;
    let lastAttemptedKey = "";
    let wasDegraded = false;
    let everConnected = false;
    const watchInterval = this.hooks.credentialWatchIntervalMs ?? 5_000;

    const handleState = (next: ListenerState, detail = "", notifyLogin = true, sessionIdOverride?: string) => {
      if (next === "reconnecting" || next === "reverifying") wasDegraded = true;
      if (next === "listening") {
        if (wasDegraded && everConnected) {
          wasDegraded = false;
          this.hooks.onReconnect();
        }
        everConnected = true;
      }
      const disk = this.loginStore.load();
      this.persistState({
        state: next,
        owner_id: this.client?.owner().id ?? disk?.owner_id ?? "",
        owner_name: this.client?.owner().name ?? disk?.owner_name ?? "",
        session_id: sessionIdOverride ?? this.client?.currentSessionId() ?? disk?.session_id ?? "",
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
        lastAttemptedKey = "";
        connectDenials = 0;
        connectDelayMs = 2_000;
        const msg = "尚未完成个人 Web 扫码登录，请运行 `pa context web-login`";
        handleState("needs_login", msg, false, "");
        log("warn", "个人 Web 通道等待登录凭据", { file: this.loginStore.file });
        await this.waitForCredentialChange(this.watchedStateKey(undefined), signal);
        continue;
      }

      const activeSessionKey = this.sessionKeyOf(login);
      const activeWatchedKey = this.watchedStateKey(login);
      if (activeWatchedKey !== lastAttemptedKey) {
        connectDenials = 0;
        connectDelayMs = 2_000;
        lastAttemptedKey = activeWatchedKey;
      }
      try {
        this.validateBoundOwner(login);
      } catch (err) {
        const msg = errMsg(err);
        handleState("needs_login", msg, true, login.session_id ?? "");
        await this.waitForCredentialChange(activeWatchedKey, signal);
        continue;
      }

      // 为本次会话建立独立 AbortController：当磁盘凭据被 web-logout 删除或被新 web-login 替换时立刻断开旧连接；
      // 同会话内若其他进程轮换了更新版本 Cookie，则同步到当前内存 CookieJar
      const sessionCtrl = new AbortController();
      const onOuterAbort = () => sessionCtrl.abort();
      signal.addEventListener("abort", onOuterAbort, { once: true });
      let invalidatedByDisk = false;
      const credWatcher = setInterval(() => {
        const latest = this.loginStore.load();
        if (!latest || this.sessionKeyOf(latest) !== activeSessionKey) {
          invalidatedByDisk = true;
          sessionCtrl.abort();
          return;
        }
        const bound = this.app.store.get(BOUND_OWNER_KV_KEY);
        if (bound && bound !== latest.owner_id) {
          invalidatedByDisk = true;
          sessionCtrl.abort();
          return;
        }
        if (this.client && (latest.cookie_version ?? 1) > this.client.currentCookieVersion()) {
          this.client.syncFromDisk(latest);
        }
      }, watchInterval);
      credWatcher.unref?.();

      try {
        handleState("connecting", "", true, login.session_id ?? "");
        const client = await FeishuWebClient.connect(
          login,
          {
            ...this.hooks.clientOptions,
            onSessionConfirmed: (updated, delta) => {
              const saved = this.loginStore.saveIfSessionMatches(updated, delta);
              if (!saved) {
                invalidatedByDisk = true;
                sessionCtrl.abort();
                return null;
              }
              if (saved.owner_name && !this.app.store.get("ctx.owner_name")) {
                this.app.store.set("ctx.owner_name", saved.owner_name);
              }
              return saved;
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
          connectDenials = 0;
          connectDelayMs = 2_000;
          log("info", "检测到个人 Web 凭据已登出或更新，正在重新同步会话状态");
          continue;
        }
        const msg = errMsg(err);
        if (err instanceof SessionNeedsLoginError) {
          // listener 内部已完成 3 次连续核验并进入 needs_login：停止用失效凭据重试，静候新的 web-login
          handleState("needs_login", msg, false, login.session_id ?? "");
          await this.waitForCredentialChange(activeWatchedKey, signal);
          connectDenials = 0;
          connectDelayMs = 2_000;
          continue;
        }
        if (err instanceof WebHttpError && err.code === "credential_denied") {
          connectDenials++;
          if (connectDenials >= 3) {
            handleState("needs_login", msg, true, login.session_id ?? "");
            await this.waitForCredentialChange(activeWatchedKey, signal);
            connectDenials = 0;
            connectDelayMs = 2_000;
            continue;
          }
          handleState("reverifying", msg, true, login.session_id ?? "");
          await waitAbortable(30_000, sessionCtrl.signal);
        } else {
          // 非鉴权失败（5xx / 网络波动 / 超时）打断连续鉴权失败计数
          connectDenials = 0;
          handleState("reconnecting", msg, true, login.session_id ?? "");
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

  // ───────── 排除规则（双向一致、实时解析、绝不 fail-open、绝不做跨通道历史绑定） ─────────

  /**
   * 仅从实时 `im chats get` 解析开放平台 `oc_*` 会话元数据（带 TTL 缓存）。
   * 绝不把静音时保存的旧群名当作当前真实群名，防止群改名后 fail-open 漏入模型。
   */
  private async resolveOpenChatMeta(ocId: string): Promise<OpenChatExclusionMeta | undefined> {
    const now = Date.now();
    const cached = this.ocExclusionCache.get(ocId);
    if (cached && cached.expiresAt > now) return cached;
    try {
      const res = (await this.app.lark.run(
        ["im", "chats", "get", "--params", JSON.stringify({ chat_id: ocId })],
        { as: "user", timeoutMs: 15_000 },
      )) as Record<string, unknown>;
      const rawName = String(deepFind(res, "name") ?? "").trim();
      const rawMode = String(deepFind(res, "chat_mode") ?? deepFind(res, "chat_type") ?? "").toLowerCase();
      const chatType: OpenChatExclusionMeta["chatType"] =
        rawMode === "p2p"
          ? "p2p"
          : rawMode === "group" || rawMode === "topic" || rawMode === "topic_group"
            ? "group"
            : rawName
              ? "group"
              : "unknown";
      const meta: OpenChatExclusionMeta = {
        name: rawName,
        chatType,
        expiresAt: now + OC_EXCLUSION_TTL_MS,
      };
      this.ocExclusionCache.set(ocId, meta);
      return meta;
    } catch {
      return undefined;
    }
  }

  private collectOpenChatExclusions(): Map<string, string> {
    const map = new Map<string, string>();
    for (const raw of this.cfg.context.groups_deny) {
      const d = raw.trim();
      if (d.startsWith("oc_")) map.set(d, "");
    }
    for (const m of this.store.mutedConvs()) {
      if (m.conv.startsWith("oc_")) map.set(m.conv, m.name || map.get(m.conv) || "");
    }
    return map;
  }

  private collectNativeChatExclusions(): Map<string, string> {
    const map = new Map<string, string>();
    for (const raw of this.cfg.context.groups_deny) {
      const d = raw.trim();
      if (d.startsWith("pw_chat:")) map.set(d.slice("pw_chat:".length), "");
      else if (/^\d+$/.test(d)) map.set(d, "");
    }
    for (const m of this.store.mutedConvs()) {
      if (m.conv.startsWith("pw_chat:")) {
        const id = m.conv.slice("pw_chat:".length);
        map.set(id, m.name || map.get(id) || "");
      } else if (/^\d+$/.test(m.conv)) {
        map.set(m.conv, m.name || map.get(m.conv) || "");
      }
    }
    return map;
  }

  private nameDenyPatterns(): string[] {
    return this.cfg.context.groups_deny
      .map((d) => d.trim())
      .filter((d) => d && !d.startsWith("oc_") && !d.startsWith("pw_chat:") && !/^\d+$/.test(d));
  }

  private matchesDirectNativeIdDeny(chatId: string, pwConv: string, dmActorId?: string): boolean {
    for (const raw of this.cfg.context.groups_deny) {
      const d = raw.trim();
      if (!d) continue;
      if (d === chatId || d === pwConv || (dmActorId && d === dmActorId)) return true;
    }
    return false;
  }

  private isDirectlyDenied(pwConv: string, chatName: string): boolean {
    const rawId = pwConv.startsWith("pw_chat:") ? pwConv.slice("pw_chat:".length) : pwConv;
    if (this.store.isConvMutedById(pwConv) || this.store.isConvMutedById(rawId)) return true;
    if (this.matchesDirectNativeIdDeny(rawId, pwConv)) return true;
    if (chatName && this.nameDenyPatterns().some((d) => chatName.includes(d))) return true;
    return false;
  }

  /**
   * 评估当前个人 Web 会话是否命中排除/静音规则：
   *   - 返回 true：明确命中排除，应丢弃；
   *   - 返回 false：确认未命中排除，允许继续；
   *   - 抛错：存在无法实时解析或无法与当前会话区分的排除规则，按 fail-closed 暂缓入库（不发 ACK）。
   */
  private async evaluateChatExclusion(params: {
    chatId: string;
    pwConv: string;
    kind: "group" | "dm";
    chatName: string;
    convName: string;
    actorId?: string;
  }): Promise<boolean> {
    const { chatId, pwConv, kind, chatName, convName, actorId } = params;
    // 1. 精确 ID 静音 / 禁用（按实际会话 ID 生效，绝不误伤同名群）
    if (this.store.isConvMutedById(pwConv) || this.store.isConvMutedById(chatId)) return true;
    if (this.matchesDirectNativeIdDeny(chatId, pwConv, kind === "dm" ? actorId : undefined)) return true;

    // 2. groups_deny 名称规则
    const nameRules = this.nameDenyPatterns();
    if (nameRules.length > 0) {
      if (kind === "group") {
        if (!chatName) {
          throw new Error("查询群名称失败，无法评估 groups_deny 名称排除规则，按 fail-closed 暂缓入库");
        }
        if (nameRules.some((d) => chatName.includes(d))) return true;
      } else if (nameRules.some((d) => convName.includes(d))) {
        return true;
      }
    }

    // 3. 开放平台 oc_* 排除/静音规则（实时经 im chats get 解析；失败时仅旧标签命中可直接丢弃，不命中一律 fail-closed）
    const ocRules = this.collectOpenChatExclusions();
    if (ocRules.size === 0) return false;
    for (const [ocId, staleLabel] of ocRules) {
      const meta = await this.resolveOpenChatMeta(ocId);
      if (!meta) {
        if (kind === "group" && chatName && staleLabel && norm(chatName) === norm(staleLabel)) {
          return true;
        }
        throw new Error(`无法实时解析排除规则 ${ocId} 的会话元数据，按 fail-closed 暂缓入库`);
      }
      if (kind === "group") {
        if (meta.chatType === "p2p") continue;
        if (!meta.name) {
          throw new Error(`排除规则 ${ocId} 缺少群名称，无法与当前个人 Web 群聊区分，按 fail-closed 暂缓入库`);
        }
        if (!chatName) {
          throw new Error(`查询群名称失败，无法与排除规则 ${ocId} 区分，按 fail-closed 暂缓入库`);
        }
        if (norm(chatName) === norm(meta.name)) return true;
      } else {
        if (meta.chatType === "group") continue;
        throw new Error(`存在开放平台私聊排除规则 (${ocId})，个人 Web 私聊无法映射其 open chat_id，按 fail-closed 暂缓入库`);
      }
    }
    return false;
  }

  /**
   * 将原生 `pw_chat:*` / 数字 ID 的静音或禁用规则同步到 lark-cli 兜底轮询与开放平台会话理解：
   * 优先通过在线 Web 客户端实时 readChat 获取当前群名；无法实时解析时对非确定场景按 fail-closed 拦下。
   */
  async resolveNativeExclusionsForPolling(): Promise<NativePollingExclusions> {
    const rules = this.collectNativeChatExclusions();
    const excludedGroupNames = new Set<string>();
    let excludeAllGroups = false;
    let excludeAllDms = false;
    if (rules.size === 0) return { excludedGroupNames, excludeAllGroups, excludeAllDms };

    const client = this.client;
    for (const [nativeId, muteName] of rules) {
      const pwConv = `pw_chat:${nativeId}`;
      const latest = this.store.latestConvObs(pwConv);
      if (client) {
        try {
          const meta = await client.readChat(nativeId, { force: true });
          if (meta.kind === CHAT_KIND_P2P) {
            excludeAllDms = true;
          } else if (meta.name.trim()) {
            excludedGroupNames.add(norm(meta.name.trim()));
          } else {
            excludeAllGroups = true;
          }
          continue;
        } catch {
          // 实时查询失败：若有已知群名先加入保守过滤，同时按 fail-closed 拦下无法区分的群
          if (latest?.meta.chat_type === "p2p" || muteName.startsWith("私聊")) {
            excludeAllDms = true;
          } else {
            excludeAllGroups = true;
          }
          continue;
        }
      }
      // 无活跃 Web 客户端时，根据已知本地元数据判断：私聊拦 DM；有明确群名拦该群；未知则 fail-closed
      const isDm = latest?.meta.chat_type === "p2p" || muteName.startsWith("私聊");
      if (isDm) {
        excludeAllDms = true;
        continue;
      }
      const rawName = (muteName || latest?.conv_name || "").trim();
      const usableName = rawName && !/^群聊\(\d+\)$/.test(rawName) ? rawName : "";
      if (usableName) {
        excludedGroupNames.add(norm(usableName));
      } else {
        excludeAllGroups = true;
      }
    }
    return { excludedGroupNames, excludeAllGroups, excludeAllDms };
  }

  /**
   * 理解执行前二次校验（覆盖快通道与常规周期）：
   * 即使消息已入库后用户才新增静音或 groups_deny 规则，也不会再被送给模型。
   */
  async checkConvAllowedForUnderstand(conv: string, convName: string): Promise<"allowed" | "excluded" | "uncertain"> {
    if (!conv.startsWith("pw_chat:") && !conv.startsWith("oc_")) return "allowed";
    if (!this.cfg.context.sources.im) return "excluded";

    if (conv.startsWith("pw_chat:")) {
      const chatId = conv.slice("pw_chat:".length);
      if (this.store.isConvMutedById(conv) || this.store.isConvMutedById(chatId)) return "excluded";
      const latest = this.store.latestConvObs(conv);
      const isDm = latest?.meta.chat_type === "p2p" || convName.startsWith("私聊");
      let chatName = "";
      if (!isDm) {
        const client = this.client;
        if (client) {
          try {
            chatName = (await client.readChat(chatId)).name.trim();
          } catch {
            chatName = "";
          }
        } else {
          const fallback = (convName || latest?.conv_name || "").trim();
          chatName = fallback && !/^群聊\(\d+\)$/.test(fallback) ? fallback : "";
        }
      }
      try {
        const excluded = await this.evaluateChatExclusion({
          chatId,
          pwConv: conv,
          kind: isDm ? "dm" : "group",
          chatName,
          convName: convName || latest?.conv_name || "",
          actorId: latest?.actor_id,
        });
        return excluded ? "excluded" : "allowed";
      } catch {
        return "uncertain";
      }
    }

    // oc_* 开放平台会话
    if (this.store.isConvMutedById(conv)) return "excluded";
    const latest = this.store.latestConvObs(conv);
    const effectiveName = (convName || latest?.conv_name || "").trim();
    const isDm = latest?.meta.chat_type === "p2p" || effectiveName.startsWith("私聊");
    for (const raw of this.cfg.context.groups_deny) {
      const d = raw.trim();
      if (!d) continue;
      if (d === conv) return "excluded";
      if (!d.startsWith("oc_") && !d.startsWith("pw_chat:") && !/^\d+$/.test(d) && effectiveName && effectiveName.includes(d)) {
        return "excluded";
      }
    }
    const nativeExcl = await this.resolveNativeExclusionsForPolling();
    if (isDm) return nativeExcl.excludeAllDms ? "excluded" : "allowed";
    if (nativeExcl.excludeAllGroups) return "uncertain";
    if (nativeExcl.excludedGroupNames.size > 0) {
      if (!effectiveName) return "uncertain";
      if (nativeExcl.excludedGroupNames.has(norm(effectiveName))) return "excluded";
    }
    return "allowed";
  }

  // ───────── 按登录账号隔离维护个人 Web 的发言群与采集范围（不污染 ctx.spoken_groups） ─────────

  private loadPwSpokenGroups(ownerId: string): Record<string, { name: string; at: number }> {
    if (!ownerId) return {};
    try {
      return JSON.parse(this.app.store.get(pwSpokenGroupsKey(ownerId)) ?? "{}") as Record<string, { name: string; at: number }>;
    } catch {
      return {};
    }
  }

  private recordPwSpokenGroup(ownerId: string, pwConv: string, chatName: string, at: number): void {
    if (!ownerId) return;
    const spoken = this.loadPwSpokenGroups(ownerId);
    const cur = spoken[pwConv];
    if (!cur || at > cur.at) spoken[pwConv] = { name: chatName || cur?.name || "", at };
    const cutoff = Date.now() - this.cfg.context.lookback_days * DAY_MS;
    for (const [k, v] of Object.entries(spoken)) {
      if (v.at < cutoff) delete spoken[k];
    }
    this.app.store.set(pwSpokenGroupsKey(ownerId), JSON.stringify(spoken));
  }

  /**
   * 群聊是否处于普通消息采集范围（严格按原生 ID、当前账号发言史与 max_groups 判定，绝不靠群名猜测授权）：
   *   - allowlist 模式：仅取 groups_allow 中的原生 ID（pw_chat:* 或纯数字），去重并按 max_groups 截断；
   *   - spoken 模式：取当前 ownerId 在 lookback_days 内发过言的个人 Web 群，按最近发言排序后取前 max_groups 个。
   */
  private isGroupInScope(chatId: string, pwConv: string, ownerId: string): boolean {
    if (this.cfg.context.groups === "allowlist") {
      const nativeAllow = [
        ...new Set(
          this.cfg.context.groups_allow
            .map((s) => s.trim())
            .filter((s) => s.startsWith("pw_chat:") || /^\d+$/.test(s))
            .map((s) => (s.startsWith("pw_chat:") ? s : `pw_chat:${s}`))
            .filter((k) => !this.isDirectlyDenied(k, "")),
        ),
      ].slice(0, this.cfg.context.max_groups);
      return nativeAllow.includes(pwConv);
    }
    if (!ownerId) return false;
    const spoken = this.loadPwSpokenGroups(ownerId);
    const cutoff = Date.now() - this.cfg.context.lookback_days * DAY_MS;
    const ranked = Object.entries(spoken)
      .filter(([k, v]) => v.at >= cutoff && !this.isDirectlyDenied(k, v.name))
      .sort((a, b) => b[1].at - a[1].at)
      .slice(0, this.cfg.context.max_groups);
    return ranked.some(([k]) => k === pwConv || k === chatId);
  }

  // ───────── 实时消息入库与快通道调度 ─────────

  /**
   * 将单条个人 Web 推送消息按采集范围与排除规则校验后落库，并在命中「真实 @本人 / 对方私聊」时触发防抖快通道。
   * 先做纯本地原生 ID 过滤与群范围筛查，再按需调用 readChat，避免范围外群拖慢串行推送与私聊 ACK。
   * 同步返回前已完成 SQLite 写入；如排除检查无法确认（fail-closed）或落库抛错，上层绝不发送 ACK。
   */
  async handleMessage(msg: WebMessage, client?: FeishuWebClient): Promise<void> {
    if (!this.cfg.context.sources.im) return;
    if (!msg.id || !msg.conversationId || msg.unsupported) return;
    if (msg.conversationKind !== "group" && msg.conversationKind !== "dm") return;
    // 仅处理个人用户消息：个人 Web 原生协议不含机器人显示名，机器人消息统一由 lark-cli 轮询通道按真实 sender.name 走 bot_allow
    if (msg.senderType !== USER_SENDER_TYPE) return;
    const text = msg.text.trim();
    if (!text) return;

    const activeClient = client ?? this.client;
    const ownerId = msg.ownerId || activeClient?.owner().id || this.loginStore.load()?.owner_id || "";
    const isMe = !!ownerId && msg.actorId === ownerId;
    const pwConv = `pw_chat:${msg.conversationId}`;
    const isAtMe = !isMe && !!ownerId && msg.mentions.some((m) => m.id === ownerId);

    // 1) 纯本地快速过滤：原生 ID 静音/禁用直接丢弃（零网络开销）
    if (this.store.isConvMutedById(pwConv) || this.store.isConvMutedById(msg.conversationId)) return;
    if (this.matchesDirectNativeIdDeny(msg.conversationId, pwConv, msg.conversationKind === "dm" ? msg.actorId : undefined)) return;

    // 2) 范围外普通群消息在 readChat 之前立刻丢弃（私聊、@我、我发的消息仍放行进入下一步排除校验）
    if (msg.conversationKind === "group" && !isMe && !isAtMe && !this.isGroupInScope(msg.conversationId, pwConv, ownerId)) {
      return;
    }

    // 3) 仅对可能入库的消息按需获取群名，再执行完整排除校验（含名称规则与实时 oc_* 解析）
    let chatName = "";
    if (msg.conversationKind === "group" && activeClient) {
      try {
        chatName = (await activeClient.readChat(msg.conversationId)).name.trim();
      } catch {
        chatName = "";
      }
    }

    const convName =
      msg.conversationKind === "dm"
        ? `私聊：${isMe ? msg.conversationId : msg.actorId || msg.conversationId}`
        : chatName || `群聊(${msg.conversationId})`;

    const excluded = await this.evaluateChatExclusion({
      chatId: msg.conversationId,
      pwConv,
      kind: msg.conversationKind,
      chatName,
      convName,
      actorId: msg.actorId,
    });
    if (excluded) return;

    if (msg.conversationKind === "group" && isMe) {
      this.recordPwSpokenGroup(ownerId, pwConv, chatName, msg.createdAtMs || Date.now());
    }

    const clippedText = text.slice(0, 2000);
    const obs: Obs = {
      id: `pw:${msg.id}`,
      source: "im",
      kind: isMe ? "mine" : msg.conversationKind === "dm" ? "p2p" : isAtMe ? "at_me" : "group",
      conv: pwConv,
      conv_name: convName,
      actor_id: msg.actorId,
      actor_name: isMe ? this.app.store.get("ctx.owner_name") || activeClient?.owner().name || "我" : msg.actorId,
      is_me: isMe,
      time: msg.createdAtMs || Date.now(),
      text: clippedText,
      url: "",
      meta: {
        transport: "personal_web",
        native_owner_id: ownerId,
        native_message_id: msg.id,
        native_chat_id: msg.conversationId,
        native_root_id: msg.rootId || msg.id,
        native_parent_id: msg.parentId,
        thread_id: msg.threadId,
        position: msg.position,
        chat_type: msg.conversationKind === "dm" ? "p2p" : "group",
        sender_type: "user",
        at_me: isAtMe,
        mentions: msg.mentions,
      },
    };

    const inserted = this.store.addObs([obs]);
    this.persistState({ last_message_at: Date.now() });

    const pwCfg = this.cfg.context.personal_web;
    const isPending = inserted > 0 || this.store.obsPending(obs.id);
    const shouldFastLane =
      isPending &&
      pwCfg.enabled &&
      pwCfg.fast_lane &&
      this.cfg.context.understand &&
      !isMe &&
      (isAtMe || msg.conversationKind === "dm");

    if (!shouldFastLane) return;

    const revHash = createHash("sha256").update(obsRevision(obs)).digest("hex").slice(0, 12);
    const trigger: FastTrigger = {
      conv: pwConv,
      conv_name: convName,
      trigger_obs_id: obs.id,
      text_hash: revHash,
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
    if (!this.cfg.context.personal_web.enabled || !this.cfg.context.personal_web.fast_lane || !this.cfg.context.understand) {
      return;
    }
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
    const key = trigger.conv;
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

  /**
   * 快通道理解前按需补读会话背景：
   *   - 严格绑定触发观测的所属账号与当前会话代际（跨 await 后再次核验，防止换号后把旧账号历史标给新账号）；
   *   - 重新校验 sources.im、静音状态、排除规则与群聊采集范围（不给范围外群拉普通背景）；
   *   - 对于话题/回复触发，即使该会话最近已有 >= 5 条消息，只要缺失 rootId 或 parentId 锚点仍会显式补读；
   *   - 仅写入用户消息（senderType === USER_SENDER_TYPE）并标记为 background_only。
   */
  async hydrateContext(anchor: FastAnchor, conv: string, convName: string, signal?: AbortSignal): Promise<number> {
    if (!this.cfg.context.sources.im) return 0;
    const client = this.client;
    if (!client) return 0;
    if (this.store.isConvMutedById(conv)) return 0;

    const clientOwnerId = client.owner().id;
    const clientOwnerName = client.owner().name;
    const clientSessionId = client.currentSessionId() ?? "";
    const triggerObs = this.store.obs(`pw:${anchor.id}`);
    const triggerOwnerId = String(triggerObs?.meta.native_owner_id ?? "");
    if (triggerOwnerId && triggerOwnerId !== clientOwnerId) return 0;

    const sessionStillValid = (): boolean => {
      if (this.client !== client) return false;
      if (client.owner().id !== clientOwnerId) return false;
      const disk = this.loginStore.load();
      if (!disk || disk.owner_id !== clientOwnerId) return false;
      if (clientSessionId && disk.session_id && disk.session_id !== clientSessionId) return false;
      const bound = this.app.store.get(BOUND_OWNER_KV_KEY);
      if (bound && bound !== clientOwnerId) return false;
      return true;
    };
    if (!sessionStillValid()) return 0;

    const isDm = triggerObs?.meta.chat_type === "p2p";
    let chatName = "";
    if (!isDm) {
      try {
        chatName = (await client.readChat(anchor.conversationId, { signal })).name.trim();
      } catch {
        chatName = "";
      }
    }
    if (!sessionStillValid()) return 0;

    try {
      const excluded = await this.evaluateChatExclusion({
        chatId: anchor.conversationId,
        pwConv: conv,
        kind: isDm ? "dm" : "group",
        chatName,
        convName,
        actorId: triggerObs?.actor_id,
      });
      if (excluded) return 0;
    } catch (err) {
      log("warn", "快通道跳过补读背景（排除规则未确认）", { conv, err: errMsg(err) });
      return 0;
    }

    // 仅允许对处于采集范围内的会话补读背景消息（allowlist 未列入或超出 max_groups 的群不拉普通背景）
    if (!isDm && !this.isGroupInScope(anchor.conversationId, conv, clientOwnerId)) {
      return 0;
    }

    const missingAnchors = [anchor.rootId, anchor.parentId]
      .filter((id): id is string => !!id && id !== anchor.id)
      .filter((id) => !this.store.obs(`pw:${id}`));
    const existing = this.store.convObs(conv, Date.now() - 24 * 3_600_000, 6);
    if (missingAnchors.length === 0 && existing.length >= 5) return 0;

    try {
      const history = await client.readContext(anchor, { limit: 15, signal });
      if (!history.length) return 0;
      // 跨网络调用后再次确认会话与账号未被切换或登出，否则丢弃结果绝不落库
      if (!sessionStillValid()) return 0;
      const ownerName = this.app.store.get("ctx.owner_name") || clientOwnerName || "我";
      const bg: Obs[] = history
        .filter((m) => m.id && m.text.trim() && m.senderType === USER_SENDER_TYPE)
        .map((m) => {
          const isMe = m.actorId === clientOwnerId;
          return {
            id: `pw:${m.id}`,
            source: "im",
            kind: isMe ? "mine" : m.conversationKind === "dm" ? "p2p" : "group",
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
              native_owner_id: clientOwnerId,
              native_message_id: m.id,
              native_chat_id: m.conversationId,
              native_root_id: m.rootId || m.id,
              native_parent_id: m.parentId,
              thread_id: m.threadId,
              position: m.position,
              chat_type: m.conversationKind === "dm" ? "p2p" : "group",
              sender_type: "user",
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

  // ───────── 确认草稿后的个人 Web 回复 ─────────

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

  private assertSendPermitted(expectedOwnerId: string, expectedSessionId = ""): WebLogin {
    if (!this.cfg.context.personal_web.send_replies) {
      throw new Error("未开启个人 Web 回复（需在配置中设置 context.personal_web.send_replies: true）");
    }
    if (!expectedOwnerId) {
      throw new Error("个人 Web 回复缺少绑定的确认账号 ID，拒绝发送");
    }
    const diskLogin = this.loginStore.load();
    if (!diskLogin) throw new Error("个人 Web 未登录或已登出，请先运行 `pa context web-login`");
    this.validateBoundOwner(diskLogin);
    if (diskLogin.owner_id !== expectedOwnerId) {
      throw new Error(
        `该回复已绑定账号 (${expectedOwnerId})，与当前登录账号 (${diskLogin.owner_id}) 不一致，拒绝以他人身份发送`,
      );
    }
    if (expectedSessionId && (diskLogin.session_id ?? "") !== expectedSessionId) {
      throw new Error("发送前检测到个人 Web 会话已登出或重新登录，已中止本次发送");
    }
    return diskLogin;
  }

  /**
   * 确认草稿后的个人 Web 回复：
   *   - 最先检查本地持久化投递记录：已 `verified` 且 CID/账号/目标/正文一致时直接幂等返回（不依赖实时登录或网络，防止进程崩溃在回写 effect done 前误标失败）；
   *   - 绑定原确认账号 owner_id：跨账号切换后绝不以新账号替旧账号发消息；
   *   - 入口与发包前（onBeforeSend）双重核验 send_replies 开关、磁盘凭据与会话代际；
   *   - 按固定 CID 持久化发送状态机（sending → rejected | created → verified）：
   *     * 已 created（有 reply_id）：仅补跑独立回读核验，绝不重发；
   *     * 明确被服务端拒绝未建消息（rejected，仅限 HTTP 400/401/403/404 或非空明确错误码 GatewayError）：允许修复后重试；
   *     * 停留在 sending（网络中断/超时/5xx/空响应载荷等结果不明）：拒绝盲目重发，避免重复发消息。
   */
  async sendVerifiedReply(args: {
    owner_id: string;
    chat_id: string;
    message_id: string;
    root_id?: string;
    text: string;
    cid: string;
  }): Promise<VerifiedReplyResult> {
    const normalizedText = args.text.replace(/\r\n/g, "\n").trim();
    const textHash = createHash("sha256").update(normalizedText).digest("hex");
    const prev = this.loadDelivery(args.cid);
    if (prev) {
      if (
        (prev.owner_id && prev.owner_id !== args.owner_id) ||
        prev.chat_id !== args.chat_id ||
        prev.message_id !== args.message_id ||
        prev.text_hash !== textHash
      ) {
        throw new Error("个人 Web 回复幂等键（CID）与草稿内容或账号冲突，拒绝发送");
      }
      // 已完成独立回读确认：直接幂等返回，无需重新登录、开启开关或发起网络请求
      if (prev.state === "verified" && prev.reply_id) {
        return { replyId: prev.reply_id, rootId: prev.root_id, parentId: prev.parent_id, threadId: "", verified: true };
      }
      if (prev.state === "sending") {
        throw new Error("上次个人 Web 发送结果不明确（对方可能已收到），为避免重复发送已中止重试；请先在飞书核实后再决定是否修改重发");
      }
    }

    const diskLogin = this.assertSendPermitted(args.owner_id);
    const initialSessionId = diskLogin.session_id ?? "";

    let client = this.client;
    if (client && (client.owner().id !== diskLogin.owner_id || (initialSessionId && client.currentSessionId() !== initialSessionId))) {
      client = undefined;
    }
    if (!client) {
      client = await FeishuWebClient.connect(diskLogin, {
        ...this.hooks.clientOptions,
        onSessionConfirmed: (updated, delta) => this.loginStore.saveIfSessionMatches(updated, delta),
      });
    }
    if (client.owner().id !== args.owner_id) {
      throw new Error(`在线核验返回的账号 (${client.owner().id}) 与草稿绑定账号 (${args.owner_id}) 不一致，拒绝发送`);
    }

    if (prev?.state === "created" && prev.reply_id) {
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

    let enteredSend = false;
    let createdOnServer = false;
    let sendMeta: { rootId: string; parentId: string; threaded: boolean } | undefined;
    let res: VerifiedReplyResult;
    try {
      res = await client.sendVerifiedReply(
        {
          chatId: args.chat_id,
          messageId: args.message_id,
          rootId: args.root_id,
          text: normalizedText,
          cid: args.cid,
        },
        {
          onBeforeSend: ({ rootId, parentId, threaded }) => {
            // 发包前最后一次复核：防止异步读原消息/读群期间登出、换号或关闭 send_replies
            this.assertSendPermitted(args.owner_id, initialSessionId);
            if (client.owner().id !== args.owner_id) {
              throw new Error("发送前检测到客户端账号不匹配，已中止发送");
            }
            sendMeta = { rootId, parentId, threaded };
            enteredSend = true;
            this.saveDelivery({
              cid: args.cid,
              owner_id: args.owner_id,
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
            createdOnServer = true;
            this.saveDelivery({
              cid: args.cid,
              owner_id: args.owner_id,
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
    } catch (err) {
      if (enteredSend && !createdOnServer && sendMeta && isDefinitiveNonCreationError(err)) {
        this.saveDelivery({
          cid: args.cid,
          owner_id: args.owner_id,
          chat_id: args.chat_id,
          message_id: args.message_id,
          root_id: sendMeta.rootId,
          parent_id: sendMeta.parentId,
          text_hash: textHash,
          threaded: sendMeta.threaded,
          state: "rejected",
          updated_at: Date.now(),
        });
      }
      throw err;
    }

    const latest = this.loadDelivery(args.cid);
    if (latest) this.saveDelivery({ ...latest, state: "verified", reply_id: res.replyId, updated_at: Date.now() });
    return res;
  }
}

/**
 * 仅把服务端明确拒绝且未创建消息的错误归类为可重试（HTTP 400/401/403/404，或非空且带明确非零状态码的 GatewayError）。
 * 空载荷成功响应（emptyPayload: true）、5xx、网络超时与断连一律停留在 sending，绝不盲目重发。
 */
function isDefinitiveNonCreationError(err: unknown): boolean {
  if (err instanceof WebHttpError && err.status !== undefined) {
    return err.status === 400 || err.status === 401 || err.status === 403 || err.status === 404;
  }
  if (err instanceof GatewayError) {
    return !err.emptyPayload && typeof err.status === "number" && err.status !== 0;
  }
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

/**
 * 扫码登录落盘前校验工作区账号绑定：
 *   1. 若本工作区已绑定过其他原生飞书账号 ID，拒绝覆盖（防止不同账号的私聊与回复混进同一图谱），除非显式传 forceSwitch。
 *   2. 若飞书个人资料返回了稳定 open_id，直接与 config.yaml 的 owner.open_id 做强核验（不一致直接拒绝，一致则免额外确认）。
 *   3. 核验 lark-cli 当前登录用户的 open_id 与 config.yaml 中的 owner.open_id 一致（不一致直接拒绝）。
 *   4. 若昵称与已知主人不一致，拒绝保存（除非显式传 allowNameMismatch）。
 *   5. 首次绑定或切换账号时，若无法通过共享稳定 ID（open_id）独立证明扫码账号即为工作区主人（仅靠同名无法区分重名同事），
 *      必须由用户显式追加 `--allow-unverified-owner` 确认后才允许落盘。
 */
export async function verifyWorkspaceOwnerBinding(
  app: App,
  login: WebLogin,
  opts: { forceSwitch?: boolean; allowNameMismatch?: boolean; allowUnverifiedOwner?: boolean } = {},
): Promise<void> {
  const loginStore = new WebLoginStore(app.cfg.dataDir);
  const boundId = app.store.get(BOUND_OWNER_KV_KEY) || loginStore.load()?.owner_id || "";
  if (boundId && boundId !== login.owner_id && !opts.forceSwitch) {
    throw new Error(
      `本工作区已绑定个人 Web 账号 ${boundId}，但本次扫码账号为 ${login.owner_id}（${login.owner_name || "无昵称"}）。` +
        "为防止混入他人私聊并以错误身份回复，已拒绝保存；若确需更换账号，请先清理数据目录或追加 --force-switch-account。",
    );
  }

  const configuredOpenId = app.cfg.owner.open_id.trim();
  // 若扫码资料返回了 open_id，与 config.yaml 的 owner.open_id 做强标识校验
  if (configuredOpenId && login.owner_open_id && login.owner_open_id !== configuredOpenId) {
    throw new Error(
      `本次扫码账号的 open_id (${login.owner_open_id}) 与 config.yaml 配置的主人 (${configuredOpenId}) 不一致，已拒绝保存。`,
    );
  }
  const openIdVerified = !!configuredOpenId && !!login.owner_open_id && login.owner_open_id === configuredOpenId;

  let cliVerified = false;
  let cliOpenId = "";
  let cliName = "";
  try {
    const st = await app.lark.authStatus();
    cliOpenId = extractOwnerOpenId(st);
    const ids = (st.identities ?? {}) as Record<string, { userName?: string; user_name?: string } | undefined>;
    cliName = String(ids.user?.userName ?? ids.user?.user_name ?? deepFind(st, "userName") ?? deepFind(st, "user_name") ?? "").trim();
    if (configuredOpenId && cliOpenId && cliOpenId !== configuredOpenId) {
      throw new Error(
        `当前 lark-cli 登录用户 (${cliOpenId}) 与 config.yaml 配置的主人 (${configuredOpenId}) 不一致，无法核验个人 Web 账号归属。` +
          "请先在 lark-cli 切回主人账号后再执行 pa context web-login。",
      );
    }
    if (cliName && (!configuredOpenId || cliOpenId === configuredOpenId)) {
      cliVerified = true;
    }
  } catch (err) {
    if (configuredOpenId && cliOpenId && cliOpenId !== configuredOpenId) {
      throw err;
    }
    // lark-cli 不可用时继续走下方独立校验门控
  }

  const storedOwnerName = (app.store.get("ctx.owner_name") ?? "").trim();
  const expectedName = cliVerified ? cliName : storedOwnerName;
  const isSameAlreadyBound = !!boundId && boundId === login.owner_id;

  if (expectedName && !opts.allowNameMismatch) {
    if (!login.owner_name || norm(expectedName) !== norm(login.owner_name)) {
      throw new Error(
        `本次扫码账号「${login.owner_name || "(无昵称)"}」（ID: ${login.owner_id}）与当前工作区主人「${expectedName}」(${configuredOpenId || "未初始化"}) 不一致，已拒绝保存。` +
          "请确认手机飞书登录的是本人账号；如确为同一账号昵称差异，可追加 --allow-name-mismatch 重试。",
      );
    }
  }

  // 首次绑定或换号时，仅凭显示名称相同不足以防止同名他人误绑：必须具备共享 open_id 强校验，或由用户显式确认 --allow-unverified-owner
  if (!isSameAlreadyBound && !openIdVerified && !opts.allowUnverifiedOwner) {
    throw new Error(
      `首次绑定个人 Web 账号「${login.owner_name || "(无昵称)"}」（原生 ID: ${login.owner_id}）时，` +
        `飞书网页资料未返回可与工作区主人 (${configuredOpenId || "未配置 owner.open_id"}) 直接比对的稳定 open_id（仅凭显示名称相同无法排除同名账号）。` +
        "请核对手机飞书确为本人账号后，追加 --allow-unverified-owner 重新执行 pa context web-login。",
    );
  }
}
