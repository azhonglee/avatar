import { createHash } from "node:crypto";
import fs from "node:fs";
import YAML from "yaml";
import type { App } from "../app.ts";
import type { CtxPersonalWebStatus } from "../api/types.ts";
import { extractOwnerOpenId } from "../lark.ts";
import type { Store } from "../store.ts";
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
import { ContextStore, norm, obsRevision, type Obs } from "./store.ts";

/**
 * 个人 Web 协议桥接层：把 FeishuWebClient 的实时推送接入 Working Context。
 *
 * 职责：
 *   1. 管理 0600 凭据文件（支持工作区外路径与 AES-256-GCM 静态加密）与长连接生命周期，支持跨进程 3-way Cookie 合并、热感知登出/重登/绑定变更；
 *   2. 严格绑定工作区主人（owner.open_id）与原生账号 ID，禁止脏数据目录原地换号，防止跨账号私聊与【我】标记泄漏；
 *   3. 严格遵守 context.sources.im、context.groups（按传输分区 + max_groups）、groups_deny、ctx_mute_conv：
 *      - 仅处理个人用户消息（senderType === USER_SENDER_TYPE）；机器人消息统一由 lark-cli 轮询通道按真实 sender.name 走 bot_allow；
 *      - groups_deny 中仅 `pw_chat:<id>` 与 `oc_*` 视为会话 ID，纯数字（如 "2024"）保留群名关键词语义；
 *      - 开放平台 oc_* 排除/静音规则负向放行前强制实时复核，避免双缓存陈旧导致改名群逃逸；
 *      - 原生 pw_chat:* 排除/静音规则同步给 lark-cli 兜底轮询与理解门控，无法实时确认时按 inconclusive 保留游标重试；
 *   4. 收到推送先在提交前复核会话代际与中止信号，再落库返回 ACK；范围外群 @我 被编辑移除时同步撤回待处理记录；
 *   5. 按会话防抖时保留所有不同话题锚点，快通道理解前仅对处于采集范围且账号一致的会话补读背景；
 *   6. 仅在用户显式确认草稿后才经个人 Web 回复：已 verified 幂等返回、已 created 允许关闭开关后仅回读、新发包前复核共享磁盘 send_replies 开关与会话代际。
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
  /** 防抖合并期间收到的所有去重锚点（覆盖同群不同话题的多次 @我） */
  anchors: FastAnchor[];
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
export const BOUND_WORKSPACE_OWNER_KV_KEY = "ctx.personal_web.bound_workspace_open_id";
export function pwSpokenGroupsKey(ownerId: string): string {
  return `ctx.pw_spoken_groups.${ownerId}`;
}

export function saveWorkspaceBinding(store: Store, nativeOwnerId: string, workspaceOpenId: string): void {
  store.set(BOUND_OWNER_KV_KEY, nativeOwnerId);
  if (workspaceOpenId.trim()) {
    store.set(BOUND_WORKSPACE_OWNER_KV_KEY, workspaceOpenId.trim());
  }
}

const ACTIVE_STATES = new Set<ListenerState>(["listening", "connecting", "reconnecting", "reverifying", "publication_blocked"]);
const DAY_MS = 86_400_000;
const OC_EXCLUSION_TTL_MS = 10 * 60_000;

/** 优先以观测中记录的权威 chat_type 区分群聊/私聊，仅无权威类型时才谨慎回退标签前缀 */
function classifyRecordedChatType(obs: Obs | undefined, label: string): "group" | "dm" | "unknown" {
  const t = String(obs?.meta.chat_type ?? "").trim().toLowerCase();
  if (t === "p2p") return "dm";
  if (t === "group" || t === "topic" || t === "topic_group") return "group";
  const trimmed = label.trim();
  if (trimmed.startsWith("私聊")) return "dm";
  return "unknown";
}

function statSignature(file: string): string {
  try {
    const st = fs.statSync(file);
    return `${st.ino}:${st.mtimeMs}:${st.size}`;
  } catch {
    return "";
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
  private readonly debouncedAnchors = new Map<string, Map<string, FastAnchor>>();
  private readonly ocExclusionCache = new Map<string, OpenChatExclusionMeta>();
  private readonly initialCfgStat: string;
  private state: PersistedState;

  constructor(app: App, store: ContextStore, hooks: PersonalWebBridgeHooks) {
    this.app = app;
    this.store = store;
    this.hooks = hooks;
    this.loginStore = new WebLoginStore(app.cfg.dataDir);
    this.initialCfgStat = app.cfg.file ? statSignature(app.cfg.file) : "";
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

  /** 当前有效绑定的个人 Web 原生账号 ID（用于按账号隔离存储查询与窗口组装） */
  activeBoundNativeOwner(): string {
    return this.app.store.get(BOUND_OWNER_KV_KEY) || this.loginStore.load()?.owner_id || "";
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
    this.debouncedAnchors.clear();
  }

  private validateBoundOwner(login: WebLogin): void {
    const bound = this.app.store.get(BOUND_OWNER_KV_KEY);
    if (bound && bound !== login.owner_id) {
      throw new SessionNeedsLoginError(
        `个人 Web 凭据账号 (${login.owner_id}) 与当前工作区已绑定的账号 (${bound}) 不一致，请重新运行 pa context web-login`,
      );
    }
    const cfgWs = this.cfg.owner.open_id.trim();
    const boundWs = (this.app.store.get(BOUND_WORKSPACE_OWNER_KV_KEY) ?? "").trim();
    if (cfgWs && boundWs && boundWs !== cfgWs) {
      throw new SessionNeedsLoginError(
        `当前 config.yaml 配置的主人 (${cfgWs}) 与个人 Web 凭据已绑定的工作区主人 (${boundWs}) 不一致；为防私聊泄漏给错误主人，已中止启动，请清理数据目录或重新扫码绑定`,
      );
    }
  }

  /** 同时包含磁盘凭据代际与工作区/原生绑定键，确保绑定变更后立即唤醒休眠中的监听 */
  private watchedStateKey(login: WebLogin | undefined): string {
    const bound = this.app.store.get(BOUND_OWNER_KV_KEY) ?? "";
    const boundWs = this.app.store.get(BOUND_WORKSPACE_OWNER_KV_KEY) ?? "";
    if (!login) return `none|${bound}|${boundWs}`;
    return `${login.owner_id}:${login.session_id ?? ""}|${bound}|${boundWs}`;
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
        try {
          this.validateBoundOwner(latest);
        } catch {
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
          saveWorkspaceBinding(this.app.store, client.owner().id, this.cfg.owner.open_id);
        } else if (!this.app.store.get(BOUND_WORKSPACE_OWNER_KV_KEY) && this.cfg.owner.open_id.trim()) {
          this.app.store.set(BOUND_WORKSPACE_OWNER_KV_KEY, this.cfg.owner.open_id.trim());
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

  // ───────── 排除规则（双向一致、实时复核负向命中、绝不 fail-open、绝不破坏数字关键词） ─────────

  private async resolveOpenChatMeta(
    ocId: string,
    opts: { force?: boolean } = {},
  ): Promise<{ meta: OpenChatExclusionMeta; fromCache: boolean } | undefined> {
    const now = Date.now();
    if (!opts.force) {
      const cached = this.ocExclusionCache.get(ocId);
      if (cached && cached.expiresAt > now) return { meta: cached, fromCache: true };
    }
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
      return { meta, fromCache: false };
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

  /** 仅收集显式 `pw_chat:<id>` 原生排除/静音规则（纯数字如 "2024" 保持既有群名关键词语义，避免误把老配置当原生 ID） */
  private collectNativeChatExclusions(): Map<string, string> {
    const map = new Map<string, string>();
    for (const raw of this.cfg.context.groups_deny) {
      const d = raw.trim();
      if (d.startsWith("pw_chat:")) map.set(d.slice("pw_chat:".length), "");
    }
    for (const m of this.store.mutedConvs()) {
      if (m.conv.startsWith("pw_chat:")) {
        const id = m.conv.slice("pw_chat:".length);
        map.set(id, m.name || map.get(id) || "");
      }
    }
    return map;
  }

  private nameDenyPatterns(): string[] {
    return this.cfg.context.groups_deny
      .map((d) => d.trim())
      .filter((d) => d && !d.startsWith("oc_") && !d.startsWith("pw_chat:"));
  }

  private matchesDirectNativeIdDeny(pwConv: string): boolean {
    return this.cfg.context.groups_deny.some((raw) => raw.trim() === pwConv);
  }

  private isDirectlyDenied(pwConv: string, chatName: string): boolean {
    const rawId = pwConv.startsWith("pw_chat:") ? pwConv.slice("pw_chat:".length) : pwConv;
    if (this.store.isConvMutedById(pwConv) || this.store.isConvMutedById(rawId)) return true;
    if (this.matchesDirectNativeIdDeny(pwConv)) return true;
    if (chatName && this.nameDenyPatterns().some((d) => chatName.includes(d))) return true;
    return false;
  }

  /**
   * 评估当前个人 Web 会话是否命中排除/静音规则：
   *   - 返回 true：明确命中排除，应丢弃；
   *   - 返回 false：确认未命中排除，允许继续；
   *   - 抛错：存在无法实时确认的排除规则，按 fail-closed 暂缓入库（不发 ACK）。
   * 当存在 oc_* 排除且使用缓存名称出现“不匹配（负向放行）”时，强制实时刷新双边群名后再决定是否放行，防止改名群借陈旧缓存逃逸。
   */
  private async evaluateChatExclusion(params: {
    chatId: string;
    pwConv: string;
    kind: "group" | "dm";
    chatName: string;
    convName: string;
    activeClient?: FeishuWebClient;
    chatNameFromCache?: boolean;
    signal?: AbortSignal;
  }): Promise<boolean> {
    const { chatId, pwConv, kind, convName, activeClient, signal } = params;
    let chatName = params.chatName;
    let chatNameRefreshed = !params.chatNameFromCache;

    if (this.store.isConvMutedById(pwConv) || this.store.isConvMutedById(chatId)) return true;
    if (this.matchesDirectNativeIdDeny(pwConv)) return true;

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

    const ocRules = this.collectOpenChatExclusions();
    if (ocRules.size === 0) return false;
    for (const [ocId, staleLabel] of ocRules) {
      let resolved = await this.resolveOpenChatMeta(ocId);
      if (!resolved) {
        if (kind === "group" && chatName && staleLabel && norm(chatName) === norm(staleLabel)) {
          return true;
        }
        throw new Error(`无法实时解析排除规则 ${ocId} 的会话元数据，按 fail-closed 暂缓入库`);
      }
      if (kind === "group") {
        if (resolved.meta.chatType === "p2p") continue;
        if (!resolved.meta.name) {
          throw new Error(`排除规则 ${ocId} 缺少群名称，无法与当前个人 Web 群聊区分，按 fail-closed 暂缓入库`);
        }
        if (!chatName) {
          throw new Error(`查询群名称失败，无法与排除规则 ${ocId} 区分，按 fail-closed 暂缓入库`);
        }
        if (norm(chatName) === norm(resolved.meta.name)) return true;

        // 负向不匹配时，若任一侧来自缓存，则强制实时刷新双边群名后再决定是否放行（防群改名后缓存不同步逃逸）
        if (resolved.fromCache || !chatNameRefreshed) {
          if (resolved.fromCache) {
            const freshOc = await this.resolveOpenChatMeta(ocId, { force: true });
            if (!freshOc) {
              throw new Error(`复核排除规则 ${ocId} 失败，按 fail-closed 暂缓入库`);
            }
            resolved = freshOc;
            if (resolved.meta.chatType === "p2p") continue;
            if (!resolved.meta.name) {
              throw new Error(`排除规则 ${ocId} 缺少群名称，无法与当前个人 Web 群聊区分，按 fail-closed 暂缓入库`);
            }
          }
          if (!chatNameRefreshed && activeClient) {
            try {
              chatName = (await activeClient.readChat(chatId, { force: true, signal })).name.trim();
              chatNameRefreshed = true;
            } catch {
              throw new Error(`实时刷新群名称失败，无法与排除规则 ${ocId} 区分，按 fail-closed 暂缓入库`);
            }
            if (!chatName) {
              throw new Error(`群名称为空，无法与排除规则 ${ocId} 区分，按 fail-closed 暂缓入库`);
            }
            if (nameRules.some((d) => chatName.includes(d))) return true;
          }
          if (norm(chatName) === norm(resolved.meta.name)) return true;
        }
      } else {
        if (resolved.meta.chatType === "group") continue;
        throw new Error(`存在开放平台私聊排除规则 (${ocId})，个人 Web 私聊无法映射其 open chat_id，按 fail-closed 暂缓入库`);
      }
    }
    return false;
  }

  /**
   * 将显式原生 `pw_chat:*` 静音或禁用规则同步给 lark-cli 兜底轮询与理解门控（批次级调用一次）：
   *   - 有在线 Web 客户端时实时 `readChat(..., { force: true })` 解析最新群名；
   *   - 无在线 Web 客户端（如独立 `pa context run`）或 `readChat` 失败时，旧标签只用于拦截已知匹配，
   *     同时将受影响会话类型标为 inconclusive（保留游标不丢失消息，绝不因改名而 fail-open 放行）。
   */
  async resolveNativeExclusionsForPolling(): Promise<NativePollingExclusions> {
    const rules = this.collectNativeChatExclusions();
    const confirmedGroupNames = new Set<string>();
    let groupsInconclusive = false;
    let dmsInconclusive = false;
    if (rules.size === 0) return { confirmedGroupNames, groupsInconclusive, dmsInconclusive };

    const client = this.client;
    for (const [nativeId, muteName] of rules) {
      const pwConv = `pw_chat:${nativeId}`;
      const latest = this.store.latestConvObs(pwConv);
      const recordedType = classifyRecordedChatType(latest, muteName);
      const rawStale = (muteName || latest?.conv_name || "").trim();
      const staleGroupName = rawStale && !/^群聊\(\d+\)$/.test(rawStale) && !rawStale.startsWith("私聊") ? rawStale : "";

      if (client) {
        try {
          const meta = await client.readChat(nativeId, { force: true });
          if (meta.kind === CHAT_KIND_P2P) {
            dmsInconclusive = true;
          } else if (meta.name.trim()) {
            confirmedGroupNames.add(norm(meta.name.trim()));
          } else {
            groupsInconclusive = true;
          }
          continue;
        } catch {
          if (staleGroupName && recordedType === "group") confirmedGroupNames.add(norm(staleGroupName));
          if (recordedType === "dm") dmsInconclusive = true;
          else if (recordedType === "group") groupsInconclusive = true;
          else {
            groupsInconclusive = true;
            dmsInconclusive = true;
          }
          continue;
        }
      }

      // 独立进程（无在线 Web 客户端）无法核实静音原生群是否已改名：旧标签可拦截命中，但非命中必须 inconclusive 暂缓并保留游标
      if (staleGroupName && recordedType === "group") confirmedGroupNames.add(norm(staleGroupName));
      if (recordedType === "dm") {
        dmsInconclusive = true;
      } else if (recordedType === "group") {
        groupsInconclusive = true;
      } else {
        groupsInconclusive = true;
        dmsInconclusive = true;
      }
    }
    return { confirmedGroupNames, groupsInconclusive, dmsInconclusive };
  }

  /**
   * 理解 / 自动预起草执行前二次校验：
   * 支持复用批次级 `nativeExclSnapshot`，避免 N 个候选会话重复触发 N×M 次 readChat。
   */
  async checkConvAllowedForUnderstand(
    conv: string,
    convName: string,
    nativeExclSnapshot?: NativePollingExclusions,
  ): Promise<"allowed" | "excluded" | "uncertain"> {
    if (!conv.startsWith("pw_chat:") && !conv.startsWith("oc_")) return "allowed";
    if (!this.cfg.context.sources.im) return "excluded";

    if (conv.startsWith("pw_chat:")) {
      const chatId = conv.slice("pw_chat:".length);
      if (this.store.isConvMutedById(conv) || this.store.isConvMutedById(chatId)) return "excluded";
      const latest = this.store.latestConvObs(conv);
      const recordedType = classifyRecordedChatType(latest, convName);
      const kind: "group" | "dm" = recordedType === "dm" ? "dm" : "group";
      const client = this.client;
      let chatName = "";
      let chatNameFromCache = false;
      if (kind === "group") {
        if (client) {
          try {
            chatName = (await client.readChat(chatId)).name.trim();
            chatNameFromCache = true;
          } catch {
            chatName = "";
          }
        } else {
          const fallback = (convName || latest?.conv_name || "").trim();
          chatName = fallback && !/^群聊\(\d+\)$/.test(fallback) ? fallback : "";
          chatNameFromCache = true;
        }
      }
      try {
        const excluded = await this.evaluateChatExclusion({
          chatId,
          pwConv: conv,
          kind,
          chatName,
          convName: convName || latest?.conv_name || "",
          activeClient: client,
          chatNameFromCache,
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
    const recordedType = classifyRecordedChatType(latest, effectiveName);
    const isDm = recordedType === "dm";
    for (const raw of this.cfg.context.groups_deny) {
      const d = raw.trim();
      if (!d) continue;
      if (d === conv) return "excluded";
      if (!d.startsWith("oc_") && !d.startsWith("pw_chat:") && effectiveName && effectiveName.includes(d)) {
        return "excluded";
      }
    }
    const nativeExcl = nativeExclSnapshot ?? (await this.resolveNativeExclusionsForPolling());
    if (isDm) return nativeExcl.dmsInconclusive ? "uncertain" : "allowed";
    if (effectiveName && nativeExcl.confirmedGroupNames.has(norm(effectiveName))) return "excluded";
    if (nativeExcl.groupsInconclusive) return "uncertain";
    if (nativeExcl.confirmedGroupNames.size > 0 && !effectiveName) return "uncertain";
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
   *   - 先做纯本地原生 ID 过滤与群范围筛查（若范围外群消息此前作为 @我 待处理但已被编辑移除 @我，则撤回旧待处理记录）；
   *   - 异步等待 readChat / 排除核验后、落库前复核信号取消与会话代际，防止登出/换号后把旧会话消息写入库或触发模型。
   */
  async handleMessage(msg: WebMessage, client?: FeishuWebClient, signal?: AbortSignal): Promise<void> {
    if (signal?.aborted) return;
    if (!this.cfg.context.sources.im) return;
    if (!msg.id || !msg.conversationId || msg.unsupported) return;
    if (msg.conversationKind !== "group" && msg.conversationKind !== "dm") return;
    if (msg.senderType !== USER_SENDER_TYPE) return;
    const text = msg.text.trim();
    if (!text) return;

    const activeClient = client ?? this.client;
    const ownerId = msg.ownerId || activeClient?.owner().id || this.loginStore.load()?.owner_id || "";
    const capturedSessionId = activeClient?.currentSessionId() ?? "";
    const isMe = !!ownerId && msg.actorId === ownerId;
    const pwConv = `pw_chat:${msg.conversationId}`;
    const isAtMe = !isMe && !!ownerId && msg.mentions.some((m) => m.id === ownerId);

    // 1) 纯本地快速过滤：原生 ID 静音/禁用直接丢弃（零网络开销）
    if (this.store.isConvMutedById(pwConv) || this.store.isConvMutedById(msg.conversationId)) return;
    if (this.matchesDirectNativeIdDeny(pwConv)) return;

    // 2) 范围外普通群消息在 readChat 之前立刻丢弃；若该消息 ID 此前曾以 @我 入库待处理，同步撤回避免模型对已撤销的 @我 提醒/起草
    if (msg.conversationKind === "group" && !isMe && !isAtMe && !this.isGroupInScope(msg.conversationId, pwConv, ownerId)) {
      this.store.retirePendingObs(`pw:${msg.id}`);
      return;
    }

    // 3) 仅对可能入库的消息按需获取群名，再执行完整排除校验（含名称规则与实时 oc_* 复核）
    let chatName = "";
    if (msg.conversationKind === "group" && activeClient) {
      try {
        chatName = (await activeClient.readChat(msg.conversationId, { signal })).name.trim();
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
      activeClient,
      chatNameFromCache: true,
      signal,
    });
    if (excluded) return;

    // 4) 落库前最终核验会话未被中止、登出或换号
    if (signal?.aborted) {
      throw new WebHttpError("aborted", "会话已中止，放弃提交推送观测");
    }
    if (capturedSessionId) {
      const diskNow = this.loginStore.load();
      if (!diskNow || diskNow.owner_id !== ownerId || (diskNow.session_id && diskNow.session_id !== capturedSessionId)) {
        throw new WebHttpError("aborted", "个人 Web 会话已登出或变更，放弃提交推送观测");
      }
      this.validateBoundOwner(diskNow);
    }

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
    const anchor: FastAnchor = {
      id: msg.id,
      conversationId: msg.conversationId,
      rootId: msg.rootId,
      parentId: msg.parentId,
      threadId: msg.threadId,
      position: msg.position,
      createdAtMs: msg.createdAtMs,
    };
    this.scheduleFastLane({
      conv: pwConv,
      conv_name: convName,
      trigger_obs_id: obs.id,
      text_hash: revHash,
      anchor,
      anchors: [anchor],
    });
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
    let bucket = this.debouncedAnchors.get(key);
    if (!bucket) {
      bucket = new Map<string, FastAnchor>();
      this.debouncedAnchors.set(key, bucket);
    }
    for (const a of trigger.anchors) bucket.set(a.id, a);

    const prev = this.debounceTimers.get(key);
    if (prev) clearTimeout(prev);
    const delay = this.cfg.context.personal_web.debounce_ms;
    const flush = () => {
      this.debounceTimers.delete(key);
      const collected = this.debouncedAnchors.get(key);
      this.debouncedAnchors.delete(key);
      const allAnchors = collected ? [...collected.values()] : trigger.anchors;
      this.fireFastTrigger({ ...trigger, anchors: allAnchors });
    };
    if (delay <= 0) {
      flush();
      return;
    }
    const timer = setTimeout(flush, delay);
    timer.unref?.();
    this.debounceTimers.set(key, timer);
  }

  /**
   * 快通道理解前按需补读会话背景（支持一次补齐防抖期内所有不同话题的 root/parent 锚点）：
   *   - 严格绑定触发观测的所属账号与当前会话代际（跨 await 后再次核验）；
   *   - 重新校验 sources.im、静音状态、排除规则与群聊采集范围；
   *   - 仅写入用户消息并标记为 background_only。
   */
  async hydrateContext(
    anchorOrAnchors: FastAnchor | FastAnchor[],
    conv: string,
    convName: string,
    signal?: AbortSignal,
  ): Promise<number> {
    const anchors = Array.isArray(anchorOrAnchors) ? anchorOrAnchors : [anchorOrAnchors];
    if (!anchors.length) return 0;
    const primary = anchors[anchors.length - 1];
    if (!this.cfg.context.sources.im) return 0;
    const client = this.client;
    if (!client) return 0;
    if (this.store.isConvMutedById(conv)) return 0;

    const clientOwnerId = client.owner().id;
    const clientOwnerName = client.owner().name;
    const clientSessionId = client.currentSessionId() ?? "";
    const triggerObs = this.store.obs(`pw:${primary.id}`);
    const triggerOwnerId = String(triggerObs?.meta.native_owner_id ?? "");
    if (triggerOwnerId && triggerOwnerId !== clientOwnerId) return 0;

    const sessionStillValid = (): boolean => {
      if (this.client !== client) return false;
      if (client.owner().id !== clientOwnerId) return false;
      const disk = this.loginStore.load();
      if (!disk || disk.owner_id !== clientOwnerId) return false;
      if (clientSessionId && disk.session_id && disk.session_id !== clientSessionId) return false;
      try {
        this.validateBoundOwner(disk);
      } catch {
        return false;
      }
      return true;
    };
    if (!sessionStillValid()) return 0;

    const isDm = classifyRecordedChatType(triggerObs, convName) === "dm";
    let chatName = "";
    if (!isDm) {
      try {
        chatName = (await client.readChat(primary.conversationId, { signal })).name.trim();
      } catch {
        chatName = "";
      }
    }
    if (!sessionStillValid()) return 0;

    try {
      const excluded = await this.evaluateChatExclusion({
        chatId: primary.conversationId,
        pwConv: conv,
        kind: isDm ? "dm" : "group",
        chatName,
        convName,
        activeClient: client,
        chatNameFromCache: true,
        signal,
      });
      if (excluded) return 0;
    } catch (err) {
      log("warn", "快通道跳过补读背景（排除规则未确认）", { conv, err: errMsg(err) });
      return 0;
    }

    if (!isDm && !this.isGroupInScope(primary.conversationId, conv, clientOwnerId)) {
      return 0;
    }

    const existing = this.store.convObs(conv, Date.now() - 24 * 3_600_000, 6, clientOwnerId);
    const needsGeneralHistory = existing.length < 5;
    const toFetch: FastAnchor[] = [];
    const seenAnchorKey = new Set<string>();
    for (const a of anchors) {
      const missingThreadAnchors = [a.rootId, a.parentId]
        .filter((id): id is string => !!id && id !== a.id)
        .filter((id) => !this.store.obs(`pw:${id}`));
      if (missingThreadAnchors.length > 0 || (needsGeneralHistory && !a.rootId && !a.threadId)) {
        const key = `${a.id}:${a.rootId}:${a.parentId}`;
        if (!seenAnchorKey.has(key)) {
          seenAnchorKey.add(key);
          toFetch.push(a);
        }
      }
    }
    if (!toFetch.length) return 0;

    try {
      const collected = new Map<string, WebMessage>();
      for (const a of toFetch) {
        const part = await client.readContext(a, { limit: 15, signal });
        for (const m of part) {
          if (m.id && m.text.trim() && m.senderType === USER_SENDER_TYPE) {
            collected.set(m.id, m);
          }
        }
      }
      if (!collected.size) return 0;
      if (!sessionStillValid()) return 0;
      const ownerName = this.app.store.get("ctx.owner_name") || clientOwnerName || "我";
      const bg: Obs[] = [...collected.values()].map((m) => {
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

  /**
   * 核验共享的 send_replies 发送权限：
   * 先查本进程配置，若磁盘 config.yaml 被另一进程（如 Web 控制台）修改过，则同步读取磁盘最新配置防止跨进程陈旧放行。
   */
  private assertSendEnabled(): void {
    if (!this.cfg.context.personal_web.send_replies) {
      throw new Error("未开启个人 Web 回复（需在配置中设置 context.personal_web.send_replies: true）");
    }
    const cfgFile = this.cfg.file;
    if (cfgFile && fs.existsSync(cfgFile)) {
      const curSig = statSignature(cfgFile);
      if (curSig && curSig !== this.initialCfgStat) {
        try {
          const parsed = YAML.parse(fs.readFileSync(cfgFile, "utf8")) as {
            context?: { personal_web?: { send_replies?: boolean } };
          };
          if (parsed?.context?.personal_web?.send_replies !== true) {
            throw new Error("检测到配置文件已关闭 context.personal_web.send_replies，已中止发送");
          }
        } catch (err) {
          if (err instanceof Error && err.message.includes("send_replies")) throw err;
          throw new Error("无法核验配置文件中的 context.personal_web.send_replies 开关，按安全原则中止发送");
        }
      }
    }
  }

  private assertSessionOwner(expectedOwnerId: string, expectedSessionId = ""): WebLogin {
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
   *   - 最先检查本地持久化投递记录：已 `verified` 时直接幂等返回（无需实时登录或开启 send_replies）；
   *   - 已 `created`（消息已在飞书创建但上次未完成回读）：仅校验账号会话并补跑独立回读，即使此时已关闭 `send_replies` 仍可完成确认；
   *   - 新发送在入口与发包前（onBeforeSend）双重核验共享磁盘 `send_replies` 开关、账号绑定与会话代际；
   *   - 空载荷响应、5xx、超时等结果不明错误保留 `sending` 拒绝重发；仅明确未创建拒绝记为 `rejected` 允许重试。
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
      if (prev.state === "verified" && prev.reply_id) {
        return { replyId: prev.reply_id, rootId: prev.root_id, parentId: prev.parent_id, threadId: "", verified: true };
      }
      if (prev.state === "sending") {
        throw new Error("上次个人 Web 发送结果不明确（对方可能已收到），为避免重复发送已中止重试；请先在飞书核实后再决定是否修改重发");
      }
    }

    const readbackOnly = prev?.state === "created" && !!prev.reply_id;
    // 只有需要发起新发送时才要求 send_replies=true；已创建待回读只读核验无需重新开启发送开关
    if (!readbackOnly) {
      this.assertSendEnabled();
    }
    const diskLogin = this.assertSessionOwner(args.owner_id);
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

    if (readbackOnly && prev?.reply_id) {
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
            this.assertSendEnabled();
            this.assertSessionOwner(args.owner_id, initialSessionId);
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
 *   1. 若本工作区已绑定过其他原生飞书账号 ID：
 *      - 未显式传 forceSwitch 直接拒绝；
 *      - 即使传了 forceSwitch，若当前数据目录已有旧账号的个人 Web 观测数据也拒绝原地覆盖（必须使用干净 data_dir，彻底杜绝旧私聊与【我】标记混入）；
 *   2. 核验 lark-cli 当前登录用户的 open_id 与 config.yaml 中的 owner.open_id 一致（同应用空间内严格比对）；
 *      注意：飞书网页资料（app_id=12）的 open_id 与 lark-cli 所属应用不同，不能跨应用直接等同或互斥；
 *   3. 若昵称与已知主人不一致，拒绝保存（除非显式传 allowNameMismatch）；
 *   4. 首次绑定或工作区 owner.open_id 发生变更时，因为跨应用无法单凭姓名密码学等价核验扫码者身份，
 *      必须由用户显式追加 `--allow-unverified-owner` 确认后才允许落盘（同账号且同工作区主人重登免重复确认）。
 */
export async function verifyWorkspaceOwnerBinding(
  app: App,
  login: WebLogin,
  opts: { forceSwitch?: boolean; allowNameMismatch?: boolean; allowUnverifiedOwner?: boolean } = {},
): Promise<void> {
  const loginStore = new WebLoginStore(app.cfg.dataDir);
  const boundId = app.store.get(BOUND_OWNER_KV_KEY) || loginStore.load()?.owner_id || "";
  if (boundId && boundId !== login.owner_id) {
    if (!opts.forceSwitch) {
      throw new Error(
        `本工作区已绑定个人 Web 账号 ${boundId}，但本次扫码账号为 ${login.owner_id}（${login.owner_name || "无昵称"}）。` +
          "为防止混入他人私聊并以错误身份回复，已拒绝保存；如需更换账号，请使用新的干净数据目录。",
      );
    }
    const ctxStore = new ContextStore(app.store.db);
    if (ctxStore.hasOtherNativeOwnerObs(login.owner_id)) {
      throw new Error(
        `当前数据目录已包含原账号 (${boundId}) 的个人 Web 历史观测；为防止旧账号私聊与【我】消息混入新账号图谱，拒绝原地换号。` +
          "请先使用全新的 data_dir 后再执行 pa context web-login。",
      );
    }
  }

  const configuredOpenId = app.cfg.owner.open_id.trim();
  const boundWorkspaceOpenId = (app.store.get(BOUND_WORKSPACE_OWNER_KV_KEY) ?? "").trim();

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
    // lark-cli 不可用时继续走下方显式确认门控
  }

  const storedOwnerName = (app.store.get("ctx.owner_name") ?? "").trim();
  const expectedName = cliVerified ? cliName : storedOwnerName;
  const sameNativeOwner = !!boundId && boundId === login.owner_id;
  const sameWorkspaceOwner = !configuredOpenId || !boundWorkspaceOpenId || boundWorkspaceOpenId === configuredOpenId;
  const isAlreadyVerifiedRelogin = sameNativeOwner && sameWorkspaceOwner && (!configuredOpenId || !!boundWorkspaceOpenId);

  if (expectedName && !opts.allowNameMismatch) {
    if (!login.owner_name || norm(expectedName) !== norm(login.owner_name)) {
      throw new Error(
        `本次扫码账号「${login.owner_name || "(无昵称)"}」（ID: ${login.owner_id}）与当前工作区主人「${expectedName}」(${configuredOpenId || "未初始化"}) 不一致，已拒绝保存。` +
          "请确认手机飞书登录的是本人账号；如确为同一账号昵称差异，可追加 --allow-name-mismatch 重试。",
      );
    }
  }

  // 首次绑定或工作区主人变更：飞书网页原生 ID 与 lark-cli 应用级 open_id 无法跨应用强等价核验，必须显式确认 --allow-unverified-owner
  if (!isAlreadyVerifiedRelogin && !opts.allowUnverifiedOwner) {
    throw new Error(
      `首次绑定或变更工作区主人时，扫码账号「${login.owner_name || "(无昵称)"}」（原生 ID: ${login.owner_id}）无法与工作区配置 (${configuredOpenId || "未配置 owner.open_id"}) 做跨应用强 ID 校验（仅靠姓名相同无法排除同名同事）。` +
        "请核对手机飞书确为本人账号后，追加 --allow-unverified-owner 重新执行 pa context web-login。",
    );
  }
}
