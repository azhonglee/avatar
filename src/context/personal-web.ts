import fs from "node:fs";
import path from "node:path";
import type { App } from "../app.ts";
import type { CtxPersonalWebStatus } from "../api/types.ts";
import type { Config } from "../config.ts";
import { PermanentEffectError } from "../effects.ts";
import { FeishuGatewayClient } from "../gateway/client.ts";
import {
  GATEWAY_USER_SENDER_TYPE,
  GatewayHttpError,
  MAX_CLIENT_DENY_RULE_LEN,
  MAX_CLIENT_DENY_RULES,
  type GatewayAnchor,
  type GatewayEvent,
  type GatewayListenerState,
  type GatewayMessagePayload,
  type GatewayReplyResult,
  type GatewayStatus,
} from "../gateway/protocol.ts";
import { errMsg, expandHome, log } from "../util.ts";
import { isRealConvName, realConvName, type ContextStore, type Obs } from "./store.ts";

/**
 * 个人 Web 协议网关客户端桥接层（纯客户端，零密钥 / 零 Cookie / 零飞书协议依赖）。
 *
 * 职责：
 *   1. 通过独立部署的 feishu-gateway（Unix Socket 或回环 HTTP）订阅 SSE 事件流，按持久化游标零丢失消费；
 *   2. 执行 Avatar 业务层过滤（groups_deny / mutedConvs / groups=spoken|allowlist / bot_allow）后写入 ctx_obs；
 *   3. 收到 delete 墓碑事件时同步删除本地观测；
 *   4. 对「真实 @本人」与「对方私聊」按会话防抖后触发单会话快通道，必要时经只读接口补读有界上下文；
 *   5. 仅在用户显式确认草稿后，使用独立 reply_token 向网关提交带固定 cid 幂等键的受控回复请求。
 */

export const BOUND_OWNER_KV_KEY = "ctx.personal_web.bound_owner_id";
export const CURSOR_KV_KEY = "ctx.pw_gateway.cursor";
/** 与游标配套保存的网关事件库实例标识：变化说明网关库被重建，游标必须重置 */
const EPOCH_KV_KEY = "ctx.pw_gateway.db_epoch";
const STATE_KV_KEY = "ctx.personal_web.state";
const SPOKEN_GROUPS_KV_KEY = "ctx.personal_web.spoken_groups";
const REPLY_STARTED_PREFIX = "ctx.pw_reply_started.";
const WATCH_INTERVAL_MS = 3_000;

export type FastAnchor = GatewayAnchor;

export interface FastTrigger {
  conv: string;
  conv_name: string;
  trigger_obs_id: string;
  anchor: FastAnchor;
}

interface PersistedState {
  state: GatewayListenerState;
  logged_in: boolean;
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
  /** 仅测试注入：替换默认按 config 构造的网关客户端 */
  gatewayClient?: FeishuGatewayClient;
  watchIntervalMs?: number;
  streamIdleTimeoutMs?: number;
}

export interface ResolvedGatewayClientConfig {
  socketPath?: string;
  baseUrl?: string;
  readToken: string;
  replyToken: string;
  endpointLabel: string;
}

function readSystemdCredential(names: string[], env: NodeJS.ProcessEnv = process.env): string {
  const dir = env.CREDENTIALS_DIRECTORY?.trim();
  if (!dir) return "";
  for (const name of names) {
    try {
      const v = fs.readFileSync(path.join(dir, name), "utf8").trim();
      if (v) return v;
    } catch {
      // absent
    }
  }
  return "";
}

/** 从配置指定的环境变量（或 systemd LoadCredential）解析网关地址与读写分离双令牌。 */
export function resolveGatewayClientConfig(
  pwCfg: Config["context"]["personal_web"],
  env: NodeJS.ProcessEnv = process.env,
): ResolvedGatewayClientConfig {
  const socketRaw = pwCfg.gateway_socket.trim();
  const urlRaw = pwCfg.gateway_url.trim();
  const socketPath = socketRaw ? path.resolve(expandHome(socketRaw)) : undefined;
  const baseUrl = urlRaw || undefined;
  const readEnvName = pwCfg.read_token_env.trim();
  const replyEnvName = pwCfg.reply_token_env.trim();

  const readToken =
    (readEnvName ? env[readEnvName]?.trim() : "") ||
    readSystemdCredential(["feishu-gw-read-token", "read-token"], env);
  const replyToken =
    (replyEnvName ? env[replyEnvName]?.trim() : "") ||
    readSystemdCredential(["feishu-gw-reply-token", "reply-token"], env);

  const endpointLabel = socketPath ? `unix://${socketPath}` : (baseUrl ?? "(未配置)");
  return { socketPath, baseUrl, readToken, replyToken, endpointLabel };
}

export function createGatewayClientForConfig(
  pwCfg: Config["context"]["personal_web"],
  env: NodeJS.ProcessEnv = process.env,
): FeishuGatewayClient {
  const resolved = resolveGatewayClientConfig(pwCfg, env);
  if (resolved.readToken && resolved.replyToken && resolved.readToken === resolved.replyToken) {
    throw new Error("安全约束违规：read_token 与 reply_token 的值不能相同，请为读写配置不同令牌");
  }
  return new FeishuGatewayClient({
    socketPath: resolved.socketPath,
    baseUrl: resolved.baseUrl,
    readToken: resolved.readToken,
    replyToken: resolved.replyToken,
  });
}

/**
 * 旧版（进程内个人 Web）遗留在 Avatar 侧的会话凭据：加密 Cookie 文件及其锁文件、仍在环境里的密钥变量。
 * 现在登录态只应存在于独立网关，这些残留会让 Avatar 与同用户 worker 仍能接触到会话。
 */
export function legacyPersonalWebArtifacts(cfg: Pick<Config, "dataDir">, env: NodeJS.ProcessEnv = process.env): { files: string[]; envKeys: string[] } {
  const base = [path.join(cfg.dataDir, "feishu-web.json"), env.PA_FEISHU_WEB_CRED_FILE?.trim() ? path.resolve(env.PA_FEISHU_WEB_CRED_FILE.trim()) : ""].filter(Boolean);
  const files = [...new Set(base.flatMap((f) => [f, `${f}.lock`, `${f}.lock.db`]))].filter((f) => fs.existsSync(f));
  const envKeys = ["PA_FEISHU_WEB_KEY", "PA_FEISHU_WEB_CRED_FILE"].filter((k) => !!env[k]?.trim());
  return { files, envKeys };
}

/** 核验网关上报的个人账号与当前 Avatar 工作区的绑定关系，防止指向错误网关实例导致跨账号混库。 */
export function verifyGatewayOwnerForWorkspace(app: App, ownerId: string): void {
  const id = ownerId.trim();
  if (!id) return;
  const bound = (app.store.get(BOUND_OWNER_KV_KEY) ?? "").trim();
  if (bound && bound !== id) {
    throw new Error(`当前工作区已绑定个人 Web 账号 ${bound}，与网关当前账号 ${id} 不一致，拒绝混入消息`);
  }
}

export class PersonalWebBridge {
  private readonly app: App;
  private readonly store: ContextStore;
  private readonly hooks: PersonalWebBridgeHooks;
  private stopCtrl: AbortController | undefined;
  private readonly debounceTimers = new Map<string, NodeJS.Timeout>();
  private state: PersistedState;

  constructor(app: App, store: ContextStore, hooks: PersonalWebBridgeHooks) {
    this.app = app;
    this.store = store;
    this.hooks = hooks;
    const saved = this.loadSavedState();
    this.state = saved ?? {
      state: "idle",
      logged_in: false,
      owner_id: "",
      owner_name: "",
      since: 0,
      last_message_at: null,
      last_error: "",
    };
  }

  private get cfg() {
    return this.app.cfg;
  }

  private getClient(): FeishuGatewayClient {
    if (this.hooks.gatewayClient) return this.hooks.gatewayClient;
    return createGatewayClientForConfig(this.cfg.context.personal_web);
  }

  cursor(): number {
    const raw = this.app.store.get(CURSOR_KV_KEY);
    const n = raw ? Number.parseInt(raw, 10) : 0;
    return Number.isFinite(n) && n >= 0 ? n : 0;
  }

  private setCursor(seq: number): void {
    if (!Number.isFinite(seq) || seq < 0) return;
    if (seq > this.cursor()) {
      this.app.store.set(CURSOR_KV_KEY, String(Math.floor(seq)));
    }
  }

  private resetCursor(seq = 0): void {
    this.app.store.set(CURSOR_KV_KEY, String(Math.max(0, Math.floor(seq))));
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
    const saved = this.loadSavedState() ?? this.state;
    const enabled = this.cfg.context.personal_web.enabled;
    if (!enabled) {
      return {
        enabled: false,
        logged_in: false,
        state: "idle",
        owner_id: saved.owner_id,
        owner_name: saved.owner_name,
        last_message_at: saved.last_message_at,
        last_error: "",
      };
    }
    return {
      enabled: true,
      logged_in: saved.logged_in,
      state: saved.state,
      owner_id: saved.owner_id,
      owner_name: saved.owner_name,
      last_message_at: saved.last_message_at,
      last_error: saved.last_error,
    };
  }

  /** 启动网关 SSE 订阅循环（异步后台运行，不阻塞常驻进程启动）。 */
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
    for (const timer of this.debounceTimers.values()) clearTimeout(timer);
    this.debounceTimers.clear();
  }

  private async runSupervisor(signal: AbortSignal): Promise<void> {
    const watchMs = this.hooks.watchIntervalMs ?? WATCH_INTERVAL_MS;
    let reconnectDelayMs = 1_000;
    let wasDegraded = false;
    let everConnected = false;
    let notifiedNeedsLogin = false;

    const applyGatewayStatus = (st: GatewayStatus) => {
      if (st.owner_id) {
        verifyGatewayOwnerForWorkspace(this.app, st.owner_id);
        if (!this.app.store.get(BOUND_OWNER_KV_KEY)) {
          this.app.store.set(BOUND_OWNER_KV_KEY, st.owner_id);
        }
      }
      if (st.owner_name && !this.app.store.get("ctx.owner_name")) {
        this.app.store.set("ctx.owner_name", st.owner_name);
      }
      if (st.state === "reconnecting" || st.state === "reverifying") wasDegraded = true;
      if (st.state === "listening") {
        notifiedNeedsLogin = false;
        if (wasDegraded && everConnected) {
          wasDegraded = false;
          this.hooks.onReconnect();
        }
        everConnected = true;
      }
      this.persistState({
        state: st.state,
        logged_in: st.logged_in,
        owner_id: st.owner_id || this.state.owner_id,
        owner_name: st.owner_name || this.state.owner_name,
        since: st.since || Date.now(),
        last_message_at: st.last_message_at ?? this.state.last_message_at,
        last_error: st.state === "listening" || st.state === "stopped" ? "" : st.last_error,
      });
      if (st.state === "needs_login" && !notifiedNeedsLogin) {
        notifiedNeedsLogin = true;
        this.hooks.onNeedsLogin(st.last_error || "个人 Web 网关会话已失效，请在网关侧运行 `feishu-gateway login` 重新扫码");
      }
    };

    while (!signal.aborted) {
      let client: FeishuGatewayClient;
      try {
        client = this.getClient();
      } catch (err) {
        const msg = errMsg(err);
        this.persistState({ state: "needs_login", logged_in: false, since: Date.now(), last_error: msg });
        if (!notifiedNeedsLogin) {
          notifiedNeedsLogin = true;
          this.hooks.onNeedsLogin(msg);
        }
        await waitAbortable(watchMs, signal);
        continue;
      }

      if (!this.hooks.gatewayClient) {
        const resolved = resolveGatewayClientConfig(this.cfg.context.personal_web);
        if (!resolved.readToken) {
          const msg = `缺少网关只读令牌（请设置环境变量 ${this.cfg.context.personal_web.read_token_env || "FEISHU_GW_READ_TOKEN"} 或 systemd LoadCredential）`;
          this.persistState({ state: "needs_login", logged_in: false, since: Date.now(), last_error: msg });
          if (!notifiedNeedsLogin) {
            notifiedNeedsLogin = true;
            this.hooks.onNeedsLogin(msg);
          }
          await waitAbortable(watchMs, signal);
          continue;
        }
      }

      const streamCtrl = new AbortController();
      const onOuterAbort = () => streamCtrl.abort();
      signal.addEventListener("abort", onOuterAbort, { once: true });
      let accountMismatch = false;
      let cursorResetReconnect = false;

      try {
        if (!everConnected) {
          this.persistState({ state: "connecting", since: Date.now(), last_error: "" });
        }
        await client.streamEvents({
          after: this.cursor(),
          signal: streamCtrl.signal,
          idleTimeoutMs: this.hooks.streamIdleTimeoutMs,
          onStatus: (st) => {
            try {
              applyGatewayStatus(st);
              reconnectDelayMs = 1_000;
              const savedEpoch = this.app.store.get(EPOCH_KV_KEY) ?? "";
              if (st.db_epoch && savedEpoch && savedEpoch !== st.db_epoch) {
                log("warn", "网关事件库实例已变化（网关数据库被重建），重置本地游标并重新订阅", {
                  local_cursor: this.cursor(),
                  saved_epoch: savedEpoch,
                  gateway_epoch: st.db_epoch,
                });
                this.resetCursor(0);
                this.app.store.set(EPOCH_KV_KEY, st.db_epoch);
                this.hooks.onReconnect();
                cursorResetReconnect = true;
                streamCtrl.abort();
                return;
              }
              if (st.db_epoch && !savedEpoch) this.app.store.set(EPOCH_KV_KEY, st.db_epoch);
              if (this.cursor() > st.latest_seq) {
                log("warn", "检测到网关事件游标回退（网关数据库可能已重建），重置本地游标并重新订阅", {
                  local_cursor: this.cursor(),
                  gateway_latest_seq: st.latest_seq,
                });
                this.resetCursor(0);
                this.hooks.onReconnect();
                cursorResetReconnect = true;
                streamCtrl.abort();
              }
            } catch (err) {
              accountMismatch = true;
              const msg = errMsg(err);
              this.persistState({ state: "needs_login", logged_in: false, since: Date.now(), last_error: msg });
              if (!notifiedNeedsLogin) {
                notifiedNeedsLogin = true;
                this.hooks.onNeedsLogin(msg);
              }
              streamCtrl.abort();
            }
          },
          onGap: (gap) => {
            log("warn", "个人 Web 网关缓存已滚动淘汰或重置，将触发一次飞书常规采集补齐", {
              after: gap.after,
              min_seq: gap.min_seq,
              latest_seq: gap.latest_seq,
            });
            if (gap.after > gap.latest_seq) {
              this.resetCursor(0);
            }
            this.hooks.onReconnect();
          },
          onEvent: async (ev) => {
            if (ev.kind === "message" && ev.message.ownerId) {
              try {
                verifyGatewayOwnerForWorkspace(this.app, ev.message.ownerId);
              } catch (err) {
                accountMismatch = true;
                const msg = errMsg(err);
                this.persistState({ state: "needs_login", logged_in: false, since: Date.now(), last_error: msg });
                if (!notifiedNeedsLogin) {
                  notifiedNeedsLogin = true;
                  this.hooks.onNeedsLogin(msg);
                }
                streamCtrl.abort();
                return;
              }
            }
            await this.handleGatewayEvent(ev);
            this.setCursor(ev.seq);
            reconnectDelayMs = 1_000;
          },
        });
      } catch (err) {
        if (signal.aborted) return;
        const msg = errMsg(err);
        if (err instanceof GatewayHttpError && (err.statusCode === 401 || err.statusCode === 403)) {
          this.persistState({
            state: "needs_login",
            logged_in: false,
            since: Date.now(),
            last_error: `网关鉴权失败（${err.code}）：${msg}`,
          });
          if (!notifiedNeedsLogin) {
            notifiedNeedsLogin = true;
            this.hooks.onNeedsLogin(`个人 Web 网关鉴权失败：${msg}`);
          }
          await waitAbortable(Math.max(watchMs, 5_000), signal);
        } else {
          wasDegraded = true;
          this.persistState({
            state: "reconnecting",
            since: Date.now(),
            last_error: `连接个人 Web 网关失败：${msg}`,
          });
          await waitAbortable(reconnectDelayMs, signal);
          reconnectDelayMs = Math.min(reconnectDelayMs * 2, 15_000);
        }
      } finally {
        signal.removeEventListener("abort", onOuterAbort);
      }

      if (cursorResetReconnect && !signal.aborted) {
        continue;
      }
      if (accountMismatch && !signal.aborted) {
        await waitAbortable(Math.max(watchMs, 5_000), signal);
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

  /** 规则项 r 是否指向这个会话：ID 相等，或群名包含关键字，或规范化私聊名一致，或 r 是 oc_ ID 且其已知群名与会话名一致 */
  private ruleMatches(r: string, ids: Set<string>, chatName: string): boolean {
    if (!r) return false;
    if (ids.has(r)) return true;
    if (!chatName) return false;
    if (chatName.includes(r)) return true;
    const normR = realConvName(r);
    if (normR && realConvName(chatName) === normR) return true;
    return r.startsWith("oc_") && this.openGroupName(r) === chatName;
  }

  isDeniedChat(chatId: string, chatName: string): boolean {
    const ids = this.chatIds(chatId);
    if (this.cfg.context.groups_deny.some((d) => this.ruleMatches(d, ids, chatName))) return true;
    const muted = this.store.mutedConvs();
    const normName = realConvName(chatName);
    return muted.some(
      (m) =>
        ids.has(m.conv) ||
        (!!chatName && m.conv.startsWith("oc_") && this.openGroupName(m.conv) === chatName) ||
        (!!chatName && m.name === chatName) ||
        (!!normName && realConvName(m.name) === normName),
    );
  }

  /** 是否存在要靠会话名才能判定的排除或静音规则（pw_chat:<id> / 纯数字原生 ID 只按 ID 匹配，不算） */
  private hasNameBasedExclusions(): boolean {
    const idOnly = (r: string) => r.startsWith("pw_chat:") || /^\d+$/.test(r);
    return (
      this.cfg.context.groups_deny.some((d) => !!d.trim() && !idOnly(d.trim())) ||
      this.store.mutedConvs().some((m) => !m.conv.startsWith("pw_chat:"))
    );
  }

  /**
   * 交给网关在发送前用实时会话名核对的规则：groups_deny 原样、oc_ 规则换成 lark-cli 记下的群名、
   * 静音会话的 pw_chat ID 与真实会话名。网关以“ID 相等 / 名称包含关键字 / 规范化私聊名一致”匹配。
   */
  private clientDenyRules(): string[] {
    const out = new Set<string>();
    const addOc = (oc: string) => {
      const name = this.openGroupName(oc);
      if (name) out.add(name);
    };
    for (const raw of this.cfg.context.groups_deny) {
      const r = raw.trim();
      if (!r) continue;
      out.add(r);
      if (r.startsWith("oc_")) addOc(r);
    }
    for (const m of this.store.mutedConvs()) {
      if (m.conv.startsWith("pw_chat:")) out.add(m.conv);
      if (m.conv.startsWith("oc_")) addOc(m.conv);
      const name = realConvName(m.name);
      if (name) out.add(name);
    }
    return [...out].filter((r) => r.length <= MAX_CLIENT_DENY_RULE_LEN).slice(0, MAX_CLIENT_DENY_RULES);
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

  /** 处理单条来自独立网关的事件（消息写入或撤回删除）。 */
  async handleGatewayEvent(ev: GatewayEvent): Promise<void> {
    if (ev.kind === "delete") {
      this.store.deleteObs(`pw:${ev.message_id}`);
      return;
    }
    this.handleGatewayMessage(ev.message);
  }

  /** 将来自独立网关的归一化消息按 Avatar 业务层规则过滤并落库 `ctx_obs`。 */
  handleGatewayMessage(msg: GatewayMessagePayload): void {
    const obsId = `pw:${msg.id}`;
    const text = msg.text.trim();
    if (!text && msg.resources.length === 0) {
      this.store.deleteObs(obsId);
      return;
    }

    const ownerId = msg.ownerId || this.state.owner_id;
    const ownerName = this.app.store.get("ctx.owner_name") || msg.ownerName || this.state.owner_name || "我";
    const isMe = !!ownerId && msg.actorId === ownerId;
    const isHuman = msg.senderType === GATEWAY_USER_SENDER_TYPE;

    if (!isHuman && !this.botAllowed(text)) return;

    const chatName = msg.chatName.trim();
    if (this.isDeniedChat(msg.conversationId, chatName)) return;
    // 不知道会话名就无法核对按名称的排除/静音规则：宁可丢弃也不放行（每 10 分钟的飞书采集仍会按规则兜底）
    if (!chatName && this.hasNameBasedExclusions()) {
      log("warn", "个人 Web 网关消息缺少会话名，无法核对按名称的排除规则，已丢弃", { chat_id: msg.conversationId, message_id: msg.id });
      return;
    }

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
  private actorDisplayName(actorId: string, kind: GatewayMessagePayload["conversationKind"], chatName: string): string {
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

  /** 快通道理解前经网关只读接口补读该会话的历史背景消息（最多 15 条，标记为已处理背景）。 */
  async hydrateContext(anchor: FastAnchor, conv: string, convName: string, signal?: AbortSignal): Promise<number> {
    if (this.isDeniedChat(anchor.conversationId, convName)) return 0;
    const existing = this.store.convObs(conv, Date.now() - 24 * 3_600_000, 6);
    if (existing.length >= 5) return 0;
    let client: FeishuGatewayClient;
    try {
      client = this.getClient();
    } catch {
      return 0;
    }
    try {
      const resp = await client.readContext({ anchor, limit: 15 }, signal);
      if (resp.owner_id) {
        verifyGatewayOwnerForWorkspace(this.app, resp.owner_id);
      }
      if (!resp.messages.length) return 0;
      const ownerId = resp.owner_id || this.state.owner_id;
      const ownerName = this.app.store.get("ctx.owner_name") || resp.owner_name || this.state.owner_name || "我";
      const bg: Obs[] = resp.messages
        .filter((m) => m.id && m.text.trim() && !this.isDeniedChat(m.conversationId, m.chatName || convName))
        .map((m) => {
          const isMe = !!ownerId && m.actorId === ownerId;
          const displayConvName = m.chatName || convName;
          return {
            id: `pw:${m.id}`,
            source: "im",
            kind: m.senderType !== GATEWAY_USER_SENDER_TYPE ? "bot" : isMe ? "mine" : m.conversationKind === "dm" ? "p2p" : "group",
            conv,
            conv_name: displayConvName,
            actor_id: m.actorId,
            actor_name: isMe ? ownerName : this.actorDisplayName(m.actorId, m.conversationKind, displayConvName),
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
              sender_type: m.senderType === GATEWAY_USER_SENDER_TYPE ? "user" : "app",
              background: true,
            },
          };
        });
      return this.store.addBackgroundObs(bg);
    } catch (e) {
      log("warn", "快通道经网关补读会话背景失败（继续理解当前消息）", { conv, err: errMsg(e) });
      return 0;
    }
  }

  /**
   * 确认草稿后经独立网关发送个人 Web 回复：
   *   - 先在 Avatar 侧执行本地黑名单/静音与 send_replies 开关检查；
   *   - 委托给网关 POST /v1/replies（必须持有独立 reply_token），由网关侧持久化 sending / created / verified 状态机防跨进程重发；
   *   - 网关返回的永久性错误（permanent=true）直接映射为 PermanentEffectError，避免 10 次无谓重试。
   */
  async sendVerifiedReply(args: {
    chat_id: string;
    message_id: string;
    root_id?: string;
    text: string;
    cid: string;
  }): Promise<GatewayReplyResult> {
    const knownConvName = this.store.convObs(`pw_chat:${args.chat_id}`, 0, 1)[0]?.conv_name ?? "";
    if (this.isDeniedChat(args.chat_id, knownConvName)) {
      throw new PermanentEffectError(`目标会话「${knownConvName || args.chat_id}」已被排除或静音，拒绝发送个人 Web 回复`);
    }

    const startedKey = `${REPLY_STARTED_PREFIX}${args.cid}`;
    const alreadyStarted = !!this.app.store.get(startedKey);
    // 关闭 send_replies 后只允许“已发出、只差回读”的收尾：本地标记无法证明网关真的发过包，交给网关按投递记录判定，拒绝任何新发送
    const readbackOnly = !this.cfg.context.personal_web.send_replies;
    if (readbackOnly && !alreadyStarted) {
      throw new PermanentEffectError("未开启个人 Web 回复（需在配置中设置 context.personal_web.send_replies: true）");
    }

    let client: FeishuGatewayClient;
    try {
      client = this.getClient();
    } catch (err) {
      throw new PermanentEffectError(`个人 Web 网关客户端未就绪：${errMsg(err)}`, err);
    }

    const expectedOwner = (this.app.store.get(BOUND_OWNER_KV_KEY) ?? "").trim() || undefined;
    this.app.store.set(startedKey, String(Date.now()));
    try {
      const res = await client.sendReply({
        chat_id: args.chat_id,
        message_id: args.message_id,
        root_id: args.root_id,
        text: args.text,
        cid: args.cid,
        ...(expectedOwner ? { expected_owner_id: expectedOwner } : {}),
        ...(readbackOnly ? { readback_only: true } : {}),
        client_deny: this.clientDenyRules(),
      });
      this.app.store.db.prepare("DELETE FROM kv WHERE k = ?").run(startedKey);
      return res;
    } catch (err) {
      if (isDefinitePreSendGatewayError(err)) {
        this.app.store.db.prepare("DELETE FROM kv WHERE k = ?").run(startedKey);
      }
      if (err instanceof GatewayHttpError && err.permanent) {
        throw new PermanentEffectError(err.message, err);
      }
      throw err;
    }
  }
}

const PRE_SEND_GATEWAY_ERROR_CODES = new Set([
  "missing_reply_token",
  "unauthorized",
  "insufficient_scope",
  "reply_disabled",
  "chat_denied",
  "invalid_request",
  "text_too_large",
  "invalid_cid",
  "unusable_original",
  "needs_login",
  "account_mismatch",
  "gateway_connect_failed",
  "upstream_rejected",
]);

const PRE_SEND_NET_CODES = new Set(["ECONNREFUSED", "ENOENT", "EACCES", "ENOTFOUND"]);

/** 确定未向飞书发出消息的客户端/网关前置错误：允许清理本地 started 标记，避免热关闭 send_replies 被绕过。 */
function isDefinitePreSendGatewayError(err: unknown): boolean {
  if (err instanceof GatewayHttpError) return PRE_SEND_GATEWAY_ERROR_CODES.has(err.code);
  const code = (err as NodeJS.ErrnoException | undefined)?.code;
  return typeof code === "string" && PRE_SEND_NET_CODES.has(code);
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
