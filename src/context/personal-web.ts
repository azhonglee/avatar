import { createHash } from "node:crypto";
import fs from "node:fs";
import YAML from "yaml";
import type { App } from "../app.ts";
import type { CtxPersonalWebStatus } from "../api/types.ts";
import { ContextScopeConfigSchema } from "../config.ts";
import { extractOwnerOpenId } from "../lark.ts";
import type { Store } from "../store.ts";
import { deepFind, errMsg, log } from "../util.ts";
import {
  loadKnownOpenGroupNames,
  loadSpokenGroups,
  rememberOpenGroupName,
  selectEffectiveOpenGroups,
  type NativePollingExclusions,
} from "./connectors.ts";
import {
  CHAT_KIND_P2P,
  clearPendingCommitMarkerIfMatches,
  FeishuWebClient,
  GatewayError,
  isGroupChat,
  isUsableWebMessage,
  MessageNotFoundError,
  SessionNeedsLoginError,
  UnusableOriginalMessageError,
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
  /** 持久化编辑代际（仅在正文/状态真实变化时递增，重复推送不递增），确保编辑撤回再恢复原文仍触发新快通道作业 */
  rev_gen: number;
  anchor: FastAnchor;
  /** 防抖合并期间收到的所有去重锚点（覆盖同群不同话题的多次 @我） */
  anchors: FastAnchor[];
}

interface PersistedState {
  state: ListenerState;
  owner_id: string;
  owner_name: string;
  session_id?: string;
  cookie_version?: number;
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
  /** 防抖合并期间最长等待毫秒数（防止高频会话持续重置防抖计时器导致饿死），默认 max(debounce_ms * 4, 15000) */
  maxDebounceWaitMs?: number;
  /** 单会话防抖期内最多保留的去重锚点数，达到后立即冲刷，默认 20 */
  maxDebounceAnchors?: number;
}

const STATE_KV_KEY = "ctx.personal_web.state";
export const BOUND_OWNER_KV_KEY = "ctx.personal_web.bound_owner_id";
export const BOUND_WORKSPACE_OWNER_KV_KEY = "ctx.personal_web.bound_workspace_open_id";
export const PENDING_CRED_COMMIT_KV_KEY = "ctx.personal_web.pending_cred_commit";
export const REVOKED_AT_KV_KEY = "ctx.personal_web.revoked_at";
export const REVOKED_SESSIONS_KV_KEY = "ctx.personal_web.revoked_sessions";
export const ACTIVE_SESSION_KV_KEY = "ctx.personal_web.active_session_id";
export function pwSpokenGroupsKey(ownerId: string): string {
  return `ctx.pw_spoken_groups.${ownerId}`;
}

function loadRevokedSessionIds(store: Store): Set<string> {
  try {
    const arr = JSON.parse(store.get(REVOKED_SESSIONS_KV_KEY) ?? "[]");
    if (Array.isArray(arr)) return new Set(arr.filter((x): x is string => typeof x === "string" && !!x.trim()));
  } catch {
    // ignore
  }
  return new Set();
}

/**
 * 吊销当前工作区的个人 Web 会话：
 *   - 优先在共享 SQLite 中原子/顺序持久化工作区级吊销标记、黑名单 session_id 与 needs_login 状态，
 *     确保即使本地凭据目录只读、文件锁超时或常驻进程使用不同的 `PA_FEISHU_WEB_CRED_FILE`，监听、入库与 pw.reply 发送也会立刻中止；
 *   - 随后尽力清理当前进程解析到的本地凭据文件，并将文件清理异常作为 `fileError` 独立返回而非阻断吊销。
 */
export function revokeWorkspacePersonalWebSession(app: App): { fileRemoved: boolean; credFile: string; fileError?: string } {
  const loginStore = new WebLoginStore(app.cfg.dataDir);
  let existingOnDisk: WebLogin | undefined;
  if (!loginStore.isExternal) {
    try {
      existingOnDisk = loginStore.load();
    } catch {
      existingOnDisk = undefined;
    }
  }

  let revokedSet = new Set<string>();
  const db = app.store.db;
  // 在单个 SQLite BEGIN IMMEDIATE 事务中原子提交工作区级吊销标记与黑名单，避免与并发 web-login 交错写坏状态
  db.exec("BEGIN IMMEDIATE");
  try {
    const revokedIds = loadRevokedSessionIds(app.store);
    const addId = (sid: string | undefined) => {
      const clean = (sid ?? "").trim();
      if (clean) revokedIds.add(clean);
    };
    // 仅对当前工作区私有凭据文件将磁盘现有 session_id 纳入黑名单；
    // 外部共享 PA_FEISHU_WEB_CRED_FILE 可能归属其他工作区，严禁未经归属核实就将其 session_id 加入本工作区吊销集
    if (!loginStore.isExternal) {
      addId(existingOnDisk?.session_id);
    }
    addId(app.store.get(ACTIVE_SESSION_KV_KEY));
    try {
      const saved = JSON.parse(app.store.get(STATE_KV_KEY) ?? "null") as { session_id?: string } | null;
      addId(saved?.session_id);
    } catch {
      // ignore
    }

    let clearPending = false;
    try {
      const rawPending = (app.store.get(PENDING_CRED_COMMIT_KV_KEY) ?? "").trim();
      if (rawPending) {
        const parsed = JSON.parse(rawPending) as { file?: string; session_id?: string };
        addId(parsed.session_id);
        if (!parsed.file || parsed.file === loginStore.file) {
          clearPending = true;
        }
      }
    } catch {
      // ignore
    }

    const capped = [...revokedIds].slice(-50);
    revokedSet = new Set(capped);
    app.store.set(REVOKED_SESSIONS_KV_KEY, JSON.stringify(capped));
    app.store.set(REVOKED_AT_KV_KEY, String(Date.now()));
    app.store.set(ACTIVE_SESSION_KV_KEY, "");
    if (clearPending) {
      app.store.set(PENDING_CRED_COMMIT_KV_KEY, "");
    }
    app.store.set(
      STATE_KV_KEY,
      JSON.stringify({
        state: "needs_login",
        owner_id: "",
        owner_name: "",
        session_id: "",
        cookie_version: 0,
        since: Date.now(),
        last_message_at: null,
        last_error: "已手动登出",
      }),
    );
    db.exec("COMMIT");
  } catch (err) {
    try {
      db.exec("ROLLBACK");
    } catch {
      // ignore
    }
    throw err;
  }

  let fileRemoved = false;
  let fileError: string | undefined;
  try {
    const res = loginStore.clearIf((curRes, stagedRes) => {
      const workspaceStillRevoked = () =>
        !!(app.store.get(REVOKED_AT_KV_KEY) ?? "").trim() && !(app.store.get(ACTIVE_SESSION_KV_KEY) ?? "").trim();
      const shouldRemoveWorkspaceOwnedEntry = (entry: typeof curRes): boolean => {
        if (entry.status === "missing") return false;
        if (entry.status === "ok" && entry.login.session_id) {
          const activeNow = (app.store.get(ACTIVE_SESSION_KV_KEY) ?? "").trim();
          // 并发 web-login 刚刚在吊销后提交了新会话：绝不删除该新会话文件
          if (activeNow && activeNow === entry.login.session_id) return false;
          if (revokedSet.has(entry.login.session_id)) return true;
          return workspaceStillRevoked();
        }
        return workspaceStillRevoked();
      };
      const shouldRemoveMainFile = (entry: typeof curRes): boolean => {
        if (entry.status === "missing") return false;
        if (!loginStore.isExternal) {
          return shouldRemoveWorkspaceOwnedEntry(entry);
        }
        // 共享外部 PA_FEISHU_WEB_CRED_FILE：仅在能够解密且确认其 session_id 明确属于当前工作区（已记录在本工作区吊销集且未被并发重登取代）时才删除；
        // 其他工作区的活跃凭据或当前进程无法解密验证归属的共享文件一律保留，仅做本工作区 SQLite 局部吊销。
        if (entry.status !== "ok" || !entry.login.session_id) return false;
        const activeNow = (app.store.get(ACTIVE_SESSION_KV_KEY) ?? "").trim();
        if (activeNow && activeNow === entry.login.session_id) return false;
        return revokedSet.has(entry.login.session_id);
      };
      return {
        removeFile: shouldRemoveMainFile(curRes),
        // stagedFile 已按工作区 dataDir 哈希隔离（<file>.<wsTag>.staged），仅归属当前工作区
        removeStaged: shouldRemoveWorkspaceOwnedEntry(stagedRes),
      };
    });
    fileRemoved = res.fileRemoved;
  } catch (err) {
    fileError = errMsg(err);
  }
  return { fileRemoved, credFile: loginStore.file, ...(fileError ? { fileError } : {}) };
}

/**
 * 校验某份本地个人 Web 凭据在当前工作区是否仍被授权使用：
 *   - 工作区未被 web-logout 吊销（REVOKED_AT_KV_KEY 为空）；
 *   - 凭据 session_id 不在工作区已吊销会话集合内；
 *   - 若工作区已记录当前活跃会话代际（ACTIVE_SESSION_KV_KEY），凭据 session_id 必须与之匹配（防止跨文件旧会话继续监听/核验/回写 Cookie）；
 *   - 已显式绑定个人 Web 账号且与 login.owner_id、cfg.owner.open_id 一致。
 */
export function assertLoginAuthorizedForWorkspace(
  app: Pick<App, "cfg" | "store">,
  login: WebLogin,
): void {
  const revokedAt = (app.store.get(REVOKED_AT_KV_KEY) ?? "").trim();
  if (revokedAt) {
    throw new SessionNeedsLoginError(
      "当前工作区的个人 Web 会话已通过 `pa context web-logout` 吊销，请重新运行 `pa context web-login`",
    );
  }
  if (login.session_id && loadRevokedSessionIds(app.store).has(login.session_id)) {
    throw new SessionNeedsLoginError(
      `当前凭据文件的个人 Web 会话 (${login.session_id}) 已被吊销，请使用新凭据或重新运行 \`pa context web-login\``,
    );
  }
  const activeSession = (app.store.get(ACTIVE_SESSION_KV_KEY) ?? "").trim();
  if (activeSession && (login.session_id ?? "").trim() !== activeSession) {
    throw new SessionNeedsLoginError(
      `当前凭据文件的个人 Web 会话 (${login.session_id || "未标注"}) 已被更新的登录会话 (${activeSession}) 取代，请切换至最新凭据文件或重新运行 \`pa context web-login\``,
    );
  }
  const bound = (app.store.get(BOUND_OWNER_KV_KEY) ?? "").trim();
  if (!bound) {
    throw new SessionNeedsLoginError(
      "当前工作区尚未完成个人 Web 账号显式绑定（即使通过 PA_FEISHU_WEB_CRED_FILE 指向已有凭据也不得静默绑定），请运行 `pa context web-login` 完成确认绑定",
    );
  }
  if (bound !== login.owner_id) {
    throw new SessionNeedsLoginError(
      `个人 Web 凭据账号 (${login.owner_id}) 与当前工作区已绑定的账号 (${bound}) 不一致，请重新运行 pa context web-login`,
    );
  }
  const cfgWs = app.cfg.owner.open_id.trim();
  const boundWs = (app.store.get(BOUND_WORKSPACE_OWNER_KV_KEY) ?? "").trim();
  if (cfgWs !== boundWs) {
    throw new SessionNeedsLoginError(
      `当前 config.yaml 配置的主人 (${cfgWs || "未配置"}) 与个人 Web 凭据已绑定的工作区主人 (${boundWs || "未绑定"}) 不一致；为防私聊泄漏给错误主人，已中止启动，请清理数据目录或重新扫码绑定`,
    );
  }
}

/**
 * 检查当前数据目录是否已存在任何归属于旧主人的上下文状态（不仅限 `pw:*` 观测，还包含轮询私聊/群观测、事项、草稿、
 * 项目、知识、冲突、信号、上下文派单/卡片任务与历史审计）。更换工作区主人或更换绑定账号前必须确保上下文库干净。
 */
export function hasExistingOwnerContextState(app: App): boolean {
  const db = app.store.db;
  const hasTable = (name: string) =>
    !!db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(name);
  const nonEmpty = (table: string) => hasTable(table) && !!db.prepare(`SELECT 1 FROM ${table} LIMIT 1`).get();
  for (const tbl of [
    "ctx_obs",
    "ctx_project",
    "ctx_item",
    "ctx_knowledge",
    "ctx_update",
    "ctx_person",
    "ctx_conflict",
    "ctx_draft",
    "ctx_feedback",
    "ctx_mute_conv",
    "signals",
  ]) {
    if (nonEmpty(tbl)) return true;
  }
  if (hasTable("work")) {
    const ctxWork = db
      .prepare(
        `SELECT 1 FROM work
          WHERE kind = 'context'
             OR ref LIKE 'card:ctx-%'
             OR ref LIKE 'ctx-draft:%'
             OR (ref LIKE 'context:%' AND ref != 'context:pw-needs-login')
          LIMIT 1`,
      )
      .get();
    if (ctxWork) return true;
  }
  if (hasTable("audit")) {
    const ctxAudit = db.prepare("SELECT 1 FROM audit WHERE command LIKE 'context.%' LIMIT 1").get();
    if (ctxAudit) return true;
  }
  if (hasTable("kv")) {
    const ctxKv = db
      .prepare(
        `SELECT 1 FROM kv
          WHERE (k LIKE 'ctx.dispatch_owner.%' OR k LIKE 'ctx.dispatch_ref_owner.%' OR k IN ('ctx.spoken_groups', 'ctx.owner_name', 'ctx.last_error'))
            AND v != '' AND v != '{}'
          LIMIT 1`,
      )
      .get();
    if (ctxKv) return true;
  }
  return false;
}

export function saveWorkspaceBinding(store: Store, nativeOwnerId: string, workspaceOpenId: string): void {
  store.set(BOUND_OWNER_KV_KEY, nativeOwnerId);
  if (workspaceOpenId.trim()) {
    store.set(BOUND_WORKSPACE_OWNER_KV_KEY, workspaceOpenId.trim());
  }
}

/**
 * 判断当前 config.yaml 的 owner.open_id 是否与已绑定的个人 Web 工作区主人发生冲突：
 * 只要工作区曾绑定过个人 Web（BOUND_OWNER_KV_KEY 或 BOUND_WORKSPACE_OWNER_KV_KEY 非空）且与当前 cfg.owner.open_id 不一致，
 * 即必须阻断旧主人派生的视图（今天/项目/事项/草稿）与全部通知/卡片投递，防止旧主人的私聊摘要泄漏给新主人。
 */
export function hasWorkspaceOwnerMismatch(store: Store, cfgOwnerOpenId: string): boolean {
  const boundNative = (store.get(BOUND_OWNER_KV_KEY) ?? "").trim();
  const boundWs = (store.get(BOUND_WORKSPACE_OWNER_KV_KEY) ?? "").trim();
  if (!boundNative && !boundWs) return false;
  return boundWs !== cfgOwnerOpenId.trim();
}

/** 统一计算 pw.reply 幂等键（CID）与规范化正文哈希，供 effects / drafts / personal-web 共用（DRY） */
export function computePwReplyCid(params: {
  draft_id?: string;
  effect_id?: string;
  owner_id: string;
  chat_id: string;
  message_id: string;
  text: string;
}): { cid: string; normalizedText: string; textHash: string } {
  const normalizedText = params.text.replace(/\r\n/g, "\n").trim();
  const textHash = createHash("sha256").update(normalizedText).digest("hex");
  const revKey = params.draft_id
    ? `draft:${params.draft_id}:${params.owner_id}:${params.chat_id}:${params.message_id}:${normalizedText}`
    : `effect:${params.effect_id ?? ""}`;
  const cid = createHash("sha256").update(`avatar-pw\0${revKey}`).digest("hex").slice(0, 32);
  return { cid, normalizedText, textHash };
}

/**
 * 判断某份草稿对应的精确投递记录是否已在飞书创建（created / verified）而仅需回读校验或幂等确认：
 *   - 仅当 owner_id、chat_id、message_id 与 text_hash 全部完全匹配该草稿时返回 true；
 *   - 用于在 send_replies 关闭后仍允许对「已发包但上次未完成回读」的失败草稿执行只读核验恢复，而不放行任何新发送。
 */
export function isReadbackOnlyDelivery(
  store: Store,
  params: { draft_id: string; owner_id: string; chat_id: string; message_id: string; text: string },
): boolean {
  const { cid, textHash } = computePwReplyCid(params);
  const raw = store.get(`pw.delivery.${cid}`);
  if (!raw) return false;
  try {
    const rec = JSON.parse(raw) as Partial<DeliveryRecord>;
    return (
      (rec.state === "created" || rec.state === "verified") &&
      !!rec.reply_id &&
      rec.owner_id === params.owner_id &&
      rec.chat_id === params.chat_id &&
      rec.message_id === params.message_id &&
      rec.text_hash === textHash
    );
  } catch {
    return false;
  }
}

const ACTIVE_STATES = new Set<ListenerState>(["listening", "connecting", "reconnecting", "reverifying", "publication_blocked"]);
const DAY_MS = 86_400_000;
const OC_EXCLUSION_TTL_MS = 10 * 60_000;

/** 仅依据观测中记录的权威 chat_type / kind 区分群聊与私聊；绝不凭用户可见群名前缀（如“私聊xxx”）推断私聊类型 */
function classifyRecordedChatType(obs: Obs | undefined): "group" | "dm" | "unknown" {
  const t = String(obs?.meta.chat_type ?? "").trim().toLowerCase();
  if (t === "p2p") return "dm";
  if (t === "group" || t === "topic" || t === "topic_group") return "group";
  if (obs?.kind === "p2p") return "dm";
  if (obs?.kind === "group") return "group";
  return "unknown";
}

const MAX_DISK_CONFIG_BYTES = 2 * 1024 * 1024;

function readDiskConfigRaw(file: string): { exists: boolean; raw?: string; error?: string } {
  try {
    const st = fs.statSync(file);
    if (!st.isFile()) return { exists: false, error: `配置文件 ${file} 不是普通文件` };
    if (st.size > MAX_DISK_CONFIG_BYTES) return { exists: true, error: `配置文件 ${file} 体积超过安全上限` };
    return { exists: true, raw: fs.readFileSync(file, "utf8") };
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code;
    if (code === "ENOENT") return { exists: false };
    return { exists: true, error: `无法读取配置文件 ${file}：${errMsg(err)}` };
  }
}

/** 判断常驻进程心跳是否在 60 秒内活跃 */
export function isLiveDaemonHeartbeat(store: Pick<Store, "get">, now = Date.now()): boolean {
  const hb = store.get("daemon.heartbeat");
  if (!hb) return false;
  const ms = Number(hb.slice(hb.lastIndexOf("|") + 1));
  return Number.isFinite(ms) && now - ms < 60_000;
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
  private readonly debounceFirstAt = new Map<string, number>();
  private readonly ocExclusionCache = new Map<string, OpenChatExclusionMeta>();
  private readonly pwGroupNameCache = new Map<string, string>();
  private readonly hadInitialCfgFile: boolean;
  private lastSyncedCfgRaw: string | undefined;
  private diskPolicyError = "";
  private state: PersistedState;

  constructor(app: App, store: ContextStore, hooks: PersonalWebBridgeHooks) {
    this.app = app;
    this.store = store;
    this.hooks = hooks;
    this.loginStore = new WebLoginStore(app.cfg.dataDir);
    this.loginStore.reconcilePendingCommit(app.store, PENDING_CRED_COMMIT_KV_KEY);
    const initDisk = app.cfg.file ? readDiskConfigRaw(app.cfg.file) : { exists: false };
    this.hadInitialCfgFile = initDisk.exists;
    this.lastSyncedCfgRaw = initDisk.raw;
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

  /**
   * 同步检测并重载被外部进程修改的磁盘 `config.yaml` 隐私与采集策略（直接比对原始文本，避免粗粒度文件系统 mtime 漏检同毫秒/等长修改；未变时零 YAML 解析）：
   *   - 复用 `ContextScopeConfigSchema` 严格校验范围/排除列表与隐私开关；
   *   - 若磁盘配置文件被删、不可读或格式损坏，记录 `diskPolicyError` 并按 fail-closed 阻断推送入库与推理提交。
   */
  syncDiskPrivacyConfig(opts?: { throwOnError?: boolean }): boolean {
    const cfgFile = this.cfg.file;
    if (!cfgFile) return true;
    const disk = readDiskConfigRaw(cfgFile);
    if (!disk.exists && !this.hadInitialCfgFile) {
      return true;
    }
    if (disk.error || !disk.exists || disk.raw === undefined) {
      this.diskPolicyError = disk.error || `配置文件 ${cfgFile} 不存在或无法读取，按安全原则暂缓采集与理解`;
      this.lastSyncedCfgRaw = undefined;
      if (opts?.throwOnError) throw new Error(this.diskPolicyError);
      return false;
    }
    if (disk.raw === this.lastSyncedCfgRaw) {
      if (this.diskPolicyError) {
        if (opts?.throwOnError) throw new Error(this.diskPolicyError);
        return false;
      }
      return true;
    }
    try {
      const parsed = YAML.parse(disk.raw) as Record<string, unknown> | null;
      if (parsed !== null && (typeof parsed !== "object" || Array.isArray(parsed))) {
        throw new Error("配置文件根节点格式非法");
      }
      const root = (parsed ?? {}) as {
        owner?: { open_id?: unknown };
        context?: {
          understand?: unknown;
          sources?: { im?: unknown; minutes?: unknown; docs?: unknown };
          groups?: unknown;
          groups_allow?: unknown;
          groups_deny?: unknown;
          max_groups?: unknown;
          lookback_days?: unknown;
          bot_allow?: unknown;
          personal_web?: {
            enabled?: unknown;
            fast_lane?: unknown;
            pre_draft?: unknown;
            send_replies?: unknown;
          };
        };
      };
      if (root.owner !== undefined && (typeof root.owner !== "object" || root.owner === null || Array.isArray(root.owner))) {
        throw new Error("配置文件中的 owner 格式非法");
      }
      if (root.owner?.open_id !== undefined && typeof root.owner.open_id !== "string") {
        throw new Error("配置文件中的 owner.open_id 格式非法");
      }
      const ctx = root.context;
      if (ctx !== undefined && (typeof ctx !== "object" || ctx === null || Array.isArray(ctx))) {
        throw new Error("配置文件中的 context 格式非法");
      }
      const scopeParsed = ContextScopeConfigSchema.safeParse({
        lookback_days: ctx?.lookback_days,
        groups: ctx?.groups,
        groups_allow: ctx?.groups_allow,
        groups_deny: ctx?.groups_deny,
        max_groups: ctx?.max_groups,
      });
      if (!scopeParsed.success) {
        const badField = String(scopeParsed.error.issues[0]?.path[0] ?? "groups");
        throw new Error(`配置文件中的 context.${badField} 格式非法`);
      }
      const parseOptBool = (val: unknown, fallback: boolean, name: string): boolean => {
        if (val === undefined) return fallback;
        if (typeof val !== "boolean") throw new Error(`配置文件中的 ${name} 格式非法`);
        return val;
      };
      if (ctx?.sources !== undefined && (typeof ctx.sources !== "object" || ctx.sources === null || Array.isArray(ctx.sources))) {
        throw new Error("配置文件中的 context.sources 格式非法");
      }
      if (
        ctx?.personal_web !== undefined &&
        (typeof ctx.personal_web !== "object" || ctx.personal_web === null || Array.isArray(ctx.personal_web))
      ) {
        throw new Error("配置文件中的 context.personal_web 格式非法");
      }
      if (ctx?.bot_allow !== undefined && (!Array.isArray(ctx.bot_allow) || !ctx.bot_allow.every((x) => typeof x === "string"))) {
        throw new Error("配置文件中的 context.bot_allow 格式非法");
      }
      const nextUnderstand = parseOptBool(ctx?.understand, true, "context.understand");
      const nextIm = parseOptBool(ctx?.sources?.im, true, "context.sources.im");
      const nextMinutes = parseOptBool(ctx?.sources?.minutes, true, "context.sources.minutes");
      const nextDocs = parseOptBool(ctx?.sources?.docs, true, "context.sources.docs");
      const nextPwEnabled = parseOptBool(ctx?.personal_web?.enabled, false, "context.personal_web.enabled");
      const nextPwFast = parseOptBool(ctx?.personal_web?.fast_lane, true, "context.personal_web.fast_lane");
      const nextPwPreDraft = parseOptBool(ctx?.personal_web?.pre_draft, false, "context.personal_web.pre_draft");
      const nextPwSend = parseOptBool(ctx?.personal_web?.send_replies, false, "context.personal_web.send_replies");

      if (typeof root.owner?.open_id === "string") {
        this.cfg.owner.open_id = root.owner.open_id;
      }
      this.cfg.context.groups = scopeParsed.data.groups;
      this.cfg.context.groups_allow = scopeParsed.data.groups_allow;
      this.cfg.context.groups_deny = scopeParsed.data.groups_deny;
      this.cfg.context.max_groups = scopeParsed.data.max_groups;
      this.cfg.context.lookback_days = scopeParsed.data.lookback_days;
      this.cfg.context.understand = nextUnderstand;
      this.cfg.context.sources.im = nextIm;
      this.cfg.context.sources.minutes = nextMinutes;
      this.cfg.context.sources.docs = nextDocs;
      if (ctx?.bot_allow !== undefined) {
        this.cfg.context.bot_allow = ctx.bot_allow as string[];
      }
      this.cfg.context.personal_web.enabled = nextPwEnabled;
      this.cfg.context.personal_web.fast_lane = nextPwFast;
      this.cfg.context.personal_web.pre_draft = nextPwPreDraft;
      this.cfg.context.personal_web.send_replies = nextPwSend;
      this.diskPolicyError = "";
      this.lastSyncedCfgRaw = disk.raw;
      return true;
    } catch (err) {
      this.diskPolicyError = `无法核验磁盘隐私配置 (${cfgFile})：${errMsg(err)}`;
      this.lastSyncedCfgRaw = disk.raw;
      if (opts?.throwOnError) throw new Error(this.diskPolicyError);
      return false;
    }
  }

  hasDiskPolicyError(): boolean {
    return !this.syncDiskPrivacyConfig({ throwOnError: false });
  }

  /**
   * 当前工作区是否存在有效且与 config.owner.open_id 一致的个人 Web 账号绑定：
   *   - 必须已由 web-login 显式写入 BOUND_OWNER_KV_KEY；
   *   - 且 BOUND_WORKSPACE_OWNER_KV_KEY 必须与当前 config.yaml 中的 owner.open_id 完全一致。
   * 绑定缺失或工作区主人变更时返回 null（调用方必须彻底拦截全部 pw:* 观测，绝不退化为无过滤）。
   */
  activeBoundNativeOwner(): string | null {
    this.syncDiskPrivacyConfig({ throwOnError: false });
    const boundNative = (this.app.store.get(BOUND_OWNER_KV_KEY) ?? "").trim();
    if (!boundNative) return null;
    const cfgWs = this.cfg.owner.open_id.trim();
    const boundWs = (this.app.store.get(BOUND_WORKSPACE_OWNER_KV_KEY) ?? "").trim();
    if (cfgWs !== boundWs) return null;
    return boundNative;
  }

  /** 轻量同步策略签名（结构化 JSON 编码，杜绝分隔符碰撞；含静音表 + groups_deny + 有序 allowlist + 发言群榜单 + sources.im + 磁盘配置健康态 + 工作区主人绑定） */
  policySignature(): string {
    this.syncDiskPrivacyConfig({ throwOnError: false });
    const mutes = this.store
      .mutedConvs()
      .map((m) => [m.conv, m.name] as const)
      .sort((a, b) => a[0].localeCompare(b[0]) || a[1].localeCompare(b[1]));
    const deny = [...this.cfg.context.groups_deny].map((s) => s.trim()).sort();
    // 保留 groups_allow 顺序：在 max_groups 截断下，顺序变更会改变生效群集合
    const allow = this.cfg.context.groups_allow.map((s) => s.trim());
    const bound = (this.app.store.get(BOUND_OWNER_KV_KEY) ?? "").trim();
    const boundWs = (this.app.store.get(BOUND_WORKSPACE_OWNER_KV_KEY) ?? "").trim();
    const openSpoken = this.app.store.get("ctx.spoken_groups") ?? "";
    const openNames = this.app.store.get("ctx.open_group_names") ?? "";
    const pwSpoken = bound ? (this.app.store.get(pwSpokenGroupsKey(bound)) ?? "") : "";
    const pw = this.cfg.context.personal_web;
    return JSON.stringify([
      this.diskPolicyError ? `err:${this.diskPolicyError}` : "ok",
      this.cfg.context.sources.im ? 1 : 0,
      this.cfg.context.sources.minutes ? 1 : 0,
      this.cfg.context.sources.docs ? 1 : 0,
      this.cfg.context.understand ? 1 : 0,
      pw.enabled ? 1 : 0,
      pw.fast_lane ? 1 : 0,
      this.cfg.context.groups,
      this.cfg.context.max_groups,
      this.cfg.context.lookback_days,
      allow,
      deny,
      mutes,
      openSpoken,
      openNames,
      pwSpoken,
      bound,
      boundWs,
      this.cfg.owner.open_id.trim(),
    ]);
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
    return isLiveDaemonHeartbeat(this.app.store, now);
  }

  /**
   * 判断非常驻进程（如交互式 `pa brief` / `pa job` / `pa dispatch`）是否应将 `pw.reply` 留给持钥常驻进程执行：
   *   - 若该回复已完成 `verified` 投递，无需凭据即可幂等完结，返回 false；
   *   - 若本进程已有在线 Web 客户端或能直接解密本地凭据，返回 false（可本地执行）；
   *   - 若本地缺少解密密钥（`missing_key`）或默认路径缺失文件但常驻进程在线（`missing` + 活跃心跳），
   *     返回 true，避免无密钥的交互式命令误领并消耗重试次数。
   */
  shouldDeferReplyToCredentialedConsumer(cid?: string): boolean {
    if (cid && this.loadDelivery(cid)?.state === "verified") return false;
    if (this.client) return false;
    this.loginStore.reconcilePendingCommit(this.app.store, PENDING_CRED_COMMIT_KV_KEY);
    const inspected = this.loginStore.inspect();
    if (inspected.status === "ok") return false;
    if (inspected.status === "missing_key") return true;
    if (inspected.status === "missing" && isLiveDaemonHeartbeat(this.app.store)) return true;
    return false;
  }

  status(now = Date.now()): CtxPersonalWebStatus {
    this.loginStore.reconcilePendingCommit(this.app.store, PENDING_CRED_COMMIT_KV_KEY);
    const inspected = this.loginStore.inspect();
    const login = inspected.status === "ok" ? inspected.login : undefined;
    const saved = this.loadSavedState() ?? this.state;
    const enabled = this.cfg.context.personal_web.enabled;
    const daemonLive = this.isDaemonLive(now);
    const localKeyMissing = inspected.status === "missing_key";
    const localCredUnavailable = inspected.status === "missing_key" || inspected.status === "missing";
    const revokedAt = (this.app.store.get(REVOKED_AT_KV_KEY) ?? "").trim();
    const revokedSessions = loadRevokedSessionIds(this.app.store);
    const activeSession = (this.app.store.get(ACTIVE_SESSION_KV_KEY) ?? "").trim();
    const boundNative = (this.app.store.get(BOUND_OWNER_KV_KEY) ?? "").trim();
    const boundWs = (this.app.store.get(BOUND_WORKSPACE_OWNER_KV_KEY) ?? "").trim();
    const cfgWs = this.cfg.owner.open_id.trim();
    const ownerMismatch = hasWorkspaceOwnerMismatch(this.app.store, cfgWs);

    let loginAuthorized = false;
    let loginAuthErr = "";
    if (login) {
      try {
        assertLoginAuthorizedForWorkspace(this.app, login);
        loginAuthorized = true;
      } catch (err) {
        loginAuthErr = errMsg(err);
      }
    }

    const savedSessionRevoked = !!revokedAt || (!!saved.session_id && revokedSessions.has(saved.session_id));
    const savedSessionSuperseded = !!activeSession && !!saved.session_id && saved.session_id !== activeSession;
    const savedOwnerMatches =
      !!saved.owner_id &&
      (!boundNative || saved.owner_id === boundNative) &&
      (!boundWs || boundWs === cfgWs) &&
      !ownerMismatch;

    // 若交互式 shell 未注入 systemd 凭据密钥（missing_key）或使用默认路径找不到 systemd 的自定义凭据文件（missing），
    // 但常驻进程本身在线且持有未吊销、未过期的有效会话，将常驻运行态与本地文件可读性分开判断，避免把在线 listening 误报成 needs_login
    const daemonHealthyWithoutLocalCred =
      !revokedAt &&
      !savedSessionRevoked &&
      !savedSessionSuperseded &&
      savedOwnerMatches &&
      localCredUnavailable &&
      daemonLive &&
      saved.state !== "needs_login";
    const staleSavedSession =
      loginAuthorized &&
      saved.state === "needs_login" &&
      ((!!login?.session_id && saved.session_id !== login.session_id) ||
        (!!saved.owner_id && saved.owner_id !== login?.owner_id) ||
        (typeof saved.cookie_version === "number" && (login?.cookie_version ?? 1) > saved.cookie_version));
    // 当前凭据文件的同一会话与 Cookie 版本已被服务端拒绝（saved.state === "needs_login"）：
    // 状态接口必须如实返回 logged_in: false，而非同时报 logged_in: true 与 needs_login；
    // 若磁盘已更换更新会话/更高 cookie_version（staleSavedSession），则仍按有效新登录放行。
    const currentSessionRejected =
      loginAuthorized &&
      saved.state === "needs_login" &&
      !staleSavedSession &&
      (!!saved.session_id || !!saved.owner_id);
    const loggedIn = (loginAuthorized && !currentSessionRejected) || daemonHealthyWithoutLocalCred;

    let state: string = staleSavedSession ? "stopped" : saved.state;
    let lastError = staleSavedSession ? "" : saved.last_error;
    if (!enabled) {
      state = "idle";
      lastError = "";
    } else if (!loggedIn) {
      state = "needs_login";
      if (revokedAt && !lastError) {
        lastError = "已手动登出";
      } else if (loginAuthErr && !lastError) {
        lastError = loginAuthErr;
      } else if (localKeyMissing && !lastError) {
        lastError = "当前环境缺少解密密钥（PA_FEISHU_WEB_KEY 或 CREDENTIALS_DIRECTORY/feishu-web-key）";
      }
    } else if (ACTIVE_STATES.has(state as ListenerState) && !daemonLive) {
      state = "stopped";
    }
    return {
      enabled,
      logged_in: loggedIn,
      state,
      owner_id: (loggedIn && loginAuthorized ? login?.owner_id : "") || (loggedIn ? saved.owner_id : ""),
      owner_name: (loggedIn && loginAuthorized ? login?.owner_name : "") || (loggedIn ? saved.owner_name : ""),
      last_message_at: saved.last_message_at,
      last_error: lastError,
    };
  }

  /** 启动个人 Web 长连接监听（异步后台运行，不阻塞常驻进程启动；所有内部异常均在守护边界内消化退避，绝不产生未捕获拒绝拖垮主进程）。 */
  start(): { stop(): void } {
    if (!this.cfg.context.personal_web.enabled) return { stop: () => undefined };
    try {
      this.loginStore.reconcilePendingCommit(this.app.store, PENDING_CRED_COMMIT_KV_KEY);
    } catch (err) {
      log("warn", "启动个人 Web 通道时恢复暂存凭据失败（将在守护循环中重试）", { err: errMsg(err) });
    }
    this.stop();
    const ctrl = new AbortController();
    this.stopCtrl = ctrl;
    void this.runSupervisor(ctrl.signal).catch((err) => {
      if (!ctrl.signal.aborted) {
        log("error", "个人 Web 监听守护循环异常退出（已隔离，不影响常驻进程）", { err: errMsg(err) });
      }
    });
    return { stop: () => this.stop() };
  }

  stop(): void {
    this.stopCtrl?.abort();
    this.stopCtrl = undefined;
    this.client = undefined;
    for (const timer of this.debounceTimers.values()) clearTimeout(timer);
    this.debounceTimers.clear();
    this.debouncedAnchors.clear();
    this.debounceFirstAt.clear();
  }

  private validateBoundOwner(login: WebLogin): void {
    assertLoginAuthorizedForWorkspace(this.app, login);
  }

  /** 失败休眠后的唤醒键：结构化 JSON 编码，包含 cookie_version、updated_at、吊销状态与当前活跃会话代际（与活跃长连接的 sessionKeyOf 分离） */
  private credentialWatchKey(login: WebLogin | undefined): string {
    const bound = this.app.store.get(BOUND_OWNER_KV_KEY) ?? "";
    const boundWs = this.app.store.get(BOUND_WORKSPACE_OWNER_KV_KEY) ?? "";
    const revoked = this.app.store.get(REVOKED_AT_KV_KEY) ?? "";
    const active = this.app.store.get(ACTIVE_SESSION_KV_KEY) ?? "";
    if (!login) return JSON.stringify(["none", bound, boundWs, revoked, active]);
    return JSON.stringify([
      login.owner_id,
      login.session_id ?? "",
      login.cookie_version ?? 1,
      login.updated_at ?? "",
      bound,
      boundWs,
      revoked,
      active,
    ]);
  }

  /** 活跃长连接的会话代际键（仅含账号与 session_id，不因同会话 Cookie 轮换主动断开健康长连接） */
  private sessionKeyOf(login: WebLogin | undefined): string {
    if (!login) return "";
    return `${login.owner_id}:${login.session_id ?? ""}`;
  }

  /** 阻塞等待直到磁盘凭据（含同会话 Cookie 修订与未完成暂存提交恢复）或工作区账号绑定发生变化，或收到中止信号 */
  private async waitForCredentialChange(lastFailedStateKey: string, signal: AbortSignal): Promise<void> {
    const interval = this.hooks.credentialWatchIntervalMs ?? 5_000;
    const checkChanged = (): boolean => {
      try {
        this.loginStore.reconcilePendingCommit(this.app.store, PENDING_CRED_COMMIT_KV_KEY);
        const cur = this.loginStore.load();
        return !!cur && this.credentialWatchKey(cur) !== lastFailedStateKey;
      } catch (err) {
        log("warn", "等待个人 Web 凭据变更时读取状态失败（将在下个轮询周期重试）", { err: errMsg(err) });
        return false;
      }
    };
    if (checkChanged()) return;
    while (!signal.aborted) {
      await waitAbortable(interval, signal);
      if (signal.aborted) return;
      if (checkChanged()) return;
    }
  }

  private async runSupervisor(signal: AbortSignal): Promise<void> {
    let connectDelayMs = 2_000;
    let supervisorErrDelayMs = 2_000;
    let connectDenials = 0;
    let lastAttemptedKey = "";
    let wasDegraded = false;
    let everConnected = false;
    const watchInterval = this.hooks.credentialWatchIntervalMs ?? 5_000;

    const handleState = (next: ListenerState, detail = "", notifyLogin = true, sessionIdOverride?: string) => {
      try {
        if (next === "reconnecting" || next === "reverifying") wasDegraded = true;
        if (next === "listening") {
          if (wasDegraded && everConnected) {
            wasDegraded = false;
            try {
              this.hooks.onReconnect();
            } catch (err) {
              log("warn", "个人 Web 重连补扫回调失败", { err: errMsg(err) });
            }
          }
          everConnected = true;
        }
        const disk = this.loginStore.load();
        this.persistState({
          state: next,
          owner_id: this.client?.owner().id ?? disk?.owner_id ?? "",
          owner_name: this.client?.owner().name ?? disk?.owner_name ?? "",
          session_id: sessionIdOverride ?? this.client?.currentSessionId() ?? disk?.session_id ?? "",
          cookie_version: this.client?.currentCookieVersion() ?? disk?.cookie_version ?? 0,
          since: Date.now(),
          last_error: next === "listening" || next === "stopped" ? "" : detail,
        });
        if (next === "needs_login" && notifyLogin) {
          this.hooks.onNeedsLogin(detail || "个人 Web 会话已失效，请重新扫码登录");
        }
      } catch (err) {
        log("warn", "更新个人 Web 监听状态或发送登录提醒失败（守护循环将继续运行）", { next, err: errMsg(err) });
      }
    };

    while (!signal.aborted) {
      try {
        this.loginStore.reconcilePendingCommit(this.app.store, PENDING_CRED_COMMIT_KV_KEY);
        const inspected = this.loginStore.inspect();
        const login = inspected.status === "ok" ? inspected.login : undefined;
        if (!login) {
          lastAttemptedKey = "";
          connectDenials = 0;
          connectDelayMs = 2_000;
          const msg =
            inspected.status === "missing_key"
              ? "检测到已加密的个人 Web 凭据，但当前环境缺少解密密钥（PA_FEISHU_WEB_KEY 或 CREDENTIALS_DIRECTORY/feishu-web-key）"
              : inspected.status === "plaintext_rejected"
                ? "检测到未加密的明文个人 Web 凭据（已拒绝加载），请配置加密密钥后重新运行 `pa context web-login`"
                : "尚未完成个人 Web 扫码登录，请运行 `pa context web-login`";
          handleState("needs_login", msg, false, "");
          log("warn", "个人 Web 通道等待有效凭据", { file: this.loginStore.file, status: inspected.status });
          await this.waitForCredentialChange(this.credentialWatchKey(undefined), signal);
          supervisorErrDelayMs = 2_000;
          continue;
        }

        const activeSessionKey = this.sessionKeyOf(login);
        let lastObservedWatchKey = this.credentialWatchKey(login);
        if (lastObservedWatchKey !== lastAttemptedKey) {
          connectDenials = 0;
          connectDelayMs = 2_000;
          lastAttemptedKey = lastObservedWatchKey;
        }
        try {
          this.validateBoundOwner(login);
        } catch (err) {
          const msg = errMsg(err);
          handleState("needs_login", msg, true, login.session_id ?? "");
          await this.waitForCredentialChange(lastObservedWatchKey, signal);
          supervisorErrDelayMs = 2_000;
          continue;
        }

        const sessionCtrl = new AbortController();
        const onOuterAbort = () => sessionCtrl.abort();
        signal.addEventListener("abort", onOuterAbort, { once: true });
        let invalidatedByDisk = false;
        const credWatcher = setInterval(() => {
          try {
            this.loginStore.reconcilePendingCommit(this.app.store, PENDING_CRED_COMMIT_KV_KEY);
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
              lastObservedWatchKey = this.credentialWatchKey(latest);
              lastAttemptedKey = lastObservedWatchKey;
            }
          } catch (err) {
            log("warn", "个人 Web 凭据定时检查失败（下个周期重试）", { err: errMsg(err) });
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
                try {
                  this.validateBoundOwner(updated);
                } catch {
                  invalidatedByDisk = true;
                  sessionCtrl.abort();
                  return null;
                }
                const saved = this.loginStore.saveIfSessionMatches(updated, delta);
                if (!saved) {
                  invalidatedByDisk = true;
                  sessionCtrl.abort();
                  return null;
                }
                // 本进程自身落盘的 Cookie 轮换同步更新 lastAttemptedKey，避免下轮误判为外部新凭据而清零 connectDenials
                lastObservedWatchKey = this.credentialWatchKey(saved);
                lastAttemptedKey = lastObservedWatchKey;
                try {
                  if (saved.owner_name && !this.app.store.get("ctx.owner_name")) {
                    this.app.store.set("ctx.owner_name", saved.owner_name);
                  }
                } catch {
                  // best-effort owner name cache
                }
                return saved;
              },
            },
            sessionCtrl.signal,
          );
          if (invalidatedByDisk || sessionCtrl.signal.aborted) continue;

          this.client = client;
          // 严禁在常驻监听中静默创建或修改工作区账号绑定（仅允许经 pa context web-login 人工确认后绑定）
          connectDelayMs = 2_000;
          supervisorErrDelayMs = 2_000;
          connectDenials = 0;
          try {
            if (client.owner().name && !this.app.store.get("ctx.owner_name")) {
              this.app.store.set("ctx.owner_name", client.owner().name);
            }
          } catch {
            // best-effort owner name cache
          }
          log("info", "个人 Web 通道已连接", { owner_id: client.owner().id, owner_name: client.owner().name });

          await client.listen({
            signal: sessionCtrl.signal,
            onMessage: (msg) => this.handleMessage(msg, client, sessionCtrl.signal),
            shouldDeliverInvalid: (msg) => {
              if (!msg.id) return false;
              const existing = this.store.obs(`pw:${msg.id}`);
              return !!existing && existing.meta.withdrawn !== true;
            },
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
            await this.waitForCredentialChange(lastObservedWatchKey, signal);
            connectDenials = 0;
            connectDelayMs = 2_000;
            continue;
          }
          if (err instanceof WebHttpError && err.code === "credential_denied") {
            connectDenials++;
            if (connectDenials >= 3) {
              handleState("needs_login", msg, true, login.session_id ?? "");
              await this.waitForCredentialChange(lastObservedWatchKey, signal);
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
        supervisorErrDelayMs = 2_000;
      } catch (outerErr) {
        if (signal.aborted) break;
        this.client = undefined;
        log("warn", "个人 Web 守护循环发生未预期异常，退避重试", { err: errMsg(outerErr), delayMs: supervisorErrDelayMs });
        await waitAbortable(supervisorErrDelayMs, signal);
        supervisorErrDelayMs = Math.min(supervisorErrDelayMs * 2, 30_000);
      }
    }
    try {
      this.persistState({ state: "stopped", since: Date.now(), last_error: "" });
    } catch {
      // ignore stop-time persistence failure
    }
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
      const rawMode = String(deepFind(res, "chat_mode") ?? deepFind(res, "chat_type") ?? "").trim().toLowerCase();
      // 仅凭明确识别的 chat_mode/chat_type 归类，绝不因展示名非空就将未知会话误判为 group 从而放行私聊
      const chatType: OpenChatExclusionMeta["chatType"] =
        rawMode === "p2p"
          ? "p2p"
          : rawMode === "group" || rawMode === "topic" || rawMode === "topic_group"
            ? "group"
            : "unknown";
      const meta: OpenChatExclusionMeta = {
        name: rawName,
        chatType,
        expiresAt: now + OC_EXCLUSION_TTL_MS,
      };
      this.ocExclusionCache.set(ocId, meta);
      if (meta.chatType === "group" && meta.name) {
        rememberOpenGroupName(this.app.store, ocId, meta.name);
      }
      return { meta, fromCache: false };
    } catch {
      return undefined;
    }
  }

  private collectOpenChatExclusions(groupsDeny: string[] = this.cfg.context.groups_deny): Map<string, string> {
    const map = new Map<string, string>();
    for (const raw of groupsDeny) {
      const d = raw.trim();
      if (d.startsWith("oc_")) map.set(d, "");
    }
    for (const m of this.store.mutedConvs()) {
      if (m.conv.startsWith("oc_")) map.set(m.conv, m.name || map.get(m.conv) || "");
    }
    return map;
  }

  private openChatExclusionsKey(): string {
    return JSON.stringify([...this.collectOpenChatExclusions().keys()].sort());
  }

  /** 原生推送入库/发送期间需监测的完整排除策略快照（结构化 JSON 编码，杜绝分隔符碰撞；含 oc_* 排除规则、本地静音集合、全部 groups_deny 规则与磁盘配置健康态） */
  private nativeExclusionPolicyKey(groupsDeny?: string[]): string {
    this.syncDiskPrivacyConfig({ throwOnError: false });
    const effectiveDeny = groupsDeny ?? this.cfg.context.groups_deny;
    const oc = [...this.collectOpenChatExclusions(effectiveDeny).entries()]
      .sort((a, b) => a[0].localeCompare(b[0]) || a[1].localeCompare(b[1]));
    const mutes = this.store
      .mutedConvs()
      .map((m) => [m.conv, m.name] as const)
      .sort((a, b) => a[0].localeCompare(b[0]) || a[1].localeCompare(b[1]));
    const deny = [...effectiveDeny].map((s) => s.trim()).sort();
    return JSON.stringify([this.diskPolicyError ? `err:${this.diskPolicyError}` : "ok", oc, mutes, deny]);
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

  private nameDenyPatterns(groupsDeny: string[] = this.cfg.context.groups_deny): string[] {
    return groupsDeny
      .map((d) => d.trim())
      .filter((d) => d && !d.startsWith("oc_") && !d.startsWith("pw_chat:"));
  }

  private matchesDirectNativeIdDeny(pwConv: string, groupsDeny: string[] = this.cfg.context.groups_deny): boolean {
    return groupsDeny.some((raw) => raw.trim() === pwConv);
  }

  /** 收集已确认的开放平台群排除名称（来自 ocExclusionCache、ctx_mute_conv 标签、open_group_names 与 spoken_groups），供原生群排位截断前剔除 */
  private confirmedOpenGroupDenyNames(groupsDeny: string[] = this.cfg.context.groups_deny): Set<string> {
    const out = new Set<string>();
    const ocRules = this.collectOpenChatExclusions(groupsDeny);
    if (ocRules.size === 0) return out;
    const now = Date.now();
    const knownNames = loadKnownOpenGroupNames(this.app.store);
    const spoken = loadSpokenGroups(this.app.store);
    for (const [ocId, muteLabel] of ocRules) {
      const cached = this.ocExclusionCache.get(ocId);
      if (cached && cached.expiresAt > now) {
        if (cached.chatType === "p2p") continue;
        if (cached.name) out.add(norm(cached.name));
        continue;
      }
      const latest = this.store.latestConvObs(ocId);
      const recordedType = classifyRecordedChatType(latest);
      if (recordedType === "dm") continue;
      const authoritativeGroupName = (
        knownNames[ocId] ||
        spoken[ocId]?.name ||
        (recordedType === "group" ? (latest?.conv_name ?? "") : "")
      ).trim();
      const untypedMuteLabel = muteLabel.trim();
      const name =
        (authoritativeGroupName && authoritativeGroupName !== "群聊" ? authoritativeGroupName : "") ||
        (untypedMuteLabel && untypedMuteLabel !== "群聊" && untypedMuteLabel !== "私聊" && !/^私聊[:：]/.test(untypedMuteLabel)
          ? untypedMuteLabel
          : "");
      if (name) {
        out.add(norm(name));
      }
    }
    return out;
  }

  private isDirectlyDenied(
    pwConv: string,
    chatName: string,
    confirmedOcDenyNames?: Set<string>,
    kind: "group" | "dm" = "group",
    groupsDeny: string[] = this.cfg.context.groups_deny,
  ): boolean {
    const rawId = pwConv.startsWith("pw_chat:") ? pwConv.slice("pw_chat:".length) : pwConv;
    if (this.store.isConvMutedById(pwConv) || this.store.isConvMutedById(rawId)) return true;
    if (this.matchesDirectNativeIdDeny(pwConv, groupsDeny)) return true;
    if (chatName) {
      const patterns = this.nameDenyPatterns(groupsDeny);
      const dmFormatted = kind === "dm" && !chatName.startsWith("私聊：") ? `私聊：${chatName}` : chatName;
      if (patterns.some((d) => chatName.includes(d) || dmFormatted.includes(d))) return true;
    }
    if (kind !== "dm" && chatName) {
      const ocDeny = confirmedOcDenyNames ?? this.confirmedOpenGroupDenyNames(groupsDeny);
      if (ocDeny.has(norm(chatName))) return true;
    }
    return false;
  }

  /**
   * 评估当前个人 Web 会话是否命中排除/静音规则：
   *   - 返回 `{ excluded: true, verifiedChatName }`：明确命中排除，应丢弃；
   *   - 返回 `{ excluded: false, verifiedChatName }`：确认未命中排除，允许继续（携带最新核验过的群/私聊展示名供提交前终检使用）；
   *   - 抛错：存在无法实时确认的排除规则，按 fail-closed 暂缓入库（不发 ACK）。
   * 当存在关键词或 oc_* 排除且群名/私聊对方展示名来自缓存或缺失时，强制实时刷新再判定，
   * 既防止改名命中规则或私聊裸数字 ID 逃逸，也防止改名脱离规则后永久卡死。
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
    groupsDeny?: string[];
  }): Promise<{ excluded: boolean; verifiedChatName: string }> {
    const { chatId, pwConv, kind, convName, activeClient, signal } = params;
    const groupsDeny = params.groupsDeny ?? this.cfg.context.groups_deny;
    let chatName = params.chatName;
    let chatNameRefreshed = !params.chatNameFromCache;

    if (this.store.isConvMutedById(pwConv) || this.store.isConvMutedById(chatId)) {
      return { excluded: true, verifiedChatName: chatName };
    }
    if (this.matchesDirectNativeIdDeny(pwConv, groupsDeny)) {
      return { excluded: true, verifiedChatName: chatName };
    }

    const ensureFreshChatName = async (reason: string): Promise<void> => {
      if (chatNameRefreshed && chatName) return;
      if (!activeClient) {
        throw new Error(
          `无在线个人 Web 客户端，无法实时刷新${kind === "dm" ? "私聊对方展示名" : "群名称"}以核验${reason}，按 fail-closed 暂缓入库`,
        );
      }
      try {
        chatName = (await activeClient.readChat(chatId, { force: true, signal })).name.trim();
        chatNameRefreshed = true;
        if (kind === "group" && chatName) this.pwGroupNameCache.set(pwConv, chatName);
      } catch {
        throw new Error(
          `实时刷新${kind === "dm" ? "私聊对方展示名" : "群名称"}失败，无法核验${reason}，按 fail-closed 暂缓入库`,
        );
      }
      if (!chatName) {
        throw new Error(
          `${kind === "dm" ? "个人 Web 私聊未返回对方展示名" : "群名称为空"}，无法核验${reason}，按 fail-closed 暂缓入库`,
        );
      }
    };

    const nameRules = this.nameDenyPatterns(groupsDeny);
    if (nameRules.length > 0) {
      if (kind === "group") {
        const staleMatched = !!chatName && nameRules.some((d) => chatName.includes(d));
        if (!chatNameRefreshed && activeClient) {
          try {
            await ensureFreshChatName("groups_deny 关键词排除规则");
          } catch (err) {
            if (staleMatched) return { excluded: true, verifiedChatName: chatName };
            throw err;
          }
        } else if (staleMatched) {
          return { excluded: true, verifiedChatName: chatName };
        } else {
          await ensureFreshChatName("groups_deny 关键词排除规则");
        }
        if (nameRules.some((d) => chatName.includes(d))) {
          return { excluded: true, verifiedChatName: chatName };
        }
      } else {
        // 原生私聊默认 convName 仅含数字 actorId/chatId：存在 groups_deny 名称规则时必须实时解析对方展示名，
        // 无法解析时按 fail-closed 暂缓入库/理解（绝不让按姓名排除的同事私聊经个人 Web 漏入快通道模型）
        const staleLabels = [chatName, convName].filter(Boolean);
        const staleMatched = staleLabels.some((lbl) => nameRules.some((d) => lbl.includes(d)));
        if (!chatNameRefreshed && activeClient) {
          try {
            await ensureFreshChatName("groups_deny 关键词排除规则");
          } catch (err) {
            if (staleMatched) return { excluded: true, verifiedChatName: chatName };
            throw err;
          }
        } else if (staleMatched) {
          return { excluded: true, verifiedChatName: chatName };
        } else {
          await ensureFreshChatName("groups_deny 关键词排除规则");
        }
        const dmFormatted = chatName.startsWith("私聊：") ? chatName : `私聊：${chatName}`;
        if (nameRules.some((d) => chatName.includes(d) || dmFormatted.includes(d))) {
          return { excluded: true, verifiedChatName: chatName };
        }
      }
    }

    const ocRules = this.collectOpenChatExclusions(groupsDeny);
    if (ocRules.size === 0) return { excluded: false, verifiedChatName: chatName };
    for (const [ocId, staleLabel] of ocRules) {
      let resolved = await this.resolveOpenChatMeta(ocId);
      if (!resolved) {
        if (kind === "group" && chatName && staleLabel && norm(chatName) === norm(staleLabel)) {
          return { excluded: true, verifiedChatName: chatName };
        }
        throw new Error(`无法实时解析排除规则 ${ocId} 的会话元数据，按 fail-closed 暂缓入库`);
      }
      if (kind === "group") {
        if (resolved.meta.chatType === "p2p") continue;
        if (resolved.meta.chatType === "unknown") {
          if (chatName && resolved.meta.name && norm(chatName) === norm(resolved.meta.name)) {
            return { excluded: true, verifiedChatName: chatName };
          }
          throw new Error(`排除规则 ${ocId} 无法识别会话类型，按 fail-closed 暂缓入库`);
        }
        if (!resolved.meta.name) {
          throw new Error(`排除规则 ${ocId} 缺少群名称，无法与当前个人 Web 群聊区分，按 fail-closed 暂缓入库`);
        }
        const staleOcMatched = !!chatName && norm(chatName) === norm(resolved.meta.name);
        if (resolved.fromCache || !chatNameRefreshed || !chatName) {
          if (resolved.fromCache) {
            const freshOc = await this.resolveOpenChatMeta(ocId, { force: true });
            if (!freshOc) {
              if (staleOcMatched) return { excluded: true, verifiedChatName: chatName };
              throw new Error(`复核排除规则 ${ocId} 失败，按 fail-closed 暂缓入库`);
            }
            resolved = freshOc;
            if (resolved.meta.chatType === "p2p") continue;
            if (resolved.meta.chatType === "unknown") {
              if (chatName && resolved.meta.name && norm(chatName) === norm(resolved.meta.name)) {
                return { excluded: true, verifiedChatName: chatName };
              }
              throw new Error(`排除规则 ${ocId} 无法识别会话类型，按 fail-closed 暂缓入库`);
            }
            if (!resolved.meta.name) {
              throw new Error(`排除规则 ${ocId} 缺少群名称，无法与当前个人 Web 群聊区分，按 fail-closed 暂缓入库`);
            }
          }
          try {
            await ensureFreshChatName(`排除规则 ${ocId}`);
          } catch (err) {
            if (staleOcMatched) return { excluded: true, verifiedChatName: chatName };
            throw err;
          }
          if (nameRules.length > 0 && nameRules.some((d) => chatName.includes(d))) {
            return { excluded: true, verifiedChatName: chatName };
          }
          if (norm(chatName) === norm(resolved.meta.name)) {
            return { excluded: true, verifiedChatName: chatName };
          }
        } else if (staleOcMatched) {
          return { excluded: true, verifiedChatName: chatName };
        }
      } else {
        if (resolved.meta.chatType === "group") continue;
        throw new Error(`存在开放平台私聊或未知类型排除规则 (${ocId})，个人 Web 私聊无法映射其 open chat_id，按 fail-closed 暂缓入库`);
      }
    }
    return { excluded: false, verifiedChatName: chatName };
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
      const recordedType = classifyRecordedChatType(latest);
      const rawStale = (muteName || latest?.conv_name || "").trim();
      const staleGroupName =
        rawStale &&
        !/^群聊\(\d+\)$/.test(rawStale) &&
        rawStale !== "群聊" &&
        (recordedType === "group" || (recordedType !== "dm" && rawStale !== "私聊" && !/^私聊[:：]/.test(rawStale)))
          ? rawStale
          : "";

      if (client) {
        try {
          const meta = await client.readChat(nativeId, { force: true });
          if (meta.kind === CHAT_KIND_P2P) {
            dmsInconclusive = true;
          } else if (isGroupChat(meta.kind)) {
            if (meta.name.trim()) {
              confirmedGroupNames.add(norm(meta.name.trim()));
            } else {
              groupsInconclusive = true;
            }
          } else {
            // 未知或未识别的原生会话类型：不能仅凭非空名称当作群聊，必须对群与私聊双路按 inconclusive 暂缓
            if (meta.name.trim()) confirmedGroupNames.add(norm(meta.name.trim()));
            groupsInconclusive = true;
            dmsInconclusive = true;
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
    if (!this.syncDiskPrivacyConfig({ throwOnError: false })) return "uncertain";
    if (conv.startsWith("minutes:")) return this.cfg.context.sources.minutes ? "allowed" : "excluded";
    if (conv.startsWith("doc:")) return this.cfg.context.sources.docs ? "allowed" : "excluded";
    if (!conv.startsWith("pw_chat:") && !conv.startsWith("oc_")) return "allowed";
    if (!this.cfg.context.sources.im) return "excluded";

    if (conv.startsWith("pw_chat:")) {
      // 工作区主人变更或尚未完成绑定时，彻底阻断全部原生个人 Web 会话理解与提醒
      if (!this.activeBoundNativeOwner()) return "excluded";
      const chatId = conv.slice("pw_chat:".length);
      if (this.store.isConvMutedById(conv) || this.store.isConvMutedById(chatId)) return "excluded";
      const latest = this.store.latestConvObs(conv);
      const recordedType = classifyRecordedChatType(latest);
      const kind: "group" | "dm" = recordedType === "dm" ? "dm" : "group";
      const client = this.client;
      let chatName = "";
      let chatNameFromCache = true;
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
        const exclRes = await this.evaluateChatExclusion({
          chatId,
          pwConv: conv,
          kind,
          chatName,
          convName: convName || latest?.conv_name || "",
          activeClient: client,
          chatNameFromCache,
        });
        return exclRes.excluded ? "excluded" : "allowed";
      } catch {
        return "uncertain";
      }
    }

    // oc_* 开放平台会话：先做确定性 ID 排除；名称排除必须先拉取当前最新群名（避免群从被排除旧名改回合法名后永远卡死）
    if (this.store.isConvMutedById(conv)) return "excluded";
    if (this.cfg.context.groups_deny.some((raw) => raw.trim() === conv)) return "excluded";
    const latest = this.store.latestConvObs(conv);
    let effectiveName = (latest?.conv_name || convName || "").trim();
    let recordedType = classifyRecordedChatType(latest);
    const nameRules = this.nameDenyPatterns();
    const nativeExcl = nativeExclSnapshot ?? (await this.resolveNativeExclusionsForPolling());
    const staleNameExcluded =
      !!effectiveName &&
      (nameRules.some((d) => effectiveName.includes(d)) ||
        (recordedType !== "dm" && nativeExcl.confirmedGroupNames.has(norm(effectiveName))));
    const hasNameBasedRules = nativeExcl.confirmedGroupNames.size > 0 || nameRules.length > 0;
    // 对未知类型会话，以及在存在关键词/原生静音规则时的已知群会话，先实时刷新最新群名后再判定是否排除或放行
    const mustRefreshOpenChat =
      (recordedType === "unknown" && (nativeExcl.dmsInconclusive || nativeExcl.groupsInconclusive || hasNameBasedRules)) ||
      (recordedType === "group" && hasNameBasedRules);
    if (mustRefreshOpenChat) {
      const fresh = await this.resolveOpenChatMeta(conv, { force: true });
      if (!fresh) return staleNameExcluded ? "excluded" : "uncertain";
      if (fresh.meta.chatType === "p2p") recordedType = "dm";
      else if (fresh.meta.chatType === "group") recordedType = "group";
      // 开放平台 p2p 会话的 im chats get 通常返回空 name：保留已记录的私聊展示名，避免覆盖导致关键词排除漏检
      effectiveName = recordedType === "dm" ? fresh.meta.name || effectiveName : fresh.meta.name;
    }
    if (recordedType === "dm") {
      // 对已知私聊先应用主人显式配置的 groups_deny 关键词匹配；跨通道原生群名（confirmedGroupNames）仍与私聊隔离
      const dmLabels = [effectiveName, convName, latest?.conv_name ?? ""].filter(Boolean);
      if (nameRules.length > 0 && dmLabels.some((lbl) => nameRules.some((d) => lbl.includes(d)))) {
        return "excluded";
      }
      // 存在名称关键词排除规则时，若开放平台私聊仅存通用占位名（如「私聊」或空）且无法核实对方姓名，
      // 先实时查询一次 im chats get，仍无法确认对方身份时按 uncertain 暂缓（fail-closed）
      if (nameRules.length > 0) {
        const hasConcretePeer = (lbl: string): boolean => {
          const clean = lbl.replace(/^私聊[:：]?/, "").trim();
          return !!clean && clean !== "私聊" && clean !== conv;
        };
        let concrete = dmLabels.some(hasConcretePeer);
        if (!concrete) {
          const fresh = await this.resolveOpenChatMeta(conv, { force: true });
          if (fresh?.meta.name) {
            if (nameRules.some((d) => fresh.meta.name.includes(d))) return "excluded";
            concrete = hasConcretePeer(fresh.meta.name);
          }
        }
        if (!concrete) return "uncertain";
      }
      return nativeExcl.dmsInconclusive ? "uncertain" : "allowed";
    }
    if (recordedType === "unknown") {
      if (effectiveName && nativeExcl.confirmedGroupNames.has(norm(effectiveName))) return "excluded";
      if (effectiveName && nameRules.some((d) => effectiveName.includes(d))) return "excluded";
      if (nativeExcl.dmsInconclusive || nativeExcl.groupsInconclusive) return "uncertain";
      if (hasNameBasedRules) return "uncertain";
      return "allowed";
    }
    if (effectiveName && nativeExcl.confirmedGroupNames.has(norm(effectiveName))) return "excluded";
    if (effectiveName && nameRules.some((d) => effectiveName.includes(d))) return "excluded";
    if (nativeExcl.groupsInconclusive) return "uncertain";
    if (hasNameBasedRules && !effectiveName) return "uncertain";
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

  private resolvePwGroupName(k: string, spoken: Record<string, { name: string; at: number }>): string {
    const cached = (this.pwGroupNameCache.get(k) ?? "").trim();
    if (cached && cached !== "群聊" && !/^群聊\(\d+\)$/.test(cached)) return cached;
    const fromSpoken = (spoken[k]?.name ?? "").trim();
    if (fromSpoken && fromSpoken !== "群聊" && !/^群聊\(\d+\)$/.test(fromSpoken)) return fromSpoken;
    const latest = this.store.latestConvObs(k);
    const recordedType = classifyRecordedChatType(latest);
    if (recordedType === "dm") return "";
    const fromObs = (latest?.conv_name ?? "").trim();
    if (!fromObs || fromObs === "群聊" || /^群聊\(\d+\)$/.test(fromObs)) return "";
    if (recordedType === "group") return fromObs;
    return fromObs !== "私聊" && !/^私聊[:：]/.test(fromObs) ? fromObs : "";
  }

  /**
   * 仅在存在跨通道 oc_* 排除或关键词排除且当前群因名额限制可能落选时，按需补全排在前面的候选原生群名称与 oc_* 群名缓存，
   * 确保被静音/排除的跨通道同名群在 max_groups 截断前被剔除，不挤占未静音群的名额。
   */
  private async ensureCrossTransportScopeMeta(
    ownerId: string,
    activeClient?: FeishuWebClient,
    signal?: AbortSignal,
  ): Promise<void> {
    const ocRules = this.collectOpenChatExclusions();
    const hasNameRules = this.nameDenyPatterns().length > 0;
    if (ocRules.size === 0 && !hasNameRules) return;
    const now = Date.now();
    for (const [ocId] of ocRules) {
      const cached = this.ocExclusionCache.get(ocId);
      if (!cached || cached.expiresAt <= now) {
        await this.resolveOpenChatMeta(ocId);
      }
    }
    if (!activeClient || this.cfg.context.max_groups <= 0) return;
    const spoken = ownerId ? this.loadPwSpokenGroups(ownerId) : {};
    const ocDeny = this.confirmedOpenGroupDenyNames();
    const candidates: string[] =
      this.cfg.context.groups === "allowlist"
        ? [
            ...new Set(
              this.cfg.context.groups_allow
                .map((s) => s.trim())
                .filter((s) => s.startsWith("pw_chat:") || /^\d+$/.test(s))
                .map((s) => (s.startsWith("pw_chat:") ? s : `pw_chat:${s}`)),
            ),
          ]
        : Object.entries(spoken)
            .filter(([, v]) => v.at >= now - this.cfg.context.lookback_days * DAY_MS)
            .sort((a, b) => b[1].at - a[1].at)
            .map(([k]) => (k.startsWith("pw_chat:") ? k : `pw_chat:${k}`));

    let allowedCount = 0;
    for (const k of candidates) {
      const rawId = k.slice("pw_chat:".length);
      if (this.store.isConvMutedById(k) || this.store.isConvMutedById(rawId) || this.matchesDirectNativeIdDeny(k)) continue;
      let name = this.resolvePwGroupName(k, spoken);
      const excludedByName = !!name && this.isDirectlyDenied(k, name, ocDeny);
      if (!name || excludedByName) {
        try {
          const meta = await activeClient.readChat(rawId, { force: excludedByName, signal });
          if (meta.name.trim()) {
            name = meta.name.trim();
            this.pwGroupNameCache.set(k, name);
          }
        } catch {
          // ignore best-effort metadata refresh during ranking
        }
      }
      if (!this.isDirectlyDenied(k, name, ocDeny)) {
        allowedCount++;
        if (allowedCount >= this.cfg.context.max_groups) break;
      }
    }
  }

  private isGroupInScope(
    chatId: string,
    pwConv: string,
    ownerId: string,
    policy?: {
      groups: "spoken" | "allowlist";
      groupsAllow: string[];
      groupsDeny: string[];
      maxGroups: number;
      lookbackDays: number;
    },
  ): boolean {
    const groupsMode = policy?.groups ?? this.cfg.context.groups;
    const groupsAllow = policy?.groupsAllow ?? this.cfg.context.groups_allow;
    const groupsDeny = policy?.groupsDeny ?? this.cfg.context.groups_deny;
    const maxGroups = policy?.maxGroups ?? this.cfg.context.max_groups;
    const lookbackDays = policy?.lookbackDays ?? this.cfg.context.lookback_days;
    const spoken = ownerId ? this.loadPwSpokenGroups(ownerId) : {};
    const ocDeny = this.confirmedOpenGroupDenyNames(groupsDeny);
    if (groupsMode === "allowlist") {
      const nativeAllow = [
        ...new Set(
          groupsAllow
            .map((s) => s.trim())
            .filter((s) => s.startsWith("pw_chat:") || /^\d+$/.test(s))
            .map((s) => (s.startsWith("pw_chat:") ? s : `pw_chat:${s}`))
            .filter((k) => !this.isDirectlyDenied(k, this.resolvePwGroupName(k, spoken), ocDeny, "group", groupsDeny)),
        ),
      ].slice(0, maxGroups);
      return nativeAllow.includes(pwConv);
    }
    if (!ownerId) return false;
    const cutoff = Date.now() - lookbackDays * DAY_MS;
    const ranked = Object.entries(spoken)
      .filter(
        ([k, v]) =>
          v.at >= cutoff &&
          !this.isDirectlyDenied(k, this.resolvePwGroupName(k, spoken) || v.name, ocDeny, "group", groupsDeny),
      )
      .sort((a, b) => b[1].at - a[1].at)
      .slice(0, maxGroups);
    return ranked.some(([k]) => k === pwConv || k === chatId);
  }

  /** 判断群会话当前是否位于生效的采集范围集合（与采集器 pullIm 共享 selectEffectiveOpenGroups 口径） */
  isGroupConvInCurrentScope(conv: string, nativeExcl?: NativePollingExclusions): boolean {
    if (conv.startsWith("pw_chat:")) {
      const ownerId = this.activeBoundNativeOwner();
      if (!ownerId) return false;
      return this.isGroupInScope(conv.slice("pw_chat:".length), conv, ownerId);
    }
    if (conv.startsWith("oc_")) {
      const spoken = loadSpokenGroups(this.app.store);
      const knownNames = loadKnownOpenGroupNames(this.app.store);
      const effective = selectEffectiveOpenGroups({
        cfg: this.cfg,
        store: this.store,
        spoken,
        knownNames,
        nativeExcl,
      });
      return effective.some(([id]) => id === conv);
    }
    return true;
  }

  /** 判断该会话当前是否仅允许真实 `@我`（不在生效群范围的非私聊群，供 SQL 窗口预筛使用，防止大量积压普通消息饿死后到的 `@我`） */
  isConvMentionsOnly(conv: string, nativeExcl?: NativePollingExclusions): boolean {
    if (!conv.startsWith("pw_chat:") && !conv.startsWith("oc_")) return false;
    if (this.store.isDmConv(conv)) return false;
    return !this.isGroupConvInCurrentScope(conv, nativeExcl);
  }

  /**
   * 按当前生效的群白名单/发言群榜单过滤进入模型提示词（理解与起草）的观测窗口：
   *   - 私聊（p2p）与非 IM 会话原样放行；
   *   - `pw_chat:*` 与 `oc_*` 群均按与采集器一致的生效群集合（allowlist / spoken + 排除 + max_groups）判断；
   *   - 若群当前不在允许范围内，剔除所有普通群消息与普通背景，仅保留真实有效的 `@我` 观测（`kind === "at_me"` 且未撤回）。
   */
  filterWindowByCurrentScope(conv: string, window: Obs[], nativeExcl?: NativePollingExclusions): Obs[] {
    if (!window.length) return window;
    const active = window.filter((o) => o.meta.withdrawn !== true);
    if (!active.length) return active;
    if (!conv.startsWith("pw_chat:") && !conv.startsWith("oc_")) return active;
    const isDm =
      active.some((o) => String(o.meta.chat_type ?? "").trim().toLowerCase() === "p2p" || o.kind === "p2p") ||
      this.store.isDmConv(conv);
    if (isDm) return active;

    if (this.isGroupConvInCurrentScope(conv, nativeExcl)) return active;
    return active.filter(
      (o) =>
        (o.kind === "at_me" || o.meta.at_me === true) &&
        o.meta.at_me !== false &&
        o.meta.is_mention_me !== false,
    );
  }

  // ───────── 实时消息入库与快通道调度 ─────────

  /**
   * 将单条个人 Web 推送消息按采集范围与排除规则校验后落库，并在命中「真实 @本人 / 对方私聊」时触发防抖快通道。
   *   - 先做纯本地原生 ID 过滤与群范围筛查（若范围外群消息此前作为 @我 待处理但已被编辑移除 @我，则撤回旧待处理记录）；
   *   - 异步等待 readChat / 排除核验后、落库前复核信号取消与会话代际，防止登出/换号后把旧会话消息写入库或触发模型。
   */
  async handleMessage(msg: WebMessage, client?: FeishuWebClient, signal?: AbortSignal): Promise<void> {
    if (signal?.aborted) return;
    this.syncDiskPrivacyConfig({ throwOnError: true });
    if (!this.cfg.context.sources.im || !this.cfg.context.personal_web.enabled) return;
    if (!msg.id) return;

    const activeClient = client ?? this.client;
    const ownerId = msg.ownerId || activeClient?.owner().id || this.loginStore.load()?.owner_id || "";
    const capturedSessionId = activeClient?.currentSessionId() ?? "";
    const hasUsableBody = (m: WebMessage): boolean => isUsableWebMessage(m);

    const assertSessionActiveForStoreMutation = (): void => {
      if (signal?.aborted) {
        throw new WebHttpError("aborted", "会话已中止，放弃修改本地观测");
      }
      if ((this.app.store.get(REVOKED_AT_KV_KEY) ?? "").trim()) {
        throw new WebHttpError("aborted", "个人 Web 会话已被 web-logout 吊销，放弃修改本地观测");
      }
      if (capturedSessionId && loadRevokedSessionIds(this.app.store).has(capturedSessionId)) {
        throw new WebHttpError("aborted", "个人 Web 会话代际已被吊销，放弃修改本地观测");
      }
      const activeSession = (this.app.store.get(ACTIVE_SESSION_KV_KEY) ?? "").trim();
      if (activeSession && (capturedSessionId || activeClient) && capturedSessionId !== activeSession) {
        throw new WebHttpError("aborted", "个人 Web 会话已被更新的登录取代，放弃修改本地观测");
      }
      if (hasWorkspaceOwnerMismatch(this.app.store, this.cfg.owner.open_id)) {
        throw new WebHttpError("aborted", "工作区主人已变更，放弃修改本地观测");
      }
      const boundNative = (this.app.store.get(BOUND_OWNER_KV_KEY) ?? "").trim();
      if (boundNative && ownerId && boundNative !== ownerId) {
        throw new WebHttpError("aborted", "个人 Web 账号绑定已变更，放弃修改本地观测");
      }
    };

    const existing = this.store.obs(`pw:${msg.id}`);
    let effectiveMsg = msg;
    let authoritativeRead = false;

    const isDirectNativeExcluded = (convId: string, rawChatId = ""): boolean => {
      const id = rawChatId || (convId.startsWith("pw_chat:") ? convId.slice("pw_chat:".length) : "");
      return (
        (!!convId && (this.store.isConvMutedById(convId) || this.matchesDirectNativeIdDeny(convId))) ||
        (!!id && this.store.isConvMutedById(id))
      );
    };
    const rawMsgPwConv = msg.conversationId ? `pw_chat:${msg.conversationId}` : "";
    // 0) 任何服务端回读（含空正文/不支持消息编辑回读）之前，先按当前原生 ID 静音与 groups_deny 规则拦截已排除会话（零网络开销）
    if (isDirectNativeExcluded(rawMsgPwConv, msg.conversationId)) return;
    if (existing && isDirectNativeExcluded(existing.conv)) return;

    const isStoredConvExcludedBeforeRead = async (): Promise<boolean> => {
      if (!existing) return false;
      const targetPwConv = existing.conv.startsWith("pw_chat:") ? existing.conv : rawMsgPwConv;
      const targetChatId = targetPwConv.startsWith("pw_chat:")
        ? targetPwConv.slice("pw_chat:".length)
        : msg.conversationId;
      if (!targetPwConv || !targetChatId) return false;
      if (isDirectNativeExcluded(targetPwConv, targetChatId)) return true;
      if (this.nameDenyPatterns().length === 0 && this.collectOpenChatExclusions().size === 0) {
        return false;
      }
      const recordedKind = classifyRecordedChatType(existing);
      const kind: "group" | "dm" =
        recordedKind === "dm" || msg.conversationKind === "dm" ? "dm" : "group";
      const cachedName = kind === "group" ? (this.pwGroupNameCache.get(targetPwConv) ?? "") : "";
      const fallbackName =
        kind === "group" && existing.conv_name && !/^群聊\(\d+\)$/.test(existing.conv_name)
          ? existing.conv_name
          : "";
      const excl = await this.evaluateChatExclusion({
        chatId: targetChatId,
        pwConv: targetPwConv,
        kind,
        chatName: cachedName || fallbackName,
        convName: existing.conv_name || "",
        activeClient,
        chatNameFromCache: true,
        signal,
      });
      return excl.excluded;
    };

    if (!hasUsableBody(effectiveMsg)) {
      // 全新空正文/不支持消息直接丢弃；若该 ID 此前已入库（含待处理/已处理观测以及补读背景消息）且尚未撤回，
      // 先确认所属会话未被新加入排除规则，再权威回读确认并撤回旧正文，防止已撤回/清空的原文继续进入后续理解窗口或触发起草
      if (!existing || existing.meta.withdrawn === true) return;
      if (await isStoredConvExcludedBeforeRead()) return;
      if (activeClient) {
        try {
          effectiveMsg = await activeClient.readMessage(msg.id, signal);
        } catch (err) {
          if (err instanceof MessageNotFoundError) {
            assertSessionActiveForStoreMutation();
            this.store.retirePendingObs(`pw:${msg.id}`);
            return;
          }
          throw err;
        }
        authoritativeRead = true;
        assertSessionActiveForStoreMutation();
        if (!hasUsableBody(effectiveMsg)) {
          this.store.retirePendingObs(`pw:${msg.id}`);
          return;
        }
        // 仅用于上下文的历史背景消息若经权威回读仍有效（本次无效推送为乱序或瞬态误报），绝不提升为待处理工作
        if (existing.meta.background_only === true) return;
      } else {
        assertSessionActiveForStoreMutation();
        this.store.retirePendingObs(`pw:${msg.id}`);
        return;
      }
    }

    const derive = (m: WebMessage) => {
      const t = m.text.trim();
      const clipped = t.slice(0, 2000);
      const me = !!ownerId && m.actorId === ownerId;
      const atMe = !me && !!ownerId && m.mentions.some((x) => x.id === ownerId);
      return { text: t, clippedText: clipped, isMe: me, isAtMe: atMe, pwConv: `pw_chat:${m.conversationId}` };
    };
    let { text, clippedText, isMe, isAtMe, pwConv } = derive(effectiveMsg);

    // 1) 纯本地快速过滤：原生 ID 静音/禁用直接丢弃（零网络开销）
    if (isDirectNativeExcluded(pwConv, effectiveMsg.conversationId)) return;

    // 2) 若同 ID 观测已存在（含 hydrateContext 写入的 background_only 行）且本次推送与之冲突（文本/@mention 变化、已撤回或触发范围外撤回），
    //    先核验已存会话是否已被排除，再向服务端权威回读 readMessage(id)，避免未 ACK 旧推送包重放回滚更新后的编辑、把已被移除的 @我 错误晋升为待处理，或复活已撤回消息
    if (existing) {
      const existingBackgroundOnly = existing.meta.background_only === true;
      const existingWithdrawn = existing.meta.withdrawn === true;
      const incomingRev = obsRevision({ text: clippedText, meta: { at_me: isAtMe, mentions: effectiveMsg.mentions } });
      const revDiffers = obsRevision(existing) !== incomingRev;
      const incomingOutOfScope =
        effectiveMsg.conversationKind === "group" &&
        !isAtMe &&
        (this.cfg.context.groups === "allowlist" || !isMe) &&
        !this.isGroupInScope(effectiveMsg.conversationId, pwConv, ownerId);
      if (revDiffers || existingWithdrawn || incomingOutOfScope) {
        if (activeClient) {
          if (!authoritativeRead) {
            if (await isStoredConvExcludedBeforeRead()) return;
            try {
              effectiveMsg = await activeClient.readMessage(effectiveMsg.id, signal);
            } catch (err) {
              if (err instanceof MessageNotFoundError) {
                assertSessionActiveForStoreMutation();
                if (!existingWithdrawn) {
                  this.store.retirePendingObs(`pw:${msg.id}`);
                }
                return;
              }
              throw err;
            }
            authoritativeRead = true;
          }
          assertSessionActiveForStoreMutation();
          if (!hasUsableBody(effectiveMsg)) {
            if (!existingWithdrawn) {
              this.store.retirePendingObs(`pw:${msg.id}`);
            }
            return;
          }
          ({ text, clippedText, isMe, isAtMe, pwConv } = derive(effectiveMsg));
          if (this.store.isConvMutedById(pwConv) || this.store.isConvMutedById(effectiveMsg.conversationId)) return;
          if (this.matchesDirectNativeIdDeny(pwConv)) return;
          const authRev = obsRevision({ text: clippedText, meta: { at_me: isAtMe, mentions: effectiveMsg.mentions } });
          let authInScope =
            effectiveMsg.conversationKind !== "group" ||
            isAtMe ||
            (this.cfg.context.groups !== "allowlist" && isMe) ||
            this.isGroupInScope(effectiveMsg.conversationId, pwConv, ownerId);
          if (!authInScope) {
            await this.ensureCrossTransportScopeMeta(ownerId, activeClient, signal);
            authInScope = this.isGroupInScope(effectiveMsg.conversationId, pwConv, ownerId);
          }
          const authOutOfScope = !authInScope;
          // 非背景行且权威消息仍与本地已落库版本一致（未撤回/未越界）：说明本次推送是陈旧重放，直接跳过；
          // 若原行为 background_only，则仅使用权威回读后的最新版本继续后续范围校验与按需晋升
          if (!existingBackgroundOnly && !existingWithdrawn && !authOutOfScope && obsRevision(existing) === authRev) {
            return;
          }
        }
      }
    }

    if (effectiveMsg.conversationKind !== "group" && effectiveMsg.conversationKind !== "dm") return;
    const convKind: "group" | "dm" = effectiveMsg.conversationKind;

    // 3) 范围外普通群消息在 readChat 之前立刻丢弃（allowlist 模式下同样约束本人发出的群消息，不把未列白名单群的正文落库）；
    //    若存在跨通道 oc_* 静音/排除规则导致排位名额可能释放，先按需刷新排位元数据后再判断；
    //    若该消息 ID 此前曾以 @我 入库待处理，同步撤回避免模型对已撤销的 @我 提醒/起草
    if (convKind === "group" && !isAtMe) {
      const allowlistMode = this.cfg.context.groups === "allowlist";
      if ((allowlistMode || !isMe) && !this.isGroupInScope(effectiveMsg.conversationId, pwConv, ownerId)) {
        await this.ensureCrossTransportScopeMeta(ownerId, activeClient, signal);
        if (!this.isGroupInScope(effectiveMsg.conversationId, pwConv, ownerId)) {
          assertSessionActiveForStoreMutation();
          if (!isMe) this.store.retirePendingObs(`pw:${effectiveMsg.id}`);
          return;
        }
      }
    }

    // 4) 仅对可能入库的消息按需获取群名，再执行完整排除校验（含名称规则与实时 oc_* 复核）
    let chatName = "";
    if (convKind === "group" && activeClient) {
      try {
        chatName = (await activeClient.readChat(effectiveMsg.conversationId, { signal })).name.trim();
        if (chatName) this.pwGroupNameCache.set(pwConv, chatName);
      } catch {
        chatName = "";
      }
    }

    let convName =
      convKind === "dm"
        ? `私聊：${isMe ? effectiveMsg.conversationId : effectiveMsg.actorId || effectiveMsg.conversationId}`
        : chatName || `群聊(${effectiveMsg.conversationId})`;

    const formatDmConvName = (label: string): string => {
      const clean = label.trim();
      if (!clean) return `私聊：${isMe ? effectiveMsg.conversationId : effectiveMsg.actorId || effectiveMsg.conversationId}`;
      return clean.startsWith("私聊：") ? clean : `私聊：${clean}`;
    };

    const exclPolicyBefore = this.nativeExclusionPolicyKey();
    const exclRes = await this.evaluateChatExclusion({
      chatId: effectiveMsg.conversationId,
      pwConv,
      kind: convKind,
      chatName,
      convName,
      activeClient,
      chatNameFromCache: true,
      signal,
    });
    if (exclRes.verifiedChatName) {
      chatName = exclRes.verifiedChatName;
      if (convKind === "group") convName = chatName;
      else convName = formatDmConvName(chatName);
    }
    if (exclRes.excluded) return;

    // 5) 落库前最终核验会话代际、中止信号与当前采集策略（包含 oc_* 与关键词排除规则）：
    //    如果异步排除查询期间策略变化，先重跑排除校验并用核验后的真实群名/私聊名做同步终检，
    //    随后在 addObs 的 BEGIN IMMEDIATE 写事务锁内再次执行同一同步终检与策略签名核对，
    //    彻底杜绝跨进程 web-logout/静音/新增关键词排除/关闭 sources.im 在写锁竞争窗口内仍把消息写入数据库。
    const checkFinalIngestSync = (): boolean => {
      if (signal?.aborted) {
        throw new WebHttpError("aborted", "会话已中止，放弃提交推送观测");
      }
      if ((this.app.store.get(REVOKED_AT_KV_KEY) ?? "").trim()) {
        throw new WebHttpError("aborted", "个人 Web 会话已被 web-logout 吊销，放弃提交推送观测");
      }
      if (capturedSessionId && loadRevokedSessionIds(this.app.store).has(capturedSessionId)) {
        throw new WebHttpError("aborted", "个人 Web 会话代际已被吊销，放弃提交推送观测");
      }
      const activeSession = (this.app.store.get(ACTIVE_SESSION_KV_KEY) ?? "").trim();
      if (activeSession && (capturedSessionId || activeClient) && capturedSessionId !== activeSession) {
        throw new WebHttpError("aborted", "个人 Web 会话已被更新的登录取代，放弃提交推送观测");
      }
      if (hasWorkspaceOwnerMismatch(this.app.store, this.cfg.owner.open_id)) {
        throw new WebHttpError("aborted", "工作区主人已变更，放弃提交推送观测");
      }
      const boundNative = (this.app.store.get(BOUND_OWNER_KV_KEY) ?? "").trim();
      if (boundNative && ownerId && boundNative !== ownerId) {
        throw new WebHttpError("aborted", "个人 Web 账号绑定已变更，放弃提交推送观测");
      }
      if (capturedSessionId) {
        const diskNow = this.loginStore.load();
        if (!diskNow || diskNow.owner_id !== ownerId || (diskNow.session_id && diskNow.session_id !== capturedSessionId)) {
          throw new WebHttpError("aborted", "个人 Web 会话已登出或变更，放弃提交推送观测");
        }
        this.validateBoundOwner(diskNow);
      }
      this.syncDiskPrivacyConfig({ throwOnError: true });
      if (!this.cfg.context.sources.im || !this.cfg.context.personal_web.enabled) return false;
      if (this.store.isConvMutedById(pwConv) || this.store.isConvMutedById(effectiveMsg.conversationId)) return false;
      if (this.isDirectlyDenied(pwConv, chatName || convName, undefined, convKind)) return false;
      return true;
    };

    if (!checkFinalIngestSync()) return;
    let verifiedExclPolicy = exclPolicyBefore;
    if (this.nativeExclusionPolicyKey() !== verifiedExclPolicy) {
      const exclPolicyRetry = this.nativeExclusionPolicyKey();
      const exclResNow = await this.evaluateChatExclusion({
        chatId: effectiveMsg.conversationId,
        pwConv,
        kind: convKind,
        chatName,
        convName,
        activeClient,
        chatNameFromCache: true,
        signal,
      });
      if (exclResNow.verifiedChatName) {
        chatName = exclResNow.verifiedChatName;
        if (convKind === "group") convName = chatName;
        else convName = formatDmConvName(chatName);
      }
      if (exclResNow.excluded) return;
      if (!checkFinalIngestSync()) return;
      if (this.nativeExclusionPolicyKey() !== exclPolicyRetry) {
        // 排除规则连续两次在异步查询期间变化：抛可重试错误暂缓 ACK，防止 handlePush 误确认导致合法消息丢失
        throw new Error("推送入库期间排除规则连续变化，暂缓 ACK 留待飞书重投");
      }
      verifiedExclPolicy = exclPolicyRetry;
    }

    const obs: Obs = {
      id: `pw:${effectiveMsg.id}`,
      source: "im",
      kind: isMe ? "mine" : effectiveMsg.conversationKind === "dm" ? "p2p" : isAtMe ? "at_me" : "group",
      conv: pwConv,
      conv_name: convName,
      actor_id: effectiveMsg.actorId,
      actor_name: isMe ? this.app.store.get("ctx.owner_name") || activeClient?.owner().name || "我" : effectiveMsg.actorId,
      is_me: isMe,
      time: effectiveMsg.createdAtMs || Date.now(),
      text: clippedText,
      url: "",
      meta: {
        transport: "personal_web",
        native_owner_id: ownerId,
        native_message_id: effectiveMsg.id,
        native_chat_id: effectiveMsg.conversationId,
        native_root_id: effectiveMsg.rootId || effectiveMsg.id,
        native_parent_id: effectiveMsg.parentId,
        thread_id: effectiveMsg.threadId,
        position: effectiveMsg.position,
        chat_type: effectiveMsg.conversationKind === "dm" ? "p2p" : "group",
        sender_type: "user",
        at_me: isAtMe,
        mentions: effectiveMsg.mentions,
      },
    };

    let committed = false;
    const inserted = this.store.addObs([obs], () => {
      if (!checkFinalIngestSync()) return false;
      if (this.nativeExclusionPolicyKey() !== verifiedExclPolicy) {
        throw new Error("推送入库写事务锁内检测到排除规则变更，暂缓 ACK 留待飞书重投");
      }
      if (effectiveMsg.conversationKind === "group" && isMe && this.cfg.context.groups !== "allowlist") {
        this.recordPwSpokenGroup(ownerId, pwConv, chatName, effectiveMsg.createdAtMs || Date.now());
      }
      if (effectiveMsg.conversationKind === "group" && !isAtMe && !this.isGroupInScope(effectiveMsg.conversationId, pwConv, ownerId)) {
        if (!isMe) this.store.retirePendingObs(`pw:${effectiveMsg.id}`);
        return false;
      }
      committed = true;
      return true;
    });
    if (!committed) return;
    this.persistState({ last_message_at: Date.now() });

    const pwCfg = this.cfg.context.personal_web;
    const isPending = inserted > 0 || this.store.obsPending(obs.id);
    const shouldFastLane =
      isPending &&
      pwCfg.enabled &&
      pwCfg.fast_lane &&
      this.cfg.context.understand &&
      !isMe &&
      (isAtMe || effectiveMsg.conversationKind === "dm");

    if (!shouldFastLane) return;

    const revHash = createHash("sha256").update(obsRevision(obs)).digest("hex").slice(0, 12);
    const storedObs = this.store.obs(obs.id);
    const revGen =
      typeof storedObs?.meta.edit_gen === "number" && Number.isFinite(storedObs.meta.edit_gen) ? storedObs.meta.edit_gen : 0;
    const anchor: FastAnchor = {
      id: effectiveMsg.id,
      conversationId: effectiveMsg.conversationId,
      rootId: effectiveMsg.rootId,
      parentId: effectiveMsg.parentId,
      threadId: effectiveMsg.threadId,
      position: effectiveMsg.position,
      createdAtMs: effectiveMsg.createdAtMs,
    };
    this.scheduleFastLane({
      conv: pwConv,
      conv_name: convName,
      trigger_obs_id: obs.id,
      text_hash: revHash,
      rev_gen: revGen,
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
    const now = Date.now();
    let bucket = this.debouncedAnchors.get(key);
    if (!bucket) {
      bucket = new Map<string, FastAnchor>();
      this.debouncedAnchors.set(key, bucket);
    }
    if (!this.debounceFirstAt.has(key)) {
      this.debounceFirstAt.set(key, now);
    }
    for (const a of trigger.anchors) bucket.set(a.id, a);

    const prev = this.debounceTimers.get(key);
    if (prev) clearTimeout(prev);
    const delay = this.cfg.context.personal_web.debounce_ms;
    const maxAnchors = Math.max(1, this.hooks.maxDebounceAnchors ?? 20);
    const maxWait = this.hooks.maxDebounceWaitMs ?? (delay > 0 ? Math.max(delay * 4, 15_000) : 0);
    const flush = () => {
      const t = this.debounceTimers.get(key);
      if (t) clearTimeout(t);
      this.debounceTimers.delete(key);
      this.debounceFirstAt.delete(key);
      const collected = this.debouncedAnchors.get(key);
      this.debouncedAnchors.delete(key);
      const allAnchors = collected ? [...collected.values()] : trigger.anchors;
      this.fireFastTrigger({ ...trigger, anchors: allAnchors });
    };
    const elapsed = now - (this.debounceFirstAt.get(key) ?? now);
    const remainingMax = Math.max(0, maxWait - elapsed);
    const effectiveDelay = Math.min(delay, remainingMax);
    if (effectiveDelay <= 0 || bucket.size >= maxAnchors) {
      flush();
      return;
    }
    const timer = setTimeout(flush, effectiveDelay);
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

    const isDm = classifyRecordedChatType(triggerObs) === "dm";
    let chatName = "";
    if (!isDm) {
      try {
        chatName = (await client.readChat(primary.conversationId, { signal })).name.trim();
      } catch {
        chatName = "";
      }
    }
    if (!sessionStillValid()) return 0;

    const exclPolicyBefore = this.nativeExclusionPolicyKey();
    try {
      const exclRes = await this.evaluateChatExclusion({
        chatId: primary.conversationId,
        pwConv: conv,
        kind: isDm ? "dm" : "group",
        chatName,
        convName,
        activeClient: client,
        chatNameFromCache: true,
        signal,
      });
      if (exclRes.verifiedChatName) chatName = exclRes.verifiedChatName;
      if (exclRes.excluded) return 0;
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
      // 落库前重新核验会话代际与全部采集策略（含最后一次异步复核之后在写事务锁内的无 await 同步终检）
      const checkHydrateFinalSync = (): boolean => {
        if (signal?.aborted) return false;
        if (!sessionStillValid()) return false;
        if (!this.cfg.context.sources.im || !this.cfg.context.personal_web.enabled) return false;
        if (this.store.isConvMutedById(conv) || this.store.isConvMutedById(primary.conversationId)) return false;
        if (this.isDirectlyDenied(conv, chatName || convName, undefined, isDm ? "dm" : "group")) return false;
        if (!isDm && !this.isGroupInScope(primary.conversationId, conv, clientOwnerId)) return false;
        return true;
      };
      if (!checkHydrateFinalSync()) return 0;
      let verifiedHydratePolicy = exclPolicyBefore;
      if (this.nativeExclusionPolicyKey() !== verifiedHydratePolicy) {
        const exclPolicyRetry = this.nativeExclusionPolicyKey();
        try {
          const exclResNow = await this.evaluateChatExclusion({
            chatId: primary.conversationId,
            pwConv: conv,
            kind: isDm ? "dm" : "group",
            chatName,
            convName,
            activeClient: client,
            chatNameFromCache: true,
            signal,
          });
          if (exclResNow.verifiedChatName) chatName = exclResNow.verifiedChatName;
          if (exclResNow.excluded) return 0;
        } catch {
          return 0;
        }
        if (!checkHydrateFinalSync()) return 0;
        if (this.nativeExclusionPolicyKey() !== exclPolicyRetry) return 0;
        verifiedHydratePolicy = exclPolicyRetry;
      }
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
      return this.store.addBackgroundObs(
        bg,
        () => checkHydrateFinalSync() && this.nativeExclusionPolicyKey() === verifiedHydratePolicy,
      );
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
   * 原子抢占发送状态（SQLite BEGIN IMMEDIATE CAS）：
   *   - 仅当当前无记录或处于明确未创建状态（rejected）时才写入 `sending`；
   *   - 在同一 SQLite 写锁内执行 `beforeClaim` 终检（发信开关、原消息未撤回、会话未登出/取代），防止与跨进程 web-logout 或撤回竞态；
   *   - 若另一进程已在异步校验期间抢先写入了 `sending` / `created` / `verified`，绝不覆盖，原样返回已有记录交调用方安全分流。
   */
  private claimDeliveryForSend(
    rec: DeliveryRecord,
    beforeClaim?: () => void,
  ): { ok: true } | { ok: false; existing: DeliveryRecord } {
    this.app.store.db.exec("BEGIN IMMEDIATE");
    try {
      const cur = this.loadDelivery(rec.cid);
      if (cur) {
        if (
          (cur.owner_id && cur.owner_id !== rec.owner_id) ||
          cur.chat_id !== rec.chat_id ||
          cur.message_id !== rec.message_id ||
          cur.text_hash !== rec.text_hash
        ) {
          this.app.store.db.exec("ROLLBACK");
          throw new Error("个人 Web 回复幂等键（CID）与草稿内容或账号冲突，拒绝发送");
        }
        if (cur.state !== "rejected") {
          this.app.store.db.exec("ROLLBACK");
          return { ok: false, existing: cur };
        }
      }
      beforeClaim?.();
      this.saveDelivery(rec);
      this.app.store.db.exec("COMMIT");
      return { ok: true };
    } catch (err) {
      try {
        this.app.store.db.exec("ROLLBACK");
      } catch {
        // ignore
      }
      throw err;
    }
  }

  /**
   * 核验共享的 send_replies 发送权限并读取当前生效的完整群范围与排除策略：
   * 先查本进程配置；若配置来自磁盘文件且文件消失/不可 stat，按 fail-closed 中止新发送；
   * 若磁盘 config.yaml 被另一进程（如 Web 控制台）修改过，同步读取磁盘最新的
   * send_replies、groups、groups_allow、groups_deny、max_groups 与 lookback_days，防止跨进程按陈旧白名单或排除规则放行。
   */
  private assertSendEnabled(): {
    groups: "spoken" | "allowlist";
    groupsAllow: string[];
    groupsDeny: string[];
    maxGroups: number;
    lookbackDays: number;
  } {
    if (!this.cfg.context.personal_web.send_replies) {
      throw new Error("未开启个人 Web 回复（需在配置中设置 context.personal_web.send_replies: true）");
    }
    const cfgFile = this.cfg.file;
    if (cfgFile) {
      const disk = readDiskConfigRaw(cfgFile);
      if (!disk.exists || disk.error || disk.raw === undefined) {
        throw new Error(`配置文件 ${cfgFile} 不存在或无法读取，无法核验 context.personal_web.send_replies 开关，按安全原则中止发送`);
      }
      this.syncDiskPrivacyConfig({ throwOnError: true });
      if (!this.cfg.context.personal_web.send_replies) {
        throw new Error("检测到配置文件已关闭 context.personal_web.send_replies，已中止发送");
      }
    }
    return {
      groups: this.cfg.context.groups,
      groupsAllow: this.cfg.context.groups_allow,
      groupsDeny: this.cfg.context.groups_deny,
      maxGroups: this.cfg.context.max_groups,
      lookbackDays: this.cfg.context.lookback_days,
    };
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
    this.loginStore.reconcilePendingCommit(this.app.store, PENDING_CRED_COMMIT_KV_KEY);
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
    const pwConv = `pw_chat:${args.chat_id}`;
    const assertTargetNotWithdrawn = () => {
      const targetObs = this.store.obs(`pw:${args.message_id}`);
      if (targetObs?.meta.withdrawn === true) {
        throw new Error("发送前检测到原个人 Web 消息已被编辑移出触发范围或撤回，已中止发送");
      }
    };
    const assertNotHardExcludedByIdSync = (groupsDeny: string[]) => {
      if (this.store.isConvMutedById(pwConv) || this.store.isConvMutedById(args.chat_id)) {
        throw new Error("目标个人 Web 会话已被静音，已中止发送");
      }
      if (this.matchesDirectNativeIdDeny(pwConv, groupsDeny)) {
        throw new Error("目标个人 Web 会话在 groups_deny 排除列表中，已中止发送");
      }
    };
    // 只有需要发起新发送时才要求 send_replies=true、目标消息未撤回且会话未被硬排除；
    // 已创建待回读只读核验无需重新开启开关也不受后续撤回/排除阻断
    let entryGroupsDeny: string[] = this.cfg.context.groups_deny;
    if (!readbackOnly) {
      ({ groupsDeny: entryGroupsDeny } = this.assertSendEnabled());
      assertTargetNotWithdrawn();
      assertNotHardExcludedByIdSync(entryGroupsDeny);
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
        onSessionConfirmed: (updated, delta) => {
          try {
            this.validateBoundOwner(updated);
          } catch {
            return null;
          }
          return this.loginStore.saveIfSessionMatches(updated, delta);
        },
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

    // 发起任何原消息读取（readMessage）之前，若存在名称关键词或跨通道 oc_* 排除规则，
    // 先按实时会话元数据核验全部硬排除规则（静音与原生 ID 排除已在入口同步拦截，群聊与私聊同等生效）
    const hasPreReadNameOrOcRules =
      this.nameDenyPatterns(entryGroupsDeny).length > 0 ||
      this.collectOpenChatExclusions(entryGroupsDeny).size > 0;
    if (hasPreReadNameOrOcRules) {
      const latestConvObs = this.store.latestConvObs(pwConv);
      const preChat = await client.readChat(args.chat_id, { force: true });
      const preKind: "group" | "dm" = isGroupChat(preChat.kind)
        ? "group"
        : preChat.kind === CHAT_KIND_P2P
          ? "dm"
          : (() => {
              throw new Error(`不支持的个人会话类型：${preChat.kind}`);
            })();
      const preExcl = await this.evaluateChatExclusion({
        chatId: args.chat_id,
        pwConv,
        kind: preKind,
        chatName: preChat.name.trim(),
        convName: latestConvObs?.conv_name || preChat.name.trim(),
        activeClient: client,
        chatNameFromCache: false,
        groupsDeny: entryGroupsDeny,
      });
      if (preExcl.excluded) {
        throw new Error("目标个人 Web 会话已被静音或命中排除规则（groups_deny），已中止读取与发送");
      }
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
          onBeforeSend: async ({ rootId, parentId, threaded, original, chat }) => {
            // 1) 发包认领前再次按实时会话元数据与磁盘最新群范围/排除配置执行全部硬排除规则（静音 / groups_deny / oc_* 排除，DM 与 @我 群均无豁免）
            const livePolicy = this.assertSendEnabled();
            const liveGroupsDeny = livePolicy.groupsDeny;
            const livePolicyKey = this.nativeExclusionPolicyKey(liveGroupsDeny);
            const liveKind: "group" | "dm" = isGroupChat(chat.kind) ? "group" : "dm";
            const liveLatest = this.store.latestConvObs(pwConv);
            const liveExcl = await this.evaluateChatExclusion({
              chatId: args.chat_id,
              pwConv,
              kind: liveKind,
              chatName: chat.name.trim(),
              convName: liveLatest?.conv_name || chat.name.trim(),
              activeClient: client,
              chatNameFromCache: false,
              groupsDeny: liveGroupsDeny,
            });
            if (liveExcl.excluded) {
              throw new Error("发送前实时核验发现目标个人 Web 会话已被静音或命中排除规则，已中止发送");
            }
            const verifiedName = liveExcl.verifiedChatName || chat.name.trim() || liveLatest?.conv_name || "";

            // 2) @本人 豁免仅适用于未被硬排除、仅仅在当前生效白名单/发言群范围之外的群聊：
            //    使用磁盘最新 groups / groups_allow / groups_deny / max_groups / lookback_days 评估范围，
            //    并依据刚回读的权威原消息复核仍存在 @本人，防止监听离线或跨进程改白名单后误发
            const liveAtMe =
              original.actorId !== args.owner_id &&
              original.mentions.some((m) => m.id === args.owner_id);
            const targetIsOutOfScopeGroup =
              liveKind === "group" &&
              !this.isGroupInScope(args.chat_id, pwConv, args.owner_id, livePolicy);
            if (targetIsOutOfScopeGroup && !liveAtMe) {
              this.store.retirePendingObs(`pw:${args.message_id}`);
              throw new Error("发送前实时核验发现范围外群原消息已不再 @本人（离线期间可能已被编辑移除 @mention 或群已移出白名单），已中止发送");
            }
            let retireOutOfScopeAfterRollback = false;
            let claimed: ReturnType<PersonalWebBridge["claimDeliveryForSend"]>;
            try {
              claimed = this.claimDeliveryForSend(
                {
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
                },
                () => {
                  // 在写入 sending 状态的同一 SQLite BEGIN IMMEDIATE 写事务锁内重检授权、硬排除、最新群范围、吊销与撤回，
                  // 彻底消除跨进程 web-logout、muteConv、修改 groups_allow/groups_deny 或消息撤回在读后锁前提交导致的误发竞态
                  const lockPolicy = this.assertSendEnabled();
                  const lockGroupsDeny = lockPolicy.groupsDeny;
                  assertTargetNotWithdrawn();
                  assertNotHardExcludedByIdSync(lockGroupsDeny);
                  if (this.isDirectlyDenied(pwConv, verifiedName, undefined, liveKind, lockGroupsDeny)) {
                    throw new Error("认领发送时检测到目标个人 Web 会话已被静音或命中排除规则，已中止发送");
                  }
                  if (this.nativeExclusionPolicyKey(lockGroupsDeny) !== livePolicyKey) {
                    throw new Error("认领发送期间会话静音或排除规则发生变更，已按安全策略中止发送");
                  }
                  if (liveKind === "group" && !this.isGroupInScope(args.chat_id, pwConv, args.owner_id, lockPolicy) && !liveAtMe) {
                    retireOutOfScopeAfterRollback = true;
                    throw new Error("认领发送时检测到目标群已移出当前允许范围且原消息未 @本人，已中止发送");
                  }
                  this.assertSessionOwner(args.owner_id, initialSessionId);
                  if (client.owner().id !== args.owner_id) {
                    throw new Error("发送前检测到客户端账号不匹配，已中止发送");
                  }
                },
              );
            } catch (err) {
              if (retireOutOfScopeAfterRollback) {
                this.store.retirePendingObs(`pw:${args.message_id}`);
              }
              throw err;
            }
            if (!claimed.ok) {
              throw new DeliveryAlreadyClaimedError(claimed.existing);
            }
            sendMeta = { rootId, parentId, threaded };
            enteredSend = true;
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
            // 已安全持久化 created 回执；若发包期间会话已被登出或取代，立刻中止后续回读与 Cookie 写入（留待重登录后只读回读恢复）
            this.assertSessionOwner(args.owner_id, initialSessionId);
          },
        },
      );
    } catch (err) {
      if (err instanceof UnusableOriginalMessageError) {
        this.store.retirePendingObs(`pw:${args.message_id}`);
        throw err;
      }
      if (err instanceof DeliveryAlreadyClaimedError) {
        const cur = err.existing;
        if (cur.state === "verified" && cur.reply_id) {
          return { replyId: cur.reply_id, rootId: cur.root_id, parentId: cur.parent_id, threadId: "", verified: true };
        }
        if (cur.state === "created" && cur.reply_id) {
          this.assertSessionOwner(args.owner_id, initialSessionId);
          const verified = await client.verifyReplyReadback({
            replyId: cur.reply_id,
            chatId: cur.chat_id,
            rootId: cur.root_id,
            parentId: cur.parent_id,
            cid: cur.cid,
            text: normalizedText,
            threaded: cur.threaded,
          });
          this.saveDelivery({ ...cur, state: "verified", updated_at: Date.now() });
          return verified;
        }
        throw new Error("该个人 Web 回复已由另一进程抢占发送或结果不明确，为避免重复发送已中止");
      }
      if (enteredSend && !createdOnServer && sendMeta && isDefinitiveNonCreationError(err)) {
        // 仅在仍为 sending 时转为 rejected，避免覆盖已进入 created/verified 的记录
        this.app.store.db.exec("BEGIN IMMEDIATE");
        try {
          const cur = this.loadDelivery(args.cid);
          if (!cur || cur.state === "sending") {
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
          this.app.store.db.exec("COMMIT");
        } catch {
          try {
            this.app.store.db.exec("ROLLBACK");
          } catch {
            // ignore
          }
        }
      }
      throw err;
    }

    const latest = this.loadDelivery(args.cid);
    if (latest) this.saveDelivery({ ...latest, state: "verified", reply_id: res.replyId, updated_at: Date.now() });
    return res;
  }
}

class DeliveryAlreadyClaimedError extends Error {
  readonly existing: DeliveryRecord;
  constructor(existing: DeliveryRecord) {
    super(`delivery ${existing.cid} already claimed (${existing.state})`);
    this.name = "DeliveryAlreadyClaimedError";
    this.existing = existing;
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
  const configuredOpenId = app.cfg.owner.open_id.trim();
  const boundWorkspaceOpenId = (app.store.get(BOUND_WORKSPACE_OWNER_KV_KEY) ?? "").trim();
  const prevWorkspaceOpenId = boundWorkspaceOpenId || (app.store.get("owner.open_id") ?? "").trim();
  const workspaceOwnerChanging = !!prevWorkspaceOpenId && configuredOpenId !== prevWorkspaceOpenId;
  const nativeOwnerChanging = !!boundId && boundId !== login.owner_id;

  if (nativeOwnerChanging) {
    if (!opts.forceSwitch) {
      throw new Error(
        `本工作区已绑定个人 Web 账号 ${boundId}，但本次扫码账号为 ${login.owner_id}（${login.owner_name || "无昵称"}）。` +
          "为防止混入他人私聊并以错误身份回复，已拒绝保存；如需更换账号，请使用新的干净数据目录。",
      );
    }
    const ctxStore = new ContextStore(app.store.db);
    if (ctxStore.hasOtherNativeOwnerObs(login.owner_id) || hasExistingOwnerContextState(app)) {
      throw new Error(
        `当前数据目录已包含原账号 (${boundId}) 的历史上下文数据；为防止旧账号私聊、草稿或待办泄漏给新账号，拒绝原地换号。` +
          "请先使用全新的 data_dir 后再执行 pa context web-login。",
      );
    }
  }
  if (workspaceOwnerChanging && hasExistingOwnerContextState(app)) {
    throw new Error(
      `当前工作区主人已从 ${prevWorkspaceOpenId} 变更为 ${configuredOpenId || "（未配置）"}，且数据目录中仍存在旧主人的上下文观测、事项、草稿或待发动作；` +
        "为防止重新绑定后旧主人的上下文数据泄漏给新主人，拒绝原地重绑，请先使用全新的 data_dir。",
    );
  }

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

/**
 * 在跨进程凭据文件锁 + SQLite BEGIN IMMEDIATE 写事务双重串行化保护下采用两阶段暂存提交登录与工作区绑定：
 *   1. 先协调恢复可能残留的上次未完成暂存提交（reconcilePendingCommit）；
 *   2. 再次核验当前工作区绑定、旧账号/无归属观测及中止信号；
 *   3. 先将新加密凭据 fsync 到 `<file>.staged`（不覆盖旧凭据），再在 SQLite 事务内写入新绑定与 pending 标记并 COMMIT；
 *      - 若 SQLite COMMIT 失败或回滚，直接删除 `.staged`，旧凭据与旧绑定完全一致；
 *      - SQLite COMMIT 成功后立即原子 rename `.staged -> <file>` 并清除 pending 标记；
 *      - 若在 COMMIT 与 rename 之间崩溃，后续启动/读取由 reconcilePendingCommit 自动补全 rename，彻底杜绝新凭据配旧绑定。
 */
export function commitWorkspaceLogin(
  app: App,
  login: WebLogin,
  opts: { forceSwitch?: boolean; allowUnverifiedOwner?: boolean; signal?: AbortSignal } = {},
): WebLogin {
  const loginStore = new WebLoginStore(app.cfg.dataDir);
  loginStore.reconcilePendingCommit(app.store, PENDING_CRED_COMMIT_KV_KEY);
  return loginStore.stageWithLock((stage) => {
    if (opts.signal?.aborted) {
      throw new Error("扫码登录已取消");
    }
    let staged:
      | {
          payload: WebLogin;
          prevFileSha256: string;
          prevSessionId: string;
          commitFile: () => void;
          abortFile: () => void;
        }
      | undefined;
    let sqliteCommitted = false;
    app.store.db.exec("BEGIN IMMEDIATE");
    try {
      const boundId = (app.store.get(BOUND_OWNER_KV_KEY) ?? "").trim() || loginStore.load()?.owner_id || "";
      const configuredOpenId = app.cfg.owner.open_id.trim();
      const boundWorkspaceOpenId = (app.store.get(BOUND_WORKSPACE_OWNER_KV_KEY) ?? "").trim();
      const prevWorkspaceOpenId = boundWorkspaceOpenId || (app.store.get("owner.open_id") ?? "").trim();
      const workspaceOwnerChanging = !!prevWorkspaceOpenId && configuredOpenId !== prevWorkspaceOpenId;

      if (boundId && boundId !== login.owner_id) {
        if (!opts.forceSwitch) {
          throw new Error(
            `提交绑定时检测到本工作区已被其他个人 Web 账号 (${boundId}) 绑定，拒绝覆写；如需更换账号请使用全新的 data_dir。`,
          );
        }
        const ctxStore = new ContextStore(app.store.db);
        if (ctxStore.hasOtherNativeOwnerObs(login.owner_id) || hasExistingOwnerContextState(app)) {
          throw new Error(
            `提交绑定时检测到当前数据目录包含原账号或无归属的历史观测、事项或草稿，拒绝原地换号；请使用全新的 data_dir。`,
          );
        }
      }
      if (workspaceOwnerChanging && hasExistingOwnerContextState(app)) {
        throw new Error(
          `提交绑定时检测到工作区主人已从 ${prevWorkspaceOpenId} 变更为 ${configuredOpenId || "（未配置）"} 且数据目录非空，拒绝原地重绑以防旧主人数据泄漏；请使用全新的 data_dir。`,
        );
      }

      const sameNativeOwner = !!boundId && boundId === login.owner_id;
      const sameWorkspaceOwner = !configuredOpenId || !boundWorkspaceOpenId || boundWorkspaceOpenId === configuredOpenId;
      const isAlreadyVerifiedRelogin = sameNativeOwner && sameWorkspaceOwner && (!configuredOpenId || !!boundWorkspaceOpenId);
      if (!isAlreadyVerifiedRelogin && !opts.allowUnverifiedOwner) {
        throw new Error(
          `首次绑定或变更工作区主人时必须显式传入 --allow-unverified-owner 确认账号归属，拒绝静默提交绑定。`,
        );
      }

      if (opts.signal?.aborted) {
        throw new Error("扫码登录已取消");
      }

      staged = stage(login);
      const saved = staged.payload;
      saveWorkspaceBinding(app.store, saved.owner_id, configuredOpenId);
      app.store.set(REVOKED_AT_KV_KEY, "");
      app.store.set(ACTIVE_SESSION_KV_KEY, saved.session_id ?? "");
      const pendingMarker = JSON.stringify({
        file: loginStore.file,
        staged_file: loginStore.stagedFile,
        owner_id: saved.owner_id,
        session_id: saved.session_id ?? "",
        prev_file_sha256: staged.prevFileSha256,
        prev_session_id: staged.prevSessionId,
        at: Date.now(),
      });
      app.store.set(PENDING_CRED_COMMIT_KV_KEY, pendingMarker);
      app.store.set(
        STATE_KV_KEY,
        JSON.stringify({
          state: "stopped",
          owner_id: saved.owner_id,
          owner_name: saved.owner_name,
          session_id: saved.session_id ?? "",
          since: Date.now(),
          last_message_at: null,
          last_error: "",
        }),
      );
      if (saved.owner_name && !app.store.get("ctx.owner_name")) {
        app.store.set("ctx.owner_name", saved.owner_name);
      }
      app.store.db.exec("COMMIT");
      sqliteCommitted = true;

      staged.commitFile();
      try {
        clearPendingCommitMarkerIfMatches(app.store, PENDING_CRED_COMMIT_KV_KEY, {
          file: loginStore.file,
          sessionId: saved.session_id ?? "",
          rawMarker: pendingMarker,
        });
      } catch {
        // 凭据文件已切换完成；下次 reconcilePendingCommit 会自动清除冗余标记
      }
      return saved;
    } catch (err) {
      if (!sqliteCommitted) {
        try {
          app.store.db.exec("ROLLBACK");
        } catch {
          // ignore
        }
        try {
          staged?.abortFile();
        } catch {
          // ignore
        }
      }
      throw err;
    }
  });
}
