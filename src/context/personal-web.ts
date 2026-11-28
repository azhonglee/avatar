import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { App } from "../app.ts";
import type { CtxPersonalWebStatus } from "../api/types.ts";
import type { Config } from "../config.ts";
import { PermanentEffectError } from "../effects.ts";
import { FeishuGatewayClient } from "../gateway/client.ts";
import {
  ENV_NAME_RE,
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

export const GATEWAY_ENV_FILENAME = "gateway.env";
const MAX_GATEWAY_ENV_BYTES = 64 * 1024;

export type GatewayTokenSource = "env" | "credential" | "env_file" | "none";
export type GatewayEnvUnsafeKind = "file_type" | "owner" | "mode";

export interface GatewayEnvFileReadResult {
  status: "ok" | "missing" | "unsafe" | "error";
  file: string;
  values: Record<string, string>;
  unsafeKind?: GatewayEnvUnsafeKind;
  error?: string;
}

export interface ResolvedGatewayClientConfig {
  socketPath?: string;
  baseUrl?: string;
  readToken: string;
  replyToken: string;
  readTokenSource: GatewayTokenSource;
  replyTokenSource: GatewayTokenSource;
  envFilePath?: string;
  envFileError?: string;
  envFileUnsafeKind?: GatewayEnvUnsafeKind;
  endpointLabel: string;
}

export function gatewayEnvFilePath(dataDir: string): string {
  return path.join(path.resolve(dataDir), GATEWAY_ENV_FILENAME);
}

export function formatTokenSourceLabel(src: GatewayTokenSource): string {
  switch (src) {
    case "env":
      return "环境变量";
    case "credential":
      return "systemd 凭据";
    case "env_file":
      return "gateway.env";
    case "none":
      return "未配置";
  }
}

/** 解析受限的 KEY=VALUE 凭据文件文本（支持 # 注释、可选 export 前缀、单双引号）。 */
export function parseGatewayEnvText(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const rawLine of text.split(/\r?\n/)) {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const body = trimmed.startsWith("export ") ? trimmed.slice("export ".length).trim() : trimmed;
    const eq = body.indexOf("=");
    if (eq <= 0) continue;
    const key = body.slice(0, eq).trim();
    if (!ENV_NAME_RE.test(key)) continue;
    let rawVal = body.slice(eq + 1).trim();
    let val = rawVal;
    if (rawVal.length >= 2 && rawVal.startsWith("'") && rawVal.endsWith("'")) {
      val = rawVal.slice(1, -1);
    } else if (rawVal.length >= 2 && rawVal.startsWith('"') && rawVal.endsWith('"')) {
      val = rawVal
        .slice(1, -1)
        .replace(/\\(["\\$`])/g, "$1");
    }
    if (!val || /[\r\n\0]/.test(val)) continue;
    out[key] = val;
  }
  return out;
}

function formatEnvValue(val: string): string {
  if (/[\r\n\0]/.test(val)) {
    throw new Error("令牌值包含非法控制字符（换行或空字节）");
  }
  if (!val.includes("'")) return `'${val}'`;
  const escaped = val.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\$/g, "\\$").replace(/`/g, "\\`");
  return `"${escaped}"`;
}

/**
 * 读取 `<data_dir>/gateway.env` 受限凭据文件（单 fd 打开后 `fstatSync` 校验，消除 TOCTOU）：
 *   - 使用 `O_NOFOLLOW` 拒绝符号链接，并在同一个 fd 上拒绝目录/FIFO/socket 等非普通文件；
 *   - 在 POSIX 上必须仅属主可访问（mode & 0o077 === 0，即 0600 / 0400）且属主与当前进程一致。
 */
export function readGatewayEnvFile(dataDir: string): GatewayEnvFileReadResult {
  const file = gatewayEnvFilePath(dataDir);
  const openFlags =
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0);
  let fd: number;
  try {
    fd = fs.openSync(file, openFlags);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === "ENOENT") {
      return { status: "missing", file, values: {} };
    }
    if (code === "ELOOP" || code === "EISDIR") {
      return {
        status: "unsafe",
        file,
        values: {},
        unsafeKind: "file_type",
        error: `${file} 必须是普通文件（拒绝符号链接或目录）`,
      };
    }
    return { status: "error", file, values: {}, error: `无法访问 ${file}：${errMsg(e)}` };
  }
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) {
      return {
        status: "unsafe",
        file,
        values: {},
        unsafeKind: "file_type",
        error: `${file} 必须是普通文件（拒绝符号链接、目录或特殊文件）`,
      };
    }
    if (st.size > MAX_GATEWAY_ENV_BYTES) {
      return { status: "error", file, values: {}, error: `${file} 体积超过上限（${MAX_GATEWAY_ENV_BYTES} 字节），已拒绝加载` };
    }
    if (process.platform !== "win32") {
      if (typeof process.getuid === "function" && st.uid !== process.getuid()) {
        return {
          status: "unsafe",
          file,
          values: {},
          unsafeKind: "owner",
          error: `${file} 属主与当前运行用户不一致，拒绝加载`,
        };
      }
      const perm = st.mode & 0o777;
      if ((perm & 0o077) !== 0) {
        return {
          status: "unsafe",
          file,
          values: {},
          unsafeKind: "mode",
          error: `${file} 权限过于宽松（当前 ${perm.toString(8).padStart(4, "0")}，必须为 0600），已拒绝加载`,
        };
      }
    }
    const raw = fs.readFileSync(fd, "utf8");
    return { status: "ok", file, values: parseGatewayEnvText(raw) };
  } catch (e) {
    return { status: "error", file, values: {}, error: `读取 ${file} 失败：${errMsg(e)}` };
  } finally {
    try {
      fs.closeSync(fd);
    } catch {
      // ignore
    }
  }
}

/** 原子写入 `0600` 权限的 `<data_dir>/gateway.env`（`O_EXCL | O_NOFOLLOW` + 随机临时名 + `fchmodSync`，零宽松权限窗口）。 */
export function writeGatewayEnvFile(dataDir: string, entries: Record<string, string>): string {
  const dir = path.resolve(dataDir);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const file = gatewayEnvFilePath(dir);
  try {
    const existing = fs.lstatSync(file);
    if (existing.isSymbolicLink()) throw new Error(`${file} 是符号链接，拒绝覆盖写入`);
    if (!existing.isFile()) throw new Error(`${file} 不是普通文件，拒绝覆盖写入`);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
  }

  const lines = [
    "# Avatar 个人 Web 网关凭据文件（由 pa context web-setup 维护，权限固定 0600，请勿提交到版本库）",
  ];
  for (const [key, rawVal] of Object.entries(entries)) {
    const k = key.trim();
    const v = rawVal.trim();
    if (!ENV_NAME_RE.test(k)) throw new Error(`无效的环境变量名：${key}`);
    if (!v) throw new Error(`环境变量 ${k} 的值不能为空`);
    lines.push(`${k}=${formatEnvValue(v)}`);
  }
  const content = lines.join("\n") + "\n";
  const rand = crypto.randomBytes(6).toString("hex");
  const tmp = path.join(dir, `.${GATEWAY_ENV_FILENAME}.${process.pid}.${Date.now()}.${rand}.tmp`);
  const createFlags =
    fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0);
  let fd: number | undefined;
  try {
    fd = fs.openSync(tmp, createFlags, 0o600);
    fs.fchmodSync(fd, 0o600);
    fs.writeFileSync(fd, content, "utf8");
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    fs.renameSync(tmp, file);
  } catch (e) {
    if (fd !== undefined) {
      try {
        fs.closeSync(fd);
      } catch {
        // ignore
      }
    }
    fs.rmSync(tmp, { force: true });
    throw e;
  }
  return file;
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

/**
 * 从配置指定的环境变量、systemd LoadCredential 或 `<data_dir>/gateway.env`（0600）解析网关地址与读写分离双令牌。
 * 优先级：显式环境变量 > systemd LoadCredential > `<data_dir>/gateway.env`。
 */
export function resolveGatewayClientConfig(
  pwCfg: Config["context"]["personal_web"],
  env: NodeJS.ProcessEnv = process.env,
  opts: { dataDir?: string } = {},
): ResolvedGatewayClientConfig {
  const socketRaw = pwCfg.gateway_socket.trim();
  const urlRaw = pwCfg.gateway_url.trim();
  const socketPath = socketRaw ? path.resolve(expandHome(socketRaw)) : undefined;
  const baseUrl = urlRaw || undefined;
  const readEnvName = pwCfg.read_token_env.trim();
  const replyEnvName = pwCfg.reply_token_env.trim();

  const envFile = opts.dataDir ? readGatewayEnvFile(opts.dataDir) : undefined;
  const envFilePath = envFile?.file;
  const envFileError = envFile && (envFile.status === "unsafe" || envFile.status === "error") ? envFile.error : undefined;
  const envFileUnsafeKind = envFile?.status === "unsafe" ? envFile.unsafeKind : undefined;

  const pickToken = (envName: string, credNames: string[]): { value: string; source: GatewayTokenSource } => {
    const fromEnv = envName ? env[envName]?.trim() : "";
    if (fromEnv) return { value: fromEnv, source: "env" };
    const fromCred = readSystemdCredential(credNames, env);
    if (fromCred) return { value: fromCred, source: "credential" };
    const fromFile = envName && envFile?.status === "ok" ? envFile.values[envName]?.trim() : "";
    if (fromFile) return { value: fromFile, source: "env_file" };
    return { value: "", source: "none" };
  };

  const read = pickToken(readEnvName, ["feishu-gw-read-token", "read-token"]);
  const reply = pickToken(replyEnvName, ["feishu-gw-reply-token", "reply-token"]);

  const endpointLabel = socketPath ? `unix://${socketPath}` : (baseUrl ?? "(未配置)");
  return {
    socketPath,
    baseUrl,
    readToken: read.value,
    replyToken: reply.value,
    readTokenSource: read.source,
    replyTokenSource: reply.source,
    envFilePath,
    envFileError,
    envFileUnsafeKind,
    endpointLabel,
  };
}

export function createGatewayClientForConfig(
  pwCfg: Config["context"]["personal_web"],
  env: NodeJS.ProcessEnv = process.env,
  opts: { dataDir?: string } = {},
): FeishuGatewayClient {
  const resolved = resolveGatewayClientConfig(pwCfg, env, opts);
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

function isRegularFile(filePath: string): boolean {
  try {
    return fs.lstatSync(filePath).isFile();
  } catch {
    return false;
  }
}

function isInsideDir(filePath: string, dir: string): boolean {
  const rel = path.relative(path.resolve(dir), path.resolve(filePath));
  return rel !== "" && !rel.startsWith("..") && !path.isAbsolute(rel);
}

/**
 * 旧版（进程内个人 Web）遗留在 Avatar 侧的会话凭据：
 *   - `files`：仅包含 `cfg.dataDir` 内的普通文件（`feishu-web.json` 及其锁文件），可由 `pa context web-logout` 安全自动清理；
 *   - `externalFiles`：位于 `cfg.dataDir` 外的 `PA_FEISHU_WEB_CRED_FILE` 路径（可能同时被新网关回退读取，只提示不自动删）；
 *   - `envKeys`：运行环境中仍设置的旧环境变量名。
 */
export function legacyPersonalWebArtifacts(
  cfg: Pick<Config, "dataDir">,
  env: NodeJS.ProcessEnv = process.env,
): { files: string[]; externalFiles: string[]; envKeys: string[] } {
  const suffixes = (f: string) => [f, `${f}.lock`, `${f}.lock.db`, `${f}.lock.db-journal`];
  const localBase = path.join(cfg.dataDir, "feishu-web.json");
  const files = new Set<string>();
  const externalFiles = new Set<string>();

  for (const f of suffixes(localBase)) {
    if (isRegularFile(f)) files.add(f);
  }
  const extRaw = env.PA_FEISHU_WEB_CRED_FILE?.trim();
  if (extRaw) {
    const extResolved = path.resolve(extRaw);
    for (const f of suffixes(extResolved)) {
      if (!isRegularFile(f)) continue;
      if (isInsideDir(f, cfg.dataDir)) files.add(f);
      else externalFiles.add(f);
    }
  }
  const envKeys = ["PA_FEISHU_WEB_KEY", "PA_FEISHU_WEB_CRED_FILE"].filter((k) => !!env[k]?.trim());
  return { files: [...files], externalFiles: [...externalFiles], envKeys };
}

/** 核验网关上报的个人账号与当前 Avatar 工作区的绑定关系，防止指向错误网关实例导致跨账号混库。 */
export function verifyGatewayOwnerForWorkspace(app: App, ownerId: string): void {
  const id = ownerId.trim();
  if (!id) return;
  const bound = (app.store.get(BOUND_OWNER_KV_KEY) ?? "").trim();
  if (bound && bound !== id) {
    throw new Error(`当前工作区已绑定个人 Web 账号 ${bound}，与网关当前账号 ${id} 不一致，拒绝混入消息（如确需切换账号，请先执行 pa context web-unbind）`);
  }
}

/** 解除当前 Avatar 工作区与个人 Web 账号的绑定，并清空本地网关游标、db_epoch、状态、发言群与跨通道别名缓存（保留历史观测）。 */
export function unbindPersonalWebAccount(app: App): { previousOwnerId: string } {
  const previousOwnerId = (app.store.get(BOUND_OWNER_KV_KEY) ?? "").trim();
  const keys = [BOUND_OWNER_KV_KEY, CURSOR_KV_KEY, EPOCH_KV_KEY, STATE_KV_KEY, SPOKEN_GROUPS_KV_KEY];
  app.store.db.exec("BEGIN IMMEDIATE");
  try {
    const del = app.store.db.prepare("DELETE FROM kv WHERE k = ?");
    for (const k of keys) del.run(k);
    const hasAliasTable = !!app.store.db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'ctx_pw_alias'").get();
    if (hasAliasTable) app.store.db.exec("DELETE FROM ctx_pw_alias");
    app.store.db.exec("COMMIT");
  } catch (e) {
    try {
      app.store.db.exec("ROLLBACK");
    } catch {
      // ignore
    }
    throw e;
  }
  return { previousOwnerId };
}

export interface PersonalWebCheckResult {
  status: "ok" | "warn" | "fail" | "skip";
  detail: string;
  fix: string;
}

export interface PersonalWebInspection {
  personalWeb: PersonalWebCheckResult;
  boundary: PersonalWebCheckResult;
  resolved?: ResolvedGatewayClientConfig;
}

const backtick = (s: string) => "`" + s + "`";

function formatEnvFileFixHint(resolved: ResolvedGatewayClientConfig, envFileLabel: string): string {
  if (!resolved.envFileError) return "";
  if (resolved.envFileUnsafeKind === "mode") {
    return `执行 ${backtick(`chmod 600 ${envFileLabel}`)} 修复权限`;
  }
  if (resolved.envFileUnsafeKind === "file_type") {
    return `移除异常的符号链接/非普通文件 ${backtick(envFileLabel)} 后重新运行 ${backtick("bin/pa context web-setup")}`;
  }
  if (resolved.envFileUnsafeKind === "owner") {
    return `核对 ${backtick(envFileLabel)} 文件属主或删除后重新运行 ${backtick("bin/pa context web-setup")}`;
  }
  return `检查或重新生成 ${backtick(envFileLabel)}`;
}

/** 个人 Web 令牌隔离边界同步检查（独立于网络探测，供 `pa doctor` 与 `inspectPersonalWebGateway` 共用）。 */
export function inspectPersonalWebBoundary(
  app: App,
  env: NodeJS.ProcessEnv = process.env,
  preResolved?: ResolvedGatewayClientConfig,
): PersonalWebCheckResult {
  const { cfg } = app;
  const pwCfg = cfg.context.personal_web;
  if (!cfg.context.enabled || !pwCfg.enabled) {
    return { status: "skip", detail: "个人 Web 通道未启用", fix: "" };
  }
  const resolved = preResolved ?? resolveGatewayClientConfig(pwCfg, env, { dataDir: cfg.dataDir });
  const replyEnv = pwCfg.reply_token_env.trim() || "FEISHU_GW_REPLY_TOKEN";
  const envFileLabel = resolved.envFilePath ?? gatewayEnvFilePath(cfg.dataDir);
  if (pwCfg.send_replies) {
    return {
      status: "warn",
      detail: `已开启 context.personal_web.send_replies：与 Avatar 同 OS 用户运行的 --approve-all worker 可从 /proc/<pid>/environ、$CREDENTIALS_DIRECTORY 或 ${GATEWAY_ENV_FILENAME} 读取 reply_token，在网关 allow_reply=true 时能以本人身份回复消息`,
      fix: `如不需要经个人 Web 自动发送回复，运行 ${backtick("bin/pa context web-setup --no-reply")}（或将 ${backtick("context.personal_web.send_replies")} 设为 false 并移除 ${backtick(replyEnv)}）；如需保留，请将派单 worker 隔离在独立 OS 用户或容器中运行`,
    };
  }
  if (resolved.replyToken) {
    return {
      status: "warn",
      detail: `context.personal_web.send_replies 已关闭，但 Avatar 仍存在 reply_token（${replyEnv}，来源：${formatTokenSourceLabel(resolved.replyTokenSource)}）：同 OS 用户的 --approve-all worker 仍可读取该令牌并在网关 allow_reply=true 时直接调用回复接口`,
      fix:
        resolved.replyTokenSource === "env_file"
          ? `运行 ${backtick("bin/pa context web-setup --no-reply")} 从 ${backtick(envFileLabel)} 中清理 ${backtick(replyEnv)}，仅保留只读令牌`
          : `从 Avatar 运行环境或 systemd LoadCredential 中移除 ${backtick(replyEnv)}（reply-token），仅保留只读令牌`,
    };
  }
  return {
    status: "ok",
    detail: "个人 Web 回复已关闭且未向 Avatar 暴露 reply_token（仅使用只读通道；如需对 read_token 做强隔离，仍建议以独立 OS 用户或容器运行 worker）",
    fix: "",
  };
}

/**
 * 个人 Web 独立网关只读检测（供 `pa doctor` 与 `pa init` 共用）：
 *   - `personalWeb`：检查开关、端点、只读/回复令牌（含 `<data_dir>/gateway.env` 权限安全）、在线连通性与账号绑定；
 *   - `boundary`：检查 `send_replies` 与 `reply_token` 的同用户隔离风险。
 */
export async function inspectPersonalWebGateway(
  app: App,
  opts: { env?: NodeJS.ProcessEnv; timeoutMs?: number } = {},
): Promise<PersonalWebInspection> {
  const { cfg } = app;
  const env = opts.env ?? process.env;
  const timeoutMs = opts.timeoutMs ?? 3_000;
  const pwCfg = cfg.context.personal_web;

  if (!cfg.context.enabled || !pwCfg.enabled) {
    return {
      personalWeb: {
        status: "skip",
        detail: "未启用（当前仅走 lark-cli 定时采集）",
        fix: `如需秒级响应任意群 @我 与私聊，请先以独立进程/用户部署 ${backtick("bin/feishu-gateway")}（${backtick("feishu-gateway login")} + ${backtick("feishu-gateway run")}），再运行 ${backtick("bin/pa context web-setup")} 自动接入，或手动在 ${backtick("config.yaml")} 中配置 ${backtick("context.personal_web.gateway_socket")}（或 ${backtick("gateway_url")}）并将 ${backtick("enabled")} 设为 true`,
      },
      boundary: inspectPersonalWebBoundary(app, env),
    };
  }

  const resolved = resolveGatewayClientConfig(pwCfg, env, { dataDir: cfg.dataDir });
  const readEnvRaw = pwCfg.read_token_env.trim();
  const replyEnvRaw = pwCfg.reply_token_env.trim();
  const readEnv = readEnvRaw || "FEISHU_GW_READ_TOKEN";
  const replyEnv = replyEnvRaw || "FEISHU_GW_REPLY_TOKEN";
  const envFileLabel = resolved.envFilePath ?? gatewayEnvFilePath(cfg.dataDir);
  const boundary = inspectPersonalWebBoundary(app, env, resolved);

  if (!resolved.socketPath && !resolved.baseUrl) {
    return {
      personalWeb: {
        status: "fail",
        detail: "已启用个人 Web 通道但未配置网关地址",
        fix: `运行 ${backtick("bin/pa context web-setup")} 自动写入，或在 ${backtick("config.yaml")} 中配置 ${backtick("context.personal_web.gateway_socket")} 或回环 ${backtick("gateway_url")}`,
      },
      boundary,
      resolved,
    };
  }

  if (!resolved.readToken) {
    const fileWarn = resolved.envFileError ? `；且 ${resolved.envFileError}` : "";
    const fileHint = formatEnvFileFixHint(resolved, envFileLabel);
    const prefixHint = fileHint ? `${fileHint}；或` : "";
    const envNameDesc = readEnvRaw
      ? `环境变量 ${readEnv}、systemd 凭据与 ${GATEWAY_ENV_FILENAME} 均未提供有效令牌`
      : `config.yaml 中 read_token_env 为空且 systemd 凭据未提供只读令牌`;
    return {
      personalWeb: {
        status: "fail",
        detail: `缺少网关只读令牌（${envNameDesc}${fileWarn}）`,
        fix: `${prefixHint}单机部署运行 ${backtick("bin/pa context web-setup")} 自动配置并同步只读令牌到 ${backtick(envFileLabel)}（或运行 ${backtick("bin/feishu-gateway tokens")} 获取 read_token）；systemd ${backtick("LoadCredential")} 部署请查看 ${backtick("/etc/feishu-gateway/secrets/read-token")} 并在运行 Avatar 前导出环境变量 ${backtick(readEnv)}`,
      },
      boundary,
      resolved,
    };
  }

  if (resolved.replyToken && resolved.readToken === resolved.replyToken) {
    return {
      personalWeb: {
        status: "fail",
        detail: "安全约束违规：read_token 与 reply_token 相同",
        fix: `为 ${backtick(readEnv)} 与 ${backtick(replyEnv)} 配置各自独立的令牌`,
      },
      boundary,
      resolved,
    };
  }

  if (pwCfg.send_replies && !resolved.replyToken) {
    const fileWarn = resolved.envFileError ? `；且 ${resolved.envFileError}` : "";
    const fileHint = formatEnvFileFixHint(resolved, envFileLabel);
    const prefixHint = fileHint ? `${fileHint}；或` : "";
    const replyNameDesc = replyEnvRaw
      ? `${replyEnv} 未在环境变量、systemd 凭据或 ${GATEWAY_ENV_FILENAME} 中配置`
      : `config.yaml 中 reply_token_env 为空且 systemd 凭据未提供回复令牌`;
    return {
      personalWeb: {
        status: "fail",
        detail: `已开启 send_replies 但缺少回复令牌（${replyNameDesc}${fileWarn}）`,
        fix: `${prefixHint}运行 ${backtick("bin/pa context web-setup --with-reply")} 同步回复令牌，或在运行 Avatar 前导出 ${backtick(replyEnv)}（文件模式来自 ${backtick("bin/feishu-gateway tokens")}，systemd 部署见 ${backtick("/etc/feishu-gateway/secrets/reply-token")}），或关闭 ${backtick("context.personal_web.send_replies")}`,
      },
      boundary,
      resolved,
    };
  }

  let client: FeishuGatewayClient;
  try {
    client = createGatewayClientForConfig(pwCfg, env, { dataDir: cfg.dataDir });
  } catch (e) {
    return {
      personalWeb: {
        status: "fail",
        detail: `个人 Web 网关配置无效：${errMsg(e)}`,
        fix: `检查 ${backtick("config.yaml")} 中的 ${backtick("context.personal_web")} 地址与令牌配置`,
      },
      boundary,
      resolved,
    };
  }

  const tokenSourceDesc = `令牌来源：${formatTokenSourceLabel(resolved.readTokenSource)}`;
  try {
    const st = await client.status({ timeoutMs });
    if (st.owner_id) {
      try {
        verifyGatewayOwnerForWorkspace(app, st.owner_id);
      } catch (e) {
        return {
          personalWeb: {
            status: "fail",
            detail: errMsg(e),
            fix: `确认 ${resolved.endpointLabel} 指向正确的网关实例；如网关已通过 ${backtick("--force-switch-account")} 切换账号，请运行 ${backtick("pa context web-unbind")} 解除当前工作区旧绑定`,
          },
          boundary,
          resolved,
        };
      }
    }
    if (st.credential_status === "missing_key") {
      return {
        personalWeb: {
          status: "fail",
          detail: `网关缺少凭据解密密钥（${resolved.endpointLabel}）`,
          fix: `在网关侧配置 ${backtick("FEISHU_GW_KEY")}（或 systemd ${backtick("LoadCredential=feishu-gw-key:...")}）并重启网关`,
        },
        boundary,
        resolved,
      };
    }
    if (st.credential_status === "plaintext_rejected" || st.credential_status === "invalid") {
      return {
        personalWeb: {
          status: "fail",
          detail: `网关凭据异常（${st.credential_status}）：${st.last_error || "解密失败"}`,
          fix: `在网关侧核对 ${backtick("FEISHU_GW_KEY")} 或重新运行 ${backtick("bin/feishu-gateway login")}`,
        },
        boundary,
        resolved,
      };
    }
    if (!st.logged_in || st.state === "needs_login") {
      return {
        personalWeb: {
          status: "warn",
          detail: `网关在线但尚未登录或会话已失效（${st.last_error || st.credential_status}）`,
          fix: `在网关侧运行 ${backtick("bin/feishu-gateway login")} 使用本人飞书 App 扫码登录`,
        },
        boundary,
        resolved,
      };
    }
    if (pwCfg.send_replies && !st.allow_reply) {
      return {
        personalWeb: {
          status: "warn",
          detail: `网关已连接（${st.owner_name || st.owner_id}，${st.state}），但网关侧 allow_reply 为 false，无法发送回复`,
          fix: `如需走个人 Web 发送回复，请在网关 ${backtick("gateway.yaml")} 中显式设置 ${backtick("allow_reply: true")} 并重启网关`,
        },
        boundary,
        resolved,
      };
    }
    if (resolved.envFileError) {
      const fixHint = formatEnvFileFixHint(resolved, envFileLabel);
      return {
        personalWeb: {
          status: "warn",
          detail: `${st.owner_name || st.owner_id}（${resolved.endpointLabel}，${tokenSourceDesc}，状态：${st.state}），但本地凭据文件异常：${resolved.envFileError}`,
          fix: `${fixHint}，或删除不需要的 ${backtick(envFileLabel)}`,
        },
        boundary,
        resolved,
      };
    }
    return {
      personalWeb: {
        status: "ok",
        detail: `${st.owner_name || st.owner_id}（${resolved.endpointLabel}，${tokenSourceDesc}，状态：${st.state}，缓存 seq ${st.latest_seq}）`,
        fix: "",
      },
      boundary,
      resolved,
    };
  } catch (e) {
    if (e instanceof GatewayHttpError && (e.statusCode === 401 || e.statusCode === 403)) {
      return {
        personalWeb: {
          status: "fail",
          detail: `网关鉴权失败（${e.code}，${tokenSourceDesc}）：${e.message}`,
          fix: `运行 ${backtick("bin/pa context web-setup")} 同步最新 read_token，或核对 ${backtick(readEnv)} 是否与网关当前生效的 read_token 一致（文件模式运行 ${backtick("bin/feishu-gateway tokens")}，systemd ${backtick("LoadCredential")} 部署请核对 ${backtick("/etc/feishu-gateway/secrets/read-token")}）`,
        },
        boundary,
        resolved,
      };
    }
    return {
      personalWeb: {
        status: "warn",
        detail: `无法连接到个人 Web 网关 ${resolved.endpointLabel}（${tokenSourceDesc}）：${errMsg(e)}（期间由每 10 分钟的飞书轮询兜底）`,
        fix: `确认独立网关正在运行（${backtick("bin/feishu-gateway run")}）且当前用户对 socket 有访问权限`,
      },
      boundary,
      resolved,
    };
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
    return createGatewayClientForConfig(this.cfg.context.personal_web, process.env, { dataDir: this.cfg.dataDir });
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
      const ownerChanged = !!st.owner_id && !!this.state.owner_id && st.owner_id !== this.state.owner_id;
      this.persistState({
        state: st.state,
        logged_in: st.logged_in,
        owner_id: st.owner_id || this.state.owner_id,
        owner_name: ownerChanged ? st.owner_name : st.owner_name || this.state.owner_name,
        since: st.since || Date.now(),
        last_message_at: ownerChanged ? st.last_message_at : (st.last_message_at ?? this.state.last_message_at),
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
        const resolved = resolveGatewayClientConfig(this.cfg.context.personal_web, process.env, { dataDir: this.cfg.dataDir });
        if (!resolved.readToken) {
          const extra = resolved.envFileError ? `；${resolved.envFileError}` : "";
          const msg = `缺少网关只读令牌（请运行 pa context web-setup，或设置环境变量 ${this.cfg.context.personal_web.read_token_env || "FEISHU_GW_READ_TOKEN"} / systemd LoadCredential${extra}）`;
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
      this.cfg.context.groups_deny.some((d) => {
        const r = d.trim();
        if (!r || idOnly(r)) return false;
        return r.startsWith("oc_") ? !!this.openGroupName(r) : true;
      }) ||
      this.store.mutedConvs().some((m) => {
        if (m.conv.startsWith("pw_chat:")) return false;
        return !!realConvName(m.name) || (m.conv.startsWith("oc_") && !!this.openGroupName(m.conv));
      })
    );
  }

  /**
   * 交给网关在发送前用实时会话名核对的规则：
   *   - `rules`（子串关键字 / ID）：groups_deny 非 oc_ 规则与静音会话的 pw_chat: ID；
   *   - `exactNames`（精确匹配，不做子串）：oc_ 反查群名与静音会话真实名称（避免静音私聊“张三”误拦“张三的评审群”）。
   */
  private clientDenyRules(): { rules: string[]; exactNames: string[] } {
    const rules = new Set<string>();
    const exactNames = new Set<string>();
    const addOcName = (oc: string) => {
      const name = this.openGroupName(oc);
      if (name) exactNames.add(name);
    };
    for (const raw of this.cfg.context.groups_deny) {
      const r = raw.trim();
      if (!r) continue;
      if (r.startsWith("oc_")) addOcName(r);
      else rules.add(r);
    }
    for (const m of this.store.mutedConvs()) {
      if (m.conv.startsWith("pw_chat:")) rules.add(m.conv);
      if (m.conv.startsWith("oc_")) addOcName(m.conv);
      const name = realConvName(m.name);
      if (name) exactNames.add(name);
    }
    return {
      rules: [...rules].filter((r) => r.length <= MAX_CLIENT_DENY_RULE_LEN).slice(0, MAX_CLIENT_DENY_RULES),
      exactNames: [...exactNames].filter((r) => r.length <= MAX_CLIENT_DENY_RULE_LEN).slice(0, MAX_CLIENT_DENY_RULES),
    };
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
   * 解析个人 Web 会话的已知真实名称（按优先级）：
   *   1. 网关本次返回的实时会话名（群改名时以最新名称为准）；
   *   2. `ctx_pw_alias('chat_name', chatId)` 已持久化的真实会话/私聊对端名；
   *   3. 私聊对端发言时查 `ctx_pw_alias('actor', peerActorId)`；
   *   4. 回扫 `pw_chat:<chatId>`（及已映射 `oc_` 会话）最近 20 条观测中第一条真实会话名（跳过“私聊：本人”等占位名）。
   */
  private knownChatName(
    chatId: string,
    kind: GatewayMessagePayload["conversationKind"] = "",
    peerActorId = "",
    liveName = "",
  ): string {
    const live = liveName.trim();
    if (live) return live;
    const aliased = this.store.pwAlias("chat_name", chatId);
    if (aliased) return aliased;
    if (kind === "dm" && peerActorId) {
      const peer = this.store.pwAlias("actor", peerActorId);
      if (peer) return peer;
    }
    const convs = [`pw_chat:${chatId}`];
    const openChat = this.store.pwAlias("chat", chatId);
    if (openChat) convs.push(openChat);
    for (const conv of convs) {
      const recent = this.store.convObs(conv, 0, 20);
      for (let i = recent.length - 1; i >= 0; i--) {
        const name = realConvName(recent[i].conv_name);
        if (name) return name;
        if (!recent[i].is_me && recent[i].meta.chat_type === "p2p" && recent[i].actor_id) {
          const peer = this.store.pwAlias("actor", recent[i].actor_id);
          if (peer) return peer;
        }
      }
    }
    return "";
  }

  /** 处理单条来自独立网关的事件（消息写入或撤回删除）。 */
  async handleGatewayEvent(ev: GatewayEvent): Promise<void> {
    if (ev.kind === "delete") {
      this.store.deleteByNativeMessageId(ev.message_id);
      return;
    }
    this.handleGatewayMessage(ev.message);
  }

  /** 将来自独立网关的归一化消息按 Avatar 业务层规则过滤并落库 `ctx_obs`。 */
  handleGatewayMessage(msg: GatewayMessagePayload): void {
    const obsId = `pw:${msg.id}`;
    const text = msg.text.trim();
    if (!text && msg.resources.length === 0) {
      this.store.deleteByNativeMessageId(msg.id);
      return;
    }

    const ownerId = msg.ownerId || this.state.owner_id;
    const ownerName = this.app.store.get("ctx.owner_name") || msg.ownerName || this.state.owner_name || "我";
    const isMe = !!ownerId && msg.actorId === ownerId;
    const isHuman = msg.senderType === GATEWAY_USER_SENDER_TYPE;

    if (!isHuman && !this.botAllowed(text)) return;

    const chatName =
      msg.chatNameResolved === false && !msg.chatName.trim()
        ? ""
        : this.knownChatName(msg.conversationId, msg.conversationKind, isMe ? "" : msg.actorId, msg.chatName);
    const normalizedChatName = realConvName(chatName);
    if (normalizedChatName) {
      this.store.setPwAlias("chat_name", msg.conversationId, normalizedChatName);
    }
    if (this.isDeniedChat(msg.conversationId, chatName)) return;
    // 仅当网关明确未能核验会话名（chatNameResolved === false）且本地存在按名称排除规则时丢弃；
    // 飞书私聊或未命名群在 readChat 成功返回空名（chatNameResolved === true）时正常放行，避免误丢真实私聊
    if (!chatName && msg.chatNameResolved === false && this.hasNameBasedExclusions()) {
      log("warn", "个人 Web 网关未能解析会话名，无法核对按名称的排除规则，已丢弃", { chat_id: msg.conversationId, message_id: msg.id });
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
    const effectiveConvName = isRealConvName(convName) ? convName : this.knownChatName(anchor.conversationId) || convName;
    if (this.isDeniedChat(anchor.conversationId, effectiveConvName)) return 0;
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
      let resolvedConvName = effectiveConvName;
      for (const m of resp.messages) {
        const isMe = !!ownerId && m.actorId === ownerId;
        const candidate = this.knownChatName(m.conversationId, m.conversationKind, isMe ? "" : m.actorId, m.chatName);
        const real = realConvName(candidate);
        if (real) {
          resolvedConvName = candidate;
          this.store.setPwAlias("chat_name", m.conversationId, real);
          break;
        }
      }
      if (this.isDeniedChat(anchor.conversationId, resolvedConvName)) return 0;
      const bg: Obs[] = [];
      for (const m of resp.messages) {
        if (!m.id || !m.text.trim()) continue;
        const isMe = !!ownerId && m.actorId === ownerId;
        const msgChatName = this.knownChatName(m.conversationId, m.conversationKind, isMe ? "" : m.actorId, m.chatName || resolvedConvName);
        if (this.isDeniedChat(m.conversationId, msgChatName)) continue;
        const displayConvName = msgChatName || resolvedConvName;
        bg.push({
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
        });
      }
      return bg.length ? this.store.addBackgroundObs(bg) : 0;
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
    const knownConvName = this.knownChatName(args.chat_id);
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
    const deny = this.clientDenyRules();
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
        client_deny: deny.rules,
        ...(deny.exactNames.length ? { client_deny_exact: deny.exactNames } : {}),
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
