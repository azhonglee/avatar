import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import YAML from "yaml";
import { z } from "zod";
import type { App } from "../app.ts";
import { ConfigSchema, ROOT, validatePersonalWebConfig } from "../config.ts";
import { FeishuGatewayClient } from "../gateway/client.ts";
import { GatewayConfigSchema } from "../gateway/config.ts";
import { GatewayHttpError, isLoopbackHostname, type GatewayStatus } from "../gateway/protocol.ts";
import { errMsg, expandHome } from "../util.ts";
import {
  GATEWAY_ENV_FILENAME,
  gatewayEnvFilePath,
  readGatewayEnvFile,
  resolveGatewayClientConfig,
  verifyGatewayOwnerForWorkspace,
  writeGatewayEnvFile,
} from "./personal-web.ts";

export type SetupTokenOrigin = "arg" | "file" | "gateway_tokens" | "env" | "credential" | "env_file";

export interface PersonalWebSetupOptions {
  /** 指定网关 gateway.yaml 路径（缺省查找 FEISHU_GW_CONFIG 或 <ROOT>/gateway.yaml） */
  gatewayConfig?: string;
  /** 显式指定网关 Unix Socket 路径（与 url 二选一） */
  socket?: string;
  /** 显式指定网关回环 HTTP 地址（与 socket 二选一） */
  url?: string;
  /** 显式传入只读令牌 */
  readToken?: string;
  /** 从文件读取只读令牌（避免出现在命令行参数/历史记录中） */
  readTokenFile?: string;
  /** 显式开启 send_replies 并同步 reply_token */
  withReply?: boolean;
  /** 显式关闭 send_replies 并从 gateway.env 清理 reply_token */
  noReply?: boolean;
  /** 配合 withReply 显式传入回复令牌 */
  replyToken?: string;
  /** 配合 withReply 从文件读取回复令牌 */
  replyTokenFile?: string;
  /** 追加飞书外网在线会话核验（GET /v1/status?verify=1） */
  verify?: boolean;
  /** 完全跳过网关连通性与鉴权探测，仅校验格式后落盘 */
  noVerify?: boolean;
  /** 测试/自定义环境注入 */
  env?: NodeJS.ProcessEnv;
  timeoutMs?: number;
}

export interface PersonalWebSetupResult {
  configFile: string;
  configChanged: boolean;
  envFile: string;
  endpointLabel: string;
  gatewaySocket: string;
  gatewayUrl: string;
  sendReplies: boolean;
  readTokenEnv: string;
  replyTokenEnv: string;
  readTokenOrigin: SetupTokenOrigin;
  replyTokenStored: boolean;
  replyTokenOrigin?: SetupTokenOrigin;
  removedReplyTokenFromEnvFile: boolean;
  reachable: boolean;
  verifiedOnline: boolean;
  gatewayStatus?: GatewayStatus;
  daemonRunning: boolean;
  warnings: string[];
}

interface ParsedGatewayYaml {
  file: string;
  exists: boolean;
  dataDir: string;
  socket: string;
  url: string;
  allowReply: boolean;
}

function assertNonEmptyOption(value: string | undefined, flag: string): string | undefined {
  if (value === undefined) return undefined;
  const trimmed = value.trim();
  if (!trimmed) throw new Error(`${flag} 不能为空`);
  return trimmed;
}

/**
 * 纯只读解析 `gateway.yaml`（复用 `GatewayConfigSchema`，绝不创建目录或修改磁盘）。
 * 与 `src/gateway/config.ts` 保持相同的校验语义（含 `FEISHU_GW_CONFIG` 必填、`expandHome`、socket/TCP 互斥及回环检查）。
 */
function readGatewayYamlReadOnly(explicitPath: string | undefined, env: NodeJS.ProcessEnv): ParsedGatewayYaml {
  const fromEnv = env.FEISHU_GW_CONFIG?.trim();
  const rawFile = explicitPath || fromEnv || path.join(ROOT, "gateway.yaml");
  const file = path.resolve(expandHome(rawFile));
  const required = Boolean(explicitPath || fromEnv);

  const defaults: ParsedGatewayYaml = {
    file,
    exists: false,
    dataDir: path.resolve(expandHome("~/.feishu-gateway")),
    socket: "~/.feishu-gateway/run/gateway.sock",
    url: "",
    allowReply: false,
  };

  let rawText: string;
  try {
    rawText = fs.readFileSync(file, "utf8");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT" && !required) return defaults;
    throw new Error(`无法读取网关配置文件 ${file}：${errMsg(e)}`);
  }

  let raw: unknown;
  try {
    raw = YAML.parse(rawText) ?? {};
  } catch (e) {
    throw new Error(`网关配置文件 ${file} 语法错误：${errMsg(e)}`);
  }
  const parsed = GatewayConfigSchema.safeParse(raw);
  if (!parsed.success) {
    throw new Error(`网关配置文件 ${file} 有误：\n${z.prettifyError(parsed.error)}`);
  }
  const cfg = parsed.data;
  const socketRaw = cfg.listen.socket.trim();
  const host = cfg.listen.host.trim().replace(/^\[|\]$/g, "");
  const port = cfg.listen.port;
  const useTcp = host.length > 0 || port > 0;

  if (socketRaw && useTcp) {
    throw new Error(`网关配置文件 ${file} 有误：listen.socket 与 listen.host/port 只能二选一`);
  }
  if (!socketRaw && !useTcp) {
    throw new Error(`网关配置文件 ${file} 有误：必须配置 listen.socket 或 listen.host + listen.port 之一`);
  }
  if (useTcp) {
    if (!host || !isLoopbackHostname(host)) {
      throw new Error(`网关配置文件 ${file} 有误：listen.host 仅允许回环地址（127.0.0.1 / localhost / ::1），拒绝：${host || "(空)"}`);
    }
    if (port < 1) {
      throw new Error(`网关配置文件 ${file} 有误：listen.port 必须在 1..65535 之间`);
    }
  }

  const url = useTcp ? `http://${host.includes(":") ? `[${host}]` : host}:${port}` : "";
  return {
    file,
    exists: true,
    dataDir: path.resolve(expandHome(cfg.data_dir)),
    socket: socketRaw,
    url,
    allowReply: cfg.allow_reply,
  };
}

function readTokenFromPlainFile(filePath: string, label: string): string {
  const resolved = path.resolve(expandHome(filePath.trim()));
  const openFlags = fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK ?? 0);
  let fd: number;
  try {
    fd = fs.openSync(resolved, openFlags);
  } catch (e) {
    throw new Error(`无法读取${label}文件 ${resolved}：${errMsg(e)}`);
  }
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) {
      throw new Error(`${label}文件 ${resolved} 不是普通文件`);
    }
    if (st.size > 16 * 1024) {
      throw new Error(`${label}文件 ${resolved} 体积异常，已拒绝读取`);
    }
    const value = fs.readFileSync(fd, "utf8").trim();
    if (!value) throw new Error(`${label}文件 ${resolved} 内容为空`);
    if (/[\r\n\0]/.test(value)) throw new Error(`${label}文件 ${resolved} 包含非法换行或控制字符`);
    return value;
  } finally {
    try {
      fs.closeSync(fd);
    } catch {
      // ignore
    }
  }
}

function readGatewayTokensFileReadOnly(gwDataDir: string): { readToken: string; replyToken: string; file: string; reason?: string } {
  const file = path.join(gwDataDir, "tokens.json");
  const openFlags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0);
  let fd: number;
  try {
    fd = fs.openSync(file, openFlags);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return { readToken: "", replyToken: "", file, reason: `未找到 ${file}` };
    if (code === "EACCES" || code === "EPERM") {
      return { readToken: "", replyToken: "", file, reason: `当前用户无权读取 ${file}（跨用户隔离部署属正常现象）` };
    }
    if (code === "ELOOP" || code === "EISDIR") {
      return { readToken: "", replyToken: "", file, reason: `${file} 不是普通文件` };
    }
    return { readToken: "", replyToken: "", file, reason: `读取 ${file} 失败：${errMsg(e)}` };
  }
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) return { readToken: "", replyToken: "", file, reason: `${file} 不是普通文件` };
    const raw = JSON.parse(fs.readFileSync(fd, "utf8")) as Record<string, unknown>;
    const readToken = typeof raw?.read_token === "string" ? raw.read_token.trim() : "";
    const replyToken = typeof raw?.reply_token === "string" ? raw.reply_token.trim() : "";
    return { readToken, replyToken, file };
  } catch (e) {
    return { readToken: "", replyToken: "", file, reason: `读取 ${file} 失败：${errMsg(e)}` };
  } finally {
    try {
      fs.closeSync(fd);
    } catch {
      // ignore
    }
  }
}

function assertWritableRegularOrAbsent(targetFile: string): void {
  try {
    const existing = fs.lstatSync(targetFile);
    if (existing.isSymbolicLink()) throw new Error(`${targetFile} 是符号链接，拒绝覆盖写入`);
    if (!existing.isFile()) throw new Error(`${targetFile} 不是普通文件，拒绝覆盖写入`);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
  }
}

function writeAtomicTextWithMode(targetFile: string, content: string, mode: number): void {
  assertWritableRegularOrAbsent(targetFile);
  const dir = path.dirname(targetFile);
  const rand = crypto.randomBytes(6).toString("hex");
  const tmp = path.join(dir, `.${path.basename(targetFile)}.${process.pid}.${Date.now()}.${rand}.tmp`);
  const createFlags =
    fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0);
  let fd: number | undefined;
  try {
    fd = fs.openSync(tmp, createFlags, mode);
    fs.fchmodSync(fd, mode);
    fs.writeFileSync(fd, content, "utf8");
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    fs.renameSync(tmp, targetFile);
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
}

function writeConfigAtomicKeepMode(file: string, rawBackup: string, updatedContent: string): void {
  const st = fs.lstatSync(file);
  if (st.isSymbolicLink() || !st.isFile()) {
    throw new Error(`${file} 必须是普通文件，拒绝写入`);
  }
  const mode = st.mode & 0o777;
  writeAtomicTextWithMode(`${file}.bak`, rawBackup, mode);
  writeAtomicTextWithMode(file, updatedContent, mode);
}

function isDaemonRunning(app: App): boolean {
  const hb = app.store.get("daemon.heartbeat");
  if (!hb) return false;
  const idx = hb.lastIndexOf("|");
  if (idx < 0) return false;
  const ms = Number(hb.slice(idx + 1));
  return Number.isFinite(ms) && Date.now() - ms < 60_000;
}

/**
 * 显式接入或更新个人 Web 独立网关配置：
 *   1. 推断/校验网关地址、只读令牌（默认绝不搬运 reply_token，仅 --with-reply 时显式同步）；
 *   2. 预校验 YAML schema 与在线网关鉴权/协议/账号绑定（401/403、404/非网关响应、账号冲突时 fail-fast，不覆盖任何文件）；
 *   3. 原子写入 `0600` 的 `<data_dir>/gateway.env` 并保注释原子更新 `config.yaml`（同步保持 `.bak` 权限）。
 */
export async function runPersonalWebSetup(app: App, opts: PersonalWebSetupOptions = {}): Promise<PersonalWebSetupResult> {
  const env = opts.env ?? process.env;
  const timeoutMs = opts.timeoutMs ?? 5_000;
  const warnings: string[] = [];

  const optGatewayConfig = assertNonEmptyOption(opts.gatewayConfig, "--gateway-config");
  const optSocket = assertNonEmptyOption(opts.socket, "--socket");
  const optUrl = assertNonEmptyOption(opts.url, "--url");
  const optReadToken = assertNonEmptyOption(opts.readToken, "--read-token");
  const optReadTokenFile = assertNonEmptyOption(opts.readTokenFile, "--read-token-file");
  const optReplyToken = assertNonEmptyOption(opts.replyToken, "--reply-token");
  const optReplyTokenFile = assertNonEmptyOption(opts.replyTokenFile, "--reply-token-file");

  if (optSocket && optUrl) {
    throw new Error("--socket 与 --url 只能二选一");
  }
  if (opts.withReply && opts.noReply) {
    throw new Error("--with-reply 与 --no-reply 不能同时指定");
  }
  if (optReadToken && optReadTokenFile) {
    throw new Error("--read-token 与 --read-token-file 只能二选一");
  }
  if (optReplyToken && optReplyTokenFile) {
    throw new Error("--reply-token 与 --reply-token-file 只能二选一");
  }
  if (!opts.withReply && (optReplyToken || optReplyTokenFile)) {
    throw new Error("传入 --reply-token / --reply-token-file 时必须同时指定 --with-reply");
  }
  if (opts.verify && opts.noVerify) {
    throw new Error("--verify 与 --no-verify 不能同时指定");
  }

  const cfgFile = app.cfg.file;
  if (!cfgFile || !fs.existsSync(cfgFile)) {
    throw new Error(`找不到 Avatar 配置文件 ${cfgFile || "（未指定）"}`);
  }

  const curPw = app.cfg.context.personal_web;
  const curReadEnv = curPw.read_token_env.trim();
  const curReplyEnv = curPw.reply_token_env.trim();
  const readEnvName = curReadEnv || "FEISHU_GW_READ_TOKEN";
  const replyEnvName = curReplyEnv || "FEISHU_GW_REPLY_TOKEN";

  // 当用户显式传入 --socket / --url 且未同时传入 --gateway-config 时，视为指向外部/指定端点，
  // 不读取本机默认 gateway.yaml / ~/.feishu-gateway/tokens.json（防止跨用户部署误读旧文件或向非网关服务外泄默认令牌）。
  const explicitEndpointOnly = Boolean((optSocket || optUrl) && !optGatewayConfig);
  const gwYaml = explicitEndpointOnly ? undefined : readGatewayYamlReadOnly(optGatewayConfig, env);

  // 1) 决定目标端点：显式参数 > 显式 --gateway-config > 已有 config.yaml 端点 > 本地 gateway.yaml / 默认值
  let targetSocket = "";
  let targetUrl = "";
  if (optSocket) {
    targetSocket = optSocket;
  } else if (optUrl) {
    targetUrl = optUrl;
  } else if (optGatewayConfig && gwYaml) {
    targetSocket = gwYaml.socket;
    targetUrl = gwYaml.url;
  } else if (curPw.gateway_socket.trim() || curPw.gateway_url.trim()) {
    targetSocket = curPw.gateway_socket.trim();
    targetUrl = curPw.gateway_url.trim();
  } else if (gwYaml) {
    targetSocket = gwYaml.socket;
    targetUrl = gwYaml.url;
  }

  const targetSendReplies = opts.withReply ? true : opts.noReply ? false : curPw.send_replies;

  // 2) 检查现有 gateway.env 与令牌来源
  const existingEnvFile = readGatewayEnvFile(app.cfg.dataDir);
  if (existingEnvFile.status === "unsafe" && existingEnvFile.unsafeKind === "file_type") {
    throw new Error(`拒绝覆盖非普通文件：${existingEnvFile.error}`);
  }
  if (existingEnvFile.status === "unsafe" || existingEnvFile.status === "error") {
    warnings.push(`原有 ${GATEWAY_ENV_FILENAME} 状态异常（${existingEnvFile.error}），本次将重新原子生成 0600 凭据文件`);
  }

  // 解析已有环境变量 / systemd 凭据 / gateway.env（即使用户原配置中 read_token_env 为空，也按目标变量名解析）
  const existingResolved = resolveGatewayClientConfig(
    { ...curPw, read_token_env: readEnvName, reply_token_env: replyEnvName },
    env,
    { dataDir: app.cfg.dataDir },
  );
  // 仅当目标端点与 gwYaml 一致（或显式传入 --gateway-config）时，才从 gwYaml.dataDir 读取 tokens.json 与参考 allow_reply
  const gwSocketAbs = gwYaml?.socket ? path.resolve(expandHome(gwYaml.socket)) : "";
  const targetSocketAbs = targetSocket ? path.resolve(expandHome(targetSocket)) : "";
  const useGwYamlTokens = Boolean(
    gwYaml &&
      (optGatewayConfig ||
        (targetSocketAbs && targetSocketAbs === gwSocketAbs) ||
        (targetUrl && targetUrl === gwYaml.url)),
  );
  const gwTokens = useGwYamlTokens && gwYaml ? readGatewayTokensFileReadOnly(gwYaml.dataDir) : undefined;

  let readToken = "";
  let readTokenOrigin: SetupTokenOrigin | undefined;
  if (optReadTokenFile) {
    readToken = readTokenFromPlainFile(optReadTokenFile, "只读令牌");
    readTokenOrigin = "file";
  } else if (optReadToken) {
    readToken = optReadToken;
    readTokenOrigin = "arg";
  } else if (gwTokens?.readToken) {
    readToken = gwTokens.readToken;
    readTokenOrigin = "gateway_tokens";
  } else if (existingResolved.readToken) {
    readToken = existingResolved.readToken;
    readTokenOrigin = existingResolved.readTokenSource as SetupTokenOrigin;
  }

  if (!readToken) {
    const extra = gwTokens?.reason ? `（${gwTokens.reason}）` : "";
    throw new Error(
      `未能获取到网关只读令牌${extra}。请先运行 bin/feishu-gateway tokens，或通过 --read-token-file <路径>（如 /etc/feishu-gateway/secrets/read-token）/ 环境变量 ${readEnvName} 提供只读令牌`,
    );
  }
  if (/[\r\n\0]/.test(readToken)) {
    throw new Error("只读令牌包含非法控制字符");
  }

  let replyToken = "";
  let replyTokenOrigin: SetupTokenOrigin | undefined;
  const hadReplyInEnvFile = existingEnvFile.status === "ok" && Boolean(existingEnvFile.values[replyEnvName]?.trim());

  if (opts.withReply) {
    if (optReplyTokenFile) {
      replyToken = readTokenFromPlainFile(optReplyTokenFile, "回复令牌");
      replyTokenOrigin = "file";
    } else if (optReplyToken) {
      replyToken = optReplyToken;
      replyTokenOrigin = "arg";
    } else if (gwTokens?.replyToken) {
      replyToken = gwTokens.replyToken;
      replyTokenOrigin = "gateway_tokens";
    } else if (existingResolved.replyToken) {
      replyToken = existingResolved.replyToken;
      replyTokenOrigin = existingResolved.replyTokenSource as SetupTokenOrigin;
    }
    if (!replyToken) {
      throw new Error(
        `已指定 --with-reply，但未获取到回复令牌。请先运行 bin/feishu-gateway tokens，或通过 --reply-token-file <路径> / 环境变量 ${replyEnvName} 提供回复令牌`,
      );
    }
    if (/[\r\n\0]/.test(replyToken)) {
      throw new Error("回复令牌包含非法控制字符");
    }
  } else if (targetSendReplies && hadReplyInEnvFile) {
    // 已启用 send_replies 且仅同步/轮换只读令牌：保留 gateway.env 中原有回复令牌
    replyToken = existingEnvFile.values[replyEnvName].trim();
    replyTokenOrigin = "env_file";
  }

  if (replyToken && replyToken === readToken) {
    throw new Error("安全约束违规：read_token 与 reply_token 的值不能相同");
  }

  // 3) 校验将要写入的 config.yaml 配置合法性（不触碰磁盘）
  const rawConfigText = fs.readFileSync(cfgFile, "utf8");
  const doc = YAML.parseDocument(rawConfigText);
  if (doc.errors.length) {
    throw new Error(`Avatar 配置文件 ${cfgFile} 语法错误：${doc.errors.map((e) => e.message).join("；")}`);
  }
  const setIfNeeded = (key: string, val: unknown, onlyWhenPresentOrNonEmpty = false): void => {
    const curVal = doc.getIn(["context", "personal_web", key]);
    if (onlyWhenPresentOrNonEmpty && curVal === undefined && (val === "" || val === false)) return;
    if (curVal !== val) {
      doc.setIn(["context", "personal_web", key], val);
    }
  };
  setIfNeeded("enabled", true);
  setIfNeeded("gateway_socket", targetSocket, true);
  setIfNeeded("gateway_url", targetUrl, true);
  // 若 config.yaml 曾显式将 read_token_env / reply_token_env 置空，补写回实际写入 gateway.env 的键名，防止运行时读不到
  if (!curReadEnv) setIfNeeded("read_token_env", readEnvName);
  if (replyToken && !curReplyEnv) setIfNeeded("reply_token_env", replyEnvName);
  if (opts.withReply || opts.noReply) {
    setIfNeeded("send_replies", targetSendReplies);
  } else {
    setIfNeeded("send_replies", targetSendReplies, true);
  }

  const parsedNext = ConfigSchema.safeParse(doc.toJS() ?? {});
  if (!parsedNext.success) {
    throw new Error(`更新后的配置文件校验失败：\n${z.prettifyError(parsedNext.error)}`);
  }
  const pwIssues = validatePersonalWebConfig(parsedNext.data.context.personal_web);
  if (pwIssues.length) {
    throw new Error(`个人 Web 网关配置校验失败：\n${pwIssues.map((i) => `- ${i.path}: ${i.message}`).join("\n")}`);
  }

  const resolvedSocketPath = targetSocket ? path.resolve(expandHome(targetSocket)) : undefined;
  const endpointLabel = resolvedSocketPath ? `unix://${resolvedSocketPath}` : targetUrl;

  // 4) 预探测运行中的网关：401/403 鉴权失败、非网关 HTTP 响应（404/invalid_response）或账号冲突时 fail-fast，不覆盖磁盘文件
  let reachable = false;
  let verifiedOnline = false;
  let gatewayStatus: GatewayStatus | undefined;

  if (!opts.noVerify) {
    const client = new FeishuGatewayClient({
      socketPath: resolvedSocketPath,
      baseUrl: targetUrl || undefined,
      readToken,
      replyToken,
    });
    let st: GatewayStatus | undefined;
    try {
      st = await client.status({ verify: false, timeoutMs });
      reachable = true;
      gatewayStatus = st;
    } catch (e) {
      if (e instanceof GatewayHttpError && (e.statusCode === 401 || e.statusCode === 403)) {
        throw new Error(
          `网关鉴权失败（${e.code}）：${e.message}（已中止，未修改配置文件）。` +
            `若网关使用 systemd LoadCredential 或环境变量注入令牌，请改用 --read-token-file <路径> 传入生效的 read_token`,
        );
      }
      if (e instanceof GatewayHttpError && (e.statusCode === 404 || e.code === "invalid_response")) {
        throw new Error(`目标地址 ${endpointLabel} 返回了非网关协议响应（HTTP ${e.statusCode} / ${e.code}）：${e.message}（已中止，未修改配置文件）`);
      }
      if (e instanceof GatewayHttpError && e.code === "account_mismatch") {
        throw new Error(`网关账号绑定冲突：${e.message}（已中止，未修改配置文件）`);
      }
      warnings.push(
        `当前无法连接到网关 ${endpointLabel}（${errMsg(e)}）；配置与凭据已保存，启动 \`bin/feishu-gateway run\` 后请运行 \`bin/pa context web-status --verify\` 验证`,
      );
    }

    if (st) {
      // 在 try/catch 外执行工作区账号绑定校验，冲突时直接 fail-fast
      if (st.owner_id) {
        verifyGatewayOwnerForWorkspace(app, st.owner_id);
      }
      if (st.credential_status === "missing_key") {
        warnings.push("网关缺少解密密钥（FEISHU_GW_KEY / LoadCredential），请在网关侧配置并重启");
      } else if (st.credential_status === "plaintext_rejected" || st.credential_status === "invalid") {
        warnings.push(`网关凭据状态异常（${st.credential_status}）：${st.last_error || "解密失败"}，请核对 FEISHU_GW_KEY 或重新扫码登录`);
      } else if (!st.logged_in || st.state === "needs_login") {
        warnings.push("网关在线但尚未登录，请运行 `bin/feishu-gateway login` 用本人飞书 App 扫码确认");
      }
      if (targetSendReplies && !st.allow_reply) {
        warnings.push("已开启 send_replies，但网关侧 allow_reply 为 false；如需实际发消息，请在 gateway.yaml 设为 allow_reply: true 并重启网关");
      }

      if (opts.verify && st.logged_in) {
        let verifiedSt: GatewayStatus | undefined;
        try {
          verifiedSt = await client.status({ verify: true, timeoutMs: Math.max(timeoutMs, 10_000) });
        } catch (e) {
          if (e instanceof GatewayHttpError && (e.statusCode === 401 || e.statusCode === 403)) {
            throw new Error(`网关在线核验鉴权失败（${e.code}）：${e.message}（已中止，未修改配置文件）`);
          }
          if (e instanceof GatewayHttpError && e.code === "account_mismatch") {
            throw new Error(`网关账号绑定冲突（${e.code}）：${e.message}（已中止，未修改配置文件）`);
          }
          warnings.push(`飞书在线会话核验失败：${errMsg(e)}`);
        }
        if (verifiedSt) {
          if (verifiedSt.owner_id) {
            verifyGatewayOwnerForWorkspace(app, verifiedSt.owner_id);
          }
          gatewayStatus = verifiedSt;
          verifiedOnline = true;
        }
      } else if (opts.verify && !st.logged_in) {
        warnings.push("因网关尚未登录，已跳过飞书在线会话核验");
      }
    }
  }

  // 离线或 --no-verify 场景下，如果目标端点对应本地 gateway.yaml 且 allow_reply=false，仍给出明确提醒
  if (!reachable && targetSendReplies && useGwYamlTokens && gwYaml?.exists && !gwYaml.allowReply) {
    warnings.push(`已开启 send_replies，但 ${gwYaml.file} 中 allow_reply 为 false；如需实际发消息，请将其设为 true 并重启网关`);
  }

  // 5) 写盘前预检 config.yaml / .bak 可写性，防止 gateway.env 已写入而 config.yaml 拒写导致半写状态
  const updatedText = doc.toString();
  const configChanged = updatedText !== rawConfigText;
  if (configChanged) {
    assertWritableRegularOrAbsent(cfgFile);
    assertWritableRegularOrAbsent(`${cfgFile}.bak`);
  }

  // 原子写入 0600 凭据文件与保注释更新 config.yaml
  const envEntries: Record<string, string> = { [readEnvName]: readToken };
  if (replyToken) envEntries[replyEnvName] = replyToken;
  const envFile = writeGatewayEnvFile(app.cfg.dataDir, envEntries);
  const removedReplyTokenFromEnvFile = hadReplyInEnvFile && !replyToken;

  if (configChanged) {
    writeConfigAtomicKeepMode(cfgFile, rawConfigText, updatedText);
  }
  app.cfg.context.personal_web = parsedNext.data.context.personal_web;

  // 运行时配置与环境变量优先级提醒
  if (!parsedNext.data.context.enabled) {
    warnings.push("config.yaml 中 context.enabled 为 false，常驻进程不会启动个人 Web 通道；如需生效请将 context.enabled 设为 true");
  }
  if (targetSendReplies && !replyToken && !existingResolved.replyToken) {
    warnings.push(
      `config.yaml 中 send_replies 为 true，但未找到回复令牌（${replyEnvName}）；请运行 \`bin/pa context web-setup --with-reply\` 同步，或运行 \`bin/pa context web-setup --no-reply\` 关闭回复`,
    );
  }
  const envReadOverride = env[readEnvName]?.trim();
  if (envReadOverride && envReadOverride !== readToken) {
    warnings.push(
      `当前 shell 环境变量 ${readEnvName} 的值与刚写入 ${gatewayEnvFilePath(app.cfg.dataDir)} 的新令牌不同，且环境变量优先级更高；请执行 \`unset ${readEnvName}\` 或更新它`,
    );
  }
  if (!targetSendReplies && env[replyEnvName]?.trim()) {
    warnings.push(`当前 shell 环境中仍存在 ${replyEnvName}，建议执行 \`unset ${replyEnvName}\` 避免向 Avatar 暴露回复令牌`);
  }

  return {
    configFile: cfgFile,
    configChanged,
    envFile,
    endpointLabel,
    gatewaySocket: targetSocket,
    gatewayUrl: targetUrl,
    sendReplies: targetSendReplies,
    readTokenEnv: readEnvName,
    replyTokenEnv: replyEnvName,
    readTokenOrigin: readTokenOrigin!,
    replyTokenStored: Boolean(replyToken),
    replyTokenOrigin,
    removedReplyTokenFromEnvFile,
    reachable,
    verifiedOnline,
    gatewayStatus,
    daemonRunning: isDaemonRunning(app),
    warnings,
  };
}
