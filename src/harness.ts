import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { ROOT, type Config } from "./config.ts";
import type { Profile } from "./guard.ts";
import { isPlainTable, parseToml, parseTomlKeyPath, parseTomlValue, type TomlTable, type TomlValue } from "./toml.ts";
import { runProcess } from "./util.ts";

const FEISHU_WEB_KEY_CRED = "feishu-web-key";
/** Linux kernel tmpfs magic number (`linux/magic.h`: `TMPFS_MAGIC`). */
const LINUX_TMPFS_MAGIC = 0x01021994;

type MountMaskBackend =
  | { kind: "bwrap"; bin: string }
  | { kind: "unshare"; bin: string; setprivBin: string }
  | { kind: "none" };
let cachedMountMaskBackend: MountMaskBackend | undefined;

function probeMountMaskBackend(): MountMaskBackend {
  if (cachedMountMaskBackend) return cachedMountMaskBackend;
  try {
    const bwrapBin = resolveBin("bwrap");
    const r = spawnSync(
      bwrapBin,
      ["--die-with-parent", "--dev-bind", "/", "/", "--unshare-pid", "--proc", "/proc", "--", "true"],
      { timeout: 3_000, stdio: "ignore" },
    );
    if (r.status === 0) {
      cachedMountMaskBackend = { kind: "bwrap", bin: bwrapBin };
      return cachedMountMaskBackend;
    }
  } catch {
    // 尝试 unshare + setpriv 降权回退
  }
  try {
    const unshareBin = resolveBin("unshare");
    const setprivBin = resolveBin("setpriv");
    const r = spawnSync(
      unshareBin,
      [
        "--user",
        "--map-root-user",
        "--mount",
        "--pid",
        "--fork",
        "--mount-proc",
        "--",
        setprivBin,
        "--bounding-set",
        "-all",
        "--inh-caps",
        "-all",
        "--ambient-caps",
        "-all",
        "--no-new-privs",
        "true",
      ],
      { timeout: 3_000, stdio: "ignore" },
    );
    if (r.status === 0) {
      cachedMountMaskBackend = { kind: "unshare", bin: unshareBin, setprivBin };
      return cachedMountMaskBackend;
    }
  } catch {
    // 均不可用
  }
  cachedMountMaskBackend = { kind: "none" };
  return cachedMountMaskBackend;
}

/** 探测当前宿主机是否具备零特权 PID + 挂载命名空间隔离能力（bwrap --unshare-pid --proc /proc 或 unshare --pid --mount-proc + setpriv 永久降权） */
export function hasCredentialMountIsolation(): boolean {
  return probeMountMaskBackend().kind !== "none";
}

/**
 * 为模型执行器、仓库校验命令、git 子进程等同 UID 不可信子进程提供内核级进程与文件系统隔离：
 *   - 当服务持有 `CREDENTIALS_DIRECTORY/feishu-web-key`（systemd LoadCredentialEncrypted）或 `PA_FEISHU_WEB_KEY`（EnvironmentFile/环境变量）时，
 *     仅从子进程环境变量剥离仍无法阻止同 UID 子进程读取密钥文件或通过宿主机 `/proc/<daemon-pid>/{environ,root,mem}` 探测常驻进程；
 *   - 本函数优先用 `bwrap --unshare-pid --proc /proc [--bind /dev/null <keyFile>]`（独立 PID 命名空间 + 干净 `/proc` 隐藏常驻进程，
 *     并遮罩密钥文件，零特权且 NoNewPrivs）；
 *   - 回退用 `unshare --user --map-root-user --mount --pid --fork --mount-proc` 完成遮罩后，立即通过 `setpriv --bounding-set -all ... --no-new-privs`
 *     永久剥离挂载与提权能力再 exec 目标命令；
 *   - 若宿主机不支持 PID + 挂载命名空间隔离，按 fail-closed 拒绝启动子进程。
 */
export function wrapCredentialIsolatedCommand(
  cmd: string,
  args: string[],
  rawEnv: NodeJS.ProcessEnv = process.env,
  opts?: { forceBackend?: MountMaskBackend },
): { cmd: string; args: string[]; isolated: boolean } {
  const credDir = rawEnv.CREDENTIALS_DIRECTORY?.trim();
  const keyFile = credDir ? path.join(credDir, FEISHU_WEB_KEY_CRED) : "";
  const hasCredKeyFile = !!keyFile && fs.existsSync(keyFile);
  const hasEnvKey = !!(rawEnv.PA_FEISHU_WEB_KEY?.trim());
  if (!hasCredKeyFile && !hasEnvKey) return { cmd, args, isolated: false };

  const resolvedKeyFile = hasCredKeyFile
    ? (() => {
        try {
          return fs.realpathSync(keyFile);
        } catch {
          return path.resolve(keyFile);
        }
      })()
    : "";

  const backend = opts?.forceBackend ?? probeMountMaskBackend();
  if (backend.kind === "bwrap") {
    const maskArgs: string[] = ["--die-with-parent", "--dev-bind", "/", "/", "--unshare-pid", "--proc", "/proc"];
    if (hasCredKeyFile) {
      maskArgs.push("--bind", "/dev/null", path.resolve(keyFile));
      if (resolvedKeyFile && resolvedKeyFile !== path.resolve(keyFile)) {
        maskArgs.push("--bind", "/dev/null", resolvedKeyFile);
      }
    }
    return { cmd: backend.bin, args: [...maskArgs, "--", cmd, ...args], isolated: true };
  }
  if (backend.kind === "unshare") {
    if (!backend.setprivBin) {
      throw new Error("unshare 回退缺少 setpriv，无法在启动子命令前永久剥离挂载权限，已按安全策略拒绝执行");
    }
    const unshareBase = ["--user", "--map-root-user", "--mount", "--pid", "--fork", "--mount-proc", "--"];
    if (!hasCredKeyFile) {
      return {
        cmd: backend.bin,
        args: [
          ...unshareBase,
          backend.setprivBin,
          "--bounding-set",
          "-all",
          "--inh-caps",
          "-all",
          "--ambient-caps",
          "-all",
          "--no-new-privs",
          cmd,
          ...args,
        ],
        isolated: true,
      };
    }
    const maskTargets =
      resolvedKeyFile && resolvedKeyFile !== path.resolve(keyFile) ? [path.resolve(keyFile), resolvedKeyFile] : [path.resolve(keyFile)];
    // 严格兼容 POSIX sh：在独立 PID+Mount 命名空间完成 bind-mount 遮罩后立刻用 setpriv 永久清空全部 capabilities 并置 NoNewPrivs
    const script =
      maskTargets.length === 2
        ? 'mount --bind /dev/null "$1" && mount --bind /dev/null "$2" && sp="$3" && shift 3 && exec "$sp" --bounding-set -all --inh-caps -all --ambient-caps -all --no-new-privs "$@"'
        : 'mount --bind /dev/null "$1" && sp="$2" && shift 2 && exec "$sp" --bounding-set -all --inh-caps -all --ambient-caps -all --no-new-privs "$@"';
    return { cmd: backend.bin, args: [...unshareBase, "sh", "-c", script, "_", ...maskTargets, backend.setprivBin, cmd, ...args], isolated: true };
  }
  throw new Error(
    "检测到当前环境持有个人 Web 加密密钥（CREDENTIALS_DIRECTORY/feishu-web-key 或 PA_FEISHU_WEB_KEY），" +
      "但宿主机不支持 bwrap 或带 setpriv 降权的 unshare PID+挂载命名空间隔离；" +
      "为防止同 UID 子进程读取密钥文件或通过 /proc/<daemon-pid> 检查常驻进程，已拒绝执行。请安装 bubblewrap 或将不可信 worker 运行在独立 OS 用户身份下。",
  );
}

/** 检测目录是否位于易失性内存文件系统（tmpfs），绝不把无关 systemd 凭据复制到磁盘介质的 /tmp */
function findVolatileTmpfsBase(env: NodeJS.ProcessEnv, overrideCandidates?: string[]): string | undefined {
  const candidates = (overrideCandidates ?? [env.XDG_RUNTIME_DIR?.trim(), "/dev/shm"]).filter((d): d is string => !!d);
  for (const dir of candidates) {
    try {
      const st = fs.statfsSync(dir);
      if (st.type === LINUX_TMPFS_MAGIC) {
        fs.accessSync(dir, fs.constants.W_OK | fs.constants.X_OK);
        return dir;
      }
    } catch {
      // 跳过不可访问或非 tmpfs 目录
    }
  }
  return undefined;
}

/**
 * 构造传给子模型或仓库校验进程的基础环境：
 *   - 始终剥离所有 `PA_FEISHU_WEB_*` 环境变量（凭据路径与静态加密密钥）；
 *   - 若 `CREDENTIALS_DIRECTORY` 不包含 `feishu-web-key`，原样保留（不破坏无关的 systemd 凭据）；
 *   - 若 `CREDENTIALS_DIRECTORY` 仅包含 `feishu-web-key`，直接移除 `CREDENTIALS_DIRECTORY`；
 *   - 若 `CREDENTIALS_DIRECTORY` 同时包含 `feishu-web-key` 与无关凭据：
 *     仅在检测到内核级内存 tmpfs（`$XDG_RUNTIME_DIR` 或 `/dev/shm`）时，将无关凭据以 0400 投影到 0700 易失目录并在结束及进程退出时清理；
 *     绝不将任何无关凭据落盘写入磁盘 `os.tmpdir()`（无可用 tmpfs 时按安全策略移除 `CREDENTIALS_DIRECTORY`）。
 */
export function prepareHarnessEnv(
  env: NodeJS.ProcessEnv = process.env,
  opts?: { tmpfsCandidates?: string[] },
): { env: NodeJS.ProcessEnv; cleanup: () => void } {
  const clean: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(env)) {
    if (k.startsWith("PA_FEISHU_WEB_")) continue;
    clean[k] = v;
  }
  const credDir = env.CREDENTIALS_DIRECTORY?.trim();
  if (!credDir) return { env: clean, cleanup: () => undefined };

  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(credDir, { withFileTypes: true });
  } catch {
    if (fs.existsSync(path.join(credDir, FEISHU_WEB_KEY_CRED))) {
      delete clean.CREDENTIALS_DIRECTORY;
    }
    return { env: clean, cleanup: () => undefined };
  }

  if (!entries.some((e) => e.name === FEISHU_WEB_KEY_CRED)) {
    return { env: clean, cleanup: () => undefined };
  }

  const others = entries.filter((e) => e.name !== FEISHU_WEB_KEY_CRED);
  if (others.length === 0) {
    delete clean.CREDENTIALS_DIRECTORY;
    return { env: clean, cleanup: () => undefined };
  }

  const volatileBase = findVolatileTmpfsBase(env, opts?.tmpfsCandidates);
  if (!volatileBase) {
    // 无内核级易失 tmpfs 时绝不向磁盘 TMPDIR 复制无关密钥，按 fail-closed 移除 CREDENTIALS_DIRECTORY
    delete clean.CREDENTIALS_DIRECTORY;
    return { env: clean, cleanup: () => undefined };
  }

  const filteredDir = fs.mkdtempSync(path.join(volatileBase, "pa-creds-"));
  fs.chmodSync(filteredDir, 0o700);
  let cleaned = false;
  const cleanup = () => {
    if (cleaned) return;
    cleaned = true;
    process.off("exit", cleanup);
    try {
      fs.rmSync(filteredDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  };
  process.once("exit", cleanup);
  try {
    for (const entry of others) {
      const src = path.join(credDir, entry.name);
      const dst = path.join(filteredDir, entry.name);
      try {
        const st = fs.statSync(src);
        if (st.isFile()) {
          fs.writeFileSync(dst, fs.readFileSync(src), { mode: 0o400 });
        }
      } catch {
        // 跳过不可读或特殊节点
      }
    }
  } catch (err) {
    cleanup();
    throw err;
  }
  clean.CREDENTIALS_DIRECTORY = filteredDir;
  return { env: clean, cleanup };
}

/**
 * 合并 harness.env：仅从过滤后的基础环境展开 `${VAR}`，且禁止通过覆写还原被过滤的 `PA_FEISHU_WEB_*` 或含 `feishu-web-key` 的 `CREDENTIALS_DIRECTORY`。
 */
export function mergeHarnessEnv(
  sanitizedBase: NodeJS.ProcessEnv,
  overrides: Record<string, string>,
  originalCredDir = process.env.CREDENTIALS_DIRECTORY?.trim(),
): NodeJS.ProcessEnv {
  const expanded: NodeJS.ProcessEnv = {};
  const credWasFiltered = !!originalCredDir && sanitizedBase.CREDENTIALS_DIRECTORY !== originalCredDir;
  for (const [k, rawVal] of Object.entries(overrides)) {
    if (k.startsWith("PA_FEISHU_WEB_")) continue;
    const val = rawVal.replace(/\$\{(\w+)\}/g, (_, n: string) => sanitizedBase[n] ?? "");
    if (k === "CREDENTIALS_DIRECTORY") {
      const candidate = val.trim();
      if (!candidate) continue;
      if (credWasFiltered) {
        if (path.resolve(candidate) === path.resolve(originalCredDir)) continue;
        try {
          if (fs.realpathSync(candidate) === fs.realpathSync(originalCredDir)) continue;
        } catch {
          // 路径不存在或不可解析时继续用后续检查兜底
        }
      }
      if (fs.existsSync(path.join(candidate, FEISHU_WEB_KEY_CRED))) continue;
    }
    expanded[k] = val;
  }
  return { ...sanitizedBase, ...expanded };
}

function formatTomlKeySegment(seg: string): string {
  return /^[A-Za-z0-9_-]+$/.test(seg) ? seg : JSON.stringify(seg);
}

function serializeTomlScalar(v: TomlValue): string {
  if (typeof v === "string") return JSON.stringify(v);
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new Error("不支持的非有限数值 TOML 配置");
    return String(v);
  }
  throw new Error("不支持的非标量 TOML 配置值");
}

function serializeTomlInlineValue(v: TomlValue): string {
  if (isPlainTable(v)) {
    const entries = Object.entries(v).map(([k, val]) => `${formatTomlKeySegment(k)}=${serializeTomlInlineValue(val)}`);
    return `{${entries.join(",")}}`;
  }
  if (Array.isArray(v)) {
    return `[${v.map((el) => serializeTomlInlineValue(el)).join(",")}]`;
  }
  return serializeTomlScalar(v);
}

// 对齐 Codex CLI 0.169+ 内置供应商与凭据存储白名单（无需 [model_providers.*]；oss 不是 provider ID）
const BUILTIN_CODEX_PROVIDERS = new Set(["openai", "ollama", "lmstudio", "amazon-bedrock", "gcp"]);
const ALLOWED_CODEX_CREDENTIAL_STORES = new Set(["file", "keyring", "auto", "ephemeral"]);
const SAFE_CODEX_TOP_SCALARS = new Set([
  "model",
  "model_provider",
  "model_reasoning_effort",
  "service_tier",
  "openai_base_url",
  "chatgpt_base_url",
  "oss_provider",
  "cli_auth_credentials_store",
]);
const SAFE_CODEX_EXTRA_SCALARS = [
  "model_reasoning_effort",
  "service_tier",
  "openai_base_url",
  "chatgpt_base_url",
  "oss_provider",
  "cli_auth_credentials_store",
] as const;
const SAFE_CODEX_PROVIDER_SCALARS = new Set([
  "name",
  "base_url",
  "env_key",
  "env_key_instructions",
  "wire_api",
  "requires_openai_auth",
  "request_max_retries",
  "stream_max_retries",
  "stream_idle_timeout_ms",
]);
const SECRET_QUERY_PARAM_RE = /(?:key|token|secret|auth|sig|pass|cred)/i;

function validateSafeCodexUrl(rawUrl: string, label: string): string {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error(`Codex ${label} 不是合法 URL；已中止 tools=none 执行`);
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new Error(`Codex ${label} 仅支持 http/https 协议；已中止 tools=none 执行`);
  }
  if (parsed.username || parsed.password) {
    throw new Error(
      `Codex ${label} 包含内嵌账号/口令（userinfo）；为避免凭据暴露在命令行参数与运行日志中，tools=none 模式拒绝透传，请改用 env_key 或 env_http_headers`,
    );
  }
  for (const [k] of parsed.searchParams) {
    if (SECRET_QUERY_PARAM_RE.test(k)) {
      throw new Error(
        `Codex ${label} 的查询参数 "${k}" 疑似包含凭据；为避免密钥暴露在命令行参数与运行日志中，tools=none 模式拒绝透传，请改用 env_key 或 env_http_headers`,
      );
    }
  }
  if (parsed.hash && SECRET_QUERY_PARAM_RE.test(parsed.hash)) {
    throw new Error(`Codex ${label} 的 URL 片段疑似包含凭据；已中止 tools=none 执行`);
  }
  return rawUrl;
}

function validateSafeScalarValue(key: string, val: TomlValue): TomlValue {
  if (key === "openai_base_url" || key === "chatgpt_base_url") {
    if (typeof val !== "string" || !val.trim()) throw new Error(`Codex ${key} 必须为非空 URL 字符串`);
    return validateSafeCodexUrl(val.trim(), key);
  }
  if (key === "cli_auth_credentials_store") {
    if (typeof val !== "string" || !ALLOWED_CODEX_CREDENTIAL_STORES.has(val)) {
      throw new Error(`Codex cli_auth_credentials_store 仅支持 file / keyring / auto`);
    }
    return val;
  }
  return val;
}

function parseCliConfigAssignment(expr: string): { key: string; value: string } | undefined {
  const eq = expr.indexOf("=");
  if (eq <= 0) return undefined;
  return { key: expr.slice(0, eq).trim(), value: expr.slice(eq + 1).trim() };
}

function parseCliTomlOrLiteral(keyLabel: string, raw: string): TomlValue {
  try {
    return parseTomlValue(raw);
  } catch {
    if (/^[A-Za-z0-9._:/+-]+$/.test(raw)) return raw;
    // 绝不回显原始配置值，防止未加引号的密钥泄漏到日志或错误信息
    throw new Error(`无法解析 Codex -c 键 "${keyLabel}" 的配置值（请检查 TOML 语法或引号）`);
  }
}

function redactCodexLogArgs(args: string[]): string[] {
  return args.map((a) => {
    if (/^(?:--config=)?model_providers\.[^=]+\.(?:http_headers|experimental_bearer_token|query_params)(?:\.[^=]+)?=/.test(a)) {
      return a.replace(/=.*$/, "=<redacted>");
    }
    if (/^(?:--config=)?(?:openai_base_url|chatgpt_base_url|model_providers\.[^=]+\.base_url)=/.test(a) && /[@?]/.test(a)) {
      return a.replace(/=.*$/, "=<redacted-url>");
    }
    return a;
  });
}

export interface SafeCodexProviderConfig {
  /** 从用户 config.toml 提取的安全 `-c` 参数（不含任何静态凭据明文；含点号供应商名以 TOML 内联表编码避免 `-c` 按点切分） */
  args: string[];
  /** 仅通过子进程环境变量传递的静态请求头（由 `env_http_headers` 引用，永不出现在 argv 或运行日志中） */
  extraEnv: Record<string, string>;
  /** 经过白名单校验与凭据环境变量化后的 `extraArgs` */
  sanitizedExtraArgs: string[];
}

/**
 * 为 `codex-exec` 的 `tools: "none"` 模式构造工具隔离参数：
 *   1. 按子进程实际 `CODEX_HOME` / `HOME` 定位 `config.toml`，并用严格 TOML 1.0 解析器解析（拒绝重复键与多行字符串误判）；
 *   2. 保留 `cli_auth_credentials_store`、`model`、`model_provider`、`model_reasoning_effort`、`service_tier`、安全 base_url 等配置；
 *   3. 严格校验 `extraArgs`，拒绝 `--profile`、`--enable`、`-c mcp_servers.*` / `plugins.*` / `hooks.*` / `sandbox_permissions` 及含凭据 URL；
 *   4. 静态 `http_headers`（无论点分表还是内联表 `{ ... }`）与 `experimental_bearer_token` 一律转为子进程环境变量 + `env_http_headers`；
 *   5. 通过 `-c model_providers={<provider>={...}}` 内联表形式下发供应商配置，兼容带点号的供应商名（如 `corp.test`）。
 */
export function extractSafeCodexProviderConfig(
  env: NodeJS.ProcessEnv,
  extraArgs: string[],
  hasExplicitModel: boolean,
): SafeCodexProviderConfig {
  const effectiveHome = env.HOME?.trim() || os.homedir();
  const codexHome = env.CODEX_HOME?.trim() || path.join(effectiveHome, ".codex");
  const configPath = path.join(codexHome, "config.toml");

  const extraEnv: Record<string, string> = {};
  let secretHdrIdx = 0;
  const allocEnvHeaderVar = (headerValue: string): string => {
    const varName = `__PA_CODEX_HDR_${secretHdrIdx++}`;
    extraEnv[varName] = headerValue;
    return varName;
  };

  const sanitizeProviderTable = (providerName: string, obj: TomlTable): TomlTable => {
    const sanitized: TomlTable = Object.create(null) as TomlTable;
    const envHeaders: TomlTable = Object.create(null) as TomlTable;
    const explicitEnvLower = new Set<string>();

    const rawEnvHeaders = obj.env_http_headers;
    if (rawEnvHeaders !== undefined) {
      if (!isPlainTable(rawEnvHeaders)) {
        throw new Error(`Codex [model_providers.${providerName}.env_http_headers] 格式非法，已中止 tools=none 执行`);
      }
      for (const [hk, hv] of Object.entries(rawEnvHeaders)) {
        if (typeof hv !== "string") {
          throw new Error(`Codex env_http_headers.${hk} 必须为环境变量名字符串`);
        }
        explicitEnvLower.add(hk.toLowerCase());
        envHeaders[hk] = hv;
      }
    }

    const rawHttpHeaders = obj.http_headers;
    if (rawHttpHeaders !== undefined) {
      if (!isPlainTable(rawHttpHeaders)) {
        throw new Error(`Codex [model_providers.${providerName}.http_headers] 格式非法，已中止 tools=none 执行`);
      }
      for (const [hk, hv] of Object.entries(rawHttpHeaders)) {
        if (typeof hv !== "string") {
          throw new Error(`Codex http_headers.${hk} 必须为字符串`);
        }
        if (!explicitEnvLower.has(hk.toLowerCase())) {
          envHeaders[hk] = allocEnvHeaderVar(hv);
        }
      }
    }

    const rawBearer = obj.experimental_bearer_token;
    if (rawBearer !== undefined) {
      if (typeof rawBearer !== "string" || !rawBearer) {
        throw new Error(`Codex [model_providers.${providerName}].experimental_bearer_token 格式非法`);
      }
      const hasAuthHdr =
        explicitEnvLower.has("authorization") ||
        (isPlainTable(rawHttpHeaders) && Object.keys(rawHttpHeaders).some((k) => k.toLowerCase() === "authorization"));
      if (!hasAuthHdr) {
        envHeaders.Authorization = allocEnvHeaderVar(`Bearer ${rawBearer}`);
      }
    }

    if (Object.keys(envHeaders).length > 0) {
      sanitized.env_http_headers = envHeaders;
    }

    const rawQuery = obj.query_params;
    if (rawQuery !== undefined) {
      if (!isPlainTable(rawQuery)) {
        throw new Error(`Codex [model_providers.${providerName}.query_params] 格式非法`);
      }
      const qMap: TomlTable = Object.create(null) as TomlTable;
      for (const [qk, qv] of Object.entries(rawQuery)) {
        if (typeof qv !== "string") throw new Error(`Codex query_params.${qk} 必须为字符串`);
        if (SECRET_QUERY_PARAM_RE.test(qk)) {
          throw new Error(
            `Codex [model_providers.${providerName}.query_params] 包含疑似密钥参数 "${qk}"；为避免密钥暴露在命令行参数中，tools=none 模式拒绝透传，请改用 env_key 或 env_http_headers`,
          );
        }
        qMap[qk] = qv;
      }
      if (Object.keys(qMap).length > 0) {
        sanitized.query_params = qMap;
      }
    }

    const rawAws = obj.aws;
    if (rawAws !== undefined) {
      if (!isPlainTable(rawAws)) {
        throw new Error(`Codex [model_providers.${providerName}.aws] 格式非法`);
      }
      const awsMap: TomlTable = Object.create(null) as TomlTable;
      for (const [ak, av] of Object.entries(rawAws)) {
        if (ak !== "profile" && ak !== "region") {
          throw new Error(
            `Codex [model_providers.${providerName}.aws] 包含不受支持的字段 "${ak}"；为防止改变认证方式或引入非白名单凭据设置，tools=none 模式仅保留 aws.profile 与 aws.region`,
          );
        }
        if (typeof av !== "string" || !av.trim()) {
          throw new Error(`Codex [model_providers.${providerName}.aws].${ak} 必须为非空字符串`);
        }
        awsMap[ak] = av;
      }
      if (Object.keys(awsMap).length > 0) {
        sanitized.aws = awsMap;
      }
    }

    for (const [k, v] of Object.entries(obj)) {
      if (k === "http_headers" || k === "env_http_headers" || k === "query_params" || k === "experimental_bearer_token" || k === "aws") continue;
      if (!SAFE_CODEX_PROVIDER_SCALARS.has(k)) {
        if (k === "gcp" || k === "auth" || k === "credentials" || k.includes("token") || k.includes("secret") || k.includes("key")) {
          throw new Error(
            `Codex [model_providers.${providerName}] 包含不受支持的认证/路由字段 "${k}"；为避免静默切换目标账号或认证方式，已中止 tools=none 执行`,
          );
        }
        continue;
      }
      if (k === "base_url") {
        if (typeof v !== "string" || !v.trim()) throw new Error(`Codex [model_providers.${providerName}].base_url 必须为非空 URL 字符串`);
        sanitized.base_url = validateSafeCodexUrl(v.trim(), `model_providers.${providerName}.base_url`);
      } else {
        sanitized[k] = v;
      }
    }
    return sanitized;
  };

  // 1) 严格校验并净化 extraArgs：tools="none" 仅允许模型/供应商/特性禁用参数
  let extraHasModelProvider = false;
  let extraProvider: string | undefined;
  const extraProviderTables = new Map<string, TomlTable>();
  let extraHasModel = hasExplicitModel;
  const sanitizedExtraArgs: string[] = [];

  const ensureExtraProvider = (pName: string): TomlTable => {
    let t = extraProviderTables.get(pName);
    if (!t) {
      t = Object.create(null) as TomlTable;
      extraProviderTables.set(pName, t);
    }
    return t;
  };

  const mergeProviderSubtable = (target: TomlTable, subKey: string, entries: TomlTable) => {
    const existing = target[subKey];
    const sub: TomlTable = isPlainTable(existing) ? existing : (Object.create(null) as TomlTable);
    for (const [k, v] of Object.entries(entries)) sub[k] = v;
    target[subKey] = sub;
  };

  const handleExtraConfigExpr = (expr: string) => {
    const parsed = parseCliConfigAssignment(expr);
    if (!parsed) {
      throw new Error('codex-exec tools="none" 模式拒绝无法解析的 -c 参数（缺少 key=value）');
    }
    const segs = parseTomlKeyPath(parsed.key);
    const val = parseCliTomlOrLiteral(parsed.key, parsed.value);
    if (segs.length === 1 && SAFE_CODEX_TOP_SCALARS.has(segs[0])) {
      const checkedVal = validateSafeScalarValue(segs[0], val);
      if (segs[0] === "model") {
        extraHasModel = true;
      } else if (segs[0] === "model_provider") {
        if (typeof checkedVal !== "string" || !checkedVal) {
          throw new Error("codex-exec extraArgs 中的 model_provider 必须为非空字符串");
        }
        extraHasModelProvider = true;
        extraProvider = checkedVal;
      }
      sanitizedExtraArgs.push("-c", `${formatTomlKeySegment(segs[0])}=${serializeTomlScalar(checkedVal)}`);
      return;
    }
    if (segs.length === 1 && segs[0] === "model_providers") {
      if (!isPlainTable(val)) throw new Error("extraArgs 中的 model_providers 必须为 TOML 内联表");
      for (const [pName, pDef] of Object.entries(val)) {
        if (!isPlainTable(pDef)) throw new Error(`extraArgs model_providers.${pName} 必须为表`);
        const sanitizedP = sanitizeProviderTable(pName, pDef);
        const dst = ensureExtraProvider(pName);
        for (const [fk, fv] of Object.entries(sanitizedP)) {
          if (isPlainTable(fv)) mergeProviderSubtable(dst, fk, fv);
          else dst[fk] = fv;
        }
      }
      return;
    }
    if (segs[0] === "model_providers" && segs.length >= 3) {
      const pName = segs[1];
      const field = segs[2];
      const dst = ensureExtraProvider(pName);
      if (segs.length === 3 && SAFE_CODEX_PROVIDER_SCALARS.has(field)) {
        if (field === "base_url") {
          if (typeof val !== "string" || !val.trim()) throw new Error(`extraArgs model_providers.${pName}.base_url 必须为非空 URL`);
          dst.base_url = validateSafeCodexUrl(val.trim(), `extraArgs model_providers.${pName}.base_url`);
        } else {
          dst[field] = val;
        }
        return;
      }
      if (segs.length === 3 && field === "experimental_bearer_token") {
        if (typeof val !== "string" || !val) throw new Error("experimental_bearer_token 必须为非空字符串");
        mergeProviderSubtable(dst, "env_http_headers", { Authorization: allocEnvHeaderVar(`Bearer ${val}`) });
        return;
      }
      if (field === "http_headers") {
        if (segs.length === 3 && isPlainTable(val)) {
          const mapped: TomlTable = Object.create(null) as TomlTable;
          for (const [hk, hv] of Object.entries(val)) {
            if (typeof hv !== "string") throw new Error(`extraArgs http_headers.${hk} 必须为字符串`);
            mapped[hk] = allocEnvHeaderVar(hv);
          }
          mergeProviderSubtable(dst, "env_http_headers", mapped);
          return;
        }
        if (segs.length === 4 && typeof val === "string") {
          mergeProviderSubtable(dst, "env_http_headers", { [segs[3]]: allocEnvHeaderVar(val) });
          return;
        }
        throw new Error(`extraArgs 中的 model_providers.${pName}.http_headers 格式非法`);
      }
      if (field === "env_http_headers") {
        if (segs.length === 3 && isPlainTable(val)) {
          for (const [hk, hv] of Object.entries(val)) {
            if (typeof hv !== "string") throw new Error(`extraArgs env_http_headers.${hk} 必须为字符串`);
          }
          mergeProviderSubtable(dst, "env_http_headers", val);
          return;
        }
        if (segs.length === 4 && typeof val === "string") {
          mergeProviderSubtable(dst, "env_http_headers", { [segs[3]]: val });
          return;
        }
        throw new Error(`extraArgs 中的 model_providers.${pName}.env_http_headers 格式非法`);
      }
      if (field === "aws") {
        if (segs.length === 3 && isPlainTable(val)) {
          const awsMap: TomlTable = Object.create(null) as TomlTable;
          for (const [ak, av] of Object.entries(val)) {
            if (ak !== "profile" && ak !== "region") {
              throw new Error(`extraArgs model_providers.${pName}.aws 不支持字段 "${ak}"，仅允许 profile 与 region`);
            }
            if (typeof av !== "string" || !av.trim()) {
              throw new Error(`extraArgs model_providers.${pName}.aws.${ak} 必须为非空字符串`);
            }
            awsMap[ak] = av;
          }
          mergeProviderSubtable(dst, "aws", awsMap);
          return;
        }
        if (segs.length === 4 && (segs[3] === "profile" || segs[3] === "region") && typeof val === "string" && val.trim()) {
          mergeProviderSubtable(dst, "aws", { [segs[3]]: val });
          return;
        }
        throw new Error(`extraArgs 中的 model_providers.${pName}.aws 格式或字段不受支持（仅允许 profile 与 region）`);
      }
      if (field === "query_params") {
        if (segs.length === 3 && isPlainTable(val)) {
          for (const [qk, qv] of Object.entries(val)) {
            if (typeof qv !== "string") throw new Error(`extraArgs query_params.${qk} 必须为字符串`);
            if (SECRET_QUERY_PARAM_RE.test(qk)) {
              throw new Error(`extraArgs query_params 包含疑似密钥参数 "${qk}"，tools=none 模式拒绝透传`);
            }
          }
          mergeProviderSubtable(dst, "query_params", val);
          return;
        }
        if (segs.length === 4 && typeof val === "string") {
          if (SECRET_QUERY_PARAM_RE.test(segs[3])) {
            throw new Error(`extraArgs query_params 包含疑似密钥参数 "${segs[3]}"，tools=none 模式拒绝透传`);
          }
          mergeProviderSubtable(dst, "query_params", { [segs[3]]: val });
          return;
        }
        throw new Error(`extraArgs 中的 model_providers.${pName}.query_params 格式非法`);
      }
    }
    throw new Error(
      `codex-exec tools="none" 模式禁止在 extraArgs 中通过 -c 注入非模型/供应商配置（${parsed.key}）；请改用独立无工具 harness 配置`,
    );
  };

  for (let i = 0; i < extraArgs.length; i++) {
    const a = extraArgs[i];
    if (a === "-m" || a === "--model") {
      const next = extraArgs[++i];
      if (!next) throw new Error(`codex-exec extraArgs 中的 ${a} 缺少值`);
      extraHasModel = true;
      sanitizedExtraArgs.push(a, next);
      continue;
    }
    if (a.startsWith("--model=")) {
      extraHasModel = true;
      sanitizedExtraArgs.push(a);
      continue;
    }
    if (a === "--disable") {
      const next = extraArgs[++i];
      if (!next) throw new Error("codex-exec extraArgs 中的 --disable 缺少值");
      sanitizedExtraArgs.push("--disable", next);
      continue;
    }
    if (a.startsWith("--disable=")) {
      sanitizedExtraArgs.push(a);
      continue;
    }
    if (a === "-c" || a === "--config") {
      const next = extraArgs[++i];
      if (!next) throw new Error(`codex-exec extraArgs 中的 ${a} 缺少配置表达式`);
      handleExtraConfigExpr(next);
      continue;
    }
    if (a.startsWith("--config=")) {
      handleExtraConfigExpr(a.slice("--config=".length));
      continue;
    }
    if (a === "-p" || a === "--profile" || a.startsWith("--profile=")) {
      const prof = a.startsWith("--profile=") ? a.slice("--profile=".length) : extraArgs[i + 1] ?? "";
      throw new Error(
        `codex-exec tools="none" 模式已禁用用户配置文件以避免加载 MCP/工具，暂不支持通过 --profile ${prof} 叠加外部配置；请在 config.yaml 的 harnesses.<name> 中直接配置 model 与 -c model_provider=...`,
      );
    }
    throw new Error(
      `codex-exec tools="none" 模式拒绝不支持或不安全的 extraArgs 选项 "${a}"；此模式仅允许模型、供应商及 --disable 参数`,
    );
  }

  // 2) 解析子进程主目录对应的 $CODEX_HOME/config.toml
  const out: string[] = [];
  const mergedProviders: TomlTable = Object.create(null) as TomlTable;

  if (fs.existsSync(configPath)) {
    const rawContent = fs.readFileSync(configPath, "utf8");
    let doc: TomlTable;
    try {
      doc = parseToml(rawContent);
    } catch (err) {
      throw new Error(
        `无法安全解析 Codex 配置文件 (${configPath})：${err instanceof Error ? err.message : "TOML 语法错误"}；为避免将私聊发往默认供应商，已中止 tools=none 执行`,
      );
    }

    const profileRaw = doc.profile;
    if (profileRaw !== undefined) {
      const legacyName = typeof profileRaw === "string" && profileRaw.trim() ? profileRaw.trim() : "<name>";
      throw new Error(
        `Codex 0.169 已废弃 config.toml 中的顶层 profile = "${legacyName}"（请改用 --profile ${legacyName} 与 ${legacyName}.config.toml，或在 config.yaml 中直接配置 model / model_provider）；为避免激活失效配置，已中止 tools=none 执行`,
      );
    }

    const effectiveVal = (key: string): TomlValue | undefined => doc[key];

    const selectedProviderVal = effectiveVal("model_provider");
    if (selectedProviderVal !== undefined && (typeof selectedProviderVal !== "string" || !selectedProviderVal.trim())) {
      throw new Error("Codex config.toml 中的 model_provider 配置非法；为避免将私聊发往默认供应商，已中止执行");
    }
    const selectedProvider = typeof selectedProviderVal === "string" ? selectedProviderVal.trim() : undefined;
    const effectiveProvider = extraProvider ?? selectedProvider ?? "openai";

    const modelVal = effectiveVal("model");
    if (!extraHasModel && modelVal !== undefined) {
      if (typeof modelVal !== "string") throw new Error("Codex config.toml 中的 model 必须为字符串");
      out.push("-c", `model=${JSON.stringify(modelVal)}`);
    }
    for (const scalarKey of SAFE_CODEX_EXTRA_SCALARS) {
      const v = effectiveVal(scalarKey);
      if (v !== undefined) {
        const checked = validateSafeScalarValue(scalarKey, v);
        out.push("-c", `${scalarKey}=${serializeTomlScalar(checked)}`);
      }
    }

    if (selectedProvider && !extraHasModelProvider) {
      out.push("-c", `model_provider=${JSON.stringify(selectedProvider)}`);
    }

    const providersRoot = doc.model_providers;
    if (providersRoot !== undefined && !isPlainTable(providersRoot)) {
      throw new Error("Codex config.toml 中的 model_providers 必须为表；已中止 tools=none 执行");
    }
    const providerObj = isPlainTable(providersRoot) ? providersRoot[effectiveProvider] : undefined;
    if (providerObj !== undefined && !isPlainTable(providerObj)) {
      throw new Error(`Codex config.toml 中的 [model_providers.${effectiveProvider}] 格式非法；已中止执行`);
    }
    if (!providerObj && !BUILTIN_CODEX_PROVIDERS.has(effectiveProvider) && !extraProviderTables.has(effectiveProvider)) {
      throw new Error(
        `Codex config.toml 指定了自定义供应商 "${effectiveProvider}"，但未能解析对应的 [model_providers.${effectiveProvider}] 配置；为避免私聊误发往默认供应商，已中止执行`,
      );
    }
    if (providerObj) {
      mergedProviders[effectiveProvider] = sanitizeProviderTable(effectiveProvider, providerObj);
    }
  }

  // 将 extraArgs 中覆盖的 model_providers 合并进同一个 TOML 内联表（extraArgs 优先），
  // 通过 `-c model_providers={...}` 传给 Codex，彻底兼容带点号的供应商名（如 corp.test）
  for (const [pName, pOverride] of extraProviderTables) {
    const existing = mergedProviders[pName];
    if (isPlainTable(existing)) {
      const combined: TomlTable = Object.create(null) as TomlTable;
      for (const [k, v] of Object.entries(existing)) combined[k] = v;
      for (const [k, v] of Object.entries(pOverride)) {
        if (isPlainTable(v)) mergeProviderSubtable(combined, k, v);
        else combined[k] = v;
      }
      mergedProviders[pName] = combined;
    } else {
      mergedProviders[pName] = pOverride;
    }
  }

  if (Object.keys(mergedProviders).length > 0) {
    out.push("-c", `model_providers=${serializeTomlInlineValue(mergedProviders)}`);
  }

  return { args: out, extraEnv, sanitizedExtraArgs };
}

/** 兼容辅助：仅返回提取后的 `-c` 参数（用于既有单元测试） */
export function extractSafeCodexProviderArgs(
  env: NodeJS.ProcessEnv,
  extraArgs: string[],
  hasExplicitModel: boolean,
): string[] {
  return extractSafeCodexProviderConfig(env, extraArgs, hasExplicitModel).args;
}

export interface HarnessRun {
  harness: string;
  prompt: string;
  cwd: string;
  /**
   * 工具权限（交给 acpx）：
   *   none  —— 拒绝所有工具调用，只要文本输出（分诊）
   *   read  —— 只自动批准读/搜索
   *   write —— 全部批准（worker 在自己的 worktree 里改代码、跑命令）
   */
  tools: "none" | "read" | "write";
  /** agent 调 lark-cli 时的守卫策略，见 guard.ts */
  lark: Profile;
  timeoutSec: number;
  logFile: string;
  /** 中止（取消 / 优雅退出）：结束整个 harness 进程组 */
  signal?: AbortSignal;
  /** harness 进程组启动后回调 pgid，调用方持久化它，崩溃恢复时据此清理遗留进程 */
  onSpawn?: (pgid: number) => void;
  /** 对应的步骤 id（用量记录用） */
  stepId?: number;
}

/**
 * 用量记录器：每次 harness 结束后调用（由用量模块设置），从输出里解析 token 数并写入步骤。
 * 解析失败不影响主流程。
 */
export type UsageRecorder = (run: HarnessRun, out: { stdout: string; stderr: string; code: number }) => void;
let usageRecorder: UsageRecorder | undefined;
export function setUsageRecorder(fn: UsageRecorder | undefined): void {
  usageRecorder = fn;
}

export interface HarnessResult {
  ok: boolean;
  exitCode: number;
  text: string;
  timedOut: boolean;
  aborted: boolean;
}

/** 通过 acpx（ACP）以无头方式调用任一 harness 跑一次性任务，返回最终回复文本。 */
export async function runHarness(cfg: Config, run: HarnessRun): Promise<HarnessResult> {
  const h = cfg.harnesses[run.harness];
  if (!h) throw new Error(`未定义的 harness：${run.harness}`);
  if (h.type === "codex-exec") return runCodexExec(cfg, run, h);
  if (h.type === "doubao-cli") return runDoubaoCli(cfg, run, h);
  const args = ["--cwd", run.cwd, "--format", "quiet", "--timeout", String(run.timeoutSec)];
  args.push(run.tools === "write" ? "--approve-all" : run.tools === "read" ? "--approve-reads" : "--deny-all");
  args.push("--non-interactive-permissions", "deny");
  if (run.tools === "none") args.push("--no-terminal");
  if (h.model) args.push("--model", h.model);
  args.push(...h.extraArgs);
  if (h.agentCommand) args.push("--agent", h.agentCommand, "exec", "--file", "-");
  else args.push(h.agent!, "exec", "--file", "-");

  fs.mkdirSync(run.cwd, { recursive: true });
  // 先解析可执行路径再准备临时凭据环境，确保 resolveBin 异常不会泄漏易失目录
  const realLark = resolveBin(cfg.bins.lark);
  const baseEnv = prepareHarnessEnv();
  const started = new Date().toISOString();
  let r: Awaited<ReturnType<typeof runProcess>>;
  try {
    const env: NodeJS.ProcessEnv = {
      ...mergeHarnessEnv(baseEnv.env, h.env),
      PATH: `${path.join(ROOT, "bin", "guard")}${path.delimiter}${process.env.PATH ?? ""}`,
      PA_GUARD_PROFILE: run.lark,
      PA_OWNER_OPEN_ID: cfg.owner.open_id,
      PA_LARK_REAL: realLark,
      PA_GUARD_LOG: path.join(cfg.dataDir, "logs", "guard.log"),
    };
    const wrapped = wrapCredentialIsolatedCommand(cfg.bins.acpx, args);
    r = await runProcess(wrapped.cmd, wrapped.args, {
      cwd: run.cwd,
      env,
      input: run.prompt,
      // acpx 自己有 --timeout；这里多留 2 分钟兜底，防止进程卡死
      timeoutMs: (run.timeoutSec + 120) * 1000,
      group: true,
      signal: run.signal,
      onSpawn: run.onSpawn,
    });
  } finally {
    baseEnv.cleanup();
  }
  fs.writeFileSync(
    run.logFile,
    [
      `# ${started} harness=${run.harness} tools=${run.tools} lark=${run.lark} cwd=${run.cwd}`,
      `# acpx ${args.join(" ")}`,
      `# exit=${r.code} timedOut=${r.timedOut} aborted=${!!run.signal?.aborted}`,
      "## prompt",
      run.prompt,
      "## stdout",
      r.stdout,
      "## stderr",
      r.stderr,
    ].join("\n"),
  );
  try {
    usageRecorder?.(run, { stdout: r.stdout, stderr: r.stderr, code: r.code });
  } catch {
    // 用量解析失败不影响主流程
  }
  const aborted = !!run.signal?.aborted;
  return { ok: r.code === 0 && !r.timedOut && !aborted, exitCode: r.code, text: r.stdout.trim(), timedOut: r.timedOut, aborted };
}

/** 守卫需要真实 lark-cli 的绝对路径，否则会递归调用自己。 */
export function resolveBin(bin: string): string {
  if (path.isAbsolute(bin)) return bin;
  const guardDir = path.join(ROOT, "bin", "guard");
  for (const dir of (process.env.PATH ?? "").split(path.delimiter)) {
    if (!dir || path.resolve(dir) === guardDir) continue;
    const p = path.join(dir, bin);
    try {
      fs.accessSync(p, fs.constants.X_OK);
      return p;
    } catch {
      // 继续找
    }
  }
  throw new Error(`在 PATH 中找不到 ${bin}`);
}

export function loadPrompt(name: string): string {
  const p = path.isAbsolute(name) ? name : path.join(ROOT, name.includes("/") ? name : `prompts/${name}`);
  return fs.readFileSync(p, "utf8");
}

/**
 * codex-exec：直接调用本机已登录的 codex CLI（只读沙箱、不保存会话），提示词从标准输入传入，
 * 最终回复写到临时文件读回。只用于不需要写权限的任务（理解、起草、审查）；派单执行需要 acpx。
 */
async function runCodexExec(cfg: Config, run: HarnessRun, h: Config["harnesses"][string]): Promise<HarnessResult> {
  if (run.tools === "write") throw new Error(`harness ${run.harness} 是 codex-exec（只读），不能执行需要写权限的任务；请改用 acpx 类型的 harness`);
  const cmd = h.cmd || "codex";
  // tools === "none"（处理不可信聊天文本的理解/起草）：在 dataDir 之外的空临时目录运行并彻底关闭 shell/执行工具与磁盘全读权限，
  // 避免模型经文件系统越界读取 dataDir 下的会话凭据或状态库。
  const isolatedTmp = run.tools === "none" ? fs.mkdtempSync(path.join(os.tmpdir(), "pa-codex-none-")) : undefined;
  const execCwd = isolatedTmp ?? run.cwd;
  if (!isolatedTmp) fs.mkdirSync(execCwd, { recursive: true });
  const outFile = path.join(execCwd, `.codex-last-${process.pid}-${Date.now()}.txt`);
  // -o 用相对 cwd 的文件名：codex 0.169 在部分路径（如经符号链接的家目录）下打开绝对路径会报 "Not a directory"
  const baseEnv = prepareHarnessEnv();
  const started = new Date().toISOString();
  let r: Awaited<ReturnType<typeof runProcess>>;
  let text = "";
  let args: string[] = [];
  try {
    let finalEnv = mergeHarnessEnv(baseEnv.env, h.env);
    args = ["exec", "--skip-git-repo-check", "--sandbox", "read-only", "--ephemeral", "--color", "never", "-o", path.basename(outFile)];
    let extraToPass = h.extraArgs;
    if (run.tools === "none") {
      // 彻底隔离用户配置（包括 ~/.codex/config.toml 中配置的任意 MCP Server / 插件 / 钩子）与执行规则，
      // 仅保留认证与提取后的安全供应商/模型参数；静态 http_headers 改走环境变量引用，并严格过滤 extraArgs。
      const safeCfg = extractSafeCodexProviderConfig(finalEnv, h.extraArgs, !!h.model);
      finalEnv = { ...finalEnv, ...safeCfg.extraEnv };
      extraToPass = safeCfg.sanitizedExtraArgs;
      args.push(
        "--ignore-user-config",
        "--ignore-rules",
        ...safeCfg.args,
        "--disable", "shell_tool",
        "--disable", "unified_exec",
        "--disable", "apps",
        "--disable", "browser_use",
        "--disable", "computer_use",
        "--disable", "view_image",
        "--disable", "image_generation",
        "--disable", "plugins",
        "--disable", "remote_plugin",
        "--disable", "sleep_tool",
        "--disable", "hooks",
        "--disable", "multi_agent",
        "--disable", "code_mode",
        "--disable", "code_mode_host",
        "-c", "sandbox_permissions=[]",
        "-c", 'web_search="disabled"',
      );
    }
    if (h.model) args.push("-m", h.model);
    args.push(...extraToPass, "-");
    const wrapped = wrapCredentialIsolatedCommand(cmd, args);
    r = await runProcess(wrapped.cmd, wrapped.args, {
      cwd: execCwd,
      env: finalEnv,
      input: run.prompt,
      timeoutMs: (run.timeoutSec + 60) * 1000,
      group: true,
      signal: run.signal,
      onSpawn: run.onSpawn,
    });
    try {
      text = fs.readFileSync(outFile, "utf8").trim();
      fs.rmSync(outFile, { force: true });
    } catch {
      text = r.stdout.trim();
    }
  } finally {
    baseEnv.cleanup();
    if (isolatedTmp) fs.rmSync(isolatedTmp, { recursive: true, force: true });
  }
  fs.writeFileSync(
    run.logFile,
    [`# ${started} harness=${run.harness} type=codex-exec tools=${run.tools} cwd=${execCwd}`, `# ${cmd} ${redactCodexLogArgs(args).join(" ")}`, `# exit=${r.code} timedOut=${r.timedOut}`, "## prompt", run.prompt, "## reply", text, "## stderr", r.stderr.slice(-4000)].join("\n"),
  );
  try {
    usageRecorder?.(run, { stdout: r.stdout, stderr: r.stderr, code: r.code });
  } catch {
    // 忽略
  }
  const aborted = !!run.signal?.aborted;
  return { ok: r.code === 0 && !r.timedOut && !aborted, exitCode: r.code, text, timedOut: r.timedOut, aborted };
}

/**
 * doubao-cli：直接调用本机已登录的豆包 CLI（`doubao -p -`，提示词走标准输入），
 * 接通飞书守卫 PATH 与权限档位（write → always_allow，read → ask_risky，none → ask_always）。
 */
async function runDoubaoCli(cfg: Config, run: HarnessRun, h: Config["harnesses"][string]): Promise<HarnessResult> {
  const cmd = h.cmd || "doubao";
  fs.mkdirSync(run.cwd, { recursive: true });
  const perm = run.tools === "write" ? "always_allow" : run.tools === "read" ? "ask_risky" : "ask_always";
  const hasPermOverride = h.extraArgs.some((a) => a === "--permission-mode" || a.startsWith("--permission-mode=") || a === "--dangerously-bypass-approvals-and-sandbox");
  const args = ["-C", run.cwd];
  if (!hasPermOverride) args.push("--permission-mode", perm);
  if (h.model) args.push("--model", h.model);
  args.push(...h.extraArgs, "-p", "-");

  let realLark = cfg.bins.lark;
  try {
    realLark = resolveBin(cfg.bins.lark);
  } catch {
    // run.lark === "none" 时不会执行真实 lark-cli
  }
  const started = new Date().toISOString();
  // Node.js spawn 的 stdio:"pipe" 在 Linux 上是 Unix socketpair（S_IFSOCK），doubao 会报
  // "stdin must be a terminal, pipe or regular file"；写到 0600 临时普通文件以 FD 传入，用完立即删除。
  const promptDir = path.join(cfg.dataDir, "runs");
  fs.mkdirSync(promptDir, { recursive: true });
  const promptFile = path.join(promptDir, `.doubao-in-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}.txt`);
  fs.writeFileSync(promptFile, run.prompt, { mode: 0o600 });
  const fd = fs.openSync(promptFile, "r");
  const baseEnv = prepareHarnessEnv();
  let r: Awaited<ReturnType<typeof runProcess>>;
  try {
    const env: NodeJS.ProcessEnv = {
      ...mergeHarnessEnv(baseEnv.env, h.env),
      DOUBAO_CLI_NO_UPDATE_CHECK: "1",
      PATH: `${path.join(ROOT, "bin", "guard")}${path.delimiter}${process.env.PATH ?? ""}`,
      PA_GUARD_PROFILE: run.lark,
      PA_OWNER_OPEN_ID: cfg.owner.open_id,
      PA_LARK_REAL: realLark,
      PA_GUARD_LOG: path.join(cfg.dataDir, "logs", "guard.log"),
    };
    const wrapped = wrapCredentialIsolatedCommand(cmd, args);
    r = await runProcess(wrapped.cmd, wrapped.args, {
      cwd: run.cwd,
      env,
      stdinFd: fd,
      timeoutMs: (run.timeoutSec + 60) * 1000,
      group: true,
      signal: run.signal,
      onSpawn: run.onSpawn,
    });
  } finally {
    baseEnv.cleanup();
    try {
      fs.closeSync(fd);
    } catch {
      // ignore
    }
    fs.rmSync(promptFile, { force: true });
  }
  const text = r.stdout.trim();
  fs.writeFileSync(
    run.logFile,
    [
      `# ${started} harness=${run.harness} type=doubao-cli tools=${run.tools} lark=${run.lark} cwd=${run.cwd}`,
      `# ${cmd} ${args.join(" ")}`,
      `# exit=${r.code} timedOut=${r.timedOut} aborted=${!!run.signal?.aborted}`,
      "## prompt",
      run.prompt,
      "## stdout",
      r.stdout,
      "## stderr",
      r.stderr.slice(-4000),
    ].join("\n"),
  );
  try {
    usageRecorder?.(run, { stdout: r.stdout, stderr: r.stderr, code: r.code });
  } catch {
    // 忽略
  }
  const aborted = !!run.signal?.aborted;
  return { ok: r.code === 0 && !r.timedOut && !aborted, exitCode: r.code, text, timedOut: r.timedOut, aborted };
}
