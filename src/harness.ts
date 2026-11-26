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
    if (!Number.isFinite(v)) throw new Error(`不支持的 Codex 非有限数值配置：${v}`);
    return String(v);
  }
  throw new Error("不支持的非标量 TOML 配置值");
}

const BUILTIN_CODEX_PROVIDERS = new Set(["openai", "oss"]);
const SAFE_CODEX_TOP_SCALARS = new Set([
  "model",
  "model_provider",
  "model_reasoning_effort",
  "service_tier",
  "openai_base_url",
  "chatgpt_base_url",
  "oss_provider",
]);
const SAFE_CODEX_EXTRA_SCALARS = [
  "model_reasoning_effort",
  "service_tier",
  "openai_base_url",
  "chatgpt_base_url",
  "oss_provider",
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

function parseCliConfigAssignment(expr: string): { key: string; value: string } | undefined {
  const eq = expr.indexOf("=");
  if (eq <= 0) return undefined;
  return { key: expr.slice(0, eq).trim(), value: expr.slice(eq + 1).trim() };
}

function parseCliTomlOrLiteral(raw: string): TomlValue {
  try {
    return parseTomlValue(raw);
  } catch {
    // codex -c 对裸字符串回退为字符串字面量；仅允许无括号/引号/换行的简单字面量，复杂非法表达式仍按 fail-closed 报错
    if (/^[A-Za-z0-9._:/+-]+$/.test(raw)) return raw;
    throw new Error(`无法解析 Codex -c 配置值：${raw.slice(0, 60)}`);
  }
}

function redactCodexLogArgs(args: string[]): string[] {
  return args.map((a) =>
    /^(?:--config=)?model_providers\.[^=]+\.(?:http_headers|experimental_bearer_token|query_params)(?:\.[^=]+)?=/.test(a)
      ? a.replace(/=.*$/, "=<redacted>")
      : a,
  );
}

export interface SafeCodexProviderConfig {
  /** 从用户 config.toml 提取的安全 `-c` 参数（不含任何静态凭据明文） */
  args: string[];
  /** 仅通过子进程环境变量传递的静态请求头（由 `env_http_headers` 引用，永不出现在 argv 或运行日志中） */
  extraEnv: Record<string, string>;
  /** 经过白名单校验与凭据环境变量化后的 `extraArgs` */
  sanitizedExtraArgs: string[];
}

/**
 * 为 `codex-exec` 的 `tools: "none"` 模式构造工具隔离参数：
 *   1. 按子进程实际 `CODEX_HOME` / `HOME` 定位 `config.toml`，并用完整 TOML 1.0 解析器解析（绝不被多行字符串中的 `[...]` 误导）；
 *   2. 严格校验 `extraArgs`，仅放行模型/供应商/禁用特性开关，拒绝 `--profile`、`--enable`、`-c mcp_servers.*` / `plugins.*` / `hooks.*` / `sandbox_permissions` 等；
 *   3. 静态 `http_headers`（无论点分表还是内联表 `{ ... }`）与 `experimental_bearer_token` 一律转为子进程环境变量 + `env_http_headers`，
 *      彻底避免供应商密钥出现在进程参数（argv / ps）或持久化运行日志中；
 *   4. 若配置了自定义供应商、profile 或无法安全解析的 TOML，按 fail-closed 抛错，绝不把私聊误发往默认供应商。
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
  const bindEnvHeader = (pKey: string, headerName: string, headerValue: string, targetArgs: string[]) => {
    const varName = `__PA_CODEX_HDR_${secretHdrIdx++}`;
    extraEnv[varName] = headerValue;
    targetArgs.push("-c", `model_providers.${pKey}.env_http_headers.${formatTomlKeySegment(headerName)}=${JSON.stringify(varName)}`);
  };

  const emitProviderEntries = (providerName: string, obj: TomlTable, targetArgs: string[]) => {
    const pKey = formatTomlKeySegment(providerName);
    const explicitEnvHeaders = new Set<string>();
    const rawEnvHeaders = obj.env_http_headers;
    if (rawEnvHeaders !== undefined) {
      if (!isPlainTable(rawEnvHeaders)) {
        throw new Error(`Codex [model_providers.${providerName}.env_http_headers] 格式非法，已中止 tools=none 执行`);
      }
      for (const [hk, hv] of Object.entries(rawEnvHeaders)) {
        if (typeof hv !== "string") {
          throw new Error(`Codex env_http_headers.${hk} 必须为环境变量名字符串`);
        }
        explicitEnvHeaders.add(hk.toLowerCase());
        targetArgs.push("-c", `model_providers.${pKey}.env_http_headers.${formatTomlKeySegment(hk)}=${JSON.stringify(hv)}`);
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
        // 静态请求头（含内联表与子表）一律走环境变量引用，绝不进入 argv 或日志
        if (!explicitEnvHeaders.has(hk.toLowerCase())) {
          bindEnvHeader(pKey, hk, hv, targetArgs);
        }
      }
    }

    const rawBearer = obj.experimental_bearer_token;
    if (rawBearer !== undefined) {
      if (typeof rawBearer !== "string" || !rawBearer) {
        throw new Error(`Codex [model_providers.${providerName}].experimental_bearer_token 格式非法`);
      }
      const hasAuthHdr =
        explicitEnvHeaders.has("authorization") ||
        (isPlainTable(rawHttpHeaders) && Object.keys(rawHttpHeaders).some((k) => k.toLowerCase() === "authorization"));
      if (!hasAuthHdr) {
        bindEnvHeader(pKey, "Authorization", `Bearer ${rawBearer}`, targetArgs);
      }
    }

    const rawQuery = obj.query_params;
    if (rawQuery !== undefined) {
      if (!isPlainTable(rawQuery)) {
        throw new Error(`Codex [model_providers.${providerName}.query_params] 格式非法`);
      }
      for (const [qk, qv] of Object.entries(rawQuery)) {
        if (typeof qv !== "string") throw new Error(`Codex query_params.${qk} 必须为字符串`);
        if (SECRET_QUERY_PARAM_RE.test(qk)) {
          throw new Error(
            `Codex [model_providers.${providerName}.query_params] 包含疑似密钥参数 "${qk}"；为避免密钥暴露在命令行参数中，tools=none 模式拒绝透传，请改用 env_key 或 env_http_headers`,
          );
        }
        targetArgs.push("-c", `model_providers.${pKey}.query_params.${formatTomlKeySegment(qk)}=${JSON.stringify(qv)}`);
      }
    }

    for (const [k, v] of Object.entries(obj)) {
      if (k === "http_headers" || k === "env_http_headers" || k === "query_params" || k === "experimental_bearer_token") continue;
      if (!SAFE_CODEX_PROVIDER_SCALARS.has(k)) continue;
      targetArgs.push("-c", `model_providers.${pKey}.${formatTomlKeySegment(k)}=${serializeTomlScalar(v)}`);
    }
  };

  // 1) 严格校验并净化 extraArgs：tools="none" 仅允许模型/供应商/特性禁用参数，禁止通过 extraArgs 注入 MCP、工具或放宽沙箱
  let extraHasModelProvider = false;
  let extraProvider: string | undefined;
  const extraProviderDefs = new Set<string>();
  let extraHasModel = hasExplicitModel;
  const sanitizedExtraArgs: string[] = [];

  const handleExtraConfigExpr = (expr: string) => {
    const parsed = parseCliConfigAssignment(expr);
    if (!parsed) {
      throw new Error(`codex-exec tools="none" 模式拒绝无法解析的 -c 参数：${expr.slice(0, 60)}`);
    }
    const segs = parseTomlKeyPath(parsed.key);
    const val = parseCliTomlOrLiteral(parsed.value);
    if (segs.length === 1 && SAFE_CODEX_TOP_SCALARS.has(segs[0])) {
      if (segs[0] === "model") {
        extraHasModel = true;
      } else if (segs[0] === "model_provider") {
        if (typeof val !== "string" || !val) throw new Error("codex-exec extraArgs 中的 model_provider 必须为非空字符串");
        extraHasModelProvider = true;
        extraProvider = val;
      }
      sanitizedExtraArgs.push("-c", `${formatTomlKeySegment(segs[0])}=${serializeTomlScalar(val)}`);
      return;
    }
    if (segs[0] === "model_providers" && segs.length >= 3) {
      const pName = segs[1];
      const field = segs[2];
      const pKey = formatTomlKeySegment(pName);
      extraProviderDefs.add(pName);
      if (segs.length === 3 && SAFE_CODEX_PROVIDER_SCALARS.has(field)) {
        sanitizedExtraArgs.push("-c", `model_providers.${pKey}.${formatTomlKeySegment(field)}=${serializeTomlScalar(val)}`);
        return;
      }
      if (segs.length === 3 && field === "experimental_bearer_token") {
        if (typeof val !== "string" || !val) throw new Error("experimental_bearer_token 必须为非空字符串");
        bindEnvHeader(pKey, "Authorization", `Bearer ${val}`, sanitizedExtraArgs);
        return;
      }
      if (field === "http_headers") {
        if (segs.length === 3 && isPlainTable(val)) {
          for (const [hk, hv] of Object.entries(val)) {
            if (typeof hv !== "string") throw new Error(`extraArgs http_headers.${hk} 必须为字符串`);
            bindEnvHeader(pKey, hk, hv, sanitizedExtraArgs);
          }
          return;
        }
        if (segs.length === 4 && typeof val === "string") {
          bindEnvHeader(pKey, segs[3], val, sanitizedExtraArgs);
          return;
        }
        throw new Error(`extraArgs 中的 model_providers.${pName}.http_headers 格式非法`);
      }
      if (field === "env_http_headers") {
        if (segs.length === 3 && isPlainTable(val)) {
          for (const [hk, hv] of Object.entries(val)) {
            if (typeof hv !== "string") throw new Error(`extraArgs env_http_headers.${hk} 必须为字符串`);
            sanitizedExtraArgs.push("-c", `model_providers.${pKey}.env_http_headers.${formatTomlKeySegment(hk)}=${JSON.stringify(hv)}`);
          }
          return;
        }
        if (segs.length === 4 && typeof val === "string") {
          sanitizedExtraArgs.push("-c", `model_providers.${pKey}.env_http_headers.${formatTomlKeySegment(segs[3])}=${JSON.stringify(val)}`);
          return;
        }
        throw new Error(`extraArgs 中的 model_providers.${pName}.env_http_headers 格式非法`);
      }
      if (field === "query_params") {
        if (segs.length === 3 && isPlainTable(val)) {
          for (const [qk, qv] of Object.entries(val)) {
            if (typeof qv !== "string") throw new Error(`extraArgs query_params.${qk} 必须为字符串`);
            if (SECRET_QUERY_PARAM_RE.test(qk)) {
              throw new Error(`extraArgs query_params 包含疑似密钥参数 "${qk}"，tools=none 模式拒绝透传`);
            }
            sanitizedExtraArgs.push("-c", `model_providers.${pKey}.query_params.${formatTomlKeySegment(qk)}=${JSON.stringify(qv)}`);
          }
          return;
        }
        if (segs.length === 4 && typeof val === "string") {
          if (SECRET_QUERY_PARAM_RE.test(segs[3])) {
            throw new Error(`extraArgs query_params 包含疑似密钥参数 "${segs[3]}"，tools=none 模式拒绝透传`);
          }
          sanitizedExtraArgs.push("-c", `model_providers.${pKey}.query_params.${formatTomlKeySegment(segs[3])}=${JSON.stringify(val)}`);
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
  if (!fs.existsSync(configPath)) {
    return { args: [], extraEnv, sanitizedExtraArgs };
  }
  const rawContent = fs.readFileSync(configPath, "utf8");
  let doc: TomlTable;
  try {
    doc = parseToml(rawContent);
  } catch (err) {
    throw new Error(
      `无法安全解析 Codex 配置文件 (${configPath})：${err instanceof Error ? err.message : String(err)}；为避免将私聊发往默认供应商，已中止 tools=none 执行`,
    );
  }

  const profileRaw = doc.profile;
  if (profileRaw !== undefined && (typeof profileRaw !== "string" || !profileRaw.trim())) {
    throw new Error("Codex config.toml 中的 profile 配置非法；为避免误发往默认供应商，已中止 tools=none 执行");
  }
  const activeProfileName = typeof profileRaw === "string" ? profileRaw.trim() : undefined;
  let activeProfile: TomlTable | undefined;
  if (activeProfileName) {
    const profilesTable = doc.profiles;
    const candidate = isPlainTable(profilesTable) ? profilesTable[activeProfileName] : undefined;
    if (!isPlainTable(candidate)) {
      throw new Error(
        `Codex config.toml 指定了 profile "${activeProfileName}"，但未找到对应的 [profiles.${activeProfileName}]；为避免将私聊发往默认供应商，已中止执行`,
      );
    }
    activeProfile = candidate;
  }

  const effectiveVal = (key: string): TomlValue | undefined =>
    activeProfile && activeProfile[key] !== undefined ? activeProfile[key] : doc[key];

  const selectedProviderVal = effectiveVal("model_provider");
  if (selectedProviderVal !== undefined && (typeof selectedProviderVal !== "string" || !selectedProviderVal.trim())) {
    throw new Error("Codex config.toml 中的 model_provider 配置非法；为避免将私聊发往默认供应商，已中止执行");
  }
  const selectedProvider = typeof selectedProviderVal === "string" ? selectedProviderVal.trim() : undefined;
  const effectiveProvider = extraProvider ?? selectedProvider ?? "openai";

  const out: string[] = [];
  const modelVal = effectiveVal("model");
  if (!extraHasModel && modelVal !== undefined) {
    if (typeof modelVal !== "string") throw new Error("Codex config.toml 中的 model 必须为字符串");
    out.push("-c", `model=${JSON.stringify(modelVal)}`);
  }
  for (const scalarKey of SAFE_CODEX_EXTRA_SCALARS) {
    const v = effectiveVal(scalarKey);
    if (v !== undefined) out.push("-c", `${scalarKey}=${serializeTomlScalar(v)}`);
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
  if (!providerObj && !BUILTIN_CODEX_PROVIDERS.has(effectiveProvider) && !extraProviderDefs.has(effectiveProvider)) {
    throw new Error(
      `Codex config.toml 指定了自定义供应商 "${effectiveProvider}"，但未能解析对应的 [model_providers.${effectiveProvider}] 配置；为避免私聊误发往默认供应商，已中止执行`,
    );
  }
  if (providerObj) {
    emitProviderEntries(effectiveProvider, providerObj, out);
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
    r = await runProcess(cfg.bins.acpx, args, {
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
    r = await runProcess(cmd, args, {
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
    r = await runProcess(cmd, args, {
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
