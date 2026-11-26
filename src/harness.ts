import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { ROOT, type Config } from "./config.ts";
import type { Profile } from "./guard.ts";
import { runProcess } from "./util.ts";

const FEISHU_WEB_KEY_CRED = "feishu-web-key";
/** Linux kernel tmpfs magic number (`linux/magic.h`: `TMPFS_MAGIC`). */
const LINUX_TMPFS_MAGIC = 0x01021994;

/** 检测目录是否位于易失性内存文件系统（tmpfs），绝不把无关 systemd 凭据复制到磁盘介质的 /tmp */
function findVolatileTmpfsBase(env: NodeJS.ProcessEnv): string | undefined {
  const candidates = [env.XDG_RUNTIME_DIR?.trim(), "/dev/shm"].filter((d): d is string => !!d);
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
export function prepareHarnessEnv(env: NodeJS.ProcessEnv = process.env): { env: NodeJS.ProcessEnv; cleanup: () => void } {
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

  const volatileBase = findVolatileTmpfsBase(env);
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

function stripTomlComment(line: string): string {
  let inSingle = false;
  let inDouble = false;
  let escaped = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inDouble) {
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === '"') inDouble = false;
    } else if (inSingle) {
      if (ch === "'") inSingle = false;
    } else if (ch === '"') {
      inDouble = true;
    } else if (ch === "'") {
      inSingle = true;
    } else if (ch === "#") {
      return line.slice(0, i);
    }
  }
  return line;
}

function parseTomlPath(raw: string): string[] {
  const parts: string[] = [];
  let i = 0;
  const s = raw.trim();
  while (i < s.length) {
    while (i < s.length && (s[i] === " " || s[i] === "\t")) i++;
    if (i >= s.length) break;
    if (s[i] === '"' || s[i] === "'") {
      const q = s[i++];
      let out = "";
      let closed = false;
      while (i < s.length) {
        const ch = s[i++];
        if (q === '"' && ch === "\\" && i < s.length) {
          out += s[i++];
          continue;
        }
        if (ch === q) {
          closed = true;
          break;
        }
        out += ch;
      }
      if (!closed) throw new Error(`TOML 路径引号未闭合：${raw}`);
      parts.push(out);
    } else {
      let start = i;
      while (i < s.length && s[i] !== "." && s[i] !== " " && s[i] !== "\t") i++;
      const seg = s.slice(start, i).trim();
      if (!seg) throw new Error(`TOML 路径非法：${raw}`);
      parts.push(seg);
    }
    while (i < s.length && (s[i] === " " || s[i] === "\t")) i++;
    if (i < s.length) {
      if (s[i] !== ".") throw new Error(`TOML 路径分隔符非法：${raw}`);
      i++;
    }
  }
  return parts;
}

function parseTomlStringValue(raw: string): string | undefined {
  const t = raw.trim();
  if (t.startsWith('"""') || t.startsWith("'''")) return undefined;
  if (t.startsWith('"') && t.endsWith('"') && t.length >= 2) {
    try {
      return JSON.parse(t) as string;
    } catch {
      return undefined;
    }
  }
  if (t.startsWith("'") && t.endsWith("'") && t.length >= 2) {
    return t.slice(1, -1);
  }
  return undefined;
}

function isSimpleSingleLineTomlValue(raw: string): boolean {
  const t = raw.trim();
  if (!t || t.startsWith('"""') || t.startsWith("'''")) return false;
  if (t.startsWith('"') || t.startsWith("'")) return parseTomlStringValue(t) !== undefined;
  if (t === "true" || t === "false") return true;
  if (/^[+-]?\d[\d_]*(\.\d[\d_]*)?([eE][+-]?\d+)?$/.test(t)) return true;
  if (t.startsWith("[")) return t.endsWith("]");
  if (t.startsWith("{")) return t.endsWith("}");
  return false;
}

function formatTomlKeySegment(seg: string): string {
  return /^[A-Za-z0-9_-]+$/.test(seg) ? seg : JSON.stringify(seg);
}

const SAFE_CODEX_PROVIDER_SUBTABLES = new Set(["http_headers", "env_http_headers", "query_params"]);
const BUILTIN_CODEX_PROVIDERS = new Set(["openai", "oss"]);
const SAFE_CODEX_SCALAR_KEYS = ["model_reasoning_effort", "service_tier", "openai_base_url", "chatgpt_base_url", "oss_provider"] as const;

function parseCliConfigAssignment(expr: string): { key: string; value: string } | undefined {
  const eq = expr.indexOf("=");
  if (eq <= 0) return undefined;
  return { key: expr.slice(0, eq).trim(), value: expr.slice(eq + 1).trim() };
}

function redactCodexLogArgs(args: string[]): string[] {
  return args.map((a) =>
    /^(model_providers\.[^=]+\.(?:http_headers|query_params)\.[^=]+)=/.test(a)
      ? a.replace(/=.*$/, "=<redacted>")
      : a,
  );
}

/**
 * 为 `codex-exec` 的 `tools: "none"` 模式构造工具隔离参数时，从用户的 `$CODEX_HOME/config.toml`
 * 仅提取安全的模型与供应商配置（`model` / `model_provider` / `model_reasoning_effort` / `service_tier` /
 * `openai_base_url` / `chatgpt_base_url` / `oss_provider` 与选中供应商对应的 `[model_providers.<name>]`），
 * 彻底忽略 `mcp_servers` / `plugins` / `hooks` / `apps` / `projects`。
 * 若用户配置指定了自定义供应商或 profile 但无法安全解析，按 fail-closed 抛错，绝不把私聊消息发往默认供应商。
 */
export function extractSafeCodexProviderArgs(
  env: NodeJS.ProcessEnv,
  extraArgs: string[],
  hasExplicitModel: boolean,
): string[] {
  const codexHome = env.CODEX_HOME?.trim() || path.join(os.homedir(), ".codex");
  const configPath = path.join(codexHome, "config.toml");

  // 检测 extraArgs 中是否已显式传入 model_provider、model、provider 字段或 profile
  let extraHasModelProvider = false;
  let extraProvider: string | undefined;
  const extraProviderDefs = new Set<string>();
  let extraHasModel = hasExplicitModel;
  let cliProfile = "";
  const inspectConfigExpr = (expr: string) => {
    const parsed = parseCliConfigAssignment(expr);
    if (!parsed) return;
    if (parsed.key === "model_provider") {
      extraHasModelProvider = true;
      extraProvider = parseTomlStringValue(parsed.value) ?? parsed.value.replace(/^["']|["']$/g, "");
    } else if (parsed.key === "model") {
      extraHasModel = true;
    } else if (parsed.key.startsWith("model_providers.")) {
      try {
        const segs = parseTomlPath(parsed.key);
        if (segs[0] === "model_providers" && segs[1]) extraProviderDefs.add(segs[1]);
      } catch {
        // ignore
      }
    }
  };
  for (let i = 0; i < extraArgs.length; i++) {
    const a = extraArgs[i];
    if (a === "-m" || a === "--model" || a.startsWith("--model=")) extraHasModel = true;
    if (a === "-p" || a === "--profile") {
      cliProfile = extraArgs[i + 1] ?? "";
    } else if (a.startsWith("--profile=")) {
      cliProfile = a.slice("--profile=".length);
    }
    if (a === "-c" || a === "--config") {
      inspectConfigExpr(extraArgs[i + 1] ?? "");
    } else if (a.startsWith("--config=")) {
      inspectConfigExpr(a.slice("--config=".length));
    }
  }

  if (cliProfile) {
    throw new Error(
      `codex-exec tools="none" 模式已禁用用户配置文件以避免加载 MCP/工具，暂不支持通过 --profile ${cliProfile} 叠加外部配置；请在 config.yaml 的 harnesses.<name> 中直接配置 model 与 -c model_provider=...`,
    );
  }

  if (!fs.existsSync(configPath)) return [];
  const rawContent = fs.readFileSync(configPath, "utf8");
  const top = new Map<string, string>();
  const profiles = new Map<string, Map<string, string>>();
  const providerTables = new Map<string, { fields: Map<string, string>; subtables: Map<string, Map<string, string>> }>();
  let curSection: string[] = [];
  let unparseableTop = "";
  const unparseableProviders = new Set<string>();
  const unparseableProfiles = new Set<string>();

  const ensureProvider = (name: string) => {
    let entry = providerTables.get(name);
    if (!entry) {
      entry = { fields: new Map(), subtables: new Map() };
      providerTables.set(name, entry);
    }
    return entry;
  };
  const markUnparseable = (section: string[], line: string) => {
    if (section[0] === "model_providers") {
      if (section[1]) unparseableProviders.add(section[1]);
      else unparseableTop = line;
    } else if (section[0] === "profiles") {
      if (section[1]) unparseableProfiles.add(section[1]);
      else unparseableTop = line;
    } else {
      unparseableTop = line;
    }
  };

  for (const rawLine of rawContent.split(/\r?\n/)) {
    const line = stripTomlComment(rawLine).trim();
    if (!line) continue;
    if (line.startsWith("[[") && line.endsWith("]]")) {
      curSection = ["__array_table__"];
      continue;
    }
    if (line.startsWith("[") && line.endsWith("]")) {
      const inner = line.slice(1, -1);
      try {
        curSection = parseTomlPath(inner);
      } catch {
        if (/\b(?:model_providers|profiles)\b/.test(inner)) unparseableTop = line;
        curSection = ["__invalid__"];
      }
      continue;
    }
    const eq = line.indexOf("=");
    if (eq <= 0) {
      if (curSection[0] === "model_providers" || curSection[0] === "profiles") {
        markUnparseable(curSection, line);
      }
      continue;
    }
    const keyPart = line.slice(0, eq).trim();
    const valPart = line.slice(eq + 1).trim();
    let keySegments: string[];
    try {
      keySegments = parseTomlPath(keyPart);
    } catch {
      if (curSection[0] === "model_providers" || curSection[0] === "profiles") {
        markUnparseable(curSection, line);
      }
      continue;
    }
    const fullPath = [...curSection, ...keySegments];
    const inSensitiveSection = fullPath[0] === "model_providers" || fullPath[0] === "profiles";
    // 顶层内联表 model_providers = { ... } / profiles = { ... } 无法安全拆解，一律按不可解析标记
    if (fullPath.length === 1 && (fullPath[0] === "model_providers" || fullPath[0] === "profiles")) {
      unparseableTop = line;
      continue;
    }
    if (!isSimpleSingleLineTomlValue(valPart)) {
      if (
        inSensitiveSection ||
        (fullPath.length === 1 &&
          (fullPath[0] === "model_provider" ||
            fullPath[0] === "profile" ||
            fullPath[0] === "model" ||
            fullPath[0] === "openai_base_url" ||
            fullPath[0] === "chatgpt_base_url"))
      ) {
        markUnparseable(fullPath, line);
      }
      continue;
    }
    if (fullPath.length === 1) {
      top.set(fullPath[0], valPart);
    } else if (fullPath[0] === "profiles" && fullPath.length === 3) {
      const pName = fullPath[1];
      let pMap = profiles.get(pName);
      if (!pMap) {
        pMap = new Map();
        profiles.set(pName, pMap);
      }
      pMap.set(fullPath[2], valPart);
    } else if (fullPath[0] === "model_providers" && fullPath.length === 3) {
      ensureProvider(fullPath[1]).fields.set(fullPath[2], valPart);
    } else if (fullPath[0] === "model_providers" && fullPath.length === 4 && SAFE_CODEX_PROVIDER_SUBTABLES.has(fullPath[2])) {
      const p = ensureProvider(fullPath[1]);
      let sub = p.subtables.get(fullPath[2]);
      if (!sub) {
        sub = new Map();
        p.subtables.set(fullPath[2], sub);
      }
      sub.set(fullPath[3], valPart);
    }
  }

  if (unparseableTop) {
    throw new Error(
      "检测到 Codex config.toml 的供应商或 profile 配置包含无法安全提取的多行/内联表语法；为避免私聊误发往默认供应商，已中止 tools=none 执行",
    );
  }

  const profileRaw = top.get("profile");
  const activeProfileName = profileRaw ? parseTomlStringValue(profileRaw) : undefined;
  if (profileRaw && !activeProfileName) {
    throw new Error("无法解析 Codex config.toml 中的 profile 配置；为避免误发往默认供应商，已中止 tools=none 执行");
  }
  const activeProfile = activeProfileName ? profiles.get(activeProfileName) : undefined;
  if (activeProfileName && (!activeProfile || unparseableProfiles.has(activeProfileName))) {
    throw new Error(
      `Codex config.toml 指定了 profile "${activeProfileName}"，但未能安全解析对应的 [profiles.${activeProfileName}]；为避免将私聊发往默认供应商，已中止执行`,
    );
  }

  const effectiveRaw = (key: string): string | undefined => activeProfile?.get(key) ?? top.get(key);
  const selectedProviderRaw = effectiveRaw("model_provider");
  const selectedProvider = selectedProviderRaw ? parseTomlStringValue(selectedProviderRaw) : undefined;

  if (selectedProviderRaw && !selectedProvider) {
    throw new Error("无法解析 Codex config.toml 中的 model_provider；为避免将私聊发往默认供应商，已中止执行");
  }

  const effectiveProvider = extraProvider ?? selectedProvider ?? "openai";
  if (unparseableProviders.has(effectiveProvider)) {
    throw new Error(
      `检测到 Codex config.toml 中 [model_providers.${effectiveProvider}] 包含无法安全提取的多行/复杂语法；为避免私聊误发往默认供应商，已中止 tools=none 执行`,
    );
  }

  const out: string[] = [];
  const modelRaw = effectiveRaw("model");
  if (!extraHasModel && modelRaw) {
    out.push("-c", `model=${modelRaw}`);
  }
  for (const scalarKey of SAFE_CODEX_SCALAR_KEYS) {
    const v = effectiveRaw(scalarKey);
    if (v) out.push("-c", `${scalarKey}=${v}`);
  }

  if (selectedProvider && !extraHasModelProvider) {
    out.push("-c", `model_provider=${JSON.stringify(selectedProvider)}`);
  }

  const providerTable = providerTables.get(effectiveProvider);
  if (!providerTable && !BUILTIN_CODEX_PROVIDERS.has(effectiveProvider) && !extraProviderDefs.has(effectiveProvider)) {
    throw new Error(
      `Codex config.toml 指定了自定义供应商 "${effectiveProvider}"，但未能解析对应的 [model_providers.${effectiveProvider}] 配置；为避免私聊误发往默认供应商，已中止执行`,
    );
  }
  if (providerTable) {
    const pKey = formatTomlKeySegment(effectiveProvider);
    for (const [k, v] of providerTable.fields) {
      out.push("-c", `model_providers.${pKey}.${formatTomlKeySegment(k)}=${v}`);
    }
    for (const [subName, subMap] of providerTable.subtables) {
      for (const [k, v] of subMap) {
        out.push("-c", `model_providers.${pKey}.${subName}.${formatTomlKeySegment(k)}=${v}`);
      }
    }
  }
  return out;
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
    const finalEnv = mergeHarnessEnv(baseEnv.env, h.env);
    args = ["exec", "--skip-git-repo-check", "--sandbox", "read-only", "--ephemeral", "--color", "never", "-o", path.basename(outFile)];
    if (run.tools === "none") {
      // 彻底隔离用户配置（包括 ~/.codex/config.toml 中配置的任意 MCP Server / 插件 / 钩子）与执行规则，仅保留认证及提取后的安全供应商/模型参数
      const safeProviderArgs = extractSafeCodexProviderArgs(finalEnv, h.extraArgs, !!h.model);
      args.push(
        "--ignore-user-config",
        "--ignore-rules",
        ...safeProviderArgs,
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
    args.push(...h.extraArgs, "-");
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
