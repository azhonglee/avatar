import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { ROOT, type Config } from "./config.ts";
import type { Profile } from "./guard.ts";
import { runProcess } from "./util.ts";

const FEISHU_WEB_KEY_CRED = "feishu-web-key";

/**
 * 构造传给子模型进程的基础环境：
 *   - 始终剥离所有 `PA_FEISHU_WEB_*` 环境变量（凭据路径与静态加密密钥）；
 *   - 若 `CREDENTIALS_DIRECTORY` 不包含 `feishu-web-key`，原样保留（不破坏无关的 systemd 凭据）；
 *   - 若 `CREDENTIALS_DIRECTORY` 包含 `feishu-web-key`，则只将无关凭据复制到 0700 临时目录（0400 文件权限）供子进程读取，
 *     并在子进程结束后立即清理（若目录内仅有 `feishu-web-key`，则移除 `CREDENTIALS_DIRECTORY`）。
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

  const filteredDir = fs.mkdtempSync(path.join(os.tmpdir(), "pa-creds-"));
  fs.chmodSync(filteredDir, 0o700);
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
  clean.CREDENTIALS_DIRECTORY = filteredDir;
  return {
    env: clean,
    cleanup: () => fs.rmSync(filteredDir, { recursive: true, force: true }),
  };
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
  // harness.env 的值支持 ${VAR} 引用守护进程的环境变量，密钥不必写进配置文件
  const harnessEnv = Object.fromEntries(
    Object.entries(h.env).map(([k, v]) => [k, v.replace(/\$\{(\w+)\}/g, (_, n: string) => process.env[n] ?? "")]),
  );
  const baseEnv = prepareHarnessEnv();
  const env: NodeJS.ProcessEnv = {
    ...baseEnv.env,
    ...harnessEnv,
    PATH: `${path.join(ROOT, "bin", "guard")}${path.delimiter}${process.env.PATH ?? ""}`,
    PA_GUARD_PROFILE: run.lark,
    PA_OWNER_OPEN_ID: cfg.owner.open_id,
    PA_LARK_REAL: resolveBin(cfg.bins.lark),
    PA_GUARD_LOG: path.join(cfg.dataDir, "logs", "guard.log"),
  };
  const started = new Date().toISOString();
  let r: Awaited<ReturnType<typeof runProcess>>;
  try {
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
  const args = ["exec", "--skip-git-repo-check", "--sandbox", "read-only", "--ephemeral", "--color", "never", "-o", path.basename(outFile)];
  if (run.tools === "none") {
    // 彻底隔离用户配置（包括 ~/.codex/config.toml 中配置的任意 MCP Server / 插件 / 钩子）与执行规则，仅保留认证，并关闭全部内置工具
    args.push(
      "--ignore-user-config",
      "--ignore-rules",
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
  const harnessEnv = Object.fromEntries(
    Object.entries(h.env).map(([k, v]) => [k, v.replace(/\$\{(\w+)\}/g, (_, n: string) => process.env[n] ?? "")]),
  );
  const baseEnv = prepareHarnessEnv();
  const started = new Date().toISOString();
  let r: Awaited<ReturnType<typeof runProcess>>;
  let text = "";
  try {
    r = await runProcess(cmd, args, {
      cwd: execCwd,
      env: { ...baseEnv.env, ...harnessEnv },
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
    [`# ${started} harness=${run.harness} type=codex-exec tools=${run.tools} cwd=${execCwd}`, `# ${cmd} ${args.join(" ")}`, `# exit=${r.code} timedOut=${r.timedOut}`, "## prompt", run.prompt, "## reply", text, "## stderr", r.stderr.slice(-4000)].join("\n"),
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

  const harnessEnv = Object.fromEntries(
    Object.entries(h.env).map(([k, v]) => [k, v.replace(/\$\{(\w+)\}/g, (_, n: string) => process.env[n] ?? "")]),
  );
  let realLark = cfg.bins.lark;
  try {
    realLark = resolveBin(cfg.bins.lark);
  } catch {
    // run.lark === "none" 时不会执行真实 lark-cli
  }
  const baseEnv = prepareHarnessEnv();
  const env: NodeJS.ProcessEnv = {
    ...baseEnv.env,
    ...harnessEnv,
    DOUBAO_CLI_NO_UPDATE_CHECK: "1",
    PATH: `${path.join(ROOT, "bin", "guard")}${path.delimiter}${process.env.PATH ?? ""}`,
    PA_GUARD_PROFILE: run.lark,
    PA_OWNER_OPEN_ID: cfg.owner.open_id,
    PA_LARK_REAL: realLark,
    PA_GUARD_LOG: path.join(cfg.dataDir, "logs", "guard.log"),
  };
  const started = new Date().toISOString();
  // Node.js spawn 的 stdio:"pipe" 在 Linux 上是 Unix socketpair（S_IFSOCK），doubao 会报
  // "stdin must be a terminal, pipe or regular file"；写到 0600 临时普通文件以 FD 传入，用完立即删除。
  const promptDir = path.join(cfg.dataDir, "runs");
  fs.mkdirSync(promptDir, { recursive: true });
  const promptFile = path.join(promptDir, `.doubao-in-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}.txt`);
  fs.writeFileSync(promptFile, run.prompt, { mode: 0o600 });
  const fd = fs.openSync(promptFile, "r");
  let r: Awaited<ReturnType<typeof runProcess>>;
  try {
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
