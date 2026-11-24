import fs from "node:fs";
import path from "node:path";
import { ROOT, type Config } from "./config.ts";
import type { Profile } from "./guard.ts";
import { runProcess } from "./util.ts";

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
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    ...harnessEnv,
    PATH: `${path.join(ROOT, "bin", "guard")}${path.delimiter}${process.env.PATH ?? ""}`,
    PA_GUARD_PROFILE: run.lark,
    PA_OWNER_OPEN_ID: cfg.owner.open_id,
    PA_LARK_REAL: resolveBin(cfg.bins.lark),
    PA_GUARD_LOG: path.join(cfg.dataDir, "logs", "guard.log"),
  };
  const started = new Date().toISOString();
  const r = await runProcess(cfg.bins.acpx, args, {
    cwd: run.cwd,
    env,
    input: run.prompt,
    // acpx 自己有 --timeout；这里多留 2 分钟兜底，防止进程卡死
    timeoutMs: (run.timeoutSec + 120) * 1000,
    group: true,
    signal: run.signal,
    onSpawn: run.onSpawn,
  });
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
  fs.mkdirSync(run.cwd, { recursive: true });
  const outFile = path.join(run.cwd, `.codex-last-${process.pid}-${Date.now()}.txt`);
  const args = ["exec", "--skip-git-repo-check", "--sandbox", "read-only", "--ephemeral", "--color", "never", "-o", outFile];
  if (h.model) args.push("-m", h.model);
  args.push(...h.extraArgs, "-");
  const harnessEnv = Object.fromEntries(
    Object.entries(h.env).map(([k, v]) => [k, v.replace(/\$\{(\w+)\}/g, (_, n: string) => process.env[n] ?? "")]),
  );
  const started = new Date().toISOString();
  const r = await runProcess(h.cmd, args, {
    cwd: run.cwd,
    env: { ...process.env, ...harnessEnv },
    input: run.prompt,
    timeoutMs: (run.timeoutSec + 60) * 1000,
    group: true,
    signal: run.signal,
    onSpawn: run.onSpawn,
  });
  let text = "";
  try {
    text = fs.readFileSync(outFile, "utf8").trim();
    fs.rmSync(outFile, { force: true });
  } catch {
    text = r.stdout.trim();
  }
  fs.writeFileSync(
    run.logFile,
    [`# ${started} harness=${run.harness} type=codex-exec cwd=${run.cwd}`, `# ${h.cmd} ${args.join(" ")}`, `# exit=${r.code} timedOut=${r.timedOut}`, "## prompt", run.prompt, "## reply", text, "## stderr", r.stderr.slice(-4000)].join("\n"),
  );
  try {
    usageRecorder?.(run, { stdout: r.stdout, stderr: r.stderr, code: r.code });
  } catch {
    // 忽略
  }
  const aborted = !!run.signal?.aborted;
  return { ok: r.code === 0 && !r.timedOut && !aborted, exitCode: r.code, text, timedOut: r.timedOut, aborted };
}
