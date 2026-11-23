import { spawn } from "node:child_process";
import os from "node:os";
import path from "node:path";

/** JSON 行日志，交给 systemd/journald 或重定向文件收集。 */
export function log(level: "info" | "warn" | "error", msg: string, extra: Record<string, unknown> = {}): void {
  const line = JSON.stringify({ t: new Date().toISOString(), level, msg, ...extra });
  (level === "error" ? process.stderr : process.stdout).write(line + "\n");
}

export function expandHome(p: string): string {
  return p.startsWith("~/") ? path.join(os.homedir(), p.slice(2)) : p;
}

export function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

export function truncate(s: string, max: number): string {
  return s.length <= max ? s : s.slice(0, max) + `\n…（已截断，原长 ${s.length} 字符）`;
}

/** 把 {{name}} 替换为 vars.name。 */
export function render(tpl: string, vars: Record<string, string>): string {
  return tpl.replace(/\{\{(\w+)\}\}/g, (_, k: string) => vars[k] ?? "");
}

/** 带时区偏移的 ISO 时间，lark-cli 的 --start/--end 需要这种格式。 */
export function isoWithOffset(d: Date): string {
  const off = -d.getTimezoneOffset();
  const sign = off >= 0 ? "+" : "-";
  const pad = (n: number) => String(Math.floor(Math.abs(n))).padStart(2, "0");
  const local = new Date(d.getTime() + off * 60_000).toISOString().slice(0, 19);
  return `${local}${sign}${pad(off / 60)}:${pad(off % 60)}`;
}

/** 在任意嵌套对象中找第一个名为 key 的字段（飞书各接口返回结构不完全一致，按字段名取更稳）。 */
export function deepFind(obj: unknown, key: string): unknown {
  if (obj === null || typeof obj !== "object") return undefined;
  if (!Array.isArray(obj) && key in (obj as Record<string, unknown>)) return (obj as Record<string, unknown>)[key];
  for (const v of Object.values(obj as Record<string, unknown>)) {
    const found = deepFind(v, key);
    if (found !== undefined) return found;
  }
  return undefined;
}

/** 找第一个“元素都含有 key 字段”的数组，例如消息列表（message_id）、任务列表（guid）。 */
export function findItems(obj: unknown, key: string): Record<string, unknown>[] {
  if (obj === null || typeof obj !== "object") return [];
  if (Array.isArray(obj)) {
    if (obj.length > 0 && obj.every((x) => x && typeof x === "object" && key in x)) return obj as Record<string, unknown>[];
    for (const x of obj) {
      const r = findItems(x, key);
      if (r.length) return r;
    }
    return [];
  }
  for (const v of Object.values(obj as Record<string, unknown>)) {
    const r = findItems(v, key);
    if (r.length) return r;
  }
  return [];
}

export interface ProcResult {
  code: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

/** 本进程启动的、以独立进程组运行的子进程（harness）。退出时一并结束，避免孤儿进程继续改 worktree。 */
const liveGroups = new Set<number>();
process.on("exit", () => {
  for (const pgid of liveGroups) killGroup(pgid, "SIGTERM");
});

/** 给整个进程组发信号（acpx 会再起 agent 子进程，只杀 acpx 不够）。 */
export function killGroup(pgid: number, sig: NodeJS.Signals): boolean {
  try {
    process.kill(-pgid, sig);
    return true;
  } catch {
    return false;
  }
}

/** 进程是否还活着（EPERM 说明存在但不属于我们，也算活着）。 */
export function isAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
}

export interface RunOpts {
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  input?: string;
  timeoutMs?: number;
  /** 以独立进程组运行：超时/中止时结束整个进程组，崩溃后也能按 pgid 清理。 */
  group?: boolean;
  /** 子进程启动后回调（pid；group 模式下即 pgid），用于持久化以便崩溃恢复时清理。 */
  onSpawn?: (pid: number) => void;
  /** 中止：结束子进程（group 模式下结束整个进程组）。 */
  signal?: AbortSignal;
}

/** 运行子进程并收集输出；超时或中止时先 SIGTERM，10 秒后 SIGKILL。 */
export function runProcess(cmd: string, args: string[], opts: RunOpts = {}): Promise<ProcResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, {
      cwd: opts.cwd,
      env: opts.env ?? process.env,
      stdio: ["pipe", "pipe", "pipe"],
      detached: !!opts.group,
    });
    const pid = child.pid;
    if (opts.group && pid) liveGroups.add(pid);
    if (pid) opts.onSpawn?.(pid);
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let killer: NodeJS.Timeout | undefined;
    const kill = (sig: NodeJS.Signals) => {
      if (opts.group && pid) killGroup(pid, sig);
      else child.kill(sig);
    };
    const stop = () => {
      kill("SIGTERM");
      killer ??= setTimeout(() => kill("SIGKILL"), 10_000);
    };
    const timer = opts.timeoutMs
      ? setTimeout(() => {
          timedOut = true;
          stop();
        }, opts.timeoutMs)
      : undefined;
    const onAbort = () => stop();
    if (opts.signal?.aborted) stop();
    else opts.signal?.addEventListener("abort", onAbort, { once: true });
    child.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
    child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
    child.on("error", (e) => {
      if (pid) liveGroups.delete(pid);
      reject(e);
    });
    child.on("close", (code) => {
      if (timer) clearTimeout(timer);
      if (killer) clearTimeout(killer);
      opts.signal?.removeEventListener("abort", onAbort);
      if (pid) liveGroups.delete(pid);
      resolve({ code: code ?? -1, stdout, stderr, timedOut });
    });
    // 子进程可能不读 stdin 就先退出（如 git），此时写入会 EPIPE；忽略它，结果以退出码为准
    child.stdin.on("error", () => undefined);
    if (opts.input) child.stdin.end(opts.input);
    else child.stdin.end();
  });
}
