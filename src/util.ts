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

/** 运行子进程并收集输出；超时先 SIGTERM，10 秒后 SIGKILL。 */
export function runProcess(
  cmd: string,
  args: string[],
  opts: { cwd?: string; env?: NodeJS.ProcessEnv; input?: string; timeoutMs?: number } = {},
): Promise<ProcResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { cwd: opts.cwd, env: opts.env ?? process.env, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let killer: NodeJS.Timeout | undefined;
    const timer = opts.timeoutMs
      ? setTimeout(() => {
          timedOut = true;
          child.kill("SIGTERM");
          killer = setTimeout(() => child.kill("SIGKILL"), 10_000);
        }, opts.timeoutMs)
      : undefined;
    child.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
    child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
    child.on("error", reject);
    child.on("close", (code) => {
      if (timer) clearTimeout(timer);
      if (killer) clearTimeout(killer);
      resolve({ code: code ?? -1, stdout, stderr, timedOut });
    });
    // 子进程可能不读 stdin 就先退出（如 git），此时写入会 EPIPE；忽略它，结果以退出码为准
    child.stdin.on("error", () => undefined);
    if (opts.input) child.stdin.end(opts.input);
    else child.stdin.end();
  });
}
