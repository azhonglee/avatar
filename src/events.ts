import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createHash } from "node:crypto";
import readline from "node:readline";
import type { Config } from "./config.ts";
import type { Identity } from "./lark.ts";
import { errMsg, log, scrubPersonalWebEnv } from "./util.ts";

export interface Subscription {
  key: string;
  as: Identity;
}

/** 收到一个事件：调用方把它写进 inbox（同步、落库即返回），处理交给引擎。 */
export type OnEvent = (key: string, eventId: string, ev: Record<string, unknown>) => void;

/**
 * 从 `lark-cli event consume` 的 stderr 尾部提取可读错误：
 * 新版 lark-cli 会输出多行缩进的 JSON 错误信封（含 error.message / error.hint / error.subtype）；
 * 不是 JSON 时回退到最后一行非空文本。
 */
export function parseEventStderr(lines: string[]): { message: string; hint?: string; subtype?: string } {
  const nonEmpty = lines.filter((l) => l.trim());
  if (!nonEmpty.length) return { message: "" };
  for (let i = nonEmpty.length - 1; i >= 0; i--) {
    if (!nonEmpty[i].trimStart().startsWith("{")) continue;
    try {
      const parsed = JSON.parse(nonEmpty.slice(i).join("\n")) as {
        error?: { message?: unknown; hint?: unknown; subtype?: unknown };
        message?: unknown;
      };
      const e = parsed.error;
      if (e && typeof e === "object") {
        const message = typeof e.message === "string" && e.message ? e.message : JSON.stringify(e);
        return {
          message,
          ...(typeof e.hint === "string" && e.hint ? { hint: e.hint } : {}),
          ...(typeof e.subtype === "string" && e.subtype ? { subtype: e.subtype } : {}),
        };
      }
      if (typeof parsed.message === "string" && parsed.message) return { message: parsed.message };
    } catch {
      // 不是完整 JSON 起点，继续往前找
    }
  }
  return { message: nonEmpty.at(-1)!.trim() };
}

/**
 * 守护 `lark-cli event consume` 子进程：每个 EventKey 一个进程（官方要求），
 * 读 NDJSON 交给 onEvent（写 inbox，按 event_id 去重），退出后指数退避重启。
 * 这里不做任何业务处理：事件只是“该看一眼”的提示，可靠性由 inbox + 引擎重试 + 定时对账保证。
 *
 * 注意：unbounded 的 consume 读到 stdin EOF 就会退出，所以这里一直持有 stdin 管道不关闭；
 * 停止时关闭 stdin 让它优雅退出（不要 kill -9，妙记/会议类事件会残留服务端订阅）。
 */
export class EventSupervisor {
  cfg: Config;
  onEvent: OnEvent;
  private procs = new Map<string, ChildProcessWithoutNullStreams>();
  private stopping = false;

  constructor(cfg: Config, onEvent: OnEvent) {
    this.cfg = cfg;
    this.onEvent = onEvent;
  }

  start(subs: Subscription[]): void {
    for (const s of subs) this.spawn(s, 1000);
  }

  private spawn(sub: Subscription, backoff: number): void {
    if (this.stopping) return;
    const child = spawn(this.cfg.bins.lark, ["event", "consume", sub.key, "--as", sub.as], {
      cwd: this.cfg.dataDir,
      env: scrubPersonalWebEnv(process.env),
      stdio: ["pipe", "pipe", "pipe"],
    });
    this.procs.set(sub.key, child);
    child.stdin.on("error", () => undefined); // 子进程已退出时关闭 stdin 会 EPIPE，忽略
    const startedAt = Date.now();
    const errLines: string[] = [];

    readline.createInterface({ input: child.stderr }).on("line", (line) => {
      if (line.includes("[event] ready")) {
        errLines.length = 0;
        log("info", "事件订阅就绪", { key: sub.key });
      } else if (line.trim()) {
        errLines.push(line);
        if (errLines.length > 60) errLines.shift();
      }
    });
    readline.createInterface({ input: child.stdout }).on("line", (line) => {
      if (!line.trim()) return;
      let ev: Record<string, unknown>;
      try {
        ev = JSON.parse(line);
      } catch {
        log("warn", "无法解析的事件行", { key: sub.key, line: line.slice(0, 200) });
        return;
      }
      const header = ev.header as Record<string, unknown> | undefined;
      // 没有 event_id 的事件用内容哈希去重
      const id = String(ev.event_id ?? header?.event_id ?? "") || createHash("sha256").update(line).digest("hex").slice(0, 32);
      try {
        this.onEvent(sub.key, id, ev);
      } catch (e) {
        log("error", "事件写入 inbox 失败", { key: sub.key, err: errMsg(e) });
      }
    });

    child.on("error", (e) => log("error", "事件进程启动失败", { key: sub.key, err: errMsg(e) }));
    child.on("close", (code) => {
      this.procs.delete(sub.key);
      if (this.stopping) return;
      const err = parseEventStderr(errLines);
      // 稳定运行超过 5 分钟就重置退避；前置条件未满足（如开发者后台未订阅该事件）放慢重连，避免刷屏
      const next =
        Date.now() - startedAt > 300_000
          ? 1000
          : Math.min(err.subtype === "failed_precondition" ? Math.max(backoff * 2, 60_000) : backoff * 2, 300_000);
      log("warn", "事件进程退出，稍后重启", {
        key: sub.key,
        code,
        retryInMs: next,
        lastErr: err.message.slice(0, 500),
        ...(err.hint ? { hint: err.hint.slice(0, 800) } : {}),
      });
      setTimeout(() => this.spawn(sub, next), next).unref();
    });
  }

  async stop(): Promise<void> {
    this.stopping = true;
    const waits = [...this.procs.values()].map(
      (p) =>
        new Promise<void>((resolve) => {
          const t = setTimeout(() => p.kill("SIGTERM"), 10_000);
          p.on("close", () => {
            clearTimeout(t);
            resolve();
          });
          p.stdin.end();
        }),
    );
    await Promise.all(waits);
  }
}
