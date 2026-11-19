import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import readline from "node:readline";
import type { Config } from "./config.ts";
import type { Identity } from "./lark.ts";
import type { Store } from "./store.ts";
import { errMsg, log } from "./util.ts";

export interface Subscription {
  key: string;
  as: Identity;
  handler: (ev: Record<string, unknown>) => Promise<void>;
}

/**
 * 守护 `lark-cli event consume` 子进程：每个 EventKey 一个进程（官方要求），
 * 读 NDJSON、按 event_id 去重、退出后指数退避重启。
 *
 * 注意：unbounded 的 consume 读到 stdin EOF 就会退出，所以这里一直持有 stdin 管道不关闭；
 * 停止时关闭 stdin 让它优雅退出（不要 kill -9，妙记/会议类事件会残留服务端订阅）。
 */
export class EventSupervisor {
  cfg: Config;
  store: Store;
  private procs = new Map<string, ChildProcessWithoutNullStreams>();
  private stopping = false;

  constructor(cfg: Config, store: Store) {
    this.cfg = cfg;
    this.store = store;
  }

  start(subs: Subscription[]): void {
    for (const s of subs) this.spawn(s, 1000);
  }

  private spawn(sub: Subscription, backoff: number): void {
    if (this.stopping) return;
    const child = spawn(this.cfg.bins.lark, ["event", "consume", sub.key, "--as", sub.as], {
      cwd: this.cfg.dataDir,
      stdio: ["pipe", "pipe", "pipe"],
    });
    this.procs.set(sub.key, child);
    child.stdin.on("error", () => undefined); // 子进程已退出时关闭 stdin 会 EPIPE，忽略
    const startedAt = Date.now();
    let lastErr = "";

    readline.createInterface({ input: child.stderr }).on("line", (line) => {
      if (line.includes("[event] ready")) log("info", "事件订阅就绪", { key: sub.key });
      else if (line.trim()) lastErr = line;
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
      const id = String(ev.event_id ?? header?.event_id ?? "");
      if (id && !this.store.markSeen(`event:${id}`, sub.key)) return;
      sub.handler(ev).catch((e) => log("error", "事件处理失败", { key: sub.key, err: errMsg(e) }));
    });

    child.on("error", (e) => log("error", "事件进程启动失败", { key: sub.key, err: errMsg(e) }));
    child.on("close", (code) => {
      this.procs.delete(sub.key);
      if (this.stopping) return;
      // 稳定运行超过 5 分钟就重置退避
      const next = Date.now() - startedAt > 300_000 ? 1000 : Math.min(backoff * 2, 300_000);
      log("warn", "事件进程退出，稍后重启", { key: sub.key, code, retryInMs: next, lastErr: lastErr.slice(0, 500) });
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
