import type { Effect, Ledger, Patch, WorkItem, WorkKind } from "./ledger.ts";
import { LeaseLost } from "./ledger.ts";
import { errMsg, killGroup, isAlive, log } from "./util.ts";

/** 执行上下文：中止信号（取消 / 优雅退出 / 失去租约）和本次是第几次尝试。 */
export interface Ctx {
  signal: AbortSignal;
  /** 当前状态的第几次尝试（崩溃重启后接着计数） */
  attempt: number;
}

export interface Handler<P = Record<string, unknown>> {
  kind: WorkKind;
  /** 本进程内的并发上限（dispatch 另受全局租约数限制） */
  concurrency: number;
  /** 同一状态最多尝试几次（含崩溃中断）；超过后调用 onExhausted 落到终态 */
  maxAttempts: number;
  /**
   * 推进这项工作。用 ledger.transition 持久化每一步进度；正常返回时若未到终态，
   * 引擎释放租约并在 payload 指定的 next_at 再次领取。抛错则按退避重试。
   */
  run(item: WorkItem<P>, ctx: Ctx): Promise<void>;
  /**
   * 优雅退出被中止时是否退回本次尝试（默认是）。有检查点或幂等的工作退回后从头/检查点重来；
   * 至多一次的工作（agent 作业、自由对话）设为 false：重启后按“中断”处理，不悄悄重跑。
   */
  refundOnStop?: boolean;
  /** 可选：领取前的附加过滤（例如非持钥交互式 CLI 跳过未完结的 pw.reply，避免消耗重试次数，同时允许已完成回读的回执本地收尾） */
  claimOpts?: () => { excludeEffectOps?: string[]; allowEffectIds?: string[] } | undefined;
  /** 重试耗尽：给出终态和需要投递的副作用（通知、评论、移卡片）。 */
  onExhausted(item: WorkItem<P>, lastError: string): { patch: Patch<P>; effects?: Effect[] };
}

export class Aborted extends Error {
  constructor(reason: string) {
    super(reason);
  }
}

export interface EngineOpts {
  leaseMs: number;
  retryBaseMs: number;
  retryMaxMs: number;
  tickMs: number;
  /** dispatch 的全局并发上限（跨进程，按有效租约数计） */
  globalLimit?: Partial<Record<WorkKind, number>>;
}

interface Running {
  item: WorkItem;
  ctrl: AbortController;
  promise: Promise<void>;
}

/**
 * 工作引擎：按种类领取工作、心跳续约、执行、按统一策略重试/落终态。
 * 正确性不依赖“事件不丢、进程不崩”：任何时刻崩溃，重启后都会从账本里把未完成的工作接着做完。
 */
export class Engine {
  ledger: Ledger;
  opts: EngineOpts;
  private handlers = new Map<WorkKind, Handler<never>>();
  private running = new Map<string, Running>();
  private timer?: NodeJS.Timeout;
  private beat?: NodeJS.Timeout;
  private stopping = false;
  private started = false;
  private ticking = false;
  private again = false;

  constructor(ledger: Ledger, opts: EngineOpts) {
    this.ledger = ledger;
    this.opts = opts;
  }

  register<P>(h: Handler<P>): void {
    this.handlers.set(h.kind, h as unknown as Handler<never>);
  }

  /** 当前引擎是否正以常驻模式运行（`pa run`）；单次 `drain` CLI 返回 false。 */
  isDaemonRunning(): boolean {
    return this.started;
  }

  /** 常驻模式：定时领取所有种类的工作。命令行单次运行不调用它，只用 drain。 */
  start(): void {
    this.started = true;
    this.timer = setInterval(() => this.kick(), this.opts.tickMs);
    this.startBeat();
    this.kick();
  }

  private startBeat(): void {
    this.beat ??= setInterval(() => this.heartbeat(), Math.max(100, Math.floor(this.opts.leaseMs / 4)));
  }

  /** 有新工作时调用：尽快领取。并发调用会合并。只在常驻模式生效。 */
  kick(): void {
    if (!this.started || this.stopping) return;
    if (this.ticking) {
      this.again = true;
      return;
    }
    this.ticking = true;
    try {
      do {
        this.again = false;
        this.tick();
      } while (this.again && !this.stopping);
    } catch (e) {
      log("error", "引擎调度失败", { err: errMsg(e) });
    } finally {
      this.ticking = false;
    }
  }

  /** 领取当前能领的工作（可限定种类）。返回新启动的数量。 */
  tick(kinds?: WorkKind[]): number {
    this.ledger.reapDeadOwners();
    let started = 0;
    for (const h of this.handlers.values()) {
      if (kinds && !kinds.includes(h.kind)) continue;
      while (!this.stopping) {
        const local = [...this.running.values()].filter((r) => r.item.kind === h.kind).length;
        if (local >= h.concurrency) break;
        const global = this.opts.globalLimit?.[h.kind];
        if (global !== undefined && this.ledger.leasedCount(h.kind) >= global) break;
        const item = this.ledger.claim(h.kind, this.opts.leaseMs, h.claimOpts?.());
        if (!item) break;
        this.launch(h, item);
        started++;
      }
    }
    return started;
  }

  private launch(h: Handler<never>, item: WorkItem): void {
    const ctrl = new AbortController();
    // 接管前任遗留的进程组（崩溃时没来得及结束的 harness），避免两个执行者同时改一个 worktree
    for (const s of this.ledger.interruptSteps(item.id)) {
      if (s.pid && s.owner.split(":")[0] === this.ledger.owner.split(":")[0] && isAlive(s.pid)) {
        killGroup(s.pid, "SIGTERM");
        setTimeout(() => killGroup(s.pid, "SIGKILL"), 5_000).unref();
        log("warn", "已结束前任遗留的执行进程", { work: item.id, pid: s.pid, step: s.name });
      }
    }
    const promise = this.execute(h, item, ctrl).finally(() => {
      this.running.delete(item.id);
      this.kick();
    });
    this.running.set(item.id, { item, ctrl, promise });
  }

  private async execute(h: Handler<never>, item: WorkItem, ctrl: AbortController): Promise<void> {
    if (item.attempts > h.maxAttempts) {
      this.exhaust(h, item, item.error || `已尝试 ${item.attempts - 1} 次（含中断）`);
      return;
    }
    try {
      await h.run(item as never, { signal: ctrl.signal, attempt: item.attempts });
      // 正常返回但没到终态：handler 已经把 next_at 写好（等待重试 / 下一阶段），释放租约
      this.ledger.release(item.id);
    } catch (e) {
      if (e instanceof LeaseLost) {
        log("warn", errMsg(e), { work: item.id });
        return;
      }
      if (ctrl.signal.aborted) {
        if (this.stopping) {
          // 优雅退出：默认不计入尝试次数，下次启动从检查点继续
          this.ledger.release(item.id, { refund: h.refundOnStop !== false, nextAt: 0 });
        } else if (this.ledger.isCancelled(item.id)) {
          // 取消：立刻重新领取，由 handler 在入口处收尾到 cancelled
          this.ledger.release(item.id, { refund: true, nextAt: 0 });
        }
        // 否则是失去租约：别人已经接管，什么都不写
        return;
      }
      const msg = errMsg(e);
      const cur = this.ledger.get(item.id);
      if (!cur || cur.terminal) return;
      if (cur.attempts >= h.maxAttempts) {
        this.exhaust(h, cur, msg);
        return;
      }
      const delay = Math.min(this.opts.retryBaseMs * 2 ** (cur.attempts - 1), this.opts.retryMaxMs);
      this.ledger.release(item.id, { nextAt: Date.now() + delay, error: msg });
      log("warn", "工作失败，稍后重试", { work: item.id, attempt: cur.attempts, delayMs: delay, err: msg });
    }
  }

  private exhaust(h: Handler<never>, item: WorkItem, lastError: string): void {
    try {
      const r = h.onExhausted(item as never, lastError);
      this.ledger.transition(item, { ...r.patch, terminal: true, error: lastError }, r.effects ?? []);
      log("error", "工作重试耗尽", { work: item.id, state: r.patch.state, err: lastError });
    } catch (e) {
      log("error", "处理重试耗尽失败", { work: item.id, err: errMsg(e) });
    }
  }

  private heartbeat(): void {
    const ids = [...this.running.keys()];
    if (!ids.length) return;
    for (const id of this.ledger.heartbeat(ids, this.opts.leaseMs)) {
      const r = this.running.get(id);
      if (!r) continue;
      const cur = this.ledger.get(id);
      if (cur?.terminal) continue; // 刚好落到终态
      log("warn", "失去租约，中止本地执行", { work: id });
      r.ctrl.abort(new Aborted("失去租约"));
    }
    for (const [id, r] of this.running) {
      if (!r.ctrl.signal.aborted && this.ledger.isCancelled(id)) r.ctrl.abort(new Aborted("已取消"));
    }
  }

  /** 只领取指定种类，直到没有在跑、也没有立即可领的工作（命令行单次运行用；期间保持心跳）。 */
  async drain(kinds: WorkKind[]): Promise<void> {
    const ownBeat = !this.beat;
    this.startBeat();
    try {
      for (;;) {
        this.tick(kinds);
        const busy = [...this.running.values()].filter((r) => kinds.includes(r.item.kind));
        if (!busy.length) return;
        await Promise.race(busy.map((r) => r.promise));
      }
    } finally {
      if (ownBeat && !this.started) {
        clearInterval(this.beat);
        this.beat = undefined;
      }
    }
  }

  /** 优雅退出：中止本地执行（结束 harness 进程组），等它们释放租约。 */
  async stop(): Promise<void> {
    this.stopping = true;
    clearInterval(this.timer);
    clearInterval(this.beat);
    for (const r of this.running.values()) r.ctrl.abort(new Aborted("进程退出"));
    await Promise.allSettled([...this.running.values()].map((r) => r.promise));
  }
}

/** handler 在步骤边界调用：已取消 / 已中止就抛出，让引擎接手。 */
export function checkpoint(ctx: Ctx): void {
  if (ctx.signal.aborted) throw ctx.signal.reason instanceof Error ? ctx.signal.reason : new Aborted(String(ctx.signal.reason));
}
