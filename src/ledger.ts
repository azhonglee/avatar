import { randomUUID } from "node:crypto";
import os from "node:os";
import type { DatabaseSync } from "node:sqlite";
import { isAlive } from "./util.ts";

/**
 * 账本：所有“要做的事”的唯一事实来源（docs/可靠性设计.md）。
 *
 * 一张 work 表承载四类工作，共用同一套领取 / 租约 / 重试 / 终态机制：
 *   event    —— inbox：外部输入（飞书事件）原样落库后才算“收到”
 *   effect   —— outbox：对飞书的写操作意图，与状态迁移在同一事务里提交，由发布器幂等投递
 *   dispatch —— 派单状态机（queued → executing → verifying → 终态）
 *   job      —— agent 作业（至多一次：中断后不重跑，而是报告）
 *
 * 领取用租约（lease_owner + lease_until）表示归属，持有者靠心跳续约；进程崩溃后租约过期或
 * 被判定持有者已死，工作会被重新领取并从最后的检查点继续。所有状态写入都以“仍持有租约”为前提
 * （fencing），失去租约的旧执行者无法覆盖新执行者的进度。
 */

export type WorkKind = "event" | "effect" | "dispatch" | "job";

export interface WorkItem<P = Record<string, unknown>> {
  seq: number;
  id: string;
  kind: WorkKind;
  /** 关联对象：dispatch 是任务 guid，event 是 EventKey，effect 是所属 work id */
  ref: string;
  state: string;
  terminal: boolean;
  outcome: string;
  reason: string;
  /** 当前状态已尝试的次数（领取时 +1，进入新状态时重置为 1） */
  attempts: number;
  next_at: number;
  lease_owner: string;
  lease_until: number;
  cancel: boolean;
  payload: P;
  error: string;
  created: number;
  updated: number;
}

export type Effect =
  | { op: "task.move"; args: { guid: string; section: string } }
  | { op: "task.comment"; args: { guid: string; content: string } }
  | { op: "notify"; args: { markdown: string } };

export interface Patch<P> {
  state?: string;
  terminal?: boolean;
  outcome?: string;
  reason?: string;
  payload?: P;
  next_at?: number;
  error?: string;
}

export interface Step {
  id: number;
  work_id: string;
  name: string;
  harness: string;
  status: "running" | "ok" | "failed" | "interrupted";
  owner: string;
  pid: number;
  log: string;
  summary: string;
  started: number;
  ended: number | null;
}

export class LeaseLost extends Error {
  constructor(id: string) {
    super(`已失去 ${id} 的租约（可能被其他进程接管），放弃本次写入`);
  }
}

type Row = Record<string, unknown>;

function toItem<P>(r: Row): WorkItem<P> {
  return {
    ...(r as unknown as WorkItem<P>),
    terminal: !!r.terminal,
    cancel: !!r.cancel,
    payload: JSON.parse(String(r.payload ?? "{}")) as P,
  };
}

/** 进程身份：主机 + pid + 随机串（容器里 pid 会复用，随机串用来区分同 pid 的前世今生）。 */
export function makeOwnerId(): string {
  return `${os.hostname()}:${process.pid}:${randomUUID().slice(0, 8)}`;
}

/** 租约持有者是否确定已经不在了。只在同一台机器上能判断；其他机器上的持有者只能等租约过期。 */
export function isDeadOwner(owner: string, self: string): boolean {
  if (!owner || owner === self) return false;
  const [host, pidStr] = owner.split(":");
  if (host !== os.hostname()) return false;
  const pid = Number(pidStr);
  if (pid === process.pid) return true; // 同 pid 但随机串不同：上一个同 pid 的进程已经没了
  return !isAlive(pid);
}

export class Ledger {
  db: DatabaseSync;
  owner: string;
  constructor(db: DatabaseSync, owner = makeOwnerId()) {
    this.db = db;
    this.owner = owner;
    db.exec(`
      CREATE TABLE IF NOT EXISTS work (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        id TEXT NOT NULL UNIQUE,
        kind TEXT NOT NULL,
        ref TEXT NOT NULL DEFAULT '',
        state TEXT NOT NULL,
        terminal INTEGER NOT NULL DEFAULT 0,
        outcome TEXT NOT NULL DEFAULT '',
        reason TEXT NOT NULL DEFAULT '',
        attempts INTEGER NOT NULL DEFAULT 0,
        next_at INTEGER NOT NULL DEFAULT 0,
        lease_owner TEXT NOT NULL DEFAULT '',
        lease_until INTEGER NOT NULL DEFAULT 0,
        cancel INTEGER NOT NULL DEFAULT 0,
        payload TEXT NOT NULL DEFAULT '{}',
        error TEXT NOT NULL DEFAULT '',
        created INTEGER NOT NULL,
        updated INTEGER NOT NULL);
      CREATE INDEX IF NOT EXISTS work_runnable ON work (kind, terminal, next_at);
      CREATE INDEX IF NOT EXISTS work_ref ON work (kind, ref);
      -- 不变量：同一张卡片同时至多一项未终结的派单（命令行和常驻进程同时对账也不会重复派单）
      CREATE UNIQUE INDEX IF NOT EXISTS work_one_active_dispatch ON work (ref) WHERE kind = 'dispatch' AND terminal = 0 AND ref != '';
      CREATE TABLE IF NOT EXISTS steps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        work_id TEXT NOT NULL,
        name TEXT NOT NULL,
        harness TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL,
        owner TEXT NOT NULL DEFAULT '',
        pid INTEGER NOT NULL DEFAULT 0,
        log TEXT NOT NULL DEFAULT '',
        summary TEXT NOT NULL DEFAULT '',
        started INTEGER NOT NULL,
        ended INTEGER);
      CREATE INDEX IF NOT EXISTS steps_work ON steps (work_id);
    `);
  }

  tx<T>(fn: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const r = fn();
      this.db.exec("COMMIT");
      return r;
    } catch (e) {
      this.db.exec("ROLLBACK");
      throw e;
    }
  }

  /** 幂等入队：同一 id 只会插入一次（事件去重、作业按时间槽去重都靠它）。返回是否新插入。 */
  enqueue(w: { id: string; kind: WorkKind; ref?: string; state?: string; payload?: unknown; next_at?: number }): boolean {
    const now = Date.now();
    const r = this.db
      .prepare(
        "INSERT OR IGNORE INTO work (id, kind, ref, state, payload, next_at, created, updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(w.id, w.kind, w.ref ?? "", w.state ?? "pending", JSON.stringify(w.payload ?? {}), w.next_at ?? 0, now, now);
    return r.changes > 0;
  }

  get<P = Record<string, unknown>>(id: string): WorkItem<P> | undefined {
    const r = this.db.prepare("SELECT * FROM work WHERE id = ?").get(id) as Row | undefined;
    return r ? toItem<P>(r) : undefined;
  }

  /**
   * 领取一项可运行的工作：未终结、到了重试时间、没有有效租约。原子地写入租约并把 attempts +1。
   * effect 额外要求同一 ref 下更早的 effect 已经落定，保证同一任务的“评论→移动”按顺序投递。
   */
  claim<P = Record<string, unknown>>(kind: WorkKind, leaseMs: number): WorkItem<P> | undefined {
    const now = Date.now();
    const order =
      kind === "effect"
        ? `AND NOT EXISTS (SELECT 1 FROM work e WHERE e.kind = 'effect' AND e.ref = w.ref AND e.seq < w.seq AND e.terminal = 0)`
        : "";
    const r = this.db
      .prepare(
        `UPDATE work SET lease_owner = ?, lease_until = ?, attempts = attempts + 1, updated = ?
         WHERE seq = (SELECT seq FROM work w WHERE kind = ? AND terminal = 0 AND next_at <= ? AND lease_until < ? ${order}
                      ORDER BY next_at, seq LIMIT 1)
         RETURNING *`,
      )
      .get(this.owner, now + leaseMs, now, kind, now, now) as Row | undefined;
    return r ? toItem<P>(r) : undefined;
  }

  /** 续约。返回已经失去租约的 id（被他人接管或已被释放）。 */
  heartbeat(ids: string[], leaseMs: number): string[] {
    const lost: string[] = [];
    const stmt = this.db.prepare("UPDATE work SET lease_until = ? WHERE id = ? AND lease_owner = ? AND terminal = 0");
    for (const id of ids) if (stmt.run(Date.now() + leaseMs, id, this.owner).changes === 0) lost.push(id);
    return lost;
  }

  /** 释放租约（不改变状态）：失败后按 nextAt 重试；refund 用于优雅退出时不计入尝试次数。 */
  release(id: string, o: { nextAt?: number; error?: string; refund?: boolean } = {}): void {
    this.db
      .prepare(
        `UPDATE work SET lease_owner = '', lease_until = 0, next_at = COALESCE(?, next_at), error = COALESCE(?, error),
           attempts = attempts - ?, updated = ? WHERE id = ? AND lease_owner = ?`,
      )
      .run(o.nextAt ?? null, o.error ?? null, o.refund ? 1 : 0, Date.now(), id, this.owner);
  }

  /**
   * 状态迁移 + 副作用意图，在同一事务里提交；以仍持有租约为前提（否则抛 LeaseLost，什么都不写）。
   * 进入新状态时 attempts 重置为 1（当前这次就是新状态的第 1 次尝试）；进入终态时同时释放租约。
   */
  transition<P>(item: WorkItem<P>, patch: Patch<P>, effects: Effect[] = []): WorkItem<P> {
    return this.tx(() => {
      const cur = this.db.prepare("SELECT * FROM work WHERE id = ?").get(item.id) as Row | undefined;
      if (!cur || cur.lease_owner !== this.owner || Number(cur.terminal)) throw new LeaseLost(item.id);
      const now = Date.now();
      const terminal = patch.terminal ?? false;
      const stateChanged = patch.state !== undefined && patch.state !== cur.state;
      this.db
        .prepare(
          `UPDATE work SET state = ?, terminal = ?, outcome = ?, reason = ?, payload = ?, next_at = ?, error = ?,
             attempts = ?, lease_owner = ?, lease_until = ?, updated = ? WHERE id = ?`,
        )
        .run(
          patch.state ?? String(cur.state),
          terminal ? 1 : 0,
          patch.outcome ?? String(cur.outcome),
          patch.reason ?? String(cur.reason),
          patch.payload !== undefined ? JSON.stringify(patch.payload) : String(cur.payload),
          patch.next_at ?? Number(cur.next_at),
          patch.error ?? (stateChanged ? "" : String(cur.error)),
          stateChanged ? 1 : Number(cur.attempts),
          terminal ? "" : this.owner,
          terminal ? 0 : Number(cur.lease_until),
          now,
          item.id,
        );
      this.insertEffects(item.id, effects, now);
      return toItem<P>(this.db.prepare("SELECT * FROM work WHERE id = ?").get(item.id) as Row);
    });
  }

  /** 不伴随状态迁移的副作用（例如晨报私信），同样落库后由发布器投递。key 用于去重。 */
  emit(parent: string, effects: Effect[], key?: string): void {
    this.tx(() => {
      if (key) {
        const exists = this.db.prepare("SELECT 1 FROM work WHERE id = ?").get(`fx:${key}`);
        if (exists) return;
      }
      this.insertEffects(parent, effects, Date.now(), key);
    });
  }

  private insertEffects(parent: string, effects: Effect[], now: number, key?: string): void {
    const stmt = this.db.prepare(
      "INSERT INTO work (id, kind, ref, state, payload, created, updated) VALUES (?, 'effect', ?, 'pending', ?, ?, ?)",
    );
    effects.forEach((e, i) => {
      const id = key ? `fx:${key}${i ? `:${i}` : ""}` : `fx:${randomUUID()}`;
      stmt.run(id, parent, JSON.stringify(e), now, now);
    });
  }

  /** 请求取消（用户把卡片拖走等）。执行者在步骤边界或心跳时看到后自行收尾。 */
  requestCancel(id: string): void {
    this.db.prepare("UPDATE work SET cancel = 1, next_at = 0, updated = ? WHERE id = ? AND terminal = 0").run(Date.now(), id);
  }

  isCancelled(id: string): boolean {
    return !!(this.db.prepare("SELECT cancel FROM work WHERE id = ?").get(id) as { cancel: number } | undefined)?.cancel;
  }

  active<P = Record<string, unknown>>(kind: WorkKind): WorkItem<P>[] {
    return (this.db.prepare("SELECT * FROM work WHERE kind = ? AND terminal = 0 ORDER BY seq").all(kind) as Row[]).map((r) => toItem<P>(r));
  }

  latest<P = Record<string, unknown>>(kind: WorkKind, ref: string): WorkItem<P> | undefined {
    const r = this.db.prepare("SELECT * FROM work WHERE kind = ? AND ref = ? ORDER BY seq DESC LIMIT 1").get(kind, ref) as Row | undefined;
    return r ? toItem<P>(r) : undefined;
  }

  /** 某项工作还有多少副作用没投递（对账时据此判断看板是否“还没跟上”）。 */
  pendingEffects(parent: string): number {
    return (this.db.prepare("SELECT COUNT(*) AS n FROM work WHERE kind = 'effect' AND ref = ? AND terminal = 0").get(parent) as { n: number }).n;
  }

  /** 有效租约数（含其他进程持有的），用于全局并发上限。 */
  leasedCount(kind: WorkKind): number {
    return (
      this.db.prepare("SELECT COUNT(*) AS n FROM work WHERE kind = ? AND terminal = 0 AND lease_until >= ?").get(kind, Date.now()) as { n: number }
    ).n;
  }

  /** 清掉确定已死的持有者的租约，让工作立即可被重新领取（不必等租约过期）。 */
  reapDeadOwners(): number {
    const owners = this.db
      .prepare("SELECT DISTINCT lease_owner FROM work WHERE terminal = 0 AND lease_until >= ? AND lease_owner != ''")
      .all(Date.now()) as { lease_owner: string }[];
    let n = 0;
    for (const { lease_owner } of owners) {
      if (!isDeadOwner(lease_owner, this.owner)) continue;
      n += Number(this.db.prepare("UPDATE work SET lease_until = 0 WHERE lease_owner = ? AND terminal = 0").run(lease_owner).changes);
    }
    return n;
  }

  // ── 步骤审计：每次 harness / 校验命令的执行都记一条 ──

  startStep(s: { work_id: string; name: string; harness?: string; log?: string }): number {
    const r = this.db
      .prepare("INSERT INTO steps (work_id, name, harness, status, owner, log, started) VALUES (?, ?, ?, 'running', ?, ?, ?)")
      .run(s.work_id, s.name, s.harness ?? "", this.owner, s.log ?? "", Date.now());
    return Number(r.lastInsertRowid);
  }

  setStepPid(id: number, pid: number): void {
    this.db.prepare("UPDATE steps SET pid = ? WHERE id = ?").run(pid, id);
  }

  endStep(id: number, status: "ok" | "failed", summary: string): void {
    this.db.prepare("UPDATE steps SET status = ?, summary = ?, ended = ? WHERE id = ? AND status = 'running'").run(status, summary, Date.now(), id);
  }

  /** 接管一项工作时，把前任遗留的 running 步骤标为中断并返回（调用方据此清理遗留进程组）。 */
  interruptSteps(workId: string): Step[] {
    const rows = this.db
      .prepare("SELECT * FROM steps WHERE work_id = ? AND status = 'running' AND owner != ?")
      .all(workId, this.owner) as unknown as Step[];
    if (rows.length)
      this.db
        .prepare("UPDATE steps SET status = 'interrupted', ended = ?, summary = '执行者中断' WHERE work_id = ? AND status = 'running' AND owner != ?")
        .run(Date.now(), workId, this.owner);
    return rows;
  }

  steps(workId: string): Step[] {
    return this.db.prepare("SELECT * FROM steps WHERE work_id = ? ORDER BY id").all(workId) as unknown as Step[];
  }

  // ── 汇总与清理 ──

  recent(kinds: WorkKind[], since: number): WorkItem[] {
    const q = `SELECT * FROM work WHERE kind IN (${kinds.map(() => "?").join(",")}) AND (terminal = 0 OR updated >= ?) ORDER BY updated`;
    return (this.db.prepare(q).all(...kinds, since) as Row[]).map((r) => toItem(r));
  }

  /** 失败落定（dead/errored）的数量，按种类。 */
  failuresSince(since: number): Record<string, number> {
    const rows = this.db
      .prepare("SELECT kind, COUNT(*) AS n FROM work WHERE terminal = 1 AND state IN ('dead', 'errored') AND updated >= ? GROUP BY kind")
      .all(since) as { kind: string; n: number }[];
    return Object.fromEntries(rows.map((r) => [r.kind, r.n]));
  }

  prune(days = 30): void {
    const cutoff = Date.now() - days * 86_400_000;
    this.tx(() => {
      this.db.prepare("DELETE FROM steps WHERE work_id IN (SELECT id FROM work WHERE terminal = 1 AND updated < ?)").run(cutoff);
      this.db.prepare("DELETE FROM work WHERE terminal = 1 AND updated < ?").run(cutoff);
    });
  }
}
