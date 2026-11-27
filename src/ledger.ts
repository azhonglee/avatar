import { randomUUID } from "node:crypto";
import os from "node:os";
import type { DatabaseSync } from "node:sqlite";
import type { Bus } from "./bus.ts";
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

export type WorkKind = "event" | "effect" | "dispatch" | "job" | "delivery" | "context";

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
  | { op: "task.complete"; args: { guid: string } }
  | { op: "notify"; args: { markdown: string; kind?: NotifyKind; owner_open_id?: string } }
  /**
   * 飞书交互卡片：同一个 key 只有一张卡片——第一次发送，之后原地更新（messages patch）。
   * card 是完整的卡片 JSON（schema 2.0）。
   */
  | { op: "card.upsert"; args: { key: string; card: Record<string, unknown>; kind?: NotifyKind; owner_open_id?: string } }
  /** 以你本人身份回复一条消息（只在你确认草稿后产生） */
  | { op: "im.reply"; args: { message_id: string; text: string; draft_id?: string } }
  /** 以你本人身份在会话里发一条消息（只在你确认草稿后产生） */
  | { op: "im.send"; args: { chat_id: string; text: string; draft_id?: string } }
  /** 以你本人身份经个人 Web 协议回复（绑定原确认账号，带发送前核验与独立回读确认；只在你确认草稿后产生） */
  | { op: "pw.reply"; args: { owner_id: string; chat_id: string; message_id: string; root_id?: string; text: string; draft_id?: string } }
  /** 以你本人身份给 Meego 工作项写评论（只在你确认草稿后产生） */
  | { op: "meego.comment"; args: { project_key: string; work_item_id: string; content: string; draft_id?: string } }
  /** 以你本人身份在「我的文档库」里新建文档（周报草稿确认后） */
  | { op: "doc.create"; args: { title: string; markdown: string; draft_id?: string } }
  /** 给你自己建一条飞书任务（L2 自主动作，需在 autonomy 里开启） */
  | { op: "task.create_own"; args: { summary: string; description: string; due?: string; item_id?: string } };

/** 通知类型，对应 config.notify.types，用于免打扰与开关 */
export type NotifyKind = "candidate" | "progress" | "result" | "failure" | "brief" | "nudge";

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
  tokens_in: number;
  tokens_out: number;
  cost_usd: number;
  duration_ms: number;
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

export interface AuditEntry {
  id: number;
  at: number;
  source: string;
  actor: string;
  command: string;
  target: string;
  args: string;
  ok: number;
  message: string;
}

export class Ledger {
  db: DatabaseSync;
  owner: string;
  /** 可选：进程内事件总线，状态变化时发出 work.changed（刷新控制台、更新卡片） */
  bus?: Bus;
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
      CREATE INDEX IF NOT EXISTS work_kind_terminal_seq ON work (kind, terminal, seq DESC);
      CREATE INDEX IF NOT EXISTS work_kind_state_seq ON work (kind, state, seq DESC);
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
      CREATE TABLE IF NOT EXISTS audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        at INTEGER NOT NULL,
        source TEXT NOT NULL,
        actor TEXT NOT NULL DEFAULT '',
        command TEXT NOT NULL,
        target TEXT NOT NULL DEFAULT '',
        args TEXT NOT NULL DEFAULT '{}',
        ok INTEGER NOT NULL,
        message TEXT NOT NULL DEFAULT '');
    `);
    // 迁移：用量列（旧库没有）
    for (const [col, def] of [
      ["tokens_in", "INTEGER NOT NULL DEFAULT 0"],
      ["tokens_out", "INTEGER NOT NULL DEFAULT 0"],
      ["cost_usd", "REAL NOT NULL DEFAULT 0"],
      ["duration_ms", "INTEGER NOT NULL DEFAULT 0"],
    ] as const) {
      const cols = db.prepare("PRAGMA table_info(steps)").all() as { name: string }[];
      if (!cols.some((c) => c.name === col)) db.exec(`ALTER TABLE steps ADD COLUMN ${col} ${def}`);
    }
  }

  /** 通知总线（在事务提交之后调用）。 */
  private changed(id: string): void {
    if (!this.bus) return;
    const w = this.get(id);
    if (w) this.bus.emit("work.changed", { id: w.id, kind: w.kind, ref: w.ref, state: w.state, terminal: w.terminal });
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
  enqueue(w: { id: string; kind: WorkKind; ref?: string; state?: string; payload?: unknown; next_at?: number }, effects: Effect[] = []): boolean {
    const now = Date.now();
    const added = this.tx(() => {
      const r = this.db
        .prepare(
          "INSERT OR IGNORE INTO work (id, kind, ref, state, payload, next_at, created, updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .run(w.id, w.kind, w.ref ?? "", w.state ?? "pending", JSON.stringify(w.payload ?? {}), w.next_at ?? 0, now, now);
      // 副作用只在真正入队时一起提交（与入队原子）
      if (r.changes > 0) this.insertEffects(w.id, effects, now);
      return r.changes > 0;
    });
    if (added && w.kind !== "effect") this.changed(w.id);
    return added;
  }

  get<P = Record<string, unknown>>(id: string): WorkItem<P> | undefined {
    const r = this.db.prepare("SELECT * FROM work WHERE id = ?").get(id) as Row | undefined;
    return r ? toItem<P>(r) : undefined;
  }

  /**
   * 领取一项可运行的工作：未终结、到了重试时间、没有有效租约。原子地写入租约并把 attempts +1。
   * effect 额外要求同一 ref 下更早的 effect 已经落定，保证同一任务的“评论→移动”按顺序投递。
   */
  claim<P = Record<string, unknown>>(
    kind: WorkKind,
    leaseMs: number,
    opts?: { excludeEffectOps?: string[]; allowEffectIds?: string[] },
  ): WorkItem<P> | undefined {
    const now = Date.now();
    const order =
      kind === "effect"
        ? `AND NOT EXISTS (SELECT 1 FROM work e WHERE e.kind = 'effect' AND e.ref = w.ref AND e.seq < w.seq AND e.terminal = 0)`
        : "";
    const excludedOps = kind === "effect" ? (opts?.excludeEffectOps ?? []).filter(Boolean) : [];
    const allowedIds = kind === "effect" ? (opts?.allowEffectIds ?? []).filter(Boolean) : [];
    const opFilter = excludedOps.length
      ? allowedIds.length
        ? `AND (COALESCE(json_extract(w.payload, '$.op'), '') NOT IN (${excludedOps.map(() => "?").join(", ")}) OR w.id IN (${allowedIds.map(() => "?").join(", ")}))`
        : `AND COALESCE(json_extract(w.payload, '$.op'), '') NOT IN (${excludedOps.map(() => "?").join(", ")})`
      : "";
    const filterArgs = excludedOps.length ? [...excludedOps, ...allowedIds] : [];
    const r = this.db
      .prepare(
        `UPDATE work SET lease_owner = ?, lease_until = ?, attempts = attempts + 1, updated = ?
         WHERE seq = (SELECT seq FROM work w WHERE kind = ? AND terminal = 0 AND next_at <= ? AND lease_until < ? ${order} ${opFilter}
                      ORDER BY next_at, seq LIMIT 1)
         RETURNING *`,
      )
      .get(this.owner, now + leaseMs, now, kind, now, now, ...filterArgs) as Row | undefined;
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
    const w = this.tx(() => {
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
    if (w.kind !== "effect") this.changed(w.id);
    else if (w.terminal) this.bus?.emit("effect.settled", { id: w.id, ref: w.ref, state: w.state });
    return w;
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
  requestCancel(id: string): boolean {
    const n = this.db.prepare("UPDATE work SET cancel = 1, next_at = 0, updated = ? WHERE id = ? AND terminal = 0").run(Date.now(), id).changes;
    if (n) this.changed(id);
    return n > 0;
  }

  /**
   * 重新激活一项失败落定的工作（event / effect / job 的 dead / errored）：回到 pending，清零尝试次数，立即可领取。
   * 只允许没有被他人持有的终态工作。返回是否成功。
   */
  revive(id: string): boolean {
    const n = this.db
      .prepare(
        `UPDATE work SET terminal = 0, state = 'pending', outcome = '', reason = '', attempts = 0, next_at = 0, error = '',
           lease_owner = '', lease_until = 0, cancel = 0, updated = ? WHERE id = ? AND terminal = 1 AND state IN ('dead', 'errored')`,
      )
      .run(Date.now(), id).changes;
    if (n) this.changed(id);
    return n > 0;
  }

  /** 确认知晓一项失败（不再在健康页 / 晨报里提示）。 */
  acknowledge(id: string): boolean {
    const n = this.db
      .prepare("UPDATE work SET outcome = 'acknowledged', updated = ? WHERE id = ? AND terminal = 1 AND state IN ('dead', 'errored')")
      .run(Date.now(), id).changes;
    if (n) this.changed(id);
    return n > 0;
  }

  /** 列出工作（控制台用）。支持 terminal、states 与 search 下推 SQL 过滤，避免在长历史账本上空扫全表。 */
  list<P = Record<string, unknown>>(f: {
    kinds: WorkKind[];
    states?: string[];
    terminal?: boolean;
    ref?: string;
    search?: string;
    updatedSince?: number;
    limit?: number;
    before?: number;
  }): WorkItem<P>[] {
    const where = [`kind IN (${f.kinds.map(() => "?").join(",")})`];
    const args: (string | number)[] = [...f.kinds];
    if (f.states?.length) {
      where.push(`state IN (${f.states.map(() => "?").join(",")})`);
      args.push(...f.states);
    }
    if (f.terminal !== undefined) {
      where.push("terminal = ?");
      args.push(f.terminal ? 1 : 0);
    }
    if (f.ref) {
      where.push("ref = ?");
      args.push(f.ref);
    }
    if (f.updatedSince !== undefined) {
      where.push("updated > ?");
      args.push(f.updatedSince);
    }
    if (f.search) {
      const q = f.search.trim().toLowerCase();
      if (q) {
        const pat = `%${q.replace(/[\\%_]/g, "\\$&")}%`;
        where.push(
          `LOWER(CAST(COALESCE(json_extract(payload, '$.summary'), '') AS TEXT) || ' ' || ref || ' ' || id) LIKE ? ESCAPE '\\'`,
        );
        args.push(pat);
      }
    }
    if (f.before) {
      where.push("seq < ?");
      args.push(f.before);
    }
    const q = `SELECT * FROM work WHERE ${where.join(" AND ")} ORDER BY seq DESC LIMIT ?`;
    return (this.db.prepare(q).all(...args, f.limit ?? 100) as Row[]).map((r) => toItem<P>(r));
  }

  /** 某项工作产生的副作用（含已投递的），按顺序。 */
  effectsOf(parent: string): WorkItem<Effect>[] {
    return (this.db.prepare("SELECT * FROM work WHERE kind = 'effect' AND ref = ? ORDER BY seq").all(parent) as Row[]).map((r) => toItem<Effect>(r));
  }

  // ── 审计：所有命令（控制台、卡片、私聊、CLI）都记一条 ──

  audit(e: { source: string; actor: string; command: string; target: string; args: unknown; ok: boolean; message: string }): void {
    this.db
      .prepare("INSERT INTO audit (at, source, actor, command, target, args, ok, message) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
      .run(Date.now(), e.source, e.actor, e.command, e.target, JSON.stringify(e.args ?? {}), e.ok ? 1 : 0, e.message);
  }

  auditLog(limit = 100, target?: string, before?: number): AuditEntry[] {
    const where: string[] = [];
    const args: (string | number)[] = [];
    if (target) {
      where.push("target = ?");
      args.push(target);
    }
    if (before !== undefined) {
      where.push("id < ?");
      args.push(before);
    }
    const clause = where.length ? `WHERE ${where.join(" AND ")}` : "";
    return this.db.prepare(`SELECT * FROM audit ${clause} ORDER BY id DESC LIMIT ?`).all(...args, limit) as unknown as AuditEntry[];
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
    this.db
      .prepare("UPDATE steps SET status = ?, summary = ?, ended = ?, duration_ms = ? - started WHERE id = ? AND status = 'running'")
      .run(status, summary, Date.now(), Date.now(), id);
  }

  /** 记录一步的用量（token 与费用；拿不到时保持 0）。 */
  setStepUsage(id: number, u: { tokens_in?: number; tokens_out?: number; cost_usd?: number }): void {
    this.db
      .prepare("UPDATE steps SET tokens_in = ?, tokens_out = ?, cost_usd = ? WHERE id = ?")
      .run(u.tokens_in ?? 0, u.tokens_out ?? 0, u.cost_usd ?? 0, id);
  }

  step(id: number): Step | undefined {
    return this.db.prepare("SELECT * FROM steps WHERE id = ?").get(id) as unknown as Step | undefined;
  }

  /** 一项工作（含同一张卡片的所有派单）累计花费。 */
  costOf(workIds: string[]): number {
    if (!workIds.length) return 0;
    const r = this.db
      .prepare(`SELECT COALESCE(SUM(cost_usd), 0) AS c FROM steps WHERE work_id IN (${workIds.map(() => "?").join(",")})`)
      .get(...workIds) as { c: number };
    return r.c;
  }

  /** 时间段内的总花费。 */
  costSince(since: number): number {
    return (this.db.prepare("SELECT COALESCE(SUM(cost_usd), 0) AS c FROM steps WHERE started >= ?").get(since) as { c: number }).c;
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
