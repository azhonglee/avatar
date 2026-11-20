import { DatabaseSync } from "node:sqlite";
import path from "node:path";

export interface Run {
  id: number;
  task_guid: string;
  harness: string;
  role: string;
  status: "running" | "ok" | "failed";
  started: number;
  ended: number | null;
  cwd: string;
  summary: string;
  log: string;
}

/** 本地状态只放“飞书里不该放”的东西：游标、去重、运行记录、分诊审计。业务状态都在飞书。 */
export class Store {
  db: DatabaseSync;

  constructor(dataDir: string) {
    this.db = new DatabaseSync(path.join(dataDir, "state.db"));
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS seen (id TEXT PRIMARY KEY, kind TEXT NOT NULL, at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS signals (
        id TEXT PRIMARY KEY, source TEXT NOT NULL, at INTEGER NOT NULL, text TEXT NOT NULL,
        link TEXT NOT NULL, verdict TEXT NOT NULL DEFAULT '', task_guid TEXT NOT NULL DEFAULT '');
      CREATE TABLE IF NOT EXISTS runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT, task_guid TEXT NOT NULL, harness TEXT NOT NULL,
        role TEXT NOT NULL, status TEXT NOT NULL, started INTEGER NOT NULL, ended INTEGER,
        cwd TEXT NOT NULL DEFAULT '', summary TEXT NOT NULL DEFAULT '', log TEXT NOT NULL DEFAULT '');
    `);
  }

  get(k: string): string | undefined {
    const row = this.db.prepare("SELECT v FROM kv WHERE k = ?").get(k) as { v: string } | undefined;
    return row?.v;
  }

  set(k: string, v: string): void {
    this.db.prepare("INSERT INTO kv (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v").run(k, v);
  }

  /** 首次见到返回 true 并记下；重复返回 false。用于事件和信号去重。 */
  markSeen(id: string, kind: string): boolean {
    const r = this.db.prepare("INSERT OR IGNORE INTO seen (id, kind, at) VALUES (?, ?, ?)").run(id, kind, Date.now());
    return r.changes > 0;
  }

  addSignal(s: { id: string; source: string; text: string; link: string }): boolean {
    const r = this.db
      .prepare("INSERT OR IGNORE INTO signals (id, source, at, text, link) VALUES (?, ?, ?, ?, ?)")
      .run(s.id, s.source, Date.now(), s.text, s.link);
    return r.changes > 0;
  }

  setVerdict(id: string, verdict: string, taskGuid = ""): void {
    this.db.prepare("UPDATE signals SET verdict = ?, task_guid = ? WHERE id = ?").run(verdict, taskGuid, id);
  }

  pendingSignals(): { id: string; source: string; text: string; link: string }[] {
    return this.db.prepare("SELECT id, source, text, link FROM signals WHERE verdict = '' ORDER BY at").all() as never;
  }

  countSignalsSince(ms: number): { total: number; tasks: number } {
    return this.db
      .prepare("SELECT COUNT(*) AS total, SUM(task_guid != '') AS tasks FROM signals WHERE at >= ?")
      .get(ms) as never;
  }

  startRun(r: { task_guid: string; harness: string; role: string; cwd: string; log: string }): number {
    const res = this.db
      .prepare("INSERT INTO runs (task_guid, harness, role, status, started, cwd, log) VALUES (?, ?, ?, 'running', ?, ?, ?)")
      .run(r.task_guid, r.harness, r.role, Date.now(), r.cwd, r.log);
    return Number(res.lastInsertRowid);
  }

  updateRun(id: number, harness: string, cwd: string): void {
    this.db.prepare("UPDATE runs SET harness = ?, cwd = ? WHERE id = ?").run(harness, cwd, id);
  }

  endRun(id: number, status: "ok" | "failed", summary: string): void {
    this.db.prepare("UPDATE runs SET status = ?, ended = ?, summary = ? WHERE id = ?").run(status, Date.now(), summary, id);
  }

  isRunning(taskGuid: string): boolean {
    return !!this.db.prepare("SELECT 1 FROM runs WHERE task_guid = ? AND status = 'running'").get(taskGuid);
  }

  runningCount(): number {
    return (this.db.prepare("SELECT COUNT(*) AS n FROM runs WHERE status = 'running' AND role = 'worker'").get() as { n: number }).n;
  }

  runsSince(ms: number): Run[] {
    return this.db.prepare("SELECT * FROM runs WHERE started >= ? ORDER BY started").all(ms) as unknown as Run[];
  }

  /** 进程重启后，上次没跑完的 run 不会再有结果，标记失败。 */
  failStaleRuns(): number {
    return Number(
      this.db.prepare("UPDATE runs SET status = 'failed', ended = ?, summary = '进程重启，运行中断' WHERE status = 'running'").run(Date.now())
        .changes,
    );
  }

  prune(days = 30): void {
    const cutoff = Date.now() - days * 86_400_000;
    this.db.prepare("DELETE FROM seen WHERE at < ?").run(cutoff);
  }
}
