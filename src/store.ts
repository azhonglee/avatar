import { DatabaseSync } from "node:sqlite";
import path from "node:path";

/**
 * 本地状态：kv（游标、看板/知识库 ID、幂等操作结果）与信号队列（分诊审计）。
 * 工作的进度与副作用在账本里（ledger.ts，和本类共用同一个 SQLite 文件）。
 */
export class Store {
  db: DatabaseSync;

  constructor(dataDir: string) {
    this.db = new DatabaseSync(path.join(dataDir, "state.db"));
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA busy_timeout = 10000;
      CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS seen (id TEXT PRIMARY KEY, kind TEXT NOT NULL, at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS signals (
        id TEXT PRIMARY KEY, source TEXT NOT NULL, at INTEGER NOT NULL, text TEXT NOT NULL,
        link TEXT NOT NULL, verdict TEXT NOT NULL DEFAULT '', task_guid TEXT NOT NULL DEFAULT '');
      -- runs 是旧版的运行记录，已由 ledger 的 work/steps 取代，保留表以兼容旧数据
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

  /** 旧版去重表的写入（只保留给兼容测试；新代码用 ledger.enqueue / addSignal 的主键去重）。 */
  markSeen(id: string, kind: string): boolean {
    const r = this.db.prepare("INSERT OR IGNORE INTO seen (id, kind, at) VALUES (?, ?, ?)").run(id, kind, Date.now());
    return r.changes > 0;
  }

  hasSignal(id: string): boolean {
    return !!this.db.prepare("SELECT 1 FROM signals WHERE id = ?").get(id);
  }

  /**
   * 幂等的外部创建操作：同一 key 只创建一次，结果（如任务 guid）记在 kv。
   * 创建成功与记录结果之间崩溃仍可能重复——外部接口没有幂等参数时这是能做到的最小窗口。
   */
  async once(key: string, create: () => Promise<string>): Promise<string> {
    const k = `op.${key}`;
    const done = this.get(k);
    if (done) return done;
    const v = await create();
    this.set(k, v);
    return v;
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

  prune(days = 30): void {
    const cutoff = Date.now() - days * 86_400_000;
    this.db.prepare("DELETE FROM seen WHERE at < ?").run(cutoff);
  }
}
