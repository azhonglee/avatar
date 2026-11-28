import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import type { GatewayEvent, GatewayEventsResponse, GatewayListenerState, GatewayMessagePayload } from "./protocol.ts";
import { MAX_EVENTS_LIMIT } from "./protocol.ts";

/**
 * 网关独立持久化存储（SQLite WAL + 0600 tokens.json）。
 *
 * 职责：
 *   - 维护单调递增 seq 事件日志（gw_events），主进程重启或断线后可按游标零丢失补拉；
 *   - 追踪已知消息（gw_messages），支持撤回/清空消息时立即擦除缓存正文并写入 delete 墓碑事件；
 *   - 维护网关侧发送幂等账本（gw_deliveries：sending / created / verified），跨进程防重发；
 *   - 托管读写分离双令牌（read_token / reply_token），优先从环境变量或 systemd LoadCredential 读取。
 */

export interface GatewayDeliveryRecord {
  cid: string;
  status: "sending" | "created" | "verified";
  reply_id: string;
  chat_id: string;
  root_id: string;
  parent_id: string;
  threaded: boolean;
  thread_id: string;
  text_hash: string;
  updated_at: number;
}

export interface GatewayPersistedState {
  state: GatewayListenerState;
  owner_id: string;
  owner_name: string;
  since: number;
  last_message_at: number | null;
  last_error: string;
}

export interface ResolvedGatewayTokens {
  readToken: string;
  replyToken: string;
  readSource: "env" | "credential" | "file";
  replySource: "env" | "credential" | "file";
  file: string;
}

export interface RecordedTokenSources {
  read: ResolvedGatewayTokens["readSource"];
  reply: ResolvedGatewayTokens["replySource"];
  updated_at?: string;
}

export interface ResolveTokensOptions {
  rotateRead?: boolean;
  rotateReply?: boolean;
  /** 当运行中的网关最近是通过 systemd LoadCredential / 环境变量加载令牌、而当前 shell 未提供它们时，拒绝静默生成冲突的 tokens.json */
  rejectConflictingFileGeneration?: boolean;
}

interface TokenFileData {
  read_token: string;
  reply_token: string;
  updated_at: string;
}

const MIN_TOKEN_LEN = 16;

function readCredentialFile(names: string[]): string | undefined {
  const dir = process.env.CREDENTIALS_DIRECTORY?.trim();
  if (!dir) return undefined;
  for (const name of names) {
    try {
      const v = fs.readFileSync(path.join(dir, name), "utf8").trim();
      if (v) return v;
    } catch {
      // absent
    }
  }
  return undefined;
}

function generateToken(): string {
  return crypto.randomBytes(32).toString("base64url");
}

function writeAtomic0600(file: string, content: string): void {
  const dir = path.dirname(file);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const tmp = path.join(dir, `.${path.basename(file)}.${process.pid}.${Date.now()}.tmp`);
  let fd: number | undefined;
  try {
    fd = fs.openSync(tmp, "w", 0o600);
    fs.writeFileSync(fd, content, "utf8");
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    fs.chmodSync(tmp, 0o600);
    fs.renameSync(tmp, file);
  } catch (e) {
    if (fd !== undefined) {
      try {
        fs.closeSync(fd);
      } catch {
        // ignore
      }
    }
    fs.rmSync(tmp, { force: true });
    throw e;
  }
}

export class GatewayStore {
  readonly dataDir: string;
  readonly dbPath: string;
  readonly tokensFile: string;
  readonly db: DatabaseSync;

  constructor(dataDir: string) {
    this.dataDir = dataDir;
    fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
    try {
      fs.chmodSync(dataDir, 0o700);
    } catch {
      // ignore if platform does not support chmod
    }
    this.dbPath = path.join(dataDir, "gateway.db");
    this.tokensFile = path.join(dataDir, "tokens.json");
    // 预建 0600 数据库文件，消除首次建库时的短暂 0644 窗口
    const dbFd = fs.openSync(this.dbPath, "a", 0o600);
    fs.closeSync(dbFd);
    try {
      fs.chmodSync(this.dbPath, 0o600);
    } catch {
      // ignore if platform does not support chmod
    }
    this.db = new DatabaseSync(this.dbPath);
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA synchronous = FULL;
      PRAGMA temp_store = MEMORY;
      PRAGMA busy_timeout = 5000;

      CREATE TABLE IF NOT EXISTS gw_kv (
        k TEXT PRIMARY KEY,
        v TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS gw_chats (
        chat_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        kind TEXT NOT NULL DEFAULT '',
        updated_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS gw_messages (
        message_id TEXT PRIMARY KEY,
        chat_id TEXT NOT NULL,
        deleted INTEGER NOT NULL DEFAULT 0,
        updated_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS gw_events (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        kind TEXT NOT NULL,
        message_id TEXT NOT NULL,
        chat_id TEXT NOT NULL,
        chat_name TEXT NOT NULL DEFAULT '',
        payload TEXT,
        created_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_gw_events_msg ON gw_events(message_id);
      CREATE INDEX IF NOT EXISTS idx_gw_events_created ON gw_events(created_at);

      CREATE TABLE IF NOT EXISTS gw_deliveries (
        cid TEXT PRIMARY KEY,
        status TEXT NOT NULL,
        reply_id TEXT NOT NULL DEFAULT '',
        chat_id TEXT NOT NULL,
        root_id TEXT NOT NULL DEFAULT '',
        parent_id TEXT NOT NULL DEFAULT '',
        threaded INTEGER NOT NULL DEFAULT 0,
        thread_id TEXT NOT NULL DEFAULT '',
        text_hash TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_gw_deliveries_updated ON gw_deliveries(updated_at);
    `);
    // 建库时原子初始化 db_epoch（INSERT OR IGNORE 防并发覆盖，且保持后续 status() 纯读）
    this.db.prepare("INSERT OR IGNORE INTO gw_kv(k, v) VALUES ('db_epoch', ?)").run(crypto.randomUUID());
  }

  close(): void {
    this.db.close();
  }

  /** 事件库实例标识：首次建库时原子生成，库被删除重建后会变化，供客户端判断是否需要重置游标 */
  dbEpoch(): string {
    const existing = this.getKv("db_epoch");
    if (existing) return existing;
    this.db.prepare("INSERT OR IGNORE INTO gw_kv(k, v) VALUES ('db_epoch', ?)").run(crypto.randomUUID());
    return this.getKv("db_epoch") ?? "";
  }

  getKv(k: string): string | undefined {
    const row = this.db.prepare("SELECT v FROM gw_kv WHERE k = ?").get(k) as { v: string } | undefined;
    return row?.v;
  }

  setKv(k: string, v: string): void {
    this.db.prepare("INSERT INTO gw_kv(k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v").run(k, v);
  }

  deleteKv(k: string): void {
    this.db.prepare("DELETE FROM gw_kv WHERE k = ?").run(k);
  }

  /**
   * 强制切换绑定账号时原子清空旧账号的事件日志、消息索引、会话名缓存、投递账本与运行状态，
   * 重置 seq 序列并轮换 db_epoch、写入新 bound_owner_id，防止旧账号事件混入并让客户端立即识别新事件库实例。
   */
  resetForAccountSwitch(newOwnerId: string): { db_epoch: string } {
    const owner = newOwnerId.trim();
    if (!owner) throw new Error("新绑定账号 owner_id 不能为空");
    const nextEpoch = crypto.randomUUID();
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.exec(`
        DELETE FROM gw_events;
        DELETE FROM gw_messages;
        DELETE FROM gw_chats;
        DELETE FROM gw_deliveries;
      `);
      this.db.prepare("DELETE FROM sqlite_sequence WHERE name = 'gw_events'").run();
      this.deleteKv("state");
      this.setKv("db_epoch", nextEpoch);
      this.setKv("bound_owner_id", owner);
      this.db.exec("COMMIT");
      return { db_epoch: nextEpoch };
    } catch (e) {
      this.safeRollback();
      throw e;
    }
  }

  loadState(): GatewayPersistedState | undefined {
    const raw = this.getKv("state");
    if (!raw) return undefined;
    try {
      return JSON.parse(raw) as GatewayPersistedState;
    } catch {
      return undefined;
    }
  }

  saveState(st: GatewayPersistedState): void {
    this.setKv("state", JSON.stringify(st));
  }

  hasKnownMessage(messageId: string): boolean {
    const row = this.db.prepare("SELECT deleted FROM gw_messages WHERE message_id = ?").get(messageId) as { deleted: number } | undefined;
    return !!row && row.deleted === 0;
  }

  upsertChat(chatId: string, name: string, kind = "", expectedOwnerId?: string): void {
    if (!chatId || !name) return;
    const expected = expectedOwnerId?.trim() ?? "";
    if (expected) {
      this.db
        .prepare(
          `INSERT INTO gw_chats(chat_id, name, kind, updated_at)
           SELECT ?, ?, ?, ?
           WHERE NOT EXISTS (SELECT 1 FROM gw_kv WHERE k = 'bound_owner_id' AND v != '' AND v != ?)
           ON CONFLICT(chat_id) DO UPDATE SET name = excluded.name, kind = CASE WHEN excluded.kind != '' THEN excluded.kind ELSE gw_chats.kind END, updated_at = excluded.updated_at`,
        )
        .run(chatId, name, kind, Date.now(), expected);
      return;
    }
    this.db
      .prepare(
        "INSERT INTO gw_chats(chat_id, name, kind, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(chat_id) DO UPDATE SET name = excluded.name, kind = CASE WHEN excluded.kind != '' THEN excluded.kind ELSE gw_chats.kind END, updated_at = excluded.updated_at",
      )
      .run(chatId, name, kind, Date.now());
  }

  getChatName(chatId: string): string {
    const row = this.db.prepare("SELECT name FROM gw_chats WHERE chat_id = ?").get(chatId) as { name: string } | undefined;
    return row?.name ?? "";
  }

  private safeRollback(): void {
    try {
      this.db.exec("ROLLBACK");
    } catch {
      // SQLite may already have rolled back automatically
    }
  }

  /**
   * 原子写入一条个人 Web 消息并分配单调递增 seq。
   * 只有此事务提交成功后，上层才会向飞书发送 WS ACK。
   * 若传入 expectedOwnerId，会在 BEGIN IMMEDIATE 事务内核对 bound_owner_id，
   * 与 resetForAccountSwitch 严格串行化，防止切号期间旧连接跨 await 写入新库。
   */
  appendMessage(msg: GatewayMessagePayload, now?: number): GatewayEvent;
  appendMessage(msg: GatewayMessagePayload, now: number | undefined, expectedOwnerId: string): GatewayEvent | null;
  appendMessage(msg: GatewayMessagePayload, now = Date.now(), expectedOwnerId?: string): GatewayEvent | null {
    const expected = expectedOwnerId?.trim() ?? "";
    this.db.exec("BEGIN IMMEDIATE");
    try {
      if (expected) {
        const bound = (this.getKv("bound_owner_id") ?? "").trim();
        if (bound && bound !== expected) {
          this.safeRollback();
          return null;
        }
      }
      if (msg.chatName) {
        this.upsertChat(msg.conversationId, msg.chatName, msg.conversationKind);
      }
      this.db
        .prepare(
          "INSERT INTO gw_messages(message_id, chat_id, deleted, updated_at) VALUES (?, ?, 0, ?) ON CONFLICT(message_id) DO UPDATE SET chat_id = excluded.chat_id, deleted = 0, updated_at = excluded.updated_at",
        )
        .run(msg.id, msg.conversationId, now);
      const info = this.db
        .prepare("INSERT INTO gw_events(kind, message_id, chat_id, chat_name, payload, created_at) VALUES ('message', ?, ?, ?, ?, ?)")
        .run(msg.id, msg.conversationId, msg.chatName, JSON.stringify(msg), now);
      this.db.exec("COMMIT");
      return {
        seq: Number(info.lastInsertRowid),
        kind: "message",
        message_id: msg.id,
        chat_id: msg.conversationId,
        created_at: now,
        message: msg,
      };
    } catch (e) {
      this.safeRollback();
      throw e;
    }
  }

  /**
   * 消息撤回/清空：立刻擦除该消息所有历史事件载荷、标记为 deleted，并追加一条 delete 墓碑事件通知下游删除本地观测。
   * 若传入 expectedOwnerId，会在 BEGIN IMMEDIATE 事务内校验 bound_owner_id。
   */
  appendDelete(messageId: string, chatId: string, now?: number): GatewayEvent;
  appendDelete(messageId: string, chatId: string, now: number | undefined, expectedOwnerId: string): GatewayEvent | null;
  appendDelete(messageId: string, chatId: string, now = Date.now(), expectedOwnerId?: string): GatewayEvent | null {
    const expected = expectedOwnerId?.trim() ?? "";
    this.db.exec("BEGIN IMMEDIATE");
    try {
      if (expected) {
        const bound = (this.getKv("bound_owner_id") ?? "").trim();
        if (bound && bound !== expected) {
          this.safeRollback();
          return null;
        }
      }
      this.db.prepare("UPDATE gw_events SET payload = NULL WHERE message_id = ? AND kind = 'message'").run(messageId);
      this.db
        .prepare(
          "INSERT INTO gw_messages(message_id, chat_id, deleted, updated_at) VALUES (?, ?, 1, ?) ON CONFLICT(message_id) DO UPDATE SET deleted = 1, updated_at = excluded.updated_at",
        )
        .run(messageId, chatId, now);
      const info = this.db
        .prepare("INSERT INTO gw_events(kind, message_id, chat_id, chat_name, payload, created_at) VALUES ('delete', ?, ?, '', NULL, ?)")
        .run(messageId, chatId, now);
      this.db.exec("COMMIT");
      return {
        seq: Number(info.lastInsertRowid),
        kind: "delete",
        message_id: messageId,
        chat_id: chatId,
        created_at: now,
      };
    } catch (e) {
      this.safeRollback();
      throw e;
    }
  }

  /** 擦除命中新增 deny_chats 规则的历史消息正文（重启生效，确保已缓存的敏感会话不再被补拉下发）。 */
  scrubDeniedMessages(isDenied: (chatId: string, chatName: string) => boolean): number {
    const rows = this.db
      .prepare("SELECT DISTINCT chat_id, chat_name FROM gw_events WHERE kind = 'message' AND payload IS NOT NULL")
      .all() as Array<{ chat_id: string; chat_name: string }>;
    const deniedChats = rows.filter((r) => isDenied(r.chat_id, r.chat_name) || isDenied(r.chat_id, this.getChatName(r.chat_id)));
    if (!deniedChats.length) return 0;
    let scrubbed = 0;
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const stmt = this.db.prepare("UPDATE gw_events SET payload = NULL WHERE kind = 'message' AND chat_id = ? AND payload IS NOT NULL");
      for (const r of deniedChats) {
        scrubbed += Number(stmt.run(r.chat_id).changes);
      }
      this.db.exec("COMMIT");
      return scrubbed;
    } catch (e) {
      this.safeRollback();
      throw e;
    }
  }

  seqStats(): { min_seq: number; latest_seq: number; cached_events: number } {
    const row = this.db
      .prepare("SELECT COALESCE(MIN(seq), 0) AS min_seq, COALESCE(MAX(seq), 0) AS max_seq, COUNT(*) AS cnt FROM gw_events")
      .get() as { min_seq: number; max_seq: number; cnt: number };
    const seqRow = this.db.prepare("SELECT seq FROM sqlite_sequence WHERE name = 'gw_events'").get() as { seq: number } | undefined;
    const latest = Math.max(Number(row.max_seq || 0), Number(seqRow?.seq || 0));
    return {
      min_seq: Number(row.min_seq || 0),
      latest_seq: latest,
      cached_events: Number(row.cnt || 0),
    };
  }

  /** 按游标递增拉取事件；已被撤回擦除的 message 事件不再返回正文（后续 delete 事件仍会送达）。 */
  listEvents(after = 0, limit = 200): GatewayEventsResponse {
    const safeAfter = Number.isFinite(after) && after >= 0 ? Math.floor(after) : 0;
    const safeLimit = Math.max(1, Math.min(MAX_EVENTS_LIMIT, Math.floor(limit || 200)));
    const stats = this.seqStats();
    const rows = this.db
      .prepare(
        `SELECT seq, kind, message_id, chat_id, payload, created_at
         FROM gw_events
         WHERE seq > ? AND (kind = 'delete' OR payload IS NOT NULL)
         ORDER BY seq ASC
         LIMIT ?`,
      )
      .all(safeAfter, safeLimit + 1) as Array<{
      seq: number;
      kind: string;
      message_id: string;
      chat_id: string;
      payload: string | null;
      created_at: number;
    }>;

    const hasMore = rows.length > safeLimit;
    const slice = hasMore ? rows.slice(0, safeLimit) : rows;
    const events: GatewayEvent[] = [];
    for (const r of slice) {
      if (r.kind === "delete") {
        events.push({
          seq: Number(r.seq),
          kind: "delete",
          message_id: r.message_id,
          chat_id: r.chat_id,
          created_at: Number(r.created_at),
        });
      } else if (r.kind === "message" && r.payload) {
        try {
          const message = JSON.parse(r.payload) as GatewayMessagePayload;
          events.push({
            seq: Number(r.seq),
            kind: "message",
            message_id: r.message_id,
            chat_id: r.chat_id,
            created_at: Number(r.created_at),
            message,
          });
        } catch {
          // skip corrupted row
        }
      }
    }

    const truncated =
      safeAfter > 0 &&
      ((stats.min_seq > 0 && safeAfter < stats.min_seq - 1) ||
        (stats.min_seq === 0 && safeAfter < stats.latest_seq) ||
        safeAfter > stats.latest_seq);
    return {
      events,
      min_seq: stats.min_seq,
      latest_seq: stats.latest_seq,
      has_more: hasMore,
      truncated,
      next_after: slice.length ? Number(slice[slice.length - 1].seq) : safeAfter,
    };
  }

  getDelivery(cid: string): GatewayDeliveryRecord | undefined {
    const row = this.db
      .prepare(
        "SELECT cid, status, reply_id, chat_id, root_id, parent_id, threaded, thread_id, text_hash, updated_at FROM gw_deliveries WHERE cid = ?",
      )
      .get(cid) as
      | {
          cid: string;
          status: "sending" | "created" | "verified";
          reply_id: string;
          chat_id: string;
          root_id: string;
          parent_id: string;
          threaded: number;
          thread_id: string;
          text_hash: string;
          updated_at: number;
        }
      | undefined;
    if (!row) return undefined;
    return { ...row, threaded: row.threaded === 1 };
  }

  saveDelivery(rec: GatewayDeliveryRecord): void {
    this.db
      .prepare(
        `INSERT INTO gw_deliveries(cid, status, reply_id, chat_id, root_id, parent_id, threaded, thread_id, text_hash, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(cid) DO UPDATE SET
           status = excluded.status,
           reply_id = excluded.reply_id,
           chat_id = excluded.chat_id,
           root_id = excluded.root_id,
           parent_id = excluded.parent_id,
           threaded = excluded.threaded,
           thread_id = excluded.thread_id,
           text_hash = excluded.text_hash,
           updated_at = excluded.updated_at`,
      )
      .run(
        rec.cid,
        rec.status,
        rec.reply_id,
        rec.chat_id,
        rec.root_id,
        rec.parent_id,
        rec.threaded ? 1 : 0,
        rec.thread_id,
        rec.text_hash,
        rec.updated_at,
      );
  }

  deleteDelivery(cid: string): void {
    this.db.prepare("DELETE FROM gw_deliveries WHERE cid = ?").run(cid);
  }

  /** 清理过期事件与过期终态投递记录（保留 sending / created 防止丢失未核验的发送防重状态）。 */
  prune(eventRetentionDays: number, deliveryRetentionDays: number, now = Date.now()): { events: number; deliveries: number } {
    const evCutoff = now - eventRetentionDays * 86_400_000;
    const delCutoff = now - deliveryRetentionDays * 86_400_000;
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const r1 = this.db.prepare("DELETE FROM gw_events WHERE created_at < ?").run(evCutoff);
      this.db.prepare("DELETE FROM gw_messages WHERE updated_at < ? AND message_id NOT IN (SELECT DISTINCT message_id FROM gw_events)").run(evCutoff);
      const r2 = this.db.prepare("DELETE FROM gw_deliveries WHERE status = 'verified' AND updated_at < ?").run(delCutoff);
      this.db.exec("COMMIT");
      return { events: Number(r1.changes), deliveries: Number(r2.changes) };
    } catch (e) {
      this.safeRollback();
      throw e;
    }
  }

  /** 记录网关最近一次 run 实际生效的令牌来源，防止交互式 shell 误执行 tokens 生成冲突的 tokens.json。 */
  recordTokenSources(tokens: Pick<ResolvedGatewayTokens, "readSource" | "replySource">): void {
    const rec: RecordedTokenSources = {
      read: tokens.readSource,
      reply: tokens.replySource,
      updated_at: new Date().toISOString(),
    };
    this.setKv("token_sources", JSON.stringify(rec));
  }

  getTokenSources(): RecordedTokenSources | undefined {
    const raw = this.getKv("token_sources");
    if (!raw) return undefined;
    try {
      const parsed = JSON.parse(raw) as Partial<RecordedTokenSources>;
      const valid = (v: unknown): v is ResolvedGatewayTokens["readSource"] => v === "env" || v === "credential" || v === "file";
      if (valid(parsed.read) && valid(parsed.reply)) {
        return { read: parsed.read, reply: parsed.reply, updated_at: typeof parsed.updated_at === "string" ? parsed.updated_at : undefined };
      }
      return undefined;
    } catch {
      return undefined;
    }
  }

  /** 解析或自动生成读写分离双令牌（read_token != reply_token）。 */
  resolveTokens(opts: ResolveTokensOptions = {}): ResolvedGatewayTokens {
    const envRead = process.env.FEISHU_GW_READ_TOKEN?.trim();
    const envReply = process.env.FEISHU_GW_REPLY_TOKEN?.trim();
    const credRead = envRead ? undefined : readCredentialFile(["read-token", "feishu-gw-read-token"]);
    const credReply = envReply ? undefined : readCredentialFile(["reply-token", "feishu-gw-reply-token"]);

    if (opts.rejectConflictingFileGeneration) {
      const prev = this.getTokenSources();
      if (prev) {
        const missingCred: string[] = [];
        const missingEnv: string[] = [];
        if (!envRead && !credRead) {
          if (prev.read === "credential") missingCred.push("read_token（/etc/feishu-gateway/secrets/read-token）");
          else if (prev.read === "env") missingEnv.push("read_token（FEISHU_GW_READ_TOKEN）");
        }
        if (!envReply && !credReply) {
          if (prev.reply === "credential") missingCred.push("reply_token（/etc/feishu-gateway/secrets/reply-token）");
          else if (prev.reply === "env") missingEnv.push("reply_token（FEISHU_GW_REPLY_TOKEN）");
        }
        if (missingCred.length || missingEnv.length) {
          const parts = [
            ...(missingCred.length ? [`systemd LoadCredential：${missingCred.join("、")}`] : []),
            ...(missingEnv.length ? [`环境变量：${missingEnv.join("、")}`] : []),
          ];
          throw new Error(
            `网关最近一次启动使用的是外部令牌（${parts.join("；")}），当前 shell 未提供它们；为避免生成与常驻进程冲突的 tokens.json 已拒绝执行。请直接查看对应凭据文件或服务环境配置；若确需改回本地 tokens.json 文件模式，请追加 --force-file 并同步修改服务配置。`,
          );
        }
      }
    }

    if (opts.rotateRead && (envRead || credRead)) {
      throw new Error("read_token 当前由环境变量或 systemd LoadCredential 提供，请直接在外部密钥管理中轮换");
    }
    if (opts.rotateReply && (envReply || credReply)) {
      throw new Error("reply_token 当前由环境变量或 systemd LoadCredential 提供，请直接在外部密钥管理中轮换");
    }

    let fileData: Partial<TokenFileData> = {};
    if (fs.existsSync(this.tokensFile)) {
      try {
        fileData = JSON.parse(fs.readFileSync(this.tokensFile, "utf8")) as Partial<TokenFileData>;
      } catch {
        fileData = {};
      }
    }

    let dirty = false;
    let fileRead = typeof fileData.read_token === "string" ? fileData.read_token.trim() : "";
    let fileReply = typeof fileData.reply_token === "string" ? fileData.reply_token.trim() : "";

    if (!envRead && !credRead && (opts.rotateRead || fileRead.length < MIN_TOKEN_LEN)) {
      fileRead = generateToken();
      dirty = true;
    }
    if (!envReply && !credReply && (opts.rotateReply || fileReply.length < MIN_TOKEN_LEN)) {
      fileReply = generateToken();
      dirty = true;
    }

    const readToken = envRead || credRead || fileRead;
    const replyToken = envReply || credReply || fileReply;
    const readSource: ResolvedGatewayTokens["readSource"] = envRead ? "env" : credRead ? "credential" : "file";
    const replySource: ResolvedGatewayTokens["replySource"] = envReply ? "env" : credReply ? "credential" : "file";

    if (readToken.length < MIN_TOKEN_LEN) {
      throw new Error(`read_token 长度过短（至少 ${MIN_TOKEN_LEN} 个字符）`);
    }
    if (replyToken.length < MIN_TOKEN_LEN) {
      throw new Error(`reply_token 长度过短（至少 ${MIN_TOKEN_LEN} 个字符）`);
    }
    if (readToken === replyToken) {
      throw new Error("安全约束违规：read_token 与 reply_token 必须严格不同，禁止共享同一令牌");
    }

    if (dirty) {
      const toWrite: Record<string, string> = { updated_at: new Date().toISOString() };
      if (readSource === "file") toWrite.read_token = fileRead;
      if (replySource === "file") toWrite.reply_token = fileReply;
      writeAtomic0600(this.tokensFile, JSON.stringify(toWrite, null, 2) + "\n");
    }

    return { readToken, replyToken, readSource, replySource, file: this.tokensFile };
  }
}
