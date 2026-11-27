import { createHash, randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import type { CtxDraftKind, CtxItemKind, CtxItemStatus, CtxPriority, CtxSource } from "../api/types.ts";
import { isDeadOwner } from "../ledger.ts";

/**
 * 计算观测的内容修订签名：包含正文及真实 @mention 标识（防止将普通 "@姓名" 编辑为真实 @mention 时被误判为无变更）。
 */
export function obsRevision(o: { text: string; meta?: Record<string, unknown> }): string {
  const meta = o.meta ?? {};
  const rawMentions = Array.isArray(meta.mentions) ? meta.mentions : [];
  if (!meta.at_me && rawMentions.length === 0) return o.text;
  const mentionsSig = rawMentions
    .map((m) => {
      const rec = m as { id?: unknown; start?: unknown; end?: unknown };
      return `${String(rec.id ?? "")}:${String(rec.start ?? "")}:${String(rec.end ?? "")}`;
    })
    .join(",");
  return `${o.text}\0at=${meta.at_me ? "1" : "0"}\0m=${mentionsSig}`;
}

/**
 * 工作图谱存储：观测（原始信号）→ 项目 / 事项 / 知识 / 动态 / 人 / 冲突 / 草稿，每条事实挂证据。
 * 和账本共用一个 SQLite 文件。所有写入都是幂等的：观测按来源 ID 去重，事项按强标识（Meego 节点、飞书任务）去重。
 */

export interface Obs {
  id: string;
  source: CtxSource;
  /** 细分类型：at_me / p2p / group / mine / bot / meego_todo / meego_done / minutes / task */
  kind: string;
  /** 会话或容器：chat_id、Meego 工作项、妙记 token */
  conv: string;
  conv_name: string;
  actor_id: string;
  actor_name: string;
  is_me: boolean;
  time: number;
  text: string;
  url: string;
  meta: Record<string, unknown>;
}

export interface ProjectRow {
  id: string;
  name: string;
  aliases: string[];
  refs: string[];
  description: string;
  my_role: string;
  stage: string;
  status: "active" | "legacy" | "archived";
  muted: boolean;
  /** 用户手动设置过静音 / 状态，自动规则不再改 */
  pinned: boolean;
  health: "ok" | "risk" | "blocked" | "unknown";
  /** 上级项目（两层：产品 / 大项目 → 子项目）；空 = 顶层 */
  parent_id: string;
  created: number;
  updated: number;
  last_activity: number;
}

export interface ItemRow {
  id: string;
  title: string;
  kind: CtxItemKind;
  project_id: string;
  status: CtxItemStatus;
  priority: CtxPriority;
  due: number | null;
  counterpart: string;
  next_step: string;
  strong_key: string;
  confidence: number;
  source: CtxSource;
  first_seen: number;
  last_seen: number;
  closed_at: number | null;
  close_reason: string;
  snooze_until: number | null;
  feedback: "" | "right" | "wrong" | "unimportant";
  /** 发提醒卡片的时间（避免重复打扰） */
  nudged_at: number | null;
  /** 用户手动改过状态，模型不能再自动重开 */
  user_locked: boolean;
  meta: Record<string, unknown>;
}

export interface EvidenceRow {
  entity: string;
  entity_id: string;
  obs_id: string;
  quote: string;
  time: number;
}

export interface KnowledgeRow {
  id: string;
  project_id: string;
  kind: "decision" | "conclusion" | "doc" | "howto" | "fact";
  title: string;
  content: string;
  confidence: number;
  created: number;
  updated: number;
}

export interface UpdateRow {
  id: string;
  project_id: string;
  time: number;
  summary: string;
  created: number;
}

export interface PersonRow {
  id: string;
  name: string;
  relation: string;
  projects: string[];
  last_seen: number;
}

export interface ConflictRow {
  id: string;
  project_id: string;
  topic: string;
  claims: { claim: string; obs_id: string; quote: string; time: number; obs_rev?: string }[];
  status: "open" | "resolved";
  resolution: string;
  created: number;
}

export interface DraftRow {
  id: string;
  item_id: string;
  project_id: string;
  kind: CtxDraftKind;
  target: Record<string, string>;
  target_label: string;
  content: string;
  status: "proposed" | "approved" | "sent" | "discarded" | "failed";
  error: string;
  created: number;
  updated: number;
}

type Row = Record<string, unknown>;
const j = <T>(v: unknown, d: T): T => {
  try {
    return v ? (JSON.parse(String(v)) as T) : d;
  } catch {
    return d;
  }
};

/** 名称归一：去空白、标点、大小写，用于项目 / 人的匹配 */
export function norm(s: string): string {
  return s
    .toLowerCase()
    .replace(/[\s「」【】\[\]()（）《》<>"'“”‘’·,，.。:：;；!！?？/\\|_\-—]+/g, "")
    .trim();
}

function grams(s: string): Set<string> {
  const n = norm(s);
  const g = new Set<string>();
  for (let i = 0; i < n.length - 1; i++) g.add(n.slice(i, i + 2));
  if (n.length === 1) g.add(n);
  return g;
}

/** 重合度（字符二元组 交集 / 较短一方）：长句换个说法时比 Jaccard 更稳，用于冲突去重 */
export function overlap(a: string, b: string): number {
  const x = grams(a);
  const y = grams(b);
  if (!x.size || !y.size) return 0;
  let inter = 0;
  for (const g of x) if (y.has(g)) inter++;
  return inter / Math.min(x.size, y.size);
}

/** 两个冲突是不是同一个问题：同一项目，且话题高度重合或引用了同一条消息 */
export function sameConflict(a: { project_id: string; topic: string; claims: { obs_id: string }[] }, b: { project_id: string; topic: string; claims: { obs_id: string }[] }): boolean {
  if (a.project_id !== b.project_id) return false;
  if (a.claims.some((x) => x.obs_id && b.claims.some((y) => y.obs_id === x.obs_id))) return true;
  return similarity(a.topic, b.topic) >= 0.5 || overlap(a.topic, b.topic) >= 0.5;
}

/** 标题相似度（字符二元组 Jaccard），中文友好 */
export function similarity(a: string, b: string): number {
  const grams = (s: string) => {
    const n = norm(s);
    const g = new Set<string>();
    for (let i = 0; i < n.length - 1; i++) g.add(n.slice(i, i + 2));
    if (n.length === 1) g.add(n);
    return g;
  };
  const x = grams(a);
  const y = grams(b);
  if (!x.size || !y.size) return 0;
  let inter = 0;
  for (const g of x) if (y.has(g)) inter++;
  return inter / (x.size + y.size - inter);
}

const newId = (prefix: string) => `${prefix}_${randomUUID().slice(0, 12)}`;
export const hashId = (prefix: string, s: string) => `${prefix}_${createHash("sha1").update(s).digest("hex").slice(0, 16)}`;

export class ContextStore {
  db: DatabaseSync;
  constructor(db: DatabaseSync) {
    this.db = db;
    db.exec(`
      CREATE TABLE IF NOT EXISTS ctx_obs (
        id TEXT PRIMARY KEY, source TEXT NOT NULL, kind TEXT NOT NULL, conv TEXT NOT NULL DEFAULT '', conv_name TEXT NOT NULL DEFAULT '',
        actor_id TEXT NOT NULL DEFAULT '', actor_name TEXT NOT NULL DEFAULT '', is_me INTEGER NOT NULL DEFAULT 0, time INTEGER NOT NULL,
        text TEXT NOT NULL DEFAULT '', url TEXT NOT NULL DEFAULT '', meta TEXT NOT NULL DEFAULT '{}',
        ingested INTEGER NOT NULL, processed INTEGER NOT NULL DEFAULT 0);
      CREATE INDEX IF NOT EXISTS ctx_obs_pending ON ctx_obs (processed, conv, time);
      CREATE INDEX IF NOT EXISTS ctx_obs_conv ON ctx_obs (conv, time);
      CREATE TABLE IF NOT EXISTS ctx_project (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, aliases TEXT NOT NULL DEFAULT '[]', refs TEXT NOT NULL DEFAULT '[]',
        description TEXT NOT NULL DEFAULT '', my_role TEXT NOT NULL DEFAULT '', stage TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'active', muted INTEGER NOT NULL DEFAULT 0, pinned INTEGER NOT NULL DEFAULT 0,
        health TEXT NOT NULL DEFAULT 'unknown', created INTEGER NOT NULL, updated INTEGER NOT NULL, last_activity INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS ctx_item (
        id TEXT PRIMARY KEY, title TEXT NOT NULL, kind TEXT NOT NULL, project_id TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'open',
        priority TEXT NOT NULL DEFAULT 'medium', due INTEGER, counterpart TEXT NOT NULL DEFAULT '', next_step TEXT NOT NULL DEFAULT '',
        strong_key TEXT, confidence REAL NOT NULL DEFAULT 0.7, source TEXT NOT NULL DEFAULT 'im',
        first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, closed_at INTEGER, close_reason TEXT NOT NULL DEFAULT '',
        snooze_until INTEGER, feedback TEXT NOT NULL DEFAULT '', nudged_at INTEGER, user_locked INTEGER NOT NULL DEFAULT 0,
        meta TEXT NOT NULL DEFAULT '{}');
      CREATE UNIQUE INDEX IF NOT EXISTS ctx_item_strong ON ctx_item (strong_key) WHERE strong_key IS NOT NULL AND strong_key != '';
      CREATE INDEX IF NOT EXISTS ctx_item_status ON ctx_item (status, project_id);
      CREATE TABLE IF NOT EXISTS ctx_evidence (
        id INTEGER PRIMARY KEY AUTOINCREMENT, entity TEXT NOT NULL, entity_id TEXT NOT NULL, obs_id TEXT NOT NULL,
        quote TEXT NOT NULL DEFAULT '', time INTEGER NOT NULL DEFAULT 0, UNIQUE (entity, entity_id, obs_id));
      CREATE INDEX IF NOT EXISTS ctx_evidence_entity ON ctx_evidence (entity, entity_id);
      CREATE TABLE IF NOT EXISTS ctx_knowledge (
        id TEXT PRIMARY KEY, project_id TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL, title TEXT NOT NULL, content TEXT NOT NULL,
        confidence REAL NOT NULL DEFAULT 0.7, created INTEGER NOT NULL, updated INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS ctx_update (
        id TEXT PRIMARY KEY, project_id TEXT NOT NULL DEFAULT '', time INTEGER NOT NULL, summary TEXT NOT NULL, created INTEGER NOT NULL);
      CREATE INDEX IF NOT EXISTS ctx_update_time ON ctx_update (time);
      CREATE TABLE IF NOT EXISTS ctx_person (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, relation TEXT NOT NULL DEFAULT '', projects TEXT NOT NULL DEFAULT '[]', last_seen INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS ctx_conflict (
        id TEXT PRIMARY KEY, project_id TEXT NOT NULL DEFAULT '', topic TEXT NOT NULL, claims TEXT NOT NULL DEFAULT '[]',
        status TEXT NOT NULL DEFAULT 'open', resolution TEXT NOT NULL DEFAULT '', created INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS ctx_feedback (
        id INTEGER PRIMARY KEY AUTOINCREMENT, entity TEXT NOT NULL, entity_id TEXT NOT NULL, verdict TEXT NOT NULL,
        note TEXT NOT NULL DEFAULT '', snapshot TEXT NOT NULL DEFAULT '', at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS ctx_draft (
        id TEXT PRIMARY KEY, item_id TEXT NOT NULL DEFAULT '', project_id TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL,
        target TEXT NOT NULL DEFAULT '{}', target_label TEXT NOT NULL DEFAULT '', content TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'proposed', error TEXT NOT NULL DEFAULT '', created INTEGER NOT NULL, updated INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS ctx_mute_conv (conv TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS ctx_conv_claim (
        conv TEXT PRIMARY KEY,
        holder TEXT NOT NULL,
        proc_owner TEXT NOT NULL,
        expires_at INTEGER NOT NULL
      );
    `);
    // 迁移：子项目
    const cols = new Set((db.prepare("PRAGMA table_info(ctx_project)").all() as { name: string }[]).map((c) => c.name));
    if (!cols.has("parent_id")) db.exec("ALTER TABLE ctx_project ADD COLUMN parent_id TEXT NOT NULL DEFAULT ''");
  }

  private txDepth = 0;
  /** 事务（可嵌套：内层直接并入外层） */
  tx<T>(fn: () => T): T {
    if (this.txDepth) return fn();
    this.db.exec("BEGIN IMMEDIATE");
    this.txDepth++;
    try {
      const r = fn();
      this.db.exec("COMMIT");
      return r;
    } catch (e) {
      this.db.exec("ROLLBACK");
      throw e;
    } finally {
      this.txDepth--;
    }
  }

  // ───────── 观测 ─────────

  /**
   * 幂等写入观测（严格按通道原生主键 ID 索引查找，绝不做跨通道启发式猜群或合并）：
   *   - 同 ID 已存在且曾仅作为历史背景写入（meta.background_only = true）时，首次真实投递将其提升为待处理；
   *   - 同 ID 已存在且正文变化（消息被编辑）时，更新正文并重新标为待处理；
   *   - 可选 `beforeCommit` 回调在 `BEGIN IMMEDIATE` 写事务锁内执行，用于跨进程吊销/静音/策略变更的原子终检。
   * 返回新增或重新变为待处理的数量。
   */
  addObs(list: Obs[], beforeCommit?: () => boolean): number {
    const now = Date.now();
    const get = this.db.prepare(
      "SELECT source, kind, conv, conv_name, actor_id, actor_name, is_me, time, text, url, meta, processed FROM ctx_obs WHERE id = ?",
    );
    const ins = this.db.prepare(
      `INSERT INTO ctx_obs (id, source, kind, conv, conv_name, actor_id, actor_name, is_me, time, text, url, meta, ingested, processed)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
    );
    const upd = this.db.prepare(
      "UPDATE ctx_obs SET source = ?, kind = ?, conv = ?, conv_name = ?, actor_id = ?, actor_name = ?, is_me = ?, time = ?, text = ?, url = ?, meta = ?, processed = 0 WHERE id = ?",
    );
    const updMetaOnly = this.db.prepare("UPDATE ctx_obs SET meta = ? WHERE id = ?");
    let n = 0;
    this.tx(() => {
      if (beforeCommit && !beforeCommit()) return;
      for (const o of list) {
        if (!o.id || !o.time) continue;
        const cur = get.get(o.id) as Row | undefined;
        if (!cur) {
          ins.run(o.id, o.source, o.kind, o.conv, o.conv_name, o.actor_id, o.actor_name, o.is_me ? 1 : 0, o.time, o.text, o.url, JSON.stringify(o.meta ?? {}), now);
          n++;
        } else {
          const curMeta = j<Record<string, unknown>>(cur.meta, {});
          const wasBgOnly = curMeta.background_only === true;
          const wasWithdrawn = curMeta.withdrawn === true;
          const wasTombstone = curMeta.tombstone === true;
          const curVer = typeof curMeta.edit_version === "number" && Number.isFinite(curMeta.edit_version) ? curMeta.edit_version : undefined;
          const nextVer = typeof o.meta?.edit_version === "number" && Number.isFinite(o.meta.edit_version) ? o.meta.edit_version : undefined;
          const curEditTime = typeof curMeta.edit_time === "number" && Number.isFinite(curMeta.edit_time) ? curMeta.edit_time : undefined;
          const nextEditTime = typeof o.meta?.edit_time === "number" && Number.isFinite(o.meta.edit_time) ? o.meta.edit_time : undefined;
          const curPollAt =
            typeof curMeta.poll_observed_at === "number" && Number.isFinite(curMeta.poll_observed_at)
              ? curMeta.poll_observed_at
              : undefined;
          const nextPollAt =
            typeof o.meta?.poll_observed_at === "number" && Number.isFinite(o.meta.poll_observed_at)
              ? o.meta.poll_observed_at
              : undefined;
          // 仅在同一时钟标尺下判陈旧：修订计数对修订计数，归一化编辑时间戳对编辑时间戳，绝不混比
          if (curVer !== undefined && nextVer !== undefined && nextVer < curVer) continue;
          if (curEditTime !== undefined && nextEditTime !== undefined && nextEditTime < curEditTime) continue;
          const hasNewerRevision =
            (curVer !== undefined && nextVer !== undefined && nextVer > curVer) ||
            (curEditTime !== undefined && nextEditTime !== undefined && nextEditTime > curEditTime);
          if (!hasNewerRevision && curPollAt !== undefined && nextPollAt !== undefined && nextPollAt < curPollAt) {
            continue;
          }
          // 若观测已被撤回或为墓碑（无论是否带服务端修订号，或仅带本地 poll_observed_at），
          // 除非新到达的副本具备严格更高的可比服务端修订号，或经服务端权威回读确认存活（authoritative_live=true），
          // 否则绝不允许旧搜索副本凭较新的本地轮询时间戳重新激活已撤回观测
          const incomingAuthoritativeLive = o.meta?.authoritative_live === true;
          const isCliIm = o.id.startsWith("im:");
          if (
            wasWithdrawn &&
            (curVer !== undefined || curEditTime !== undefined || curPollAt !== undefined || wasTombstone || isCliIm) &&
            !hasNewerRevision &&
            !incomingAuthoritativeLive
          ) {
            continue;
          }
          const curEffectiveMeta =
            curMeta.at_me === undefined && String(cur.kind ?? "") === "at_me" ? { ...curMeta, at_me: true } : curMeta;
          const incomingMeta = { ...(o.meta ?? {}) };
          delete incomingMeta.authoritative_live;
          const nextMeta: Record<string, unknown> = { ...curEffectiveMeta, ...incomingMeta };
          if (curVer !== undefined && nextVer !== undefined) nextMeta.edit_version = Math.max(curVer, nextVer);
          if (curEditTime !== undefined && nextEditTime !== undefined) nextMeta.edit_time = Math.max(curEditTime, nextEditTime);
          if (curPollAt !== undefined && nextPollAt !== undefined) nextMeta.poll_observed_at = Math.max(curPollAt, nextPollAt);
          delete nextMeta.background_only;
          delete nextMeta.withdrawn;
          delete nextMeta.tombstone;
          // 按即将落库的合并后元数据比对修订：未确认的省略（undefined）保留原值且不误触发重开，确认移除（at_me: false）则清除旧标记且后续重复投递幂等
          const revChanged =
            obsRevision({ text: String(cur.text ?? ""), meta: curEffectiveMeta }) !==
            obsRevision({ text: o.text, meta: nextMeta });
          if (wasBgOnly || wasWithdrawn || revChanged) {
            const prevGen = typeof curMeta.edit_gen === "number" && Number.isFinite(curMeta.edit_gen) ? curMeta.edit_gen : 0;
            const mergedMeta: Record<string, unknown> = { ...nextMeta, edit_gen: prevGen + 1 };
            const curActorId = String(cur.actor_id ?? "");
            const curConv = String(cur.conv ?? "");
            const revivingPlaceholder = wasTombstone || (wasWithdrawn && !curActorId);
            const nextSource = revivingPlaceholder ? o.source : (o.source || String(cur.source ?? "im"));
            const nextConv = revivingPlaceholder ? o.conv : (o.conv || curConv);
            const nextActorId = revivingPlaceholder ? o.actor_id : (o.actor_id || curActorId);
            const nextIsMe = revivingPlaceholder || !!o.actor_id ? (o.is_me ? 1 : 0) : Number(cur.is_me ?? 0);
            const nextTime = revivingPlaceholder ? o.time : (Number(cur.time ?? 0) || o.time);
            upd.run(
              nextSource,
              o.kind,
              nextConv,
              o.conv_name || String(cur.conv_name ?? ""),
              nextActorId,
              o.actor_name || String(cur.actor_name ?? ""),
              nextIsMe,
              nextTime,
              o.text,
              o.url || String(cur.url ?? ""),
              JSON.stringify(mergedMeta),
              o.id,
            );
            // 原消息正文被编辑时，保留在修订后正文中仍然出现的精确证据摘录（避免长消息修一处错字把多条事项的不同引文都抹成开头 300 字），
            // 仅将已从修订后正文中移除的过期摘录清空失效，等待重理解给出替换摘录（视图层会安全回退至当前正文）
            if (String(cur.text ?? "") !== o.text) {
              const evRows = this.db
                .prepare("SELECT id, quote FROM ctx_evidence WHERE obs_id = ?")
                .all(o.id) as { id: number; quote: string }[];
              const clearQuote = this.db.prepare("UPDATE ctx_evidence SET quote = '' WHERE id = ?");
              for (const ev of evRows) {
                const q = (ev.quote ?? "").trim();
                if (q && !o.text.includes(q)) {
                  clearQuote.run(ev.id);
                }
              }
            }
            n++;
          } else {
            // 内容与 @mention 均未变化但收到更高的排序水位（edit_version / edit_time / poll_observed_at）：
            // 仅推进水位元数据，不重置 processed 也不递增 edit_gen，防止后续乱序到达的中间旧版本覆写当前状态
            const advancedVer = nextVer !== undefined && (curVer === undefined || nextVer > curVer);
            const advancedEditTime = nextEditTime !== undefined && (curEditTime === undefined || nextEditTime > curEditTime);
            const advancedPollAt = nextPollAt !== undefined && (curPollAt === undefined || nextPollAt > curPollAt);
            if (advancedVer || advancedEditTime || advancedPollAt) {
              const watermarkMeta: Record<string, unknown> = {
                ...curMeta,
                ...(advancedVer ? { edit_version: nextVer } : {}),
                ...(advancedEditTime ? { edit_time: nextEditTime } : {}),
                ...(advancedPollAt ? { poll_observed_at: nextPollAt } : {}),
              };
              updMetaOnly.run(JSON.stringify(watermarkMeta), o.id);
            }
          }
        }
      }
    });
    return n;
  }

  /**
   * 写入历史背景观测（仅插入未出现过的 ID，标为 processed = 1 且 meta.background_only = true）。
   * 后续若该消息经真实推送或轮询到达，addObs 会将其提升为待处理。
   * 可选 `beforeCommit` 回调在 `BEGIN IMMEDIATE` 写事务锁内执行，防止并发吊销/静音后落库背景消息。
   */
  addBackgroundObs(list: Obs[], beforeCommit?: () => boolean): number {
    const now = Date.now();
    const get = this.db.prepare("SELECT 1 FROM ctx_obs WHERE id = ?");
    const ins = this.db.prepare(
      `INSERT INTO ctx_obs (id, source, kind, conv, conv_name, actor_id, actor_name, is_me, time, text, url, meta, ingested, processed)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`,
    );
    let n = 0;
    this.tx(() => {
      if (beforeCommit && !beforeCommit()) return;
      for (const o of list) {
        if (!o.id || !o.time) continue;
        if (get.get(o.id)) continue;
        const meta = { ...(o.meta ?? {}), background_only: true };
        ins.run(o.id, o.source, o.kind, o.conv, o.conv_name, o.actor_id, o.actor_name, o.is_me ? 1 : 0, o.time, o.text, o.url, JSON.stringify(meta), now);
        n++;
      }
    });
    return n;
  }

  obs(id: string): Obs | undefined {
    const r = this.db.prepare("SELECT * FROM ctx_obs WHERE id = ?").get(id) as Row | undefined;
    return r ? this.toObs(r) : undefined;
  }

  obsPending(id: string): boolean {
    const r = this.db.prepare("SELECT processed FROM ctx_obs WHERE id = ?").get(id) as { processed: number } | undefined;
    return r !== undefined && r.processed === 0;
  }

  private toObs(r: Row): Obs {
    return { ...(r as unknown as Obs), is_me: !!r.is_me, meta: j(r.meta, {}) };
  }

  private static readonly NOT_WITHDRAWN = " AND COALESCE(json_extract(meta, '$.withdrawn'), 0) = 0";

  /**
   * 按账号隔离条件：
   *   - `undefined`：调用方未启用账号隔离过滤（单账号/非 pw 场景）；
   *   - `null` 或 `""`：工作区当前无有效个人 Web 绑定（例如 owner.open_id 已变更或未绑定）→ 严格拦截所有 `pw:*` 观测；
   *   - 非空原生账号 ID：严格精确匹配 `native_owner_id = ?`，隔离无主/历史遗留无归属 `pw:*` 记录，绝不混入新账号窗口。
   */
  private ownerClause(activeNativeOwner?: string | null): { sql: string; args: string[] } {
    if (activeNativeOwner === undefined) return { sql: "", args: [] };
    if (!activeNativeOwner) return { sql: " AND id NOT LIKE 'pw:%'", args: [] };
    return {
      sql: " AND (id NOT LIKE 'pw:%' OR COALESCE(json_extract(meta, '$.native_owner_id'), '') = ?)",
      args: [activeNativeOwner],
    };
  }

  /** 检查库中是否已存在归属其他账号（或缺少 native_owner_id 无法证明归属当前账号）的个人 Web 观测 */
  hasOtherNativeOwnerObs(ownerId: string): boolean {
    const r = this.db
      .prepare("SELECT 1 FROM ctx_obs WHERE id LIKE 'pw:%' AND COALESCE(json_extract(meta, '$.native_owner_id'), '') != ? LIMIT 1")
      .get(ownerId);
    return !!r;
  }

  /**
   * 撤回一条观测（例如消息被撤回或范围外群的 @我 被编辑移除），将其移出待处理队列并永久排除在后续理解/起草背景窗口之外：
   *   - 当携带修订水位（`editVersion` / `editTimeMs` / `pollObservedAt`）时，比较并推进水位，避免陈旧撤回覆盖更新的存活编辑；
   *   - 若该 ID 尚未入库但携带修订水位，写入已处理的撤回墓碑行（`processed = 1, meta.withdrawn = true`），防止后续到达的陈旧副本复活已撤回消息。
   */
  retirePendingObs(
    id: string,
    opts?: {
      editVersion?: number;
      editTimeMs?: number;
      pollObservedAt?: number;
      conv?: string;
      source?: CtxSource;
      kind?: string;
      time?: number;
    },
  ): boolean {
    return this.tx(() => {
      const cur = this.db.prepare("SELECT processed, meta FROM ctx_obs WHERE id = ?").get(id) as
        | { processed: number; meta: string }
        | undefined;
      const incVer =
        typeof opts?.editVersion === "number" && Number.isFinite(opts.editVersion) ? opts.editVersion : undefined;
      const incEditTime =
        typeof opts?.editTimeMs === "number" && Number.isFinite(opts.editTimeMs) ? opts.editTimeMs : undefined;
      const incPollAt =
        typeof opts?.pollObservedAt === "number" && Number.isFinite(opts.pollObservedAt)
          ? opts.pollObservedAt
          : undefined;
      if (!cur) {
        if (incVer === undefined && incEditTime === undefined && incPollAt === undefined) return false;
        const now = Date.now();
        const tombstoneMeta: Record<string, unknown> = {
          withdrawn: true,
          tombstone: true,
          edit_gen: 1,
          ...(incVer !== undefined ? { edit_version: incVer } : {}),
          ...(incEditTime !== undefined ? { edit_time: incEditTime } : {}),
          ...(incPollAt !== undefined ? { poll_observed_at: incPollAt } : {}),
        };
        this.db
          .prepare(
            `INSERT INTO ctx_obs (id, source, kind, conv, conv_name, actor_id, actor_name, is_me, time, text, url, meta, ingested, processed)
             VALUES (?, ?, ?, ?, '', '', '', 0, ?, '', '', ?, ?, 1)`,
          )
          .run(
            id,
            opts?.source ?? "im",
            opts?.kind ?? "group",
            opts?.conv ?? "im",
            opts?.time ?? now,
            JSON.stringify(tombstoneMeta),
            now,
          );
        return true;
      }
      const m = j<Record<string, unknown>>(cur.meta, {});
      const curVer = typeof m.edit_version === "number" && Number.isFinite(m.edit_version) ? m.edit_version : undefined;
      const curEditTime =
        typeof m.edit_time === "number" && Number.isFinite(m.edit_time) ? m.edit_time : undefined;
      const curPollAt =
        typeof m.poll_observed_at === "number" && Number.isFinite(m.poll_observed_at)
          ? m.poll_observed_at
          : undefined;
      if (curVer !== undefined && incVer !== undefined && incVer < curVer) return false;
      if (curEditTime !== undefined && incEditTime !== undefined && incEditTime < curEditTime) return false;
      const hasNewer =
        (curVer !== undefined && incVer !== undefined && incVer > curVer) ||
        (curEditTime !== undefined && incEditTime !== undefined && incEditTime > curEditTime);
      if (!hasNewer && curPollAt !== undefined && incPollAt !== undefined && incPollAt < curPollAt) return false;

      const verChanged = incVer !== undefined && (curVer === undefined || incVer > curVer);
      const editTimeChanged = incEditTime !== undefined && (curEditTime === undefined || incEditTime > curEditTime);
      const pollAtChanged = incPollAt !== undefined && (curPollAt === undefined || incPollAt > curPollAt);
      if (cur.processed !== 0 && m.withdrawn === true && !verChanged && !editTimeChanged && !pollAtChanged) {
        return false;
      }
      if (cur.processed === 0 || m.withdrawn !== true) {
        const prevGen = typeof m.edit_gen === "number" && Number.isFinite(m.edit_gen) ? m.edit_gen : 0;
        m.edit_gen = prevGen + 1;
      }
      m.withdrawn = true;
      if (incVer !== undefined) m.edit_version = curVer !== undefined ? Math.max(curVer, incVer) : incVer;
      if (incEditTime !== undefined) m.edit_time = curEditTime !== undefined ? Math.max(curEditTime, incEditTime) : incEditTime;
      if (incPollAt !== undefined) m.poll_observed_at = curPollAt !== undefined ? Math.max(curPollAt, incPollAt) : incPollAt;
      this.db.prepare("UPDATE ctx_obs SET processed = 1, meta = ? WHERE id = ?").run(JSON.stringify(m), id);
      return true;
    });
  }

  /** 待理解的会话（按最早未处理观测排序），支持分页跳过排除列表、按当前绑定 Web 账号隔离，以及在 CLI 认证受阻时仅放行已验权的原生 pw:* IM 观测 */
  pendingConvs(
    limit: number,
    sources: string[] = ["im", "minutes", "doc"],
    opts: { excludeConvs?: Iterable<string>; activeNativeOwner?: string | null; excludeCliIm?: boolean } = {},
  ): { conv: string; conv_name: string; n: number }[] {
    if (!sources.length) return [];
    const excluded = opts.excludeConvs ? [...opts.excludeConvs] : [];
    const owner = this.ownerClause(opts.activeNativeOwner);
    const exclSql = excluded.length ? ` AND conv NOT IN (${excluded.map(() => "?").join(",")})` : "";
    const cliImSql = opts.excludeCliIm ? " AND NOT (source = 'im' AND id NOT LIKE 'pw:%')" : "";
    const q = `SELECT conv, MAX(conv_name) AS conv_name, COUNT(*) AS n, MIN(time) AS t FROM ctx_obs
               WHERE processed = 0 AND source IN (${sources.map(() => "?").join(",")}) AND conv NOT IN (SELECT conv FROM ctx_mute_conv)${ContextStore.NOT_WITHDRAWN}${exclSql}${cliImSql}${owner.sql}
               GROUP BY conv ORDER BY t LIMIT ?`;
    return this.db.prepare(q).all(...sources, ...excluded, ...owner.args, limit) as { conv: string; conv_name: string; n: number }[];
  }

  pendingCount(): number {
    return (this.db.prepare(`SELECT COUNT(*) AS n FROM ctx_obs WHERE processed = 0 AND source IN ('im','minutes','doc')${ContextStore.NOT_WITHDRAWN}`).get() as { n: number }).n;
  }

  /**
   * 理解窗口：这个会话最早的一批待处理观测（按时间正序，最多 maxFresh 条）+ 它们之前的若干条已处理观测作为背景。
   * 当 `opts.onlyMentions` 为 true（例如群已被移出 allowlist，仅允许真实 @我 例外）时，
   * 在 SQL LIMIT 之前直接筛选 `kind = 'at_me'`，防止前面积压超过 60 条普通消息饿死后到的真实 @我。
   */
  convWindow(
    conv: string,
    maxFresh = 60,
    context = 12,
    activeNativeOwner?: string | null,
    opts?: { onlyMentions?: boolean; excludeCliIm?: boolean },
  ): Obs[] {
    const owner = this.ownerClause(activeNativeOwner);
    const nw = ContextStore.NOT_WITHDRAWN;
    const mentionSql = opts?.onlyMentions
      ? " AND (kind = 'at_me' OR json_extract(meta, '$.at_me') = 1) AND COALESCE(json_extract(meta, '$.at_me'), 1) != 0 AND COALESCE(json_extract(meta, '$.is_mention_me'), 1) != 0"
      : "";
    const cliImSql = opts?.excludeCliIm ? " AND NOT (source = 'im' AND id NOT LIKE 'pw:%')" : "";
    const fresh = this.db
      .prepare(`SELECT * FROM ctx_obs WHERE conv = ? AND processed = 0${nw}${mentionSql}${cliImSql}${owner.sql} ORDER BY time ASC, id ASC LIMIT ?`)
      .all(conv, ...owner.args, maxFresh) as Row[];
    if (!fresh.length) return [];
    if (opts?.onlyMentions) {
      return fresh.map((r) => this.toObs(r));
    }
    const t0 = Number(fresh[0].time);
    const before = this.db
      .prepare(`SELECT * FROM ctx_obs WHERE conv = ? AND processed = 1 AND time <= ?${nw}${cliImSql}${owner.sql} ORDER BY time DESC, id DESC LIMIT ?`)
      .all(conv, t0, ...owner.args, context) as Row[];
    return [...before.reverse(), ...fresh].map((r) => this.toObs(r));
  }

  /**
   * 快通道理解窗口：
   *   - 若触发消息（targetObsId）已被常规周期或前序作业处理完（或已撤回/不属于当前账号），直接返回空数组；
   *   - 当 `opts.onlyMentions` 为 true（群已移出白名单/有效发言群，仅允许真实 @我）时，仅选择真实 `@me` 观测，不混入普通群消息或普通背景；
   *   - 否则包含触发消息及其前后待处理消息（最多 maxFresh 条）、紧贴触发前的最近背景，并为批次中**所有**待处理话题消息补齐 root/parent 锚点。
   */
  convWindowAround(
    conv: string,
    targetObsId: string,
    maxFresh = 60,
    context = 12,
    activeNativeOwner?: string | null,
    opts?: { onlyMentions?: boolean },
  ): Obs[] {
    const owner = this.ownerClause(activeNativeOwner);
    const nw = ContextStore.NOT_WITHDRAWN;
    const mentionSql = opts?.onlyMentions
      ? " AND (kind = 'at_me' OR json_extract(meta, '$.at_me') = 1) AND COALESCE(json_extract(meta, '$.at_me'), 1) != 0 AND COALESCE(json_extract(meta, '$.is_mention_me'), 1) != 0"
      : "";
    const target = this.db
      .prepare(`SELECT * FROM ctx_obs WHERE id = ? AND conv = ? AND processed = 0${nw}${mentionSql}${owner.sql}`)
      .get(targetObsId, conv, ...owner.args) as Row | undefined;
    if (!target) return [];
    const targetTime = Number(target.time);
    const after = this.db
      .prepare(`SELECT * FROM ctx_obs WHERE conv = ? AND processed = 0 AND time >= ?${nw}${mentionSql}${owner.sql} ORDER BY time ASC, id ASC LIMIT ?`)
      .all(conv, targetTime, ...owner.args, maxFresh) as Row[];
    const hasTarget = after.some((r) => String(r.id) === String(target.id));
    let fresh = hasTarget ? after : [target, ...after.slice(0, Math.max(0, maxFresh - 1))];
    const rem = maxFresh - fresh.length;
    if (rem > 0) {
      const seen = new Set(fresh.map((r) => String(r.id)));
      const earlierPending = this.db
        .prepare(`SELECT * FROM ctx_obs WHERE conv = ? AND processed = 0 AND time <= ?${nw}${mentionSql}${owner.sql} ORDER BY time DESC, id DESC LIMIT ?`)
        .all(conv, targetTime, ...owner.args, rem + seen.size) as Row[];
      const extra = earlierPending.filter((r) => !seen.has(String(r.id))).slice(0, rem).reverse();
      fresh = [...extra, ...fresh];
    }
    fresh.sort((a, b) => Number(a.time) - Number(b.time) || String(a.id).localeCompare(String(b.id)));
    if (opts?.onlyMentions) {
      return fresh.map((r) => this.toObs(r));
    }
    const includedIds = new Set(fresh.map((r) => String(r.id)));
    // 独立拉取紧贴触发消息之前的最近背景（以 targetTime 为锚点而非最早积压 t0，防止刚补读的近邻背景被旧积压挤出）
    const beforeTrigger = (
      this.db
        .prepare(`SELECT * FROM ctx_obs WHERE conv = ? AND time <= ?${nw}${owner.sql} ORDER BY time DESC, id DESC LIMIT ?`)
        .all(conv, targetTime, ...owner.args, context + includedIds.size) as Row[]
    )
      .filter((r) => !includedIds.has(String(r.id)))
      .slice(0, context);
    beforeTrigger.forEach((r) => includedIds.add(String(r.id)));

    // 显式补齐本批次所有待处理消息的话题根消息与引用父消息锚点（避免防抖合并多话题 @我 时丢失任一话题上下文）
    const anchors: Row[] = [];
    for (const f of fresh) {
      const meta = j<Record<string, unknown>>(f.meta, {});
      for (const rawId of [String(meta.native_root_id ?? ""), String(meta.native_parent_id ?? "")]) {
        if (!rawId) continue;
        const anchorObsId = `pw:${rawId}`;
        if (includedIds.has(anchorObsId)) continue;
        const row = this.db
          .prepare(`SELECT * FROM ctx_obs WHERE id = ? AND conv = ?${nw}${owner.sql}`)
          .get(anchorObsId, conv, ...owner.args) as Row | undefined;
        if (row) {
          anchors.push(row);
          includedIds.add(String(row.id));
        }
      }
    }
    const combined = [...anchors, ...beforeTrigger, ...fresh];
    combined.sort((a, b) => Number(a.time) - Number(b.time) || String(a.id).localeCompare(String(b.id)));
    return combined.map((r) => this.toObs(r));
  }

  convObs(conv: string, since: number, limit = 80, activeNativeOwner?: string | null): Obs[] {
    const owner = this.ownerClause(activeNativeOwner);
    const rows = this.db
      .prepare(`SELECT * FROM ctx_obs WHERE conv = ? AND time >= ?${ContextStore.NOT_WITHDRAWN}${owner.sql} ORDER BY time DESC LIMIT ?`)
      .all(conv, since, ...owner.args, limit) as Row[];
    return rows.map((r) => this.toObs(r)).reverse();
  }

  latestConvObs(conv: string): Obs | undefined {
    const row = this.db.prepare("SELECT * FROM ctx_obs WHERE conv = ? ORDER BY time DESC LIMIT 1").get(conv) as Row | undefined;
    return row ? this.toObs(row) : undefined;
  }

  isDmConv(conv: string): boolean {
    return !!this.db
      .prepare("SELECT 1 FROM ctx_obs WHERE conv = ? AND (kind = 'p2p' OR lower(coalesce(json_extract(meta, '$.chat_type'), '')) = 'p2p') LIMIT 1")
      .get(conv);
  }

  /**
   * 标记观测为已处理；传入 `{ id, rev }` 或 `{ id, text }` 时仅当当前修订与送给模型的版本一致才标记，
   * 防止模型推理期间到达的正文或 @mention 编辑被旧批次静默吞掉。
   */
  markProcessed(entries: (string | { id: string; text?: string; rev?: string })[]): void {
    const get = this.db.prepare("SELECT text, meta FROM ctx_obs WHERE id = ?");
    const upd = this.db.prepare("UPDATE ctx_obs SET processed = 1, meta = ? WHERE id = ? AND text = ? AND meta = ?");
    this.tx(() => {
      for (const entry of entries) {
        const id = typeof entry === "string" ? entry : entry.id;
        const expectedRev = typeof entry === "string" ? undefined : entry.rev;
        const expectedText = typeof entry === "string" ? undefined : entry.text;
        const cur = get.get(id) as { text: string; meta: string } | undefined;
        if (!cur) continue;
        const m = j<Record<string, unknown>>(cur.meta, {});
        if (expectedRev !== undefined && obsRevision({ text: cur.text, meta: m }) !== expectedRev) continue;
        if (expectedRev === undefined && expectedText !== undefined && cur.text !== expectedText) continue;
        if (m.background_only) delete m.background_only;
        upd.run(JSON.stringify(m), id, cur.text, cur.meta);
      }
    });
  }

  /** 跨进程会话理解占坑：绑定唯一 holder 令牌与进程 proc_owner，避免旧进程接管失效后误续租或误释放新进程占坑 */
  claimConv(conv: string, holder: string, procOwner: string, ttlMs = 120_000, now = Date.now()): boolean {
    return this.tx(() => {
      const cur = this.db.prepare("SELECT holder, proc_owner, expires_at FROM ctx_conv_claim WHERE conv = ?").get(conv) as
        | { holder: string; proc_owner: string; expires_at: number }
        | undefined;
      if (
        cur &&
        !(cur.holder === holder && cur.proc_owner === procOwner) &&
        cur.expires_at > now &&
        !isDeadOwner(cur.proc_owner, procOwner)
      ) {
        return false;
      }
      this.db
        .prepare("INSERT OR REPLACE INTO ctx_conv_claim (conv, holder, proc_owner, expires_at) VALUES (?, ?, ?, ?)")
        .run(conv, holder, procOwner, now + ttlMs);
      return true;
    });
  }

  renewConv(conv: string, holder: string, procOwner?: string, ttlMs = 120_000, now = Date.now()): boolean {
    const r = procOwner
      ? this.db
          .prepare("UPDATE ctx_conv_claim SET expires_at = ? WHERE conv = ? AND holder = ? AND proc_owner = ? AND expires_at > ?")
          .run(now + ttlMs, conv, holder, procOwner, now)
      : this.db
          .prepare("UPDATE ctx_conv_claim SET expires_at = ? WHERE conv = ? AND holder = ? AND expires_at > ?")
          .run(now + ttlMs, conv, holder, now);
    return Number(r.changes) > 0;
  }

  /** 在写事务内校验会话认领租约仍由指定执行者有效持有（未过期且未被他进程接管） */
  isConvClaimedBy(conv: string, holder: string, procOwner: string, now = Date.now()): boolean {
    return !!this.db
      .prepare("SELECT 1 FROM ctx_conv_claim WHERE conv = ? AND holder = ? AND proc_owner = ? AND expires_at > ?")
      .get(conv, holder, procOwner, now);
  }

  releaseConv(conv: string, holder: string, procOwner?: string): void {
    if (procOwner) {
      this.db.prepare("DELETE FROM ctx_conv_claim WHERE conv = ? AND holder = ? AND proc_owner = ?").run(conv, holder, procOwner);
    } else {
      this.db.prepare("DELETE FROM ctx_conv_claim WHERE conv = ? AND holder = ?").run(conv, holder);
    }
  }

  muteConv(conv: string, name: string, muted: boolean): void {
    const resolvedName = name || (muted ? this.latestConvObs(conv)?.conv_name ?? "" : "");
    if (muted) this.db.prepare("INSERT OR REPLACE INTO ctx_mute_conv (conv, name, at) VALUES (?, ?, ?)").run(conv, resolvedName, Date.now());
    else this.db.prepare("DELETE FROM ctx_mute_conv WHERE conv = ?").run(conv);
    if (muted) this.db.prepare("UPDATE ctx_obs SET processed = 1 WHERE conv = ?").run(conv);
  }

  isConvMutedById(conv: string): boolean {
    return !!this.db.prepare("SELECT 1 FROM ctx_mute_conv WHERE conv = ?").get(conv);
  }

  mutedConvs(): { conv: string; name: string }[] {
    return this.db.prepare("SELECT conv, name FROM ctx_mute_conv").all() as { conv: string; name: string }[];
  }

  // ───────── 项目 ─────────

  private toProject(r: Row): ProjectRow {
    return { ...(r as unknown as ProjectRow), aliases: j(r.aliases, []), refs: j(r.refs, []), muted: !!r.muted, pinned: !!r.pinned, parent_id: String(r.parent_id ?? "") };
  }

  projects(o: { includeLegacy?: boolean } = {}): ProjectRow[] {
    const rows = this.db.prepare("SELECT * FROM ctx_project ORDER BY last_activity DESC").all() as Row[];
    return rows.map((r) => this.toProject(r)).filter((p) => o.includeLegacy || (p.status === "active" && !p.muted));
  }

  project(id: string): ProjectRow | undefined {
    const r = this.db.prepare("SELECT * FROM ctx_project WHERE id = ?").get(id) as Row | undefined;
    return r ? this.toProject(r) : undefined;
  }

  /** 按 ID、名称、别名、引用（如 story#123）找项目 */
  findProject(key: string): ProjectRow | undefined {
    if (!key) return undefined;
    const byId = this.project(key);
    if (byId) return byId;
    const k = norm(key);
    const all = this.projects({ includeLegacy: true });
    return (
      all.find((p) => norm(p.name) === k || p.aliases.some((a) => norm(a) === k) || p.refs.some((r) => norm(r) === k)) ??
      // 模糊匹配只用于模型识别出的项目；系统项目（Meego 空间、飞书任务，id 以 sys_ 开头）只按精确名称匹配
      all.find((p) => !p.id.startsWith("sys_") && k.length >= 4 && (norm(p.name).includes(k) || k.includes(norm(p.name))) && similarity(p.name, key) > 0.5)
    );
  }

  /** 创建或合并项目（名称 / 别名 / 引用任一命中即合并） */
  upsertProject(p: Partial<ProjectRow> & { name: string }, activityAt = Date.now()): ProjectRow {
    const now = Date.now();
    // 指定了 sys_ 开头的 id：只按 id 匹配（不存在就用这个 id 新建），避免和名字相近的项目合并
    const hit = p.id?.startsWith("sys_")
      ? this.project(p.id)
      : (p.id && this.project(p.id)) || this.findProject(p.name) || (p.refs ?? []).map((r) => this.findProject(r)).find(Boolean) || (p.aliases ?? []).map((a) => this.findProject(a)).find(Boolean);
    if (hit) {
      const aliases = [...new Set([...hit.aliases, ...(p.aliases ?? []), ...(norm(p.name) !== norm(hit.name) ? [p.name] : [])])].slice(0, 20);
      const refs = [...new Set([...hit.refs, ...(p.refs ?? [])])].slice(0, 50);
      this.db
        .prepare(
          `UPDATE ctx_project SET aliases = ?, refs = ?, description = ?, my_role = ?, stage = ?, health = ?, status = ?, parent_id = ?, updated = ?, last_activity = MAX(last_activity, ?) WHERE id = ?`,
        )
        .run(
          JSON.stringify(aliases),
          JSON.stringify(refs),
          p.description || hit.description,
          p.my_role || hit.my_role,
          p.stage || hit.stage,
          p.health || hit.health,
          hit.pinned ? hit.status : (p.status ?? hit.status),
          p.parent_id !== undefined && p.parent_id !== hit.id && !hit.pinned ? p.parent_id : hit.parent_id,
          now,
          activityAt,
          hit.id,
        );
      return this.project(hit.id)!;
    }
    const id = p.id || newId("prj");
    this.db
      .prepare(
        `INSERT INTO ctx_project (id, name, aliases, refs, description, my_role, stage, status, muted, health, parent_id, created, updated, last_activity)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(id, p.name, JSON.stringify(p.aliases ?? []), JSON.stringify(p.refs ?? []), p.description ?? "", p.my_role ?? "", p.stage ?? "", p.status ?? "active", p.muted ? 1 : 0, p.health ?? "unknown", p.parent_id ?? "", now, now, activityAt);
    return this.project(id)!;
  }

  setProject(id: string, patch: { status?: ProjectRow["status"]; muted?: boolean; pinned?: boolean; health?: ProjectRow["health"]; parent_id?: string }): void {
    const p = this.project(id);
    if (!p) return;
    this.db
      .prepare("UPDATE ctx_project SET status = ?, muted = ?, pinned = ?, health = ?, parent_id = ?, updated = ? WHERE id = ?")
      .run(patch.status ?? p.status, (patch.muted ?? p.muted) ? 1 : 0, (patch.pinned ?? p.pinned) ? 1 : 0, patch.health ?? p.health, patch.parent_id ?? p.parent_id, Date.now(), id);
  }

  /** 子项目 */
  children(id: string): ProjectRow[] {
    return (this.db.prepare("SELECT * FROM ctx_project WHERE parent_id = ? ORDER BY last_activity DESC").all(id) as Row[]).map((r) => this.toProject(r));
  }

  /** 项目实际是否可见：自己或上级被静音 / 不再活跃都算隐藏 */
  hidden(p: ProjectRow | undefined): boolean {
    if (!p) return false;
    if (p.muted || p.status !== "active") return true;
    const parent = p.parent_id ? this.project(p.parent_id) : undefined;
    return !!parent && (parent.muted || parent.status !== "active");
  }

  /** 把事项 / 知识 / 动态 / 冲突挪到另一个项目（拆分子项目用） */
  moveTo(projectId: string, ids: { items?: string[]; knowledge?: string[]; updates?: string[]; conflicts?: string[] }): number {
    let n = 0;
    const run = (table: string, list: string[] = []) => {
      const st = this.db.prepare(`UPDATE ${table} SET project_id = ? WHERE id = ?`);
      for (const id of list) n += Number(st.run(projectId, id).changes);
    };
    this.tx(() => {
      run("ctx_item", ids.items);
      run("ctx_knowledge", ids.knowledge);
      run("ctx_update", ids.updates);
      run("ctx_conflict", ids.conflicts);
    });
    return n;
  }

  // ───────── 事项 ─────────

  private toItem(r: Row): ItemRow {
    return { ...(r as unknown as ItemRow), user_locked: !!r.user_locked, meta: j(r.meta, {}), strong_key: String(r.strong_key ?? "") };
  }

  item(id: string): ItemRow | undefined {
    const r = this.db.prepare("SELECT * FROM ctx_item WHERE id = ?").get(id) as Row | undefined;
    return r ? this.toItem(r) : undefined;
  }

  itemByKey(key: string): ItemRow | undefined {
    const r = this.db.prepare("SELECT * FROM ctx_item WHERE strong_key = ?").get(key) as Row | undefined;
    return r ? this.toItem(r) : undefined;
  }

  items(f: { status?: CtxItemStatus[]; project_id?: string; source?: CtxSource; kinds?: CtxItemKind[]; limit?: number } = {}): ItemRow[] {
    const where: string[] = [];
    const args: (string | number)[] = [];
    if (f.status?.length) {
      where.push(`status IN (${f.status.map(() => "?").join(",")})`);
      args.push(...f.status);
    }
    if (f.kinds?.length) {
      where.push(`kind IN (${f.kinds.map(() => "?").join(",")})`);
      args.push(...f.kinds);
    }
    if (f.project_id) {
      where.push("project_id = ?");
      args.push(f.project_id);
    }
    if (f.source) {
      where.push("source = ?");
      args.push(f.source);
    }
    const q = `SELECT * FROM ctx_item ${where.length ? `WHERE ${where.join(" AND ")}` : ""} ORDER BY last_seen DESC LIMIT ?`;
    return (this.db.prepare(q).all(...args, f.limit ?? 1000) as Row[]).map((r) => this.toItem(r));
  }

  /** 同一项目里标题相近的未关闭事项（去重用） */
  similarOpenItem(projectId: string, title: string, kind?: CtxItemKind): ItemRow | undefined {
    const cands = this.items({ status: ["open", "snoozed"], project_id: projectId, limit: 300 });
    let best: { it: ItemRow; s: number } | undefined;
    for (const it of cands) {
      const s = similarity(it.title, title) + (kind && it.kind === kind ? 0.05 : 0);
      if (s >= 0.55 && (!best || s > best.s)) best = { it, s };
    }
    return best?.it;
  }

  /**
   * 创建或更新事项。优先按强标识合并，其次按 ID，再其次按同项目相似标题。
   * 用户锁定（手动完成 / 驳回）的事项不会被模型重新打开。
   */
  upsertItem(p: Partial<ItemRow> & { title: string; kind: CtxItemKind }, seenAt = Date.now()): { item: ItemRow; created: boolean } {
    const now = Date.now();
    const hit =
      (p.strong_key && this.itemByKey(p.strong_key)) ||
      (p.id && this.item(p.id)) ||
      // 有强标识（Meego 节点、飞书任务）的事项只按强标识合并：标题相近的不同工作项不能合成一件
      (!p.strong_key && p.project_id && this.similarOpenItem(p.project_id, p.title, p.kind)) ||
      undefined;
    if (hit) {
      let status = p.status ?? hit.status;
      if (hit.user_locked && (hit.status === "done" || hit.status === "dismissed")) status = hit.status;
      const closing = (status === "done" || status === "dismissed") && hit.status !== status;
      this.db
        .prepare(
          `UPDATE ctx_item SET title = ?, kind = ?, project_id = ?, status = ?, priority = ?, due = ?, counterpart = ?, next_step = ?,
             confidence = ?, last_seen = MAX(last_seen, ?), closed_at = ?, close_reason = ?, meta = ? WHERE id = ?`,
        )
        .run(
          p.title || hit.title,
          p.kind || hit.kind,
          p.project_id || hit.project_id,
          status,
          p.priority ?? hit.priority,
          p.due !== undefined ? p.due : hit.due,
          p.counterpart || hit.counterpart,
          p.next_step || hit.next_step,
          Math.max(hit.confidence, p.confidence ?? 0),
          seenAt,
          closing ? now : status === "open" ? null : hit.closed_at,
          closing ? (p.close_reason ?? "") : status === "open" ? "" : hit.close_reason,
          JSON.stringify({ ...hit.meta, ...(p.meta ?? {}) }),
          hit.id,
        );
      return { item: this.item(hit.id)!, created: false };
    }
    const id = p.id || newId("itm");
    this.db
      .prepare(
        `INSERT INTO ctx_item (id, title, kind, project_id, status, priority, due, counterpart, next_step, strong_key, confidence, source,
           first_seen, last_seen, closed_at, close_reason, meta) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        id,
        p.title,
        p.kind,
        p.project_id ?? "",
        p.status ?? "open",
        p.priority ?? "medium",
        p.due ?? null,
        p.counterpart ?? "",
        p.next_step ?? "",
        p.strong_key || null,
        p.confidence ?? 0.7,
        p.source ?? "im",
        seenAt,
        seenAt,
        p.status === "done" || p.status === "dismissed" ? now : null,
        p.close_reason ?? "",
        JSON.stringify(p.meta ?? {}),
      );
    return { item: this.item(id)!, created: true };
  }

  /** 用户操作事项状态（锁定，模型不再自动改回） */
  setItemStatus(id: string, status: CtxItemStatus, o: { reason?: string; snoozeUntil?: number | null; lock?: boolean } = {}): ItemRow | undefined {
    const it = this.item(id);
    if (!it) return undefined;
    const closed = status === "done" || status === "dismissed";
    this.db
      .prepare("UPDATE ctx_item SET status = ?, closed_at = ?, close_reason = ?, snooze_until = ?, user_locked = ? WHERE id = ?")
      .run(status, closed ? Date.now() : null, o.reason ?? "", status === "snoozed" ? (o.snoozeUntil ?? null) : null, (o.lock ?? true) ? 1 : 0, id);
    return this.item(id);
  }

  setItemField(id: string, patch: { nudged_at?: number; feedback?: ItemRow["feedback"]; project_id?: string; meta?: Record<string, unknown> }): void {
    const it = this.item(id);
    if (!it) return;
    this.db
      .prepare("UPDATE ctx_item SET nudged_at = ?, feedback = ?, project_id = ?, meta = ? WHERE id = ?")
      .run(patch.nudged_at ?? it.nudged_at, patch.feedback ?? it.feedback, patch.project_id ?? it.project_id, JSON.stringify({ ...it.meta, ...(patch.meta ?? {}) }), id);
  }

  /** 到期的稍后事项回到 open */
  wakeSnoozed(now = Date.now()): number {
    return Number(this.db.prepare("UPDATE ctx_item SET status = 'open', snooze_until = NULL WHERE status = 'snoozed' AND snooze_until IS NOT NULL AND snooze_until <= ?").run(now).changes);
  }

  // ───────── 证据 ─────────

  addEvidence(entity: string, entityId: string, obsId: string, quote: string, time: number): void {
    this.db
      .prepare(
        `INSERT INTO ctx_evidence (entity, entity_id, obs_id, quote, time) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(entity, entity_id, obs_id) DO UPDATE SET quote = excluded.quote, time = MAX(time, excluded.time)`,
      )
      .run(entity, entityId, obsId, quote.slice(0, 300), time);
  }

  /** 查询实体的证据列表：默认排除已撤回观测的摘录，避免新卡片、视图与委派派单继续携带已撤回原文（审计可显式传 includeWithdrawn: true） */
  evidence(entity: string, entityId: string, limit = 20, opts?: { includeWithdrawn?: boolean }): EvidenceRow[] {
    if (opts?.includeWithdrawn) {
      return this.db
        .prepare("SELECT * FROM ctx_evidence WHERE entity = ? AND entity_id = ? ORDER BY time DESC LIMIT ?")
        .all(entity, entityId, limit) as unknown as EvidenceRow[];
    }
    return this.db
      .prepare(
        `SELECT e.* FROM ctx_evidence e
         LEFT JOIN ctx_obs o ON o.id = e.obs_id
         WHERE e.entity = ? AND e.entity_id = ?
           AND COALESCE(json_extract(o.meta, '$.withdrawn'), 0) = 0
         ORDER BY e.time DESC LIMIT ?`,
      )
      .all(entity, entityId, limit) as unknown as EvidenceRow[];
  }

  /** 事项最近一次有效（未撤回）证据所在的会话（起草回复时用） */
  lastEvidenceObs(entity: string, entityId: string, filter?: (o: Obs) => boolean): Obs | undefined {
    for (const e of this.evidence(entity, entityId, 50)) {
      const o = this.obs(e.obs_id);
      if (o && o.meta.withdrawn !== true && (!filter || filter(o))) return o;
    }
    return undefined;
  }

  // ───────── 知识 / 动态 / 人 ─────────

  upsertKnowledge(k: Omit<KnowledgeRow, "id" | "created" | "updated"> & { id?: string }): KnowledgeRow {
    const now = Date.now();
    const same = (this.db.prepare("SELECT * FROM ctx_knowledge WHERE project_id = ?").all(k.project_id) as unknown as KnowledgeRow[]).find(
      (x) => similarity(x.title, k.title) >= 0.6,
    );
    if (same) {
      this.db.prepare("UPDATE ctx_knowledge SET content = ?, kind = ?, confidence = ?, updated = ? WHERE id = ?").run(k.content || same.content, k.kind, Math.max(same.confidence, k.confidence), now, same.id);
      return { ...same, content: k.content || same.content, updated: now };
    }
    const id = k.id || newId("knw");
    this.db.prepare("INSERT INTO ctx_knowledge (id, project_id, kind, title, content, confidence, created, updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?)").run(id, k.project_id, k.kind, k.title, k.content, k.confidence, now, now);
    return { ...k, id, created: now, updated: now };
  }

  knowledge(f: { project_id?: string; q?: string; limit?: number } = {}): KnowledgeRow[] {
    let rows = (f.project_id
      ? this.db.prepare("SELECT * FROM ctx_knowledge WHERE project_id = ? ORDER BY updated DESC").all(f.project_id)
      : this.db.prepare("SELECT * FROM ctx_knowledge ORDER BY updated DESC").all()) as unknown as KnowledgeRow[];
    if (f.q) {
      const q = f.q.toLowerCase();
      rows = rows.filter((k) => `${k.title} ${k.content}`.toLowerCase().includes(q));
    }
    return rows.slice(0, f.limit ?? 500);
  }

  addUpdate(u: { project_id: string; time: number; summary: string }): UpdateRow | undefined {
    const recent = this.db.prepare("SELECT * FROM ctx_update WHERE project_id = ? AND time >= ?").all(u.project_id, u.time - 2 * 86_400_000) as unknown as UpdateRow[];
    if (recent.some((x) => similarity(x.summary, u.summary) >= 0.6)) return undefined;
    const id = newId("upd");
    this.db.prepare("INSERT INTO ctx_update (id, project_id, time, summary, created) VALUES (?, ?, ?, ?, ?)").run(id, u.project_id, u.time, u.summary, Date.now());
    return { id, ...u, created: Date.now() };
  }

  updates(f: { since?: number; project_id?: string; limit?: number } = {}): UpdateRow[] {
    const rows = (f.project_id
      ? this.db.prepare("SELECT * FROM ctx_update WHERE project_id = ? AND time >= ? ORDER BY time DESC LIMIT ?").all(f.project_id, f.since ?? 0, f.limit ?? 200)
      : this.db.prepare("SELECT * FROM ctx_update WHERE time >= ? ORDER BY time DESC LIMIT ?").all(f.since ?? 0, f.limit ?? 200)) as unknown as UpdateRow[];
    return rows;
  }

  upsertPerson(p: { id?: string; name: string; relation?: string; projects?: string[] }, seenAt = Date.now()): PersonRow {
    const id = p.id || hashId("psn", norm(p.name));
    const cur = this.db.prepare("SELECT * FROM ctx_person WHERE id = ? OR name = ?").get(id, p.name) as Row | undefined;
    if (cur) {
      const projects = [...new Set([...j<string[]>(cur.projects, []), ...(p.projects ?? [])])];
      this.db
        .prepare("UPDATE ctx_person SET relation = ?, projects = ?, last_seen = MAX(last_seen, ?) WHERE id = ?")
        .run(p.relation || String(cur.relation), JSON.stringify(projects), seenAt, String(cur.id));
      return { id: String(cur.id), name: String(cur.name), relation: p.relation || String(cur.relation), projects, last_seen: seenAt };
    }
    this.db.prepare("INSERT INTO ctx_person (id, name, relation, projects, last_seen) VALUES (?, ?, ?, ?, ?)").run(id, p.name, p.relation ?? "", JSON.stringify(p.projects ?? []), seenAt);
    return { id, name: p.name, relation: p.relation ?? "", projects: p.projects ?? [], last_seen: seenAt };
  }

  people(): PersonRow[] {
    return (this.db.prepare("SELECT * FROM ctx_person ORDER BY last_seen DESC").all() as Row[]).map((r) => ({ ...(r as unknown as PersonRow), projects: j(r.projects, []) }));
  }

  // ───────── 冲突 ─────────

  addConflict(c: { project_id: string; topic: string; claims: ConflictRow["claims"]; ref?: string }): ConflictRow {
    const stampedClaims: ConflictRow["claims"] = c.claims.map((cl) => {
      if (cl.obs_rev) return cl;
      const obs = cl.obs_id ? this.obs(cl.obs_id) : undefined;
      return obs ? { ...cl, obs_rev: obsRevision(obs) } : cl;
    });
    const normalizedInput = { ...c, claims: stampedClaims };
    const byRef = c.ref ? this.conflicts("open").find((x) => x.id === c.ref) : undefined;
    const open = byRef ?? this.conflicts("open").find((x) => sameConflict(x, normalizedInput));
    if (open) {
      const claims = [...open.claims];
      for (const cl of stampedClaims) {
        const idx = claims.findIndex((x) => x.obs_id === cl.obs_id);
        if (idx >= 0) {
          // 同一观测经编辑重理解后再次写入冲突时，原地替换旧修订说法，避免旧说法残留为可选裁决项
          claims[idx] = cl;
        } else {
          claims.push(cl);
        }
      }
      this.db.prepare("UPDATE ctx_conflict SET claims = ? WHERE id = ?").run(JSON.stringify(claims), open.id);
      return { ...open, claims };
    }
    const id = newId("cfl");
    this.db.prepare("INSERT INTO ctx_conflict (id, project_id, topic, claims, status, created) VALUES (?, ?, ?, ?, 'open', ?)").run(id, c.project_id, c.topic, JSON.stringify(stampedClaims), Date.now());
    return { id, ...normalizedInput, status: "open", resolution: "", created: Date.now() };
  }

  conflicts(status?: "open" | "resolved"): ConflictRow[] {
    const rows = (status ? this.db.prepare("SELECT * FROM ctx_conflict WHERE status = ? ORDER BY created DESC").all(status) : this.db.prepare("SELECT * FROM ctx_conflict ORDER BY created DESC").all()) as Row[];
    return rows.map((r) => ({ ...(r as unknown as ConflictRow), claims: j(r.claims, []) }));
  }

  conflict(id: string): ConflictRow | undefined {
    return this.conflicts().find((c) => c.id === id);
  }

  /** 合并说的是同一件事的未解决冲突（说法并到最早的那条），返回合并掉的条数 */
  mergeConflicts(): number {
    const open = this.conflicts("open").sort((a, b) => a.created - b.created);
    const gone = new Set<string>();
    for (let i = 0; i < open.length; i++) {
      const keep = open[i];
      if (gone.has(keep.id)) continue;
      for (let k = i + 1; k < open.length; k++) {
        const dup = open[k];
        if (gone.has(dup.id) || !sameConflict(keep, dup)) continue;
        for (const cl of dup.claims) {
          const existingIdx = keep.claims.findIndex((x) => x.obs_id === cl.obs_id);
          if (existingIdx >= 0) {
            const obs = cl.obs_id ? this.obs(cl.obs_id) : undefined;
            if (obs && cl.obs_rev && obsRevision(obs) === cl.obs_rev) {
              keep.claims[existingIdx] = cl;
            }
          } else {
            keep.claims.push(cl);
          }
        }
        this.db.prepare("UPDATE ctx_conflict SET claims = ? WHERE id = ?").run(JSON.stringify(keep.claims), keep.id);
        this.db.prepare("DELETE FROM ctx_conflict WHERE id = ?").run(dup.id);
        gone.add(dup.id);
      }
    }
    return gone.size;
  }

  resolveConflict(id: string, resolution: string): void {
    this.db.prepare("UPDATE ctx_conflict SET status = 'resolved', resolution = ? WHERE id = ?").run(resolution, id);
  }

  // ───────── 反馈 ─────────

  addFeedback(entity: string, entityId: string, verdict: string, note: string, snapshot: string): void {
    this.db.prepare("INSERT INTO ctx_feedback (entity, entity_id, verdict, note, snapshot, at) VALUES (?, ?, ?, ?, ?, ?)").run(entity, entityId, verdict, note, snapshot, Date.now());
  }

  recentFeedback(limit = 12): { entity: string; verdict: string; note: string; snapshot: string; at: number }[] {
    return this.db.prepare("SELECT entity, verdict, note, snapshot, at FROM ctx_feedback ORDER BY at DESC LIMIT ?").all(limit) as never;
  }

  feedbackStats(sinceMs: number): { right: number; wrong: number; unimportant: number } {
    const rows = this.db.prepare("SELECT verdict, COUNT(*) AS n FROM ctx_feedback WHERE at >= ? GROUP BY verdict").all(sinceMs) as { verdict: string; n: number }[];
    const m = Object.fromEntries(rows.map((r) => [r.verdict, r.n]));
    return { right: m.right ?? 0, wrong: m.wrong ?? 0, unimportant: m.unimportant ?? 0 };
  }

  // ───────── 草稿 ─────────

  private toDraft(r: Row): DraftRow {
    return { ...(r as unknown as DraftRow), target: j(r.target, {}) };
  }

  hasProposedDraft(itemId: string, kind: CtxDraftKind): boolean {
    if (!itemId) return false;
    return !!this.db
      .prepare("SELECT 1 FROM ctx_draft WHERE item_id = ? AND kind = ? AND status = 'proposed' LIMIT 1")
      .get(itemId, kind);
  }

  addDraft(d: Omit<DraftRow, "id" | "created" | "updated" | "status" | "error">): DraftRow {
    const now = Date.now();
    // 同一事项同一类型已有待确认草稿时，先将旧草稿标为 discarded 再签发新 ID（绝不复用旧 ID 原地替换目标与正文，
    // 防止用户从尚未刷新的旧卡片/标签页点击确认时，把审阅过的正文错发到新会话）
    if (d.item_id) {
      this.db
        .prepare("UPDATE ctx_draft SET status = 'discarded', updated = ? WHERE item_id = ? AND kind = ? AND status = 'proposed'")
        .run(now, d.item_id, d.kind);
    }
    const id = newId("drf");
    this.db
      .prepare("INSERT INTO ctx_draft (id, item_id, project_id, kind, target, target_label, content, status, created, updated) VALUES (?, ?, ?, ?, ?, ?, ?, 'proposed', ?, ?)")
      .run(id, d.item_id, d.project_id, d.kind, JSON.stringify(d.target), d.target_label, d.content, now, now);
    return this.draft(id)!;
  }

  draft(id: string): DraftRow | undefined {
    const r = this.db.prepare("SELECT * FROM ctx_draft WHERE id = ?").get(id) as Row | undefined;
    return r ? this.toDraft(r) : undefined;
  }

  drafts(f: { status?: DraftRow["status"][]; item_id?: string } = {}): DraftRow[] {
    const rows = this.db.prepare("SELECT * FROM ctx_draft ORDER BY updated DESC LIMIT 200").all() as Row[];
    return rows.map((r) => this.toDraft(r)).filter((d) => (!f.status || f.status.includes(d.status)) && (!f.item_id || d.item_id === f.item_id));
  }

  setDraft(id: string, patch: { status?: DraftRow["status"]; content?: string; error?: string; target?: Record<string, string> }): void {
    const d = this.draft(id);
    if (!d) return;
    this.db
      .prepare("UPDATE ctx_draft SET status = ?, content = ?, error = ?, target = ?, updated = ? WHERE id = ?")
      .run(patch.status ?? d.status, patch.content ?? d.content, patch.error ?? d.error, JSON.stringify(patch.target ?? d.target), Date.now(), id);
  }

  /** 草稿状态的比较并交换：只有当前状态在 from 里才改（卡片和控制台同时操作只有一次生效） */
  casDraft(id: string, from: DraftRow["status"][], to: DraftRow["status"], content?: string): boolean {
    const r = this.db
      .prepare(`UPDATE ctx_draft SET status = ?, content = COALESCE(?, content), error = '', updated = ? WHERE id = ? AND status IN (${from.map(() => "?").join(",")})`)
      .run(to, content ?? null, Date.now(), id, ...from);
    return Number(r.changes) > 0;
  }

  /** 删除被你判为错误的知识 / 动态（连同证据） */
  deleteEntity(entity: "knowledge" | "update", id: string): void {
    const table = entity === "knowledge" ? "ctx_knowledge" : "ctx_update";
    this.tx(() => {
      this.db.prepare(`DELETE FROM ${table} WHERE id = ?`).run(id);
      this.db.prepare("DELETE FROM ctx_evidence WHERE entity = ? AND entity_id = ?").run(entity, id);
    });
  }

  /**
   * 在仍持有该会话占坑租约的同一写事务内，只将指定提交给模型的精确观测（且当前修订仍匹配）标为已处理，
   * 避免 mention-only 失败跳过把该群未送入模型的普通待处理消息一并吞掉。
   */
  skipObsIfClaimed(
    conv: string,
    entries: { id: string; rev: string }[],
    holder: string,
    procOwner: string,
    now = Date.now(),
  ): number {
    if (!entries.length) return 0;
    const get = this.db.prepare("SELECT conv, text, meta, processed FROM ctx_obs WHERE id = ?");
    const upd = this.db.prepare("UPDATE ctx_obs SET processed = 1, meta = ? WHERE id = ? AND text = ? AND meta = ?");
    return this.tx(() => {
      if (!this.isConvClaimedBy(conv, holder, procOwner, now)) return 0;
      let n = 0;
      for (const entry of entries) {
        const cur = get.get(entry.id) as { conv: string; text: string; meta: string; processed: number } | undefined;
        if (!cur || cur.processed !== 0 || cur.conv !== conv) continue;
        const m = j<Record<string, unknown>>(cur.meta, {});
        if (obsRevision({ text: cur.text, meta: m }) !== entry.rev) continue;
        if (m.background_only) delete m.background_only;
        n += Number(upd.run(JSON.stringify(m), entry.id, cur.text, cur.meta).changes);
      }
      return n;
    });
  }

  /** 某会话所有待处理观测标为已处理（理解反复失败时跳过） */
  skipConv(conv: string): number {
    return Number(this.db.prepare("UPDATE ctx_obs SET processed = 1 WHERE conv = ? AND processed = 0").run(conv).changes);
  }

  /** 今天（since 之后）关闭的事项 */
  closedSince(since: number): ItemRow[] {
    return (this.db.prepare("SELECT * FROM ctx_item WHERE status = 'done' AND closed_at >= ? ORDER BY closed_at DESC LIMIT 100").all(since) as Row[]).map((r) => this.toItem(r));
  }

  totals(): { projects: number; open_items: number; knowledge: number; people: number } {
    const one = (q: string) => (this.db.prepare(q).get() as { n: number }).n;
    return {
      projects: one("SELECT COUNT(*) AS n FROM ctx_project WHERE status = 'active' AND muted = 0"),
      open_items: one("SELECT COUNT(*) AS n FROM ctx_item WHERE status = 'open'"),
      knowledge: one("SELECT COUNT(*) AS n FROM ctx_knowledge"),
      people: one("SELECT COUNT(*) AS n FROM ctx_person"),
    };
  }
}
