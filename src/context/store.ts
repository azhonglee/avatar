import { createHash, randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import type { CtxDraftKind, CtxItemKind, CtxItemStatus, CtxPriority, CtxSource } from "../api/types.ts";

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
  claims: { claim: string; obs_id: string; quote: string; time: number }[];
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
        ingested INTEGER NOT NULL, processed INTEGER NOT NULL DEFAULT 0, alt_id TEXT NOT NULL DEFAULT '');
      CREATE INDEX IF NOT EXISTS ctx_obs_pending ON ctx_obs (processed, conv, time);
      CREATE INDEX IF NOT EXISTS ctx_obs_conv ON ctx_obs (conv, time);
      CREATE INDEX IF NOT EXISTS ctx_obs_im_time ON ctx_obs (source, is_me, time);
      CREATE TABLE IF NOT EXISTS ctx_conv_alias (
        pw_conv TEXT PRIMARY KEY, open_conv TEXT NOT NULL UNIQUE, conv_name TEXT NOT NULL DEFAULT '', updated INTEGER NOT NULL);
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
    `);
    // 迁移：子项目
    const cols = new Set((db.prepare("PRAGMA table_info(ctx_project)").all() as { name: string }[]).map((c) => c.name));
    if (!cols.has("parent_id")) db.exec("ALTER TABLE ctx_project ADD COLUMN parent_id TEXT NOT NULL DEFAULT ''");
    // 迁移：观测跨通道备用 ID（pw:* ↔ im:* 1 对 1 绑定，编辑更新直接按 alt_id 定位）
    const obsCols = new Set((db.prepare("PRAGMA table_info(ctx_obs)").all() as { name: string }[]).map((c) => c.name));
    if (!obsCols.has("alt_id")) db.exec("ALTER TABLE ctx_obs ADD COLUMN alt_id TEXT NOT NULL DEFAULT ''");
    db.exec("CREATE INDEX IF NOT EXISTS ctx_obs_alt_id ON ctx_obs (alt_id) WHERE alt_id != ''");
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

  // ───────── 会话别名（pw_chat:* ↔ oc_* 1 对 1 绑定） ─────────

  private static isGenericConvName(name: string): boolean {
    const t = name.trim();
    return !t || t === "群聊" || t === "私聊" || /^群聊\(/.test(t) || /^私聊：\d+$/.test(t);
  }

  convAlias(conv: string): { pw_conv: string; open_conv: string; conv_name: string } | undefined {
    if (!conv) return undefined;
    const r = this.db
      .prepare("SELECT pw_conv, open_conv, conv_name FROM ctx_conv_alias WHERE pw_conv = ? OR open_conv = ? LIMIT 1")
      .get(conv, conv) as { pw_conv: string; open_conv: string; conv_name: string } | undefined;
    return r;
  }

  /** 按精确非泛化群名反查已记录的开放平台会话（用于首次关联前或静音/排除校验） */
  findOpenConvsByName(convName: string): string[] {
    if (ContextStore.isGenericConvName(convName)) return [];
    const target = norm(convName);
    const rows = this.db
      .prepare("SELECT DISTINCT conv, conv_name FROM ctx_obs WHERE source = 'im' AND conv NOT LIKE 'pw_chat:%' AND conv != '' AND conv_name != ''")
      .all() as { conv: string; conv_name: string }[];
    return rows.filter((r) => norm(r.conv_name) === target).map((r) => r.conv);
  }

  /** 建立或更新 1 对 1 会话别名；若任一端已绑定到其他会话则拒绝覆盖并返回 false。 */
  linkConvAlias(pwConv: string, openConv: string, convName = ""): boolean {
    if (!pwConv.startsWith("pw_chat:") || !openConv || openConv.startsWith("pw_chat:")) return false;
    const byPw = this.db.prepare("SELECT open_conv, conv_name FROM ctx_conv_alias WHERE pw_conv = ?").get(pwConv) as { open_conv: string; conv_name: string } | undefined;
    if (byPw && byPw.open_conv !== openConv) return false;
    const byOpen = this.db.prepare("SELECT pw_conv FROM ctx_conv_alias WHERE open_conv = ?").get(openConv) as { pw_conv: string } | undefined;
    if (byOpen && byOpen.pw_conv !== pwConv) return false;
    const finalName = !ContextStore.isGenericConvName(convName) ? convName : (byPw?.conv_name ?? "");
    this.db
      .prepare("INSERT OR REPLACE INTO ctx_conv_alias (pw_conv, open_conv, conv_name, updated) VALUES (?, ?, ?, ?)")
      .run(pwConv, openConv, finalName, Date.now());
    return true;
  }

  /** 返回同一会话的所有等价键（[conv] 或 [pw_conv, open_conv]） */
  convGroup(conv: string): string[] {
    const a = this.convAlias(conv);
    return a ? [a.pw_conv, a.open_conv] : [conv];
  }

  /** 规范会话键：已绑定别名时优先使用 open_conv，保证锁、待处理列表和背景窗口合并到同一会话 */
  canonicalConv(conv: string): string {
    return this.convAlias(conv)?.open_conv ?? conv;
  }

  // ───────── 观测 ─────────

  /**
   * 幂等写入观测：
   *   1. 按主 ID 或备用 ID（alt_id）直接定位：支持跨通道消息的后续编辑，以及把历史背景行（background_only）在首次真实投递时提升为待处理。
   *   2. 跨通道 1 对 1 去重（pw:* ↔ im:*）：必须满足已验证会话匹配（已有别名 / 同非泛化群名 / 无冲突且唯一长文本 ≥12 字）、同 chat_type、
   *      同 is_me、±15 秒且目标行尚未绑定 alt_id；存在歧义（多于 1 条候选）时绝不合并，防止回复目标串群。
   * 返回新增或重新变为待处理的数量。
   */
  addObs(list: Obs[]): number {
    const now = Date.now();
    const findExisting = this.db.prepare(
      "SELECT id, alt_id, kind, conv, conv_name, actor_id, actor_name, text, url, meta, processed FROM ctx_obs WHERE id = ? OR alt_id = ? LIMIT 1",
    );
    const nearIm = this.db.prepare(
      `SELECT id, alt_id, conv, conv_name, actor_id, actor_name, text, url, meta, processed FROM ctx_obs
       WHERE source = 'im' AND is_me = ? AND alt_id = '' AND time BETWEEN ? AND ? AND id LIKE ? LIMIT 50`,
    );
    const updRow = this.db.prepare(
      "UPDATE ctx_obs SET kind = ?, conv_name = ?, actor_name = ?, text = ?, url = ?, meta = ?, alt_id = ?, processed = ? WHERE id = ?",
    );
    const ins = this.db.prepare(
      `INSERT INTO ctx_obs (id, source, kind, conv, conv_name, actor_id, actor_name, is_me, time, text, url, meta, ingested, processed, alt_id)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, '')`,
    );
    let n = 0;

    const mergeMeta = (base: Record<string, unknown>, incoming: Obs, isIncomingLark: boolean, clearBg: boolean): Record<string, unknown> => {
      const merged: Record<string, unknown> = { ...base, ...(incoming.meta ?? {}) };
      if (isIncomingLark) {
        merged.open_message_id = String(incoming.meta.message_id ?? incoming.id.replace(/^im:/, ""));
        merged.open_chat_id = incoming.conv;
        merged.open_actor_id = incoming.actor_id;
        // 保留已有的个人 Web 原生字段
        for (const k of ["transport", "native_message_id", "native_chat_id", "native_root_id", "native_parent_id", "position", "at_me", "mentions"]) {
          if (base[k] !== undefined) merged[k] = base[k];
        }
      } else if (incoming.id.startsWith("pw:")) {
        merged.native_message_id = String(incoming.meta.native_message_id ?? incoming.id.replace(/^pw:/, ""));
        merged.native_chat_id = String(incoming.meta.native_chat_id ?? "");
        merged.native_root_id = String(incoming.meta.native_root_id ?? "");
        for (const k of ["message_id", "open_message_id", "open_chat_id", "open_actor_id"]) {
          if (base[k] !== undefined) merged[k] = base[k];
        }
      }
      if (clearBg) delete merged.background_only;
      return merged;
    };

    const pickBetterConv = (curName: string, incName: string, preferInc: boolean) =>
      preferInc && incName && ContextStore.isGenericConvName(curName) ? incName : curName || incName;
    const pickBetterActor = (curActor: string, incActor: string, preferInc: boolean) =>
      preferInc && incActor && (!curActor || /^\d+$/.test(curActor)) ? incActor : curActor || incActor;

    this.tx(() => {
      for (const o of list) {
        if (!o.id || !o.time) continue;
        const cur = findExisting.get(o.id, o.id) as Row | undefined;
        if (cur) {
          const curMeta = j<Record<string, unknown>>(cur.meta, {});
          const isIncomingLark = o.id.startsWith("im:");
          const wasBgOnly = curMeta.background_only === true;
          const textChanged = String(cur.text ?? "") !== o.text;
          const nextProcessed = wasBgOnly || textChanged ? 0 : Number(cur.processed ?? 0);
          const mergedMeta = mergeMeta(curMeta, o, isIncomingLark, wasBgOnly);
          const nextKind = wasBgOnly ? o.kind : String(cur.kind ?? o.kind);
          const nextConvName = pickBetterConv(String(cur.conv_name ?? ""), o.conv_name, isIncomingLark || wasBgOnly);
          const nextActorName = pickBetterActor(String(cur.actor_name ?? ""), o.actor_name, isIncomingLark || wasBgOnly);
          const nextUrl = String(cur.url ?? "") || o.url;
          updRow.run(nextKind, nextConvName, nextActorName, o.text, nextUrl, JSON.stringify(mergedMeta), String(cur.alt_id ?? ""), nextProcessed, String(cur.id));
          if (wasBgOnly || textChanged) n++;
          continue;
        }

        // 跨通道 1 对 1 匹配（pw:* ↔ im:*）
        if (o.source === "im" && (o.id.startsWith("im:") || o.id.startsWith("pw:"))) {
          const nt = norm(o.text);
          if (nt.length >= 2) {
            const isIncomingLark = o.id.startsWith("im:");
            const otherPrefix = isIncomingLark ? "pw:%" : "im:%";
            const incChatType = String(o.meta.chat_type ?? "");
            const cands = nearIm.all(o.is_me ? 1 : 0, o.time - 15_000, o.time + 15_000, otherPrefix) as Row[];
            const textMatches = cands.filter((c) => {
              if (norm(String(c.text ?? "")) !== nt) return false;
              const cm = j<Record<string, unknown>>(c.meta, {});
              const cChatType = String(cm.chat_type ?? "");
              if (incChatType && cChatType && (incChatType === "p2p") !== (cChatType === "p2p")) return false;
              return true;
            });

            const proven = textMatches.filter((c) => {
              const pwConv = isIncomingLark ? String(c.conv ?? "") : o.conv;
              const openConv = isIncomingLark ? o.conv : String(c.conv ?? "");
              const byPw = this.convAlias(pwConv);
              const byOpen = this.convAlias(openConv);
              // 已绑定且指向同一会话：直接通过
              if (byPw && byPw.open_conv === openConv) return true;
              // 任一端已绑定到别的会话：绝不串群合并
              if (byPw && byPw.open_conv !== openConv) return false;
              if (byOpen && byOpen.pw_conv !== pwConv) return false;
              // 群聊且两边都有非泛化群名且一致：可证明是同一个群
              const cName = String(c.conv_name ?? "");
              if (incChatType !== "p2p" && !ContextStore.isGenericConvName(cName) && !ContextStore.isGenericConvName(o.conv_name)) {
                return norm(cName) === norm(o.conv_name);
              }
              // 尚未建立别名（例如私聊或群名缺失）：仅在全局 ±15s 唯一命中且正文足够特异（≥12 归一字符）时允许匹配
              return textMatches.length === 1 && nt.length >= 12;
            });

            if (proven.length === 1) {
              const hit = proven[0];
              const pwConv = isIncomingLark ? String(hit.conv ?? "") : o.conv;
              const openConv = isIncomingLark ? o.conv : String(hit.conv ?? "");
              const bestName = pickBetterConv(String(hit.conv_name ?? ""), o.conv_name, isIncomingLark);
              if (this.linkConvAlias(pwConv, openConv, bestName)) {
                const hitMeta = j<Record<string, unknown>>(hit.meta, {});
                const wasBgOnly = hitMeta.background_only === true;
                const mergedMeta = mergeMeta(hitMeta, o, isIncomingLark, wasBgOnly);
                const bestActor = pickBetterActor(String(hit.actor_name ?? ""), o.actor_name, isIncomingLark);
                const bestUrl = String(hit.url ?? "") || o.url;
                const nextProcessed = wasBgOnly ? 0 : Number(hit.processed ?? 0);
                const nextKind = wasBgOnly ? o.kind : String(hit.kind ?? o.kind);
                updRow.run(nextKind, bestName, bestActor, String(hit.text ?? ""), bestUrl, JSON.stringify(mergedMeta), o.id, nextProcessed, String(hit.id));
                if (wasBgOnly) n++;
                continue;
              }
            }
          }
        }

        ins.run(o.id, o.source, o.kind, o.conv, o.conv_name, o.actor_id, o.actor_name, o.is_me ? 1 : 0, o.time, o.text, o.url, JSON.stringify(o.meta ?? {}), now);
        n++;
      }
    });
    return n;
  }

  /**
   * 写入历史背景观测（只插未出现过的记录，标记 processed = 1 且 meta.background_only = true）。
   * 后续若该消息经推送或轮询真实投递，addObs 会将其从背景态提升为 processed = 0 进入理解。
   */
  addBackgroundObs(list: Obs[]): number {
    const now = Date.now();
    const get = this.db.prepare("SELECT 1 FROM ctx_obs WHERE id = ? OR alt_id = ? LIMIT 1");
    const ins = this.db.prepare(
      `INSERT INTO ctx_obs (id, source, kind, conv, conv_name, actor_id, actor_name, is_me, time, text, url, meta, ingested, processed, alt_id)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, '')`,
    );
    let n = 0;
    this.tx(() => {
      for (const o of list) {
        if (!o.id || !o.time) continue;
        if (get.get(o.id, o.id)) continue;
        // 仅在同一已验证会话（含别名）内做背景去重，避免跨群误跳过
        const nt = norm(o.text);
        if (o.source === "im" && nt.length >= 2) {
          const keys = this.convGroup(o.conv);
          const q = `SELECT text FROM ctx_obs WHERE source = 'im' AND is_me = ? AND conv IN (${keys.map(() => "?").join(",")}) AND time BETWEEN ? AND ? LIMIT 30`;
          const cands = this.db.prepare(q).all(o.is_me ? 1 : 0, ...keys, o.time - 15_000, o.time + 15_000) as { text: string }[];
          if (cands.some((c) => norm(c.text) === nt)) continue;
        }
        const meta = { ...(o.meta ?? {}), background_only: true };
        ins.run(o.id, o.source, o.kind, o.conv, o.conv_name, o.actor_id, o.actor_name, o.is_me ? 1 : 0, o.time, o.text, o.url, JSON.stringify(meta), now);
        n++;
      }
    });
    return n;
  }

  obs(id: string): Obs | undefined {
    const r = this.db.prepare("SELECT * FROM ctx_obs WHERE id = ? OR alt_id = ? LIMIT 1").get(id, id) as Row | undefined;
    return r ? this.toObs(r) : undefined;
  }

  private toObs(r: Row): Obs {
    return { ...(r as unknown as Obs), is_me: !!r.is_me, meta: j(r.meta, {}) };
  }

  /** 待理解的会话（按最早未处理观测排序），已绑定别名的会话合并计数，排除静音会话 */
  pendingConvs(limit: number, sources: string[] = ["im", "minutes", "doc"]): { conv: string; conv_name: string; n: number }[] {
    const q = `SELECT conv, MAX(conv_name) AS conv_name, COUNT(*) AS n, MIN(time) AS t FROM ctx_obs
               WHERE processed = 0 AND source IN (${sources.map(() => "?").join(",")})
               GROUP BY conv ORDER BY t`;
    const rows = this.db.prepare(q).all(...sources) as { conv: string; conv_name: string; n: number; t: number }[];
    const merged = new Map<string, { conv: string; conv_name: string; n: number; t: number }>();
    for (const r of rows) {
      if (this.isConvMuted(r.conv, r.conv_name)) continue;
      const key = this.canonicalConv(r.conv);
      const cur = merged.get(key);
      if (!cur) {
        merged.set(key, { conv: key, conv_name: r.conv_name, n: r.n, t: r.t });
      } else {
        cur.n += r.n;
        cur.t = Math.min(cur.t, r.t);
        if (ContextStore.isGenericConvName(cur.conv_name) && !ContextStore.isGenericConvName(r.conv_name)) {
          cur.conv_name = r.conv_name;
        }
      }
    }
    return [...merged.values()]
      .sort((a, b) => a.t - b.t)
      .slice(0, limit)
      .map(({ conv, conv_name, n }) => ({ conv, conv_name, n }));
  }

  pendingCount(): number {
    return (this.db.prepare("SELECT COUNT(*) AS n FROM ctx_obs WHERE processed = 0 AND source IN ('im','minutes','doc')").get() as { n: number }).n;
  }

  /**
   * 理解窗口：这个会话（含别名）最早的一批待处理观测（按时间正序，最多 maxFresh 条）+ 它们之前的若干条已处理观测作为背景。
   * 从最早的待处理开始，保证大群 / 停机后积压的消息分几批都能处理到，不会因为只取最近 N 条而永远卡住。
   */
  convWindow(conv: string, maxFresh = 60, context = 12): Obs[] {
    const keys = this.convGroup(conv);
    const ph = keys.map(() => "?").join(",");
    const fresh = this.db.prepare(`SELECT * FROM ctx_obs WHERE conv IN (${ph}) AND processed = 0 ORDER BY time ASC, id ASC LIMIT ?`).all(...keys, maxFresh) as Row[];
    if (!fresh.length) return [];
    const t0 = Number(fresh[0].time);
    const before = this.db.prepare(`SELECT * FROM ctx_obs WHERE conv IN (${ph}) AND processed = 1 AND time <= ? ORDER BY time DESC, id DESC LIMIT ?`).all(...keys, t0, context) as Row[];
    return [...before.reverse(), ...fresh].map((r) => this.toObs(r));
  }

  /**
   * 快通道理解窗口：保证包含触发消息（targetObsId）及其后防抖期内的新消息（最多 maxFresh 条），
   * 并在其前附带最多 context 条历史背景；更早的积压消息仍保持 processed = 0 留给常规周期消化。
   */
  convWindowAround(conv: string, targetObsId: string, maxFresh = 60, context = 12): Obs[] {
    const keys = this.convGroup(conv);
    const ph = keys.map(() => "?").join(",");
    const target = this.db.prepare("SELECT * FROM ctx_obs WHERE (id = ? OR alt_id = ?) AND processed = 0 LIMIT 1").get(targetObsId, targetObsId) as Row | undefined;
    if (!target) return this.convWindow(conv, maxFresh, context);
    const targetTime = Number(target.time);
    const after = this.db
      .prepare(`SELECT * FROM ctx_obs WHERE conv IN (${ph}) AND processed = 0 AND time >= ? ORDER BY time ASC, id ASC LIMIT ?`)
      .all(...keys, targetTime, maxFresh) as Row[];
    const hasTarget = after.some((r) => String(r.id) === String(target.id));
    let fresh = hasTarget ? after : [target, ...after.slice(0, Math.max(0, maxFresh - 1))];
    const rem = maxFresh - fresh.length;
    if (rem > 0) {
      const seen = new Set(fresh.map((r) => String(r.id)));
      const earlierPending = this.db
        .prepare(`SELECT * FROM ctx_obs WHERE conv IN (${ph}) AND processed = 0 AND time <= ? ORDER BY time DESC, id DESC LIMIT ?`)
        .all(...keys, targetTime, rem + seen.size) as Row[];
      const extra = earlierPending.filter((r) => !seen.has(String(r.id))).slice(0, rem).reverse();
      fresh = [...extra, ...fresh];
    }
    fresh.sort((a, b) => Number(a.time) - Number(b.time) || String(a.id).localeCompare(String(b.id)));
    const freshIds = new Set(fresh.map((r) => String(r.id)));
    const t0 = Number(fresh[0].time);
    const before = (
      this.db
        .prepare(`SELECT * FROM ctx_obs WHERE conv IN (${ph}) AND time <= ? ORDER BY time DESC, id DESC LIMIT ?`)
        .all(...keys, t0, context + freshIds.size) as Row[]
    )
      .filter((r) => !freshIds.has(String(r.id)))
      .slice(0, context)
      .reverse();
    return [...before, ...fresh].map((r) => this.toObs(r));
  }

  convObs(conv: string, since: number, limit = 80): Obs[] {
    const keys = this.convGroup(conv);
    const ph = keys.map(() => "?").join(",");
    const rows = this.db.prepare(`SELECT * FROM ctx_obs WHERE conv IN (${ph}) AND time >= ? ORDER BY time DESC LIMIT ?`).all(...keys, since, limit) as Row[];
    return rows.map((r) => this.toObs(r)).reverse();
  }

  markProcessed(ids: string[]): void {
    const get = this.db.prepare("SELECT meta FROM ctx_obs WHERE id = ?");
    const upd = this.db.prepare("UPDATE ctx_obs SET processed = 1, meta = ? WHERE id = ?");
    this.tx(() => {
      for (const id of ids) {
        const cur = get.get(id) as { meta: string } | undefined;
        if (!cur) continue;
        const m = j<Record<string, unknown>>(cur.meta, {});
        if (m.background_only) delete m.background_only;
        upd.run(JSON.stringify(m), id);
      }
    });
  }

  muteConv(conv: string, name: string, muted: boolean): void {
    const keys = this.convGroup(conv);
    const now = Date.now();
    this.tx(() => {
      if (muted) {
        for (const k of keys) {
          this.db.prepare("INSERT OR REPLACE INTO ctx_mute_conv (conv, name, at) VALUES (?, ?, ?)").run(k, name, now);
          this.db.prepare("UPDATE ctx_obs SET processed = 1 WHERE conv = ?").run(k);
        }
      } else {
        for (const k of keys) this.db.prepare("DELETE FROM ctx_mute_conv WHERE conv = ?").run(k);
      }
    });
  }

  isConvMuted(conv: string, chatName = ""): boolean {
    const keys = new Set(this.convGroup(conv));
    for (const m of this.mutedConvs()) {
      if (keys.has(m.conv)) return true;
      if (chatName && !ContextStore.isGenericConvName(chatName) && m.name && norm(m.name) === norm(chatName)) return true;
    }
    return false;
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
      .prepare("INSERT OR IGNORE INTO ctx_evidence (entity, entity_id, obs_id, quote, time) VALUES (?, ?, ?, ?, ?)")
      .run(entity, entityId, obsId, quote.slice(0, 300), time);
  }

  evidence(entity: string, entityId: string, limit = 20): EvidenceRow[] {
    return this.db.prepare("SELECT * FROM ctx_evidence WHERE entity = ? AND entity_id = ? ORDER BY time DESC LIMIT ?").all(entity, entityId, limit) as unknown as EvidenceRow[];
  }

  /** 事项最近一次证据所在的会话（起草回复时用） */
  lastEvidenceObs(entity: string, entityId: string, filter?: (o: Obs) => boolean): Obs | undefined {
    for (const e of this.evidence(entity, entityId, 50)) {
      const o = this.obs(e.obs_id);
      if (o && (!filter || filter(o))) return o;
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
    const byRef = c.ref ? this.conflicts("open").find((x) => x.id === c.ref) : undefined;
    const open = byRef ?? this.conflicts("open").find((x) => sameConflict(x, c));
    if (open) {
      const claims = [...open.claims];
      for (const cl of c.claims) if (!claims.some((x) => x.obs_id === cl.obs_id)) claims.push(cl);
      this.db.prepare("UPDATE ctx_conflict SET claims = ? WHERE id = ?").run(JSON.stringify(claims), open.id);
      return { ...open, claims };
    }
    const id = newId("cfl");
    this.db.prepare("INSERT INTO ctx_conflict (id, project_id, topic, claims, status, created) VALUES (?, ?, ?, ?, 'open', ?)").run(id, c.project_id, c.topic, JSON.stringify(c.claims), Date.now());
    return { id, ...c, status: "open", resolution: "", created: Date.now() };
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
        for (const cl of dup.claims) if (!keep.claims.some((x) => x.obs_id === cl.obs_id && x.claim === cl.claim)) keep.claims.push(cl);
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

  addDraft(d: Omit<DraftRow, "id" | "created" | "updated" | "status" | "error">): DraftRow {
    const now = Date.now();
    // 同一事项同一类型只保留一份待确认草稿
    const old = this.db.prepare("SELECT id FROM ctx_draft WHERE item_id = ? AND kind = ? AND status = 'proposed'").get(d.item_id, d.kind) as { id: string } | undefined;
    if (old && d.item_id) {
      this.db.prepare("UPDATE ctx_draft SET content = ?, target = ?, target_label = ?, updated = ? WHERE id = ?").run(d.content, JSON.stringify(d.target), d.target_label, now, old.id);
      return this.draft(old.id)!;
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

  /** 某会话（含别名）所有待处理观测标为已处理（理解反复失败时跳过） */
  skipConv(conv: string): number {
    const keys = this.convGroup(conv);
    const ph = keys.map(() => "?").join(",");
    return Number(this.db.prepare(`UPDATE ctx_obs SET processed = 1 WHERE conv IN (${ph}) AND processed = 0`).run(...keys).changes);
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
