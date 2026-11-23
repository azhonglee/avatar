import fs from "node:fs";
import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { z } from "zod";
import type { App } from "./app.ts";
import type { CandidateList, CandidateView } from "./api/types.ts";
import { taskUrl } from "./api/queries.ts";
import { CommandError } from "./commands.ts";
import { comment, move } from "./effects.ts";
import type { Effect } from "./ledger.ts";
import { expandHome, log, truncate } from "./util.ts";
import { setTriageExamples } from "./workflows/triage.ts";

/**
 * 候选任务（分诊结果）与反馈：
 *   - 列出最近被建成任务 / 被忽略的信号，统计准确率（确认 /（确认 + 驳回））；
 *   - 命令：确认（移到 Inbox）、驳回（评论 + 完成任务）、直接派单（移到“派给Agent”）；
 *   - 学习闭环：最近的确认 / 驳回样例填进分诊提示词的“历史判断校准”。
 *
 * 反馈记在 signals 表上（本模块迁移添加）：
 *   feedback        "" | "confirmed" | "rejected"
 *   feedback_at     反馈时间（毫秒）
 *   feedback_reason 驳回理由
 *   summary/section 建卡时的任务标题与所在列（来自 candidate.created 事件；旧数据为空，按置信度推断）
 */

const DAY = 86_400_000;
type Feedback = "" | "confirmed" | "rejected";

interface SignalRow {
  id: string;
  source: string;
  at: number;
  text: string;
  link: string;
  verdict: string;
  task_guid: string;
  feedback: Feedback;
  feedback_at: number | null;
  feedback_reason: string | null;
  summary: string;
  section: string;
}

/** 迁移：给 signals 表补反馈相关的列。可重复执行。 */
export function migrateSignals(db: DatabaseSync): void {
  const cols = new Set((db.prepare("PRAGMA table_info(signals)").all() as { name: string }[]).map((c) => c.name));
  for (const [col, def] of [
    ["feedback", "TEXT NOT NULL DEFAULT ''"],
    ["feedback_at", "INTEGER"],
    ["feedback_reason", "TEXT"],
    ["summary", "TEXT NOT NULL DEFAULT ''"],
    ["section", "TEXT NOT NULL DEFAULT ''"],
  ] as const) {
    if (!cols.has(col)) db.exec(`ALTER TABLE signals ADD COLUMN ${col} ${def}`);
  }
}

/** 从分诊结论里取置信度：task(0.8) / ignored(0.3) 理由；ignored(无结论) 为 null。 */
export function parseConfidence(verdict: string): number | null {
  const m = verdict.match(/^(?:task|ignored)\((\d*\.?\d+)\)/);
  return m ? Number(m[1]) : null;
}

type Deps = Pick<App, "cfg" | "store" | "ledger" | "board" | "dispatcher">;

function getSignal(d: Pick<Deps, "store">, id: string): SignalRow | undefined {
  return d.store.db.prepare("SELECT * FROM signals WHERE id = ?").get(id) as unknown as SignalRow | undefined;
}

/** 候选任务所在的列：有记录用记录，否则按置信度与当前配置推断。 */
function sectionOf(d: Pick<Deps, "cfg">, r: SignalRow): string {
  if (r.section) return r.section;
  const c = parseConfidence(r.verdict);
  return c !== null && c >= d.cfg.capture.auto_inbox_confidence ? "inbox" : "pending";
}

function view(app: Pick<App, "cfg">, r: SignalRow): CandidateView {
  return {
    signal_id: r.id,
    source: r.source,
    text: r.text,
    link: r.link,
    at: r.at,
    verdict: r.verdict,
    task_guid: r.task_guid,
    task_url: taskUrl(app as App, r.task_guid),
    summary: r.summary || truncate(r.text.replace(/\s+/g, " ").trim(), 60),
    confidence: parseConfidence(r.verdict),
    feedback: (r.feedback ?? "") as Feedback,
  };
}

export function listCandidates(app: Pick<App, "cfg" | "store">, o: { days: number; feedback?: Feedback | "all" }, now = Date.now()): CandidateList {
  const days = Math.min(Math.max(Math.floor(o.days) || 1, 1), 90);
  const since = now - days * DAY;
  const where = ["at >= ?", "verdict != ''"];
  const args: (string | number)[] = [since];
  const f = o.feedback ?? "all";
  if (f === "") where.push("task_guid != '' AND feedback = ''");
  else if (f !== "all") {
    where.push("feedback = ?");
    args.push(f);
  }
  const rows = app.store.db.prepare(`SELECT * FROM signals WHERE ${where.join(" AND ")} ORDER BY at DESC LIMIT 200`).all(...args) as unknown as SignalRow[];
  const s = app.store.db
    .prepare(
      `SELECT COALESCE(SUM(task_guid != ''), 0) AS created, COALESCE(SUM(feedback = 'confirmed'), 0) AS confirmed,
              COALESCE(SUM(feedback = 'rejected'), 0) AS rejected FROM signals WHERE at >= ?`,
    )
    .get(since) as { created: number; confirmed: number; rejected: number };
  const judged = s.confirmed + s.rejected;
  return {
    items: rows.map((r) => view(app, r)),
    stats: { window_days: days, created: s.created, confirmed: s.confirmed, rejected: s.rejected, precision: judged ? s.confirmed / judged : null },
  };
}

/** 待你确认的候选任务：最近 14 天建在“待确认”列、还没有反馈的。 */
export function pendingCount(app: Pick<App, "cfg" | "store">, now = Date.now()): number {
  const rows = app.store.db
    .prepare("SELECT * FROM signals WHERE at >= ? AND task_guid != '' AND feedback = ''")
    .all(now - 14 * DAY) as unknown as SignalRow[];
  return rows.filter((r) => sectionOf(app, r) === "pending").length;
}

/** 分诊提示词里的校准样例：最近 8 条确认 / 驳回。 */
export function triageExamples(app: Pick<App, "store">, limit = 8): string {
  const rows = app.store.db
    .prepare("SELECT * FROM signals WHERE feedback IN ('confirmed', 'rejected') ORDER BY feedback_at DESC LIMIT ?")
    .all(limit) as unknown as SignalRow[];
  return rows
    .map((r) => {
      const c = parseConfidence(r.verdict);
      const judged = `当时判为任务${c !== null ? `（置信度 ${c}）` : ""}`;
      const text = truncate(r.text.replace(/\s+/g, " ").trim(), 160).replace(/\n/g, " ");
      const fb = r.feedback === "confirmed" ? "主人确认：是任务" : `主人驳回：不该建成任务${r.feedback_reason ? `（理由：${truncate(r.feedback_reason, 100).replace(/\n/g, " ")}）` : ""}`;
      return `- <example source="${r.source}">${text}</example> → ${judged}${r.summary ? `「${r.summary}」` : ""}；${fb}`;
    })
    .join("\n");
}

/** 记反馈（只在还没有反馈时成功：重复点击 / 卡片与控制台同时操作只有一次生效）。 */
function setFeedback(d: Pick<Deps, "store">, id: string, fb: Exclude<Feedback, "">, reason?: string): boolean {
  const r = d.store.db
    .prepare("UPDATE signals SET feedback = ?, feedback_at = ?, feedback_reason = ? WHERE id = ? AND feedback = ''")
    .run(fb, Date.now(), reason ?? null, id);
  return r.changes > 0;
}

function clearFeedback(d: Pick<Deps, "store">, id: string): void {
  d.store.db.prepare("UPDATE signals SET feedback = '', feedback_at = NULL, feedback_reason = NULL WHERE id = ?").run(id);
}

/** 命令的共同前置条件：信号存在、建成了任务、还没有反馈。 */
function candidate(d: Pick<Deps, "store">, id: string): SignalRow & { task_guid: string } {
  const r = getSignal(d, id);
  if (!r) throw new CommandError("not_found", `没有这条候选：${id}`);
  if (!r.task_guid) throw new CommandError("invalid", "这条信号没有建成任务，无法操作");
  if (r.feedback) throw new CommandError("conflict", `已经${r.feedback === "confirmed" ? "确认" : "驳回"}过了`);
  return r;
}

/** 先占住反馈（CAS），再执行；执行失败把反馈退回，可以再试。 */
async function withFeedback<T>(d: Pick<Deps, "store">, id: string, fb: Exclude<Feedback, "">, reason: string | undefined, fn: () => Promise<T> | T): Promise<T> {
  if (!setFeedback(d, id, fb, reason)) throw new CommandError("conflict", "已经处理过了");
  try {
    return await fn();
  } catch (e) {
    clearFeedback(d, id);
    throw e;
  }
}

/** 描述里写上 repo 行（已有则替换）。 */
export function withRepoLine(description: string, alias: string): string {
  const re = /^\s*repo\s*[:：].*$/im;
  if (re.test(description)) return description.replace(re, `repo: ${alias}`);
  return description.trim() ? `repo: ${alias}\n${description}` : `repo: ${alias}`;
}

export function registerCandidates(app: App): void {
  const { cfg, store, ledger, board, dispatcher, commands, bus } = app;
  migrateSignals(store.db);

  // 建卡时记下标题与列（列表展示、待确认计数用）
  bus.on("candidate.created", (e) => {
    store.db.prepare("UPDATE signals SET summary = ?, section = ? WHERE id = ?").run(e.summary, e.section, e.signalId);
  });

  app.ext.candidates = {
    list: (o) => listCandidates(app, o),
    pendingCount: () => pendingCount(app),
  };
  setTriageExamples(() => triageExamples(app));

  const signalId = z.string().min(1);
  const emit = (id: string, action: string, effects: Effect[]) => ledger.emit(`candidate:${id}`, effects, `candidate-${action}-${id}`);

  commands.register({
    name: "candidate.confirm",
    title: "确认候选任务（移到 Inbox）",
    schema: z.object({ signal_id: signalId }),
    target: (a) => a.signal_id,
    run: async (a) => {
      const c = candidate(app, a.signal_id);
      await withFeedback(app, c.id, "confirmed", undefined, () => emit(c.id, "confirm", [move(c.task_guid, "inbox")]));
      return { ok: true, message: "已确认，任务移到 Inbox", target: a.signal_id };
    },
  });

  commands.register({
    name: "candidate.reject",
    title: "驳回候选任务（完成并注明理由）",
    schema: z.object({ signal_id: signalId, reason: z.string().trim().max(500).optional() }),
    target: (a) => a.signal_id,
    run: async (a) => {
      const c = candidate(app, a.signal_id);
      const reason = a.reason || "";
      await withFeedback(app, c.id, "rejected", reason || undefined, () =>
        emit(c.id, "reject", [comment(c.task_guid, `已驳回：${reason || "不是需要我做的事"}`), { op: "task.complete", args: { guid: c.task_guid } }]),
      );
      return { ok: true, message: "已驳回，之后的分诊会参考这次判断", target: a.signal_id };
    },
  });

  commands.register({
    name: "candidate.dispatch",
    title: "候选任务直接派给 Agent",
    schema: z.object({
      signal_id: signalId,
      harness: z
        .string()
        .refine((h) => !!cfg.harnesses[h], { message: "未定义的执行者" })
        .optional(),
      repo: z
        .string()
        .refine((r) => !!cfg.dispatch.repos[r] || fs.existsSync(path.resolve(expandHome(r))), { message: "未配置的仓库别名，且路径不存在" })
        .optional(),
    }),
    target: (a) => a.signal_id,
    run: async (a) => {
      const c = candidate(app, a.signal_id);
      const last = ledger.latest("dispatch", c.task_guid);
      if (last && !last.terminal) throw new CommandError("conflict", "这张卡片已有进行中的派单");
      const id = await withFeedback(app, c.id, "confirmed", undefined, async () => {
        if (a.repo) {
          // 派单准备阶段会重新读取卡片描述，从中解析 repo 行
          const t = await board.getTask(c.task_guid);
          await board.updateDescription(c.task_guid, withRepoLine(t.description, a.repo));
        }
        try {
          return dispatcher.redispatch(c.task_guid, { reason: "从候选任务派单", harness: a.harness });
        } catch (e) {
          throw new CommandError("conflict", String(e instanceof Error ? e.message : e));
        }
      });
      log("info", "候选任务直接派单", { signal: c.id, task: c.task_guid, harness: a.harness, repo: a.repo });
      return { ok: true, message: "已派给 Agent，进度会实时更新", target: id };
    },
  });
}
