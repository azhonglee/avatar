import path from "node:path";
import { z } from "zod";
import type { App } from "../app.ts";
import type { CtxItemKind, CtxPriority } from "../api/types.ts";
import { loadPrompt, runHarness } from "../harness.ts";
import { errMsg, log, render, truncate } from "../util.ts";
import type { ContextStore, ItemRow, KnowledgeRow, Obs, ProjectRow } from "./store.ts";

/**
 * 理解层：把待处理的会话观测交给模型，得到结构化的图谱更新（项目 / 事项 / 知识 / 动态 / 人 / 冲突），
 * 校验证据后写入。模型没有任何工具和写权限，只输出 JSON。
 */

const DAY = 86_400_000;
const Ev = z.object({ obs_id: z.string(), quote: z.string().default("") });
const lowerEnum = <T extends [string, ...string[]]>(vals: T, d: T[number]) =>
  z.preprocess((v) => (typeof v === "string" ? v.trim().toLowerCase() : v), z.enum(vals).catch(d));

export const UnderstandOut = z.object({
  projects: z
    .array(
      z.object({
        ref: z.string().default(""),
        name: z.string(),
        aliases: z.array(z.string()).default([]),
        refs: z.array(z.string()).default([]),
        description: z.string().default(""),
        my_role: z.string().default(""),
        stage: z.string().default(""),
        health: lowerEnum(["ok", "risk", "blocked", "unknown"], "unknown"),
      }),
    )
    .default([]),
  items: z
    .array(
      z.object({
        ref: z.string().default(""),
        title: z.string(),
        kind: lowerEnum(["todo", "ask_me", "my_commitment", "waiting_on", "meeting_action", "risk"], "todo"),
        project: z.string().default(""),
        status: lowerEnum(["open", "done"], "open"),
        priority: lowerEnum(["high", "medium", "low"], "medium"),
        due: z.string().nullable().default(null),
        counterpart: z.string().default(""),
        next_step: z.string().default(""),
        confidence: z.number().min(0).max(1).catch(0.6).default(0.6),
        close_reason: z.string().default(""),
        evidence: z.array(Ev).default([]),
      }),
    )
    .default([]),
  knowledge: z
    .array(
      z.object({
        project: z.string().default(""),
        kind: lowerEnum(["decision", "conclusion", "doc", "howto", "fact"], "fact"),
        title: z.string(),
        content: z.string().default(""),
        confidence: z.number().min(0).max(1).catch(0.6).default(0.6),
        evidence: z.array(Ev).default([]),
      }),
    )
    .default([]),
  updates: z.array(z.object({ project: z.string().default(""), time: z.string().default(""), summary: z.string(), evidence: z.array(Ev).default([]) })).default([]),
  people: z.array(z.object({ name: z.string(), open_id: z.string().default(""), relation: z.string().default(""), projects: z.array(z.string()).default([]) })).default([]),
  conflicts: z
    .array(z.object({ project: z.string().default(""), topic: z.string(), claims: z.array(z.object({ claim: z.string(), obs_id: z.string().default(""), quote: z.string().default("") })).default([]) }))
    .default([]),
});
export type UnderstandOut = z.infer<typeof UnderstandOut>;

/** 从模型回复里取 JSON 对象（容忍代码块和前后文字） */
export function parseUnderstand(text: string): UnderstandOut {
  const blocks = [...text.matchAll(/```(?:json)?\s*([\s\S]*?)```/g)].map((m) => m[1]).reverse();
  const first = text.indexOf("{");
  const last = text.lastIndexOf("}");
  if (first >= 0 && last > first) blocks.push(text.slice(first, last + 1));
  for (const b of blocks) {
    try {
      return UnderstandOut.parse(JSON.parse(b));
    } catch {
      // 试下一个
    }
  }
  throw new Error(`理解结果不是合法的 JSON：${truncate(text, 300)}`);
}

export interface ApplyResult {
  projects: number;
  created: ItemRow[];
  closed: ItemRow[];
  updated: number;
  knowledge: number;
  updates: number;
  people: number;
  conflicts: number;
  rejected: number;
}

const fmt = (ms: number, tz: string) =>
  new Intl.DateTimeFormat("zh-CN", { timeZone: tz, month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false }).format(new Date(ms));

export class Understander {
  app: App;
  store: ContextStore;
  constructor(app: App, store: ContextStore) {
    this.app = app;
    this.store = store;
  }

  private get cfg() {
    return this.app.cfg;
  }

  /** 组装一批会话（控制总长度），返回提示词和这批涉及的观测 */
  buildBatch(convs: { conv: string; conv_name: string }[], maxChars = 24_000): { prompt: string; obs: Obs[]; fresh: string[]; convs: string[] } {
    const tz = this.cfg.owner.timezone;
    const since = Date.now() - this.cfg.context.lookback_days * DAY;
    const sections: string[] = [];
    const all: Obs[] = [];
    const fresh: string[] = [];
    const used: string[] = [];
    let size = 0;
    for (const c of convs) {
      const list = this.store.convObs(c.conv, since, 80);
      if (!list.length) continue;
      const lines = list.map((o) => {
        const isNew = !this.isProcessed(o.id);
        return `[${o.id}] ${fmt(o.time, tz)} ${o.is_me ? "【我】" : o.actor_name || o.actor_id}: ${truncate(o.text, 500)}${isNew ? " (新)" : ""}`;
      });
      const block = `<conv id="${c.conv}" name="${(c.conv_name || list[0].conv_name).replace(/"/g, "'")}">\n${lines.join("\n")}\n</conv>`;
      if (size && size + block.length > maxChars) break;
      size += block.length;
      sections.push(block);
      used.push(c.conv);
      for (const o of list) {
        all.push(o);
        if (!this.isProcessed(o.id)) fresh.push(o.id);
      }
    }
    const actors = new Set(all.map((o) => o.actor_name).filter(Boolean));
    const related = this.relatedItems(new Set(used), actors);
    const projects = this.store.projects({ includeLegacy: true }).filter((p) => !p.name.startsWith("Meego · ") && p.name !== "飞书任务" && p.name !== "飞书任务（历史）");
    const prompt = render(loadPrompt("context-understand.md"), {
      owner_name: this.app.store.get("ctx.owner_name") ?? "主人",
      now: new Date().toLocaleString("zh-CN", { timeZone: tz }),
      timezone: tz,
      projects: projects.length ? projects.map((p) => projectLine(p)).join("\n") : "（暂无，按需新建）",
      meego: this.unlinkedMeego() || "（无）",
      items: related.length ? related.map((i) => itemLine(i, this.store)).join("\n") : "（无）",
      feedback: this.feedbackText() || "（暂无）",
      conversations: sections.join("\n\n"),
    });
    return { prompt, obs: all, fresh, convs: used };
  }

  private processedCache = new Map<string, boolean>();
  private isProcessed(id: string): boolean {
    if (!this.processedCache.has(id)) {
      const r = this.store.db.prepare("SELECT processed FROM ctx_obs WHERE id = ?").get(id) as { processed: number } | undefined;
      this.processedCache.set(id, !!r?.processed);
    }
    return this.processedCache.get(id)!;
  }

  /** 和这些会话 / 人有关的未关闭事项 */
  private relatedItems(convs: Set<string>, actors: Set<string>): ItemRow[] {
    const open = this.store.items({ status: ["open", "snoozed"], limit: 2000 }).filter((i) => i.source !== "meego" && i.source !== "task");
    const scored = open
      .map((it) => {
        let s = 0;
        for (const e of this.store.evidence("item", it.id, 10)) {
          const o = this.store.obs(e.obs_id);
          if (o && convs.has(o.conv)) s += 3;
        }
        if (it.counterpart && [...actors].some((a) => it.counterpart.includes(a))) s += 1;
        return { it, s };
      })
      .filter((x) => x.s > 0)
      .sort((a, b) => b.s - a.s);
    return scored.slice(0, 40).map((x) => x.it);
  }

  private unlinkedMeego(): string {
    const items = this.store.items({ status: ["open"], source: "meego", limit: 500 }).filter((i) => !i.meta.legacy);
    const byId = new Map<string, string>();
    for (const it of items) {
      const id = String(it.meta.work_item_id ?? "");
      const p = this.store.project(it.project_id);
      if (id && p?.name.startsWith("Meego · ")) byId.set(id, it.title.split("｜")[0]);
    }
    return [...byId.entries()].slice(0, 60).map(([id, t]) => `- meego:${id} ${t}`).join("\n");
  }

  private feedbackText(): string {
    return this.store
      .recentFeedback(10)
      .filter((f) => f.verdict !== "right")
      .map((f) => `- ${f.verdict === "wrong" ? "识别错了" : "不重要"}：${truncate(f.snapshot, 120)}${f.note ? `（他说：${truncate(f.note, 80)}）` : ""}`)
      .join("\n");
  }

  /** 跑一批：调用模型 → 解析 → 写入 */
  async runBatch(workId: string, convs: { conv: string; conv_name: string }[], signal?: AbortSignal): Promise<ApplyResult & { convs: string[] }> {
    this.processedCache.clear();
    const batch = this.buildBatch(convs);
    if (!batch.fresh.length) {
      return { ...emptyResult(), convs: batch.convs };
    }
    const harness = this.cfg.context.harness || this.cfg.roles.brain;
    const logFile = path.join(this.cfg.dataDir, "runs", `context-${Date.now()}.log`);
    const step = this.app.ledger.startStep({ work_id: workId, name: "understand", harness, log: logFile });
    try {
      const r = await runHarness(this.cfg, {
        harness,
        prompt: batch.prompt,
        cwd: path.join(this.cfg.dataDir, "workspace", "context"),
        tools: "none",
        lark: "none",
        timeoutSec: 900,
        logFile,
        signal,
        onSpawn: (pid) => this.app.ledger.setStepPid(step, pid),
        stepId: step,
      });
      if (!r.text) throw new Error(`理解 harness 无输出（exit ${r.exitCode}${r.timedOut ? "，超时" : ""}）`);
      const out = parseUnderstand(r.text);
      const res = this.apply(out, batch.obs, batch.fresh);
      this.app.ledger.endStep(step, "ok", `新事项 ${res.created.length}，关闭 ${res.closed.length}，知识 ${res.knowledge}`);
      return { ...res, convs: batch.convs };
    } catch (e) {
      this.app.ledger.endStep(step, "failed", errMsg(e));
      throw e;
    }
  }

  /** 写入模型结果。证据必须指向这批里真实存在的观测，否则丢弃（防幻觉）。 */
  apply(out: UnderstandOut, obs: Obs[], fresh: string[]): ApplyResult {
    const res = emptyResult();
    const byId = new Map(obs.map((o) => [o.id, o]));
    const auto = this.cfg.context.autonomy;
    const minConf = this.cfg.context.min_confidence;
    const validEv = (evs: { obs_id: string; quote: string }[]) => evs.filter((e) => byId.has(e.obs_id));
    const latestTime = (evs: { obs_id: string }[]) => Math.max(0, ...evs.map((e) => byId.get(e.obs_id)?.time ?? 0)) || Date.now();
    const batchProjects = new Map<string, ProjectRow>();

    const resolveProject = (key: string, at: number): ProjectRow | undefined => {
      if (!key) return undefined;
      return batchProjects.get(key) ?? this.store.findProject(key) ?? undefined;
    };

    this.store.tx(() => {
      for (const p of out.projects) {
        if (!p.name.trim()) continue;
        const row = this.store.upsertProject(
          { id: p.ref && this.store.project(p.ref) ? p.ref : undefined, name: p.name.trim(), aliases: p.aliases, refs: p.refs.map((r) => r.trim()).filter(Boolean), description: p.description, my_role: p.my_role, stage: p.stage, health: p.health as ProjectRow["health"] },
          Date.now(),
        );
        batchProjects.set(p.name, row);
        if (p.ref) batchProjects.set(p.ref, row);
        res.projects++;
      }

      for (const it of out.items) {
        const evs = validEv(it.evidence);
        if (!evs.length) {
          res.rejected++;
          continue;
        }
        const at = latestTime(evs);
        let project = resolveProject(it.project, at);
        if (!project && it.project.trim()) {
          project = this.store.upsertProject({ name: it.project.trim() }, at);
          batchProjects.set(it.project, project);
        }
        const existing = it.ref ? this.store.item(it.ref) : undefined;
        const due = it.due ? Date.parse(it.due) : NaN;
        const wantDone = it.status === "done";
        const status = wantDone ? (auto.auto_close ? "done" : existing?.status ?? "open") : "open";
        const { item, created } = this.store.upsertItem(
          {
            id: existing?.id,
            title: it.title.trim(),
            kind: it.kind as CtxItemKind,
            project_id: project?.id ?? existing?.project_id ?? "",
            status,
            priority: it.priority as CtxPriority,
            due: Number.isNaN(due) ? (existing?.due ?? null) : due,
            counterpart: it.counterpart,
            next_step: it.next_step,
            confidence: it.confidence,
            source: byId.get(evs[0].obs_id)?.source ?? "im",
            close_reason: wantDone ? it.close_reason || "消息显示已完成" : "",
            meta: { needs_review: it.confidence < minConf, ...(wantDone && !auto.auto_close ? { suggest_close: it.close_reason || "消息显示已完成" } : {}) },
          },
          at,
        );
        for (const e of evs) this.store.addEvidence("item", item.id, e.obs_id, e.quote, byId.get(e.obs_id)!.time);
        if (created && item.status === "open") res.created.push(item);
        else if (wantDone && item.status === "done" && existing?.status !== "done") res.closed.push(item);
        else res.updated++;
      }

      for (const k of out.knowledge) {
        const evs = validEv(k.evidence);
        if (!evs.length || !k.title.trim()) {
          res.rejected++;
          continue;
        }
        const project = resolveProject(k.project, latestTime(evs));
        const row = this.store.upsertKnowledge({ project_id: project?.id ?? "", kind: k.kind as KnowledgeRow["kind"], title: k.title.trim(), content: k.content, confidence: k.confidence });
        for (const e of evs) this.store.addEvidence("knowledge", row.id, e.obs_id, e.quote, byId.get(e.obs_id)!.time);
        res.knowledge++;
      }

      for (const u of out.updates) {
        const evs = validEv(u.evidence);
        if (!evs.length) {
          res.rejected++;
          continue;
        }
        const t = Date.parse(u.time);
        const time = Number.isNaN(t) ? latestTime(evs) : t;
        const project = resolveProject(u.project, time);
        const row = this.store.addUpdate({ project_id: project?.id ?? "", time, summary: u.summary });
        if (row) {
          for (const e of evs) this.store.addEvidence("update", row.id, e.obs_id, e.quote, byId.get(e.obs_id)!.time);
          res.updates++;
        }
      }

      for (const p of out.people) {
        if (!p.name.trim() || p.name.includes("【我】")) continue;
        const projects = p.projects.map((n) => resolveProject(n, Date.now())?.id).filter((x): x is string => !!x);
        const fromObs = obs.find((o) => o.actor_name === p.name && o.actor_id.startsWith("ou_"));
        this.store.upsertPerson({ id: p.open_id || fromObs?.actor_id || undefined, name: p.name.trim(), relation: p.relation, projects });
        res.people++;
      }

      for (const c of out.conflicts) {
        const claims = c.claims.filter((cl) => byId.has(cl.obs_id)).map((cl) => ({ claim: cl.claim, obs_id: cl.obs_id, quote: cl.quote, time: byId.get(cl.obs_id)!.time }));
        if (claims.length < 2) continue;
        const project = resolveProject(c.project, Date.now());
        this.store.addConflict({ project_id: project?.id ?? "", topic: c.topic, claims });
        res.conflicts++;
      }
    });
    this.store.markProcessed(fresh);
    // 把 Meego 待办挂到具体项目
    return res;
  }
}

function emptyResult(): ApplyResult {
  return { projects: 0, created: [], closed: [], updated: 0, knowledge: 0, updates: 0, people: 0, conflicts: 0, rejected: 0 };
}

function projectLine(p: ProjectRow): string {
  return `- [${p.id}] ${p.name}${p.aliases.length ? `（别名：${p.aliases.slice(0, 4).join("、")}）` : ""}${p.refs.length ? ` refs:${p.refs.slice(0, 6).join(",")}` : ""}｜${p.status === "legacy" ? "历史遗留｜" : ""}${p.stage || "阶段未知"}`;
}

function itemLine(i: ItemRow, store: ContextStore): string {
  const p = store.project(i.project_id);
  return `- [${i.id}] ${i.kind}｜${i.title}｜项目:${p?.name ?? "-"}｜对方:${i.counterpart || "-"}｜${i.status}`;
}

export { log };
