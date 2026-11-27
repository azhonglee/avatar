import type { App } from "../app.ts";
import type {
  CtxConflictView,
  CtxDraftView,
  CtxEvidenceView,
  CtxItemDetail,
  CtxItemView,
  CtxKnowledgeView,
  CtxMeeting,
  CtxPersonView,
  CtxPersonalWebStatus,
  CtxProjectDetail,
  CtxProjectSummary,
  CtxStatus,
  CtxToday,
  CtxUpdateView,
} from "../api/types.ts";
import { defaultDraftKind } from "./drafts.ts";
import { hasWorkspaceOwnerMismatch } from "./personal-web.ts";
import type { ContextStore, DraftRow, ItemRow, ProjectRow } from "./store.ts";

/**
 * 排序与视图：确定性规则给事项打分（并说明原因），组装今天页、项目页等视图。
 * 规则可解释：每个分数都带 why，界面上直接展示。
 */

const DAY = 86_400_000;
const HOUR = 3_600_000;

const KIND_BASE: Record<string, number> = { ask_me: 30, my_commitment: 25, risk: 25, meeting_action: 15, todo: 15, waiting_on: 8 };
const KIND_TEXT: Record<string, string> = { ask_me: "别人在等你", my_commitment: "你答应过", risk: "风险", meeting_action: "会议行动项", todo: "待办", waiting_on: "你在等别人" };

export function startOfDay(tz: string, now = Date.now()): number {
  const parts = new Intl.DateTimeFormat("en-US", { timeZone: tz, hour: "numeric", minute: "numeric", second: "numeric", hourCycle: "h23" })
    .formatToParts(new Date(now))
    .reduce<Record<string, number>>((a, p) => (p.type === "literal" ? a : { ...a, [p.type]: Number(p.value) }), {});
  return now - ((parts.hour * 60 + parts.minute) * 60 + parts.second) * 1000 - (now % 1000);
}

/** 事项打分（越高越该先处理）及原因 */
export function scoreItem(it: ItemRow, project: ProjectRow | undefined, tz: string, now = Date.now()): { score: number; why: string[] } {
  const why: string[] = [];
  let s = KIND_BASE[it.kind] ?? 10;
  why.push(KIND_TEXT[it.kind] ?? it.kind);
  if (it.priority === "high") {
    s += 30;
    why.push("高优先级");
  } else if (it.priority === "medium") s += 10;
  if (it.due) {
    const eod = startOfDay(tz, now) + DAY;
    if (it.due < now) {
      s += 40;
      why.push("已逾期");
    } else if (it.due < eod) {
      s += 35;
      why.push("今天到期");
    } else if (it.due < eod + DAY) {
      s += 25;
      why.push("明天到期");
    } else if (it.due < now + 3 * DAY) {
      s += 15;
      why.push("3 天内到期");
    }
  }
  const age = now - it.first_seen;
  if ((it.kind === "ask_me" || it.kind === "my_commitment") && age > DAY) {
    s += Math.min(20, Math.floor(age / DAY) * 8);
    why.push(`已过 ${Math.floor(age / DAY)} 天`);
  }
  if (it.kind === "waiting_on" && age > 2 * DAY) {
    s += 10;
    why.push("等了超过 2 天，可以催一下");
  }
  if (it.meta.needs_review) {
    s -= 15;
    why.push("识别把握不大");
  }
  if (it.feedback === "unimportant") {
    s -= 40;
    why.push(it.meta.auto_unimportant ? "你设为不重要的类型" : "你标记为不重要");
  }
  if (project && (project.muted || project.status !== "active")) s -= 100;
  if (it.meta.legacy) s -= 100;
  return { score: s, why };
}

export class ContextViews {
  app: App;
  store: ContextStore;
  constructor(app: App, store: ContextStore) {
    this.app = app;
    this.store = store;
  }
  private get tz() {
    return this.app.cfg.owner.timezone;
  }

  private projectCache = new Map<string, ProjectRow | undefined>();
  private proj(id: string): ProjectRow | undefined {
    if (!this.projectCache.has(id)) this.projectCache.set(id, this.store.project(id));
    return this.projectCache.get(id);
  }

  evidence(entity: string, id: string, limit = 10): CtxEvidenceView[] {
    return this.store.evidence(entity, id, limit).map((e) => {
      const o = this.store.obs(e.obs_id);
      return {
        obs_id: e.obs_id,
        source: o?.source ?? "im",
        quote: e.quote || o?.text.slice(0, 120) || "",
        time: e.time || o?.time || 0,
        conv_name: o?.conv_name ?? "",
        actor_name: o?.is_me ? "我" : (o?.actor_name ?? ""),
        is_me: !!o?.is_me,
        url: o?.url ?? "",
      };
    });
  }

  itemView(it: ItemRow, now = Date.now()): CtxItemView {
    const p = this.proj(it.project_id);
    const { score, why } = scoreItem(it, p, this.tz, now);
    return {
      id: it.id,
      title: it.title,
      kind: it.kind,
      status: it.status,
      priority: it.priority,
      project_id: it.project_id,
      project_name: p?.name ?? "",
      due: it.due,
      counterpart: it.counterpart,
      next_step: it.next_step,
      confidence: it.confidence,
      source: it.source,
      strong_key: it.strong_key,
      first_seen: it.first_seen,
      last_seen: it.last_seen,
      closed_at: it.closed_at,
      close_reason: it.close_reason,
      snooze_until: it.snooze_until,
      score,
      why,
      needs_review: !!it.meta.needs_review,
      feedback: it.feedback,
      url: String(it.meta.url ?? "") || this.store.lastEvidenceObs("item", it.id)?.url || "",
      draft_kind: it.status === "open" ? (defaultDraftKind(it) ?? "") : "",
    };
  }

  /** 当前可见（项目未静音、非历史遗留）的未关闭事项，按分数排序 */
  openItems(now = Date.now()): CtxItemView[] {
    this.projectCache.clear();
    return this.store
      .items({ status: ["open"], limit: 3000 })
      .filter((it) => {
        const p = this.proj(it.project_id);
        return !it.meta.legacy && !this.store.hidden(p) && it.feedback !== "wrong";
      })
      .map((it) => this.itemView(it, now))
      .sort((a, b) => b.score - a.score);
  }

  draftView(d: DraftRow): CtxDraftView {
    return { id: d.id, item_id: d.item_id, project_id: d.project_id, kind: d.kind, target_label: d.target_label, content: d.content, status: d.status, error: d.error, created: d.created, updated: d.updated, url: d.target.url ?? "" };
  }

  conflictView(c: ReturnType<ContextStore["conflicts"]>[number]): CtxConflictView {
    const claims: CtxConflictView["claims"] = [];
    for (let i = 0; i < c.claims.length; i++) {
      const cl = c.claims[i];
      const obs = cl.obs_id ? this.store.obs(cl.obs_id) : undefined;
      if (obs?.meta.withdrawn === true) continue;
      claims.push({
        index: i,
        claim: cl.claim,
        quote: cl.quote,
        time: cl.time,
        url: obs?.url ?? "",
      });
    }
    return {
      id: c.id,
      project_id: c.project_id,
      project_name: this.proj(c.project_id)?.name ?? "",
      topic: c.topic,
      claims,
      status: c.status,
      resolution: c.resolution,
      created: c.created,
    };
  }

  /** 项目及其子项目的 id */
  private family(p: ProjectRow): string[] {
    return p.parent_id ? [p.id] : [p.id, ...this.store.children(p.id).map((c) => c.id)];
  }

  projectSummary(p: ProjectRow): CtxProjectSummary {
    const ids = this.family(p);
    const items = ids.flatMap((id) => this.store.items({ status: ["open"], project_id: id, limit: 2000 })).filter((i) => !i.meta.legacy);
    const high = items.filter((i) => i.priority === "high" || i.kind === "risk").length;
    const overdue = items.some((i) => i.due && i.due < Date.now());
    const health = p.health !== "unknown" ? p.health : high || overdue ? "risk" : items.length ? "ok" : "unknown";
    const parent = p.parent_id ? this.proj(p.parent_id) : undefined;
    return {
      id: p.id,
      name: p.name,
      description: p.description,
      my_role: p.my_role,
      stage: p.stage,
      status: p.status,
      muted: p.muted,
      health,
      open_items: items.length,
      high_items: high,
      last_activity: p.last_activity,
      refs: p.refs,
      parent_id: p.parent_id,
      parent_name: parent?.name ?? "",
      children: ids.length - 1,
    };
  }

  projects(includeLegacy = false): CtxProjectSummary[] {
    this.projectCache.clear();
    return this.store
      .projects({ includeLegacy: true })
      .filter((p) => includeLegacy || !this.store.hidden(p))
      .map((p) => this.projectSummary(p))
      .sort((a, b) => Number(a.muted) - Number(b.muted) || b.high_items - a.high_items || b.last_activity - a.last_activity);
  }

  knowledgeView(k: ReturnType<ContextStore["knowledge"]>[number]): CtxKnowledgeView {
    return { ...k, project_name: this.proj(k.project_id)?.name ?? "", evidence: this.evidence("knowledge", k.id, 5) };
  }

  updateView(u: ReturnType<ContextStore["updates"]>[number]): CtxUpdateView {
    return { id: u.id, project_id: u.project_id, project_name: this.proj(u.project_id)?.name ?? "", time: u.time, summary: u.summary, evidence: this.evidence("update", u.id, 3) };
  }

  people(): CtxPersonView[] {
    const open = this.store.items({ status: ["open"], limit: 3000 });
    return this.store.people().map((p) => ({
      id: p.id,
      name: p.name,
      relation: p.relation,
      projects: p.projects.map((id) => this.proj(id)?.name ?? id),
      open_items: open.filter((i) => i.counterpart.includes(p.name)).length,
      last_seen: p.last_seen,
    }));
  }

  projectDetail(id: string): CtxProjectDetail | undefined {
    this.projectCache.clear();
    const p = this.store.project(id);
    if (!p) return undefined;
    const ids = this.family(p);
    const names = new Set(ids.map((x) => this.proj(x)?.name ?? ""));
    const items = ids
      .flatMap((pid) => this.store.items({ project_id: pid, limit: 500 }))
      .map((it) => this.itemView(it))
      .sort((a, b) => Number(a.status !== "open") - Number(b.status !== "open") || b.score - a.score);
    const people = this.people().filter((x) => x.projects.some((n) => names.has(n)));
    return {
      ...this.projectSummary(p),
      subprojects: p.parent_id ? [] : this.store.children(p.id).map((c) => this.projectSummary(c)),
      items,
      knowledge: ids.flatMap((pid) => this.store.knowledge({ project_id: pid })).map((k) => this.knowledgeView(k)),
      updates: ids
        .flatMap((pid) => this.store.updates({ project_id: pid, limit: 50 }))
        .sort((a, b) => b.time - a.time)
        .map((u) => this.updateView(u)),
      people,
      conflicts: this.store
        .conflicts()
        .filter((c) => ids.includes(c.project_id))
        .map((c) => this.conflictView(c))
        .filter((c) => c.status === "resolved" || c.claims.length > 0),
    };
  }

  itemDetail(id: string, actions: string[]): CtxItemDetail | undefined {
    const it = this.store.item(id);
    if (!it) return undefined;
    return { ...this.itemView(it), evidence: this.evidence("item", id, 20), drafts: this.store.drafts({ item_id: id }).map((d) => this.draftView(d)), actions };
  }

  status(running: boolean, personalWeb?: CtxPersonalWebStatus, ownerMismatchOverride?: boolean): CtxStatus {
    const kv = this.app.store;
    const ownerMismatch = ownerMismatchOverride ?? hasWorkspaceOwnerMismatch(kv, this.app.cfg.owner.open_id);
    const sources = ["meego", "tasks", "im", "minutes", "calendar", "docs"].map((s) => {
      const r = JSON.parse(kv.get(`ctx.source.${s}`) ?? "null") as { at?: number; count?: number; error?: string } | null;
      return { source: s, last_pull: r?.at ?? null, last_count: r?.count ?? 0, error: ownerMismatch ? "" : r?.error ?? "" };
    });
    const safePersonalWeb =
      personalWeb && ownerMismatch
        ? {
            enabled: personalWeb.enabled,
            logged_in: false,
            state: "needs_login",
            owner_id: "",
            owner_name: "",
            last_message_at: null,
            last_error: "当前工作区 owner.open_id 与已绑定的个人 Web 主人不一致，已隔离上下文",
          }
        : personalWeb;
    return {
      last_cycle: Number(kv.get("ctx.last_cycle") ?? 0) || null,
      last_error: ownerMismatch ? "当前工作区 owner.open_id 与已绑定的个人 Web 主人不一致，已隔离上下文" : kv.get("ctx.last_error") ?? "",
      running,
      sources,
      pending_obs: ownerMismatch ? 0 : this.store.pendingCount(),
      totals: ownerMismatch
        ? { projects: 0, open_items: 0, knowledge: 0, people: 0 }
        : this.store.totals(),
      understand_enabled: this.app.cfg.context.understand,
      ...(safePersonalWeb ? { personal_web: safePersonalWeb } : {}),
    };
  }

  meetings(): CtxMeeting[] {
    const all = JSON.parse(this.app.store.get("ctx.calendar") ?? "[]") as CtxMeeting[];
    const sod = startOfDay(this.tz);
    return all.filter((m) => m.end >= Date.now() - HOUR && m.start < sod + DAY);
  }

  today(running = false, personalWeb?: CtxPersonalWebStatus): CtxToday {
    const now = Date.now();
    this.store.wakeSnoozed(now);
    const open = this.openItems(now);
    const sod = startOfDay(this.tz, now);
    const by = (k: string) => open.filter((i) => i.kind === k);
    const dueSoon = open.filter((i) => i.due && i.due < sod + 2 * DAY);
    return {
      date: new Intl.DateTimeFormat("en-CA", { timeZone: this.tz }).format(new Date(now)),
      focus: open.filter((i) => !i.needs_review).slice(0, 8),
      asks: by("ask_me"),
      commitments: by("my_commitment"),
      waiting: by("waiting_on"),
      risks: by("risk"),
      due_soon: dueSoon,
      needs_review: open.filter((i) => i.needs_review).slice(0, 20),
      conflicts: this.store
        .conflicts("open")
        .map((c) => this.conflictView(c))
        .filter((c) => c.claims.length > 0),
      drafts: this.store.drafts({ status: ["proposed", "failed"] }).map((d) => this.draftView(d)),
      meetings: this.meetings(),
      changes: this.store.updates({ since: now - DAY, limit: 30 }).map((u) => this.updateView(u)),
      projects: this.projects(false).slice(0, 12),
      status: this.status(running, personalWeb),
    };
  }
}

export { KIND_TEXT };
