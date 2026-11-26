import fs from "node:fs";
import path from "node:path";
import { Cron } from "croner";
import { tryGit } from "../delivery/git.ts";
import type { App } from "../app.ts";
import { availableActions } from "../core-commands.ts";
import type { Effect, WorkItem } from "../ledger.ts";
import type { DispatchPayload } from "../workflows/dispatch.ts";
import type {
  AuditView,
  DeliveryStatus,
  DiffView,
  DispatchDetail,
  DispatchState,
  DispatchSummary,
  Health,
  HealthItem,
  JobView,
  LogChunk,
  Meta,
  Overview,
  StepView,
} from "./types.ts";

/** 控制台的只读查询：从账本、步骤、审计拼出 API 返回的视图。 */

const ATTENTION: DispatchState[] = ["needs_human", "errored"];
const REVIEW: DispatchState[] = ["accepted", "unverified"];
const DAY = 86_400_000;

export function taskUrl(app: App, guid: string): string {
  return guid ? `https://${app.cfg.applink_host}/client/todo/detail?guid=${encodeURIComponent(guid)}` : "";
}

/**
 * 派单的交付状态：由 ref = 派单 id 的最新一项 delivery 工作推导。
 * action = "cleanup" 是放弃后的延迟清理，属于放弃的附属动作，不改变状态（保留期内外都是 discarded）。
 */
export function deliveryOf(app: App, dispatchId: string): { status: DeliveryStatus; url: string } {
  const d = app.ledger
    .list<{ action?: string; url?: string }>({ kinds: ["delivery"], ref: dispatchId, limit: 50 })
    .find((x) => x.payload.action !== "cleanup");
  if (!d) return { status: "none", url: "" };
  if (!d.terminal) return { status: "pending", url: "" };
  if (d.state !== "done") return { status: "failed", url: "" };
  const url = d.payload.url ?? "";
  switch (d.payload.action) {
    case "create_pr":
      return { status: "pr_open", url };
    case "merge_local":
      return { status: "merged_local", url };
    case "discard":
      return { status: "discarded", url };
    default:
      return { status: "none", url };
  }
}

function repoAlias(p: DispatchPayload): string {
  return p.description?.match(/^\s*repo\s*[:：]\s*(\S+)\s*$/im)?.[1] ?? "";
}

export function summarize(app: App, w: WorkItem<DispatchPayload>): DispatchSummary {
  const p = w.payload;
  const del = deliveryOf(app, w.id);
  return {
    id: w.id,
    task_guid: w.ref,
    task_url: taskUrl(app, w.ref),
    summary: (p.summary ?? "").replace(/^\s*\[[\w-]+\]\s*/, "") || w.ref,
    state: w.state as DispatchState,
    terminal: w.terminal,
    reason: w.reason,
    harness: p.harness ?? "",
    reviewer: p.reviewer ?? "",
    repo: repoAlias(p),
    round: p.round ?? 0,
    max_rounds: p.maxRounds ?? 0,
    attempts: w.attempts,
    active: !w.terminal && w.lease_until >= Date.now(),
    cancel_requested: w.cancel,
    created: w.created,
    updated: w.updated,
    cost_usd: app.ledger.costOf([w.id]),
    delivery: del.status,
    delivery_url: del.url,
  };
}

/** 每张卡片只取最新一次派单。 */
function latestPerCard(app: App, items: WorkItem<DispatchPayload>[]): WorkItem<DispatchPayload>[] {
  const seen = new Set<string>();
  return items.filter((w) => {
    if (seen.has(w.ref)) return false;
    seen.add(w.ref);
    return app.ledger.latest("dispatch", w.ref)?.id === w.id;
  });
}

export function meta(app: App, version: string): Meta {
  const { cfg } = app;
  return {
    version,
    owner: { open_id: cfg.owner.open_id, timezone: cfg.owner.timezone },
    harnesses: Object.keys(cfg.harnesses),
    roles: { brain: cfg.roles.brain, reviewer: cfg.roles.reviewer, default_harness: cfg.dispatch.default_harness || cfg.roles.brain },
    repos: Object.entries(cfg.dispatch.repos).map(([alias, v]) =>
      typeof v === "string" ? { alias, path: v } : { alias, path: v.path, verify: v.verify, provider: v.provider },
    ),
    providers: Object.entries(cfg.delivery.providers).map(([name, p]) => ({ name, type: p.type })),
    features: {
      cards: !!app.ext.cards && cfg.cards.enabled,
      delivery: app.commands.has("delivery.merge_local"),
      usage: !!app.ext.usage,
      settings: !!app.ext.settings,
      doctor: !!app.ext.doctor,
      candidates: !!app.ext.candidates,
      context: !!app.ext.context,
    },
    lark_web: cfg.lark_web,
  };
}

function startOfLocalDay(tz: string, now = Date.now()): number {
  const parts = new Intl.DateTimeFormat("en-US", { timeZone: tz, hour: "numeric", minute: "numeric", second: "numeric", hourCycle: "h23" })
    .formatToParts(new Date(now))
    .reduce<Record<string, number>>((acc, p) => (p.type === "literal" ? acc : { ...acc, [p.type]: Number(p.value) }), {});
  return now - ((parts.hour * 60 + parts.minute) * 60 + parts.second) * 1000 - (now % 1000);
}

export function overview(app: App): Overview {
  const { ledger, cfg } = app;
  const recent = ledger.list<DispatchPayload>({ kinds: ["dispatch"], limit: 500 }).filter((w) => !w.terminal || w.updated > Date.now() - 14 * DAY);
  const latest = latestPerCard(app, recent);
  const needs = latest.filter((w) => ATTENTION.includes(w.state as DispatchState)).map((w) => summarize(app, w));
  const review = latest
    .filter((w) => REVIEW.includes(w.state as DispatchState))
    .map((w) => summarize(app, w))
    .filter((s) => s.delivery === "none" || s.delivery === "failed" || s.delivery === "pending");
  const running = recent.filter((w) => !w.terminal).map((w) => summarize(app, w));
  const dayStart = startOfLocalDay(cfg.owner.timezone);
  const today = recent.filter((w) => w.created >= dayStart);
  const count = (s: string) => today.filter((w) => w.state === s).length;
  const h = health(app);
  return {
    attention: {
      needs_human: needs.filter((s) => !(s.delivery === "discarded")),
      to_review: review,
      candidates: app.ext.candidates?.pendingCount() ?? 0,
      failures: h.failed.filter((f) => !f.acknowledged).length,
    },
    running,
    today: {
      dispatched: today.length,
      accepted: count("accepted"),
      needs_human: count("needs_human"),
      errored: count("errored"),
      cost_usd: ledger.costSince(dayStart),
      budget_usd: cfg.budget.daily_usd,
    },
    health: {
      ok: !!h.daemon.last_heartbeat && Date.now() - h.daemon.last_heartbeat < 60_000 && h.failed.every((f) => f.acknowledged),
      pending_events: ledger.active("event").length,
      pending_effects: ledger.active("effect").length,
      dead: h.failed.filter((f) => !f.acknowledged).length,
      daemon_owner: h.daemon.owner,
    },
  };
}

export type DispatchFilter = "active" | "attention" | "review" | "done" | "all";

export function listDispatches(app: App, f: { filter?: DispatchFilter; q?: string; limit?: number }): DispatchSummary[] {
  const items = app.ledger.list<DispatchPayload>({ kinds: ["dispatch"], limit: Math.min(f.limit ?? 200, 500) });
  const q = f.q?.trim().toLowerCase();
  return items
    .filter((w) => {
      switch (f.filter ?? "all") {
        case "active":
          return !w.terminal;
        case "attention":
          return ATTENTION.includes(w.state as DispatchState);
        case "review":
          return REVIEW.includes(w.state as DispatchState);
        case "done":
          return w.terminal;
        default:
          return true;
      }
    })
    .filter((w) => !q || `${w.payload.summary ?? ""} ${w.ref} ${w.id}`.toLowerCase().includes(q))
    .map((w) => summarize(app, w));
}

function stepView(s: ReturnType<App["ledger"]["steps"]>[number]): StepView {
  return {
    id: s.id,
    name: s.name,
    harness: s.harness,
    status: s.status,
    started: s.started,
    ended: s.ended,
    duration_ms: s.ended ? s.duration_ms || s.ended - s.started : Date.now() - s.started,
    summary: s.summary,
    has_log: !!s.log && fs.existsSync(s.log),
    tokens_in: s.tokens_in ?? 0,
    tokens_out: s.tokens_out ?? 0,
    cost_usd: s.cost_usd ?? 0,
  };
}

function effectSummary(e: Effect): string {
  switch (e.op) {
    case "task.move":
      return `移到「${e.args.section}」`;
    case "task.comment":
      return `评论：${e.args.content.split("\n")[0].slice(0, 80)}`;
    case "task.complete":
      return "标记完成";
    case "notify":
      return `私信：${e.args.markdown.split("\n")[0].slice(0, 80)}`;
    case "card.upsert":
      return `卡片：${e.args.key}`;
    case "im.reply":
      return `以你的身份回复：${e.args.text.split("\n")[0].slice(0, 60)}`;
    case "im.send":
      return `以你的身份发送：${e.args.text.split("\n")[0].slice(0, 60)}`;
    case "meego.comment":
      return `Meego 评论 #${e.args.work_item_id}：${e.args.content.split("\n")[0].slice(0, 60)}`;
    case "doc.create":
      return `新建文档：${e.args.title}`;
    case "task.create_own":
      return `给自己建任务：${e.args.summary}`;
    default:
      return (e as { op: string }).op;
  }
}

export function auditViews(app: App, target?: string, limit = 50): AuditView[] {
  return app.ledger.auditLog(limit, target).map((a) => ({ id: a.id, at: a.at, source: a.source, command: a.command, target: a.target, ok: !!a.ok, message: a.message }));
}

export async function dispatchDetail(app: App, id: string): Promise<DispatchDetail | undefined> {
  const w = app.ledger.get<DispatchPayload>(id);
  if (!w || w.kind !== "dispatch") return undefined;
  const p = w.payload;
  const s = summarize(app, w);
  const latest = app.ledger.latest("dispatch", w.ref);
  let diffStat = "";
  if (p.base && p.cwd && fs.existsSync(p.cwd)) diffStat = (await tryGit(p.cwd, ["diff", "--stat", p.base])).stdout.trim();
  return {
    ...s,
    description: p.description ?? "",
    cwd: p.cwd ?? "",
    branch: p.branch ?? "",
    base: p.base ?? "",
    verify: p.verify ?? "",
    report: p.report ?? "",
    feedback: p.feedback ?? "",
    error: w.error,
    rounds: (p.history ?? []).map((h) => ({ round: h.round, checks: h.checks })),
    steps: app.ledger.steps(id).map(stepView),
    effects: app.ledger.effectsOf(id).map((e) => ({ id: e.id, op: e.payload.op, state: e.state, summary: effectSummary(e.payload), error: e.error, updated: e.updated })),
    previous: app.ledger
      .list<DispatchPayload>({ kinds: ["dispatch"], ref: w.ref, limit: 20 })
      .filter((x) => x.id !== id)
      .map((x) => summarize(app, x)),
    diff_stat: diffStat,
    actions: availableActions(w, {
      delivery: s.delivery,
      providers: Object.keys(app.cfg.delivery.providers).length,
      deliveryEnabled: app.commands.has("delivery.merge_local"),
      isLatest: latest?.id === id,
    }).filter((a) => app.commands.has(a)),
    audit: auditViews(app, id),
  };
}

const DIFF_MAX = 400_000;

export async function dispatchDiff(app: App, id: string): Promise<DiffView | undefined> {
  const w = app.ledger.get<DispatchPayload>(id);
  if (!w || w.kind !== "dispatch") return undefined;
  const p = w.payload;
  if (!p.base || !p.cwd || !fs.existsSync(p.cwd)) return { base: p.base ?? "", head: "", stat: "", patch: "", truncated: false };
  // 与基线比较（含尚未提交的已跟踪文件改动）；只读，不改动索引
  const [head, stat, patch] = await Promise.all([
    tryGit(p.cwd, ["rev-parse", "HEAD"]),
    tryGit(p.cwd, ["diff", "--stat", p.base]),
    tryGit(p.cwd, ["diff", "--no-color", p.base]),
  ]);
  return {
    base: p.base,
    head: head.stdout.trim(),
    stat: stat.stdout.trim(),
    patch: patch.stdout.slice(0, DIFF_MAX),
    truncated: patch.stdout.length > DIFF_MAX,
  };
}

const LOG_CHUNK = 64 * 1024;

export function stepLog(app: App, stepId: number, offset: number): LogChunk | undefined {
  const s = app.ledger.step(stepId);
  if (!s) return undefined;
  const file = path.resolve(s.log || "");
  // 只允许读取数据目录下的日志
  if (!s.log || !file.startsWith(path.resolve(app.cfg.dataDir) + path.sep) || !fs.existsSync(file)) {
    return { step_id: stepId, offset, next_offset: offset, text: "", eof: true, running: s.status === "running" };
  }
  const size = fs.statSync(file).size;
  const start = Math.max(0, Math.min(offset, size));
  const len = Math.min(LOG_CHUNK, size - start);
  const buf = Buffer.alloc(len);
  if (len > 0) {
    const fd = fs.openSync(file, "r");
    try {
      fs.readSync(fd, buf, 0, len, start);
    } finally {
      fs.closeSync(fd);
    }
  }
  return { step_id: stepId, offset: start, next_offset: start + len, text: buf.toString("utf8"), eof: start + len >= size, running: s.status === "running" };
}

function healthItem(w: WorkItem): HealthItem {
  const p = w.payload as Record<string, unknown>;
  const summary =
    w.kind === "effect" ? effectSummary(w.payload as unknown as Effect) : String(p.summary ?? p.name ?? p.action ?? w.ref).slice(0, 120);
  return {
    id: w.id,
    kind: w.kind as HealthItem["kind"],
    ref: w.ref,
    state: w.state,
    terminal: w.terminal,
    attempts: w.attempts,
    next_at: w.next_at,
    error: w.error,
    summary,
    updated: w.updated,
    acknowledged: w.outcome === "acknowledged",
  };
}

export function health(app: App): Health {
  const { ledger, store, cfg } = app;
  const kinds = ["event", "effect", "job", "delivery"] as const;
  const retrying = kinds.flatMap((k) => ledger.active(k)).filter((w) => w.attempts > 1 || !!w.error).map(healthItem);
  const failed = ledger
    .list({ kinds: [...kinds], states: ["dead", "errored"], limit: 200 })
    .filter((w) => w.updated > Date.now() - 14 * DAY)
    .map(healthItem);
  const hb = store.get("daemon.heartbeat");
  const [owner, at] = hb ? hb.split("|") : [null, null];
  let guard: Health["guard"] = [];
  const gl = path.join(cfg.dataDir, "logs", "guard.log");
  if (fs.existsSync(gl)) {
    const text = fs.readFileSync(gl, "utf8");
    guard = text
      .trim()
      .split("\n")
      .slice(-50)
      .reverse()
      .flatMap((l) => {
        try {
          const j = JSON.parse(l);
          return [{ at: j.t, profile: j.profile, allow: !!j.allow, reason: j.reason, argv: j.argv ?? [] }];
        } catch {
          return [];
        }
      });
  }
  return { daemon: { owner: owner ?? null, last_heartbeat: at ? Number(at) : null }, retrying, failed, guard };
}

export function jobs(app: App): JobView[] {
  return Object.entries(app.cfg.jobs).map(([name, j]) => {
    let next: number | null = null;
    try {
      next = new Cron(j.cron, { timezone: app.cfg.owner.timezone, paused: true }).nextRun()?.getTime() ?? null;
    } catch {
      next = null;
    }
    const last = app.ledger.list<{ result?: string }>({ kinds: ["job"], ref: name, limit: 1 })[0];
    return {
      name,
      cron: j.cron,
      prompt: j.prompt,
      harness: j.harness ?? app.cfg.roles.brain,
      notify: j.notify,
      next_run: next,
      last: last ? { id: last.id, state: last.state, updated: last.updated, result: last.payload.result ?? "", error: last.error } : null,
    };
  });
}
