import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { Cron } from "croner";
import { tryGit } from "../delivery/git.ts";
import type { App } from "../app.ts";
import { CommandError } from "../commands.ts";
import { repoSpec } from "../config.ts";
import { hasWorkspaceOwnerMismatch } from "../context/personal-web.ts";
import { availableActions } from "../core-commands.ts";
import type { Effect, WorkItem } from "../ledger.ts";
import { parseRepo, type DispatchPayload } from "../workflows/dispatch.ts";
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
  const recent = ledger
    .list<DispatchPayload>({ kinds: ["dispatch"], limit: 500 })
    .filter((w) => (!w.terminal || w.updated > Date.now() - 14 * DAY) && !isContextDerivedDispatchBlocked(app, w.id));
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
  // 使用 health() 在全 14 天报告窗口内分页统计出的当前主人未确认可操作失败总数，
  // 避免最新 200 条失败被旧主人隔离记录占满时把当前主人的待处理失败挤出概览或误判为健康
  const actionableCount = h.actionable_failures;
  return {
    attention: {
      needs_human: needs.filter((s) => !(s.delivery === "discarded")),
      to_review: review,
      candidates: app.ext.candidates?.pendingCount() ?? 0,
      failures: actionableCount,
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
      ok: !!h.daemon.last_heartbeat && Date.now() - h.daemon.last_heartbeat < 60_000 && actionableCount === 0,
      pending_events: ledger.active("event").length,
      pending_effects: ledger.active("effect").length,
      dead: actionableCount,
      daemon_owner: h.daemon.owner,
    },
  };
}

export type DispatchFilter = "active" | "attention" | "review" | "done" | "all";

/** 判断某条派单（或其关联任务 ref / 交付工作 / 卡片 key / 完整重试链路）是否源自工作上下文委派且归属的旧主人与当前配置 owner.open_id 不一致 */
export function isContextDerivedDispatchBlocked(app: Pick<App, "cfg" | "store" | "ledger">, dispatchId: string): boolean {
  if (!dispatchId) return false;
  const curOwner = app.cfg.owner.open_id.trim();
  const normalized = dispatchId.startsWith("card:") ? dispatchId.slice("card:".length) : dispatchId;
  const w = app.ledger.get(normalized);
  if (w?.kind === "delivery") {
    const p = w.payload as { dispatch_id?: unknown; guid?: unknown };
    const candidates = [
      w.ref,
      typeof p.dispatch_id === "string" ? p.dispatch_id : "",
      typeof p.guid === "string" ? p.guid : "",
    ].filter(Boolean);
    if (candidates.some((c) => c !== normalized && isContextDerivedDispatchBlocked(app, c))) return true;
  } else if (!w && normalized.startsWith("delivery:")) {
    const rest = normalized.slice("delivery:".length);
    if (rest.startsWith("dispatch:")) {
      const parts = rest.split(":");
      const parsedDispatchId = parts.length >= 3 ? parts.slice(0, 3).join(":") : "";
      const parsedDeliveryGuid = parts[1] ?? "";
      if (parsedDispatchId && isContextDerivedDispatchBlocked(app, parsedDispatchId)) return true;
      if (parsedDeliveryGuid && isContextDerivedDispatchBlocked(app, parsedDeliveryGuid)) return true;
    }
  }
  const parsedGuid = normalized.startsWith("dispatch:") ? (normalized.split(":")[1] ?? "") : "";
  const candidateGuids = [...new Set([normalized, w?.ref ?? "", parsedGuid].filter(Boolean))];
  const directOrigin = (app.store.get(`ctx.dispatch_owner.${normalized}`) ?? "").trim();
  const refOrigin = (w?.ref ? app.store.get(`ctx.dispatch_ref_owner.${w.ref}`) : undefined)?.trim() ?? "";
  const idAsRefOrigin = (app.store.get(`ctx.dispatch_ref_owner.${normalized}`) ?? "").trim();
  const parsedGuidOrigin = parsedGuid ? (app.store.get(`ctx.dispatch_ref_owner.${parsedGuid}`) ?? "").trim() : "";
  const ownTaskOrigin =
    candidateGuids
      .map((g) => (app.store.get(`ctx.own_task_owner.${g}`) ?? "").trim())
      .find(Boolean) ?? "";
  const originOwner = directOrigin || refOrigin || idAsRefOrigin || parsedGuidOrigin || ownTaskOrigin;
  if (originOwner && originOwner !== curOwner) return true;
  const prevOwnerOpenId = (app.store.get("owner.open_id") ?? "").trim();
  const ownerSwitched =
    hasWorkspaceOwnerMismatch(app.store, curOwner) ||
    (!!prevOwnerOpenId && prevOwnerOpenId !== curOwner);
  if (!ownerSwitched) return false;
  if (originOwner) return true;
  // 兜底兼容升级前已通过 task.create_own 或 item_delegate 创建但尚未写 owner 标记的派单/任务（含同 ref 的完整重试历史与卡片 key）
  try {
    for (const g of candidateGuids) {
      const legacyOwn = app.store.db
        .prepare("SELECT 1 FROM kv WHERE k LIKE 'op.task.create_own.%' AND v = ? LIMIT 1")
        .get(g);
      if (legacyOwn) return true;
    }
    const hasTable = app.store.db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'ctx_item'").get();
    if (!hasTable) return false;
    const directRow = app.store.db
      .prepare("SELECT 1 FROM ctx_item WHERE json_extract(meta, '$.delegated') = ? LIMIT 1")
      .get(normalized);
    if (directRow) return true;
    const candidateRef = w?.ref || parsedGuid || normalized;
    if (candidateRef) {
      const refRow = app.store.db
        .prepare("SELECT 1 FROM ctx_item WHERE json_extract(meta, '$.delegated') = ? LIMIT 1")
        .get(candidateRef);
      if (refRow) return true;
      const historyRow = app.store.db
        .prepare(
          `SELECT 1 FROM work w
            WHERE w.kind = 'dispatch' AND w.ref = ?
              AND EXISTS (SELECT 1 FROM ctx_item ci WHERE json_extract(ci.meta, '$.delegated') = w.id)
            LIMIT 1`,
        )
        .get(candidateRef);
      if (historyRow) return true;
    }
    return false;
  } catch {
    return false;
  }
}

/** 判断某条个人任务 GUID（含上下文委派派单任务与自主创建的 task.create_own 任务）是否归属旧主人而应对当前主人隐藏 */
export function isContextOwnedTaskBlocked(app: Pick<App, "cfg" | "store" | "ledger">, guid: string): boolean {
  if (!guid) return false;
  if (isContextDerivedDispatchBlocked(app, guid)) return true;
  const curOwner = app.cfg.owner.open_id.trim();
  const ownOrigin = (app.store.get(`ctx.own_task_owner.${guid}`) ?? "").trim();
  if (ownOrigin && ownOrigin !== curOwner) return true;
  const prevOwnerOpenId = (app.store.get("owner.open_id") ?? "").trim();
  const ownerSwitched =
    hasWorkspaceOwnerMismatch(app.store, curOwner) ||
    (!!prevOwnerOpenId && prevOwnerOpenId !== curOwner);
  if (!ownerSwitched) return false;
  if (ownOrigin) return true;
  // 兼容升级前通过 task.create_own 创建、仅在 op.task.create_own.* 记录了 guid 的自主任务
  try {
    const legacyOwn = app.store.db
      .prepare("SELECT 1 FROM kv WHERE k LIKE 'op.task.create_own.%' AND v = ? LIMIT 1")
      .get(guid);
    if (legacyOwn) return true;
  } catch {
    // ignore
  }
  return false;
}

/**
 * 判断某条派单 / 交付工作 / 任务 GUID 是否源自工作上下文（无论当前工作区配置主人是否变更）。
 * 用于在投递其后续评论/移列/完成副作用前强制核验活跃 lark-cli 登录用户，防止 CLI 切号后以他人身份发布委派报告。
 */
export function isContextDerivedWorkOrTask(
  app: Pick<App, "cfg" | "store" | "ledger">,
  idOrGuid: string,
  visited: Set<string> = new Set(),
): boolean {
  if (!idOrGuid) return false;
  const normalized = idOrGuid.startsWith("card:") ? idOrGuid.slice("card:".length) : idOrGuid;
  if (!normalized || visited.has(normalized)) return false;
  visited.add(normalized);

  const w = app.ledger.get(normalized);
  if (w?.kind === "delivery") {
    const p = w.payload as { dispatch_id?: unknown; guid?: unknown };
    const candidates = [
      w.ref,
      typeof p.dispatch_id === "string" ? p.dispatch_id : "",
      typeof p.guid === "string" ? p.guid : "",
    ].filter(Boolean);
    if (candidates.some((c) => isContextDerivedWorkOrTask(app, c, visited))) return true;
  } else if (!w && normalized.startsWith("delivery:")) {
    const rest = normalized.slice("delivery:".length);
    if (rest.startsWith("dispatch:")) {
      const parts = rest.split(":");
      const parsedDispatchId = parts.length >= 3 ? parts.slice(0, 3).join(":") : "";
      const parsedDeliveryGuid = parts[1] ?? "";
      if (parsedDispatchId && isContextDerivedWorkOrTask(app, parsedDispatchId, visited)) return true;
      if (parsedDeliveryGuid && isContextDerivedWorkOrTask(app, parsedDeliveryGuid, visited)) return true;
    }
  }

  const parsedGuid = normalized.startsWith("dispatch:") ? (normalized.split(":")[1] ?? "") : "";
  const hasOrigin =
    !!(app.store.get(`ctx.dispatch_owner.${normalized}`) ?? "").trim() ||
    !!(w?.ref ? (app.store.get(`ctx.dispatch_ref_owner.${w.ref}`) ?? "").trim() : "") ||
    !!(app.store.get(`ctx.dispatch_ref_owner.${normalized}`) ?? "").trim() ||
    !!(parsedGuid ? (app.store.get(`ctx.dispatch_ref_owner.${parsedGuid}`) ?? "").trim() : "") ||
    !!(app.store.get(`ctx.own_task_owner.${normalized}`) ?? "").trim() ||
    !!(w?.ref ? (app.store.get(`ctx.own_task_owner.${w.ref}`) ?? "").trim() : "") ||
    !!(parsedGuid ? (app.store.get(`ctx.own_task_owner.${parsedGuid}`) ?? "").trim() : "");
  if (hasOrigin) return true;

  try {
    const candidateRef = w?.ref || parsedGuid || normalized;
    const hasCtxTable = app.store.db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'ctx_item'").get();
    if (hasCtxTable) {
      if (app.store.db.prepare("SELECT 1 FROM ctx_item WHERE json_extract(meta, '$.delegated') = ? LIMIT 1").get(normalized)) {
        return true;
      }
      if (candidateRef) {
        if (app.store.db.prepare("SELECT 1 FROM ctx_item WHERE json_extract(meta, '$.delegated') = ? LIMIT 1").get(candidateRef)) {
          return true;
        }
        const historyRow = app.store.db
          .prepare(
            `SELECT 1 FROM work w
              WHERE w.kind = 'dispatch' AND w.ref = ?
                AND EXISTS (SELECT 1 FROM ctx_item ci WHERE json_extract(ci.meta, '$.delegated') = w.id)
              LIMIT 1`,
          )
          .get(candidateRef);
        if (historyRow) return true;
      }
    }
    if (candidateRef) {
      const legacyOwn = app.store.db
        .prepare("SELECT 1 FROM kv WHERE k LIKE 'op.task.create_own.%' AND v = ? LIMIT 1")
        .get(candidateRef);
      if (legacyOwn) return true;
    }
  } catch {
    // ignore
  }
  return false;
}

/** 生成紧凑的主人隔离标签（用于 brief 卡片与去重键，保证飞书 50 字符幂等键不截断冲突） */
export function briefOwnerTag(ownerOpenId: string): string {
  const clean = ownerOpenId.trim();
  if (!clean) return "";
  return createHash("sha256").update(clean).digest("hex").slice(0, 12);
}

/**
 * 统一判断任意账本工作项 / 卡片 key（含 failure:<workId> 失败告警卡片、queued brief、delivery、effect、context）
 * 是否应因工作区主人隔离而被阻断或隐藏。
 */
export function isWorkBlockedByOwner(
  app: Pick<App, "cfg" | "store" | "ledger">,
  workOrId: WorkItem | string,
  visited: Set<string> = new Set(),
): boolean {
  const rawId = typeof workOrId === "string" ? workOrId : workOrId.id;
  if (!rawId || visited.has(rawId)) return false;
  visited.add(rawId);

  const curOwner = app.cfg.owner.open_id.trim();
  const curBriefTag = briefOwnerTag(curOwner);
  const ownerMismatch = hasWorkspaceOwnerMismatch(app.store, curOwner);
  if (typeof workOrId === "string") {
    if (workOrId.startsWith("card:failure:")) {
      return isWorkBlockedByOwner(app, workOrId.slice("card:failure:".length), visited);
    }
    if (workOrId.startsWith("failure:")) {
      return isWorkBlockedByOwner(app, workOrId.slice("failure:".length), visited);
    }
  }

  const w = typeof workOrId === "string" ? app.ledger.get(workOrId) : workOrId;
  if (!w) {
    if (ownerMismatch) {
      const isBriefKey = rawId === "brief" || rawId.startsWith("card:brief:") || rawId.startsWith("brief:");
      if (isBriefKey) {
        // 显式按当前主人作用域生成的 brief 卡片键放行，未绑定或旧主人作用域的 brief 键阻断
        return !curBriefTag || !rawId.endsWith(`-${curBriefTag}`);
      }
      if (
        rawId.startsWith("card:ctx-") ||
        rawId.startsWith("ctx-draft:") ||
        (rawId.startsWith("context:") && rawId !== "context:pw-needs-login")
      ) {
        return true;
      }
    }
    return isContextOwnedTaskBlocked(app, rawId);
  }

  if (ownerMismatch && isContextHealthWork(w)) return true;

  if (w.kind === "dispatch" || w.kind === "delivery") {
    if (isContextDerivedDispatchBlocked(app, w.id) || (!!w.ref && isContextDerivedDispatchBlocked(app, w.ref))) {
      return true;
    }
    return false;
  }

  if (w.kind === "effect") {
    const e = w.payload as unknown as Partial<Effect>;
    // 显式绑定了目标主人的通知/卡片（如 sendBrief 生成的概览），仅在目标主人与当前 owner.open_id 不一致时阻断；
    // 为当前主人重新渲染并绑定了 curOwner 的 brief（buildBrief 已按主人过滤旧上下文任务）允许正常投递，未绑定旧版 brief 保持兜底阻断
    const boundRecipient =
      e.args && "owner_open_id" in e.args && typeof e.args.owner_open_id === "string"
        ? e.args.owner_open_id.trim()
        : "";
    if (boundRecipient && boundRecipient !== curOwner) return true;
    const isBriefEffect =
      w.ref === "brief" ||
      w.ref.startsWith("card:brief:") ||
      (e.op === "card.upsert" && typeof e.args?.key === "string" && e.args.key.startsWith("brief:"));
    if (isBriefEffect && !boundRecipient && ownerMismatch) return true;
    if (w.ref.startsWith("card:failure:")) {
      if (isWorkBlockedByOwner(app, w.ref.slice("card:failure:".length), visited)) return true;
    }
    if (e.op === "card.upsert" && typeof e.args?.key === "string" && e.args.key.startsWith("failure:")) {
      if (isWorkBlockedByOwner(app, e.args.key.slice("failure:".length), visited)) return true;
    }
    const candidates = [
      w.ref,
      e.op === "card.upsert" && typeof e.args?.key === "string" ? e.args.key : "",
      e.args && "guid" in e.args && typeof e.args.guid === "string" ? e.args.guid : "",
    ].filter(Boolean);
    if (candidates.some((c) => isContextOwnedTaskBlocked(app, c))) return true;
    return false;
  }

  return !!w.ref && isContextOwnedTaskBlocked(app, w.ref);
}

export function listDispatches(app: App, f: { filter?: DispatchFilter; q?: string; limit?: number }): DispatchSummary[] {
  const maxItems = Math.min(Math.max(0, f.limit ?? 200), 500);
  if (maxItems === 0) return [];
  const rawQ = f.q?.trim();
  const q = rawQ?.toLowerCase();
  // SQLite LOWER() 仅折叠 ASCII；在全部 Unicode 码点中，仅 'i'（来自 İ U+0130）与 'k'（来自 K U+212A）
  // 会由非 ASCII 字符经 JS .toLowerCase() 折叠进 ASCII。因此检查原始查询：仅当不含 i/k 且不含具大小写映射的非 ASCII 字符时才下推 SQL 预筛。
  const canPushSearch =
    !!rawQ &&
    [...rawQ].every((ch) => {
      const code = ch.charCodeAt(0);
      if (code < 128) {
        const lo = ch.toLowerCase();
        return lo !== "i" && lo !== "k";
      }
      return ch.toLowerCase() === ch && ch.toUpperCase() === ch;
    });
  let states: string[] | undefined;
  let terminal: boolean | undefined;
  switch (f.filter ?? "all") {
    case "active":
      terminal = false;
      break;
    case "attention":
      states = [...ATTENTION];
      break;
    case "review":
      states = [...REVIEW];
      break;
    case "done":
      terminal = true;
      break;
    default:
      break;
  }
  const pageSize = Math.min(Math.max(maxItems * 2, 50), 500);
  const matched: WorkItem<DispatchPayload>[] = [];
  let before: number | undefined;
  for (;;) {
    const page = app.ledger.list<DispatchPayload>({
      kinds: ["dispatch"],
      states,
      terminal,
      search: canPushSearch ? q : undefined,
      limit: pageSize,
      before,
    });
    if (!page.length) break;
    for (const w of page) {
      if (q && !canPushSearch && !`${w.payload.summary ?? ""} ${w.ref} ${w.id}`.toLowerCase().includes(q)) continue;
      if (isContextDerivedDispatchBlocked(app, w.id)) continue;
      matched.push(w);
      if (matched.length >= maxItems) break;
    }
    if (matched.length >= maxItems || page.length < pageSize) break;
    before = page[page.length - 1].seq;
  }
  return matched.map((w) => summarize(app, w));
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
  const maxItems = Math.max(0, limit);
  if (maxItems === 0) return [];
  const curOwner = app.cfg.owner.open_id.trim();
  const ownerMismatch = hasWorkspaceOwnerMismatch(app.store, curOwner);
  const pageSize = Math.min(Math.max(maxItems * 2, 50), 500);
  const out: AuditView[] = [];
  let before: number | undefined;
  for (;;) {
    const page = app.ledger.auditLog(pageSize, target, before);
    if (!page.length) break;
    for (const a of page) {
      if (ownerMismatch && a.command.startsWith("context.")) continue;
      if (a.target && isWorkBlockedByOwner(app, a.target)) continue;
      // 嵌套委派命令（如 context.item_delegate 调用 dispatch.create 失败时无派单 ID）通过 args.__context_owner 保留主人归属隔离
      let blockedByOrigin = false;
      if (a.args) {
        try {
          const parsed = JSON.parse(a.args) as { __context_owner?: unknown };
          if (typeof parsed.__context_owner === "string") {
            const origin = parsed.__context_owner.trim();
            if ((origin && origin !== curOwner) || ownerMismatch) blockedByOrigin = true;
          }
        } catch {
          // ignore malformed args json
        }
      }
      if (blockedByOrigin) continue;
      out.push({ id: a.id, at: a.at, source: a.source, command: a.command, target: a.target, ok: !!a.ok, message: a.message });
      if (out.length >= maxItems) break;
    }
    if (out.length >= maxItems || page.length < pageSize) break;
    before = page[page.length - 1].id;
  }
  return out;
}

function dispatchRepoGuard(app: App, p: Pick<DispatchPayload, "description" | "base">): {
  trustedRepoRoot?: string;
  disableGitWorktreeMounts?: boolean;
} {
  if (!p.base) return { disableGitWorktreeMounts: true };
  const ref = parseRepo({ description: p.description ?? "" });
  if (!ref) return { disableGitWorktreeMounts: true };
  return { trustedRepoRoot: repoSpec(app.cfg, ref).path };
}

export async function dispatchDetail(app: App, id: string): Promise<DispatchDetail | undefined> {
  if (isContextDerivedDispatchBlocked(app, id)) {
    throw new CommandError("conflict", "该派单源自旧工作区主人的工作上下文，已按主人隔离阻断访问");
  }
  const w = app.ledger.get<DispatchPayload>(id);
  if (!w || w.kind !== "dispatch") return undefined;
  const p = w.payload;
  const s = summarize(app, w);
  const latest = app.ledger.latest("dispatch", w.ref);
  let diffStat = "";
  if (p.base && p.cwd && fs.existsSync(p.cwd)) {
    diffStat = (await tryGit(p.cwd, ["diff", "--stat", p.base], { cfg: app.cfg, readOnly: true, ...dispatchRepoGuard(app, p) })).stdout.trim();
  }
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
      .filter((x) => x.id !== id && !isContextDerivedDispatchBlocked(app, x.id))
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
  if (isContextDerivedDispatchBlocked(app, id)) {
    throw new CommandError("conflict", "该派单源自旧工作区主人的工作上下文，已按主人隔离阻断访问");
  }
  const w = app.ledger.get<DispatchPayload>(id);
  if (!w || w.kind !== "dispatch") return undefined;
  const p = w.payload;
  if (!p.base || !p.cwd || !fs.existsSync(p.cwd)) return { base: p.base ?? "", head: "", stat: "", patch: "", truncated: false };
  const gitOpts = { cfg: app.cfg, readOnly: true, ...dispatchRepoGuard(app, p) };
  // 与基线比较（含尚未提交的已跟踪文件改动）；只读，不改动索引
  const [head, stat, patch] = await Promise.all([
    tryGit(p.cwd, ["rev-parse", "HEAD"], gitOpts),
    tryGit(p.cwd, ["diff", "--stat", p.base], gitOpts),
    tryGit(p.cwd, ["diff", "--no-color", p.base], gitOpts),
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
  if (isContextDerivedDispatchBlocked(app, s.work_id)) {
    throw new CommandError("conflict", "该步骤日志属于旧工作区主人委派的上下文派单，已按主人隔离阻断读取");
  }
  if (hasWorkspaceOwnerMismatch(app.store, app.cfg.owner.open_id)) {
    const work = app.ledger.get(s.work_id);
    const isContextStep =
      work?.kind === "context" ||
      s.work_id.startsWith("context:") ||
      path.basename(file).startsWith("context-");
    if (isContextStep) {
      throw new CommandError("conflict", "当前工作区 owner.open_id 与已绑定的个人 Web 主人不一致，已阻断读取上下文运行日志以防跨账号泄漏");
    }
  }
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

function isContextHealthWork(w: WorkItem): boolean {
  if (w.kind === "context") return true;
  if (w.ref.startsWith("card:ctx-") || w.ref.startsWith("ctx-draft:")) return true;
  if (w.ref.startsWith("context:") && w.ref !== "context:pw-needs-login") return true;
  if (w.kind === "effect") {
    const e = w.payload as unknown as Partial<Effect>;
    if (e.op === "pw.reply") return true;
    if (e.op === "card.upsert" && typeof e.args?.key === "string" && e.args.key.startsWith("ctx-")) return true;
  }
  return false;
}

function healthItem(app: App, w: WorkItem, ownerMismatch = false): HealthItem {
  if ((ownerMismatch && isContextHealthWork(w)) || isWorkBlockedByOwner(app, w)) {
    return {
      id: w.id,
      kind: w.kind as HealthItem["kind"],
      ref: "context:isolated",
      state: w.state,
      terminal: w.terminal,
      attempts: w.attempts,
      next_at: w.next_at,
      error: "工作区 owner.open_id 与已绑定账号不一致，上下文已隔离",
      summary: "上下文任务已按主人隔离",
      updated: w.updated,
      acknowledged: w.outcome === "acknowledged",
      isolated: true,
    };
  }
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
  const ownerMismatch = hasWorkspaceOwnerMismatch(store, cfg.owner.open_id);
  const kinds = ["event", "effect", "job", "delivery"] as const;
  const retrying = kinds.flatMap((k) => ledger.active(k)).filter((w) => w.attempts > 1 || !!w.error).map((w) => healthItem(app, w, ownerMismatch));

  // 在 14 天报告窗口内分页扫描全部失败项：
  //   1. 精确累计当前主人未确认的可操作失败总数（actionable_failures），不受 200 条展示上限截断；
  //   2. 展示列表（最多 200 条）按优先级依次保留：未确认当前主人失败 → 已确认当前主人失败 → 旧主人隔离记录，
  //      确保已确认的历史失败或旧主人隔离记录绝不会把可操作的当前故障挤出 Health 页面。
  const cutoff = Date.now() - 14 * DAY;
  const DISPLAY_LIMIT = 200;
  const PAGE_SIZE = 500;
  const actionableOwnFailed: HealthItem[] = [];
  const acknowledgedOwnFailed: HealthItem[] = [];
  const isolatedFailed: HealthItem[] = [];
  let actionableFailures = 0;
  let before: number | undefined;
  for (;;) {
    const page = ledger.list({
      kinds: [...kinds],
      states: ["dead", "errored"],
      updatedSince: cutoff,
      limit: PAGE_SIZE,
      before,
    });
    if (!page.length) break;
    for (const w of page) {
      const item = healthItem(app, w, ownerMismatch);
      if (item.isolated) {
        if (isolatedFailed.length < DISPLAY_LIMIT) isolatedFailed.push(item);
      } else if (!item.acknowledged) {
        actionableFailures++;
        if (actionableOwnFailed.length < DISPLAY_LIMIT) actionableOwnFailed.push(item);
      } else {
        if (acknowledgedOwnFailed.length < DISPLAY_LIMIT) acknowledgedOwnFailed.push(item);
      }
    }
    if (page.length < PAGE_SIZE) break;
    before = page[page.length - 1].seq;
  }
  const failed: HealthItem[] = [];
  for (const bucket of [actionableOwnFailed, acknowledgedOwnFailed, isolatedFailed]) {
    if (failed.length >= DISPLAY_LIMIT) break;
    failed.push(...bucket.slice(0, DISPLAY_LIMIT - failed.length));
  }

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
  return {
    daemon: { owner: owner ?? null, last_heartbeat: at ? Number(at) : null },
    retrying,
    failed,
    actionable_failures: actionableFailures,
    guard,
  };
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
