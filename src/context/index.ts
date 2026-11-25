import { Cron } from "croner";
import { z } from "zod";
import type { App } from "../app.ts";
import type { CtxCycleReport, CtxDraftKind, CtxItemStatus, CtxItemView, CommandResult } from "../api/types.ts";
import { consoleBaseUrl } from "../server/index.ts";
import { CommandError } from "../commands.ts";
import { card as cardEffect, notify } from "../effects.ts";
import type { Handler } from "../engine.ts";
import type { Effect, NotifyKind } from "../ledger.ts";
import { deepFind, errMsg, log, runProcess, truncate } from "../util.ts";
import { draftCard, eveningCard, itemCard, KIND_LABEL, morningCard, type CtxRenderCtx } from "./cards.ts";
import { Connectors, relinkMeegoItems } from "./connectors.ts";
import { defaultDraftKind, Drafter } from "./drafts.ts";
import { ContextStore, type ItemRow } from "./store.ts";
import { splitProject, Understander, type SplitResult } from "./understand.ts";
import { ContextViews, startOfDay } from "./views.ts";

/**
 * 工作上下文模块：
 *   采集（Meego / 飞书任务 / 消息 / 妙记 / 日历） → 理解（模型抽取项目、事项、知识、动态、人、冲突，带证据）
 *   → 视图（今天 / 项目 / 事项 / 知识 / 动态 / 人） → 主动反馈（晨间卡、收尾卡、实时提醒）
 *   → 推进（起草回复 / 跟进 / Meego 评论 / 周报，你确认后以你本人身份执行；可选委托给 Agent）。
 *
 * 自主等级：
 *   L0 提醒（卡片）  L1 起草（需确认）  L2 只影响你自己的低风险动作（autonomy 开关）  L3 委托（dispatch.create）
 * 对外可见的动作（发消息、写 Meego、建文档）永远只在你确认草稿后发生。
 */

const HOUR = 3_600_000;
const DAY = 24 * HOUR;

type CtxPayload = { task: "cycle" } | { task: "draft"; item_id: string; kind?: CtxDraftKind } | { task: "weekly"; days: number } | { task: "split"; project_id: string };

export class ContextService {
  app: App;
  store: ContextStore;
  connectors: Connectors;
  understander: Understander;
  views: ContextViews;
  drafter: Drafter;
  running = false;

  constructor(app: App) {
    this.app = app;
    this.store = new ContextStore(app.store.db);
    this.connectors = new Connectors(app, this.store);
    this.understander = new Understander(app, this.store);
    this.views = new ContextViews(app, this.store);
    this.drafter = new Drafter(app, this.store);
  }

  private get cfg() {
    return this.app.cfg;
  }

  renderCtx(notice?: string): CtxRenderCtx {
    const { cfg } = this;
    return { consoleBase: cfg.server.enabled ? consoleBaseUrl(cfg.server.host, cfg.server.port) : "", timezone: cfg.owner.timezone, notice };
  }

  cardsOn(): boolean {
    return !!this.app.ext.cards && this.cfg.cards.enabled;
  }

  private emitCard(key: string, json: Record<string, unknown>, kind?: NotifyKind, dedupe?: string): void {
    this.app.ledger.emit(`card:${key}`, [cardEffect(key, json, kind)], dedupe);
    this.app.engine.kick();
  }

  draftable(it: Pick<CtxItemView, "id">): boolean {
    const row = this.store.item(it.id);
    if (!row) return false;
    const k = defaultDraftKind(row);
    if (!k) return false;
    try {
      this.drafter.target(row, k);
      return true;
    } catch {
      return false;
    }
  }

  // ───────── 周期 ─────────

  enqueue(id: string, payload: CtxPayload): boolean {
    const added = this.app.ledger.enqueue({ id: `context:${id}`, kind: "context", ref: payload.task, payload });
    if (added) this.app.engine.kick();
    return added;
  }

  /** 一轮：唤醒稍后事项 → 采集 → 理解 → 挂接 → 提醒 / 自主动作 */
  async cycle(workId: string, signal?: AbortSignal): Promise<CtxCycleReport> {
    const rep: CtxCycleReport = { skipped: false, sources: [], convs: 0, created: 0, closed: 0, knowledge: 0, updates: 0, conflicts: 0, rejected: 0, nudged: 0, errors: [] };
    if (this.running) return { ...rep, skipped: true };
    this.running = true;
    const kv = this.app.store;
    try {
      this.store.wakeSnoozed();
      rep.sources = await this.connectors.pullAll();
      for (const s of rep.sources) if (s.error) rep.errors.push(`${s.source}: ${s.error}`);
      await this.ensureOwnerName();
      const created: ItemRow[] = [];
      if (this.cfg.context.understand) {
        // 每轮最多理解 max_convs_per_cycle 个会话批次；并行跑 understand_parallel 批（会话互不重叠）
        let budget = this.cfg.context.max_convs_per_cycle;
        const par = this.cfg.context.understand_parallel;
        while (budget > 0 && !signal?.aborted) {
          const pending = this.store.pendingConvs(Math.min(budget, 8 * par));
          if (!pending.length) break;
          const groups: (typeof pending)[] = Array.from({ length: Math.min(par, pending.length) }, () => []);
          pending.forEach((c, i) => groups[i % groups.length].push(c));
          const results = await Promise.allSettled(groups.map((g) => this.understander.runBatch(workId, g, signal)));
          if (signal?.aborted) throw new Error("aborted");
          let progress = 0;
          results.forEach((res, gi) => {
            if (res.status === "fulfilled") {
              const r = res.value;
              progress += r.fresh;
              budget -= Math.max(1, r.convs.length);
              rep.convs += r.convs.length;
              rep.created += r.created.length;
              rep.closed += r.closed.length;
              rep.knowledge += r.knowledge;
              rep.updates += r.updates;
              rep.conflicts += r.conflicts;
              rep.rejected += r.rejected;
              created.push(...r.created);
              for (const c of r.convs) kv.db.prepare("DELETE FROM kv WHERE k = ?").run(`ctx.fail.${c}`);
              return;
            }
            budget -= groups[gi].length;
            rep.errors.push(`理解失败：${truncate(errMsg(res.reason), 300)}`);
            // 同一会话连续失败 3 次就跳过，避免卡住后面的消息
            for (const c of groups[gi]) {
              const n = Number(kv.get(`ctx.fail.${c.conv}`) ?? 0) + 1;
              kv.set(`ctx.fail.${c.conv}`, String(n));
              if (n >= 3) {
                const skipped = this.store.skipConv(c.conv);
                log("warn", "会话理解连续失败，已跳过", { conv: c.conv_name, skipped });
              }
            }
          });
          if (!progress) break; // 本轮全部失败或没有进展：等下一轮
        }
      }
      relinkMeegoItems(this.store);
      this.store.mergeConflicts();
      this.markNotImportant();
      this.syncDrafts();
      rep.nudged = this.nudge(created);
      this.autonomy(created);
      kv.set("ctx.last_cycle", String(Date.now()));
      kv.set("ctx.last_error", rep.errors.join("\n").slice(0, 1000));
      kv.set("ctx.last_report", JSON.stringify(rep));
      return rep;
    } catch (e) {
      kv.set("ctx.last_error", truncate(errMsg(e), 1000));
      throw e;
    } finally {
      this.running = false;
    }
  }

  private async ensureOwnerName(): Promise<void> {
    if (this.app.store.get("ctx.owner_name")) return;
    try {
      // 新版 lark-cli 的 auth status 是裸 JSON（没有 ok/data 信封）
      const r = await runProcess(this.cfg.bins.lark, ["auth", "status", "--json"], { timeoutMs: 30_000, cwd: this.cfg.dataDir });
      const st = JSON.parse(r.stdout.trim() || "{}") as unknown;
      const name = String(deepFind(st, "userName") ?? deepFind(st, "user_name") ?? deepFind(st, "name") ?? "");
      if (name) this.app.store.set("ctx.owner_name", name);
    } catch (e) {
      log("warn", "取不到你的飞书名字", { err: errMsg(e) });
    }
  }

  /** 你说不重要的类型（context.not_important）：标题匹配的未关闭事项自动降为不重要 */
  markNotImportant(): number {
    const res = this.cfg.context.not_important.flatMap((p) => {
      try {
        return [new RegExp(p, "i")];
      } catch {
        return [];
      }
    });
    if (!res.length) return 0;
    let n = 0;
    for (const it of this.store.items({ status: ["open", "snoozed"], limit: 5000 })) {
      if (it.feedback || !res.some((re) => re.test(it.title))) continue;
      this.store.setItemField(it.id, { feedback: "unimportant", meta: { auto_unimportant: true } });
      n++;
    }
    return n;
  }

  /** 实时提醒：新出现的、近期的、高优先级的请求 / 风险 / 快到期的承诺。每轮最多 3 条。 */
  nudge(created: ItemRow[], now = Date.now()): number {
    if (!this.cfg.context.nudge) return 0;
    const picks = created
      .map((c) => this.store.item(c.id))
      .filter((it): it is ItemRow => !!it && it.status === "open" && !it.nudged_at && !it.meta.needs_review && !it.meta.legacy && !it.feedback && it.last_seen >= now - 6 * HOUR)
      .filter((it) => {
        const p = this.store.project(it.project_id);
        if (this.store.hidden(p)) return false;
        const urgent = (it.kind === "ask_me" || it.kind === "risk") && it.priority === "high";
        const dueSoon = !!it.due && it.due < now + 2 * DAY && (it.kind === "ask_me" || it.kind === "my_commitment");
        return urgent || dueSoon;
      })
      .slice(0, 3);
    for (const it of picks) {
      this.store.setItemField(it.id, { nudged_at: now });
      this.sendItem(it.id, undefined, "nudge", `ctx-nudge-${it.id}`);
    }
    return picks.length;
  }

  sendItem(id: string, notice?: string, kind?: NotifyKind, dedupe?: string): void {
    const d = this.views.itemDetail(id, []);
    if (!d) return;
    if (this.cardsOn()) return this.emitCard(`ctx-item:${id}`, itemCard(d, this.renderCtx(notice), this.draftable(d)), kind, dedupe);
    if (notice) return; // 没启用卡片时，操作结果不再私信
    const ev = d.evidence[0];
    const text = `**${KIND_LABEL[d.kind] ?? "提醒"}：${d.title}**\n${[d.project_name, d.counterpart && `对方 ${d.counterpart}`, d.next_step && `建议：${d.next_step}`].filter(Boolean).join(" ｜ ")}${ev ? `\n> ${truncate(ev.quote, 120)}` : ""}`;
    this.app.ledger.emit(`context:item:${id}`, [notify(text, kind)], dedupe);
    this.app.engine.kick();
  }

  /** L2：只影响你自己的低风险动作 */
  autonomy(created: ItemRow[]): void {
    if (!this.cfg.context.autonomy.create_own_todo) return;
    for (const it of created) {
      const cur = this.store.item(it.id);
      if (!cur || cur.kind !== "my_commitment" || cur.status !== "open" || cur.meta.needs_review || cur.meta.own_task) continue;
      const ev = this.store.lastEvidenceObs("item", cur.id);
      const e: Effect = {
        op: "task.create_own",
        args: { summary: cur.title, description: `${cur.next_step ? `下一步：${cur.next_step}\n` : ""}${ev?.url ? `来源：${ev.url}` : ""}`.trim() || cur.title, due: cur.due ? new Date(cur.due).toISOString() : undefined, item_id: cur.id },
      };
      this.store.setItemField(cur.id, { meta: { own_task: true } });
      this.app.ledger.emit(`context:own-todo:${cur.id}`, [e], `ctx-own-${cur.id}`);
    }
  }

  // ───────── 晨间 / 收尾 ─────────

  today(): string {
    return new Intl.DateTimeFormat("en-CA", { timeZone: this.cfg.owner.timezone }).format(new Date());
  }

  renderMorning(date: string, notice?: string, dedupe?: string): void {
    const t = { ...this.views.today(this.running), date };
    const draftable = (it: CtxItemView) => this.draftable(it);
    this.emitCard(`ctx-morning:${date}`, morningCard(t, this.renderCtx(notice), draftable), notice ? undefined : "brief", dedupe);
  }

  eveningView(date: string) {
    const sod = startOfDay(this.cfg.owner.timezone);
    const open = this.views.openItems();
    return {
      date,
      closed: this.store.closedSince(sod).map((i) => this.views.itemView(i)),
      asks: open.filter((i) => i.kind === "ask_me"),
      tomorrow: open.filter((i) => !i.needs_review).slice(0, 3),
      changes: this.store.updates({ since: sod, limit: 20 }).map((u) => this.views.updateView(u)),
    };
  }

  renderEvening(date: string, notice?: string, dedupe?: string): void {
    this.emitCard(`ctx-evening:${date}`, eveningCard(this.eveningView(date), this.renderCtx(notice)), notice ? undefined : "brief", dedupe);
  }

  sendDigest(mode: "morning" | "evening"): void {
    const date = this.today();
    if (this.cardsOn()) {
      if (mode === "morning") this.renderMorning(date, undefined, `ctx-morning-${date}`);
      else this.renderEvening(date, undefined, `ctx-evening-${date}`);
      return;
    }
    this.app.ledger.emit("context:digest", [notify(this.digestText(mode), "brief")], `ctx-${mode}-${date}`);
    this.app.engine.kick();
  }

  digestText(mode: "morning" | "evening"): string {
    const tz = this.cfg.owner.timezone;
    if (mode === "morning") {
      const t = this.views.today(this.running);
      const lines = [`**今天 · ${t.date}**`];
      if (t.focus.length) lines.push("**先做这几件**", ...t.focus.slice(0, 6).map((i, n) => `${n + 1}. 【${KIND_LABEL[i.kind]}】${i.title}${i.project_name ? `（${i.project_name}）` : ""}`));
      if (t.conflicts.length) lines.push("**需要你判断**", ...t.conflicts.slice(0, 3).map((c) => `- ${c.topic}`));
      if (t.meetings.length) lines.push("**今天的会**", ...t.meetings.map((m) => `- ${new Date(m.start).toLocaleTimeString("zh-CN", { timeZone: tz, hour: "2-digit", minute: "2-digit" })} ${m.summary}`));
      return lines.join("\n");
    }
    const v = this.eveningView(this.today());
    return [`**收尾 · ${v.date}**`, `今天关掉 ${v.closed.length} 件，还欠着别人 ${v.asks.length} 件。`, ...v.tomorrow.map((i, n) => `${n + 1}. ${i.title}`)].join("\n");
  }

  // ───────── 草稿 ─────────

  renderDraft(id: string, notice?: string): void {
    const d = this.store.draft(id);
    if (!d || !this.cardsOn()) return;
    const it = d.item_id ? this.store.item(d.item_id) : undefined;
    this.emitCard(`ctx-draft:${id}`, draftCard(this.views.draftView(d), this.renderCtx(notice), it?.title ?? ""));
  }

  /**
   * 草稿对应的对外动作落定后，回写草稿状态。状态从 outbox 推导（总线只是提示）：
   * 落定事件、每轮周期、每次读取草稿列表时都会对一遍，进程中途退出也不会卡在“发送中”。
   */
  syncDraft(id: string, render = true): void {
    const d = this.store.draft(id);
    if (!d || d.status !== "approved") return;
    const fx = this.app.ledger.effectsOf(`ctx-draft:${id}`).at(-1);
    if (!fx || !fx.terminal) return;
    if (fx.state === "done") {
      const url = this.app.store.get(`effect.result.${fx.id}`);
      this.store.setDraft(d.id, { status: "sent", error: "", ...(url ? { target: { ...d.target, url } } : {}) });
      // 回复 / 评论发出去了：记一笔，不自动关闭事项，等下一轮证据（对方确认等）
      if (d.item_id) this.store.setItemField(d.item_id, { meta: { replied_at: Date.now() } });
    } else {
      this.store.setDraft(d.id, { status: "failed", error: fx.error || `发送失败（${fx.state}）` });
    }
    if (render) this.renderDraft(d.id);
  }

  syncDrafts(): void {
    for (const d of this.store.drafts({ status: ["approved"] })) this.syncDraft(d.id);
  }

  // ───────── 引擎 ─────────

  handler(): Handler<CtxPayload> {
    return {
      kind: "context",
      concurrency: 2,
      maxAttempts: 2,
      run: async (item, ctx) => {
        const p = item.payload;
        if (p.task === "cycle") {
          const r = await this.cycle(item.id, ctx.signal);
          this.app.ledger.transition(item, { state: r.skipped ? "skipped" : "done", terminal: true, payload: { ...p, report: r } as never });
          return;
        }
        if (p.task === "draft") {
          const d = await this.drafter.forItem(p.item_id, p.kind);
          this.app.ledger.transition(item, { state: "done", terminal: true, payload: { ...p, draft_id: d.id } as never });
          this.renderDraft(d.id);
          return;
        }
        if (p.task === "split") {
          const r = await splitProject(this.understander, item.id, p.project_id, ctx.signal);
          this.app.ledger.transition(item, { state: "done", terminal: true, payload: { ...p, result: r } as never });
          return;
        }
        if (p.task === "weekly") {
          const d = await this.drafter.weekly(p.days);
          this.app.ledger.transition(item, { state: "done", terminal: true, payload: { ...p, draft_id: d.id } as never });
          this.renderDraft(d.id);
          return;
        }
        this.app.ledger.transition(item, { state: "skipped", terminal: true });
      },
      onExhausted: (item, err) => {
        const p = item.payload;
        if (p.task === "cycle") return { patch: { state: "errored" } };
        const what = p.task === "draft" ? "起草" : p.task === "split" ? "拆分子项目" : "周报草稿";
        return { patch: { state: "errored" }, effects: [notify(`⚠️ ${what}没有成功：${truncate(err, 300)}`, "failure")] };
      },
    };
  }

  /** 常驻进程的定时任务 */
  start(): { stop(): void } {
    const c = this.cfg.context;
    const opts = { timezone: this.cfg.owner.timezone, protect: true };
    const slot = (cr: Cron) => (cr.currentRun() ?? new Date()).toISOString().slice(0, 16);
    const guard = (name: string, fn: (cr: Cron) => void) => (cr: Cron) => {
      try {
        fn(cr);
      } catch (e) {
        log("error", `${name} 失败`, { err: errMsg(e) });
      }
    };
    const crons = [
      new Cron(c.schedule, opts, guard("工作上下文采集", (cr) => void this.enqueue(`cycle:${slot(cr)}`, { task: "cycle" }))),
      new Cron(c.morning, opts, guard("晨间卡", () => this.sendDigest("morning"))),
      new Cron(c.evening, opts, guard("收尾卡", () => this.sendDigest("evening"))),
      new Cron(c.weekly, opts, guard("周报草稿", (cr) => void this.enqueue(`weekly:${slot(cr)}`, { task: "weekly", days: 7 }))),
    ];
    // 启动后先跑一轮（停机期间的消息）
    const t = setTimeout(() => this.enqueue(`cycle:start-${Date.now()}`, { task: "cycle" }), 5000);
    return {
      stop: () => {
        clearTimeout(t);
        crons.forEach((x) => x.stop());
      },
    };
  }

  /** 立即拆分一个项目（命令行用） */
  async splitNow(key: string): Promise<SplitResult> {
    const p = this.store.findProject(key);
    if (!p) throw new Error(`没有找到项目：${key}`);
    const id = `split:${p.id}:${Date.now()}`;
    this.enqueue(id, { task: "split", project_id: p.id });
    await this.app.engine.drain(["context"]);
    const w = this.app.ledger.get<{ result?: SplitResult }>(`context:${id}`);
    if (w?.payload.result) return w.payload.result;
    throw new Error(`拆分没有完成：${w?.state ?? "未知"}${w?.error ? `（${w.error}）` : ""}`);
  }

  async runOnce(): Promise<CtxCycleReport> {
    const id = `cycle:manual-${Date.now()}`;
    this.enqueue(id, { task: "cycle" });
    await this.app.engine.drain(["context", "effect"]);
    const w = this.app.ledger.get<{ report?: CtxCycleReport }>(`context:${id}`);
    if (w?.payload.report) return w.payload.report;
    throw new Error(`采集没有完成：${w?.state ?? "未知"}${w?.error ? `（${w.error}）` : ""}`);
  }

  // ───────── 查询 ─────────

  items(f: { status?: string; kind?: string; project?: string; q?: string }): CtxItemView[] {
    let list: CtxItemView[];
    if (!f.status || f.status === "open") list = this.views.openItems();
    else if (f.status === "review") list = this.views.openItems().filter((i) => i.needs_review);
    else {
      const status = f.status === "all" ? undefined : ([f.status] as CtxItemStatus[]);
      list = this.store.items({ status, limit: 1000 }).map((i) => this.views.itemView(i));
    }
    if (f.kind) list = list.filter((i) => i.kind === f.kind);
    if (f.project) list = list.filter((i) => i.project_id === f.project);
    if (f.q) {
      const q = f.q.toLowerCase();
      list = list.filter((i) => `${i.title} ${i.counterpart} ${i.project_name} ${i.next_step}`.toLowerCase().includes(q));
    }
    return list.slice(0, 500);
  }

  itemActions(id: string): string[] {
    const it = this.store.item(id);
    if (!it) return [];
    const a: string[] = it.status === "open" ? ["context.item_done", "context.item_snooze", "context.feedback"] : ["context.item_reopen"];
    if (it.status === "open" && this.draftable(it)) a.push("context.draft_create");
    if (it.status === "open" && this.app.commands.has("dispatch.create")) a.push("context.item_delegate");
    return a;
  }
}

const id = z.string().min(1);

export function registerContext(app: App): ContextService | undefined {
  if (!app.cfg.context.enabled) return undefined;
  const svc = new ContextService(app);
  const { commands, ledger, bus } = app;
  app.engine.register(svc.handler());
  bus.on("effect.settled", (e) => {
    if (e.ref.startsWith("ctx-draft:")) svc.syncDraft(e.ref.slice("ctx-draft:".length));
  });

  const ok = (message: string, target = ""): CommandResult => ({ ok: true, message, target });
  const needItem = (itemId: string) => {
    const it = svc.store.item(itemId);
    if (!it) throw new CommandError("not_found", `没有这个事项：${itemId}`);
    return it;
  };
  const snapshot = (it: ItemRow) => `${it.kind}｜${it.title}｜${svc.store.lastEvidenceObs("item", it.id)?.text.slice(0, 160) ?? ""}`;

  commands.register({
    name: "context.refresh",
    title: "立即采集并理解最新的消息与待办",
    schema: z.object({}).strict() as never,
    target: () => "context",
    run: async () => {
      if (svc.running) return ok("正在采集中，稍后自动刷新");
      svc.enqueue(`cycle:manual-${Date.now()}`, { task: "cycle" });
      return ok("开始采集，完成后页面会自动刷新");
    },
  });

  commands.register({
    name: "context.item_done",
    title: "把事项标为完成",
    schema: z.object({ id, note: z.string().max(500).optional() }),
    target: (a) => a.id,
    run: async (a) => {
      const it = needItem(a.id);
      if (it.status === "done") throw new CommandError("conflict", "已经是完成状态");
      svc.store.setItemStatus(it.id, "done", { reason: a.note || "你标记完成" });
      svc.store.addFeedback("item", it.id, "right", "done", snapshot(it));
      return ok("已完成", it.id);
    },
  });

  commands.register({
    name: "context.item_reopen",
    title: "重新打开事项",
    schema: z.object({ id }),
    target: (a) => a.id,
    run: async (a) => {
      const it = needItem(a.id);
      if (it.status === "open") throw new CommandError("conflict", "事项本来就是打开的");
      svc.store.setItemStatus(it.id, "open", { lock: false });
      if (it.feedback === "wrong") svc.store.setItemField(it.id, { feedback: "" });
      return ok("已重新打开", it.id);
    },
  });

  commands.register({
    name: "context.item_snooze",
    title: "稍后再提醒",
    schema: z.object({ id, hours: z.coerce.number().min(0.25).max(24 * 30).optional(), until: z.string().optional() }),
    target: (a) => a.id,
    run: async (a) => {
      const it = needItem(a.id);
      const until = a.until ? Date.parse(a.until) : Date.now() + (a.hours ?? 4) * HOUR;
      if (Number.isNaN(until) || until <= Date.now()) throw new CommandError("invalid", "提醒时间不对");
      svc.store.setItemStatus(it.id, "snoozed", { snoozeUntil: until, lock: false });
      const when = new Date(until).toLocaleString("zh-CN", { timeZone: app.cfg.owner.timezone, month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit" });
      return ok(`${when} 再提醒你`, it.id);
    },
  });

  commands.register({
    name: "context.item_delegate",
    title: "把事项交给 Agent 执行（新建派单）",
    schema: z.object({ id, harness: z.string().optional(), repo: z.string().optional() }),
    target: (a) => a.id,
    run: async (a, ctx) => {
      const it = needItem(a.id);
      if (!commands.has("dispatch.create")) throw new CommandError("unavailable", "派单功能未启用");
      const ev = svc.views.evidence("item", it.id, 5);
      const description = [
        it.next_step ? `目标：${it.next_step}` : "",
        it.counterpart ? `相关的人：${it.counterpart}` : "",
        ev.length ? `背景（来自工作上下文）：\n${ev.map((e) => `- ${e.actor_name}${e.conv_name ? `@${e.conv_name}` : ""}：${e.quote}${e.url ? ` ${e.url}` : ""}`).join("\n")}` : "",
      ]
        .filter(Boolean)
        .join("\n\n");
      const r = await commands.exec("dispatch.create", { summary: it.title.slice(0, 120), description, harness: a.harness, repo: a.repo }, ctx);
      svc.store.setItemField(it.id, { meta: { delegated: r.target ?? "" } });
      return { ...r, message: `已交给 Agent：${r.message}` };
    },
  });

  commands.register({
    name: "context.feedback",
    title: "告诉我识别得对不对",
    schema: z.object({ entity: z.enum(["item", "project", "knowledge", "update", "person"]), id, verdict: z.enum(["right", "wrong", "unimportant"]), note: z.string().max(500).optional() }),
    target: (a) => a.id,
    run: async (a) => {
      const note = a.note ?? "";
      switch (a.entity) {
        case "item": {
          const it = needItem(a.id);
          svc.store.addFeedback("item", it.id, a.verdict, note, snapshot(it));
          svc.store.setItemField(it.id, { feedback: a.verdict });
          if (a.verdict === "wrong") svc.store.setItemStatus(it.id, "dismissed", { reason: note || "你说识别错了" });
          return ok(a.verdict === "wrong" ? "已移除，之后会参考这次判断" : a.verdict === "unimportant" ? "已降低优先级" : "收到，识别正确", it.id);
        }
        case "project": {
          const p = svc.store.project(a.id);
          if (!p) throw new CommandError("not_found", "没有这个项目");
          svc.store.addFeedback("project", p.id, a.verdict, note, `项目｜${p.name}`);
          if (a.verdict === "wrong") svc.store.setProject(p.id, { status: "archived", muted: true, pinned: true });
          if (a.verdict === "unimportant") svc.store.setProject(p.id, { muted: true, pinned: true });
          return ok("收到", p.id);
        }
        case "knowledge":
        case "update": {
          svc.store.addFeedback(a.entity, a.id, a.verdict, note, "");
          if (a.verdict === "wrong") svc.store.deleteEntity(a.entity, a.id);
          return ok(a.verdict === "wrong" ? "已删除" : "收到", a.id);
        }
        case "person":
          svc.store.addFeedback("person", a.id, a.verdict, note, "");
          return ok("收到", a.id);
      }
    },
  });

  commands.register({
    name: "context.project_mute",
    title: "静音 / 取消静音项目",
    schema: z.object({ id, muted: z.boolean() }),
    target: (a) => a.id,
    run: async (a) => {
      const p = svc.store.project(a.id);
      if (!p) throw new CommandError("not_found", "没有这个项目");
      svc.store.setProject(p.id, a.muted ? { muted: true, pinned: true } : { muted: false, status: "active", pinned: true });
      return ok(a.muted ? `已静音「${p.name}」，它的事项不再出现在今天` : `已恢复「${p.name}」`, p.id);
    },
  });

  commands.register({
    name: "context.project_split",
    title: "把项目拆成子项目",
    schema: z.object({ id }),
    target: (a) => a.id,
    run: async (a) => {
      const p = svc.store.project(a.id);
      if (!p) throw new CommandError("not_found", "没有这个项目");
      if (p.parent_id) throw new CommandError("invalid", "只能拆分顶层项目");
      const busy = ledger.list({ kinds: ["context"], states: ["pending"], ref: "split", limit: 20 }).some((w) => (w.payload as { project_id?: string }).project_id === p.id && !w.terminal);
      if (busy) return ok("正在拆分中", p.id);
      svc.enqueue(`split:${p.id}:${Date.now()}`, { task: "split", project_id: p.id });
      return ok(`正在把「${p.name}」拆成子项目，完成后页面会自动刷新`, p.id);
    },
  });

  commands.register({
    name: "context.conv_mute",
    title: "不再读取某个会话",
    schema: z.object({ conv: id, muted: z.boolean(), name: z.string().optional() }),
    target: (a) => a.conv,
    run: async (a) => {
      svc.store.muteConv(a.conv, a.name ?? "", a.muted);
      return ok(a.muted ? "这个会话之后不再读取" : "已恢复读取", a.conv);
    },
  });

  commands.register({
    name: "context.conflict_resolve",
    title: "确认冲突的结论",
    schema: z.object({ id, choice: z.coerce.number().int().min(0).optional(), resolution: z.string().max(1000).optional() }),
    target: (a) => a.id,
    run: async (a) => {
      const c = svc.store.conflict(a.id);
      if (!c) throw new CommandError("not_found", "没有这个冲突");
      if (c.status === "resolved") throw new CommandError("conflict", "已经确认过了");
      const chosen = a.choice !== undefined ? c.claims[a.choice] : undefined;
      const resolution = a.resolution?.trim() || chosen?.claim;
      if (!resolution) throw new CommandError("invalid", "请选择一个说法或写下结论");
      svc.store.resolveConflict(c.id, resolution);
      // 你的判断沉淀为一条决策知识
      const k = svc.store.upsertKnowledge({ project_id: c.project_id, kind: "decision", title: c.topic, content: resolution, confidence: 1 });
      if (chosen) svc.store.addEvidence("knowledge", k.id, chosen.obs_id, chosen.quote, chosen.time);
      return ok(`已确认：${truncate(resolution, 60)}`, c.id);
    },
  });

  commands.register({
    name: "context.draft_create",
    title: "为事项起草回复 / 跟进 / Meego 评论",
    schema: z.object({ item_id: id, kind: z.enum(["reply", "followup", "meego_comment"]).optional() }),
    target: (a) => a.item_id,
    run: async (a) => {
      const it = needItem(a.item_id);
      const k = a.kind ?? defaultDraftKind(it);
      if (!k) throw new CommandError("invalid", "这个事项没有合适的草稿类型");
      try {
        svc.drafter.target(it, k);
      } catch (e) {
        throw new CommandError("invalid", errMsg(e));
      }
      const running = ledger.list({ kinds: ["context"], states: ["pending"], ref: "draft", limit: 50 }).some((w) => (w.payload as { item_id?: string }).item_id === it.id && !w.terminal);
      if (running) return ok("正在起草中", it.id);
      svc.enqueue(`draft:${it.id}:${k}:${Date.now()}`, { task: "draft", item_id: it.id, kind: k });
      return ok(svc.cardsOn() ? "正在起草，好了会发草稿卡片给你确认" : "正在起草，好了会出现在草稿列表", it.id);
    },
  });

  commands.register({
    name: "context.draft_approve",
    title: "确认草稿并以你本人身份发送",
    schema: z.object({ id, content: z.string().max(8000).optional() }),
    target: (a) => a.id,
    run: async (a) => {
      const d = svc.store.draft(a.id);
      if (!d) throw new CommandError("not_found", "没有这份草稿");
      const content = a.content?.trim() || d.content;
      if (!content.trim()) throw new CommandError("invalid", "内容不能为空");
      const effect = svc.drafter.effectFor(d, content);
      if (!svc.store.casDraft(d.id, ["proposed", "failed"], "approved", content)) {
        throw new CommandError("conflict", d.status === "sent" ? "已经发送过了" : d.status === "discarded" ? "草稿已丢弃" : "正在发送中");
      }
      ledger.emit(`ctx-draft:${d.id}`, [effect], `ctx-draft-${d.id}-${Date.now()}`);
      return ok(d.kind === "weekly_report" ? "正在新建文档" : "正在以你的身份发送", d.id);
    },
  });

  commands.register({
    name: "context.draft_discard",
    title: "丢弃草稿",
    schema: z.object({ id }),
    target: (a) => a.id,
    run: async (a) => {
      if (!svc.store.casDraft(a.id, ["proposed", "failed"], "discarded")) throw new CommandError("conflict", "这份草稿已经处理过了");
      return ok("已丢弃", a.id);
    },
  });

  commands.register({
    name: "context.weekly_report",
    title: "起草周报",
    schema: z.object({ days: z.coerce.number().int().min(1).max(31).optional() }),
    target: () => "weekly",
    run: async (a) => {
      svc.enqueue(`weekly:manual-${Date.now()}`, { task: "weekly", days: a.days ?? 7 });
      return ok("正在起草周报，好了会出现在草稿里");
    },
  });

  // 卡片：操作后原地刷新
  const cards = app.ext.cards;
  if (cards?.register) {
    cards.register("ctx-item", (itemId, notice) => svc.sendItem(itemId, notice), (itemId) => ({ id: itemId }));
    cards.register("ctx-draft", (draftId, notice) => svc.renderDraft(draftId, notice), (draftId) => ({ id: draftId }));
    cards.register("ctx-morning", (date, notice) => svc.renderMorning(date, notice));
    cards.register("ctx-evening", (date, notice) => svc.renderEvening(date, notice));
  }

  app.ext.context = {
    today: () => (svc.syncDrafts(), svc.views.today(svc.running)),
    projects: (o) => svc.views.projects(!!o.legacy),
    project: (pid) => svc.views.projectDetail(pid),
    items: (f) => svc.items(f),
    item: (iid) => svc.views.itemDetail(iid, svc.itemActions(iid)),
    knowledge: (f) => svc.store.knowledge({ q: f.q, project_id: f.project }).map((k) => svc.views.knowledgeView(k)),
    updates: (f) => svc.store.updates({ since: Date.now() - (f.days ?? 7) * DAY, project_id: f.project, limit: 300 }).map((u) => svc.views.updateView(u)),
    people: () => svc.views.people(),
    conflicts: (status) => svc.store.conflicts(status).map((c) => svc.views.conflictView(c)),
    drafts: (status) => (svc.syncDrafts(), svc.store).drafts(status ? { status: status.split(",") as never } : {}).map((d) => svc.views.draftView(d)),
    status: () => svc.views.status(svc.running),
    start: () => svc.start(),
    refresh: () => void svc.enqueue(`cycle:hint-${Math.floor(Date.now() / 60_000)}`, { task: "cycle" }),
    runOnce: () => svc.runOnce(),
    split: (key) => svc.splitNow(key),
    sendDigest: (mode) => svc.sendDigest(mode),
  };
  return svc;
}
