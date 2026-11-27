import type { App } from "../app.ts";
import { summarize, taskUrl } from "../api/queries.ts";
import type { CommandName } from "../api/types.ts";
import type { BusEvents } from "../bus.ts";
import { availableActions } from "../core-commands.ts";
import { card as cardEffect, notify } from "../effects.ts";
import type { Effect, NotifyKind, WorkItem } from "../ledger.ts";
import { consoleBaseUrl, serverToken, signLoginTicket } from "../server/index.ts";
import { errMsg, log, truncate } from "../util.ts";
import type { DispatchPayload } from "../workflows/dispatch.ts";
import { parseAction } from "./actions.ts";
import {
  briefCard,
  candidateCard,
  dispatchCard,
  doFormCard,
  failureCard,
  type Card,
  type CandidateCardView,
  type DispatchCardView,
  type DoFormView,
  type FailureCardView,
  type RenderCtx,
} from "./templates.ts";

/**
 * 卡片服务：把账本里的变化渲染成飞书交互卡片，经 outbox（card.upsert）发送 / 原地更新；
 * 把卡片上的按钮回调（card.action.trigger，经 inbox）交给命令层执行。
 *
 *   一个对象一张卡片：dispatch:<任务 guid>（跟随这张任务的所有派单）、candidate:<signal id>、
 *   failure:<work id>、brief:<日期>-<mode>、do:<私聊消息 id>（/do 表单）。
 *
 * 总线只是“提示”：进行中的变化按卡片去抖（默认 800ms）合并成一次更新，终态立即渲染（同步写进 outbox，
 * 命令行单次运行也能在 drain 时发出去）。同一张卡片的更新以 card:<key> 为 parent 落库，按顺序投递。
 */

export interface CardOptions {
  /** 进行中变化的去抖时间 */
  debounceMs?: number;
}

const FAILED = ["dead", "errored"];

const CMD_TEXT: Partial<Record<CommandName, string>> = {
  "dispatch.create": "新建派单",
  "dispatch.cancel": "取消",
  "dispatch.retry": "重试",
  "dispatch.rework": "带意见返工",
  "dispatch.switch_harness": "换执行者重试",
  "delivery.create_pr": "创建 PR",
  "delivery.merge_local": "合并到本地分支",
  "delivery.discard": "放弃",
  "delivery.restore": "恢复",
  "candidate.confirm": "是任务",
  "candidate.reject": "不是任务",
  "candidate.dispatch": "派给 Agent",
  "work.retry": "重试",
  "work.acknowledge": "忽略",
  "context.item_done": "完成",
  "context.item_reopen": "重新打开",
  "context.item_snooze": "稍后提醒",
  "context.item_delegate": "交给 Agent",
  "context.feedback": "反馈",
  "context.conflict_resolve": "确认结论",
  "context.draft_create": "起草",
  "context.draft_approve": "确认发送",
  "context.draft_discard": "丢弃草稿",
  "context.project_mute": "静音项目",
  "context.conv_mute": "静音会话",
  "context.weekly_report": "起草周报",
  "context.refresh": "刷新",
  "context.project_split": "拆分子项目",
};

const EVENT_TEXT: Record<string, string> = {
  "im.message.receive_v1": "私聊机器人的消息",
  "drive.notice.comment_add_v1": "文档评论",
  "minutes.minute.generated_v1": "会议妙记",
  "task.task.update_user_access_v2": "任务变更通知",
  "card.action.trigger": "卡片按钮操作",
};

const DELIVERY_ACTION_TEXT: Record<string, string> = { create_pr: "创建 PR", merge_local: "合并到本地分支", discard: "放弃", restore: "恢复" };

/** 候选任务卡片需要、但信号表里没有的信息（建卡时取一次，之后刷新卡片用缓存）。 */
interface CandidateInfo {
  taskGuid: string;
  summary: string;
  section: string;
  reason: string;
  dueMs: number | null;
  feedback: "" | "confirmed" | "rejected" | "dispatched";
}

interface ActionResult {
  ok: boolean;
  message: string;
  target: string;
}

export type CardRenderer = (id: string, notice: string, cmd: string, args: Record<string, unknown>, res: { ok: boolean; message: string; target: string }) => void;

export class CardService {
  app: App;
  debounceMs: number;
  /** 其他模块的卡片：key 前缀 → 操作后的重新渲染 */
  renderers = new Map<string, CardRenderer>();
  /** 其他模块的卡片：key 前缀 → 表单兜底时补上的操作对象参数 */
  targetResolvers = new Map<string, (id: string) => Record<string, unknown>>();
  private timers = new Map<string, { t: NodeJS.Timeout; fn: () => unknown }>();
  private offs: (() => void)[] = [];

  constructor(app: App, o: CardOptions = {}) {
    this.app = app;
    this.debounceMs = o.debounceMs ?? 800;
  }

  register(): void {
    const { app } = this;
    this.offs.push(
      app.bus.on("work.changed", (e) => this.onWork(e)),
      app.bus.on("candidate.created", (e) => void this.onCandidate(e)),
    );
    app.ext.cards = {
      onAction: (ev) => this.onAction(ev),
      brief: (mode, text) => briefCard(mode, text, this.ctx()),
      register: (type, render, target) => {
        this.renderers.set(type, render);
        if (target) this.targetResolvers.set(type, target);
      },
    };
    app.bot.doForm = (messageId) => this.sendDoForm(messageId);
  }

  stop(): void {
    for (const { t } of this.timers.values()) clearTimeout(t);
    this.timers.clear();
    this.offs.splice(0).forEach((off) => off());
  }

  /** 立即执行所有待发的刷新（测试、退出前用）。 */
  async flush(): Promise<void> {
    const pending = [...this.timers.entries()];
    this.timers.clear();
    for (const [key, { t, fn }] of pending) {
      clearTimeout(t);
      await this.run(key, fn);
    }
  }

  ctx(notice?: string): RenderCtx {
    const { cfg } = this.app;
    return {
      harnesses: Object.keys(cfg.harnesses),
      consoleBase: cfg.server.enabled ? consoleBaseUrl(cfg.server.host, cfg.server.port) : "",
      consoleTicket: cfg.server.enabled ? signLoginTicket(serverToken(this.app)) : undefined,
      timezone: cfg.owner.timezone,
      notice,
    };
  }

  // ───────── 调度 ─────────

  private async run(key: string, fn: () => unknown): Promise<void> {
    try {
      await fn();
    } catch (e) {
      log("warn", "刷新卡片失败", { card: key, err: errMsg(e) });
    }
  }

  private cancel(key: string): void {
    const p = this.timers.get(key);
    if (p) clearTimeout(p.t);
    this.timers.delete(key);
  }

  /** 去抖：同一张卡片在窗口内的多次变化只渲染最后一次。 */
  private schedule(key: string, fn: () => unknown): void {
    this.cancel(key);
    const t = setTimeout(() => {
      this.timers.delete(key);
      void this.run(key, fn);
    }, this.debounceMs);
    t.unref();
    this.timers.set(key, { t, fn });
  }

  /** 立即渲染（终态、按钮操作之后）；失败时退回去抖重试一次。 */
  private now(key: string, fn: () => void): void {
    this.cancel(key);
    try {
      fn();
    } catch (e) {
      log("warn", "刷新卡片失败，稍后重试", { card: key, err: errMsg(e) });
      this.schedule(key, fn);
    }
  }

  private emit(key: string, json: Card, kind?: NotifyKind): void {
    this.app.ledger.emit(`card:${key}`, [cardEffect(key, json, kind)]);
    this.app.engine.kick();
  }

  // ───────── 账本变化 ─────────

  private onWork(e: BusEvents["work.changed"]): void {
    if (e.kind === "dispatch") this.queueDispatch(e.ref, e.terminal);
    else if (e.kind === "delivery") {
      const d = this.app.ledger.get(e.ref);
      if (d?.kind === "dispatch") this.queueDispatch(d.ref, e.terminal);
    }
    if (e.kind === "event" || e.kind === "job" || e.kind === "delivery" || e.kind === "effect") this.onMaybeFailure(e);
  }

  private queueDispatch(guid: string, immediate: boolean): void {
    if (!guid) return;
    const key = `dispatch:${guid}`;
    const fn = () => this.renderDispatch(guid);
    if (immediate) this.now(key, fn);
    else this.schedule(key, fn);
  }

  /** 失败落定的事件 / 作业 / 交付 / 飞书写入 → 告警卡片；之后它的状态变化（重试、忽略）更新同一张卡片。 */
  private onMaybeFailure(e: BusEvents["work.changed"]): void {
    const marker = `cards.failure.${e.id}`;
    const key = `failure:${e.id}`;
    if (this.app.store.get(marker)) return this.schedule(key, () => this.renderFailure(e.id));
    if (!e.terminal || !FAILED.includes(e.state)) return;
    const w = this.app.ledger.get(e.id);
    if (!w || !failureWorthy(w)) return;
    this.app.store.set(marker, "1");
    this.now(key, () => this.renderFailure(e.id));
  }

  // ───────── 渲染 ─────────

  dispatchView(w: WorkItem<DispatchPayload>): DispatchCardView {
    const { app } = this;
    const p = w.payload;
    const s = summarize(app, w);
    const all = app.ledger.list({ kinds: ["dispatch"], ref: w.ref, limit: 100 });
    const last = (p.history ?? []).at(-1);
    const latest = app.ledger.latest("dispatch", w.ref);
    const actions = availableActions(w, {
      delivery: s.delivery,
      providers: Object.keys(app.cfg.delivery.providers).length,
      deliveryEnabled: app.commands.has("delivery.merge_local"),
      isLatest: latest?.id === w.id,
    }).filter((a) => app.commands.has(a));
    return {
      id: w.id,
      guid: w.ref,
      taskUrl: s.task_url,
      summary: s.summary,
      state: w.state,
      terminal: w.terminal,
      reason: w.reason,
      error: w.error,
      harness: p.harness ?? "",
      reviewer: p.reviewer ?? "",
      round: p.round ?? 0,
      maxRounds: p.maxRounds ?? 0,
      attempts: w.attempts,
      cancelRequested: w.cancel,
      elapsedMs: (w.terminal ? w.updated : Date.now()) - w.created,
      costUsd: app.ledger.costOf(all.map((x) => x.id)),
      dispatchNo: all.findIndex((x) => x.id === w.id) >= 0 ? all.length - all.findIndex((x) => x.id === w.id) : all.length,
      checks: last?.checks ?? [],
      checksRound: last?.round ?? 0,
      branch: p.branch ?? "",
      delivery: s.delivery,
      deliveryUrl: s.delivery_url,
      deliveryError: s.delivery === "failed" ? (app.ledger.latest("delivery", w.id)?.error ?? "") : "",
      actions,
    };
  }

  /** 渲染这张任务最新一次派单的卡片。 */
  renderDispatch(guid: string, notice?: string): void {
    const w = this.app.ledger.latest<DispatchPayload>("dispatch", guid);
    if (!w) return;
    this.emit(`dispatch:${guid}`, dispatchCard(this.dispatchView(w), this.ctx(notice)), w.terminal ? "result" : "progress");
  }

  failureView(w: WorkItem): FailureCardView {
    const { app } = this;
    const p = w.payload as Record<string, unknown>;
    let title = "工作失败";
    let detail = w.ref;
    let impact = "";
    switch (w.kind) {
      case "event":
        title = "飞书事件处理失败";
        detail = EVENT_TEXT[w.ref] ?? w.ref;
        impact = "这条事件还没有被处理（例如私聊指令没有回复、评论没有识别成任务）";
        break;
      case "job":
        title = `作业「${String(p.name ?? w.ref)}」没有完成`;
        detail = String(p.name ?? w.ref);
        impact = "作业可能已经执行了一部分；重试会从头再执行一次";
        break;
      case "delivery": {
        const d = app.ledger.get<DispatchPayload>(w.ref);
        title = `交付失败：${DELIVERY_ACTION_TEXT[String(p.action ?? "")] ?? String(p.action ?? "")}`;
        detail = d ? (d.payload.summary ?? "").replace(/^\s*\[[\w-]+\]\s*/, "") || d.ref : w.ref;
        impact = "派单结果还没有交付；可以重试，或在派单卡片上换一种交付方式";
        break;
      }
      case "effect": {
        const e = w.payload as unknown as Effect;
        title = "飞书写入失败";
        detail = e.op === "task.comment" ? `任务评论：${truncate(e.args.content.split("\n")[0], 60)}` : e.op === "task.move" ? `移动任务卡片到「${e.args.section}」` : e.op;
        impact = "飞书上的看板 / 评论暂时没有跟上本地状态";
        break;
      }
    }
    return {
      id: w.id,
      kind: w.kind,
      state: w.state,
      terminal: w.terminal,
      acknowledged: w.outcome === "acknowledged",
      title,
      detail,
      impact,
      error: w.error,
      attempts: w.attempts,
      updated: w.updated,
      canRetry: app.commands.has("work.retry"),
      canAcknowledge: app.commands.has("work.acknowledge"),
    };
  }

  renderFailure(id: string, notice?: string): void {
    const w = this.app.ledger.get(id);
    if (!w) return;
    this.emit(`failure:${id}`, failureCard(this.failureView(w), this.ctx(notice)), "failure");
  }

  private candidateKey(signalId: string): string {
    return `cards.candidate.${signalId}`;
  }

  private candidateInfo(signalId: string): CandidateInfo | undefined {
    const raw = this.app.store.get(this.candidateKey(signalId));
    if (!raw) return undefined;
    try {
      return JSON.parse(raw) as CandidateInfo;
    } catch {
      return undefined;
    }
  }

  private async onCandidate(e: BusEvents["candidate.created"]): Promise<void> {
    try {
      if (!this.candidateInfo(e.signalId)) {
        // 判断依据和建议截止写在任务描述 / 截止时间里，取一次存下来（取不到就不显示）
        let reason = "";
        let dueMs: number | null = null;
        try {
          const t = await this.app.board.getTask(e.taskGuid);
          reason = t.description.match(/判断依据[:：]\s*(.+?)(?:（置信度[^）]*）)?\s*$/m)?.[1]?.trim() ?? "";
          dueMs = t.dueMs;
        } catch (err) {
          log("warn", "读取候选任务详情失败，卡片不显示判断依据", { task: e.taskGuid, err: errMsg(err) });
        }
        const info: CandidateInfo = { taskGuid: e.taskGuid, summary: e.summary, section: e.section, reason, dueMs, feedback: "" };
        this.app.store.set(this.candidateKey(e.signalId), JSON.stringify(info));
      }
      this.renderCandidate(e.signalId);
    } catch (err) {
      log("warn", "发送候选任务卡片失败", { signal: e.signalId, err: errMsg(err) });
    }
  }

  candidateView(signalId: string, info: CandidateInfo): CandidateCardView {
    const { app } = this;
    const row = app.store.db.prepare("SELECT * FROM signals WHERE id = ?").get(signalId) as Record<string, unknown> | undefined;
    const conf = String(row?.verdict ?? "").match(/\(([\d.]+)\)/)?.[1];
    const dbFeedback = String(row?.feedback ?? "");
    const feedback =
      info.feedback === "dispatched" ? "dispatched" : dbFeedback === "confirmed" || dbFeedback === "rejected" ? dbFeedback : info.feedback;
    return {
      signalId,
      taskGuid: info.taskGuid,
      taskUrl: taskUrl(app, info.taskGuid),
      summary: info.summary,
      section: info.section,
      source: String(row?.source ?? ""),
      text: String(row?.text ?? ""),
      link: String(row?.link ?? ""),
      confidence: conf ? Number(conf) : null,
      reason: info.reason,
      dueMs: info.dueMs,
      feedback,
      canConfirm: app.commands.has("candidate.confirm"),
      canReject: app.commands.has("candidate.reject"),
      canDispatch: app.commands.has("candidate.dispatch"),
      defaultHarness: app.cfg.dispatch.default_harness || app.cfg.roles.brain,
      repos: Object.keys(app.cfg.dispatch.repos),
    };
  }

  renderCandidate(signalId: string, notice?: string): void {
    const info = this.candidateInfo(signalId);
    if (!info) return;
    this.emit(`candidate:${signalId}`, candidateCard(this.candidateView(signalId, info), this.ctx(notice)), "candidate");
  }

  private doView(key: string, extra: Partial<DoFormView> = {}): DoFormView {
    const { cfg } = this.app;
    return {
      key,
      harnesses: Object.keys(cfg.harnesses),
      defaultHarness: cfg.dispatch.default_harness || cfg.roles.brain,
      repos: Object.keys(cfg.dispatch.repos),
      ...extra,
    };
  }

  /** /do 不带参数：发一张派单表单。同一条私聊消息只发一次。 */
  sendDoForm(messageId: string): boolean {
    const key = `do:${messageId}`;
    this.app.ledger.emit(`card:${key}`, [cardEffect(key, doFormCard(this.doView(key), this.ctx()))], `card-do-${messageId}`);
    this.app.engine.kick();
    return true;
  }

  // ───────── 按钮回调 ─────────

  /**
   * 处理一次卡片操作：只认主人；同一事件只执行一次命令（inbox 重试时直接用上次的结果）；
   * 执行后原地刷新这张卡片，失败时额外私信一句原因。
   */
  async onAction(raw: Record<string, unknown>): Promise<void> {
    const { app } = this;
    const p = parseAction(raw, app.cfg.owner.open_id);
    if (!p.ok) {
      log("warn", "忽略卡片操作", { reason: p.reason, operator: p.actor });
      return;
    }
    const key = p.card ?? (p.messageId ? this.keyOfMessage(p.messageId) : undefined);
    // 兜底识别出的表单提交：操作对象按卡片补上（不能被表单字段覆盖）
    const args = p.inferred ? { ...p.args, ...(key ? this.targetArgs(key) : {}) } : p.args;
    const label = CMD_TEXT[p.cmd as CommandName] ?? p.cmd;
    const out = await app.store.once(`card.action.${p.eventKey}`, async () => {
      try {
        const r = await app.commands.exec(p.cmd, args, { source: "card", actor: p.actor });
        return JSON.stringify({ ok: r.ok, message: r.message, target: r.target ?? "" } satisfies ActionResult);
      } catch (e) {
        const msg = errMsg(e);
        app.ledger.emit("card:action-errors", [notify(`⚠️ 卡片操作「${label}」没有成功：${truncate(msg, 500)}`, "failure")], `card-err-${p.eventKey}`);
        return JSON.stringify({ ok: false, message: msg, target: "" } satisfies ActionResult);
      }
    });
    const res = JSON.parse(out) as ActionResult;
    this.afterAction(p.cmd, args, key ?? this.keyFor(p.cmd, args), res, label);
    app.engine.kick();
  }

  /** 操作之后原地刷新卡片，底部显示操作结果。 */
  private afterAction(cmd: string, args: Record<string, unknown>, key: string | undefined, res: ActionResult, label: string): void {
    if (!key) return;
    const notice = `${res.ok ? "✅" : "⚠️"} ${label}：${truncate(res.message, 200)}`;
    const i = key.indexOf(":");
    const type = key.slice(0, i);
    const id = key.slice(i + 1);
    this.cancel(key);
    switch (type) {
      case "dispatch":
        return this.renderDispatch(id, notice);
      case "candidate": {
        const info = this.candidateInfo(id);
        if (info && res.ok) {
          const fb = ({ "candidate.confirm": "confirmed", "candidate.reject": "rejected", "candidate.dispatch": "dispatched" } as const)[cmd as "candidate.confirm"];
          if (fb) this.app.store.set(this.candidateKey(id), JSON.stringify({ ...info, feedback: fb }));
        }
        return this.renderCandidate(id, notice);
      }
      case "failure":
        return this.renderFailure(id, notice);
      default: {
        // 其他模块注册的卡片类型（如工作上下文的 ctx-item / ctx-morning）
        const r = this.renderers.get(type);
        if (r) return r(id, notice, cmd, args, res);
        return;
      }
      case "do": {
        const values = { summary: String(args.summary ?? ""), description: String(args.description ?? ""), harness: String(args.harness ?? ""), repo: String(args.repo ?? "") };
        const view = res.ok
          ? this.doView(key, { submitted: { summary: values.summary, message: res.message, dispatchId: res.target } })
          : this.doView(key, { values });
        return this.emit(key, doFormCard(view, this.ctx(res.ok ? undefined : notice)));
      }
    }
  }

  /** 卡片 message_id → key（发送时记在 kv：card.msg.<key> = message_id）。 */
  private keyOfMessage(messageId: string): string | undefined {
    const r = this.app.store.db.prepare("SELECT k FROM kv WHERE k LIKE 'card.msg.%' AND v = ?").get(messageId) as { k: string } | undefined;
    return r?.k.slice("card.msg.".length);
  }

  /** 卡片 key → 命令的操作对象参数。 */
  private targetArgs(key: string): Record<string, unknown> {
    const i = key.indexOf(":");
    const type = key.slice(0, i);
    const id = key.slice(i + 1);
    const ext = this.targetResolvers.get(type);
    if (ext) return ext(id);
    if (type === "dispatch") {
      const w = this.app.ledger.latest("dispatch", id);
      return w ? { id: w.id } : {};
    }
    if (type === "candidate") return { signal_id: id };
    if (type === "failure") return { id };
    return {};
  }

  /** 回调值里没带卡片 key 时，按命令和参数推断该刷新哪张卡片。 */
  private keyFor(cmd: string, args: Record<string, unknown>): string | undefined {
    const id = typeof args.id === "string" ? args.id : "";
    if ((cmd.startsWith("dispatch.") || cmd.startsWith("delivery.")) && id) {
      const w = this.app.ledger.get(id);
      return w?.kind === "dispatch" ? `dispatch:${w.ref}` : undefined;
    }
    if (cmd.startsWith("candidate.") && typeof args.signal_id === "string") return `candidate:${args.signal_id}`;
    if (cmd.startsWith("work.") && id && this.app.store.get(`cards.failure.${id}`)) return `failure:${id}`;
    return undefined;
  }
}

/** 哪些失败值得发告警卡片：卡片和私信本身的投递失败不发（否则会循环告警）。 */
export function failureWorthy(w: WorkItem): boolean {
  if (w.kind === "effect") {
    const op = (w.payload as unknown as Effect).op;
    return op !== "card.upsert" && op !== "notify";
  }
  return w.kind === "event" || w.kind === "job" || w.kind === "delivery";
}

/** 模块注册：cards.enabled 时启用卡片服务。 */
export function registerCards(app: App, o: CardOptions = {}): CardService | undefined {
  if (!app.cfg.cards.enabled) return undefined;
  const s = new CardService(app, o);
  s.register();
  return s;
}
