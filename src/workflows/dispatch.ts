import fs from "node:fs";
import path from "node:path";
import { z } from "zod";
import { isContextDerivedDispatchBlocked } from "../api/queries.ts";
import type { Board, BoardTask } from "../board.ts";
import { repoSpec, type Config } from "../config.ts";
import {
  commitAll,
  ensureGitLfsObjectsForCheckout,
  removeStaleWorktreeAdminRecord,
  resolveExternalLfsStorageGitOpts,
  tryGit,
} from "../delivery/git.ts";
import { comment, move } from "../effects.ts";
import { checkpoint, type Ctx, type Handler } from "../engine.ts";
import {
  applySanitizedGitConfigEnv,
  applySanitizedNpmrcEnv,
  buildWorkspaceIsolation,
  isolatedSandboxTempEnv,
  loadPrompt,
  prepareHarnessEnv,
  runHarness,
  stageSanitizedGitConfig,
  stageSanitizedNpmrc,
  wrapCredentialIsolatedCommand,
} from "../harness.ts";
import type { Effect, Ledger, WorkItem } from "../ledger.ts";
import type { Store } from "../store.ts";
import { errMsg, log, render, runProcess, truncate } from "../util.ts";

const COMMENT_MAX = 2800;

// ───────────────────────── 纯函数：解析与决策（单元测试覆盖） ─────────────────────────

/** 从任务标题前缀 `[codex]` 或描述里的 `harness: codex` 行解析执行者。 */
export function parseHarness(t: Pick<BoardTask, "summary" | "description">, known: string[]): string | undefined {
  const m = t.summary.match(/^\s*\[([\w-]+)\]/) ?? t.description.match(/^\s*harness\s*[:：]\s*([\w-]+)\s*$/im);
  return m && known.includes(m[1]) ? m[1] : undefined;
}

/** 描述里的 `repo: 别名或路径` 行。 */
export function parseRepo(t: Pick<BoardTask, "description">): string | undefined {
  return t.description.match(/^\s*repo\s*[:：]\s*(\S+)\s*$/im)?.[1];
}

/** 交叉审查必须换一个 harness：执行者正好是 reviewer 时改由 brain 审；都相同则没有审查者。 */
export function pickReviewer(roles: { brain: string; reviewer: string }, worker: string): string {
  if (!roles.reviewer) return "";
  if (roles.reviewer !== worker) return roles.reviewer;
  return roles.brain !== worker ? roles.brain : "";
}

const Review = z.object({
  verdict: z.preprocess((v) => (typeof v === "string" ? v.trim().toLowerCase() : v), z.enum(["approve", "changes"])),
  summary: z.string().default(""),
  issues: z
    .array(
      z.object({
        severity: z.string().default(""),
        location: z.string().default(""),
        problem: z.string().default(""),
        suggestion: z.string().default(""),
      }),
    )
    .default([]),
});
export type Review = z.infer<typeof Review>;

/**
 * 解析审查结论。优先取回复里最后一个合法的 JSON 对象（prompts/review.md 要求的格式）；
 * 兼容旧格式时只认最后一个非空行的 `VERDICT: APPROVE|CHANGES`——正文里提到这个字样不算数。
 * 解析不出来返回 undefined：这是审查器故障，不是打回。
 */
export function parseReview(text: string): Review | undefined {
  const candidates = [...text.matchAll(/```(?:json)?\s*([\s\S]*?)```/g)].map((m) => m[1]).reverse();
  const first = text.indexOf("{");
  const last = text.lastIndexOf("}");
  if (first >= 0 && last > first) candidates.push(text.slice(first, last + 1));
  for (const c of candidates) {
    try {
      const r = Review.safeParse(JSON.parse(c));
      if (r.success) return r.data;
    } catch {
      // 不是 JSON，继续试下一个
    }
  }
  const lastLine = text.trim().split("\n").map((s) => s.trim()).filter(Boolean).at(-1) ?? "";
  const m = lastLine.match(/^VERDICT\s*[:：]\s*(APPROVE|CHANGES)$/i);
  return m ? { verdict: m[1].toLowerCase() as Review["verdict"], summary: text.trim(), issues: [] } : undefined;
}

export interface CheckResult {
  kind: "command" | "review";
  name: string;
  status: "pass" | "fail" | "error";
  detail: string;
}

export type Next = "accept" | "rework" | "needs_human" | "unverified";
export type Reason = "passed" | "checks_failed" | "rejected" | "verifier_error" | "unverified";

/**
 * 验收关卡：本轮校验结果 → 下一步。
 *   校验器故障        → 需人工介入（故障 ≠ 打回，不消耗返工轮次）
 *   有校验不通过      → 还有返工轮次就返工，否则需人工介入
 *   没有任何校验      → 按 on_unverified 策略：需人工介入，或标为“未验证”进待验收
 *   全部通过          → 通过
 */
export function decideRound(
  round: number,
  maxRounds: number,
  checks: CheckResult[],
  onUnverified: "needs_human" | "review",
): { next: Next; reason: Reason } {
  if (checks.some((c) => c.status === "error")) return { next: "needs_human", reason: "verifier_error" };
  if (checks.some((c) => c.status === "fail"))
    return round < maxRounds ? { next: "rework", reason: "checks_failed" } : { next: "needs_human", reason: "rejected" };
  if (!checks.length) return onUnverified === "review" ? { next: "unverified", reason: "unverified" } : { next: "needs_human", reason: "unverified" };
  return { next: "accept", reason: "passed" };
}

const REASON_TEXT: Record<string, string> = {
  passed: "校验全部通过",
  rejected: "返工轮次用完，校验仍未通过",
  verifier_error: "校验器故障（审查超时 / 无输出 / 结论无法解析，或校验命令无法运行），无法判断是否达标",
  unverified: "没有配置任何校验（无 reviewer、无 verify 命令），结果未经验证",
  errored: "执行反复失败",
  cancelled: "卡片被移出派单列，已取消",
  budget: "超出用量预算，已暂停",
};

/**
 * 对账计划：比较看板（派给Agent / Agent进行中 两列里的卡片）和账本。
 * 看板上的操作是用户意图：拖进“派给Agent”= 派单；把进行中的卡片拖走或完成 = 取消。
 *
 * 两次列表读取不是同一个快照（Avatar 自己移列时，可能先读到移动前的“进行中”、再读到移动后的“派给Agent”），
 * 所以这里只给出“候选”，凡是会产生不可逆后果的判断都要按任务 ID 核实（见 Dispatcher.reconcile）：
 *   enqueue  —— 从没派过的新卡片：直接入队（读漏了只是晚一轮，不会出错）
 *   redo     —— 上一次派单已终结、卡片又出现在派单列：核实确实在“派给Agent”才再派
 *   suspects —— 未终结的派单，两列都没看到：核实确实已完成 / 离开两列才取消
 */
export function planReconcile(input: {
  cards: { guid: string; section: "dispatch" | "running" }[];
  /** 每个任务最新的一项派单工作 */
  latest: Map<string, { id: string; terminal: boolean; pendingEffects: number }>;
}): { enqueue: string[]; redo: string[]; suspects: string[] } {
  const visible = new Set(input.cards.map((c) => c.guid));
  const queued = [...new Set(input.cards.filter((c) => c.section === "dispatch").map((c) => c.guid))];
  const enqueue = queued.filter((g) => !input.latest.has(g));
  // 上一项派单的飞书写入还没落地时，看板还没跟上，不算“又拖回来了”
  const redo = queued.filter((g) => {
    const w = input.latest.get(g);
    return !!w && w.terminal && w.pendingEffects === 0;
  });
  // 自己的移动卡片还没投递（例如刚被命令重新派单）时，看板还没跟上，不算可疑
  const suspects = [...input.latest.entries()].filter(([g, w]) => !w.terminal && !visible.has(g) && w.pendingEffects === 0).map(([, w]) => w.id);
  return { enqueue, redo, suspects };
}

/** 按 ID 核实后：卡片是否确实离开了派单两列（已完成、不在本看板、或在其他列）。 */
export function hasLeft(loc: { completed: boolean; sectionGuid: string | null }, activeSections: string[]): boolean {
  return loc.completed || loc.sectionGuid === null || !activeSections.includes(loc.sectionGuid);
}

// ───────────────────────── 状态机 ─────────────────────────

export interface DispatchPayload {
  guid: string;
  summary: string;
  description: string;
  harness: string;
  reviewer: string;
  verify: string;
  cwd: string;
  branch: string;
  base: string;
  round: number;
  maxRounds: number;
  /** 每轮开始时的 git 提交：崩溃后重跑这一轮前先回到这里，保证起点确定 */
  checkpoints: Record<string, string>;
  report: string;
  feedback: string;
  history: { round: number; checks: CheckResult[] }[];
  /** 重新派单时指定的执行者（覆盖标题前缀 / 默认执行者） */
  harness_override?: string;
  /** 重新派单（带意见返工）时，第一轮就带上的意见 */
  initial_feedback?: string;
  /** 由哪一项派单重新派出（返工 / 换执行者 / 重试） */
  redispatch_of?: string;
}

type Item = WorkItem<DispatchPayload>;

/**
 * 派单：queued → executing(第 n 轮) → verifying(第 n 轮) → [executing(n+1) | 终态]
 * 终态：accepted（通过）/ unverified（未验证）/ needs_human（需人工介入）/ errored（执行出错）/ cancelled（已取消）
 *
 * 每一步结束都用 ledger.transition 持久化（连同要写到飞书的评论/移动）；崩溃后从当前状态继续。
 * worker 不拿飞书权限，飞书只经由 outbox 写。
 */
export class Dispatcher {
  cfg: Config;
  ledger: Ledger;
  store: Store;
  board: Board;
  /**
   * 每次运行 harness 之前调用：返回非空字符串表示不能继续（如超出预算），派单收尾为“需人工介入”。
   * 由用量模块设置。
   */
  guard?: (it: WorkItem<DispatchPayload>) => string | undefined;

  constructor(cfg: Config, ledger: Ledger, store: Store, board: Board) {
    this.cfg = cfg;
    this.ledger = ledger;
    this.store = store;
    this.board = board;
  }

  /**
   * 看板 → 账本 对账：新建派单、取消被拖走的派单。
   * 列表读取只用来发现候选；取消和再派这类不可逆的决定都先按任务 ID 核实，查不清就留到下次对账。
   */
  async reconcile(): Promise<{ enqueued: number; cancelled: number; deferred: number }> {
    const [queued, running] = await Promise.all([this.board.listSection("dispatch"), this.board.listSection("running")]);
    const cards = [
      ...queued.map((t) => ({ guid: t.guid, section: "dispatch" as const, task: t })),
      ...running.map((t) => ({ guid: t.guid, section: "running" as const, task: t })),
    ];
    const latest = new Map<string, { id: string; terminal: boolean; pendingEffects: number }>();
    for (const g of new Set([...cards.map((c) => c.guid), ...this.ledger.active("dispatch").map((w) => w.ref)])) {
      const w = this.ledger.latest("dispatch", g);
      if (w) latest.set(g, { id: w.id, terminal: w.terminal, pendingEffects: this.ledger.pendingEffects(w.id) });
    }
    const plan = planReconcile({ cards, latest });
    const activeSections = [this.board.section("dispatch"), this.board.section("running")];
    let enqueued = 0;
    let cancelled = 0;
    let deferred = 0;
    /** 按 ID 核实；查不清返回 undefined（留到下次对账） */
    const locate = async (guid: string) => {
      try {
        return await this.board.locateTask(guid);
      } catch (e) {
        deferred++;
        log("warn", "无法按任务 ID 核实卡片位置，留到下次对账", { task: guid, err: errMsg(e) });
        return undefined;
      }
    };

    for (const guid of plan.redo) {
      if (isContextDerivedDispatchBlocked({ cfg: this.cfg, store: this.store, ledger: this.ledger }, guid)) {
        log("warn", "跳过归属旧主人的上下文委派卡片再派", { task: guid });
        continue;
      }
      const loc = await locate(guid);
      if (!loc) continue;
      if (hasLeft(loc, activeSections) || loc.sectionGuid !== this.board.section("dispatch")) {
        log("info", "列表里的卡片已不在“派给Agent”（读取到的是旧快照），不再派", { task: guid });
        continue;
      }
      if (this.enqueue(cards.find((c) => c.guid === guid)!.task)) enqueued++;
    }
    for (const guid of plan.enqueue) {
      if (isContextDerivedDispatchBlocked({ cfg: this.cfg, store: this.store, ledger: this.ledger }, guid)) {
        log("warn", "跳过归属旧主人的上下文委派卡片入队", { task: guid });
        continue;
      }
      if (this.enqueue(cards.find((c) => c.guid === guid)!.task)) enqueued++;
    }
    for (const id of plan.suspects) {
      const w = this.ledger.get(id);
      if (!w || w.terminal) continue;
      const loc = await locate(w.ref);
      if (!loc) continue;
      if (!hasLeft(loc, activeSections)) {
        log("info", "两列读取都没看到卡片，但按 ID 核实仍在派单列（读取不一致），不取消", { work: id });
        continue;
      }
      this.ledger.requestCancel(id);
      cancelled++;
      log("info", "卡片已离开派单列，请求取消", { work: id, completed: loc.completed, section: loc.sectionGuid });
    }
    return { enqueued, cancelled, deferred };
  }

  /**
   * 重新派单（返工 / 换执行者 / 重试）：新建一项派单，并在同一事务里把卡片移回“派给Agent”、写一条评论。
   * 在同一个 worktree 分支上继续。已有未终结派单时抛错（同一卡片至多一项）。
   */
  redispatch(guid: string, o: { reason: string; feedback?: string; harness?: string; from?: string }): string {
    const last = this.ledger.latest<DispatchPayload>("dispatch", guid);
    if (last && !last.terminal) throw new Error("这张卡片已有进行中的派单，请先取消或等它结束");
    const id = `dispatch:${guid}:${Date.now()}`;
    const p = last?.payload;
    const payload: Partial<DispatchPayload> = {
      guid,
      summary: p?.summary ?? "",
      description: p?.description ?? "",
      harness_override: o.harness,
      initial_feedback: o.feedback,
      redispatch_of: o.from ?? last?.id,
    };
    const note = [`🔁 重新派单：${o.reason}`, o.harness ? `执行者：${o.harness}` : "", o.feedback ? `意见：\n${truncate(o.feedback, 1500)}` : ""]
      .filter(Boolean)
      .join("\n");
    const added = this.ledger.enqueue({ id, kind: "dispatch", ref: guid, state: "queued", payload }, [comment(guid, note), move(guid, "dispatch")]);
    if (!added) throw new Error("这张卡片已有进行中的派单");
    log("info", "重新派单", { task: guid, reason: o.reason, harness: o.harness });
    return id;
  }

  /** 唯一索引保证同一卡片至多一项未终结派单：并发对账时后到的插入被忽略。返回是否新入队。 */
  private enqueue(t: BoardTask): boolean {
    const added = this.ledger.enqueue({
      id: `dispatch:${t.guid}:${Date.now()}`,
      kind: "dispatch",
      ref: t.guid,
      state: "queued",
      payload: { guid: t.guid, summary: t.summary, description: t.description },
    });
    if (added) log("info", "新派单入队", { task: t.summary });
    return added;
  }

  handler(): Handler<DispatchPayload> {
    return {
      kind: "dispatch",
      concurrency: this.cfg.dispatch.max_parallel,
      maxAttempts: this.cfg.dispatch.max_attempts,
      run: (item, ctx) => this.advance(item, ctx),
      onExhausted: (item, err) => {
        const p = item.payload;
        const effects: Effect[] = [];
        if (p.guid) {
          effects.push(
            comment(p.guid, truncate(`❌ 执行失败（${stateText(item.state)}阶段已达尝试上限 ${this.cfg.dispatch.max_attempts} 次，含进程中断）：${err}\n日志：${this.logDir(p.guid)}`, COMMENT_MAX)),
            move(p.guid, "attention"),
          );
        }
        return { patch: { state: "errored", outcome: "errored", reason: "errored" }, effects };
      },
    };
  }

  private logDir(guid: string): string {
    return path.join(this.cfg.dataDir, "runs", guid.slice(0, 8));
  }

  async advance(start: Item, ctx: Ctx): Promise<void> {
    let it = start;
    for (;;) {
      if (
        isContextDerivedDispatchBlocked({ cfg: this.cfg, store: this.store, ledger: this.ledger }, it.id) ||
        isContextDerivedDispatchBlocked({ cfg: this.cfg, store: this.store, ledger: this.ledger }, it.ref)
      ) {
        this.finish(it, "errored", "owner_isolated", []);
        log("warn", "该派单源自旧工作区主人的工作上下文，已按主人隔离中止执行", { work: it.id, reason: "owner_isolated" });
        return;
      }
      if (this.ledger.isCancelled(it.id)) {
        this.finish(it, "cancelled", "cancelled", [comment(it.payload.guid, `⏹️ ${REASON_TEXT.cancelled}。已有改动保留在工作目录${it.payload.cwd ? `：${it.payload.cwd}` : ""}。`)]);
        return;
      }
      checkpoint(ctx);
      if ((it.state === "executing" || it.state === "verifying") && this.guard) {
        const why = this.guard(it);
        if (why) {
          this.finish(it, "needs_human", "budget", [
            comment(it.payload.guid, `⏸️ ${REASON_TEXT.budget}：${why}\n调整预算后可在控制台或卡片上“重试”。`),
            move(it.payload.guid, "attention"),
          ]);
          return;
        }
      }
      if (it.state === "queued") it = await this.prepare(it);
      else if (it.state === "executing") it = await this.execute(it, ctx);
      else if (it.state === "verifying") it = await this.verify(it, ctx);
      else return;
      if (it.terminal) return;
    }
  }

  private finish(it: Item, state: string, reason: string, effects: Effect[], payload?: DispatchPayload): void {
    this.ledger.transition(it, { state, terminal: true, outcome: state, reason, payload }, effects);
    if (reason === "owner_isolated") {
      log("warn", "派单结束", { work: it.id, state, reason });
    } else {
      log(state === "accepted" ? "info" : "warn", "派单结束", { task: it.payload.summary, state, reason });
    }
  }

  /** queued：读取最新的卡片内容，选执行者/审查者，准备工作目录。 */
  private async prepare(it: Item): Promise<Item> {
    const t = { ...it.payload, ...(await this.board.getTask(it.payload.guid)) };
    const override = it.payload.harness_override && this.cfg.harnesses[it.payload.harness_override] ? it.payload.harness_override : undefined;
    const harness = override ?? parseHarness(t, Object.keys(this.cfg.harnesses)) ?? (this.cfg.dispatch.default_harness || this.cfg.roles.brain);
    const reviewer = pickReviewer(this.cfg.roles, harness);
    const ws = await this.prepareWorkspace(t);
    fs.mkdirSync(this.logDir(t.guid), { recursive: true });
    const payload: DispatchPayload = {
      guid: t.guid,
      summary: t.summary,
      description: t.description,
      harness,
      reviewer,
      verify: ws.verify,
      cwd: ws.cwd,
      branch: ws.branch,
      base: ws.base,
      round: 1,
      maxRounds: 1 + this.cfg.dispatch.fix_rounds,
      checkpoints: {},
      report: "",
      feedback: it.payload.initial_feedback ?? "",
      history: [],
      harness_override: override,
      initial_feedback: it.payload.initial_feedback,
      redispatch_of: it.payload.redispatch_of,
    };
    const checks = [reviewer && `${reviewer} 审查`, ws.verify && `命令 \`${ws.verify}\``].filter(Boolean).join(" + ") || "无（结果将标为未验证）";
    return this.ledger.transition(it, { state: "executing", payload }, [
      move(t.guid, "running"),
      comment(t.guid, `🤖 ${harness} 开始执行\n工作目录：${ws.cwd}${ws.branch ? `\n分支：${ws.branch}` : ""}\n验收：${checks}`),
    ]);
  }

  /** 从派单描述解析受信任仓库根目录（无 repo: 时返回 undefined，并禁止挂载任意外部 .git） */
  private trustedRepoOpts(p: Pick<DispatchPayload, "description" | "base">): {
    trustedRepoRoot?: string;
    disableGitWorktreeMounts?: boolean;
  } {
    if (!p.base) return { disableGitWorktreeMounts: true };
    const ref = parseRepo({ description: p.description ?? "" });
    if (!ref) return { disableGitWorktreeMounts: true };
    return { trustedRepoRoot: repoSpec(this.cfg, ref).path };
  }

  /** executing：在本轮检查点上运行 worker；成功则提交本轮改动，进入 verifying。 */
  private async execute(it: Item, ctx: Ctx): Promise<Item> {
    let p = it.payload;
    const round = String(p.round);
    const repoGuard = this.trustedRepoOpts(p);
    if (p.base) {
      const cp = p.checkpoints[round];
      const gitOpts = { cfg: this.cfg, ...repoGuard };
      if (cp) {
        // 重入（崩溃 / 失败重试）：丢弃上次没跑完的半成品，回到本轮起点（挂载受信任外部 lfs.storage 以便 smudge 还原 LFS 文件）
        const resetOpts = await resolveExternalLfsStorageGitOpts(p.cwd, gitOpts);
        await git(p.cwd, ["reset", "--hard", cp], resetOpts);
        await git(p.cwd, ["clean", "-fd"], gitOpts);
        log("info", "回到本轮检查点后重跑", { task: p.summary, round: p.round, checkpoint: cp.slice(0, 8) });
      } else {
        await autoCommit(p.cwd, `pa: 第 ${round} 轮开始前的快照`, gitOpts);
        p = { ...p, checkpoints: { ...p.checkpoints, [round]: (await git(p.cwd, ["rev-parse", "HEAD"], { ...gitOpts, readOnly: true })).trim() } };
        it = this.ledger.transition(it, { payload: p }); // 先落检查点，再动手
      }
    }
    const logFile = path.join(this.logDir(p.guid), `worker-${round}-${ctx.attempt}.log`);
    const step = this.ledger.startStep({ work_id: it.id, name: `worker#${round}`, harness: p.harness, log: logFile });
    const r = await runHarness(this.cfg, {
      harness: p.harness,
      prompt: render(loadPrompt("worker.md"), {
        summary: p.summary.replace(/^\s*\[[\w-]+\]\s*/, ""),
        description: p.description,
        cwd: p.cwd,
        feedback: p.feedback || "（无）",
      }),
      cwd: p.cwd,
      tools: "write",
      lark: "none",
      timeoutSec: this.cfg.dispatch.timeout_sec,
      logFile,
      signal: ctx.signal,
      onSpawn: (pid) => this.ledger.setStepPid(step, pid),
      stepId: step,
      ...repoGuard,
    });
    const report = r.text || "（无输出）";
    if (!r.ok) {
      this.ledger.endStep(step, "failed", r.aborted ? "中止" : truncate(report, 500));
      checkpoint(ctx);
      throw new Error(`${p.harness} 执行失败（exit ${r.exitCode}${r.timedOut ? "，超时" : ""}）：${truncate(report, 800)}`);
    }
    if (p.base) await autoCommit(p.cwd, `pa: 第 ${round} 轮（${p.harness}）`, { cfg: this.cfg, ...repoGuard });
    this.ledger.endStep(step, "ok", truncate(report, 500));
    return this.ledger.transition(it, { state: "verifying", payload: { ...p, report } });
  }

  /** verifying：确定性校验 → LLM 审查 → 验收关卡决定下一步。 */
  private async verify(it: Item, ctx: Ctx): Promise<Item> {
    const p = it.payload;
    const checks: CheckResult[] = [];
    if (p.verify) checks.push(await this.runVerifyCommand(it, ctx));
    // 确定性校验没过就不必再花钱审查，直接返工
    if (p.reviewer && !checks.some((c) => c.status === "fail")) checks.push(await this.runReview(it, ctx));
    checkpoint(ctx);

    const d = decideRound(p.round, p.maxRounds, checks, this.cfg.acceptance.on_unverified);
    const history = [...p.history, { round: p.round, checks }];
    const notes = checks.map((c) => truncate(`${c.kind === "review" ? "🔍" : "🧪"} ${c.name}（第 ${p.round} 轮）：${statusText(c.status)}\n${c.detail}`, COMMENT_MAX));
    const effects: Effect[] = notes.map((n) => comment(p.guid, n));

    if (d.next === "rework") {
      const feedback = checks.filter((c) => c.status === "fail").map((c) => `### ${c.name}\n${c.detail}`).join("\n\n");
      return this.ledger.transition(it, { state: "executing", payload: { ...p, history, round: p.round + 1, feedback } }, effects);
    }
    const stat = p.base ? await gitDiffStat(p.cwd, p.base, { cfg: this.cfg, readOnly: true, ...this.trustedRepoOpts(p) }) : "";
    const tail = [truncate(p.report, 1800), stat ? `\n变更：\n${stat}` : "", p.branch ? `分支：${p.branch}（worktree：${p.cwd}）` : ""].filter(Boolean).join("\n");
    const final = { ...p, history };
    if (d.next === "accept") {
      this.finish(it, "accepted", d.reason, [...effects, comment(p.guid, truncate(`✅ ${p.harness} 完成，已通过验收\n${tail}`, COMMENT_MAX)), move(p.guid, "review")], final);
    } else if (d.next === "unverified") {
      this.finish(it, "unverified", d.reason, [...effects, comment(p.guid, truncate(`⚪ ${p.harness} 完成，但${REASON_TEXT.unverified}\n${tail}`, COMMENT_MAX)), move(p.guid, "review")], final);
    } else {
      const effectsHuman = [
        ...effects,
        comment(p.guid, truncate(`⚠️ 需要你介入：${REASON_TEXT[d.reason]}\n\n执行者报告：\n${tail}`, COMMENT_MAX)),
        move(p.guid, "attention"),
      ];
      this.finish(it, "needs_human", d.reason, effectsHuman, final);
    }
    return this.ledger.get<DispatchPayload>(it.id)!;
  }

  private async runVerifyCommand(it: Item, ctx: Ctx): Promise<CheckResult> {
    const p = it.payload;
    const name = `校验命令 \`${p.verify}\``;
    const logFile = path.join(this.logDir(p.guid), `verify-${p.round}-${ctx.attempt}.log`);
    const step = this.ledger.startStep({ work_id: it.id, name: `verify#${p.round}`, log: logFile });
    let baseEnv: ReturnType<typeof prepareHarnessEnv> | undefined;
    let stagedNpmrc: ReturnType<typeof stageSanitizedNpmrc> | undefined;
    let stagedGitCfg: ReturnType<typeof stageSanitizedGitConfig> | undefined;
    try {
      baseEnv = prepareHarnessEnv();
      stagedNpmrc = stageSanitizedNpmrc(process.env, this.cfg.dataDir);
      stagedGitCfg = stageSanitizedGitConfig(process.env, this.cfg.dataDir, { cwd: p.cwd });
      const wrapped = wrapCredentialIsolatedCommand(
        "bash",
        ["-lc", p.verify],
        process.env,
        buildWorkspaceIsolation(this.cfg, {
          mode: "verify",
          cwd: p.cwd,
          ...this.trustedRepoOpts(p),
          extraReadOnlyPaths: [
            ...(baseEnv.env.CREDENTIALS_DIRECTORY ? [baseEnv.env.CREDENTIALS_DIRECTORY] : []),
            ...(stagedNpmrc ? [stagedNpmrc.dir] : []),
            ...(stagedGitCfg ? [stagedGitCfg.dir, ...stagedGitCfg.extraReadOnlyPaths] : []),
          ],
          ...(stagedGitCfg?.symlinks.length ? { extraSymlinks: stagedGitCfg.symlinks } : {}),
          extraBindMounts: [
            ...(stagedNpmrc ? [{ src: stagedNpmrc.file, dest: stagedNpmrc.homeMountDest, mode: "ro" as const }] : []),
            ...(stagedGitCfg ? stagedGitCfg.bindMounts : []),
          ],
        }),
      );
      const verifyEnv: NodeJS.ProcessEnv = wrapped.isolated
        ? { ...baseEnv.env, ...isolatedSandboxTempEnv() }
        : { ...baseEnv.env };
      applySanitizedNpmrcEnv(verifyEnv, stagedNpmrc, wrapped.isolated);
      applySanitizedGitConfigEnv(verifyEnv, stagedGitCfg, wrapped.isolated);
      const r = await runProcess(wrapped.cmd, wrapped.args, {
        cwd: p.cwd,
        env: verifyEnv,
        timeoutMs: this.cfg.acceptance.verify_timeout_sec * 1000,
        group: true,
        signal: ctx.signal,
        onSpawn: (pid) => this.ledger.setStepPid(step, pid),
      });
      const out = `${r.stdout}\n${r.stderr}`.trim();
      fs.writeFileSync(logFile, `# exit=${r.code} timedOut=${r.timedOut}\n${out}`);
      checkpoint(ctx);
      const ok = r.code === 0 && !r.timedOut;
      this.ledger.endStep(step, ok ? "ok" : "failed", `exit ${r.code}`);
      const detail = ok ? "通过" : `${r.timedOut ? "超时" : `退出码 ${r.code}`}，输出末尾：\n${out.slice(-1500)}`;
      return { kind: "command", name, status: ok ? "pass" : "fail", detail };
    } catch (e) {
      this.ledger.endStep(step, "failed", String(e));
      checkpoint(ctx);
      return { kind: "command", name, status: "error", detail: `无法运行：${String(e)}` };
    } finally {
      stagedGitCfg?.cleanup();
      stagedNpmrc?.cleanup();
      baseEnv?.cleanup();
    }
  }

  /** LLM 交叉审查；审查器故障会重试，仍失败返回 error（不是 fail）。 */
  private async runReview(it: Item, ctx: Ctx): Promise<CheckResult> {
    const p = it.payload;
    const name = `${p.reviewer} 审查`;
    const repoGuard = this.trustedRepoOpts(p);
    const diff = p.base ? await gitDiff(p.cwd, p.base, { cfg: this.cfg, readOnly: true, ...repoGuard }) : "";
    let lastErr = "";
    for (let i = 0; i <= this.cfg.acceptance.review_retries; i++) {
      checkpoint(ctx);
      const logFile = path.join(this.logDir(p.guid), `review-${p.round}-${ctx.attempt}-${i + 1}.log`);
      const step = this.ledger.startStep({ work_id: it.id, name: `review#${p.round}`, harness: p.reviewer, log: logFile });
      const rv = await runHarness(this.cfg, {
        harness: p.reviewer,
        prompt: render(loadPrompt("review.md"), {
          summary: p.summary,
          description: p.description,
          report: truncate(p.report, 8000),
          diff: diff ? truncate(diff, 30000) : "（非代码任务，无 diff）",
        }),
        cwd: p.cwd,
        tools: "read",
        lark: "none",
        timeoutSec: this.cfg.acceptance.review_timeout_sec,
        logFile,
        signal: ctx.signal,
        onSpawn: (pid) => this.ledger.setStepPid(step, pid),
        stepId: step,
        ...repoGuard,
      });
      checkpoint(ctx);
      const parsed = rv.text ? parseReview(rv.text) : undefined;
      if (parsed) {
        this.ledger.endStep(step, "ok", parsed.verdict);
        return { kind: "review", name, status: parsed.verdict === "approve" ? "pass" : "fail", detail: formatReview(parsed) };
      }
      lastErr = rv.text ? `结论无法解析：${truncate(rv.text, 300)}` : `无输出（exit ${rv.exitCode}${rv.timedOut ? "，超时" : ""}）`;
      this.ledger.endStep(step, "failed", lastErr);
      log("warn", "审查器故障", { task: p.summary, try: i + 1, err: lastErr });
    }
    return { kind: "review", name, status: "error", detail: lastErr };
  }

  /** 指定了仓库就在该仓库的独立 git worktree 里干活；否则给一个独立的空工作目录。可重复调用。 */
  async prepareWorkspace(t: BoardTask): Promise<{ cwd: string; branch: string; base: string; verify: string }> {
    const repoRef = parseRepo(t);
    const short = t.guid.slice(0, 8);
    if (!repoRef) {
      const cwd = path.join(this.cfg.dataDir, "workspace", short);
      fs.mkdirSync(cwd, { recursive: true });
      return { cwd, branch: "", base: "", verify: "" };
    }
    const spec = repoSpec(this.cfg, repoRef);
    const cwd = path.join(this.cfg.dataDir, "worktrees", short);
    const branch = `pa/${short}`;
    const baseKey = `worktree.${t.guid}.base`;

    const realPathSafe = (p: string): string => {
      try {
        return fs.realpathSync(p);
      } catch {
        return path.resolve(p);
      }
    };
    const isRegisteredValidWorktree = async (): Promise<boolean> => {
      if (!fs.existsSync(path.join(cwd, ".git"))) return false;
      const wtList = await tryGit(spec.path, ["worktree", "list", "--porcelain"], {
        cfg: this.cfg,
        readOnly: true,
        trustedRepoRoot: spec.path,
      });
      if (wtList.code !== 0) return false;
      const targetReal = realPathSafe(cwd);
      const registered = wtList.stdout
        .split(/\r?\n/)
        .filter((l) => l.startsWith("worktree "))
        .map((l) => realPathSafe(l.slice("worktree ".length).trim()))
        .includes(targetReal);
      if (!registered) return false;
      const inside = await tryGit(cwd, ["rev-parse", "--is-inside-work-tree"], {
        cfg: this.cfg,
        readOnly: true,
        trustedRepoRoot: spec.path,
      });
      return inside.code === 0 && inside.stdout.trim() === "true";
    };

    let ready = fs.existsSync(cwd) && (await isRegisteredValidWorktree());
    if (fs.existsSync(cwd) && !ready) {
      let isEmptyDir = false;
      try {
        isEmptyDir = fs.statSync(cwd).isDirectory() && fs.readdirSync(cwd).length === 0;
      } catch {
        isEmptyDir = false;
      }
      if (!isEmptyDir) {
        throw new Error(`工作树目录 ${cwd} 已存在且不是有效的已注册 Git worktree，拒绝按空基线继续执行`);
      }
    }

    if (!ready) {
      // 预先仅创建本次派单专属空目录并只将该目录开放给 git worktree add，绝不把包含其他在途派单的 worktrees/ 父目录设为可写；
      // 若存在指向当前目标路径的失效 worktree 管理记录，仅在宿主机定向清理该单一目标记录，绝不执行全局 git worktree prune（防止沙箱看不到其他同级派单目录时误删其有效注册）。
      fs.mkdirSync(cwd, { recursive: true });
      try {
        const stale = await removeStaleWorktreeAdminRecord(spec.path, cwd, {
          cfg: this.cfg,
          trustedRepoRoot: spec.path,
        });
        if (stale.locked) {
          throw new Error(`工作树 ${cwd} 存在已锁定的历史 worktree 管理记录，拒绝自动覆盖`);
        }
        const head = (
          await git(spec.path, ["rev-parse", "HEAD"], { cfg: this.cfg, readOnly: true, trustedRepoRoot: spec.path })
        ).trim();
        const hasBranch = (await tryGit(spec.path, ["rev-parse", "--verify", "--quiet", `refs/heads/${branch}`], { cfg: this.cfg, readOnly: true, trustedRepoRoot: spec.path })).code === 0;
        if (!hasBranch) {
          const lfsPre = await ensureGitLfsObjectsForCheckout(spec.path, head, {
            cfg: this.cfg,
            trustedRepoRoot: spec.path,
          });
          // 新分支必须显式以已预拉取的 head 作为起点，防止预拉取期间宿主机仓库切换分支或推进 HEAD 导致检出树与基线错位
          await git(spec.path, ["worktree", "add", "-b", branch, cwd, head], {
            cfg: this.cfg,
            trustedRepoRoot: spec.path,
            extraWritablePaths: [
              cwd,
              ...(lfsPre.lfsStorageExternal && lfsPre.lfsStorageDir ? [lfsPre.lfsStorageDir] : []),
            ],
            ...(lfsPre.lfsStorageExternal && lfsPre.lfsStorageDir
              ? { extraGitConfigArgs: ["-c", `lfs.storage=${lfsPre.lfsStorageDir}`] }
              : {}),
          });
        } else {
          // 已有分支：先锁定当前 tip SHA 预拉取缺失 LFS 对象，再复核分支尖端未在预检期间推进；若推进则自动重跑预检，避免无凭据检出沙箱缺少新提交的 LFS 对象
          let checkedOut = false;
          const MAX_EXISTING_BRANCH_PREFLIGHT = 3;
          for (let attempt = 0; attempt < MAX_EXISTING_BRANCH_PREFLIGHT; attempt++) {
            const beforeSha = (
              await git(spec.path, ["rev-parse", "--verify", `refs/heads/${branch}`], {
                cfg: this.cfg,
                readOnly: true,
                trustedRepoRoot: spec.path,
              })
            ).trim();
            const lfsPre = await ensureGitLfsObjectsForCheckout(spec.path, beforeSha, {
              cfg: this.cfg,
              trustedRepoRoot: spec.path,
              branchHint: branch,
            });
            const afterPreSha = (
              await git(spec.path, ["rev-parse", "--verify", `refs/heads/${branch}`], {
                cfg: this.cfg,
                readOnly: true,
                trustedRepoRoot: spec.path,
              })
            ).trim();
            if (afterPreSha !== beforeSha) {
              continue;
            }
            try {
              await git(spec.path, ["worktree", "add", cwd, branch], {
                cfg: this.cfg,
                trustedRepoRoot: spec.path,
                extraWritablePaths: [
                  cwd,
                  ...(lfsPre.lfsStorageExternal && lfsPre.lfsStorageDir ? [lfsPre.lfsStorageDir] : []),
                ],
                ...(lfsPre.lfsStorageExternal && lfsPre.lfsStorageDir
                  ? { extraGitConfigArgs: ["-c", `lfs.storage=${lfsPre.lfsStorageDir}`] }
                  : {}),
              });
              checkedOut = true;
              break;
            } catch (wtErr) {
              const postErrSha = (
                await tryGit(spec.path, ["rev-parse", "--verify", `refs/heads/${branch}`], {
                  cfg: this.cfg,
                  readOnly: true,
                  trustedRepoRoot: spec.path,
                })
              ).stdout.trim();
              if (postErrSha && postErrSha !== beforeSha && attempt + 1 < MAX_EXISTING_BRANCH_PREFLIGHT) {
                fs.rmSync(cwd, { recursive: true, force: true });
                fs.mkdirSync(cwd, { recursive: true });
                await removeStaleWorktreeAdminRecord(spec.path, cwd, {
                  cfg: this.cfg,
                  trustedRepoRoot: spec.path,
                });
                continue;
              }
              throw wtErr;
            }
          }
          if (!checkedOut) {
            throw new Error(`分支 ${branch} 在 LFS 预检期间持续推进，已中止工作树检出以避免缺失 LFS 对象`);
          }
        }
        if (!this.store.get(baseKey)) this.store.set(baseKey, head);
        ready = true;
      } catch (err) {
        try {
          if (fs.existsSync(cwd) && fs.readdirSync(cwd).length === 0) fs.rmdirSync(cwd);
        } catch {
          // 忽略空目录回滚失败
        }
        throw err;
      }
    }

    let base = (this.store.get(baseKey) ?? "").trim();
    if (!base && ready) {
      // 若进程在 git worktree add 完成后、写入 baseKey 前中断，从已注册 worktree 恢复真实基线提交
      const mb = await tryGit(spec.path, ["merge-base", "HEAD", branch], {
        cfg: this.cfg,
        readOnly: true,
        trustedRepoRoot: spec.path,
      });
      const recovered =
        (mb.code === 0 ? mb.stdout.trim() : "") ||
        (await git(cwd, ["rev-parse", "HEAD"], { cfg: this.cfg, readOnly: true, trustedRepoRoot: spec.path })).trim();
      if (recovered) {
        this.store.set(baseKey, recovered);
        base = recovered;
      }
    }
    if (!base) {
      throw new Error(`工作树 ${cwd} 缺少有效基线提交，无法继续代码任务`);
    }
    return { cwd, branch, base, verify: spec.verify ?? "" };
  }
}

function stateText(s: string): string {
  return { queued: "准备", executing: "执行", verifying: "验收" }[s] ?? s;
}

function statusText(s: CheckResult["status"]): string {
  return s === "pass" ? "通过" : s === "fail" ? "需修改" : "故障";
}

export function formatReview(r: Review): string {
  const issues = r.issues.map((i, n) => `${n + 1}. [${i.severity || "-"}] ${i.location ? `${i.location}：` : ""}${i.problem}${i.suggestion ? `（建议：${i.suggestion}）` : ""}`);
  return [r.summary, ...issues].filter(Boolean).join("\n") || (r.verdict === "approve" ? "没有发现问题" : "需修改");
}

async function git(cwd: string, args: string[], opts?: import("../delivery/git.ts").GitRunOpts): Promise<string> {
  const r = await tryGit(cwd, args, opts);
  if (r.code !== 0) throw new Error(`git ${args.join(" ")} 失败：${r.stderr.trim()}`);
  return r.stdout;
}

/** 有改动就提交（含新文件）；没有改动什么都不做（复用交付层签名感知提交逻辑）。 */
async function autoCommit(cwd: string, message: string, opts?: import("../delivery/git.ts").GitRunOpts): Promise<void> {
  await commitAll(cwd, message, opts);
}

/** 相对创建 worktree 时的基线（每轮结束都已自动提交，所以比较到 HEAD 即可）。 */
async function gitDiff(cwd: string, base: string, opts?: import("../delivery/git.ts").GitRunOpts): Promise<string> {
  return (await tryGit(cwd, ["diff", base, "HEAD"], { ...opts, readOnly: true })).stdout;
}

async function gitDiffStat(cwd: string, base: string, opts?: import("../delivery/git.ts").GitRunOpts): Promise<string> {
  return (await tryGit(cwd, ["diff", "--stat", base, "HEAD"], { ...opts, readOnly: true })).stdout.trim();
}
