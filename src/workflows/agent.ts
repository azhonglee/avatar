import path from "node:path";
import type { Board } from "../board.ts";
import type { Config } from "../config.ts";
import { notify } from "../effects.ts";
import { checkpoint, type Ctx, type Handler } from "../engine.ts";
import { loadPrompt, runHarness } from "../harness.ts";
import type { Ledger } from "../ledger.ts";
import type { Lark } from "../lark.ts";
import type { Store } from "../store.ts";
import { errMsg, log, render, truncate } from "../util.ts";
import { buildBrief } from "./brief.ts";
import type { Capture } from "./capture.ts";
import type { Dispatcher } from "./dispatch.ts";

/** 给 agent 的公共上下文：身份、规则和看板/知识库的 ID（见 prompts/superagent.md）。 */
export function superagentContext(cfg: Config, store: Store): string {
  const kbNodes = cfg.kb.nodes.map((n) => `  - ${n}: ${store.get(`kb.node.${n}`) ?? "（未初始化）"}`).join("\n");
  const sections = Object.entries(cfg.board.sections)
    .map(([k, name]) => `  - ${name}: ${store.get(`board.section.${k}`) ?? "（未初始化）"}`)
    .join("\n");
  return render(loadPrompt("superagent.md"), {
    owner: cfg.owner.open_id,
    timezone: cfg.owner.timezone,
    now: new Date().toLocaleString("zh-CN", { timeZone: cfg.owner.timezone }),
    tasklist: store.get("board.tasklist") ?? "（未初始化）",
    sections,
    kb_space: store.get("kb.space") ?? "（未初始化）",
    kb_nodes: kbNodes,
  });
}

/**
 * agent 作业：让 brain（或指定 harness）带着受限的 lark-cli（守卫 profile=agent）完成一段开放式工作，
 * 例如整理知识库、把妙记写成纪要、回答你在私聊里的提问。执行记成一个步骤（ledger.steps）。
 */
export async function runAgentJob(
  cfg: Config,
  store: Store,
  ledger: Ledger,
  job: { name: string; task: string; harness?: string; workId?: string; signal?: AbortSignal },
): Promise<{ ok: boolean; text: string }> {
  const harness = job.harness ?? cfg.roles.brain;
  const logFile = path.join(cfg.dataDir, "runs", `job-${job.name}-${Date.now()}.log`);
  const step = ledger.startStep({ work_id: job.workId ?? `adhoc:${job.name}:${Date.now()}`, name: `job:${job.name}`, harness, log: logFile });
  try {
    const r = await runHarness(cfg, {
      harness,
      prompt: `${superagentContext(cfg, store)}\n\n# 本次任务\n\n${job.task}`,
      cwd: path.join(cfg.dataDir, "workspace", "jobs", job.name),
      tools: "write",
      lark: "agent",
      timeoutSec: 1800,
      logFile,
      signal: job.signal,
      onSpawn: (pid) => ledger.setStepPid(step, pid),
    });
    const text = r.text || `（无输出，exit ${r.exitCode}）`;
    ledger.endStep(step, r.ok ? "ok" : "failed", truncate(text, 500));
    return { ok: r.ok, text };
  } catch (e) {
    ledger.endStep(step, "failed", errMsg(e));
    throw e;
  }
}

export interface JobPayload {
  name: string;
  task: string;
  harness?: string;
  notify: boolean;
  result?: string;
}

/**
 * 作业入队。id 决定去重粒度：定时作业按“名称 + 计划时间”、妙记纪要按妙记 token，
 * 重复触发（重启后补跑、事件重放）只会执行一次。
 */
export function enqueueJob(ledger: Ledger, id: string, p: JobPayload): boolean {
  return ledger.enqueue({ id: `job:${id}`, kind: "job", ref: p.name, payload: p });
}

/**
 * 作业执行器。agent 作业会写飞书（文档、任务），没有幂等保证，所以是“至多一次”：
 * 执行中途进程退出不会自动重跑（可能写了一半），而是落到 errored 并私信告诉你。
 */
export function jobHandler(cfg: Config, store: Store, ledger: Ledger): Handler<JobPayload> {
  return {
    kind: "job",
    concurrency: 1,
    maxAttempts: 1,
    refundOnStop: false,
    async run(item, ctx) {
      const p = item.payload;
      const r = await runAgentJob(cfg, store, ledger, { name: p.name, task: p.task, harness: p.harness, workId: item.id, signal: ctx.signal });
      if (ctx.signal.aborted) throw new Error("作业被中止");
      const effects = p.notify || !r.ok ? [notify(truncate(`🗂️ 作业「${p.name}」${r.ok ? "完成" : "失败"}\n\n${r.text}`, 6000))] : [];
      const state = r.ok ? "done" : "errored";
      ledger.transition(item, { state, terminal: true, outcome: state, payload: { ...p, result: r.text } }, effects);
      log(r.ok ? "info" : "error", "作业结束", { job: p.name, ok: r.ok });
    },
    onExhausted: (item, err) => ({
      patch: { state: "errored", outcome: "errored", reason: "interrupted" },
      effects: [notify(`⚠️ 作业「${item.payload.name}」没有完成：${truncate(err, 500)}\n作业可能已经执行了一部分，为避免重复写入不会自动重跑。需要的话用 \`pa job ${item.payload.name}\` 手动再跑一次。`)],
    }),
  };
}

const HELP = [
  "可用指令：",
  "- `/brief` 立即生成概览",
  "- `/capture` 立即识别一轮任务",
  "- `/dispatch` 立即扫描“派给Agent”列",
  "- `/do [harness] 任务描述` 新建派单任务，例如 `/do [codex] 修复登录页报错 repo: web`",
  "- `/status` 最近 24 小时的运行情况",
  "- 其他任何文字：交给 superagent 处理（可查询/整理你的任务和知识库）",
].join("\n");

/**
 * 处理你私聊机器人的消息（im.message.receive_v1，经 inbox 投递）。只听主人的。
 * 回复先算好存进 kv 再发送：发送失败重试时直接重发，不会把指令再执行一遍。
 * 指令都是幂等的；自由对话（agent 作业）是至多一次——中途被打断时告诉你，而不是悄悄重跑。
 */
export class BotHandler {
  cfg: Config;
  lark: Lark;
  store: Store;
  ledger: Ledger;
  board: Board;
  capture: Capture;
  dispatcher: Dispatcher;
  kick: () => void;

  constructor(
    cfg: Config,
    lark: Lark,
    store: Store,
    ledger: Ledger,
    board: Board,
    capture: Capture,
    dispatcher: Dispatcher,
    kick: () => void = () => undefined,
  ) {
    this.cfg = cfg;
    this.lark = lark;
    this.store = store;
    this.ledger = ledger;
    this.board = board;
    this.capture = capture;
    this.dispatcher = dispatcher;
    this.kick = kick;
  }

  async onMessage(ev: Record<string, unknown>, ctx: Ctx): Promise<void> {
    if (ev.sender_id !== this.cfg.owner.open_id || ev.chat_type !== "p2p") {
      log("warn", "忽略非主人的机器人消息", { sender: ev.sender_id, chat_type: ev.chat_type });
      return;
    }
    const messageId = String(ev.message_id ?? "");
    const text = String(ev.content ?? "").trim();
    const reply = await this.store.once(`bot.reply.${messageId}`, async () => {
      try {
        return await this.handle(text, { ...ctx, messageId });
      } catch (e) {
        if (ctx.signal.aborted) throw e; // 中止交给引擎，不缓存
        log("error", "处理机器人消息失败", { err: errMsg(e) });
        return `处理失败：${errMsg(e)}`;
      }
    });
    await this.lark.notifyOwner(reply, `reply-${messageId}`);
  }

  async handle(text: string, ctx: Ctx & { messageId: string }): Promise<string> {
    const [cmd, ...rest] = text.split(/\s+/);
    const arg = rest.join(" ").trim();
    switch (cmd) {
      case "/help":
        return HELP;
      case "/brief":
        return buildBrief(this.cfg, this.lark, this.store, this.ledger, this.board, localHour(this.cfg.owner.timezone) < 14 ? "morning" : "evening");
      case "/capture": {
        const r = await this.capture.run();
        return `新收集信号 ${r.added} 条，建任务 ${r.created} 个（在看板“待确认”/Inbox）。`;
      }
      case "/dispatch": {
        const r = await this.dispatcher.reconcile();
        this.kick();
        return `本轮新派单 ${r.enqueued} 个${r.cancelled ? `，取消 ${r.cancelled} 个` : ""}。进度会写在卡片评论里。`;
      }
      case "/do": {
        if (!arg) return "用法：/do [harness] 任务描述（可在描述中写 repo: 别名）";
        const repo = arg.match(/\brepo\s*[:：]\s*(\S+)/)?.[1];
        const summary = arg.replace(/\brepo\s*[:：]\s*\S+/, "").trim();
        const guid = await this.board.createTask({
          summary,
          description: [`由私聊指令创建：${arg}`, repo ? `repo: ${repo}` : ""].filter(Boolean).join("\n"),
          section: "dispatch",
          opKey: `bot:${ctx.messageId}`,
        });
        await this.dispatcher.reconcile();
        this.kick();
        return `已创建派单任务（${guid.slice(0, 8)}），进度会写在卡片评论里；通过验收后移到“待验收”，否则移到“需人工介入”。`;
      }
      case "/status":
        return statusText(this.ledger);
      default: {
        if (ctx.attempt > 1) {
          return "⚠️ 上次处理这条消息时进程中断了。为避免重复操作，没有自动重跑；需要的话请重新发送。";
        }
        const r = await runAgentJob(this.cfg, this.store, this.ledger, {
          name: "chat",
          task: `主人在飞书私聊里对你说：\n\n${text}\n\n完成后用中文简洁回复（你的最终回复会原样发给主人）。`,
          signal: ctx.signal,
        });
        checkpoint(ctx); // 被中止的半截输出不能当作回复缓存下来
        return truncate(r.text, 6000);
      }
    }
  }
}

const ICON: Record<string, string> = {
  accepted: "✅",
  unverified: "⚪",
  needs_human: "⚠️",
  errored: "❌",
  cancelled: "⏹️",
  dead: "💀",
  done: "✅",
};

/** 最近 24 小时的工作（派单、作业、失败的事件和飞书写入）。 */
export function statusText(ledger: Ledger): string {
  const items = ledger
    .recent(["dispatch", "job", "event", "effect"], Date.now() - 86_400_000)
    .filter((w) => w.kind === "dispatch" || w.kind === "job" || !w.terminal || w.state === "dead");
  if (!items.length) return "最近 24 小时没有运行记录。";
  return items
    .slice(-15)
    .map((w) => {
      const icon = w.terminal ? (ICON[w.state] ?? "•") : w.lease_owner ? "⏳" : w.next_at > Date.now() ? "🔁" : "🕒";
      const p = w.payload as Record<string, unknown>;
      const title = String(p.summary ?? p.name ?? w.ref);
      const extra = !w.terminal && w.attempts > 1 ? `（第 ${w.attempts} 次尝试）` : w.error ? `：${truncate(w.error, 60)}` : "";
      return `- ${icon} ${w.kind} ${w.state} ${truncate(title, 40)}${extra}`;
    })
    .join("\n");
}

function localHour(tz: string): number {
  return Number(new Intl.DateTimeFormat("en-US", { timeZone: tz, hour: "numeric", hourCycle: "h23" }).format(new Date()));
}


