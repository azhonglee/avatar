import path from "node:path";
import type { Board } from "../board.ts";
import type { Config } from "../config.ts";
import { loadPrompt, runHarness } from "../harness.ts";
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
 * 例如整理知识库、把妙记写成纪要、回答你在私聊里的提问。
 */
export async function runAgentJob(
  cfg: Config,
  store: Store,
  job: { name: string; task: string; harness?: string },
): Promise<{ ok: boolean; text: string }> {
  const harness = job.harness ?? cfg.roles.brain;
  const logFile = path.join(cfg.dataDir, "runs", `job-${job.name}-${Date.now()}.log`);
  const runId = store.startRun({ task_guid: `job:${job.name}`, harness, role: "job", cwd: "", log: logFile });
  try {
    const r = await runHarness(cfg, {
      harness,
      prompt: `${superagentContext(cfg, store)}\n\n# 本次任务\n\n${job.task}`,
      cwd: path.join(cfg.dataDir, "workspace", "jobs", job.name),
      tools: "write",
      lark: "agent",
      timeoutSec: 1800,
      logFile,
    });
    const text = r.text || `（无输出，exit ${r.exitCode}）`;
    store.endRun(runId, r.ok ? "ok" : "failed", truncate(text, 500));
    return { ok: r.ok, text };
  } catch (e) {
    store.endRun(runId, "failed", errMsg(e));
    throw e;
  }
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

/** 处理你私聊机器人的消息（im.message.receive_v1）。只听主人的。 */
export class BotHandler {
  cfg: Config;
  lark: Lark;
  store: Store;
  board: Board;
  capture: Capture;
  dispatcher: Dispatcher;

  constructor(cfg: Config, lark: Lark, store: Store, board: Board, capture: Capture, dispatcher: Dispatcher) {
    this.cfg = cfg;
    this.lark = lark;
    this.store = store;
    this.board = board;
    this.capture = capture;
    this.dispatcher = dispatcher;
  }

  async onMessage(ev: Record<string, unknown>): Promise<void> {
    if (ev.sender_id !== this.cfg.owner.open_id || ev.chat_type !== "p2p") {
      log("warn", "忽略非主人的机器人消息", { sender: ev.sender_id, chat_type: ev.chat_type });
      return;
    }
    if (!this.store.markSeen(`botmsg:${ev.message_id}`, "bot")) return;
    const text = String(ev.content ?? "").trim();
    try {
      await this.lark.notifyOwner(await this.handle(text), `reply-${ev.message_id}`);
    } catch (e) {
      log("error", "处理机器人消息失败", { err: errMsg(e) });
      await this.lark.notifyOwner(`处理失败：${errMsg(e)}`).catch(() => undefined);
    }
  }

  async handle(text: string): Promise<string> {
    const [cmd, ...rest] = text.split(/\s+/);
    const arg = rest.join(" ").trim();
    switch (cmd) {
      case "/help":
        return HELP;
      case "/brief":
        return buildBrief(this.cfg, this.lark, this.store, this.board, localHour(this.cfg.owner.timezone) < 14 ? "morning" : "evening");
      case "/capture": {
        const r = await this.capture.run();
        return `新收集信号 ${r.added} 条，建任务 ${r.created} 个（在看板“待确认”/Inbox）。`;
      }
      case "/dispatch":
        return `本轮领取 ${await this.dispatcher.scan()} 个派单任务。`;
      case "/do": {
        if (!arg) return "用法：/do [harness] 任务描述（可在描述中写 repo: 别名）";
        const repo = arg.match(/\brepo\s*[:：]\s*(\S+)/)?.[1];
        const summary = arg.replace(/\brepo\s*[:：]\s*\S+/, "").trim();
        const guid = await this.board.createTask({
          summary,
          description: [`由私聊指令创建：${arg}`, repo ? `repo: ${repo}` : ""].filter(Boolean).join("\n"),
          section: "dispatch",
        });
        const n = await this.dispatcher.scan();
        return `已创建派单任务（${guid.slice(0, 8)}）${n ? "，已开始执行" : "，等待空闲 worker"}。完成后会出现在看板“待验收”。`;
      }
      case "/status": {
        const runs = this.store.runsSince(Date.now() - 86_400_000);
        if (!runs.length) return "最近 24 小时没有运行记录。";
        return runs
          .slice(-15)
          .map((r) => `- ${r.status === "ok" ? "✅" : r.status === "failed" ? "❌" : "⏳"} ${r.role} ${r.harness} ${r.task_guid.slice(0, 12)} ${truncate(r.summary, 80)}`)
          .join("\n");
      }
      default: {
        const r = await runAgentJob(this.cfg, this.store, { name: "chat", task: `主人在飞书私聊里对你说：\n\n${text}\n\n完成后用中文简洁回复（你的最终回复会原样发给主人）。` });
        return truncate(r.text, 6000);
      }
    }
  }
}

function localHour(tz: string): number {
  return Number(new Intl.DateTimeFormat("en-US", { timeZone: tz, hour: "numeric", hourCycle: "h23" }).format(new Date()));
}
