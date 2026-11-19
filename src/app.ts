import { Cron } from "croner";
import { Board, KnowledgeBase } from "./board.ts";
import type { Config } from "./config.ts";
import { EventSupervisor, type Subscription } from "./events.ts";
import { loadPrompt } from "./harness.ts";
import { Lark } from "./lark.ts";
import { Store } from "./store.ts";
import { deepFind, errMsg, log, render } from "./util.ts";
import { BotHandler, runAgentJob } from "./workflows/agent.ts";
import { buildBrief } from "./workflows/brief.ts";
import { Capture } from "./workflows/capture.ts";
import { Dispatcher } from "./workflows/dispatch.ts";

/** 组装所有组件。命令行单次命令和常驻进程共用。 */
export function createApp(cfg: Config) {
  const store = new Store(cfg.dataDir);
  cfg.owner.open_id ||= store.get("owner.open_id") ?? "";
  const lark = new Lark(cfg);
  const board = new Board(cfg, lark, store);
  const kb = new KnowledgeBase(cfg, lark, store);
  const capture = new Capture(cfg, lark, store, board);
  const dispatcher = new Dispatcher(cfg, store, board);
  const bot = new BotHandler(cfg, lark, store, board, capture, dispatcher);
  return { cfg, store, lark, board, kb, capture, dispatcher, bot };
}
export type App = ReturnType<typeof createApp>;

/** 初始化：确定主人 open_id，建看板清单与分组、知识空间与节点。可重复执行。 */
export async function initApp(app: App): Promise<void> {
  if (!app.cfg.owner.open_id) {
    const status = await app.lark.run(["auth", "status", "--json"]);
    const id = String(deepFind(status, "open_id") ?? deepFind(status, "user_open_id") ?? "");
    if (!id.startsWith("ou_")) {
      throw new Error(`无法从 lark-cli auth status 得到你的 open_id，请在 config.yaml 的 owner.open_id 手动填写。输出：${JSON.stringify(status)}`);
    }
    app.cfg.owner.open_id = id;
  }
  app.store.set("owner.open_id", app.cfg.owner.open_id);
  await app.board.init();
  await app.kb.init();
}

async function sendBrief(app: App, mode: "morning" | "evening"): Promise<void> {
  const text = await buildBrief(app.cfg, app.lark, app.store, app.board, mode);
  await app.lark.notifyOwner(text, `brief-${mode}-${new Date().toISOString().slice(0, 10)}`);
}

async function runConfiguredJob(app: App, name: string): Promise<string> {
  const job = app.cfg.jobs[name];
  if (!job) throw new Error(`未定义的作业：${name}`);
  const r = await runAgentJob(app.cfg, app.store, { name, task: loadPrompt(job.prompt), harness: job.harness });
  if (job.notify) await app.lark.notifyOwner(`🗂️ 作业「${name}」${r.ok ? "完成" : "失败"}\n\n${r.text}`.slice(0, 6000));
  return r.text;
}
export { runConfiguredJob, sendBrief };

/** 常驻运行：事件长连接 + 定时任务。 */
export async function runDaemon(app: App): Promise<void> {
  const { cfg, store, capture, dispatcher, bot } = app;
  if (!cfg.owner.open_id || !store.get("board.tasklist")) throw new Error("尚未初始化，请先运行 pa init");
  const stale = store.failStaleRuns();
  if (stale) log("warn", "上次未完成的运行已标记失败", { count: stale });

  const guard = (name: string, fn: () => Promise<unknown>) => async () => {
    try {
      await fn();
    } catch (e) {
      log("error", `${name} 失败`, { err: errMsg(e) });
    }
  };
  // 任务变更后尽快看一眼派单列（拖动卡片本身没有事件，所以仍保留定时扫描）
  let scanTimer: NodeJS.Timeout | undefined;
  const scanSoon = () => {
    clearTimeout(scanTimer);
    scanTimer = setTimeout(guard("派单扫描", () => dispatcher.scan()), 5000);
  };

  const subs: Subscription[] = [];
  if (cfg.events.bot_messages) subs.push({ key: "im.message.receive_v1", as: "bot", handler: (ev) => bot.onMessage(ev) });
  if (cfg.events.task_updates) subs.push({ key: "task.task.update_user_access_v2", as: "user", handler: async () => scanSoon() });
  if (cfg.events.doc_comments) subs.push({ key: "drive.notice.comment_add_v1", as: "user", handler: (ev) => capture.onComment(ev) });
  if (cfg.events.minutes)
    subs.push({
      key: "minutes.minute.generated_v1",
      as: "user",
      handler: async (ev) => {
        await capture.onMinutes(ev);
        if (cfg.kb.minutes_notes) {
          const task = render(loadPrompt("kb-minutes.md"), { minute_token: String(ev.minute_token ?? ""), title: String(ev.title ?? "") });
          const r = await runAgentJob(cfg, store, { name: "kb-minutes", task });
          log(r.ok ? "info" : "error", "妙记整理作业结束", { title: ev.title, ok: r.ok });
        }
      },
    });
  const events = new EventSupervisor(cfg, store);
  events.start(subs);

  const opts = { timezone: cfg.owner.timezone, protect: true };
  const crons = [
    new Cron(cfg.schedules.capture, opts, guard("任务识别", () => capture.run())),
    new Cron(cfg.schedules.dispatch, opts, guard("派单扫描", () => dispatcher.scan())),
    new Cron(cfg.schedules.brief_morning, opts, guard("晨报", () => sendBrief(app, "morning"))),
    new Cron(cfg.schedules.brief_evening, opts, guard("晚报", () => sendBrief(app, "evening"))),
    new Cron("17 3 * * *", opts, guard("清理", async () => store.prune())),
    ...Object.entries(cfg.jobs).map(([name, j]) => new Cron(j.cron, opts, guard(`作业 ${name}`, () => runConfiguredJob(app, name)))),
  ];
  log("info", "personal-agent 已启动", { events: subs.map((s) => s.key), jobs: Object.keys(cfg.jobs) });

  await new Promise<void>((resolve) => {
    const shutdown = async (sig: string) => {
      log("info", "收到退出信号，正在停止", { sig });
      crons.forEach((c) => c.stop());
      clearTimeout(scanTimer);
      await events.stop();
      resolve();
    };
    process.once("SIGTERM", () => void shutdown("SIGTERM"));
    process.once("SIGINT", () => void shutdown("SIGINT"));
  });
}
