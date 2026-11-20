import { Cron } from "croner";
import { Board, KnowledgeBase } from "./board.ts";
import type { Config } from "./config.ts";
import { effectHandler, notify } from "./effects.ts";
import { Engine, type Handler } from "./engine.ts";
import { EventSupervisor, type Subscription } from "./events.ts";
import { loadPrompt } from "./harness.ts";
import { Lark } from "./lark.ts";
import { Ledger, type WorkItem } from "./ledger.ts";
import { Store } from "./store.ts";
import { deepFind, errMsg, log, render, truncate } from "./util.ts";
import { BotHandler, enqueueJob, jobHandler, type JobPayload } from "./workflows/agent.ts";
import { buildBrief } from "./workflows/brief.ts";
import { Capture } from "./workflows/capture.ts";
import { Dispatcher, type DispatchPayload } from "./workflows/dispatch.ts";

/**
 * 组装所有组件。命令行单次命令和常驻进程共用。
 *
 *   输入（事件 / 轮询 / 看板拖动 / cron） → 账本（work 表） → 引擎领取执行 → outbox → 飞书
 *
 * 详见 docs/可靠性设计.md。
 */
export function createApp(cfg: Config) {
  const store = new Store(cfg.dataDir);
  cfg.owner.open_id ||= store.get("owner.open_id") ?? "";
  const ledger = new Ledger(store.db);
  const lark = new Lark(cfg);
  const board = new Board(cfg, lark, store);
  const kb = new KnowledgeBase(cfg, lark, store);
  const capture = new Capture(cfg, lark, store, board);
  const dispatcher = new Dispatcher(cfg, ledger, store, board);
  const engine = new Engine(ledger, {
    leaseMs: cfg.engine.lease_sec * 1000,
    tickMs: cfg.engine.tick_ms,
    retryBaseMs: cfg.engine.retry_base_ms,
    retryMaxMs: cfg.engine.retry_max_ms,
    globalLimit: { dispatch: cfg.dispatch.max_parallel },
  });
  const bot = new BotHandler(cfg, lark, store, ledger, board, capture, dispatcher, () => engine.kick());
  const hooks = { onTaskUpdate: () => undefined as void, onSignals: () => undefined as void };
  const app = { cfg, store, ledger, lark, board, kb, capture, dispatcher, engine, bot, hooks };
  engine.register(effectHandler(cfg, ledger, board, lark));
  engine.register(dispatcher.handler());
  engine.register(jobHandler(cfg, store, ledger));
  engine.register(eventHandler(app));
  return app;
}
export type App = ReturnType<typeof createApp>;

/**
 * inbox 处理器：飞书事件落库后由这里处理。每个分支都是幂等的，失败抛错即可，引擎会退避重试；
 * 重试耗尽私信告诉你。这里只做“把输入变成账本里的工作”，耗时的事交给对应的工作类型。
 */
function eventHandler(app: Pick<App, "cfg" | "ledger" | "capture" | "bot" | "engine" | "hooks">): Handler<Record<string, unknown>> {
  const { cfg, ledger, capture, bot, engine, hooks } = app;
  return {
    kind: "event",
    concurrency: 3,
    maxAttempts: cfg.engine.event_attempts,
    // 事件处理器大多幂等，多算一次尝试无妨；私聊里的自由对话靠这一点在重启后识别“上次被中断”
    refundOnStop: false,
    async run(item, ctx) {
      const ev = item.payload;
      switch (item.ref) {
        case "im.message.receive_v1":
          await bot.onMessage(ev, ctx);
          break;
        case "task.task.update_user_access_v2":
          hooks.onTaskUpdate();
          break;
        case "drive.notice.comment_add_v1":
          if (await capture.onComment(ev)) hooks.onSignals();
          break;
        case "minutes.minute.generated_v1": {
          if (await capture.onMinutes(ev)) hooks.onSignals();
          const token = String(ev.minute_token ?? "");
          if (cfg.kb.minutes_notes && token) {
            const task = render(loadPrompt("kb-minutes.md"), { minute_token: token, title: String(ev.title ?? "") });
            if (enqueueJob(ledger, `kb-minutes:${token}`, { name: "kb-minutes", task, notify: false })) engine.kick();
          }
          break;
        }
        default:
          log("warn", "未知事件类型，忽略", { key: item.ref });
      }
      ledger.transition(item, { state: "done", terminal: true });
    },
    onExhausted: (item, err) => ({
      patch: { state: "dead" },
      effects: [notify(`⚠️ 飞书事件 ${item.ref} 处理失败，已重试 ${cfg.engine.event_attempts} 次：${truncate(err, 500)}`)],
    }),
  };
}

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

/** 生成概览并经 outbox 私信（同一天同一种只发一次）。 */
export async function sendBrief(app: App, mode: "morning" | "evening"): Promise<void> {
  const text = await buildBrief(app.cfg, app.lark, app.store, app.ledger, app.board, mode);
  app.ledger.emit("brief", [notify(text)], `brief-${mode}-${new Date().toISOString().slice(0, 10)}`);
}

/** 立即执行一个配置的作业并等待结果（命令行用）。 */
export async function runConfiguredJob(app: App, name: string): Promise<string> {
  const job = app.cfg.jobs[name];
  if (!job) throw new Error(`未定义的作业：${name}`);
  const id = `${name}:manual-${Date.now()}`;
  enqueueJob(app.ledger, id, { name, task: loadPrompt(job.prompt), harness: job.harness, notify: job.notify });
  await app.engine.drain(["job", "effect"]);
  const w = app.ledger.get<JobPayload>(`job:${id}`);
  return w?.payload.result ?? `作业状态：${w?.state ?? "未知"}${w?.error ? `（${w.error}）` : ""}`;
}

/** 命令行单次派单：对账后把能做的派单做完，返回本次涉及的派单。 */
export async function runDispatchOnce(app: App): Promise<{ enqueued: number; items: (WorkItem<DispatchPayload> | undefined)[] }> {
  const r = await app.dispatcher.reconcile();
  const before = new Set(app.ledger.active("dispatch").map((w) => w.id));
  await app.engine.drain(["dispatch", "effect"]);
  return { enqueued: r.enqueued, items: [...before].map((id) => app.ledger.get<DispatchPayload>(id)) };
}

/** 常驻运行：事件长连接 + 定时任务 + 工作引擎。 */
export async function runDaemon(app: App): Promise<void> {
  const { cfg, store, ledger, board, capture, dispatcher, engine, hooks } = app;
  if (!cfg.owner.open_id || !store.get("board.tasklist")) throw new Error("尚未初始化，请先运行 pa init");
  if (!board.isInitialized()) {
    await board.init(); // 升级后新增的看板分组（如“需人工介入”）
    log("info", "已补建新增的看板分组");
  }

  const guard = (name: string, fn: () => Promise<unknown>) => async () => {
    try {
      await fn();
    } catch (e) {
      log("error", `${name} 失败`, { err: errMsg(e) });
    }
  };
  const debounce = (ms: number, fn: () => Promise<unknown>) => {
    let t: NodeJS.Timeout | undefined;
    const call = () => {
      clearTimeout(t);
      t = setTimeout(fn, ms);
    };
    call.cancel = () => clearTimeout(t);
    return call;
  };
  // 看板对账：拖动卡片没有事件，所以定时 + 任务变更事件提示时都跑；正确性不依赖事件
  const reconcileSoon = debounce(
    3000,
    guard("看板对账", async () => {
      await dispatcher.reconcile();
      engine.kick();
    }),
  );
  const triageSoon = debounce(2000, guard("任务识别", () => capture.process()));
  hooks.onTaskUpdate = reconcileSoon;
  hooks.onSignals = triageSoon;

  engine.start();
  const subs: Subscription[] = [];
  if (cfg.events.bot_messages) subs.push({ key: "im.message.receive_v1", as: "bot" });
  if (cfg.events.task_updates) subs.push({ key: "task.task.update_user_access_v2", as: "user" });
  if (cfg.events.doc_comments) subs.push({ key: "drive.notice.comment_add_v1", as: "user" });
  if (cfg.events.minutes) subs.push({ key: "minutes.minute.generated_v1", as: "user" });
  const events = new EventSupervisor(cfg, (key, id, ev) => {
    if (ledger.enqueue({ id: `event:${key}:${id}`, kind: "event", ref: key, payload: ev })) engine.kick();
  });
  events.start(subs);

  const opts = { timezone: cfg.owner.timezone, protect: true };
  const slot = (c: Cron) => (c.currentRun() ?? new Date()).toISOString().slice(0, 16);
  const crons = [
    new Cron(cfg.schedules.capture, opts, guard("任务识别", () => capture.run())),
    new Cron(cfg.schedules.dispatch, opts, async () => reconcileSoon()),
    new Cron(cfg.schedules.brief_morning, opts, guard("晨报", async () => (await sendBrief(app, "morning"), engine.kick()))),
    new Cron(cfg.schedules.brief_evening, opts, guard("晚报", async () => (await sendBrief(app, "evening"), engine.kick()))),
    new Cron(
      "17 3 * * *",
      opts,
      guard("清理", async () => {
        store.prune();
        ledger.prune();
      }),
    ),
    ...Object.entries(cfg.jobs).map(
      ([name, j]) =>
        new Cron(j.cron, opts, (c: Cron) => {
          // 按“名称 + 计划时间”去重：同一时间槽只跑一次
          if (enqueueJob(ledger, `${name}:${slot(c)}`, { name, task: loadPrompt(j.prompt), harness: j.harness, notify: j.notify })) engine.kick();
        }),
    ),
  ];
  reconcileSoon(); // 启动时先对一次账：停机期间拖进派单列的卡片、被拖走的卡片
  log("info", "personal-agent 已启动", { owner: ledger.owner, events: subs.map((s) => s.key), jobs: Object.keys(cfg.jobs) });

  await new Promise<void>((resolve) => {
    const shutdown = async (sig: string) => {
      log("info", "收到退出信号，正在停止", { sig });
      crons.forEach((c) => c.stop());
      reconcileSoon.cancel();
      triageSoon.cancel();
      await events.stop();
      await engine.stop(); // 中止进行中的 harness；租约释放，下次启动从检查点继续
      resolve();
    };
    process.once("SIGTERM", () => void shutdown("SIGTERM"));
    process.once("SIGINT", () => void shutdown("SIGINT"));
  });
}
