/**
 * 用量与预算：acpx 用量输出解析、计费、按本地日 / harness 汇总、预算守卫（含经引擎驱动的派单被暂停）。
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test, type TestContext } from "node:test";
import { fileURLToPath } from "node:url";
import { createApp, initApp, type App } from "../src/app.ts";
import { loadConfig } from "../src/config.ts";
import { runHarness } from "../src/harness.ts";
import type { WorkItem } from "../src/ledger.ts";
import { budgetGuard, costOf, localDay, parseUsage, usageSummary } from "../src/usage.ts";
import type { DispatchPayload } from "../src/workflows/dispatch.ts";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const STUBS = path.join(ROOT, "test", "stubs");

function mkApp(t: TestContext, extra: Record<string, unknown> = {}): { app: App; dir: string } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pa-usage-"));
  const file = path.join(dir, "config.yaml");
  fs.writeFileSync(
    file,
    JSON.stringify({
      data_dir: path.join(dir, "data"),
      bins: { lark: path.join(STUBS, "lark-cli"), acpx: path.join(STUBS, "acpx") },
      harnesses: { claude: { agent: "claude" }, codex: { agent: "codex" } },
      roles: { brain: "claude", reviewer: "codex" },
      owner: { open_id: "ou_owner", timezone: "Asia/Shanghai" },
      ...extra,
    }),
  );
  const app = createApp(loadConfig(file));
  t.after(() => {
    app.store.db.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });
  return { app, dir };
}

/** 往账本里放一项派单和一步带用量的 harness 运行。 */
function seedStep(app: App, o: { guid: string; harness: string; started: number; usd: number; tin?: number; tout?: number; dur?: number; summary?: string; workId?: string }): string {
  const id = o.workId ?? `dispatch:${o.guid}:${Math.random().toString(36).slice(2)}`;
  if (!app.ledger.get(id)) {
    app.ledger.enqueue({ id, kind: "dispatch", ref: o.guid, state: "accepted", payload: { guid: o.guid, summary: o.summary ?? `[codex] 任务 ${o.guid}` } });
    app.ledger.db.prepare("UPDATE work SET terminal = 1 WHERE id = ?").run(id);
  }
  app.ledger.db
    .prepare(
      "INSERT INTO steps (work_id, name, harness, status, started, ended, tokens_in, tokens_out, cost_usd, duration_ms) VALUES (?, 'worker#1', ?, 'ok', ?, ?, ?, ?, ?, ?)",
    )
    .run(id, o.harness, o.started, o.started + (o.dur ?? 1000), o.tin ?? 0, o.tout ?? 0, o.usd, o.dur ?? 1000);
  return id;
}

test("解析：acpx quiet 模式写到 stderr 的 tokens / cost 行", () => {
  const u = parseUsage("[acpx] permission: denied x\n[acpx] tokens: input=17030 output=4 cache_read=12 cache_write=3 total=17049\n[acpx] cost: 0.051276 USD\n");
  assert.deepEqual(u, { input: 17030, output: 4, cache_read: 12, cache_write: 3, cost_usd: 0.051276 });
  // 只有 tokens，没有 cost
  assert.deepEqual(parseUsage("[acpx] tokens: input=100 output=20\n"), { input: 100, output: 20, cache_read: 0, cache_write: 0 });
  // 只有 total：全部算输入（保守）
  assert.equal(parseUsage("[acpx] tokens: total=500\n")?.input, 500);
  // 非美元费用不采信（交给单价估算）
  assert.equal(parseUsage("[acpx] tokens: input=1 output=1\n[acpx] cost: 3.5 CNY\n")?.cost_usd, undefined);
  // 无币种按美元
  assert.equal(parseUsage("[acpx] cost: 0.2\n")?.cost_usd, 0.2);
});

test("解析：通用 JSON 字段（Anthropic / OpenAI 风格），没有用量返回 undefined", () => {
  const claude = parseUsage(
    'debug\n{"type":"result","usage":{"input_tokens":10,"cache_creation_input_tokens":5,"cache_read_input_tokens":200,"output_tokens":30},"total_cost_usd":0.0123}\n',
  );
  assert.deepEqual(claude, { input: 10, output: 30, cache_read: 200, cache_write: 5, cost_usd: 0.0123 });
  const openai = parseUsage('{"usage": {"prompt_tokens": 1200, "completion_tokens": 340, "total_tokens": 1540}}');
  assert.deepEqual(openai, { input: 1200, output: 340, cache_read: 0, cache_write: 0 });
  assert.equal(parseUsage(""), undefined);
  assert.equal(parseUsage("[acpx] error: TIMEOUT took too long\n"), undefined);
  assert.equal(parseUsage("some warning about tokens\n"), undefined);
});

test("计费：上报的美元费用优先；否则按每百万 token 单价估算（缓存读取打一折）；都没有为 0", () => {
  const u = { input: 1_000_000, output: 200_000, cache_read: 0, cache_write: 0 };
  assert.equal(costOf(u, { input: 3, output: 15 }), 3 + 3);
  assert.equal(costOf({ ...u, cache_read: 1_000_000 }, { input: 3, output: 15 }), 6 + 0.3);
  assert.equal(costOf({ ...u, cache_write: 500_000 }, { input: 2, output: 0 }), 3);
  assert.equal(costOf({ ...u, cost_usd: 0.5 }, { input: 3, output: 15 }), 0.5);
  assert.equal(costOf(u, undefined), 0);
});

test("记录：runHarness 结束后把 acpx 报告的 token 写进步骤并按单价计费；没有用量只留耗时", async (t) => {
  const { app, dir } = mkApp(t, { budget: { pricing: { claude: { input: 3, output: 15 } } } });
  const fake = path.join(dir, "fake-acpx.mjs");
  fs.writeFileSync(
    fake,
    `#!/usr/bin/env node
import fs from "node:fs";
fs.readFileSync(0, "utf8");
process.stdout.write('回复正文里提到 "input_tokens": 999999 不算数\\n');
if (process.env.FAKE_USAGE) process.stderr.write("[acpx] tokens: input=1000 cache_read=10000 output=500 total=11500\\n");
`,
  );
  fs.chmodSync(fake, 0o755);
  app.cfg.bins.acpx = fake;
  const run = async (harness: string) => {
    const step = app.ledger.startStep({ work_id: "w1", name: "worker#1", harness });
    await runHarness(app.cfg, { harness, prompt: "hi", cwd: path.join(dir, "ws"), tools: "none", lark: "none", timeoutSec: 30, logFile: path.join(dir, `${step}.log`), stepId: step });
    return app.ledger.step(step)!;
  };
  process.env.FAKE_USAGE = "1";
  try {
    const s = await run("claude");
    assert.equal(s.tokens_in, 11000);
    assert.equal(s.tokens_out, 500);
    assert.ok(Math.abs(s.cost_usd - (1000 * 3 + 10000 * 0.1 * 3 + 500 * 15) / 1e6) < 1e-12);
    // 没配单价的 harness：只记 token
    const c = await run("codex");
    assert.equal(c.tokens_in, 11000);
    assert.equal(c.cost_usd, 0);
  } finally {
    delete process.env.FAKE_USAGE;
  }
  const none = await run("claude");
  assert.equal(none.tokens_in, 0);
  assert.equal(none.cost_usd, 0);
});

test("汇总：按 owner.timezone 的本地日、按 harness 分组，花费最多的任务按卡片合计", (t) => {
  const { app } = mkApp(t, { budget: { daily_usd: 5, per_task_usd: 2 } });
  const now = Date.parse("2026-11-20T10:00:00+08:00");
  // 本地 11-20 01:00（UTC 还是 11-19）
  const a = seedStep(app, { guid: "g_a", harness: "codex", started: Date.parse("2026-11-20T01:00:00+08:00"), usd: 1.5, tin: 100, tout: 10, dur: 2000, summary: "[codex] 修登录 bug" });
  seedStep(app, { guid: "g_a", harness: "claude", started: Date.parse("2026-11-20T02:00:00+08:00"), usd: 0.5, tin: 50, tout: 5, dur: 1000, workId: a });
  // 同一张卡片的另一次派单（更新的）
  const a2 = seedStep(app, { guid: "g_a", harness: "codex", started: Date.parse("2026-11-20T03:00:00+08:00"), usd: 1, summary: "[codex] 修登录 bug（返工）" });
  seedStep(app, { guid: "g_b", harness: "claude", started: Date.parse("2026-11-19T23:30:00+08:00"), usd: 0.25, tin: 10, tout: 1 });
  // 窗口外
  seedStep(app, { guid: "g_old", harness: "claude", started: Date.parse("2026-11-10T12:00:00+08:00"), usd: 100 });
  // 校验命令（无 harness）不计入
  app.ledger.db.prepare("INSERT INTO steps (work_id, name, harness, status, started, duration_ms) VALUES (?, 'verify#1', '', 'ok', ?, 99999)").run(a, now - 1000);

  assert.equal(localDay(Date.parse("2026-11-20T01:00:00+08:00"), "Asia/Shanghai"), "2026-11-20");
  const s = usageSummary(app, 3, now);
  assert.equal(s.days, 3);
  assert.deepEqual(s.by_day.map((d) => d.day), ["2026-11-18", "2026-11-19", "2026-11-20"]);
  assert.deepEqual(s.by_day.map((d) => d.usd), [0, 0.25, 3]);
  assert.equal(s.by_day[2].tokens_in, 150);
  assert.equal(s.by_day[2].duration_ms, 4000);
  assert.equal(s.total_usd, 3.25);
  assert.deepEqual(
    s.by_harness.map((h) => [h.harness, h.usd, h.runs]),
    [["codex", 2.5, 2], ["claude", 0.75, 2]],
  );
  assert.equal(s.top_tasks.length, 2);
  assert.deepEqual(s.top_tasks[0], { dispatch_id: a2, summary: "修登录 bug（返工）", usd: 3 });
  assert.equal(s.top_tasks[1].usd, 0.25);
  assert.equal(s.metered, true);
  assert.equal(s.budget.daily_usd, 5);
  assert.equal(s.budget.per_task_usd, 2);
  assert.equal(s.budget.exceeded, false);
  // 窗口里没有任何 token / 费用：metered = false
  const empty = usageSummary(app, 1, Date.parse("2026-12-20T10:00:00+08:00"));
  assert.equal(empty.metered, false);
  assert.equal(empty.total_usd, 0);
  assert.equal(empty.by_day.length, 1);
  assert.equal(app.ext.usage?.summary(7).days, 7);
});

test("预算守卫：每日预算与单任务预算（同一张卡片所有派单合计），实时读取配置", (t) => {
  const { app } = mkApp(t);
  const item = (guid: string, id: string) => ({ id, ref: guid, payload: { guid } }) as unknown as WorkItem<DispatchPayload>;
  const prev = seedStep(app, { guid: "g_task", harness: "codex", started: Date.now() - 60_000, usd: 0.6 });
  seedStep(app, { guid: "g_other", harness: "codex", started: Date.now() - 60_000, usd: 0.3 });
  const cur = item("g_task", "dispatch:g_task:new");
  assert.equal(budgetGuard(app, cur), undefined, "预算为 0 表示不限制");
  // 设置热更新：直接改 cfg
  app.cfg.budget.daily_usd = 1;
  assert.equal(budgetGuard(app, cur), undefined);
  app.cfg.budget.daily_usd = 0.9;
  assert.match(budgetGuard(app, cur) ?? "", /今日花费 \$0\.9000 已达每日预算 \$0\.9000/);
  app.cfg.budget.daily_usd = 0;
  app.cfg.budget.per_task_usd = 0.5;
  assert.match(budgetGuard(app, cur) ?? "", /这张卡片累计花费 \$0\.6000 已达单任务预算 \$0\.5000/);
  assert.equal(budgetGuard(app, item("g_other", "dispatch:g_other:new")), undefined, "其他卡片的花费不算");
  assert.ok(prev);
  assert.equal(app.ext.usage?.summary(1).budget.today_usd, 0.9);
});

test("预算守卫接入派单：超出预算的派单经引擎驱动后结束为 needs_human / budget，卡片进“需人工介入”，不运行 harness", async (t) => {
  const { app, dir } = mkApp(t);
  process.env.STUB_STATE = path.join(dir, "stub-state.json");
  process.env.STUB_ACPX_LOG = path.join(dir, "acpx-calls.ndjson");
  t.after(() => {
    delete process.env.STUB_STATE;
    delete process.env.STUB_ACPX_LOG;
  });
  await initApp(app);
  const st = JSON.parse(fs.readFileSync(process.env.STUB_STATE, "utf8"));
  st.tasks.task_budget = { guid: "task_budget", summary: "[codex] 很贵的任务", description: "", section: "sec_派给Agent", comments: [] };
  fs.writeFileSync(process.env.STUB_STATE, JSON.stringify(st));
  seedStep(app, { guid: "g_spent", harness: "claude", started: Date.now() - 1000, usd: 2 });
  app.cfg.budget.daily_usd = 1;

  await app.dispatcher.reconcile();
  await app.engine.drain(["dispatch", "effect"]);
  const w = app.ledger.latest<DispatchPayload>("dispatch", "task_budget")!;
  assert.equal(w.state, "needs_human");
  assert.equal(w.reason, "budget");
  assert.equal(w.terminal, true);
  const task = JSON.parse(fs.readFileSync(process.env.STUB_STATE, "utf8")).tasks.task_budget;
  assert.equal(task.section, "sec_需人工介入");
  assert.match(task.comments.join("\n"), /超出用量预算，已暂停：今日花费 \$2\.00 已达每日预算 \$1\.00/);
  assert.ok(!fs.existsSync(process.env.STUB_ACPX_LOG), "预算超出时不应调用 harness");
});
