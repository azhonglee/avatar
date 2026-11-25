/**
 * 跨模块集成测试：验证命令层、HTTP API、飞书卡片、交付、用量与预算、候选反馈、设置与体检
 * 在同一个 App 里协同工作（真实 SQLite + 真实 git worktree + 桩 lark-cli）。
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { createApp, initApp, type App } from "../src/app.ts";
import type { CandidateList, CommandResult, DiffView, DispatchDetail, DoctorReport, Meta, SettingsUpdateResult, SettingsView, UsageSummary } from "../src/api/types.ts";
import { loadConfig } from "../src/config.ts";
import { serverToken, startServer, type ConsoleServer } from "../src/server/index.ts";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "pa-int-"));
const STUB_STATE = path.join(tmp, "stub-state.json");
let app: App;
let srv: ConsoleServer;
let token: string;
let repoDir: string;

before(async () => {
  process.env.STUB_STATE = STUB_STATE;
  repoDir = path.join(tmp, "repo");
  fs.mkdirSync(repoDir);
  execFileSync("git", ["-C", repoDir, "init", "-q", "-b", "main"]);
  fs.writeFileSync(path.join(repoDir, "app.txt"), "v1\n");
  execFileSync("git", ["-C", repoDir, "add", "-A"]);
  execFileSync("git", ["-C", repoDir, "-c", "user.name=t", "-c", "user.email=t@x", "commit", "-qm", "init"]);

  const cfgFile = path.join(tmp, "config.yaml");
  fs.writeFileSync(
    cfgFile,
    `# 保留注释测试
data_dir: ${path.join(tmp, "data")}
bins:
  lark: ${path.join(ROOT, "test/stubs/lark-cli")}
  acpx: ${path.join(ROOT, "test/stubs/acpx")}
owner:
  open_id: ou_owner
  timezone: Asia/Shanghai
harnesses:
  claude:
    agent: claude
    env:
      SECRET_KEY: plain_secret_value
      REF_KEY: \${MY_ENV_VAR}
  codex:
    agent: codex
roles:
  brain: claude
  reviewer: codex
dispatch:
  default_harness: claude
  repos:
    demo:
      path: ${repoDir}
budget:
  daily_usd: 10
  pricing:
    codex: { input: 3, output: 15 }
server:
  port: 0
cards:
  enabled: true
`,
  );
  app = createApp(loadConfig(cfgFile));
  await initApp(app);
  srv = await startServer(app, { version: "0.2.0-int", port: 0 });
  token = serverToken(app);
});

after(async () => {
  await srv.close();
  app.store.db.close();
  fs.rmSync(tmp, { recursive: true, force: true });
});

const api = (p: string, init: RequestInit = {}) =>
  fetch(srv.url + p, {
    ...init,
    headers: { Authorization: `Bearer ${token}`, ...(init.headers ?? {}) },
  });
const cmd = (name: string, args: unknown) =>
  api(`/api/commands/${name}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ args }) });
const stubState = () => JSON.parse(fs.readFileSync(STUB_STATE, "utf8")) as { tasks: Record<string, { section: string; comments: string[] }>; messages: { msg_type?: string; card?: unknown; markdown?: string }[] };

test("集成：元信息展示全部 7 个模块已启用，体检返回结构化报告", async () => {
  const m = (await (await api("/api/meta")).json()) as Meta;
  assert.deepEqual(m.features, { cards: true, delivery: true, usage: true, settings: true, doctor: true, candidates: true, context: true });
  assert.equal(m.repos[0].alias, "demo");
  const cmds = (await (await api("/api/commands")).json()) as string[];
  for (const name of ["dispatch.create", "dispatch.rework", "delivery.create_pr", "delivery.merge_local", "candidate.confirm", "candidate.reject", "work.retry"]) {
    assert.ok(cmds.includes(name), `缺少命令 ${name}`);
  }
  const doc = (await (await api("/api/doctor")).json()) as DoctorReport;
  assert.ok(doc.checks.length >= 10);
  assert.equal(doc.checks.find((c) => c.id === "board")?.status, "ok");
});

test("集成：设置脱敏读取、热加载预算并保留 YAML 注释、拒绝修改受保护字段", async () => {
  const s = (await (await api("/api/settings")).json()) as SettingsView;
  const harnesses = s.config.harnesses as Record<string, { env: Record<string, string> }>;
  assert.equal(harnesses.claude.env.SECRET_KEY, "******", "明文环境变量打码");
  assert.equal(harnesses.claude.env.REF_KEY, "${MY_ENV_VAR}", "环境变量引用原样显示");

  const r = (await (
    await api("/api/settings", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ budget: { daily_usd: 0.05 } }) })
  ).json()) as SettingsUpdateResult;
  assert.equal(r.ok, true);
  assert.equal(r.restart_required, false);
  assert.equal(app.cfg.budget.daily_usd, 0.05, "内存配置已热更新");
  assert.match(fs.readFileSync(app.cfg.file, "utf8"), /# 保留注释测试/);

  // 删除映射中的最后一个键（前端 diffPatch 发送 null）：YAML 仍可正常校验，且键确实被删除
  const del = (await (
    await api("/api/settings", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ budget: { pricing: { codex: null } } }) })
  ).json()) as SettingsUpdateResult;
  assert.equal(del.ok, true, JSON.stringify(del.errors));
  assert.deepEqual(app.cfg.budget.pricing, {});

  const bad = await api("/api/settings", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ data_dir: "/tmp/evil" }) });
  assert.equal(bad.status, 400);
});

test("集成：候选任务 → 发出交互卡片 → 经 API 确认 → 移到 Inbox 并更新准确率与卡片", async () => {
  const taskGuid = await app.board.createTask({ summary: "评审 Q4 预算", description: "来源：群聊@我", section: "pending" });
  app.store.addSignal({ id: "msg:int_1", source: "群聊@我", text: "@主人 请评审 Q4 预算", link: "https://feishu.cn/x" });
  app.store.setVerdict("msg:int_1", "task(0.82)", taskGuid);
  app.bus.emit("candidate.created", { signalId: "msg:int_1", taskGuid, summary: "评审 Q4 预算", section: "pending" });
  // 建卡是异步的（先读任务信息）：等卡片进入 outbox，而不是固定睡一段时间（负载高时会不稳定）
  for (let i = 0; i < 100 && !app.ledger.list({ kinds: ["effect"], ref: "card:candidate:msg:int_1", limit: 1 }).length; i++) await new Promise((r) => setTimeout(r, 20));
  await app.engine.drain(["effect"]);
  assert.ok(stubState().messages.some((m) => m.msg_type === "interactive" && JSON.stringify(m.card).includes("评审 Q4 预算")));

  const res = (await (await cmd("candidate.confirm", { signal_id: "msg:int_1" })).json()) as CommandResult;
  assert.equal(res.ok, true);
  await app.engine.drain(["effect"]);
  assert.equal(stubState().tasks[taskGuid].section, "sec_Inbox");

  const list = (await (await api("/api/candidates?days=7")).json()) as CandidateList;
  assert.equal(list.stats.confirmed, 1);
  assert.equal(list.stats.precision, 1);
  assert.equal(list.items.find((x) => x.signal_id === "msg:int_1")?.feedback, "confirmed");
});

test("集成：派单 diff 浏览 + 本地快进合并交付 + 用量与热更新预算联动", async () => {
  const taskGuid = await app.board.createTask({ summary: "[codex] 更新 app.txt", description: "repo: demo", section: "review" });
  const base = execFileSync("git", ["-C", repoDir, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  const wt = path.join(app.cfg.dataDir, "worktrees", taskGuid.slice(0, 8));
  const branch = `pa/${taskGuid.slice(0, 8)}`;
  execFileSync("git", ["-C", repoDir, "worktree", "add", "-b", branch, wt]);
  fs.writeFileSync(path.join(wt, "app.txt"), "v2 from agent\n");
  execFileSync("git", ["-C", wt, "add", "-A"]);
  execFileSync("git", ["-C", wt, "-c", "user.name=t", "-c", "user.email=t@x", "commit", "-qm", "update app"]);

  const dispatchId = `dispatch:${taskGuid}:1`;
  app.ledger.enqueue({
    id: dispatchId,
    kind: "dispatch",
    ref: taskGuid,
    state: "accepted",
    payload: {
      guid: taskGuid,
      summary: "[codex] 更新 app.txt",
      description: "repo: demo",
      harness: "codex",
      reviewer: "claude",
      verify: "",
      cwd: wt,
      branch,
      base,
      round: 1,
      maxRounds: 2,
      checkpoints: {},
      report: "已把 app.txt 更新为 v2",
      feedback: "",
      history: [{ round: 1, checks: [{ kind: "review", name: "claude 审查", status: "pass", detail: "没问题" }] }],
    },
  });
  app.ledger.db.prepare("UPDATE work SET terminal = 1, outcome = 'accepted', reason = 'passed' WHERE id = ?").run(dispatchId);

  // 记一步用量（$0.06 > 前面热更新后的 0.05 每日预算）
  const stepId = app.ledger.startStep({ work_id: dispatchId, name: "worker#1", harness: "codex" });
  app.ledger.endStep(stepId, "ok", "done");
  app.ledger.setStepUsage(stepId, { tokens_in: 10_000, tokens_out: 2_000, cost_usd: 0.06 });

  const detail = (await (await api(`/api/dispatches/${encodeURIComponent(dispatchId)}`)).json()) as DispatchDetail;
  assert.ok(detail.actions.includes("delivery.merge_local"));
  assert.equal(detail.cost_usd, 0.06);

  const diff = (await (await api(`/api/dispatches/${encodeURIComponent(dispatchId)}/diff`)).json()) as DiffView;
  assert.match(diff.patch, /\+v2 from agent/);

  const merged = (await (await cmd("delivery.merge_local", { id: dispatchId })).json()) as CommandResult;
  assert.equal(merged.ok, true);
  await app.engine.drain(["delivery", "effect"]);
  assert.equal(fs.readFileSync(path.join(repoDir, "app.txt"), "utf8"), "v2 from agent\n", "主仓库已快进合并");

  const afterDetail = (await (await api(`/api/dispatches/${encodeURIComponent(dispatchId)}`)).json()) as DispatchDetail;
  assert.equal(afterDetail.delivery, "merged_local");
  assert.ok(!afterDetail.actions.includes("delivery.merge_local"), "合并后不再显示合并按钮");

  const usage = (await (await api("/api/usage?days=7")).json()) as UsageSummary;
  assert.equal(usage.metered, true);
  assert.ok(usage.total_usd >= 0.06);
  assert.equal(usage.budget.daily_usd, 0.05);
  assert.equal(usage.budget.exceeded, true, "已触发热更新后的每日预算上限");
});
