/**
 * 候选任务与分诊反馈：signals 迁移、列表与准确率、确认 / 驳回 / 直接派单命令的效果与前置条件、
 * 待确认计数、分诊提示词里的历史判断校准样例。
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test, type TestContext } from "node:test";
import { fileURLToPath } from "node:url";
import { createApp, initApp, type App } from "../src/app.ts";
import { migrateSignals, parseConfidence, withRepoLine } from "../src/candidates.ts";
import { CommandError } from "../src/commands.ts";
import { loadConfig } from "../src/config.ts";
import { Store } from "../src/store.ts";
import { triage } from "../src/workflows/triage.ts";
import type { DispatchPayload } from "../src/workflows/dispatch.ts";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const STUBS = path.join(ROOT, "test", "stubs");
const DAY = 86_400_000;
const ctx = { source: "web" as const, actor: "owner" };

function mkApp(t: TestContext): { app: App; dir: string; file: string } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pa-cand-"));
  const repo = path.join(dir, "demo-repo");
  fs.mkdirSync(repo);
  const file = path.join(dir, "config.yaml");
  fs.writeFileSync(
    file,
    JSON.stringify({
      data_dir: path.join(dir, "data"),
      bins: { lark: path.join(STUBS, "lark-cli"), acpx: path.join(STUBS, "acpx") },
      harnesses: { claude: { agent: "claude" }, codex: { agent: "codex" } },
      roles: { brain: "claude", reviewer: "codex" },
      owner: { open_id: "ou_owner" },
      dispatch: { repos: { demo: repo } },
    }),
  );
  const app = createApp(loadConfig(file));
  t.after(() => {
    app.store.db.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });
  return { app, dir, file };
}

/** 放一条信号；task 给出时同时在桩看板上建卡。 */
function seed(app: App, id: string, o: { verdict: string; task?: string; at?: number; text?: string; section?: string; summary?: string; feedback?: string; reason?: string }) {
  app.store.addSignal({ id, source: "群聊@我", text: o.text ?? `信号 ${id} 的原文`, link: "" });
  app.store.setVerdict(id, o.verdict, o.task ?? "");
  if (o.at !== undefined) app.store.db.prepare("UPDATE signals SET at = ? WHERE id = ?").run(o.at, id);
  if (o.section !== undefined || o.summary !== undefined)
    app.store.db.prepare("UPDATE signals SET section = ?, summary = ? WHERE id = ?").run(o.section ?? "", o.summary ?? "", id);
  if (o.feedback) app.store.db.prepare("UPDATE signals SET feedback = ?, feedback_at = ?, feedback_reason = ? WHERE id = ?").run(o.feedback, Date.now(), o.reason ?? null, id);
}

/** 带有状态桩看板的 app（命令测试用）。 */
async function boardApp(t: TestContext) {
  const env = mkApp(t);
  const statePath = path.join(env.dir, "stub-state.json");
  process.env.STUB_STATE = statePath;
  t.after(() => void delete process.env.STUB_STATE);
  await initApp(env.app);
  const state = () => JSON.parse(fs.readFileSync(statePath, "utf8"));
  const addTask = (guid: string, description: string) => {
    const s = state();
    s.tasks[guid] = { guid, summary: `候选 ${guid}`, description, section: "sec_待确认", comments: [] };
    fs.writeFileSync(statePath, JSON.stringify(s));
  };
  return { ...env, state, addTask };
}

const feedbackOf = (app: App, id: string) =>
  app.store.db.prepare("SELECT feedback, feedback_at, feedback_reason FROM signals WHERE id = ?").get(id) as { feedback: string; feedback_at: number | null; feedback_reason: string | null };

async function rejects(p: Promise<unknown>, code: string) {
  await assert.rejects(p, (e: unknown) => e instanceof CommandError && e.code === code);
}

test("迁移：给 signals 补反馈列，可重复执行；旧库重新打开不丢数据", (t) => {
  const { app, file } = mkApp(t);
  const cols = () => (app.store.db.prepare("PRAGMA table_info(signals)").all() as { name: string }[]).map((c) => c.name);
  for (const c of ["feedback", "feedback_at", "feedback_reason", "summary", "section"]) assert.ok(cols().includes(c), c);
  seed(app, "s1", { verdict: "task(0.8)", task: "t1", feedback: "confirmed" });
  migrateSignals(app.store.db);
  migrateSignals(app.store.db);
  // 同一个库再组装一次（常驻进程重启）
  const again = createApp(loadConfig(file));
  assert.equal(feedbackOf(again, "s1").feedback, "confirmed");
  again.store.db.close();
  // 全新的旧版库（只有原始列）
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pa-cand-old-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const old = new Store(dir);
  old.addSignal({ id: "x", source: "s", text: "t", link: "" });
  migrateSignals(old.db);
  assert.equal((old.db.prepare("SELECT feedback FROM signals WHERE id = 'x'").get() as { feedback: string }).feedback, "");
  old.db.close();
});

test("解析：置信度与 repo 行", () => {
  assert.equal(parseConfidence("task(0.8)"), 0.8);
  assert.equal(parseConfidence("ignored(0.3) 只是通知"), 0.3);
  assert.equal(parseConfidence("ignored(无结论)"), null);
  assert.equal(parseConfidence(""), null);
  assert.equal(withRepoLine("来源：x\n\n[pa:signal=a]", "demo"), "repo: demo\n来源：x\n\n[pa:signal=a]");
  assert.equal(withRepoLine("repo: old\n其他", "demo"), "repo: demo\n其他");
  assert.equal(withRepoLine("", "demo"), "repo: demo");
});

test("列表与统计：窗口内的任务 / 忽略信号，按反馈过滤，准确率 = 确认 /（确认 + 驳回）", (t) => {
  const { app } = mkApp(t);
  const empty = app.ext.candidates!.list({ days: 7 });
  assert.equal(empty.stats.precision, null);
  seed(app, "a", { verdict: "task(0.8)", task: "ta", summary: "评审 Q4 预算", section: "pending", feedback: "confirmed" });
  seed(app, "b", { verdict: "task(0.6)", task: "tb", feedback: "rejected", reason: "只是抄送" });
  seed(app, "c", { verdict: "task(0.95)", task: "tc", feedback: "confirmed" });
  seed(app, "d", { verdict: "task(0.7)", task: "td" });
  seed(app, "e", { verdict: "ignored(0.1) 寒暄", text: "收到，谢谢" });
  seed(app, "old", { verdict: "task(0.8)", task: "to", at: Date.now() - 10 * DAY, feedback: "rejected" });
  seed(app, "pending-triage", { verdict: "" });

  const all = app.ext.candidates!.list({ days: 7 });
  assert.deepEqual(all.items.map((i) => i.signal_id).sort(), ["a", "b", "c", "d", "e"]);
  assert.deepEqual(all.stats, { window_days: 7, created: 4, confirmed: 2, rejected: 1, precision: 2 / 3 });
  const a = all.items.find((i) => i.signal_id === "a")!;
  assert.equal(a.summary, "评审 Q4 预算");
  assert.equal(a.confidence, 0.8);
  assert.equal(a.feedback, "confirmed");
  assert.match(a.task_url, /todo\/detail\?guid=ta/);
  const e = all.items.find((i) => i.signal_id === "e")!;
  assert.equal(e.task_guid, "");
  assert.equal(e.task_url, "");
  assert.equal(e.confidence, 0.1);
  assert.equal(e.summary, "收到，谢谢", "没有标题时用原文摘录");
  assert.deepEqual(app.ext.candidates!.list({ days: 7, feedback: "" }).items.map((i) => i.signal_id), ["d"]);
  assert.deepEqual(app.ext.candidates!.list({ days: 7, feedback: "rejected" }).items.map((i) => i.signal_id), ["b"]);
  const wide = app.ext.candidates!.list({ days: 30 });
  assert.equal(wide.stats.rejected, 2);
  assert.equal(wide.stats.precision, 0.5);
});

test("待确认计数：最近 14 天建在“待确认”列且未反馈的；旧数据没有列信息时按置信度推断", (t) => {
  const { app } = mkApp(t);
  seed(app, "p1", { verdict: "task(0.6)", task: "t1", section: "pending" });
  seed(app, "p2", { verdict: "task(0.7)", task: "t2" }); // 旧数据：0.7 < auto_inbox_confidence → 待确认
  seed(app, "i1", { verdict: "task(0.95)", task: "t3" }); // 高置信 → Inbox
  seed(app, "i2", { verdict: "task(0.5)", task: "t4", section: "inbox" });
  seed(app, "f1", { verdict: "task(0.6)", task: "t5", section: "pending", feedback: "confirmed" });
  seed(app, "o1", { verdict: "task(0.6)", task: "t6", section: "pending", at: Date.now() - 15 * DAY });
  seed(app, "n1", { verdict: "ignored(0.2) x" });
  assert.equal(app.ext.candidates!.pendingCount(), 2);
  // 建卡事件记下标题与列
  seed(app, "p3", { verdict: "task(0.99)", task: "t7" });
  app.bus.emit("candidate.created", { signalId: "p3", taskGuid: "t7", summary: "整理上线清单", section: "pending" });
  assert.equal(app.ext.candidates!.pendingCount(), 3);
  assert.equal(app.ext.candidates!.list({ days: 1 }).items.find((i) => i.signal_id === "p3")?.summary, "整理上线清单");
});

test("candidate.confirm：移到 Inbox 并记反馈；重复确认 409；不存在 404；没建成任务的信号不可操作", async (t) => {
  const { app, state, addTask } = await boardApp(t);
  addTask("task_c1", "来源：x\n[pa:signal=s1]");
  seed(app, "s1", { verdict: "task(0.7)", task: "task_c1", section: "pending" });
  seed(app, "s_ign", { verdict: "ignored(0.2) 寒暄" });
  const r = await app.commands.exec("candidate.confirm", { signal_id: "s1" }, ctx);
  assert.equal(r.ok, true);
  assert.equal(feedbackOf(app, "s1").feedback, "confirmed");
  assert.ok(feedbackOf(app, "s1").feedback_at);
  await app.engine.drain(["effect"]);
  assert.equal(state().tasks.task_c1.section, "sec_Inbox");
  assert.equal(app.ext.candidates!.pendingCount(), 0);
  await rejects(app.commands.exec("candidate.confirm", { signal_id: "s1" }, ctx), "conflict");
  await rejects(app.commands.exec("candidate.reject", { signal_id: "s1" }, ctx), "conflict");
  await rejects(app.commands.exec("candidate.confirm", { signal_id: "nope" }, ctx), "not_found");
  await rejects(app.commands.exec("candidate.confirm", { signal_id: "s_ign" }, ctx), "invalid");
  await rejects(app.commands.exec("candidate.confirm", {}, ctx), "invalid");
  // 审计
  assert.ok(app.ledger.auditLog(10, "s1").some((a) => a.command === "candidate.confirm" && a.ok === 1));
});

test("candidate.reject：评论“已驳回：理由”并完成任务，记下理由", async (t) => {
  const { app, state, addTask } = await boardApp(t);
  addTask("task_r1", "来源：x\n[pa:signal=s2]");
  seed(app, "s2", { verdict: "task(0.6)", task: "task_r1", section: "pending" });
  await app.commands.exec("candidate.reject", { signal_id: "s2", reason: "只是抄送我" }, ctx);
  assert.deepEqual({ ...feedbackOf(app, "s2"), feedback_at: 0 }, { feedback: "rejected", feedback_at: 0, feedback_reason: "只是抄送我" });
  await app.engine.drain(["effect"]);
  const task = state().tasks.task_r1;
  assert.deepEqual(task.comments, ["已驳回：只是抄送我"]);
  assert.equal(task.completed, true);
  // 不写理由也可以
  addTask("task_r2", "");
  seed(app, "s3", { verdict: "task(0.6)", task: "task_r2" });
  await app.commands.exec("candidate.reject", { signal_id: "s3" }, ctx);
  await app.engine.drain(["effect"]);
  assert.match(state().tasks.task_r2.comments[0], /^已驳回：/);
  assert.equal(feedbackOf(app, "s3").feedback_reason, null);
});

test("candidate.dispatch：写入 repo 行、重新派单移到“派给Agent”、记为确认；已有进行中的派单时 409 且不记反馈", async (t) => {
  const { app, state, addTask } = await boardApp(t);
  addTask("task_d1", "来源：x\n\n[pa:signal=s4]");
  seed(app, "s4", { verdict: "task(0.7)", task: "task_d1", section: "pending" });
  await rejects(app.commands.exec("candidate.dispatch", { signal_id: "s4", harness: "nope" }, ctx), "invalid");
  await rejects(app.commands.exec("candidate.dispatch", { signal_id: "s4", repo: "no-such-repo-xyz" }, ctx), "invalid");
  assert.equal(feedbackOf(app, "s4").feedback, "");
  const r = await app.commands.exec("candidate.dispatch", { signal_id: "s4", harness: "codex", repo: "demo" }, ctx);
  assert.equal(r.ok, true);
  const w = app.ledger.latest<DispatchPayload>("dispatch", "task_d1")!;
  assert.equal(r.target, w.id);
  assert.equal(w.state, "queued");
  assert.equal(w.payload.harness_override, "codex");
  assert.equal(feedbackOf(app, "s4").feedback, "confirmed");
  const desc = state().tasks.task_d1.description;
  assert.match(desc, /^repo: demo$/m);
  assert.match(desc, /\[pa:signal=s4\]/);
  await app.engine.drain(["effect"]);
  const task = state().tasks.task_d1;
  assert.equal(task.section, "sec_派给Agent");
  assert.match(task.comments.join("\n"), /从候选任务派单[\s\S]*执行者：codex/);
  await rejects(app.commands.exec("candidate.dispatch", { signal_id: "s4" }, ctx), "conflict");

  // 卡片已有进行中的派单（例如用户先手动拖进了派单列）
  addTask("task_d2", "");
  seed(app, "s5", { verdict: "task(0.7)", task: "task_d2" });
  app.ledger.enqueue({ id: "dispatch:task_d2:1", kind: "dispatch", ref: "task_d2", state: "executing", payload: { guid: "task_d2" } });
  await rejects(app.commands.exec("candidate.dispatch", { signal_id: "s5" }, ctx), "conflict");
  assert.equal(feedbackOf(app, "s5").feedback, "", "失败时不记反馈");
});

test("学习闭环：分诊提示词带上最近的确认 / 驳回样例（含理由），没有反馈时显示“暂无”", async (t) => {
  const { app, dir } = mkApp(t);
  const dump = path.join(dir, "prompt.txt");
  const fake = path.join(dir, "fake-acpx.mjs");
  fs.writeFileSync(fake, `#!/usr/bin/env node\nimport fs from "node:fs";\nfs.writeFileSync(${JSON.stringify(dump)}, fs.readFileSync(0, "utf8"));\nprocess.stdout.write("[]\\n");\n`);
  fs.chmodSync(fake, 0o755);
  app.cfg.bins.acpx = fake;
  const signals = [{ id: "new1", source: "群聊@我", text: "@主人 看一下", link: "" }];

  await triage(app.cfg, signals, []);
  assert.match(fs.readFileSync(dump, "utf8"), /## 历史判断校准[\s\S]*（暂无）/);

  seed(app, "y1", { verdict: "task(0.8)", task: "t1", summary: "评审预算", text: "@主人 周五前评审预算", feedback: "confirmed" });
  seed(app, "n1", { verdict: "task(0.6)", task: "t2", text: "FYI 上线通知\n第二行", feedback: "rejected", reason: "只是通知" });
  for (let i = 0; i < 10; i++) seed(app, `bulk${i}`, { verdict: "task(0.5)", task: `tb${i}`, feedback: "confirmed" });
  app.store.db.prepare("UPDATE signals SET feedback_at = ? WHERE id LIKE 'bulk%'").run(Date.now() - DAY);
  app.store.db.prepare("UPDATE signals SET feedback_at = ? WHERE id IN ('y1', 'n1')").run(Date.now());
  await triage(app.cfg, signals, []);
  const prompt = fs.readFileSync(dump, "utf8");
  const section = prompt.slice(prompt.indexOf("## 历史判断校准"), prompt.indexOf("## 待判断的信号"));
  assert.match(section, /周五前评审预算.*当时判为任务（置信度 0\.8）「评审预算」；主人确认：是任务/);
  assert.match(section, /FYI 上线通知 第二行.*主人驳回：不该建成任务（理由：只是通知）/);
  assert.equal((section.match(/<example /g) ?? []).length, 8, "最多 8 条");
  assert.match(prompt, /<signal id="new1"/);
});
