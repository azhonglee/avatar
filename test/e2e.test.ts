/**
 * 端到端：用 test/stubs 下有状态的 lark-cli / acpx 桩跑真实的 pa 命令和常驻进程。
 * 验证的是本框架的编排逻辑；飞书和各 harness 的真实行为需在开发机上联调。
 */
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const STUBS = path.join(ROOT, "test", "stubs");
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "pa-e2e-"));
const env = {
  ...process.env,
  PA_CONFIG: path.join(tmp, "config.yaml"),
  STUB_STATE: path.join(tmp, "stub-state.json"),
  STUB_LOG: path.join(tmp, "lark-calls.ndjson"),
  STUB_ACPX_LOG: path.join(tmp, "acpx-calls.ndjson"),
  STUB_EVENTS_DIR: path.join(tmp, "events"),
};
const state = () => JSON.parse(fs.readFileSync(env.STUB_STATE, "utf8"));
const pa = (...args: string[]) => execFileSync(path.join(ROOT, "bin", "pa"), args, { env, encoding: "utf8", cwd: tmp });
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const alive = (pid: number) => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};
/** 往桩的看板里放一张卡片。 */
const addCard = (guid: string, summary: string, description: string, section = "sec_派给Agent") => {
  const s = state();
  s.tasks[guid] = { guid, summary, description, section, comments: [] };
  fs.writeFileSync(env.STUB_STATE, JSON.stringify(s));
};
/** 直接读账本（只读）。 */
const db = () => new DatabaseSync(path.join(tmp, "data", "state.db"), { readOnly: true });
const calls = (file: string) => fs.readFileSync(file, "utf8").trim().split("\n").map((l) => JSON.parse(l));

before(() => {
  const repo = path.join(tmp, "demo-repo");
  fs.mkdirSync(repo);
  execFileSync("git", ["-C", repo, "init", "-q", "-b", "main"]);
  fs.writeFileSync(path.join(repo, "README.md"), "demo\n");
  execFileSync("git", ["-C", repo, "add", "-A"]);
  execFileSync("git", ["-C", repo, "-c", "user.name=t", "-c", "user.email=t@x", "commit", "-qm", "init"]);
  fs.mkdirSync(env.STUB_EVENTS_DIR);
  fs.writeFileSync(
    env.PA_CONFIG,
    `
data_dir: ${path.join(tmp, "data")}
bins: { lark: ${path.join(STUBS, "lark-cli")}, acpx: ${path.join(STUBS, "acpx")} }
harnesses:
  claude: { agent: claude }
  codex: { agent: codex }
roles: { brain: claude, reviewer: codex }
dispatch: { default_harness: claude, repos: { demo: ${repo} } }
events: { bot_messages: true, task_updates: false, doc_comments: true, minutes: false }
schedules: { capture: "0 0 1 1 *", dispatch: "0 0 1 1 *", brief_morning: "0 0 1 1 *", brief_evening: "0 0 1 1 *" }
engine: { tick_ms: 100, retry_base_ms: 300, lease_sec: 3 }
server: { port: 0 }
context: { enabled: false }
`,
  );
});
after(() => fs.rmSync(tmp, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }));

test("init：记录主人 open_id，建看板分组和知识库节点", () => {
  const out = pa("init");
  assert.match(out, /ou_owner/);
  const s = state();
  assert.deepEqual(
    s.sections.map((x: { name: string }) => x.name),
    ["Inbox", "待确认", "派给Agent", "Agent进行中", "待验收", "需人工介入", "等待他人"],
  );
  pa("init"); // 幂等
  assert.equal(state().sections.length, 7);
});

test("capture：@我 的请求建成任务，寒暄和自己的消息被忽略，重复运行不重复建", () => {
  pa("capture");
  const tasks = Object.values(state().tasks) as { summary: string; section: string; description: string; assignee: string }[];
  assert.equal(tasks.length, 1);
  assert.equal(tasks[0].section, "sec_待确认");
  assert.equal(tasks[0].assignee, "ou_owner");
  assert.match(tasks[0].description, /\[pa:signal=msg:om_1\]/);
  const triage = calls(env.STUB_ACPX_LOG).find((c) => c.head.includes("私人助理"));
  assert.equal(triage.perm, "--deny-all", "分诊不给工具权限");
  pa("capture");
  assert.equal(Object.keys(state().tasks).length, 1);
});

test("dispatch：codex 在 worktree 执行，claude 交叉审查，结果写回评论并移到待验收", () => {
  const s = state();
  s.tasks.task_d = { guid: "task_dispatch_1", summary: "[codex] 写个 hello 文件", description: "repo: demo", section: "sec_派给Agent", comments: [] };
  s.tasks.task_dispatch_1 = s.tasks.task_d;
  delete s.tasks.task_d;
  fs.writeFileSync(env.STUB_STATE, JSON.stringify(s));

  pa("dispatch");
  const t = state().tasks.task_dispatch_1;
  assert.equal(t.section, "sec_待验收");
  assert.match(t.comments[0], /codex 开始执行/);
  assert.match(t.comments.join("\n"), /审查.*通过/);
  assert.match(t.comments.at(-1), /✅ codex 完成，已通过验收[\s\S]*hello\.txt/);
  const wt = path.join(tmp, "data", "worktrees", "task_dis");
  assert.ok(fs.existsSync(path.join(wt, "hello.txt")), "改动发生在 worktree 里");
  assert.ok(!fs.existsSync(path.join(tmp, "demo-repo", "hello.txt")), "主工作区不受影响");
  const acpx = calls(env.STUB_ACPX_LOG);
  assert.ok(acpx.some((c) => c.agent === "codex" && c.perm === "--approve-all" && c.cwd === wt));
  assert.ok(acpx.some((c) => c.agent === "claude" && c.perm === "--approve-reads"), "reviewer 是 claude 只读（执行者是 codex 时不自审）");
});

test("验收关卡：审查一直打回 → 返工一轮后进“需人工介入”；审查器故障 → 不算打回，也进“需人工介入”", () => {
  addCard("task_reject_1", "[codex] 总是打回 的任务", "repo: demo");
  addCard("task_garble_1", "[codex] 审查乱码 的任务", "repo: demo");
  pa("dispatch");

  const rejected = state().tasks.task_reject_1;
  assert.equal(rejected.section, "sec_需人工介入", "返工耗尽不再进“待验收”");
  assert.equal(rejected.comments.filter((c: string) => /审查（第 \d 轮）：需修改/.test(c)).length, 2, `执行 + 返工各审查一次：${JSON.stringify(rejected.comments, null, 1)}`);
  assert.match(rejected.comments.at(-1), /⚠️ 需要你介入：返工轮次用完/);
  assert.ok(!rejected.comments.some((c: string) => c.includes("✅")), "不会出现“完成”字样");

  const garbled = state().tasks.task_garble_1;
  assert.equal(garbled.section, "sec_需人工介入");
  assert.match(garbled.comments.join("\n"), /审查（第 1 轮）：故障/);
  assert.match(garbled.comments.at(-1), /校验器故障/);
  const reviews = calls(env.STUB_ACPX_LOG).filter((c) => c.cwd?.endsWith("task_gar") && c.perm === "--approve-reads");
  assert.equal(reviews.length, 2, "审查器故障重试一次，不消耗返工轮次（worker 只跑了一轮）");
  assert.equal(calls(env.STUB_ACPX_LOG).filter((c) => c.cwd?.endsWith("task_gar") && c.perm === "--approve-all").length, 1);

  const d = db();
  const rows = d.prepare("SELECT ref, state, reason FROM work WHERE kind = 'dispatch' ORDER BY seq").all() as { ref: string; state: string; reason: string }[];
  d.close();
  assert.deepEqual(
    rows.map((r) => [r.ref, r.state, r.reason]),
    [
      ["task_dispatch_1", "accepted", "passed"],
      ["task_reject_1", "needs_human", "rejected"],
      ["task_garble_1", "needs_human", "verifier_error"],
    ],
  );
});

test("崩溃恢复：执行中 kill -9 常驻进程，再次运行时结束遗留进程、回到检查点重跑并完成", async () => {
  const hangFile = path.join(tmp, "hang");
  fs.writeFileSync(hangFile, "armed");
  addCard("task_crash_1", "[codex] 崩溃恢复", "repo: demo");
  const env2 = { ...env, STUB_HANG_FILE: hangFile };
  const daemon = spawn(path.join(ROOT, "bin", "pa"), ["run"], { env: env2, cwd: tmp, stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  daemon.stdout.on("data", (d) => (output += d));
  daemon.stderr.on("data", (d) => (output += d));
  let hungPid = 0;
  try {
    const deadline = Date.now() + 60_000;
    // outbox 移卡片与 worker 启动并行：等两件事都到位再 kill -9
    while ((fs.readFileSync(hangFile, "utf8") === "armed" || state().tasks.task_crash_1.section !== "sec_Agent进行中") && Date.now() < deadline)
      await sleep(100);
    hungPid = Number(fs.readFileSync(hangFile, "utf8"));
    assert.ok(hungPid > 0, `worker 没有启动。输出：\n${output}`);
    const wt = path.join(tmp, "data", "worktrees", "task_cra");
    assert.ok(fs.existsSync(path.join(wt, "partial.txt")), "半成品已写入");

    daemon.kill("SIGKILL");
    await new Promise((r) => daemon.on("close", r));
    assert.ok(alive(hungPid), "kill -9 后 harness 成了孤儿进程，还在运行");
    assert.equal(state().tasks.task_crash_1.section, "sec_Agent进行中", "卡片停在进行中");

    // 再次运行（命令行单次派单即可，常驻进程重启效果相同）：接管 → 清理孤儿 → 回检查点 → 重跑
    const out = execFileSync(path.join(ROOT, "bin", "pa"), ["dispatch"], { env: env2, encoding: "utf8", cwd: tmp });
    for (let i = 0; i < 50 && alive(hungPid); i++) await sleep(100);
    assert.ok(!alive(hungPid), "遗留的 harness 进程组已被结束");

    const t = state().tasks.task_crash_1;
    assert.equal(t.section, "sec_待验收", out);
    assert.equal(t.comments.filter((c: string) => c.includes("开始执行")).length, 1, `准备阶段不重复执行：${JSON.stringify(t.comments, null, 1)}\n${out}`);
    assert.match(t.comments.at(-1), /✅ codex 完成，已通过验收/);
    assert.ok(!fs.existsSync(path.join(wt, "partial.txt")), "上次的半成品被丢弃（回到本轮检查点）");
    assert.ok(fs.existsSync(path.join(wt, "hello.txt")));

    const d = db();
    const steps = d.prepare("SELECT s.name, s.status FROM steps s JOIN work w ON w.id = s.work_id WHERE w.ref = 'task_crash_1' ORDER BY s.id").all();
    d.close();
    assert.deepEqual(
      steps.map((s) => `${s.name}:${s.status}`),
      ["worker#1:interrupted", "worker#1:ok", "review#1:ok"],
    );
  } finally {
    if (daemon.exitCode === null) daemon.kill("SIGKILL");
    if (hungPid > 0 && alive(hungPid)) {
      try {
        process.kill(-hungPid, "SIGKILL");
      } catch {
        // 已退出
      }
    }
  }
});

test("取消：执行中把卡片拖回 Inbox，对账按 ID 核实后取消，结束正在跑的 harness", async () => {
  const hangFile = path.join(tmp, "hang-cancel");
  fs.writeFileSync(hangFile, "armed");
  addCard("task_cancel_1", "[codex] 取消测试", "repo: demo");
  const env2 = { ...env, STUB_HANG_FILE: hangFile };
  const daemon = spawn(path.join(ROOT, "bin", "pa"), ["run"], { env: env2, cwd: tmp, stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  daemon.stdout.on("data", (d) => (output += d));
  daemon.stderr.on("data", (d) => (output += d));
  let hungPid = 0;
  try {
    const started = () => fs.readFileSync(hangFile, "utf8") !== "armed" && state().tasks.task_cancel_1.comments.some((c: string) => c.includes("开始执行"));
    for (let i = 0; i < 600 && !started(); i++) await sleep(100);
    assert.ok(started(), `worker 没有启动。输出：\n${output}`);
    hungPid = Number(fs.readFileSync(hangFile, "utf8"));

    // 用户把正在跑的卡片拖回 Inbox；任意一次对账（这里用命令行）发现它不在两列，按 ID 核实后请求取消
    const s = state();
    s.tasks.task_cancel_1.section = "sec_Inbox";
    fs.writeFileSync(env.STUB_STATE, JSON.stringify(s));
    pa("dispatch");

    const cancelled = () => state().tasks.task_cancel_1.comments.some((c: string) => c.includes("已取消"));
    for (let i = 0; i < 200 && !(cancelled() && !alive(hungPid)); i++) await sleep(100);
    const code = await new Promise((resolve) => {
      daemon.on("close", resolve);
      daemon.kill("SIGTERM");
    });
    assert.ok(cancelled(), `没有收尾为已取消。输出：\n${output}`);
    assert.ok(!alive(hungPid), "正在跑的 harness 已被结束");
    assert.equal(state().tasks.task_cancel_1.section, "sec_Inbox", "取消不移动卡片：位置由用户决定");
    assert.equal(code, 0, output);
    const d = db();
    const w = d.prepare("SELECT state FROM work WHERE kind = 'dispatch' AND ref = 'task_cancel_1'").get() as { state: string };
    d.close();
    assert.equal(w.state, "cancelled");
  } finally {
    if (daemon.exitCode === null) daemon.kill("SIGKILL");
    if (hungPid > 0 && alive(hungPid)) {
      try {
        process.kill(-hungPid, "SIGKILL");
      } catch {
        // 已退出
      }
    }
  }
});

test("brief：汇总逾期、待确认、待验收并私信主人", () => {
  const text = pa("brief", "--print");
  assert.match(text, /已逾期（1）/);
  assert.match(text, /待你确认/);
  assert.match(text, /待你验收.*\n- 写个 hello 文件|待你验收/);
  pa("brief");
  const m = state().messages.at(-1);
  assert.equal(m.to, "ou_owner");
  assert.equal(m.as, "bot");
});

test("ask：agent 作业经过守卫，越权发消息被拒，读任务放行", () => {
  const out = pa("ask", "看看我的任务");
  assert.match(out, /越权发消息 exit=13；读取任务 exit=0/);
  const guardLog = fs.readFileSync(path.join(tmp, "data", "logs", "guard.log"), "utf8");
  assert.match(guardLog, /"allow":false/);
  assert.match(guardLog, /"allow":true/);
});

test("run：常驻进程处理主人私信指令和文档评论事件，并能优雅退出", async () => {
  fs.writeFileSync(
    path.join(env.STUB_EVENTS_DIR, "im.message.receive_v1.ndjson"),
    [
      { event_id: "ev1", sender_id: "ou_owner", chat_type: "p2p", message_id: "om_cmd", content: "/status" },
      { event_id: "ev1", sender_id: "ou_owner", chat_type: "p2p", message_id: "om_cmd", content: "/status" },
      { event_id: "ev2", sender_id: "ou_stranger", chat_type: "p2p", message_id: "om_x", content: "/brief" },
    ]
      .map((e) => JSON.stringify(e))
      .join("\n") + "\n",
  );
  fs.writeFileSync(
    path.join(env.STUB_EVENTS_DIR, "drive.notice.comment_add_v1.ndjson"),
    JSON.stringify({ event_id: "ev3", file_token: "doxABC", file_type: "docx", comment_id: "c1", reply_id: "r1", is_mentioned: true, from_open_id: "ou_alice" }) + "\n",
  );
  // 故障注入：拉评论正文第一次失败。事件已落进 inbox，引擎退避后重试成功（旧实现会永久丢掉这条）
  const st = state();
  st.failOnce = { "drive +batch-query-comments": 1 };
  fs.writeFileSync(env.STUB_STATE, JSON.stringify(st));
  const before = state().messages.length;
  const daemon = spawn(path.join(ROOT, "bin", "pa"), ["run"], { env, cwd: tmp, stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  daemon.stdout.on("data", (d) => (output += d));
  daemon.stderr.on("data", (d) => (output += d));

  const deadline = Date.now() + 60_000;
  try {
    const done = () => {
      const s = state();
      const added = s.messages.slice(before) as { msg_type?: string; markdown?: string; card?: unknown }[];
      const replied = added.some((m) => !m.msg_type);
      const commentTask = Object.values(s.tasks).some((t) => (t as { description: string }).description.includes("comment:c1"));
      const candidateCard = added.some((m) => m.msg_type === "interactive" && JSON.stringify(m.card).includes("候选任务"));
      return replied && commentTask && candidateCard;
    };
    while (!done() && Date.now() < deadline) await new Promise((r) => setTimeout(r, 200));
    assert.ok(done(), `常驻进程未按预期处理事件。输出：\n${output}`);

    const s = state();
    const added = s.messages.slice(before) as { msg_type?: string; markdown?: string; card?: unknown }[];
    const replies = added.filter((m) => !m.msg_type);
    const cards = added.filter((m) => m.msg_type === "interactive");
    assert.equal(replies.length, 1, "重复事件只处理一次，陌生人的消息被忽略");
    assert.match(replies[0].markdown ?? "", /worker|job|dispatch|✅|❌/);
    assert.ok(cards.some((c) => JSON.stringify(c.card).includes("候选任务")), "文档评论识别出的候选任务同步发出了交互卡片");
    assert.match(output, /忽略非主人的机器人消息/);
    assert.match(output, /工作失败，稍后重试[\s\S]*注入的临时故障/, "第一次拉评论失败后被重试");

    const code = await new Promise((resolve) => {
      daemon.on("close", resolve);
      daemon.kill("SIGTERM");
    });
    assert.equal(code, 0, output);
  } finally {
    if (daemon.exitCode === null) daemon.kill("SIGKILL");
  }
});
