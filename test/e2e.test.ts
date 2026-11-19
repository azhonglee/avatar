/**
 * 端到端：用 test/stubs 下有状态的 lark-cli / acpx 桩跑真实的 pa 命令和常驻进程。
 * 验证的是本框架的编排逻辑；飞书和各 harness 的真实行为需在开发机上联调。
 */
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
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
    ["Inbox", "待确认", "派给Agent", "Agent进行中", "待验收", "等待他人"],
  );
  pa("init"); // 幂等
  assert.equal(state().sections.length, 6);
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
  assert.match(t.comments.at(-1), /✅ codex 完成[\s\S]*hello\.txt/);
  const wt = path.join(tmp, "data", "worktrees", "task_dis");
  assert.ok(fs.existsSync(path.join(wt, "hello.txt")), "改动发生在 worktree 里");
  assert.ok(!fs.existsSync(path.join(tmp, "demo-repo", "hello.txt")), "主工作区不受影响");
  const acpx = calls(env.STUB_ACPX_LOG);
  assert.ok(acpx.some((c) => c.agent === "codex" && c.perm === "--approve-all" && c.cwd === wt));
  assert.ok(acpx.some((c) => c.agent === "claude" && c.perm === "--approve-reads"), "reviewer 是 claude 只读（执行者是 codex 时不自审）");
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
  const before = state().messages.length;
  const daemon = spawn(path.join(ROOT, "bin", "pa"), ["run"], { env, cwd: tmp, stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  daemon.stdout.on("data", (d) => (output += d));
  daemon.stderr.on("data", (d) => (output += d));

  const deadline = Date.now() + 60_000;
  const done = () => {
    const s = state();
    const replied = s.messages.length > before;
    const commentTask = Object.values(s.tasks).some((t) => (t as { description: string }).description.includes("comment:c1"));
    return replied && commentTask;
  };
  while (!done() && Date.now() < deadline) await new Promise((r) => setTimeout(r, 200));
  if (!done()) daemon.kill("SIGKILL"); // 失败时也别让常驻进程挂住测试
  assert.ok(done(), `常驻进程未按预期处理事件。输出：\n${output}`);

  const s = state();
  assert.equal(s.messages.length - before, 1, "重复事件只处理一次，陌生人的消息被忽略");
  assert.match(s.messages.at(-1).markdown, /worker|job|✅|❌/);
  assert.match(output, /忽略非主人的机器人消息/);

  const code = await new Promise((resolve) => {
    daemon.on("close", resolve);
    daemon.kill("SIGTERM");
  });
  assert.equal(code, 0, output);
});
