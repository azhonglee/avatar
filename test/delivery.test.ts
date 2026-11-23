/**
 * 交付模块：创建 PR/MR（GitHub / GitLab 用本地假服务器，Codebase 用假 bytedcli）、快进合并到本地分支、
 * 放弃 → 延迟清理 → 恢复、命令前置条件与可执行操作的联动。
 * 所有 git 仓库都在临时目录里，origin 是本地裸仓库（用 url.<裸仓库>.insteadOf 让 remote 地址看起来像真实平台）。
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { createApp, type App } from "../src/app.ts";
import { deliveryOf, dispatchDetail } from "../src/api/queries.ts";
import type { CommandName, DeliveryStatus } from "../src/api/types.ts";
import { CommandError } from "../src/commands.ts";
import { loadConfig } from "../src/config.ts";
import { availableActions } from "../src/core-commands.ts";
import { denyReason, prBody, prTitle, type DeliveryAction, type DeliveryPayload } from "../src/delivery/body.ts";
import { maskUrl } from "../src/delivery/index.ts";
import { parseRemote } from "../src/delivery/git.ts";
import { apiMessage, codebasePermanent, httpError, parseCodebaseMr } from "../src/delivery/providers.ts";
import type { WorkItem } from "../src/ledger.ts";
import type { DispatchPayload } from "../src/workflows/dispatch.ts";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "pa-delivery-"));
const STATE = path.join(tmp, "stub-state.json");
const GH_TOKEN = "gh-secret-token-123";
const GL_TOKEN = "gl-secret-token-456";
process.env.STUB_STATE = STATE;
process.env.PA_TEST_GH_TOKEN = GH_TOKEN;
process.env.PA_TEST_GL_TOKEN = GL_TOKEN;

let app: App;
let server: http.Server;
const repos: Record<string, string> = {};

// ───────────────────────── 工具 ─────────────────────────

function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", ["-C", cwd, "-c", "user.name=t", "-c", "user.email=t@t", ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}

/** 主仓库 + 本地裸仓库 origin；remoteUrl 给出时 remote 配成它，并用 insteadOf 指回裸仓库。 */
function mkRepo(name: string, remoteUrl?: string): string {
  const bare = path.join(tmp, `${name}-origin.git`);
  execFileSync("git", ["init", "-q", "--bare", "-b", "main", bare]);
  const repo = path.join(tmp, name);
  execFileSync("git", ["init", "-q", "-b", "main", repo]);
  fs.writeFileSync(path.join(repo, "README.md"), "# demo\n");
  git(repo, "add", "-A");
  git(repo, "commit", "-q", "-m", "init");
  git(repo, "remote", "add", "origin", remoteUrl ?? bare);
  if (remoteUrl) git(repo, "config", `url.${bare}.insteadOf`, remoteUrl);
  git(repo, "push", "-q", "origin", "main");
  return repo;
}

const stubState = () => (fs.existsSync(STATE) ? JSON.parse(fs.readFileSync(STATE, "utf8")) : { tasks: {}, messages: [], seq: 0, sections: [] });
const comments = (guid: string): string[] => stubState().tasks[guid]?.comments ?? [];

let n = 0;
interface Seeded {
  id: string;
  guid: string;
  cwd: string;
  branch: string;
  repo: string;
}

/** 放一项已结束的派单到账本，并像派单器那样建好 worktree 与 pa/ 分支、提交一处改动。 */
function seed(alias: string, o: { state?: string; terminal?: boolean; guid?: string; uncommitted?: boolean; summary?: string } = {}): Seeded {
  const guid = o.guid ?? `g${String(++n).padStart(3, "0")}${Math.random().toString(36).slice(2, 8)}xx`;
  const short = guid.slice(0, 8);
  const repo = repos[alias];
  const cwd = path.join(app.cfg.dataDir, "worktrees", short);
  const branch = `pa/${short}`;
  const base = git(repo, "rev-parse", "HEAD");
  if (!fs.existsSync(cwd)) git(repo, "worktree", "add", "-q", "-b", branch, cwd);
  fs.writeFileSync(path.join(cwd, `${short}.txt`), `改动 ${Math.random()}\n`);
  git(cwd, "add", "-A");
  git(cwd, "commit", "-q", "-m", "work");
  if (o.uncommitted) fs.writeFileSync(path.join(cwd, "extra.txt"), "未提交的改动\n");
  const summary = o.summary ?? `[codex] 修复登录 ${short}`;
  const s = stubState();
  s.tasks[guid] ??= { guid, summary, description: `repo: ${alias}`, section: "", comments: [] };
  fs.writeFileSync(STATE, JSON.stringify(s));
  const id = `dispatch:${guid}:${Date.now()}${Math.random().toString(36).slice(2, 5)}`;
  const payload: Partial<DispatchPayload> = {
    guid,
    summary,
    description: `repo: ${alias}`,
    harness: "codex",
    reviewer: "claude",
    cwd,
    branch,
    base,
    round: 1,
    maxRounds: 2,
    report: "已修复登录超时，补充了单元测试。",
    history: [
      {
        round: 1,
        checks: [
          { kind: "command", name: "校验命令 `npm test`", status: "pass", detail: "通过" },
          { kind: "review", name: "claude 审查", status: "pass", detail: "没有发现问题" },
        ],
      },
    ],
  };
  app.ledger.enqueue({ id, kind: "dispatch", ref: guid, state: o.state ?? "accepted", payload });
  if (o.terminal !== false) app.ledger.db.prepare("UPDATE work SET terminal = 1, outcome = state WHERE id = ?").run(id);
  return { id, guid, cwd, branch, repo };
}

const ctx = { source: "web" as const, actor: "owner" };
const exec = (name: CommandName, args: unknown) => app.commands.exec(name, args, ctx);
const drain = () => app.engine.drain(["delivery", "effect"]);
const status = (id: string) => deliveryOf(app, id);
const actions = async (id: string) => (await dispatchDetail(app, id))!.actions;
const deliveries = (id: string) => app.ledger.list<DeliveryPayload>({ kinds: ["delivery"], ref: id, limit: 50 });
const latestOf = (id: string, action: DeliveryPayload["action"]) => deliveries(id).find((d) => d.payload.action === action)!;

async function rejectsWith(p: Promise<unknown>, code: CommandError["code"], re?: RegExp): Promise<void> {
  await assert.rejects(p, (e: unknown) => {
    assert.ok(e instanceof CommandError, String(e));
    assert.equal(e.code, code, e.message);
    if (re) assert.match(e.message, re);
    return true;
  });
}

// ───────────────────────── 假平台 ─────────────────────────

interface Req {
  method: string;
  url: string;
  path: string;
  query: URLSearchParams;
  headers: http.IncomingHttpHeaders;
  body: Record<string, unknown> | undefined;
}
const fake = {
  requests: [] as Req[],
  gh: { mode: "ok" as "ok" | "401" | "404" | "500", prs: [] as Record<string, unknown>[] },
  gl: { mode: "ok" as "ok" | "race", mrs: [] as Record<string, unknown>[] },
};

function startFake(): Promise<string> {
  server = http.createServer(async (req, res) => {
    let raw = "";
    for await (const c of req) raw += c;
    const u = new URL(req.url!, "http://x");
    const body = raw ? (JSON.parse(raw) as Record<string, unknown>) : undefined;
    fake.requests.push({ method: req.method!, url: req.url!, path: u.pathname, query: u.searchParams, headers: req.headers, body });
    const send = (s: number, j: unknown) => {
      res.writeHead(s, { "Content-Type": "application/json" });
      res.end(JSON.stringify(j));
    };
    if (u.pathname === "/gh/repos/acme/demo/pulls") {
      if (req.headers.authorization !== `Bearer ${GH_TOKEN}` || fake.gh.mode === "401") return send(401, { message: "Bad credentials" });
      if (fake.gh.mode === "404") return send(404, { message: "Not Found" });
      if (fake.gh.mode === "500") return send(502, { message: "Server Error" });
      if (req.method === "GET") return send(200, fake.gh.prs.filter((p) => p.state === "open" && `acme:${(p.head as { ref: string }).ref}` === u.searchParams.get("head")));
      const num = 41 + fake.gh.prs.length;
      const pr = { number: num, html_url: `https://github.com/acme/demo/pull/${num}`, state: "open", head: { ref: body!.head }, base: { ref: body!.base }, draft: body!.draft, title: body!.title };
      fake.gh.prs.push(pr);
      return send(201, pr);
    }
    // GitLab：项目路径必须整体 URL 编码
    if (req.url!.startsWith("/gl/api/v4/projects/grp%2Fsub%2Fdemo/merge_requests")) {
      if (req.headers["private-token"] !== GL_TOKEN) return send(401, { message: "401 Unauthorized" });
      if (req.method === "GET") return send(200, fake.gl.mrs.filter((m) => m.state === "opened" && m.source_branch === u.searchParams.get("source_branch")));
      const iid = 7 + fake.gl.mrs.length;
      const mr = { iid, web_url: `https://gitlab.example.com/grp/sub/demo/-/merge_requests/${iid}`, state: "opened", source_branch: body!.source_branch, target_branch: body!.target_branch, title: body!.title };
      fake.gl.mrs.push(mr);
      // 模拟并发：别人刚建好了同一分支的 MR
      if (fake.gl.mode === "race") return send(409, { message: ["Another open merge request already exists for this source branch: !7"] });
      return send(201, mr);
    }
    send(404, { message: "no route" });
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${(server.address() as AddressInfo).port}`)));
}

/** 假 bytedcli：记录参数与标准输入，按 codebase mr list / create 返回 JSON。 */
const BYTEDCLI = path.join(tmp, "bin", "bytedcli");
const CB_STATE = path.join(tmp, "bin", "bytedcli-state.json");
const CB_LOG = path.join(tmp, "bin", "bytedcli-log.jsonl");
function writeFakeBytedcli(): void {
  fs.mkdirSync(path.dirname(BYTEDCLI), { recursive: true });
  fs.writeFileSync(
    BYTEDCLI,
    `#!/usr/bin/env node
const fs = require("fs");
const argv = process.argv.slice(2);
const st = fs.existsSync(${JSON.stringify(CB_STATE)}) ? JSON.parse(fs.readFileSync(${JSON.stringify(CB_STATE)}, "utf8")) : { mrs: [] };
let input = "";
if (argv.includes("-F")) { try { input = fs.readFileSync(0, "utf8"); } catch {} }
fs.appendFileSync(${JSON.stringify(CB_LOG)}, JSON.stringify({ argv, input }) + "\\n");
const flag = (n) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : undefined; };
const out = (j, code = 0) => { process.stdout.write(JSON.stringify(j)); process.exit(code); };
if (argv[0] !== "--json") { process.stderr.write("need --json"); process.exit(2); }
if (st.fail) out({ status: "error", error: { message: st.fail } }, 1);
const sub = argv.slice(1, 4).join(" ");
if (sub === "codebase mr list") out({ status: "success", data: { merge_requests: st.mrs.filter((m) => m.SourceBranchName === flag("-H") && m.Status === "open") } });
if (sub === "codebase mr create") {
  const m = { Number: 100 + st.mrs.length, Status: "open", SourceBranchName: flag("--head"), TargetBranchName: flag("--base"), Title: flag("--title"), Draft: argv.includes("--draft"), Description: input, URL: "" };
  st.mrs.push(m);
  fs.writeFileSync(${JSON.stringify(CB_STATE)}, JSON.stringify(st));
  out({ status: "success", data: { merge_request: m } });
}
process.stderr.write("unknown command"); process.exit(2);
`,
  );
  fs.chmodSync(BYTEDCLI, 0o755);
}
const cbState = () => (fs.existsSync(CB_STATE) ? JSON.parse(fs.readFileSync(CB_STATE, "utf8")) : { mrs: [] });
const cbLog = () => (fs.existsSync(CB_LOG) ? fs.readFileSync(CB_LOG, "utf8").trim().split("\n").map((l) => JSON.parse(l) as { argv: string[]; input: string }) : []);

// ───────────────────────── 准备 ─────────────────────────

before(async () => {
  const srv = await startFake();
  writeFakeBytedcli();
  repos.gh = mkRepo("gh", "https://github.com/acme/demo.git");
  repos.gl = mkRepo("gl", "git@gitlab.example.com:grp/sub/demo.git");
  repos.cb = mkRepo("cb", "git@code.example.org:team/demo.git");
  repos.local = mkRepo("local");
  const file = path.join(tmp, "config.yaml");
  fs.writeFileSync(
    file,
    JSON.stringify({
      data_dir: path.join(tmp, "data"),
      bins: { lark: path.join(ROOT, "test/stubs/lark-cli"), acpx: path.join(ROOT, "test/stubs/acpx"), bytedcli: BYTEDCLI },
      harnesses: { claude: { agent: "claude" }, codex: { agent: "codex" } },
      roles: { brain: "claude", reviewer: "codex" },
      owner: { open_id: "ou_owner" },
      dispatch: {
        repos: {
          gh: { path: repos.gh, provider: "gh" },
          gl: { path: repos.gl, provider: "gl", target_branch: "main" },
          cb: { path: repos.cb, provider: "cb" },
          local: { path: repos.local },
        },
      },
      delivery: {
        providers: {
          gh: { type: "github", base_url: `${srv}/gh`, token_env: "PA_TEST_GH_TOKEN" },
          gl: { type: "gitlab", base_url: `${srv}/gl`, token_env: "PA_TEST_GL_TOKEN" },
          cb: { type: "codebase", base_url: "https://code.example.org" },
        },
        discard_retention_days: 7,
      },
      engine: { retry_base_ms: 10, retry_max_ms: 20 },
    }),
  );
  app = createApp(loadConfig(file));
});

after(async () => {
  await new Promise((r) => server.close(r));
  app.store.db.close();
  fs.rmSync(tmp, { recursive: true, force: true });
});

// ───────────────────────── 纯函数 ─────────────────────────

test("解析 remote 地址：https / ssh / scp 形式，本地路径不识别；URL 里的账号密码被遮掉", () => {
  assert.deepEqual(parseRemote("https://github.com/acme/demo.git"), { host: "github.com", path: "acme/demo" });
  assert.deepEqual(parseRemote("https://x-access-token:abc@github.com/acme/demo"), { host: "github.com", path: "acme/demo" });
  assert.deepEqual(parseRemote("git@github.com:acme/demo.git"), { host: "github.com", path: "acme/demo" });
  assert.deepEqual(parseRemote("ssh://git@gitlab.example.com:2222/grp/sub/demo.git"), { host: "gitlab.example.com", path: "grp/sub/demo" });
  assert.deepEqual(parseRemote("git@code.byted.org:team/demo.git"), { host: "code.byted.org", path: "team/demo" });
  assert.equal(parseRemote("/tmp/origin.git"), undefined);
  assert.equal(parseRemote("../origin"), undefined);
  assert.equal(maskUrl("https://user:secret@github.com/a/b.git"), "https://***@github.com/a/b.git");
  assert.equal(maskUrl("fatal: unable to access 'https://x:tok@h.example/a.git/': 403"), "fatal: unable to access 'https://***@h.example/a.git/': 403");
});

test("错误映射：认证 / 权限 / 不存在为永久错误，限流与 5xx 可重试；“已存在”单独标记", () => {
  const c = { platform: "GitHub", repo: "acme/demo", tokenEnv: "GH_TOKEN" };
  const e401 = httpError(401, { message: "Bad credentials" }, c);
  assert.equal(e401.permanent, true);
  assert.match(e401.message, /认证失败.*GH_TOKEN.*Bad credentials/);
  assert.equal(httpError(403, { message: "Resource not accessible" }, c).permanent, true);
  assert.equal(httpError(403, { message: "API rate limit exceeded" }, c).permanent, false);
  assert.match(httpError(404, {}, c).message, /找不到仓库 acme\/demo/);
  assert.equal(httpError(502, "bad gateway", c).permanent, false);
  assert.equal(httpError(429, {}, c).permanent, false);
  const exists = httpError(422, { message: "Validation Failed", errors: [{ message: "A pull request already exists for acme:pa/x." }] }, c);
  assert.equal(exists.alreadyExists, true);
  assert.equal(apiMessage({ message: { source_branch: ["is invalid"] } }), "source_branch is invalid");
  assert.equal(codebasePermanent("not logged in, run bytedcli auth login"), true);
  assert.equal(codebasePermanent("ETIMEDOUT"), false);
});

test("Codebase 返回解析：有链接用链接，只有编号时拼链接", () => {
  assert.deepEqual(parseCodebaseMr({ data: { merge_request: { Number: 12, URL: "" } } }, "https://code.byted.org", "team/demo"), {
    url: "https://code.byted.org/team/demo/merge_requests/12",
    number: 12,
  });
  assert.deepEqual(parseCodebaseMr({ data: { url: "https://code.byted.org/team/demo/merge_requests/9" } }, "https://code.byted.org", "team/demo"), {
    url: "https://code.byted.org/team/demo/merge_requests/9",
    number: 9,
  });
  assert.equal(parseCodebaseMr({ status: "success", data: {} }, "https://code.byted.org", "team/demo"), undefined);
});

test("PR 标题与正文：去掉执行者前缀；包含任务链接、执行者报告、每轮校验、变更统计与落款", () => {
  assert.equal(prTitle("[codex] 修复登录"), "修复登录");
  assert.equal(prTitle("[codex] 修复登录", "自定义标题"), "自定义标题");
  const body = prBody(
    {
      summary: "[codex] 修复登录",
      harness: "codex",
      reviewer: "claude",
      report: "改好了\n第二行",
      branch: "pa/abc",
      base: "x",
      history: [{ round: 1, checks: [{ kind: "review", name: "claude 审查", status: "fail", detail: "缺少测试" }] }, { round: 2, checks: [] }],
    },
    { taskUrl: "https://applink.feishu.cn/client/todo/detail?guid=g1", dispatchId: "dispatch:g1:1", diffStat: " a.ts | 2 +-" },
  );
  assert.match(body, /\[修复登录\]\(https:\/\/applink\.feishu\.cn\/client\/todo\/detail\?guid=g1\)/);
  assert.match(body, /## 执行者报告\n\n> 改好了\n> 第二行/);
  assert.match(body, /### 第 1 轮[\s\S]*claude 审查：❌ 需修改[\s\S]*> 缺少测试/);
  assert.match(body, /### 第 2 轮\n\n- 无校验/);
  assert.match(body, /## 变更统计\n\n```\n a\.ts \| 2 \+-\n```/);
  assert.match(body, /由 Avatar 生成（执行者：codex · 审查：claude · 分支：pa\/abc · 派单：dispatch:g1:1）$/);
});

test("前置条件与 availableActions 一致：按钮出现 ⇔ 命令允许", () => {
  const states = ["accepted", "unverified", "needs_human", "errored", "cancelled"];
  const statuses: DeliveryStatus[] = ["none", "pending", "pr_open", "merged_local", "discarded", "failed"];
  const acts: DeliveryAction[] = ["create_pr", "merge_local", "discard", "restore"];
  for (const state of states)
    for (const s of statuses) {
      const w = { terminal: true, cancel: false, state, payload: { branch: "pa/x" } } as unknown as WorkItem<DispatchPayload>;
      const shown = availableActions(w, { delivery: s, providers: 1, deliveryEnabled: true, isLatest: true });
      for (const a of acts) assert.equal(shown.includes(`delivery.${a}`), denyReason(a, state, s) === undefined, `${state}/${s}/${a}`);
    }
});

// ───────────────────────── 创建 PR / MR ─────────────────────────

test("GitHub：提交未提交的改动、推送 pa/ 分支、创建草稿 PR；正文与请求头正确；评论 PR 链接", async () => {
  const d = seed("gh", { uncommitted: true });
  const r = await exec("delivery.create_pr", { id: d.id, draft: true });
  assert.equal(r.ok, true);
  assert.match(r.message, /草稿 PR/);
  assert.equal(r.target, d.id);
  assert.equal(status(d.id).status, "pending");
  assert.deepEqual(await actions(d.id), ["dispatch.retry", "dispatch.rework", "dispatch.switch_harness"], "交付进行中不显示交付按钮");
  fake.requests.length = 0;
  await drain();

  const item = latestOf(d.id, "create_pr");
  assert.equal(item.state, "done", item.error);
  assert.equal(item.payload.url, "https://github.com/acme/demo/pull/41");
  assert.equal(item.payload.target_branch, "main");
  assert.deepEqual(status(d.id), { status: "pr_open", url: "https://github.com/acme/demo/pull/41" });
  // 未提交的改动先提交再推送：裸仓库里的分支与 worktree HEAD 一致，工作区干净
  assert.equal(git(d.cwd, "status", "--porcelain"), "");
  assert.equal(git(path.join(tmp, "gh-origin.git"), "rev-parse", d.branch), git(d.cwd, "rev-parse", "HEAD"));
  // 请求：先查已有，再创建
  const [find, create] = fake.requests;
  assert.equal(find.method, "GET");
  assert.equal(find.query.get("head"), `acme:${d.branch}`);
  assert.equal(find.query.get("state"), "open");
  assert.equal(create.method, "POST");
  assert.equal(create.headers.authorization, `Bearer ${GH_TOKEN}`);
  assert.equal(create.headers.accept, "application/vnd.github+json");
  assert.equal(create.body!.head, d.branch);
  assert.equal(create.body!.base, "main");
  assert.equal(create.body!.draft, true);
  assert.equal(create.body!.title, `修复登录 ${d.guid.slice(0, 8)}`);
  const body = String(create.body!.body);
  assert.match(body, /guid=/);
  assert.match(body, /已修复登录超时/);
  assert.match(body, /校验命令 `npm test`：✅ 通过/);
  assert.match(body, /extra\.txt/, "变更统计包含交付前补提交的文件");
  assert.match(body, /由 Avatar 生成/);
  assert.ok(comments(d.guid).some((c) => c.includes("https://github.com/acme/demo/pull/41")), "任务评论里有 PR 链接");
  // PR 已打开：只能放弃
  const acts = await actions(d.id);
  assert.ok(acts.includes("delivery.discard"));
  assert.ok(!acts.includes("delivery.create_pr") && !acts.includes("delivery.merge_local"));
  await rejectsWith(exec("delivery.create_pr", { id: d.id }), "conflict", /已经创建过 PR/);
});

test("GitHub：同一分支已有打开的 PR 时复用，不重复创建", async () => {
  const d = seed("gh");
  fake.gh.prs.push({ number: 7, html_url: "https://github.com/acme/demo/pull/7", state: "open", head: { ref: d.branch }, base: { ref: "main" } });
  fake.requests.length = 0;
  await exec("delivery.create_pr", { id: d.id, title: "自定义标题" });
  await drain();
  const item = latestOf(d.id, "create_pr");
  assert.equal(item.state, "done", item.error);
  assert.equal(item.payload.url, "https://github.com/acme/demo/pull/7");
  assert.equal(item.payload.reused, true);
  assert.equal(fake.requests.filter((r) => r.method === "POST").length, 0);
  assert.ok(comments(d.guid).some((c) => c.includes("复用") && c.includes("/pull/7")));
});

test("GitHub 错误：401 落定为失败且不泄露令牌，可以再次交付；5xx 退避重试后成功", async () => {
  const d = seed("gh");
  fake.gh.mode = "401";
  await exec("delivery.create_pr", { id: d.id });
  await drain();
  const failed = latestOf(d.id, "create_pr");
  assert.equal(failed.state, "errored");
  assert.match(failed.error, /认证失败.*PA_TEST_GH_TOKEN/);
  assert.ok(!failed.error.includes(GH_TOKEN) && !JSON.stringify(failed.payload).includes(GH_TOKEN), "错误信息里没有令牌");
  assert.ok(comments(d.guid).some((c) => c.startsWith("❌ 创建 PR失败")));
  assert.equal(status(d.id).status, "failed");
  assert.ok((await actions(d.id)).includes("delivery.create_pr"), "失败后可以重新交付");

  fake.gh.mode = "500";
  await exec("delivery.create_pr", { id: d.id });
  await drain();
  const retrying = latestOf(d.id, "create_pr");
  assert.equal(retrying.terminal, false, "暂时性错误不落定");
  assert.match(retrying.error, /暂时不可用/);
  assert.equal(status(d.id).status, "pending");
  fake.gh.mode = "ok";
  await new Promise((r) => setTimeout(r, 50));
  await drain();
  assert.equal(latestOf(d.id, "create_pr").state, "done");
  assert.equal(status(d.id).status, "pr_open");

  // 404：仓库不存在
  const d2 = seed("gh");
  fake.gh.mode = "404";
  await exec("delivery.create_pr", { id: d2.id });
  await drain();
  assert.match(latestOf(d2.id, "create_pr").error, /找不到仓库 acme\/demo/);
  fake.gh.mode = "ok";
});

test("GitLab：项目路径编码、PRIVATE-TOKEN、草稿标题前缀、仓库配置的目标分支；创建撞上“已存在”时转为复用", async () => {
  const d = seed("gl");
  fake.requests.length = 0;
  await exec("delivery.create_pr", { id: d.id, draft: true });
  await drain();
  const item = latestOf(d.id, "create_pr");
  assert.equal(item.state, "done", item.error);
  assert.match(item.payload.url!, /^https:\/\/gitlab\.example\.com\/grp\/sub\/demo\/-\/merge_requests\/\d+$/);
  const create = fake.requests.find((r) => r.method === "POST")!;
  assert.match(create.url, /^\/gl\/api\/v4\/projects\/grp%2Fsub%2Fdemo\/merge_requests$/);
  assert.equal(create.headers["private-token"], GL_TOKEN);
  assert.equal(create.headers.authorization, undefined);
  assert.equal(create.body!.source_branch, d.branch);
  assert.equal(create.body!.target_branch, "main");
  assert.match(String(create.body!.title), /^Draft: 修复登录/);
  assert.match(String(create.body!.description), /由 Avatar 生成/);
  assert.equal(git(path.join(tmp, "gl-origin.git"), "rev-parse", d.branch), git(d.cwd, "rev-parse", "HEAD"));
  assert.ok(comments(d.guid).some((c) => c.includes("MR")));

  const d2 = seed("gl");
  fake.gl.mode = "race";
  await exec("delivery.create_pr", { id: d2.id });
  await drain();
  const raced = latestOf(d2.id, "create_pr");
  assert.equal(raced.state, "done", raced.error);
  assert.equal(raced.payload.reused, true);
  fake.gl.mode = "ok";
});

test("Codebase：经 bytedcli 创建 MR（参数、正文走标准输入、草稿），链接按编号拼出；已有 MR 时复用", async () => {
  const d = seed("cb");
  await exec("delivery.create_pr", { id: d.id, draft: true });
  await drain();
  const item = latestOf(d.id, "create_pr");
  assert.equal(item.state, "done", item.error);
  assert.equal(item.payload.url, "https://code.example.org/team/demo/merge_requests/100");
  const calls = cbLog();
  assert.deepEqual(calls[0].argv.slice(0, 6), ["--json", "codebase", "mr", "list", "-R", "team/demo"]);
  assert.ok(calls[0].argv.includes(d.branch));
  const create = calls[1].argv;
  assert.deepEqual(create.slice(0, 4), ["--json", "codebase", "mr", "create"]);
  const flag = (f: string) => create[create.indexOf(f) + 1];
  assert.equal(flag("-R"), "team/demo");
  assert.equal(flag("--head"), d.branch);
  assert.equal(flag("--base"), "main");
  assert.equal(flag("-F"), "-");
  assert.ok(create.includes("--draft"));
  assert.match(calls[1].input, /由 Avatar 生成/);
  assert.equal(git(path.join(tmp, "cb-origin.git"), "rev-parse", d.branch), git(d.cwd, "rev-parse", "HEAD"));

  // 复用：bytedcli 里已有这个分支的 MR
  const d2 = seed("cb");
  const s = cbState();
  s.mrs.push({ Number: 555, Status: "open", SourceBranchName: d2.branch, URL: "" });
  fs.writeFileSync(CB_STATE, JSON.stringify(s));
  const before = cbLog().length;
  await exec("delivery.create_pr", { id: d2.id });
  await drain();
  assert.equal(latestOf(d2.id, "create_pr").payload.url, "https://code.example.org/team/demo/merge_requests/555");
  assert.ok(!cbLog().slice(before).some((c) => c.argv.includes("create")), "没有再次创建");

  // bytedcli 未登录：永久失败
  const d3 = seed("cb");
  fs.writeFileSync(CB_STATE, JSON.stringify({ ...cbState(), fail: "not logged in, please run bytedcli auth login" }));
  await exec("delivery.create_pr", { id: d3.id });
  await drain();
  const f = latestOf(d3.id, "create_pr");
  assert.equal(f.state, "errored");
  assert.match(f.error, /Codebase：not logged in/);
  fs.writeFileSync(CB_STATE, JSON.stringify({ ...cbState(), fail: undefined }));
});

// ───────────────────────── 合并到本地分支 ─────────────────────────

test("本地合并：目标分支未检出时直接快进引用；检出且干净时 merge --ff-only", async () => {
  const repo = repos.local;
  git(repo, "branch", "release");
  const d = seed("local");
  await exec("delivery.merge_local", { id: d.id, target_branch: "release" });
  await drain();
  const item = latestOf(d.id, "merge_local");
  assert.equal(item.state, "done", item.error);
  assert.equal(git(repo, "rev-parse", "release"), git(d.cwd, "rev-parse", "HEAD"));
  assert.equal(git(repo, "symbolic-ref", "--short", "HEAD"), "main", "主仓库检出的分支不变");
  assert.equal(status(d.id).status, "merged_local");
  assert.ok(comments(d.guid).some((c) => c.includes("已快进合并到本地分支 release")));
  const acts = await actions(d.id);
  assert.ok(!acts.some((a) => a.startsWith("delivery.")), "合并后没有交付按钮");

  const d2 = seed("local");
  await exec("delivery.merge_local", { id: d2.id });
  await drain();
  assert.equal(latestOf(d2.id, "merge_local").state, "done", latestOf(d2.id, "merge_local").error);
  assert.equal(git(repo, "rev-parse", "main"), git(d2.cwd, "rev-parse", "HEAD"), "缺省合并到主仓库当前分支");
  assert.ok(fs.existsSync(path.join(repo, `${d2.guid.slice(0, 8)}.txt`)), "工作区随之更新");
  assert.equal(git(repo, "status", "--porcelain"), "");
});

test("本地合并：主仓库有未提交改动时拒绝；无法快进时建议创建 PR 或 rebase", async () => {
  const repo = repos.local;
  const d = seed("local");
  fs.appendFileSync(path.join(repo, "README.md"), "本地改了一半\n");
  await exec("delivery.merge_local", { id: d.id });
  await drain();
  const dirty = latestOf(d.id, "merge_local");
  assert.equal(dirty.state, "errored");
  assert.match(dirty.error, /未提交的改动/);
  assert.equal(status(d.id).status, "failed");
  assert.ok(comments(d.guid).some((c) => c.startsWith("❌ 合并到本地分支失败")));
  git(repo, "checkout", "--", "README.md");

  // 主分支上有了新提交：不能快进
  fs.writeFileSync(path.join(repo, "other.txt"), "别人的提交\n");
  git(repo, "add", "-A");
  git(repo, "commit", "-q", "-m", "other");
  await exec("delivery.merge_local", { id: d.id });
  await drain();
  const nonff = latestOf(d.id, "merge_local");
  assert.equal(nonff.state, "errored");
  assert.match(nonff.error, /无法快进.*创建 PR.*rebase/);
  assert.notEqual(git(repo, "rev-parse", "main"), git(d.cwd, "rev-parse", "HEAD"));

  await rejectsWith(exec("delivery.merge_local", { id: d.id, target_branch: "bad..name" }), "invalid", /分支名不合法/);
});

// ───────────────────────── 放弃 / 清理 / 恢复 ─────────────────────────

test("放弃：立即标记为已放弃、保留 worktree 并排定清理；保留期内恢复会取消清理", async () => {
  const d = seed("local");
  const r = await exec("delivery.discard", { id: d.id });
  assert.match(r.message, /保留 7 天/);
  await drain();
  assert.equal(status(d.id).status, "discarded");
  const discard = latestOf(d.id, "discard");
  const cleanup = app.ledger.get<DeliveryPayload>(discard.payload.cleanup_id!)!;
  assert.equal(cleanup.terminal, false);
  assert.equal(cleanup.payload.action, "cleanup");
  assert.ok(Math.abs(cleanup.next_at - (discard.created + 7 * 86_400_000)) < 1000, "保留 7 天后清理");
  assert.ok(fs.existsSync(d.cwd), "保留期内 worktree 还在");
  assert.ok(comments(d.guid).some((c) => c.startsWith("🗑️ 已放弃")));
  assert.deepEqual((await actions(d.id)).filter((a) => a.startsWith("delivery.")), ["delivery.restore"]);
  await rejectsWith(exec("delivery.merge_local", { id: d.id }), "conflict", /已放弃/);

  await exec("delivery.restore", { id: d.id });
  assert.equal(app.ledger.isCancelled(cleanup.id), true, "命令立即取消清理");
  await drain();
  assert.equal(status(d.id).status, "none");
  assert.equal(app.ledger.get(cleanup.id)!.state, "cancelled");
  assert.ok(fs.existsSync(d.cwd));
  assert.ok(git(repos.local, "branch", "--list", d.branch).includes(d.branch));
  assert.ok(comments(d.guid).some((c) => c.startsWith("↩️ 已恢复")));
  const acts = await actions(d.id);
  assert.ok(acts.includes("delivery.merge_local") && acts.includes("delivery.discard"));
});

test("放弃：保留期到了清理 worktree 与本地分支，之后仍显示已放弃、不能恢复", async () => {
  const d = seed("local");
  await exec("delivery.discard", { id: d.id });
  await drain();
  const cleanupId = latestOf(d.id, "discard").payload.cleanup_id!;
  // 模拟保留期已过
  app.ledger.db.prepare("UPDATE work SET next_at = 0 WHERE id = ?").run(cleanupId);
  await drain();
  const cleanup = app.ledger.get<DeliveryPayload>(cleanupId)!;
  assert.equal(cleanup.state, "done", cleanup.error);
  assert.ok(!fs.existsSync(d.cwd), "worktree 已删除");
  assert.equal(git(repos.local, "branch", "--list", d.branch), "", "本地分支已删除");
  assert.ok(!git(repos.local, "worktree", "list").includes(d.cwd));
  assert.equal(status(d.id).status, "discarded");
  assert.equal(app.store.get(`worktree.${d.guid}.base`), "");
  assert.ok(comments(d.guid).some((c) => c.startsWith("🧹")));
  await rejectsWith(exec("delivery.restore", { id: d.id }), "conflict");
});

test("放弃后卡片又被重新派单：清理跳过，不删正在使用的 worktree", async () => {
  const d = seed("local");
  await exec("delivery.discard", { id: d.id });
  await drain();
  const cleanupId = latestOf(d.id, "discard").payload.cleanup_id!;
  seed("local", { guid: d.guid, state: "executing", terminal: false }); // 同一张卡片的新一次派单（同一 worktree）
  app.ledger.db.prepare("UPDATE work SET next_at = 0 WHERE id = ?").run(cleanupId);
  await drain();
  assert.equal(app.ledger.get(cleanupId)!.state, "cancelled");
  assert.ok(fs.existsSync(d.cwd));
});

test("已创建 PR 后放弃：提示 PR 不会自动关闭", async () => {
  const d = seed("gh");
  await exec("delivery.create_pr", { id: d.id });
  await drain();
  assert.equal(status(d.id).status, "pr_open");
  await exec("delivery.discard", { id: d.id });
  await drain();
  assert.equal(status(d.id).status, "discarded");
  assert.ok(comments(d.guid).some((c) => c.includes("不会自动关闭") && c.includes("/pull/")));
});

// ───────────────────────── 命令前置条件 ─────────────────────────

test("命令前置条件：不存在 404；进行中 / 非最新 / 无分支 / 交付进行中 / worktree 缺失 / 无交付平台 409", async () => {
  await rejectsWith(exec("delivery.merge_local", { id: "dispatch:nope:1" }), "not_found");
  await rejectsWith(exec("delivery.merge_local", {}), "invalid");

  const running = seed("local", { state: "executing", terminal: false });
  await rejectsWith(exec("delivery.merge_local", { id: running.id }), "conflict", /进行中/);
  app.ledger.db.prepare("UPDATE work SET terminal = 1, state = 'cancelled' WHERE id = ?").run(running.id);
  await rejectsWith(exec("delivery.merge_local", { id: running.id }), "conflict", /只有已通过/);

  const old = seed("local");
  const newer = seed("local", { guid: old.guid });
  await rejectsWith(exec("delivery.discard", { id: old.id }), "conflict", /更新的派单/);

  // 没有在 worktree 中执行
  const id = `dispatch:gnobranch:${Date.now()}`;
  app.ledger.enqueue({ id, kind: "dispatch", ref: "gnobranch", state: "accepted", payload: { guid: "gnobranch", summary: "x", description: "", branch: "", cwd: "" } });
  app.ledger.db.prepare("UPDATE work SET terminal = 1 WHERE id = ?").run(id);
  await rejectsWith(exec("delivery.merge_local", { id }), "conflict", /没有可交付的分支/);
  assert.ok(!(await actions(id)).some((a) => a.startsWith("delivery.")));

  // 交付进行中：重复点击被拒绝
  await exec("delivery.merge_local", { id: newer.id });
  await rejectsWith(exec("delivery.discard", { id: newer.id }), "conflict", /进行中/);
  await drain();

  // 无法解析交付平台（local 仓库没有 provider，配置了多个平台且没有 default_provider）
  const d = seed("local");
  await rejectsWith(exec("delivery.create_pr", { id: d.id }), "conflict", /没有指定交付平台/);

  // worktree 不在了
  const gone = seed("local");
  git(repos.local, "worktree", "remove", "--force", gone.cwd);
  await rejectsWith(exec("delivery.merge_local", { id: gone.id }), "conflict", /worktree 已不存在/);

  // 审计
  const audit = app.ledger.auditLog(5, gone.id);
  assert.equal(audit[0].command, "delivery.merge_local");
  assert.equal(audit[0].ok, 0);
});

test("控制台元信息：交付功能已启用", async () => {
  const { meta } = await import("../src/api/queries.ts");
  assert.equal(meta(app, "test").features.delivery, true);
});
