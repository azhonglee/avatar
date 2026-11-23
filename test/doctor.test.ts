/**
 * 体检：用桩程序和临时目录跑各项检查；每项隔离、外部命令有超时、ready 由 fail 决定；pa doctor 的输出与退出码。
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import type { DoctorReport } from "../src/api/types.ts";
import { createApp, type App } from "../src/app.ts";
import { loadConfig } from "../src/config.ts";
import { formatReport, runDoctor } from "../src/doctor.ts";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const STUBS = path.join(ROOT, "test", "stubs");
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "pa-doctor-"));
const file = path.join(tmp, "config.yaml");
const repo = path.join(tmp, "demo-repo");
let app: App;

const byId = (r: DoctorReport, id: string) => {
  const c = r.checks.find((x) => x.id === id);
  assert.ok(c, `缺少检查项 ${id}：${r.checks.map((x) => x.id).join(",")}`);
  return c;
};

before(() => {
  process.env.STUB_STATE = path.join(tmp, "stub-state.json");
  fs.mkdirSync(repo);
  execFileSync("git", ["-C", repo, "init", "-q"]);
  fs.mkdirSync(path.join(tmp, "not-a-repo"));
  fs.writeFileSync(
    file,
    `
data_dir: ${path.join(tmp, "data")}
bins: { lark: ${path.join(STUBS, "lark-cli")}, acpx: ${path.join(STUBS, "acpx")} }
owner: { open_id: ou_owner }
harnesses:
  claude: { agent: claude }
  codex:
    agent: codex
    env: { API_KEY: "\${PA_DOCTOR_TEST_KEY}" }
roles: { brain: claude, reviewer: codex }
dispatch:
  repos:
    demo: { path: ${repo}, verify: "npm test" }
    gone: ${path.join(tmp, "nope")}
    plain: ${path.join(tmp, "not-a-repo")}
delivery:
  providers:
    gh: { type: github, token_env: PA_DOCTOR_GH_TOKEN }
    lab: { type: gitlab }
`,
  );
  app = createApp(loadConfig(file));
});
after(() => {
  app.store.db.close();
  fs.rmSync(tmp, { recursive: true, force: true });
});

test("未初始化：看板失败、仓库问题、令牌与环境变量提醒；ready=false", async () => {
  const r = await runDoctor(app, { env: { PA_DOCTOR_GH_TOKEN: "super-secret-token" } });
  assert.equal(r.ready, false);
  for (const id of ["node", "config", "lark_cli", "lark_auth", "owner", "acpx", "harness:claude", "git", "repo:demo", "data_dir", "server"]) {
    assert.equal(byId(r, id).status, "ok", `${id}: ${byId(r, id).detail}`);
  }
  assert.match(byId(r, "lark_auth").detail, /主人/);
  assert.match(byId(r, "repo:demo").detail, /npm test/);
  const board = byId(r, "board");
  assert.equal(board.status, "fail");
  assert.match(board.fix, /pa init/);
  assert.equal(byId(r, "kb").status, "warn");
  assert.equal(byId(r, "repo:gone").status, "fail");
  assert.match(byId(r, "repo:gone").detail, /路径不存在/);
  assert.equal(byId(r, "repo:plain").status, "fail");
  assert.match(byId(r, "repo:plain").detail, /不是 git 仓库/);
  // harness 引用的环境变量没设置
  const codex = byId(r, "harness:codex");
  assert.equal(codex.status, "warn");
  assert.match(codex.detail, /PA_DOCTOR_TEST_KEY/);
  // 交付平台：令牌只检查是否设置，从不输出值
  assert.equal(byId(r, "provider:gh").status, "ok");
  assert.equal(byId(r, "provider:lab").status, "warn");
  assert.ok(!JSON.stringify(r).includes("super-secret-token"));
  // 事件订阅提醒：卡片启用时包含 card.action.trigger
  const ev = byId(r, "events");
  assert.match(ev.fix, /card\.action\.trigger/);
  assert.match(ev.fix, /im\.message\.receive_v1/);
  assert.equal(byId(r, "daemon").status, "warn");
  assert.match(byId(r, "acceptance").detail, /codex/);
  // 每项都有中文标题；失败项都有修复指引
  for (const c of r.checks) {
    assert.ok(c.title);
    if (c.status === "fail") assert.ok(c.fix, `${c.id} 缺少修复指引`);
  }
  const text = formatReport(r);
  assert.match(text, /❌ Agent 看板/);
  assert.match(text, /还有 \d+ 项需要处理/);
});

test("初始化完成、问题修好后 ready=true；看板缺分组只是提醒", async () => {
  const { store, cfg } = app;
  store.set("board.tasklist", "tl_board");
  const keys = Object.keys(cfg.board.sections);
  for (const k of keys.filter((k) => k !== "attention")) store.set(`board.section.${k}`, `sec_${k}`);
  store.set("kb.space", "sp_1");
  for (const n of cfg.kb.nodes) store.set(`kb.node.${n}`, `node_${n}`);
  delete cfg.dispatch.repos.gone;
  delete cfg.dispatch.repos.plain;
  let r = await runDoctor(app, { env: {} });
  assert.equal(byId(r, "board").status, "warn");
  assert.match(byId(r, "board").detail, /需人工介入/);
  assert.equal(r.ready, true, JSON.stringify(r.checks.filter((c) => c.status === "fail")));
  store.set("board.section.attention", "sec_attention");
  store.set("daemon.heartbeat", `host:1:abc|${Date.now() - 5000}`);
  r = await runDoctor(app, { env: { PA_DOCTOR_TEST_KEY: "k", PA_DOCTOR_GH_TOKEN: "t" } });
  assert.equal(byId(r, "board").status, "ok");
  assert.equal(byId(r, "kb").status, "ok");
  assert.equal(byId(r, "daemon").status, "ok");
  assert.equal(byId(r, "harness:codex").status, "ok");
  assert.equal(r.ready, true);
  // 心跳过期 → 提醒
  store.set("daemon.heartbeat", `host:1:abc|${Date.now() - 10 * 60_000}`);
  r = await runDoctor(app);
  assert.equal(byId(r, "daemon").status, "warn");
  assert.match(byId(r, "daemon").detail, /没有在运行/);
});

test("隔离：某项抛错只让它自己失败；缺少 lark-cli 时依赖它的检查跳过", async () => {
  const origGet = app.store.get.bind(app.store);
  const origLark = app.cfg.bins.lark;
  app.store.get = (k: string) => {
    if (k === "daemon.heartbeat") throw new Error("磁盘坏了");
    return origGet(k);
  };
  app.cfg.bins.lark = path.join(tmp, "no-such-lark-cli");
  try {
    const r = await runDoctor(app);
    const d = byId(r, "daemon");
    assert.equal(d.status, "fail");
    assert.match(d.detail, /检查出错：磁盘坏了/);
    assert.equal(byId(r, "lark_cli").status, "fail");
    assert.equal(byId(r, "lark_auth").status, "skip");
    assert.equal(byId(r, "board").status, "ok");
    assert.equal(r.ready, false);
  } finally {
    app.store.get = origGet;
    app.cfg.bins.lark = origLark;
  }
});

test("外部命令卡住：按超时失败，总耗时有上限；依赖它的检查跳过", async () => {
  const hang = path.join(tmp, "hang-acpx");
  fs.writeFileSync(hang, "#!/usr/bin/env bash\nexec sleep 20\n", { mode: 0o755 });
  const orig = app.cfg.bins.acpx;
  app.cfg.bins.acpx = hang;
  try {
    const t0 = Date.now();
    const r = await runDoctor(app, { commandTimeoutMs: 300, checkTimeoutMs: 3000 });
    assert.ok(Date.now() - t0 < 5000, `耗时 ${Date.now() - t0}ms`);
    const a = byId(r, "acpx");
    assert.equal(a.status, "fail");
    assert.match(a.detail, /超时/);
    assert.equal(byId(r, "harness:claude").status, "skip");
    assert.equal(r.ready, false);
  } finally {
    app.cfg.bins.acpx = orig;
  }
});

test("新版 lark-cli 的裸 JSON 登录状态：解析用户/机器人身份；版本过低时提醒", async () => {
  const fake = path.join(tmp, "fake-lark");
  const status = path.join(tmp, "auth.json");
  fs.writeFileSync(
    fake,
    `#!/usr/bin/env bash\nif [ "$1" = "--version" ]; then echo "lark-cli version 1.0.99"; exit 0; fi\ncat "${status}"\n`,
    { mode: 0o755 },
  );
  const orig = app.cfg.bins.lark;
  app.cfg.bins.lark = fake;
  const write = (user: Record<string, unknown>, bot: Record<string, unknown>) =>
    fs.writeFileSync(status, JSON.stringify({ appId: "cli_x", identity: "user", identities: { user, bot } }));
  try {
    const later = new Date(Date.now() + 5 * 86400_000).toISOString();
    write({ status: "needs_refresh", available: true, userName: "主人", openId: "ou_real", refreshExpiresAt: later }, { status: "ready", available: true });
    let r = await runDoctor(app);
    assert.equal(byId(r, "lark_auth").status, "ok");
    assert.match(byId(r, "lark_auth").detail, /主人（ou_real）/);
    assert.equal(byId(r, "lark_cli").status, "warn");
    assert.match(byId(r, "lark_cli").detail, /1\.0\.100/);
    write({ status: "expired", available: false }, { status: "ready", available: true });
    r = await runDoctor(app);
    assert.equal(byId(r, "lark_auth").status, "fail");
    assert.match(byId(r, "lark_auth").fix, /lark-cli auth login/);
    write({ status: "ready", available: true, refreshExpiresAt: new Date(Date.now() + 3600_000).toISOString() }, { status: "ready", available: true });
    r = await runDoctor(app);
    assert.equal(byId(r, "lark_auth").status, "warn");
  } finally {
    app.cfg.bins.lark = orig;
  }
});

test("pa doctor：打印报告，未就绪时退出码非 0", () => {
  const fresh = path.join(tmp, "fresh");
  fs.mkdirSync(fresh);
  const cfgFile = path.join(fresh, "config.yaml");
  fs.writeFileSync(
    cfgFile,
    `data_dir: ${path.join(fresh, "data")}
bins: { lark: ${path.join(STUBS, "lark-cli")}, acpx: ${path.join(STUBS, "acpx")} }
harnesses: { claude: { agent: claude } }
roles: { brain: claude }
`,
  );
  let out = "";
  let status = 0;
  try {
    out = execFileSync(path.join(ROOT, "bin", "pa"), ["doctor"], { env: { ...process.env, PA_CONFIG: cfgFile }, encoding: "utf8", cwd: fresh });
  } catch (e) {
    const err = e as { status: number; stdout: string };
    status = err.status;
    out = err.stdout;
  }
  assert.equal(status, 1, out);
  assert.match(out, /✅ lark-cli/);
  assert.match(out, /❌ 主人身份/);
  assert.match(out, /pa init/);
  assert.match(out, /⚠️ {1,2}验收方式/);
});
