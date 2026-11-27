/**
 * 控制台服务与命令层：鉴权、CSRF、命令 API、只读查询、SSE、日志读取的路径限制、重新派单语义。
 * 不访问飞书：只用到账本，lark-cli 指向测试桩。
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { createApp, type App } from "../src/app.ts";
import type { CommandResult, DispatchDetail, DispatchSummary, Meta, Overview } from "../src/api/types.ts";
import { loadConfig } from "../src/config.ts";
import {
  consoleBaseUrl,
  consoleLinkUrl,
  detectLanIp,
  isLoopbackHost,
  isWildcardHost,
  safeNextPath,
  serverToken,
  signLoginTicket,
  startServer,
  verifyLoginTicket,
  type ConsoleServer,
} from "../src/server/index.ts";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "pa-server-"));
let app: App;
let srv: ConsoleServer;
let token: string;

before(async () => {
  const file = path.join(tmp, "config.yaml");
  fs.writeFileSync(
    file,
    JSON.stringify({
      data_dir: path.join(tmp, "data"),
      bins: { lark: path.join(ROOT, "test/stubs/lark-cli"), acpx: path.join(ROOT, "test/stubs/acpx") },
      harnesses: { claude: { agent: "claude" }, codex: { agent: "codex" } },
      roles: { brain: "claude", reviewer: "codex" },
      owner: { open_id: "ou_owner" },
    }),
  );
  app = createApp(loadConfig(file));
  srv = await startServer(app, { version: "test", port: 0 });
  token = serverToken(app);
});
after(async () => {
  await srv.close();
  app.store.db.close();
  fs.rmSync(tmp, { recursive: true, force: true });
});

const api = (p: string, init: RequestInit & { auth?: boolean } = {}) =>
  fetch(srv.url + p, {
    ...init,
    redirect: "manual",
    headers: { ...(init.auth === false ? {} : { Authorization: `Bearer ${token}` }), ...(init.headers ?? {}) },
  });
const cmd = (name: string, args: unknown, headers: Record<string, string> = {}) =>
  api(`/api/commands/${name}`, { method: "POST", body: JSON.stringify({ args }), headers: { "Content-Type": "application/json", ...headers } });

/** 放一项派单到账本里（不经飞书）。 */
function seedDispatch(guid: string, state: string, terminal: boolean, extra: Record<string, unknown> = {}): string {
  const id = `dispatch:${guid}:${Math.random().toString(36).slice(2)}`;
  app.ledger.enqueue({ id, kind: "dispatch", ref: guid, state, payload: { guid, summary: `[codex] 任务 ${guid}`, description: "repo: demo", harness: "codex", round: 1, maxRounds: 2, history: [], ...extra } });
  if (terminal) app.ledger.db.prepare("UPDATE work SET terminal = 1, outcome = state WHERE id = ?").run(id);
  return id;
}

test("鉴权：没有令牌 401；登录链接写 HttpOnly Cookie；错误令牌拒绝；静态页面无需登录", async () => {
  assert.equal((await api("/api/meta", { auth: false })).status, 401);
  const bad = await api("/login?token=wrong", { auth: false });
  assert.equal(bad.status, 401);
  const login = await api(`/login?token=${token}`, { auth: false });
  assert.equal(login.status, 302);
  assert.equal(login.headers.get("location"), "/");
  const cookie = login.headers.get("set-cookie") ?? "";
  assert.match(cookie, /pa_session=.+HttpOnly; SameSite=Lax/);
  const viaCookie = await api("/api/meta", { auth: false, headers: { Cookie: cookie.split(";")[0] } });
  assert.equal(viaCookie.status, 200);
  const meta = (await viaCookie.json()) as Meta;
  assert.deepEqual(meta.harnesses, ["claude", "codex"]);
  const page = await api("/", { auth: false });
  assert.equal(page.status, 200);
  assert.match(page.headers.get("content-security-policy") ?? "", /default-src 'self'/);
});

test("卡片登录票据与 next 跳转：有效票据自动种 Cookie 并跳目标页；防开放重定向；过期票据对已登录浏览器放行；令牌轮换即时失效", async () => {
  const ticket = signLoginTicket(token);
  assert.ok(!ticket.includes(token), "票据不暴露主令牌");
  assert.equal(verifyLoginTicket(token, ticket), true);
  assert.equal(verifyLoginTicket(token, `${ticket}x`), false);

  const link = consoleLinkUrl(srv.url, "/today", ticket);
  const parsed = new URL(link);
  assert.equal(parsed.pathname, "/login");
  assert.equal(parsed.searchParams.get("ticket"), ticket);
  assert.equal(parsed.searchParams.get("next"), "/today");

  // 有效票据：种 HttpOnly + SameSite=Lax Cookie 并跳 /today
  const okRes = await api(`${parsed.pathname}${parsed.search}`, { auth: false });
  assert.equal(okRes.status, 302);
  assert.equal(okRes.headers.get("location"), "/today");
  const cookie = okRes.headers.get("set-cookie") ?? "";
  assert.match(cookie, /pa_session=.+HttpOnly; SameSite=Lax/);
  const cookiePair = cookie.split(";")[0];
  assert.equal((await api("/api/meta", { auth: false, headers: { Cookie: cookiePair } })).status, 200);

  // 篡改票据 / 过期票据：未登录时 401
  const expired = signLoginTicket(token, -1000);
  assert.equal(verifyLoginTicket(token, expired), false);
  assert.equal((await api(`/login?ticket=${encodeURIComponent(expired)}&next=%2Ftoday`, { auth: false })).status, 401);
  assert.equal((await api(`/login?ticket=${encodeURIComponent(`${ticket}x`)}&next=%2Ftoday`, { auth: false })).status, 401);

  // 过期票据：已持有有效 Cookie 的浏览器 / 飞书 WebView 直接跳去目标页
  const passThrough = await api(`/login?ticket=${encodeURIComponent(expired)}&next=%2Ftoday`, { auth: false, headers: { Cookie: cookiePair } });
  assert.equal(passThrough.status, 302);
  assert.equal(passThrough.headers.get("location"), "/today");
  assert.equal(passThrough.headers.get("set-cookie"), null);

  // 开放重定向防护：非站内相对路径一律回退 /
  for (const evil of ["//evil.example/x", "https://evil.example/x", "/\\evil.example", "/today\r\nX-Test: 1"]) {
    assert.equal(safeNextPath(evil), "/", evil);
    const r = await api(`/login?ticket=${encodeURIComponent(ticket)}&next=${encodeURIComponent(evil)}`, { auth: false });
    assert.equal(r.status, 302);
    assert.equal(r.headers.get("location"), "/", evil);
  }
  assert.equal(safeNextPath("/dispatches/dispatch%3Ag1%3A1?tab=diff"), "/dispatches/dispatch%3Ag1%3A1?tab=diff");

  // 主令牌轮换：旧 Cookie 与旧票据在运行中的服务里立即失效，新票据生效
  const rotated = serverToken(app, true);
  try {
    assert.notEqual(rotated, token);
    assert.equal((await api("/api/meta", { auth: false, headers: { Cookie: cookiePair } })).status, 401);
    assert.equal((await api(`/login?ticket=${encodeURIComponent(ticket)}&next=%2Ftoday`, { auth: false })).status, 401);
    const freshTicket = signLoginTicket(rotated);
    const freshRes = await api(`/login?ticket=${encodeURIComponent(freshTicket)}&next=%2Ftoday`, { auth: false });
    assert.equal(freshRes.status, 302);
    assert.equal(freshRes.headers.get("location"), "/today");
  } finally {
    app.store.set("server.token", token);
  }
});

test("CSRF：跨站来源的写请求被拒绝；写请求必须是 JSON", async () => {
  const id = seedDispatch("g_csrf", "executing", false);
  const evil = await cmd("dispatch.cancel", { id }, { Origin: "http://evil.example" });
  assert.equal(evil.status, 403);
  assert.equal(app.ledger.isCancelled(id), false);
  const form = await api("/api/commands/dispatch.cancel", { method: "POST", body: "id=x", headers: { "Content-Type": "application/x-www-form-urlencoded" } });
  assert.equal(form.status, 415);
  const same = await cmd("dispatch.cancel", { id }, { Origin: srv.url });
  assert.equal(same.status, 200);
  assert.equal(app.ledger.isCancelled(id), true);
});

test("命令 API：参数校验 400、未知命令 404、前置条件 409，并写审计", async () => {
  assert.equal((await cmd("dispatch.cancel", {})).status, 400);
  assert.equal((await cmd("no.such", {})).status, 404);
  const done = seedDispatch("g_done", "accepted", true);
  const r = await cmd("dispatch.cancel", { id: done });
  assert.equal(r.status, 409);
  const body = (await r.json()) as { error: { message: string } };
  assert.match(body.error.message, /已经结束/);
  const audit = app.ledger.auditLog(10, done);
  assert.equal(audit[0].command, "dispatch.cancel");
  assert.equal(audit[0].ok, 0);
  assert.equal(audit[0].source, "web");
});

test("重新派单：返工带意见、换执行者；同一卡片已有进行中的派单时拒绝；只能操作最新一次", async () => {
  const first = seedDispatch("g_rework", "needs_human", true);
  const r = await cmd("dispatch.rework", { id: first, feedback: "请补上单元测试" });
  assert.equal(r.status, 200);
  const res = (await r.json()) as CommandResult;
  const next = app.ledger.get<{ initial_feedback: string; harness_override: string; redispatch_of: string }>(res.target!)!;
  assert.equal(next.state, "queued");
  assert.equal(next.payload.initial_feedback, "请补上单元测试");
  assert.equal(next.payload.harness_override, "codex", "返工沿用原执行者");
  assert.equal(next.payload.redispatch_of, first);
  const fx = app.ledger.effectsOf(res.target!).map((e) => e.payload.op);
  assert.deepEqual(fx, ["task.comment", "task.move"], "评论和移回派单列与入队同一事务");
  // 已有进行中的派单：再操作旧的一次被拒绝
  assert.equal((await cmd("dispatch.switch_harness", { id: first, harness: "claude" })).status, 409);
  // 换执行者需要合法的执行者名
  assert.equal((await cmd("dispatch.switch_harness", { id: first, harness: "nope" })).status, 400);
});

test("只读查询：列表、详情（含可执行操作）、概览；跨卡片只取最新一次", async () => {
  const id = seedDispatch("g_view", "accepted", true, { branch: "pa/g_view", report: "做完了" });
  const list = (await (await api("/api/dispatches?filter=review")).json()) as DispatchSummary[];
  const row = list.find((d) => d.id === id)!;
  assert.equal(row.summary, "任务 g_view", "去掉执行者前缀");
  assert.equal(row.repo, "demo");
  const detail = (await (await api(`/api/dispatches/${encodeURIComponent(id)}`)).json()) as DispatchDetail;
  assert.equal(detail.report, "做完了");
  assert.ok(detail.actions.includes("dispatch.rework"));
  assert.ok(!detail.actions.includes("dispatch.cancel"), "已结束的派单不能取消");
  assert.equal((await api("/api/dispatches/nope")).status, 404);
  const ov = (await (await api("/api/overview")).json()) as Overview;
  assert.ok(ov.attention.to_review.some((d) => d.id === id));
  assert.equal(ov.health.ok, false, "常驻进程没有心跳");
});

test("日志读取：只允许数据目录下的文件；分段读取", async () => {
  const id = seedDispatch("g_log", "executing", false);
  const inside = path.join(app.cfg.dataDir, "runs", "x.log");
  fs.mkdirSync(path.dirname(inside), { recursive: true });
  fs.writeFileSync(inside, "line1\nline2\n");
  const ok = app.ledger.startStep({ work_id: id, name: "worker#1", log: inside });
  const chunk = await (await api(`/api/steps/${ok}/log?offset=6`)).json();
  assert.equal(chunk.text, "line2\n");
  assert.equal(chunk.eof, true);
  assert.equal(chunk.running, true);
  const outside = app.ledger.startStep({ work_id: id, name: "worker#1", log: "/etc/passwd" });
  const denied = await (await api(`/api/steps/${outside}/log`)).json();
  assert.equal(denied.text, "", "数据目录之外的文件不可读");
});

test("SSE：账本变化实时推送", async () => {
  const ctrl = new AbortController();
  const res = await fetch(`${srv.url}/api/events`, { headers: { Authorization: `Bearer ${token}` }, signal: ctrl.signal });
  assert.equal(res.headers.get("content-type"), "text/event-stream");
  const reader = res.body!.getReader();
  const id = seedDispatch("g_sse", "queued", false);
  let buf = "";
  const deadline = Date.now() + 3000;
  while (!buf.includes(id) && Date.now() < deadline) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += new TextDecoder().decode(value);
  }
  ctrl.abort();
  assert.match(buf, new RegExp(`"type":"work".*${id.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));
});

test("未启用的模块：接口返回 501，而不是报错", async () => {
  // 模块是否注册取决于 src/modules.ts；这里临时摘掉一个，验证未启用时的行为
  const saved = app.ext.usage;
  delete app.ext.usage;
  try {
    const r = await api("/api/usage");
    assert.equal(r.status, 501);
  } finally {
    app.ext.usage = saved;
  }
});

test("局域网地址解析：优先物理网卡私网 IPv4，避开 docker/网桥/link-local，无可用网卡回退 127.0.0.1", () => {
  const nic = (address: string, extra: Partial<os.NetworkInterfaceInfo> = {}): os.NetworkInterfaceInfo =>
    ({ address, netmask: "255.255.255.0", family: "IPv4", mac: "00:00:00:00:00:00", internal: false, cidr: `${address}/24`, ...extra }) as os.NetworkInterfaceInfo;

  assert.equal(
    detectLanIp({
      lo: [nic("127.0.0.1", { internal: true })],
      docker0: [nic("172.17.0.1")],
      "br-1234": [nic("172.18.0.1")],
      utun0: [nic("100.64.0.2")],
      eth0: [nic("169.254.1.9"), nic("2605:340::1", { family: "IPv6" }), nic("10.251.232.51")],
    }),
    "10.251.232.51",
  );
  assert.equal(detectLanIp({ lo: [nic("127.0.0.1", { internal: true })], docker0: [nic("172.17.0.1")] }), "172.17.0.1");
  assert.equal(detectLanIp({ lo: [nic("127.0.0.1", { internal: true })], eth0: [nic("169.254.1.9"), nic("::1", { family: "IPv6" })] }), undefined);

  const fakeIfaces = { eth0: [nic("10.251.232.51")] };
  assert.equal(consoleBaseUrl("0.0.0.0", 7878, fakeIfaces), "http://10.251.232.51:7878");
  assert.equal(consoleBaseUrl("::", 7878, fakeIfaces), "http://10.251.232.51:7878");
  assert.equal(consoleBaseUrl("", 7878, fakeIfaces), "http://10.251.232.51:7878");
  assert.equal(consoleBaseUrl("0.0.0.0", 7878, {}), "http://127.0.0.1:7878");
  assert.equal(consoleBaseUrl("127.0.0.1", 7878, fakeIfaces), "http://127.0.0.1:7878");
  assert.equal(consoleBaseUrl("192.168.1.20", 7878, fakeIfaces), "http://192.168.1.20:7878");
  assert.equal(consoleBaseUrl("::1", 7878, fakeIfaces), "http://[::1]:7878");
  assert.equal(isWildcardHost("0.0.0.0"), true);
  assert.equal(isWildcardHost("[::]"), true);
  assert.equal(isLoopbackHost("127.0.0.1"), true);
  assert.equal(isLoopbackHost("[::1]"), true);
  assert.equal(isLoopbackHost("10.251.232.51"), false);
});

test("默认监听 0.0.0.0 返回局域网地址；显式 127.0.0.1 返回回环地址；pa console 输出匹配", async () => {
  const expectedDefaultHost = detectLanIp() ?? "127.0.0.1";
  assert.equal(new URL(srv.url).hostname, expectedDefaultHost);

  const localSrv = await startServer(app, { version: "test", host: "127.0.0.1", port: 0 });
  try {
    assert.equal(new URL(localSrv.url).hostname, "127.0.0.1");
  } finally {
    await localSrv.close();
  }

  const outDefault = execFileSync(path.join(ROOT, "bin", "pa"), ["console"], {
    env: { ...process.env, PA_CONFIG: path.join(tmp, "config.yaml") },
    encoding: "utf8",
  });
  assert.ok(outDefault.includes(`http://${expectedDefaultHost}:7878/login?token=`), outDefault);
  if (expectedDefaultHost !== "127.0.0.1") {
    assert.ok(!outDefault.includes("127.0.0.1:7878"), outDefault);
  }

  const loopCfg = path.join(tmp, "config-loopback.yaml");
  fs.writeFileSync(
    loopCfg,
    JSON.stringify({
      data_dir: path.join(tmp, "data"),
      bins: { lark: path.join(ROOT, "test/stubs/lark-cli"), acpx: path.join(ROOT, "test/stubs/acpx") },
      harnesses: { claude: { agent: "claude" } },
      roles: { brain: "claude" },
      owner: { open_id: "ou_owner" },
      server: { host: "127.0.0.1", port: 7878 },
    }),
  );
  const outLoop = execFileSync(path.join(ROOT, "bin", "pa"), ["console"], {
    env: { ...process.env, PA_CONFIG: loopCfg },
    encoding: "utf8",
  });
  assert.ok(outLoop.includes("http://127.0.0.1:7878/login?token="), outLoop);
  assert.match(outLoop, /ssh -L 7878:127\.0\.0\.1:7878/);
});
