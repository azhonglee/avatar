/**
 * 设置服务：保留注释的合并写入、带路径的中文校验错误、原子写 + .bak、热加载与需要重启、禁止修改的字段、审计。
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import YAML from "yaml";
import { createApp, type App } from "../src/app.ts";
import { loadConfig } from "../src/config.ts";
import { MASK } from "../src/settings.ts";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "pa-settings-"));
const file = path.join(tmp, "config.yaml");
let app: App;

const ORIGINAL = `# 顶部注释：personal-agent 配置
owner:
  open_id: ou_owner   # 主人
data_dir: ${path.join(tmp, "data")}
bins: { lark: ${path.join(ROOT, "test/stubs/lark-cli")}, acpx: ${path.join(ROOT, "test/stubs/acpx")} }

harnesses:
  claude: { agent: claude }
  codex:
    agent: codex
    env:
      SECRET: literal-secret-value
      REF: \${MY_KEY}

roles:
  brain: claude     # 大脑
  reviewer: codex

dispatch:
  # 并发上限
  max_parallel: 2
  fix_rounds: 1     # 返工轮数
  repos:
    web: ~/code/web

schedules:
  capture: "*/15 * * * *"
`;

const settings = () => app.ext.settings!;
const read = () => fs.readFileSync(file, "utf8");
const lastAudit = () => app.ledger.auditLog(1)[0];

before(() => {
  fs.writeFileSync(file, ORIGINAL);
  app = createApp(loadConfig(file));
});
after(() => {
  app.store.db.close();
  fs.rmSync(tmp, { recursive: true, force: true });
});

test("读取：带默认值，harness.env 明文打码、${VAR} 原样显示，热加载表", () => {
  const v = settings().get();
  assert.equal(v.file, file);
  assert.equal(v.restart_required, false);
  const c = v.config as any;
  assert.equal(c.harnesses.codex.env.SECRET, MASK);
  assert.equal(c.harnesses.codex.env.REF, "${MY_KEY}");
  assert.equal(c.dispatch.fix_rounds, 1);
  assert.equal(c.notify.quiet_start, ""); // 默认值
  assert.equal(c.dataDir, undefined);
  assert.ok(!JSON.stringify(v).includes("literal-secret-value"));
  assert.equal(v.hot_reload.notify, true);
  assert.equal(v.hot_reload.dispatch, true);
  assert.equal(v.hot_reload["dispatch.max_parallel"], false);
  assert.equal(v.hot_reload.schedules, false);
  assert.equal(v.hot_reload.harnesses, false);
});

test("热加载：保留注释与顺序，原子写 + .bak，原地更新 app.cfg，写审计", async () => {
  const dispatchRef = app.cfg.dispatch;
  const notifyRef = app.cfg.notify;
  const r = await settings().put({
    dispatch: { fix_rounds: 3, repos: { api: { path: "~/code/api", verify: "npm test" } } },
    notify: { quiet_start: "22:00", quiet_end: "08:00", types: { brief: false } },
  });
  assert.deepEqual(r, { ok: true, errors: [], restart_required: false });
  const text = read();
  for (const c of ["# 顶部注释：personal-agent 配置", "# 主人", "# 大脑", "# 并发上限", "# 返工轮数"]) assert.ok(text.includes(c), `丢了注释 ${c}`);
  assert.ok(text.indexOf("owner:") < text.indexOf("harnesses:") && text.indexOf("roles:") < text.indexOf("dispatch:"), "顺序变了");
  assert.match(text, /fix_rounds: 3\s+# 返工轮数/);
  const parsed = YAML.parse(text);
  assert.equal(parsed.dispatch.repos.web, "~/code/web");
  assert.deepEqual(parsed.dispatch.repos.api, { path: "~/code/api", verify: "npm test" });
  assert.equal(parsed.harnesses.codex.env.SECRET, "literal-secret-value");
  assert.equal(parsed.notify.types.brief, false);
  assert.equal(parsed.engine, undefined, "不应把未改动的默认值写进文件");
  // .bak 是旧内容；没有遗留临时文件
  assert.equal(fs.readFileSync(`${file}.bak`, "utf8"), ORIGINAL);
  assert.deepEqual(fs.readdirSync(tmp).filter((f) => f.endsWith(".tmp")), []);
  // 内存：原地修改，引用不变
  assert.equal(app.cfg.dispatch, dispatchRef);
  assert.equal(app.cfg.notify, notifyRef);
  assert.equal(dispatchRef.fix_rounds, 3);
  assert.equal(notifyRef.quiet_start, "22:00");
  assert.equal(notifyRef.types.brief, false);
  assert.deepEqual(dispatchRef.repos.api, { path: "~/code/api", verify: "npm test" });
  const a = lastAudit();
  assert.equal(a.command, "settings.update");
  assert.equal(a.source, "web");
  assert.equal(a.ok, 1);
  assert.match(a.message, /dispatch\.fix_rounds/);
  // null 删除一个键
  const del = await settings().put({ dispatch: { repos: { api: null } } });
  assert.equal(del.ok, true);
  assert.equal(YAML.parse(read()).dispatch.repos.api, undefined);
  assert.equal(app.cfg.dispatch.repos.api, undefined);
});

test("校验失败：返回点分路径和中文信息，文件和内存都不动，审计记失败", async () => {
  const before = read();
  const cases: [Record<string, unknown>, string, RegExp][] = [
    [{ dispatch: { fix_rounds: -1 } }, "dispatch.fix_rounds", /[\u4e00-\u9fa5]/],
    [{ dispatch: { timeout_sec: "很久" } }, "dispatch.timeout_sec", /[\u4e00-\u9fa5]/],
    [{ roles: { brain: "nobody" } }, "roles.brain", /未定义的 harness/],
    [{ harnesses: { bad: { agent: "x", agentCommand: "y" } } }, "harnesses.bad", /agent 或 agentCommand/],
    [{ notify: { quiet_start: "25:00", quiet_end: "08:00" } }, "notify.quiet_start", /HH:MM/],
    [{ notify: { quiet_start: "22:00", quiet_end: "" } }, "notify.quiet_end", /同时填写/],
    [{ owner: { timezone: "Mars/Base" } }, "owner.timezone", /无效的时区/],
    [{ schedules: { capture: "not a cron" } }, "schedules.capture", /cron/],
    [{ delivery: { default_provider: "gh" } }, "delivery.default_provider", /未定义的交付平台/],
    [{ foo: 1 }, "foo", /未知的配置项/],
    [{ notify: { types: { nonsense: true } } }, "notify.types.nonsense", /未知的配置项/],
  ];
  for (const [patch, p, msg] of cases) {
    const r = await settings().put(patch);
    assert.equal(r.ok, false, JSON.stringify(patch));
    const e = r.errors.find((x) => x.path === p);
    assert.ok(e, `${JSON.stringify(patch)} 应报 ${p}，实际 ${JSON.stringify(r.errors)}`);
    assert.match(e.message, msg);
    assert.equal(read(), before);
    assert.equal(lastAudit().ok, 0);
  }
  assert.equal(app.cfg.dispatch.fix_rounds, 3);
  assert.equal(app.cfg.roles.brain, "claude");
});

test("禁止修改 data_dir / bins；回传原值可以", async () => {
  const before = read();
  for (const patch of [{ data_dir: "/tmp/elsewhere" }, { bins: { lark: "/usr/bin/evil" } }]) {
    const r = await settings().put(patch);
    assert.equal(r.ok, false);
    assert.equal(r.errors[0].path, Object.keys(patch)[0]);
    assert.match(r.errors[0].message, /不能在控制台修改/);
    assert.equal(read(), before);
  }
  // 前端回传整份配置（含打码的密钥、data_dir、bins 原值）：只落真正的改动
  const whole = structuredClone(settings().get().config) as any;
  whole.capture.lookback_hours = 48;
  const r = await settings().put(whole);
  assert.deepEqual(r.errors, []);
  assert.equal(r.ok, true);
  const parsed = YAML.parse(read());
  assert.equal(parsed.harnesses.codex.env.SECRET, "literal-secret-value", "打码占位符不能覆盖密钥");
  assert.equal(parsed.capture.lookback_hours, 48);
  assert.equal(parsed.engine, undefined);
  assert.equal(app.cfg.capture.lookback_hours, 48);
});

test("需要重启的改动：不改内存，restart_required；改回去后清除", async () => {
  const r = await settings().put({ schedules: { capture: "*/30 * * * *" }, dispatch: { max_parallel: 5, fix_rounds: 2 } });
  assert.equal(r.ok, true);
  assert.equal(r.restart_required, true);
  assert.equal(app.cfg.schedules.capture, "*/15 * * * *");
  assert.equal(app.cfg.dispatch.max_parallel, 2);
  assert.equal(app.cfg.dispatch.fix_rounds, 2, "同组里可热加载的字段照样生效");
  const v = settings().get();
  assert.equal(v.restart_required, true);
  assert.equal((v.config as any).schedules.capture, "*/30 * * * *");
  assert.match(lastAudit().message, /需要重启常驻进程生效：.*schedules\.capture/);
  const back = await settings().put({ schedules: { capture: "*/15 * * * *" }, dispatch: { max_parallel: 2 } });
  assert.equal(back.restart_required, false);
  assert.equal(settings().get().restart_required, false);

  // 3 层冷配置（context.personal_web.enabled）不得原地改写内存，同组热配置（debounce_ms）照常热生效
  const r3 = await settings().put({ context: { personal_web: { enabled: true, debounce_ms: 4000 } } });
  assert.equal(r3.ok, true);
  assert.equal(r3.restart_required, true);
  assert.equal(app.cfg.context.personal_web.enabled, false, "3 层冷配置未重启前不能修改内存");
  assert.equal(app.cfg.context.personal_web.debounce_ms, 4000, "同对象下热配置字段应立即生效");
  const back3 = await settings().put({ context: { personal_web: { enabled: false, debounce_ms: 2500 } } });
  assert.equal(back3.restart_required, false);
});

test("并发保存按顺序串行执行，互不覆盖", async () => {
  const rs = await Promise.all([settings().put({ capture: { lookback_hours: 10 } }), settings().put({ budget: { daily_usd: 5 } })]);
  assert.ok(rs.every((r) => r.ok));
  const parsed = YAML.parse(read());
  assert.equal(parsed.capture.lookback_hours, 10);
  assert.equal(parsed.budget.daily_usd, 5);
  assert.equal(app.cfg.budget.daily_usd, 5);
});

test("配置文件被手工改坏：读取退回内存配置，保存报错且不覆盖", async () => {
  const good = read();
  fs.writeFileSync(file, "roles: [unclosed\n");
  try {
    const v = settings().get();
    assert.equal((v.config as any).roles.brain, "claude");
    const r = await settings().put({ budget: { daily_usd: 1 } });
    assert.equal(r.ok, false);
    assert.match(r.errors[0].message, /语法错误/);
    assert.equal(read(), "roles: [unclosed\n");
  } finally {
    fs.writeFileSync(file, good);
  }
});
