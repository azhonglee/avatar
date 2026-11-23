/**
 * 通知偏好：免打扰时段（含跨午夜、时区）、按类型关闭、失败告警总是发送、已有卡片的原地更新不延后；
 * 以及经 outbox 发布器的集成：延后的私信退回尝试次数，时段结束后再投递。
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, mock, test } from "node:test";
import { fileURLToPath } from "node:url";
import { createApp, type App } from "../src/app.ts";
import { loadConfig, type Config } from "../src/config.ts";
import { card, notify } from "../src/effects.ts";
import { notifyGate, parseHHMM, quietUntil } from "../src/notify-prefs.ts";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const T = (iso: string) => Date.parse(iso);
const SH = "Asia/Shanghai";
const NIGHT = { quiet_start: "22:00", quiet_end: "08:00" };

test("parseHHMM", () => {
  assert.equal(parseHHMM("22:00"), 1320);
  assert.equal(parseHHMM("8:05"), 485);
  assert.equal(parseHHMM("24:00"), undefined);
  assert.equal(parseHHMM("12:60"), undefined);
  assert.equal(parseHHMM("abc"), undefined);
});

test("免打扰时段：跨午夜、边界、时段内的结束时间", () => {
  // 上海 23:00 → 延后到次日 08:00（= 00:00Z）
  assert.equal(quietUntil(T("2026-01-15T15:00:00Z"), NIGHT, SH), T("2026-01-16T00:00:00Z"));
  // 秒数不影响结束时刻
  assert.equal(quietUntil(T("2026-01-15T15:00:37.5Z"), NIGHT, SH), T("2026-01-16T00:00:00Z"));
  // 上海凌晨 04:00 → 当天 08:00
  assert.equal(quietUntil(T("2026-01-14T20:00:00Z"), NIGHT, SH), T("2026-01-15T00:00:00Z"));
  // 上海 09:30 不在时段内
  assert.equal(quietUntil(T("2026-01-15T01:30:00Z"), NIGHT, SH), undefined);
  // 边界：开始时刻算在内，结束时刻不算
  assert.equal(quietUntil(T("2026-01-15T14:00:00Z"), NIGHT, SH), T("2026-01-16T00:00:00Z"));
  assert.equal(quietUntil(T("2026-01-16T00:00:00Z"), NIGHT, SH), undefined);
  // 不跨午夜的时段：12:00–14:00，12:30 → 14:00
  assert.equal(quietUntil(T("2026-01-15T04:30:00Z"), { quiet_start: "12:00", quiet_end: "14:00" }, SH), T("2026-01-15T06:00:00Z"));
  assert.equal(quietUntil(T("2026-01-15T07:00:00Z"), { quiet_start: "12:00", quiet_end: "14:00" }, SH), undefined);
  // 留空或首尾相同 = 关闭
  assert.equal(quietUntil(T("2026-01-15T15:00:00Z"), { quiet_start: "", quiet_end: "" }, SH), undefined);
  assert.equal(quietUntil(T("2026-01-15T15:00:00Z"), { quiet_start: "22:00", quiet_end: "22:00" }, SH), undefined);
});

test("免打扰时段按 owner.timezone 计算", () => {
  const ts = T("2026-01-15T04:00:00Z"); // 纽约 23:00（UTC-5），上海 12:00
  assert.equal(quietUntil(ts, NIGHT, "America/New_York"), T("2026-01-15T13:00:00Z"));
  assert.equal(quietUntil(ts, NIGHT, SH), undefined);
});

function fakeApp(notifyCfg: Partial<Config["notify"]> = {}, kv: Record<string, string> = {}) {
  const cfg = {
    owner: { open_id: "ou_owner", timezone: SH },
    notify: { quiet_start: "", quiet_end: "", types: { candidate: true, progress: true, result: true, failure: true, brief: true }, ...notifyCfg },
  } as unknown as Config;
  return { cfg, store: { get: (k: string) => kv[k] } } as unknown as App;
}

test("门控：按类型关闭、失败总是发送、未标注类型的私信照发、已有卡片原地更新不延后、读取实时配置", () => {
  const night = T("2026-01-15T15:00:00Z");
  const end = T("2026-01-16T00:00:00Z");
  const app = fakeApp({ ...NIGHT, types: { candidate: false, progress: true, result: true, failure: false, brief: true } }, { "card.msg.dispatch:g_old": "om_1" });
  const gate = notifyGate(app, () => night);
  // 按类型关闭
  assert.equal(gate("candidate", notify("x", "candidate")), false);
  assert.equal(gate(undefined, card("candidate:s1", {})), false, "从卡片 key 推断类型");
  // 失败告警：关不掉，也不延后
  assert.equal(gate("failure", notify("x", "failure")), undefined);
  assert.equal(gate(undefined, card("failure:w1", {})), undefined);
  // 免打扰：延后到时段结束
  assert.equal(gate("result", notify("x", "result")), end);
  assert.equal(gate("progress", card("dispatch:g_new", {}, "progress")), end);
  assert.equal(gate(undefined, card("dispatch:g_new", {})), end);
  // 已经发出的卡片：原地更新不提醒，立即更新
  assert.equal(gate("progress", card("dispatch:g_old", {}, "progress")), undefined);
  // 未标注类型的私信（旧路径的告警等）照常发送
  assert.equal(gate(undefined, notify("x")), undefined);
  // 实时读取配置：关闭免打扰后立即生效
  app.cfg.notify.quiet_start = "";
  app.cfg.notify.quiet_end = "";
  assert.equal(gate("result", notify("x", "result")), undefined);
  app.cfg.notify.types.result = false;
  assert.equal(gate("result", notify("x", "result")), false);
  // 白天不受免打扰影响
  const day = notifyGate(fakeApp(NIGHT), () => T("2026-01-15T03:00:00Z"));
  assert.equal(day("result", notify("x", "result")), undefined);
});

// ───────── 集成：经 outbox 发布器 ─────────

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "pa-notify-"));
let app: App;
const stubState = () => JSON.parse(fs.readFileSync(path.join(tmp, "stub-state.json"), "utf8")) as { messages: { markdown: string }[] };

before(() => {
  process.env.STUB_STATE = path.join(tmp, "stub-state.json");
  const file = path.join(tmp, "config.yaml");
  fs.writeFileSync(
    file,
    JSON.stringify({
      data_dir: path.join(tmp, "data"),
      bins: { lark: path.join(ROOT, "test/stubs/lark-cli"), acpx: path.join(ROOT, "test/stubs/acpx") },
      harnesses: { claude: { agent: "claude" } },
      roles: { brain: "claude" },
      owner: { open_id: "ou_owner", timezone: SH },
      notify: { quiet_start: "22:00", quiet_end: "08:00", types: { brief: false } },
    }),
  );
  app = createApp(loadConfig(file));
});
after(() => {
  mock.timers.reset();
  app.store.db.close();
  fs.rmSync(tmp, { recursive: true, force: true });
});

test("集成：免打扰期间的私信延后（不计重试次数），结束后投递；失败告警立即发；关闭的类型跳过", async () => {
  const night = T("2026-01-15T15:00:00Z");
  const end = T("2026-01-16T00:00:00Z");
  mock.timers.enable({ apis: ["Date"], now: night });
  try {
    app.ledger.emit("p1", [notify("验收结果：通过", "result")]);
    app.ledger.emit("p2", [notify("作业失败了", "failure")]);
    app.ledger.emit("p3", [notify("晨报内容", "brief")]);
    app.store.set("card.msg.dispatch:g_old", "om_existing");
    app.ledger.emit("p4", [card("dispatch:g_old", { header: "进度更新" }, "progress")]);
    app.ledger.emit("p5", [card("dispatch:g_new", { header: "新卡片" }, "progress")]);
    await app.engine.drain(["effect"]);

    // 已有卡片的更新立即投递；新卡片延后
    assert.equal(app.ledger.effectsOf("p4")[0].state, "done");
    assert.equal(app.ledger.effectsOf("p5")[0].terminal, false);
    assert.equal(app.ledger.effectsOf("p5")[0].next_at, end);
    const texts = () => stubState().messages.map((m) => m.markdown);

    const [deferred] = app.ledger.effectsOf("p1");
    assert.equal(deferred.terminal, false);
    assert.equal(deferred.state, "pending");
    assert.equal(deferred.attempts, 0, "延后不计入重试次数");
    assert.equal(deferred.next_at, end);
    assert.equal(deferred.lease_owner, "");
    assert.equal(app.ledger.effectsOf("p2")[0].state, "done");
    assert.equal(app.ledger.effectsOf("p3")[0].state, "skipped");
    assert.ok(texts().includes("作业失败了"));
    assert.ok(texts().some((t) => t.includes("进度更新")));
    assert.ok(!texts().includes("验收结果：通过"));
    assert.ok(!texts().some((t) => t.includes("新卡片") || t === "晨报内容"));

    // 时段还没结束：不会被领取
    mock.timers.setTime(end - 60_000);
    await app.engine.drain(["effect"]);
    assert.equal(app.ledger.effectsOf("p1")[0].terminal, false);

    // 时段结束：投递
    mock.timers.setTime(end + 1000);
    await app.engine.drain(["effect"]);
    const done = app.ledger.effectsOf("p1")[0];
    assert.equal(done.state, "done");
    assert.equal(done.attempts, 1);
    assert.ok(texts().includes("验收结果：通过"));
    assert.ok(texts().some((t) => t.includes("新卡片")));
    assert.equal(app.ledger.effectsOf("p5")[0].state, "done");
    assert.ok(!texts().includes("晨报内容"));
  } finally {
    mock.timers.reset();
  }
});
