import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test, type TestContext } from "node:test";
import { Board } from "../src/board.ts";
import { loadConfig } from "../src/config.ts";
import { Lark } from "../src/lark.ts";
import { Store } from "../src/store.ts";
import { isoWithOffset } from "../src/util.ts";
import { Capture } from "../src/workflows/capture.ts";

const CURSOR = "capture.cursor";
const START = "2026-11-19T00:00:00.000Z";
const empty = { messages: [], has_more: false, page_token: "" };
const msg = (id: string) => ({ message_id: id, content: "test", chat_id: "oc_test" });
const page = (ids: string[], next?: string) => ({ messages: ids.map(msg), has_more: next !== undefined, page_token: next ?? "" });

function setup(t: TestContext, run: Lark["run"]) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pa-capture-"));
  const file = path.join(dir, "config.yaml");
  fs.writeFileSync(file, JSON.stringify({ data_dir: dir, harnesses: { stub: { agent: "stub" } }, roles: { brain: "stub" }, owner: { open_id: "ou_owner" } }));
  const cfg = loadConfig(file);
  const store = new Store(dir);
  t.after(() => {
    store.db.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });
  store.set(CURSOR, START);
  const lark = new Lark(cfg);
  lark.run = run;
  return { store, capture: new Capture(cfg, lark, store, new Board(cfg, lark, store)) };
}

function flag(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  return i === -1 ? undefined : args[i + 1];
}

test("capture：两个筛选独立续页、固定时间范围、重叠消息只入库一次", async (t) => {
  const bounds: (string | undefined)[][] = [];
  const visited: string[] = [];
  const { capture, store } = setup(t, async (args, opts) => {
    assert.equal(opts?.as, "user");
    assert.ok(!args.includes("--page-all"));
    bounds.push([flag(args, "--start"), flag(args, "--end")]);
    const token = flag(args, "--page-token");
    if (args.includes("--is-at-me")) {
      visited.push("mention:" + (token ?? ""));
      if (!token) return page(["om_shared"], "mention-next");
      assert.equal(token, "mention-next");
      return { ...page(["om_mention"]), page_token: "mention-next" }; // 终页以 has_more 为准
    }
    assert.equal(flag(args, "--chat-type"), "p2p");
    assert.equal(flag(args, "--exclude-sender-type"), "bot");
    visited.push("p2p:" + (token ?? ""));
    if (!token) return page([], "p2p-next"); // 空页也可以有下一页
    assert.equal(token, "p2p-next");
    return page(["om_shared", "om_direct"]);
  });
  assert.equal(await capture.pollMessages(), 3);
  assert.deepEqual(visited.sort(), ["mention:", "mention:mention-next", "p2p:", "p2p:p2p-next"]);
  const end = store.get(CURSOR)!;
  assert.notEqual(end, START);
  assert.deepEqual(bounds, Array.from({ length: 4 }, () => [isoWithOffset(new Date(START)), isoWithOffset(new Date(end))]));
  assert.deepEqual(store.pendingSignals().map((s) => s.id).sort(), ["msg:om_direct", "msg:om_mention", "msg:om_shared"]);
});

test("capture：续页调用失败不推进游标，重试从原起点补齐", async (t) => {
  let fail = true;
  const { capture, store } = setup(t, async (args) => {
    assert.equal(flag(args, "--start"), isoWithOffset(new Date(START)));
    if (!args.includes("--is-at-me")) return page(["om_direct"]);
    if (!flag(args, "--page-token")) return page(["om_early"], "next");
    if (fail) throw new Error("临时失败");
    return page(["om_late"]);
  });
  await assert.rejects(capture.pollMessages(), /临时失败/);
  assert.equal(store.get(CURSOR), START);
  assert.deepEqual(store.pendingSignals(), []);
  fail = false;
  assert.equal(await capture.pollMessages(), 3);
  assert.notEqual(store.get(CURSOR), START);
});

test("capture：详情退化、分页状态错误或缺失/循环 token 时不提交", async (t) => {
  const invalid = [
    ["id-only", { message_ids: ["om_hidden"], has_more: false, page_token: "" }, /仅返回 ID/],
    ["bad-status", { messages: [], has_more: "false" }, /分页状态/],
    ["bad-item", { messages: [{}], has_more: false }, /无效的消息/],
    ["missing-token", { messages: [], has_more: true }, /分页游标/],
    ["blank-token", { messages: [], has_more: true, page_token: " " }, /分页游标/],
  ] as const;
  for (const [name, response, error] of invalid) {
    await t.test(name, async (sub) => {
      const { capture, store } = setup(sub, async (args) => args.includes("--is-at-me") ? response : page(["om_direct"]));
      await assert.rejects(capture.pollMessages(), error);
      assert.equal(store.get(CURSOR), START);
      assert.deepEqual(store.pendingSignals(), []);
    });
  }
  await t.test("cyclic-token", async (sub) => {
    const { capture, store } = setup(sub, async (args) => {
      if (!args.includes("--is-at-me")) return empty;
      return page([], flag(args, "--page-token") === "a" ? "b" : "a");
    });
    await assert.rejects(capture.pollMessages(), /分页游标/);
    assert.equal(store.get(CURSOR), START);
  });
});

test("capture：有效空结果推进游标", async (t) => {
  const { capture, store } = setup(t, async () => empty);
  assert.equal(await capture.pollMessages(), 0);
  assert.notEqual(store.get(CURSOR), START);
});

test("capture：入库中断不推进游标，重试跳过已入库消息且修复仅 seen 的旧记录", async (t) => {
  const { capture, store } = setup(t, async (args) => args.includes("--is-at-me") ? page(["om_early", "om_late"]) : empty);
  store.markSeen("msg:om_late", "signal");
  store.db.exec(`CREATE TRIGGER fail_insert BEFORE INSERT ON signals
    WHEN NEW.id = 'msg:om_late' BEGIN SELECT RAISE(ABORT, 'insert failed'); END`);
  await assert.rejects(capture.pollMessages(), /insert failed/);
  assert.equal(store.get(CURSOR), START);
  assert.deepEqual(store.pendingSignals().map((s) => s.id), ["msg:om_early"]);
  store.db.exec("DROP TRIGGER fail_insert");
  assert.equal(await capture.pollMessages(), 1);
  assert.deepEqual(store.pendingSignals().map((s) => s.id), ["msg:om_early", "msg:om_late"]);
  assert.notEqual(store.get(CURSOR), START);
});
