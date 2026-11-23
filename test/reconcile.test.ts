/**
 * 对账与看板的时序：两次列表读取不是同一个快照。
 * Avatar 自己把卡片从「派给Agent」移到「Agent进行中」时，可能先读到移动前的「进行中」、再读到移动后的「派给Agent」，
 * 两列都看不到这张卡片。这种“两列都没找到”只能当作待确认信号，必须按任务 ID 核实后才能取消。
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test, type TestContext } from "node:test";
import { Board, type BoardTask, type SectionKey } from "../src/board.ts";
import { Lark } from "../src/lark.ts";
import { loadConfig } from "../src/config.ts";
import { Ledger } from "../src/ledger.ts";
import { Store } from "../src/store.ts";
import { Dispatcher } from "../src/workflows/dispatch.ts";

const GUID = "task_moving";
const SECTIONS: Record<string, string> = { dispatch: "sec_dispatch", running: "sec_running", review: "sec_review", inbox: "sec_inbox" };

/**
 * 模拟看板：where 是卡片此刻真实所在的列（null = 已不在本看板）。
 * seenBy 可以让每次列表读取看到不同时刻的快照，用来复现不一致的读。
 */
class FakeBoard {
  where: string | null = "running";
  completed = false;
  seenBy: ((key: SectionKey) => string | null) | null = null;
  getTaskError: Error | null = null;

  section(key: SectionKey): string {
    return SECTIONS[key] ?? `sec_${key}`;
  }

  async listSection(key: SectionKey): Promise<BoardTask[]> {
    const where = this.seenBy ? this.seenBy(key) : this.where;
    const card = { guid: GUID, summary: "[codex] 正在跑的任务", description: "", dueMs: null, url: "" };
    return where === key && !this.completed ? [card] : [];
  }

  async locateTask(guid: string) {
    if (this.getTaskError) throw this.getTaskError;
    assert.equal(guid, GUID);
    return { completed: this.completed, sectionGuid: this.where ? this.section(this.where as SectionKey) : null };
  }
}

function setup(t: TestContext) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pa-reconcile-"));
  const file = path.join(dir, "config.yaml");
  fs.writeFileSync(file, JSON.stringify({ data_dir: dir, harnesses: { stub: { agent: "stub" } }, roles: { brain: "stub" }, owner: { open_id: "ou_owner" } }));
  const cfg = loadConfig(file);
  const store = new Store(dir);
  const ledger = new Ledger(store.db);
  const board = new FakeBoard();
  const dispatcher = new Dispatcher(cfg, ledger, store, board as unknown as Board);
  // 一项正在执行的派单（卡片已经或正在被移到「进行中」）
  ledger.enqueue({ id: `dispatch:${GUID}:1`, kind: "dispatch", ref: GUID, state: "executing", payload: { guid: GUID } });
  t.after(() => {
    store.db.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });
  return { ledger, board, dispatcher, id: `dispatch:${GUID}:1` };
}

test("对账时序：先读到移动前的「进行中」、再读到移动后的「派给Agent」，正在跑的任务不能被取消", async (t) => {
  const { ledger, board, dispatcher, id } = setup(t);
  // Avatar 的 outbox 正在把卡片从「派给Agent」移到「Agent进行中」：
  // 「进行中」那次读拿到的是移动前的快照（还没过来），「派给Agent」那次读拿到的是移动后的快照（已经走了）
  board.where = "running"; // 移动已完成，按 ID 查到的是真实位置
  board.seenBy = (key) => (key === "running" ? "dispatch" : "running");
  const r = await dispatcher.reconcile();
  assert.equal(ledger.isCancelled(id), false, "正常移列不能被当作取消");
  assert.equal(r.cancelled, 0);
});

test("对账：两列都没找到时按任务 ID 核实——确实移出两列才取消", async (t) => {
  const { ledger, board, dispatcher, id } = setup(t);
  board.where = "inbox"; // 用户把卡片拖回 Inbox
  const r = await dispatcher.reconcile();
  assert.equal(ledger.isCancelled(id), true);
  assert.equal(r.cancelled, 1);
});

test("对账：两列都没找到时按任务 ID 核实——已完成才取消", async (t) => {
  const { ledger, board, dispatcher, id } = setup(t);
  board.completed = true;
  await dispatcher.reconcile();
  assert.equal(ledger.isCancelled(id), true);
});

test("对账：两列都没找到时按任务 ID 核实——已不在本看板才取消", async (t) => {
  const { ledger, board, dispatcher, id } = setup(t);
  board.where = null;
  await dispatcher.reconcile();
  assert.equal(ledger.isCancelled(id), true);
});

test("对账：核实时发现卡片其实在两列之一（列表读取不完整），不取消", async (t) => {
  const { ledger, board, dispatcher, id } = setup(t);
  board.where = "dispatch";
  board.seenBy = () => null; // 两次列表读取都没看到
  const r = await dispatcher.reconcile();
  assert.equal(ledger.isCancelled(id), false);
  assert.equal(r.cancelled, 0);
  assert.equal(r.deferred, 0);
});

test("对账：按任务 ID 查不清（接口失败/结构不明）时不取消，留到下次对账", async (t) => {
  const { ledger, board, dispatcher, id } = setup(t);
  board.where = "inbox";
  board.getTaskError = new Error("网络抖动");
  const r = await dispatcher.reconcile();
  assert.equal(ledger.isCancelled(id), false);
  assert.equal(r.deferred, 1);
  // 下一轮能查清了，才真正取消
  board.getTaskError = null;
  await dispatcher.reconcile();
  assert.equal(ledger.isCancelled(id), true);
});

test("对账：上一次派单已终结、列表里又看到卡片在「派给Agent」——核实确实在才再派，旧快照不再派", async (t) => {
  const { ledger, board, dispatcher, id } = setup(t);
  // 上一次派单已经结束，卡片已移到「待验收」，但这次读「派给Agent」拿到的是旧快照
  const w = ledger.claim("dispatch", 60_000)!;
  assert.equal(w.id, id);
  ledger.transition(w, { state: "accepted", terminal: true });
  board.where = "review";
  board.seenBy = (key) => (key === "dispatch" ? "dispatch" : null);
  let r = await dispatcher.reconcile();
  assert.equal(r.enqueued, 0, "旧快照不能触发再派");
  // 用户真的把卡片拖回「派给Agent」
  board.where = "dispatch";
  board.seenBy = null;
  r = await dispatcher.reconcile();
  assert.equal(r.enqueued, 1);
  assert.equal(ledger.active("dispatch").length, 1);
});

function realBoard(t: TestContext) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pa-locate-"));
  const file = path.join(dir, "config.yaml");
  fs.writeFileSync(file, JSON.stringify({ data_dir: dir, harnesses: { stub: { agent: "stub" } }, roles: { brain: "stub" } }));
  const cfg = loadConfig(file);
  const store = new Store(dir);
  t.after(() => {
    store.db.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });
  store.set("board.tasklist", "tl_board");
  const lark = new Lark(cfg);
  const board = new Board(cfg, lark, store);
  const reply = (task: unknown) => {
    lark.run = async () => ({ task });
  };
  return { cfg, store, lark, board, reply };
}

test("locateTask：按真实接口结构解析完成状态与所在分组，结构不明时抛错（由对账留到下次）", async (t) => {
  const { board, reply } = realBoard(t);
  reply({ guid: "g", completed_at: "0", tasklists: [{ tasklist_guid: "tl_board", section_guid: "sec_running" }] });
  assert.deepEqual(await board.locateTask("g"), { completed: false, sectionGuid: "sec_running" });
  reply({ guid: "g", completed_at: "1732000000000", tasklists: [] });
  assert.deepEqual(await board.locateTask("g"), { completed: true, sectionGuid: null });
  reply({ guid: "g", completed_at: "0", tasklists: [{ tasklist_guid: "tl_other", section_guid: "x" }] });
  assert.deepEqual(await board.locateTask("g"), { completed: false, sectionGuid: null }, "不在本看板");
  reply({ guid: "g", completed_at: "0" });
  await assert.rejects(board.locateTask("g"), /tasklists/, "缺少分组信息：查不清");
  reply({ guid: "g", completed_at: "0", tasklists: [{ tasklist_guid: "tl_board" }] });
  await assert.rejects(board.locateTask("g"), /分组未知/);
  reply({ guid: "other" });
  await assert.rejects(board.locateTask("g"), /结构无法识别/);
});

test("locateTask：completed_at 只认已核实的两种形式（\"0\" 与毫秒时间戳字符串），其他一律查不清", async (t) => {
  const { board, reply } = realBoard(t);
  const inList = [{ tasklist_guid: "tl_board", section_guid: "sec_running" }];
  reply({ guid: "g", completed_at: "1732000000000", tasklists: inList });
  assert.equal((await board.locateTask("g")).completed, true);
  reply({ guid: "g", completed_at: "0", tasklists: inList });
  assert.equal((await board.locateTask("g")).completed, false);
  // 非空、非 "0" 但不是毫秒时间戳的值：以前会被判为已完成，现在是查不清
  for (const v of ["null", "abc", "", " ", "123", "1732000000", "01732000000000", "-1732000000000", "1732000000000.5", null, undefined, 1732000000000, 0, true]) {
    reply({ guid: "g", completed_at: v, tasklists: inList });
    await assert.rejects(board.locateTask("g"), /完成状态无法识别/, `completed_at=${JSON.stringify(v)}`);
  }
  // status 不是已核实的来源：completed_at 说未完成就是未完成
  reply({ guid: "g", completed_at: "0", status: "done", tasklists: inList });
  assert.equal((await board.locateTask("g")).completed, false);
});

test("对账：completed_at 无法识别时不取消，留到下次对账", async (t) => {
  const { board, lark, cfg, store } = realBoard(t);
  store.set("board.section.dispatch", "sec_dispatch");
  store.set("board.section.running", "sec_running");
  let completedAt: unknown = "null";
  lark.run = async (args) => {
    if (args[1] === "sections") return { items: [], has_more: false }; // 两列都没读到
    return { task: { guid: GUID, completed_at: completedAt, tasklists: [] } };
  };
  const ledger = new Ledger(store.db);
  const dispatcher = new Dispatcher(cfg, ledger, store, board);
  const id = `dispatch:${GUID}:1`;
  ledger.enqueue({ id, kind: "dispatch", ref: GUID, state: "executing", payload: { guid: GUID } });
  let r = await dispatcher.reconcile();
  assert.equal(ledger.isCancelled(id), false, "\"null\" 不能被当作已完成");
  assert.equal(r.deferred, 1);
  completedAt = "1732000000000";
  r = await dispatcher.reconcile();
  assert.equal(ledger.isCancelled(id), true, "查清是已完成后才取消");
});
