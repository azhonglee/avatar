/**
 * 账本与引擎：租约、fencing、崩溃接管、重试/耗尽、副作用顺序、取消。
 * 用真实的 SQLite 文件和真实的子进程（模拟“已死的持有者”），不依赖飞书和模型。
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { test, type TestContext } from "node:test";
import { checkpoint, Engine, type Handler } from "../src/engine.ts";
import { isDeadOwner, LeaseLost, Ledger } from "../src/ledger.ts";

function setup(t: TestContext, opts: Partial<ConstructorParameters<typeof Engine>[1]> = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pa-ledger-"));
  const file = path.join(dir, "state.db");
  const db = new DatabaseSync(file);
  db.exec("PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;");
  const ledger = new Ledger(db);
  const engine = new Engine(ledger, { leaseMs: 60_000, tickMs: 1000, retryBaseMs: 10, retryMaxMs: 50, ...opts });
  t.after(async () => {
    await engine.stop();
    db.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });
  return { ledger, engine, db, file };
}

/** 一个已经退出的进程的 pid（用来伪造“崩溃的前任”）。 */
function deadPid(): number {
  return Number(spawnSync(process.execPath, ["-e", "process.stdout.write(String(process.pid))"], { encoding: "utf8" }).stdout);
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

test("账本：入队幂等，领取写租约并计数，transition 以持有租约为前提（fencing）", (t) => {
  const { ledger, file } = setup(t);
  assert.equal(ledger.enqueue({ id: "event:k:1", kind: "event", ref: "k" }), true);
  assert.equal(ledger.enqueue({ id: "event:k:1", kind: "event", ref: "k" }), false, "同一事件只入队一次");

  const a = ledger.claim("event", 60_000)!;
  assert.equal(a.attempts, 1);
  assert.equal(a.lease_owner, ledger.owner);
  assert.equal(ledger.claim("event", 60_000), undefined, "有效租约期内别人领不到");

  // 另一个进程（另一个 owner）在租约过期后接管
  const other = new Ledger(new DatabaseSync(file), "otherhost:1:x");
  ledger.db.prepare("UPDATE work SET lease_until = 0").run();
  const b = other.claim("event", 60_000)!;
  assert.equal(b.attempts, 2, "接管也计入尝试次数");
  // 旧持有者醒来后想写进度：被拒绝，什么都不写
  assert.throws(() => ledger.transition(a, { state: "done", terminal: true }, [{ op: "notify", args: { markdown: "x" } }]), LeaseLost);
  assert.equal(ledger.pendingEffects(a.id), 0, "被拒绝的迁移不会留下副作用");
  // 新持有者正常推进；进入新状态时 attempts 重置为 1
  const c = other.transition(b, { state: "processing" });
  assert.equal(c.attempts, 1);
  other.transition(c, { state: "done", terminal: true }, [{ op: "notify", args: { markdown: "hi" } }]);
  const done = ledger.get(a.id)!;
  assert.equal(done.terminal, true);
  assert.equal(done.lease_owner, "", "终态释放租约");
  assert.equal(ledger.pendingEffects(a.id), 1, "状态迁移和副作用意图在同一事务里提交");
  other.db.close();
});

test("账本：同一张卡片至多一项未终结的派单（数据库约束）", (t) => {
  const { ledger } = setup(t);
  assert.equal(ledger.enqueue({ id: "dispatch:g:1", kind: "dispatch", ref: "g", state: "queued" }), true);
  assert.equal(ledger.enqueue({ id: "dispatch:g:2", kind: "dispatch", ref: "g", state: "queued" }), false, "并发对账的第二次入队被忽略");
  const w = ledger.claim("dispatch", 60_000)!;
  ledger.transition(w, { state: "accepted", terminal: true });
  assert.equal(ledger.enqueue({ id: "dispatch:g:3", kind: "dispatch", ref: "g", state: "queued" }), true, "上一项终结后可以再派");
});

test("账本：确定已死的持有者立即被收回，存活的不动；同 pid 不同随机串视为前世", (t) => {
  const { ledger } = setup(t);
  const host = os.hostname();
  const dead = `${host}:${deadPid()}:aaaa`;
  const alive = `${host}:${process.ppid}:bbbb`;
  assert.equal(isDeadOwner(dead, ledger.owner), true);
  assert.equal(isDeadOwner(alive, ledger.owner), false);
  assert.equal(isDeadOwner(`${host}:${process.pid}:zzzz`, ledger.owner), true, "容器里 pid 复用：同 pid 不同随机串是上一个进程");
  assert.equal(isDeadOwner(`elsewhere:1:x`, ledger.owner), false, "别的机器只能等租约过期");
  assert.equal(isDeadOwner(ledger.owner, ledger.owner), false);

  ledger.enqueue({ id: "d1", kind: "dispatch" });
  ledger.enqueue({ id: "d2", kind: "dispatch" });
  const far = Date.now() + 3_600_000;
  ledger.db.prepare("UPDATE work SET lease_owner = ?, lease_until = ? WHERE id = 'd1'").run(dead, far);
  ledger.db.prepare("UPDATE work SET lease_owner = ?, lease_until = ? WHERE id = 'd2'").run(alive, far);
  assert.equal(ledger.reapDeadOwners(), 1);
  assert.equal(ledger.claim("dispatch", 1000)?.id, "d1");
  assert.equal(ledger.claim("dispatch", 1000), undefined);
});

test("账本：同一工作的副作用按顺序投递，前一条没落定后一条领不到", (t) => {
  const { ledger } = setup(t);
  ledger.enqueue({ id: "w", kind: "job" });
  const w = ledger.claim("job", 60_000)!;
  ledger.transition(w, { state: "x" }, [
    { op: "task.comment", args: { guid: "g", content: "1" } },
    { op: "task.move", args: { guid: "g", section: "review" } },
  ]);
  const first = ledger.claim("effect", 60_000)!;
  assert.equal((first.payload as { op: string }).op, "task.comment");
  assert.equal(ledger.claim("effect", 60_000), undefined, "移动卡片要等评论落定");
  ledger.transition(first, { state: "done", terminal: true });
  assert.equal((ledger.claim("effect", 60_000)!.payload as { op: string }).op, "task.move");
});

test("引擎：失败退避重试，耗尽后落终态并投递通知；成功则不再领取", async (t) => {
  const { ledger, engine } = setup(t);
  let calls = 0;
  const h: Handler = {
    kind: "event",
    concurrency: 1,
    maxAttempts: 3,
    async run(item) {
      calls++;
      if (item.ref === "ok" && calls >= 2) return void ledger.transition(item, { state: "done", terminal: true });
      throw new Error(`第 ${calls} 次失败`);
    },
    onExhausted: (item, err) => ({ patch: { state: "dead" }, effects: [{ op: "notify", args: { markdown: `${item.id}: ${err}` } }] }),
  };
  engine.register(h);

  ledger.enqueue({ id: "e-ok", kind: "event", ref: "ok" });
  for (let i = 0; i < 50 && !ledger.get("e-ok")!.terminal; i++) {
    await engine.drain(["event"]);
    await sleep(15);
  }
  assert.equal(ledger.get("e-ok")!.state, "done");
  assert.equal(calls, 2);

  calls = 0;
  ledger.enqueue({ id: "e-bad", kind: "event", ref: "bad" });
  for (let i = 0; i < 50 && !ledger.get("e-bad")!.terminal; i++) {
    await engine.drain(["event"]);
    await sleep(15);
  }
  const bad = ledger.get("e-bad")!;
  assert.equal(bad.state, "dead");
  assert.equal(calls, 3, "最多尝试 maxAttempts 次");
  assert.match(bad.error, /第 3 次失败/);
  assert.equal(ledger.pendingEffects("e-bad"), 1, "耗尽时的通知也走 outbox");
});

test("引擎：崩溃中断计入尝试次数——至多一次的工作被接管时不重跑，而是落终态", async (t) => {
  const { ledger, engine } = setup(t);
  let ran = 0;
  engine.register({
    kind: "job",
    concurrency: 1,
    maxAttempts: 1,
    async run(item) {
      ran++;
      ledger.transition(item, { state: "done", terminal: true });
    },
    onExhausted: () => ({ patch: { state: "errored" } }),
  });
  ledger.enqueue({ id: "j", kind: "job" });
  // 前任领取后崩溃：attempts=1，租约属于一个已死的进程
  ledger.db.prepare("UPDATE work SET attempts = 1, lease_owner = ?, lease_until = ? WHERE id = 'j'").run(`${os.hostname()}:${deadPid()}:dead`, Date.now() + 3_600_000);
  await engine.drain(["job"]);
  assert.equal(ran, 0, "没有重跑");
  assert.equal(ledger.get("j")!.state, "errored");
});

test("引擎：优雅退出中止执行、不计入尝试次数；取消在下一次领取时由 handler 收尾", async (t) => {
  const { ledger, engine } = setup(t, { leaseMs: 400 });
  let started = 0;
  engine.register({
    kind: "dispatch",
    concurrency: 2,
    maxAttempts: 2,
    async run(item, ctx) {
      if (ledger.isCancelled(item.id)) return void ledger.transition(item, { state: "cancelled", terminal: true });
      started++;
      await new Promise<void>((resolve) => ctx.signal.addEventListener("abort", () => resolve(), { once: true }));
      checkpoint(ctx);
    },
    onExhausted: () => ({ patch: { state: "errored" } }),
  });
  ledger.enqueue({ id: "keep", kind: "dispatch" });
  ledger.enqueue({ id: "drop", kind: "dispatch" });
  engine.start();
  for (let i = 0; i < 50 && started < 2; i++) await sleep(20);
  assert.equal(started, 2);

  // 取消：心跳发现后中止本地执行，随后重新领取并收尾
  ledger.requestCancel("drop");
  for (let i = 0; i < 100 && !ledger.get("drop")!.terminal; i++) await sleep(20);
  assert.equal(ledger.get("drop")!.state, "cancelled");

  // 优雅退出：租约释放、尝试次数退回
  await engine.stop();
  const keep = ledger.get("keep")!;
  assert.equal(keep.terminal, false);
  assert.equal(keep.lease_owner, "");
  assert.equal(keep.attempts, 0, "优雅退出不消耗尝试次数");
});
