/**
 * 飞书交互卡片：模板（按钮随状态、危险操作二次确认、表单字段）、回调解析与执行（只认主人、表单合并、幂等、
 * 失败私信）、去抖合并、失败告警不循环；以及用桩跑通“一次派单只有一张卡片、随状态原地更新”。
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { createApp, initApp, sendBrief, type App } from "../src/app.ts";
import { parseAction } from "../src/cards/actions.ts";
import { CardService, failureWorthy, registerCards } from "../src/cards/index.ts";
import {
  briefCard,
  candidateCard,
  dispatchCard,
  doFormCard,
  failureCard,
  stageLine,
  type CandidateCardView,
  type DispatchCardView,
  type FailureCardView,
  type RenderCtx,
} from "../src/cards/templates.ts";
import { CommandError } from "../src/commands.ts";
import { loadConfig } from "../src/config.ts";
import type { Ctx } from "../src/engine.ts";
import type { Effect, WorkItem } from "../src/ledger.ts";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "pa-cards-"));
const STUB_STATE = path.join(tmp, "stub-state.json");
process.env.STUB_STATE = STUB_STATE;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const ctxStub = {} as Ctx;

type J = Record<string, unknown>;
/** 递归找出满足条件的节点 */
function findAll(node: unknown, pred: (n: J) => boolean, out: J[] = []): J[] {
  if (Array.isArray(node)) node.forEach((n) => findAll(n, pred, out));
  else if (node && typeof node === "object") {
    if (pred(node as J)) out.push(node as J);
    Object.values(node).forEach((v) => findAll(v, pred, out));
  }
  return out;
}
const callbackValue = (b: J) => (b.behaviors as { type: string; value?: J }[] | undefined)?.find((x) => x.type === "callback")?.value;
const cmdButtons = (c: unknown) => findAll(c, (n) => n.tag === "button" && !!callbackValue(n) && !n.form_action_type);
const cmds = (c: unknown) => cmdButtons(c).map((b) => callbackValue(b)!.cmd);
const buttonFor = (c: unknown, cmd: string) => findAll(c, (n) => n.tag === "button" && callbackValue(n)?.cmd === cmd)[0];
const forms = (c: unknown) => findAll(c, (n) => n.tag === "form");
const text = (c: unknown) => JSON.stringify(c);

const ctx: RenderCtx = { harnesses: ["claude", "codex"], consoleBase: "http://127.0.0.1:7878", timezone: "Asia/Shanghai" };

function dview(o: Partial<DispatchCardView> = {}): DispatchCardView {
  return {
    id: "dispatch:g1:1",
    guid: "g1",
    taskUrl: "https://applink.feishu.cn/client/todo/detail?guid=g1",
    summary: "修登录页",
    state: "executing",
    terminal: false,
    reason: "",
    error: "",
    harness: "codex",
    reviewer: "claude",
    round: 1,
    maxRounds: 2,
    attempts: 1,
    cancelRequested: false,
    elapsedMs: 125_000,
    costUsd: 0.1234,
    dispatchNo: 1,
    checks: [],
    checksRound: 0,
    branch: "pa/g1",
    delivery: "none",
    deliveryUrl: "",
    deliveryError: "",
    actions: [],
    ...o,
  };
}

// ───────── 模板 ─────────

test("派单卡片：进行中只有取消（带确认）和控制台链接；阶段条、轮次、费用", () => {
  const c = dispatchCard(dview({ actions: ["dispatch.cancel"] }), ctx);
  assert.equal(c.schema, "2.0");
  assert.equal((c.header as J).template, "blue");
  assert.deepEqual(cmds(c), ["dispatch.cancel"]);
  assert.ok(buttonFor(c, "dispatch.cancel").confirm, "取消要二次确认");
  assert.deepEqual(callbackValue(buttonFor(c, "dispatch.cancel")), { cmd: "dispatch.cancel", args: { id: "dispatch:g1:1" }, card: "dispatch:g1" });
  const link = findAll(c, (n) => n.tag === "button" && (n.behaviors as { type: string }[])[0].type === "open_url").map((b) => (b.behaviors as J[])[0].default_url);
  assert.ok(link.includes("http://127.0.0.1:7878/dispatches/dispatch%3Ag1%3A1"), JSON.stringify(link));
  assert.equal(forms(c).length, 0);
  assert.match(text(c), /✅ 准备  →  🔄 执行  →  ⚪ 验收/);
  assert.match(text(c), /1\/2/);
  assert.match(text(c), /\$0\.12/);
  assert.match(text(c), /2 分 5 秒/);
});

test("派单卡片：通过验收后给出交付操作；合并/放弃带确认；返工表单与换执行者下拉", () => {
  const c = dispatchCard(
    dview({
      state: "accepted",
      terminal: true,
      reason: "passed",
      checks: [{ kind: "review", name: "claude 审查", status: "pass", detail: "没有发现问题" }],
      checksRound: 1,
      actions: ["dispatch.retry", "dispatch.rework", "dispatch.switch_harness", "delivery.create_pr", "delivery.merge_local", "delivery.discard"],
    }),
    ctx,
  );
  assert.equal((c.header as J).template, "green");
  assert.deepEqual(cmds(c), ["delivery.create_pr", "delivery.merge_local", "dispatch.retry", "delivery.discard"]);
  assert.equal(buttonFor(c, "delivery.create_pr").type, "primary_filled", "一主多次");
  assert.ok(buttonFor(c, "delivery.merge_local").confirm, "合并要确认");
  assert.ok(buttonFor(c, "delivery.discard").confirm, "放弃要确认");
  assert.equal(buttonFor(c, "delivery.discard").type, "danger");
  assert.ok(!buttonFor(c, "dispatch.retry").confirm);
  const [rework, sw] = forms(c);
  const input = findAll(rework, (n) => n.tag === "input")[0];
  assert.equal(input.name, "feedback");
  assert.equal(input.required, true);
  const submit = findAll(rework, (n) => n.form_action_type === "submit")[0];
  assert.equal(submit.name, "btn_rework");
  assert.deepEqual(callbackValue(submit), { cmd: "dispatch.rework", args: { id: "dispatch:g1:1" }, card: "dispatch:g1" });
  const sel = findAll(sw, (n) => n.tag === "select_static")[0];
  assert.equal(sel.name, "harness");
  assert.deepEqual((sel.options as { value: string }[]).map((o) => o.value), ["claude"], "不列当前执行者");
  assert.match(text(c), /校验全部通过/);
  assert.match(text(c), /✅ 准备  →  ✅ 执行  →  ✅ 验收/);
});

test("派单卡片：需介入 / 出错 / 取消的颜色与阶段；交付状态与 PR 链接；没有可执行命令时没有操作按钮", () => {
  const nh = dispatchCard(dview({ state: "needs_human", terminal: true, reason: "rejected", checks: [{ kind: "command", name: "校验命令", status: "fail", detail: "退出码 1" }], checksRound: 2 }), ctx);
  assert.equal((nh.header as J).template, "orange");
  assert.match(text(nh), /返工轮次用完/);
  assert.match(text(nh), /审查与校验详情/);
  assert.deepEqual(cmds(nh), []);
  const er = dispatchCard(dview({ state: "errored", terminal: true, reason: "errored", error: "codex 执行失败（exit 1）", checks: [] }), ctx);
  assert.equal((er.header as J).template, "red");
  assert.match(text(er), /最后的错误/);
  assert.equal(stageLine({ state: "errored", terminal: true, harness: "codex", checks: [] }), "✅ 准备  →  ❌ 执行  →  ⚪ 验收");
  assert.equal(stageLine({ state: "cancelled", terminal: true, harness: "", checks: [] }), "⏹️ 准备  →  ⚪ 执行  →  ⚪ 验收");
  const pr = dispatchCard(dview({ state: "accepted", terminal: true, reason: "passed", delivery: "pr_open", deliveryUrl: "https://github.com/x/y/pull/1", actions: ["delivery.discard"] }), ctx);
  assert.match(text(pr), /\[🔗 PR 已创建\]\(https:\/\/github.com\/x\/y\/pull\/1\)/);
  const noConsole = dispatchCard(dview(), { ...ctx, consoleBase: "" });
  assert.ok(!text(noConsole).includes("在控制台查看"), "没启用控制台时不给链接");
});

function cview(o: Partial<CandidateCardView> = {}): CandidateCardView {
  return {
    signalId: "msg:om_1",
    taskGuid: "t1",
    taskUrl: "https://applink.feishu.cn/client/todo/detail?guid=t1",
    summary: "评审 Q4 预算方案",
    section: "pending",
    source: "群聊@我",
    text: "@主人 周五前帮忙评审一下 Q4 预算方案",
    link: "https://feishu.cn/x",
    confidence: 0.82,
    reason: "明确请求你在周五前评审",
    dueMs: Date.UTC(2026, 10, 21, 10),
    feedback: "",
    canConfirm: true,
    canReject: true,
    canDispatch: true,
    defaultHarness: "claude",
    repos: ["web"],
    ...o,
  };
}

test("候选任务卡片：是任务 / 不是任务 / 派给 Agent（执行者与仓库下拉）；反馈后收起按钮；命令未注册不显示", () => {
  const c = candidateCard(cview(), ctx);
  assert.deepEqual(cmds(c), ["candidate.confirm", "candidate.reject"]);
  assert.equal(buttonFor(c, "candidate.reject").type, "danger");
  assert.match(text(c), /82%/);
  assert.match(text(c), /明确请求你在周五前评审/);
  assert.match(text(c), /查看原文/);
  const [f] = forms(c);
  const sels = findAll(f, (n) => n.tag === "select_static");
  assert.deepEqual(sels.map((s) => s.name), ["harness", "repo"]);
  assert.equal(sels[0].initial_option, "claude");
  assert.deepEqual(callbackValue(findAll(f, (n) => n.form_action_type === "submit")[0]), { cmd: "candidate.dispatch", args: { signal_id: "msg:om_1" }, card: "candidate:msg:om_1" });

  const confirmed = candidateCard(cview({ feedback: "confirmed" }), ctx);
  assert.deepEqual(cmds(confirmed), ["candidate.reject"]);
  assert.equal((confirmed.header as J).template, "green");
  const rejected = candidateCard(cview({ feedback: "rejected" }), ctx);
  assert.deepEqual(cmds(rejected), []);
  assert.equal(forms(rejected).length, 0);
  const none = candidateCard(cview({ canConfirm: false, canReject: false, canDispatch: false }), ctx);
  assert.deepEqual(cmds(none), []);
  assert.equal(forms(none).length, 0);
  const inbox = candidateCard(cview({ section: "inbox" }), ctx);
  assert.ok(!cmds(inbox).includes("candidate.confirm"), "已进 Inbox 的不需要再确认");
  const evil = candidateCard(cview({ link: "javascript:alert(1)", text: "<at id=all></at> [x](y)" }), ctx);
  assert.ok(!text(evil).includes("javascript:"), "只放 http(s) 链接");
  assert.ok(!text(evil).includes("<at"), "用户文本不能注入标签");
});

function fview(o: Partial<FailureCardView> = {}): FailureCardView {
  return {
    id: "event:drive.notice.comment_add_v1:ev9",
    kind: "event",
    state: "dead",
    terminal: true,
    acknowledged: false,
    title: "飞书事件处理失败",
    detail: "文档评论",
    impact: "这条事件还没有被处理",
    error: "lark-cli 超时",
    attempts: 8,
    updated: Date.now(),
    canRetry: true,
    canAcknowledge: true,
    ...o,
  };
}

test("失败告警卡片：重试 / 忽略；忽略后、重新排队后、恢复后不再给按钮", () => {
  const c = failureCard(fview(), ctx);
  assert.equal((c.header as J).template, "red");
  assert.deepEqual(cmds(c), ["work.retry", "work.acknowledge"]);
  assert.match(text(c), /lark-cli 超时/);
  assert.equal(callbackValue(buttonFor(c, "work.retry"))!.card, "failure:event:drive.notice.comment_add_v1:ev9");
  assert.deepEqual(cmds(failureCard(fview({ acknowledged: true }), ctx)), []);
  const queued = failureCard(fview({ state: "pending", terminal: false }), ctx);
  assert.deepEqual(cmds(queued), []);
  assert.match(text(queued), /已重新排队/);
  assert.equal((failureCard(fview({ state: "done" }), ctx).header as J).template, "green");
});

test("晨报卡片：按分区成块，保留计数和链接，带打开控制台按钮", () => {
  const md = [
    "☀️ **早上好，今日概览**",
    "**⚠️ 已逾期（1）**",
    "- [已经逾期的事](https://x/over)（11/20 09:00）",
    "**❓ 待你确认（agent 识别出的候选任务，拖到 Inbox 即确认）（2）**",
    "- 评审预算",
    "- 整理清单",
    "**🤖 过去 24 小时**：识别信号 3 条",
  ].join("\n");
  const c = briefCard("morning", md, ctx, "2026-11-23");
  assert.equal((c.header as J).template, "wathet");
  assert.match(text(c), /早上好，今日概览/);
  const blocks = findAll(c, (n) => n.tag === "markdown").map((n) => n.content as string);
  assert.equal(blocks.length, 3);
  assert.match(blocks[0], /已逾期（1）[\s\S]*\(https:\/\/x\/over\)/);
  assert.match(blocks[1], /（2）\*\*\n- 评审预算\n- 整理清单/);
  const btn = findAll(c, (n) => n.tag === "button")[0];
  assert.equal((btn.behaviors as J[])[0].default_url, "http://127.0.0.1:7878/");
});

test("/do 表单卡片：描述、执行者、仓库字段；提交后显示结果", () => {
  const c = doFormCard({ key: "do:om_9", harnesses: ["claude", "codex"], defaultHarness: "claude", repos: ["web", "api"] }, ctx);
  const [f] = forms(c);
  assert.deepEqual(findAll(f, (n) => n.tag === "input" || n.tag === "select_static").map((n) => n.name), ["summary", "description", "harness", "repo"]);
  assert.equal(findAll(f, (n) => n.name === "summary")[0].required, true);
  assert.deepEqual(callbackValue(findAll(f, (n) => n.form_action_type === "submit")[0]), { cmd: "dispatch.create", args: {}, card: "do:om_9" });
  const prefilled = doFormCard({ key: "do:om_9", harnesses: ["claude", "codex"], defaultHarness: "claude", repos: [], values: { summary: "修 bug", harness: "codex" } }, ctx);
  assert.equal(findAll(prefilled, (n) => n.name === "summary")[0].default_value, "修 bug");
  assert.equal(findAll(prefilled, (n) => n.name === "harness")[0].initial_option, "codex");
  const done = doFormCard({ key: "do:om_9", harnesses: [], defaultHarness: "", repos: [], submitted: { summary: "修 bug", message: "已创建派单", dispatchId: "dispatch:g:1" } }, ctx);
  assert.equal(forms(done).length, 0);
  assert.match(text(done), /dispatches\/dispatch%3Ag%3A1/);
});

test("卡片控制台链接携带签名票据：自动经 /login?ticket=...&next=... 跳转", () => {
  const tctx: RenderCtx = { ...ctx, consoleTicket: "1893456000000.sig_abc" };
  const openUrls = (c: unknown) =>
    findAll(c, (n) => n.tag === "button" && (n.behaviors as { type: string }[])[0]?.type === "open_url").map((b) => (b.behaviors as J[])[0].default_url as string);

  const d = openUrls(dispatchCard(dview(), tctx));
  assert.ok(d.includes("http://127.0.0.1:7878/login?ticket=1893456000000.sig_abc&next=%2Fdispatches%2Fdispatch%253Ag1%253A1"), JSON.stringify(d));
  const f = openUrls(failureCard(fview(), tctx));
  assert.ok(f.includes("http://127.0.0.1:7878/login?ticket=1893456000000.sig_abc&next=%2Fhealth"), JSON.stringify(f));
  const b = openUrls(briefCard("morning", "**早报**\n**今日**\n- 1", tctx, "2026-11-23"));
  assert.ok(b.includes("http://127.0.0.1:7878/login?ticket=1893456000000.sig_abc"), JSON.stringify(b));
  const df = openUrls(doFormCard({ key: "do:om_9", harnesses: [], defaultHarness: "", repos: [], submitted: { summary: "修 bug", message: "已创建派单", dispatchId: "dispatch:g:1" } }, tctx));
  assert.ok(df.includes("http://127.0.0.1:7878/login?ticket=1893456000000.sig_abc&next=%2Fdispatches%2Fdispatch%253Ag%253A1"), JSON.stringify(df));
});

// ───────── 回调解析 ─────────

test("parseAction：只认主人；回调值与表单合并（操作对象不能被表单覆盖）；独立下拉；兜底识别表单提交；坏输入", () => {
  const value = JSON.stringify({ cmd: "dispatch.rework", args: { id: "dispatch:g1:1" }, card: "dispatch:g1" });
  const base = { event_id: "e1", operator_id: "ou_owner", action_tag: "button", action_value: value, message_id: "om_c" };
  assert.deepEqual(parseAction({ ...base, operator_id: "ou_x" }, "ou_owner"), { ok: false, reason: "操作者不是主人", actor: "ou_x" });
  assert.equal(parseAction(base, "").ok, false, "没有主人 open_id 时一律不认");
  const r = parseAction({ ...base, form_value: JSON.stringify({ feedback: "补测试", id: "dispatch:other", empty: "  ", "bad key": "x" }) }, "ou_owner");
  assert.ok(r.ok);
  assert.equal(r.cmd, "dispatch.rework");
  assert.deepEqual(r.args, { feedback: "补测试", id: "dispatch:g1:1" });
  assert.equal(r.card, "dispatch:g1");
  assert.equal(r.eventKey, "e1");
  const opt = parseAction({ ...base, action_tag: "select_static", option: "claude", action_value: { cmd: "dispatch.switch_harness", args: { id: "d" }, option_arg: "harness" } }, "ou_owner");
  assert.ok(opt.ok);
  assert.deepEqual(opt.args, { harness: "claude", id: "d" });
  const inferred = parseAction({ event_id: "e2", operator_id: "ou_owner", action_name: "btn_rework", form_value: { feedback: "x" }, message_id: "om_c" }, "ou_owner");
  assert.ok(inferred.ok && inferred.inferred && inferred.cmd === "dispatch.rework");
  assert.equal(parseAction({ ...base, action_value: "{not json" }, "ou_owner").ok, false);
  assert.equal(parseAction({ ...base, action_value: JSON.stringify({ cmd: "rm -rf /" }) }, "ou_owner").ok, false);
  const raw = parseAction({ header: { event_id: "e3" }, event: { operator: { open_id: "ou_owner" }, action: { value: { cmd: "work.retry", args: { id: "w" } }, tag: "button" }, context: { open_message_id: "om_r" } } }, "ou_owner");
  assert.ok(raw.ok && raw.cmd === "work.retry" && raw.eventKey === "e3" && raw.messageId === "om_r", "兼容原始回调结构");
  const noId = parseAction({ ...base, event_id: "", token: "" }, "ou_owner");
  assert.ok(noId.ok && noId.eventKey.length === 32, "没有 event_id/token 用内容哈希去重");
});

// ───────── 卡片服务（真实账本，不发飞书） ─────────

let app: App;
let svc: CardService;

function writeConfig(dir: string, extra: J = {}): string {
  const file = path.join(dir, "config.yaml");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    file,
    JSON.stringify({
      data_dir: path.join(dir, "data"),
      bins: { lark: path.join(ROOT, "test/stubs/lark-cli"), acpx: path.join(ROOT, "test/stubs/acpx") },
      harnesses: { claude: { agent: "claude" }, codex: { agent: "codex" } },
      roles: { brain: "claude", reviewer: "codex" },
      owner: { open_id: "ou_owner" },
      dispatch: { repos: { demo: dir } },
      engine: { retry_base_ms: 50, retry_max_ms: 200 },
      cards: { enabled: false },
      ...extra,
    }),
  );
  return file;
}

const calls: { name: string; args: unknown; source: string; actor: string }[] = [];

before(() => {
  app = createApp(loadConfig(writeConfig(path.join(tmp, "svc"))));
  assert.equal(app.ext.cards, undefined, "cards.enabled=false 时不注册");
  app.cfg.cards.enabled = true;
  svc = registerCards(app, { debounceMs: 40 })!;
  // 其他模块的命令：用假实现
  app.commands.register({
    name: "candidate.confirm",
    title: "确认候选",
    schema: z.object({ signal_id: z.string() }),
    target: (a) => a.signal_id,
    run: async (a, c) => (calls.push({ name: "candidate.confirm", args: a, source: c.source, actor: c.actor }), { ok: true, message: "已确认" }),
  });
  app.commands.register({
    name: "candidate.reject",
    title: "驳回候选",
    schema: z.object({ signal_id: z.string(), reason: z.string().optional() }),
    target: (a) => a.signal_id,
    run: async () => {
      throw new CommandError("conflict", "这条候选已经处理过了");
    },
  });
  app.commands.register({
    name: "candidate.dispatch",
    title: "派给 Agent",
    schema: z.object({ signal_id: z.string(), harness: z.string().optional(), repo: z.string().optional() }),
    target: (a) => a.signal_id,
    run: async (a, c) => (calls.push({ name: "candidate.dispatch", args: a, source: c.source, actor: c.actor }), { ok: true, message: "已派单" }),
  });
});
after(() => {
  svc?.stop();
  app?.store.db.close();
  e2e?.svc.stop();
  e2e?.app.store.db.close();
  fs.rmSync(tmp, { recursive: true, force: true });
});

const cardFx = (a: App, key: string) => a.ledger.list<Effect>({ kinds: ["effect"], ref: `card:${key}`, limit: 100 }).reverse();
const lastCard = (a: App, key: string) => {
  const e = cardFx(a, key).at(-1)?.payload;
  return e?.op === "card.upsert" ? e.args : undefined;
};

function seedSignal(id: string, guid: string): void {
  app.store.addSignal({ id, source: "群聊@我", text: "@主人 周五前帮忙评审一下 Q4 预算方案", link: "https://feishu.cn/x" });
  app.store.setVerdict(id, "task(0.8)", guid);
  // 跳过取任务详情（建卡缓存已存在）
  app.store.set(`cards.candidate.${id}`, JSON.stringify({ taskGuid: guid, summary: "评审 Q4 预算", section: "pending", reason: "明确请求", dueMs: null, feedback: "" }));
}

const ev = (o: J): J => ({ operator_id: "ou_owner", action_tag: "button", message_id: "om_x", ...o });

test("onAction：非主人忽略；主人执行命令（来源 card、操作者 open_id），并原地刷新卡片显示结果", async () => {
  seedSignal("sig:a", "t_a");
  app.bus.emit("candidate.created", { signalId: "sig:a", taskGuid: "t_a", summary: "评审 Q4 预算", section: "pending" });
  await sleep(10);
  const first = lastCard(app, "candidate:sig:a");
  assert.ok(first, "候选任务建卡");
  assert.equal(first.kind, "candidate");
  const value = callbackValue(buttonFor(first.card, "candidate.confirm"))!;

  await app.ext.cards!.onAction(ev({ event_id: "x1", operator_id: "ou_stranger", action_value: JSON.stringify(value) }), ctxStub);
  assert.equal(calls.length, 0, "陌生人点按钮不执行");

  const before = cardFx(app, "candidate:sig:a").length;
  await app.ext.cards!.onAction(ev({ event_id: "a1", action_value: JSON.stringify(value) }), ctxStub);
  assert.deepEqual(calls.at(-1), { name: "candidate.confirm", args: { signal_id: "sig:a" }, source: "card", actor: "ou_owner" });
  assert.equal(cardFx(app, "candidate:sig:a").length, before + 1, "操作后立即刷新");
  const after1 = lastCard(app, "candidate:sig:a")!;
  assert.match(text(after1.card), /✅ 是任务：已确认/);
  assert.ok(!cmds(after1.card).includes("candidate.confirm"), "确认后不再显示“是任务”");
  assert.equal(app.ledger.auditLog(1)[0].source, "card");
});

test("onAction：同一事件重复投递只执行一次命令；表单字段合并进参数", async () => {
  seedSignal("sig:b", "t_b");
  const value = { cmd: "candidate.dispatch", args: { signal_id: "sig:b" }, card: "candidate:sig:b" };
  const e = ev({ event_id: "b1", action_value: JSON.stringify(value), form_value: JSON.stringify({ harness: "codex", repo: "demo" }) });
  const n = calls.length;
  await app.ext.cards!.onAction(e, ctxStub);
  await app.ext.cards!.onAction(e, ctxStub);
  assert.equal(calls.length, n + 1, "幂等");
  assert.deepEqual(calls.at(-1)!.args, { signal_id: "sig:b", harness: "codex", repo: "demo" });
  assert.match(text(lastCard(app, "candidate:sig:b")!.card), /已派给 Agent/);
});

test("onAction：命令失败 → 私信原因（failure 类型）且卡片底部提示；未知命令同样处理", async () => {
  seedSignal("sig:c", "t_c");
  await app.ext.cards!.onAction(ev({ event_id: "c1", action_value: JSON.stringify({ cmd: "candidate.reject", args: { signal_id: "sig:c" }, card: "candidate:sig:c" }) }), ctxStub);
  const fx = app.ledger.list<Effect>({ kinds: ["effect"], ref: "card:action-errors", limit: 10 });
  const n = fx.find((f) => f.payload.op === "notify" && f.payload.args.markdown.includes("这条候选已经处理过了"));
  assert.ok(n, JSON.stringify(fx.map((f) => f.payload)));
  assert.equal(n.payload.op === "notify" && n.payload.args.kind, "failure");
  assert.match(text(lastCard(app, "candidate:sig:c")!.card), /⚠️ 不是任务：这条候选已经处理过了/);
  // 重复投递不重复私信
  await app.ext.cards!.onAction(ev({ event_id: "c1", action_value: JSON.stringify({ cmd: "candidate.reject", args: { signal_id: "sig:c" }, card: "candidate:sig:c" }) }), ctxStub);
  assert.equal(app.ledger.list({ kinds: ["effect"], ref: "card:action-errors", limit: 10 }).length, fx.length);
  // 命令未注册（对应模块未启用）同样私信提示
  const defs = (app.commands as unknown as { defs: Map<string, unknown> }).defs;
  const saved = defs.get("delivery.create_pr");
  defs.delete("delivery.create_pr");
  try {
    await app.ext.cards!.onAction(ev({ event_id: "c2", action_value: JSON.stringify({ cmd: "delivery.create_pr", args: { id: "nope" } }) }), ctxStub);
    assert.ok(app.ledger.list<Effect>({ kinds: ["effect"], ref: "card:action-errors", limit: 10 }).some((f) => f.payload.op === "notify" && /未知的命令/.test(f.payload.args.markdown)));
  } finally {
    if (saved) defs.set("delivery.create_pr", saved);
  }
});

/** 放一项派单到账本里（不经飞书）。 */
function seedDispatch(a: App, guid: string, state: string, payload: J = {}): string {
  const id = `dispatch:${guid}:${Math.random().toString(36).slice(2)}`;
  a.ledger.enqueue({ id, kind: "dispatch", ref: guid, state, payload: { guid, summary: `[codex] 任务 ${guid}`, description: "", harness: "codex", round: 1, maxRounds: 2, history: [], ...payload } });
  return id;
}

/** 以引擎的方式推进派单状态（领取 → 迁移）。 */
function advance<P>(a: App, id: string, patch: { state: string; terminal?: boolean; outcome?: string; reason?: string; payload?: P }): WorkItem<P> {
  a.ledger.db.prepare("UPDATE work SET lease_owner = ?, lease_until = ? WHERE id = ?").run(a.ledger.owner, Date.now() + 60_000, id);
  return a.ledger.transition(a.ledger.get<P>(id)!, patch);
}

test("去抖：进行中的多次变化合并成一次更新；终态立即渲染（result）", async () => {
  const id = seedDispatch(app, "g_deb", "queued");
  advance(app, id, { state: "executing" });
  advance(app, id, { state: "verifying" });
  assert.equal(cardFx(app, "dispatch:g_deb").length, 0, "窗口内还没渲染");
  await sleep(120);
  const fx = cardFx(app, "dispatch:g_deb");
  assert.equal(fx.length, 1, "三次变化合并成一次");
  assert.equal(lastCard(app, "dispatch:g_deb")!.kind, "progress");
  assert.match(text(lastCard(app, "dispatch:g_deb")!.card), /验收中/);
  advance(app, id, { state: "accepted", terminal: true, outcome: "accepted", reason: "passed" });
  assert.equal(cardFx(app, "dispatch:g_deb").length, 2, "终态不等去抖");
  assert.equal(lastCard(app, "dispatch:g_deb")!.kind, "result");
  await sleep(100);
  assert.equal(cardFx(app, "dispatch:g_deb").length, 2, "没有多余的更新");
});

test("交付变化刷新对应的派单卡片", async () => {
  const id = seedDispatch(app, "g_del", "accepted", { branch: "pa/g_del" });
  app.ledger.db.prepare("UPDATE work SET terminal = 1, outcome = state WHERE id = ?").run(id);
  const n = cardFx(app, "dispatch:g_del").length;
  app.ledger.enqueue({ id: `delivery:${id}:1`, kind: "delivery", ref: id, payload: { action: "create_pr", dispatch_id: id } });
  await sleep(100);
  assert.equal(cardFx(app, "dispatch:g_del").length, n + 1);
  assert.match(text(lastCard(app, "dispatch:g_del")!.card), /正在交付/);
});

test("失败告警：事件重试耗尽 → 告警卡片；卡片和私信自身的投递失败不告警（防循环）；重试后更新同一张卡片", async () => {
  // 事件落定为 dead
  const eid = "event:drive.notice.comment_add_v1:ev_dead";
  app.ledger.enqueue({ id: eid, kind: "event", ref: "drive.notice.comment_add_v1", payload: {} });
  app.ledger.db.prepare("UPDATE work SET error = 'lark-cli 超时', attempts = 8 WHERE id = ?").run(eid);
  advance(app, eid, { state: "dead", terminal: true });
  const c = lastCard(app, `failure:${eid}`);
  assert.ok(c, "发出告警卡片");
  assert.equal(c.kind, "failure");
  assert.match(text(c.card), /文档评论/);
  assert.deepEqual(cmds(c.card), ["work.retry", "work.acknowledge"]);

  // 点“重试” → 命令层 revive → 卡片显示已重新排队
  await app.ext.cards!.onAction(ev({ event_id: "f1", action_value: JSON.stringify(callbackValue(buttonFor(c.card, "work.retry"))) }), ctxStub);
  assert.equal(app.ledger.get(eid)!.state, "pending");
  assert.match(text(lastCard(app, `failure:${eid}`)!.card), /已重新排队/);

  // 卡片 / 私信 effect 自身失败：不告警
  for (const op of ["card.upsert", "notify", "task.move"] as const) {
    const fid = `fx:test-${op}`;
    const payload: Effect = op === "card.upsert" ? { op, args: { key: "k", card: {} } } : op === "notify" ? { op, args: { markdown: "m" } } : { op, args: { guid: "g", section: "review" } };
    app.ledger.db
      .prepare("INSERT INTO work (id, kind, ref, state, terminal, payload, created, updated) VALUES (?, 'effect', 'p', 'dead', 1, ?, ?, ?)")
      .run(fid, JSON.stringify(payload), Date.now(), Date.now());
    app.bus.emit("work.changed", { id: fid, kind: "effect", ref: "p", state: "dead", terminal: true });
    assert.equal(!!lastCard(app, `failure:${fid}`), op === "task.move", op);
    assert.equal(failureWorthy(app.ledger.get(fid)!), op === "task.move");
  }
  // 派单出错不发失败卡（派单卡片本身会显示）
  const did = seedDispatch(app, "g_err", "executing");
  advance(app, did, { state: "errored", terminal: true, outcome: "errored", reason: "errored" });
  assert.equal(lastCard(app, `failure:${did}`), undefined);
});

test("早晚报：启用卡片时以卡片发送（brief:<日期>-<mode>），同一天只发一次", async () => {
  const a = createApp(loadConfig(writeConfig(path.join(tmp, "brief"), { cards: { enabled: true } })));
  try {
    await initApp(a);
    await sendBrief(a, "evening");
    await sendBrief(a, "evening");
    const date = new Date().toISOString().slice(0, 10);
    const fx = cardFx(a, `brief:${date}-evening`);
    assert.equal(fx.length, 1);
    const p = fx[0].payload;
    assert.ok(p.op === "card.upsert" && p.args.kind === "brief" && p.args.key === `brief:${date}-evening`);
    assert.match(text(p.args.card), /今日收尾/);
  } finally {
    a.store.db.close();
  }
});

test("/do 不带参数：发派单表单卡片；提交后创建派单并把表单换成结果", async () => {
  const reply = await app.bot.handle("/do", { messageId: "om_do1", attempt: 1 } as Ctx & { messageId: string });
  assert.match(reply, /已发送派单表单/);
  const form = lastCard(app, "do:om_do1");
  assert.ok(form);
  assert.equal(forms(form.card).length, 1);
  // 提交（board.createTask 走桩会失败：没有初始化看板）→ 私信原因、表单保留已填内容
  await app.ext.cards!.onAction(
    ev({ event_id: "d1", action_name: "btn_do", action_value: JSON.stringify({ cmd: "dispatch.create", args: {}, card: "do:om_do1" }), form_value: JSON.stringify({ summary: "修 bug", harness: "codex" }) }),
    ctxStub,
  );
  const again = lastCard(app, "do:om_do1")!;
  assert.equal(forms(again.card).length, 1, "失败时保留表单");
  assert.equal(findAll(again.card, (n) => n.name === "summary")[0].default_value, "修 bug");
  assert.match(text(again.card), /⚠️ 新建派单/);
});

// ───────── 端到端：桩 + 引擎投递 ─────────

let e2e: { app: App; svc: CardService } | undefined;

test("端到端：一次派单只有一张卡片，随状态原地更新；卡片上点“重试”后同一张卡片继续跟随新派单", async () => {
  const dir = path.join(tmp, "e2e");
  const a = createApp(loadConfig(writeConfig(dir)));
  a.cfg.cards.enabled = true;
  const s = registerCards(a, { debounceMs: 30 })!;
  e2e = { app: a, svc: s };
  await initApp(a);
  const st = JSON.parse(fs.readFileSync(STUB_STATE, "utf8"));
  st.tasks.g_e2e = { guid: "g_e2e", summary: "[codex] 修登录页", description: "", section: "sec_派给Agent", comments: [] };
  fs.writeFileSync(STUB_STATE, JSON.stringify(st));
  const cards = () => (JSON.parse(fs.readFileSync(STUB_STATE, "utf8")).messages as J[]).filter((m) => m.msg_type === "interactive");
  const step = async () => {
    await sleep(80);
    await a.engine.drain(["effect"]);
  };

  const id = `dispatch:g_e2e:1`;
  a.ledger.enqueue({ id, kind: "dispatch", ref: "g_e2e", state: "queued", payload: { guid: "g_e2e", summary: "[codex] 修登录页", description: "" } });
  await step();
  assert.equal(cards().length, 1);
  assert.equal(cards()[0].to, "ou_owner");
  assert.equal(cards()[0].as, "bot");
  assert.match(text(cards()[0].card), /排队中/);

  const p = { guid: "g_e2e", summary: "[codex] 修登录页", description: "", harness: "codex", reviewer: "claude", round: 1, maxRounds: 2, history: [] as J[], branch: "pa/g_e2e" };
  advance(a, id, { state: "executing", payload: p });
  await step();
  advance(a, id, { state: "verifying", payload: p });
  await step();
  assert.equal(cards().length, 1, "没有刷屏");
  assert.match(text(cards()[0].card), /验收中/);
  const history = [{ round: 1, checks: [{ kind: "review", name: "claude 审查", status: "pass", detail: "没有发现问题" }] }];
  advance(a, id, { state: "accepted", terminal: true, outcome: "accepted", reason: "passed", payload: { ...p, history } });
  await a.engine.drain(["effect"]);
  const done = cards();
  assert.equal(done.length, 1);
  assert.ok((done[0].patches as number) >= 3, `原地更新了 ${done[0].patches} 次`);
  assert.match(text(done[0].card), /已通过验收/);
  assert.deepEqual(cmds(done[0].card), ["delivery.merge_local", "dispatch.retry", "delivery.discard"], "未配置 PR 平台时不显示创建 PR，显示本地合并/重试/放弃");

  // 点卡片上的“重试”
  const retry = callbackValue(buttonFor(done[0].card, "dispatch.retry"))!;
  await a.ext.cards!.onAction(ev({ event_id: "r1", action_value: JSON.stringify(retry), message_id: done[0].message_id }), ctxStub);
  await step();
  const latest = a.ledger.latest("dispatch", "g_e2e")!;
  assert.notEqual(latest.id, id, "新开了一次派单");
  assert.equal(cards().length, 1, "仍然是同一张卡片");
  assert.match(text(cards()[0].card), /排队中/);
  assert.match(text(cards()[0].card), /第 2 次派单/);
  assert.deepEqual(cmds(cards()[0].card), ["dispatch.cancel"]);

  // 表单提交没带回调值时：按提交按钮 name + message_id 反查卡片兜底
  advance(a, latest.id, { state: "needs_human", terminal: true, outcome: "needs_human", reason: "rejected" });
  await a.engine.drain(["effect"]);
  await a.ext.cards!.onAction(ev({ event_id: "r2", action_name: "btn_rework", form_value: JSON.stringify({ feedback: "补上单元测试" }), message_id: cards()[0].message_id }), ctxStub);
  const third = a.ledger.latest<{ initial_feedback: string }>("dispatch", "g_e2e")!;
  assert.notEqual(third.id, latest.id);
  assert.equal(third.payload.initial_feedback, "补上单元测试");
  await step();
  assert.equal(cards().length, 1);
});

test("默认配置下模块自动注册（cards.enabled 默认开启）", () => {
  const dir = path.join(tmp, "default");
  const file = writeConfig(dir);
  const cfg = JSON.parse(fs.readFileSync(file, "utf8"));
  delete cfg.cards;
  fs.writeFileSync(file, JSON.stringify(cfg));
  const a = createApp(loadConfig(file));
  assert.ok(a.ext.cards?.onAction);
  assert.ok(a.ext.cards?.brief);
  assert.ok(a.bot.doForm);
  a.store.db.close();
});
