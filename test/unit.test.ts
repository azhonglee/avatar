import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { createApp, initApp } from "../src/app.ts";
import { KnowledgeBase } from "../src/board.ts";
import { loadConfig } from "../src/config.ts";
import { decide } from "../src/guard.ts";
import { extractOwnerOpenId, Lark, LarkError } from "../src/lark.ts";
import { Store } from "../src/store.ts";
import { endOfLocalDay } from "../src/workflows/brief.ts";
import { parseHarness, parseRepo, parseReview, decideRound, planReconcile, type CheckResult, pickReviewer } from "../src/workflows/dispatch.ts";
import { parseVerdicts } from "../src/workflows/triage.ts";
import { deepFind, findItems, isoWithOffset, render } from "../src/util.ts";

const OWNER = "ou_owner";
const allow = (argv: string[], p: "none" | "readonly" | "agent" = "agent") => decide(argv, p, OWNER).allow;

test("守卫：读操作放行，危险/越权操作拒绝", () => {
  assert.equal(allow(["task", "+get-my-tasks", "--as", "user"]), true);
  assert.equal(allow(["im", "+messages-search", "--query", "x"]), true);
  assert.equal(allow(["task", "tasks", "get", "--params", "{}"]), true);
  assert.equal(allow(["task", "+tasklist-search", "--query", "x"]), true);
  assert.equal(allow(["skills", "read", "lark-task"], "none"), true);
  assert.equal(allow(["task", "+create", "--help"], "none"), true);

  assert.equal(allow(["task", "+get-my-tasks"], "none"), false);
  assert.equal(allow(["task", "+create", "--summary", "x"], "readonly"), false);
  assert.equal(allow(["auth", "login"]), false);
  assert.equal(allow(["wiki", "+node-delete", "--node-token", "x"]), false);
  assert.equal(allow(["drive", "+delete", "--file-token", "x"]), false);
  assert.equal(allow(["docs", "+history-revert"]), false);
  assert.equal(allow(["im", "+chat-create", "--name", "x"]), false);
  assert.equal(allow(["drive", "+add-comment", "--url", "x"]), false);
  assert.equal(allow(["task", "sections", "create", "--data", "{}"]), false);
});

test("守卫：写操作白名单与消息/指派限制", () => {
  assert.equal(allow(["docs", "+create", "--title", "x"]), true);
  assert.equal(allow(["task", "+create", "--summary", "x", "--assignee", OWNER]), true);
  assert.equal(allow(["task", "+create", "--summary", "x", "--assignee", "ou_other"]), false);
  assert.equal(allow(["im", "+messages-send", "--as", "bot", "--user-id", OWNER, "--text", "hi"]), true);
  assert.equal(allow(["im", "+messages-send", "--as", "bot", "--user-id=ou_other", "--text", "hi"]), false);
  assert.equal(allow(["im", "+messages-send", "--as", "user", "--user-id", OWNER, "--text", "hi"]), false);
  assert.equal(allow(["im", "+messages-send", "--as", "bot", "--chat-id", "oc_x", "--text", "hi"]), false);
  assert.equal(allow(["im", "+messages-send", "--chat-id", "oc_x", "--dry-run"]), true);
});

test("分诊：从带说明文字和代码块的回复里解析 JSON", () => {
  const v = parseVerdicts('结果：\n```json\n[{"signal_id":"msg:1","is_task":true,"summary":"评审预算","due":null,"confidence":0.8,"reason":"明确请求"}]\n```');
  assert.equal(v.length, 1);
  assert.equal(v[0].summary, "评审预算");
  assert.throws(() => parseVerdicts("没有 JSON"));
  assert.throws(() => parseVerdicts('[{"signal_id":1}]'));
});

test("派单：解析 harness、仓库和审查结论", () => {
  const t = (summary: string, description = "") => ({ guid: "g", summary, description, dueMs: null, url: "" });
  const known = ["claude", "codex", "dsh"];
  assert.equal(parseHarness(t("[codex] 修 bug"), known), "codex");
  assert.equal(parseHarness(t("修 bug", "harness: dsh"), known), "dsh");
  assert.equal(parseHarness(t("[unknown] 修 bug"), known), undefined);
  assert.equal(parseRepo(t("x", "背景\nrepo: web\n")), "web");
  assert.equal(parseRepo(t("x", "没有仓库")), undefined);
  assert.equal(pickReviewer({ brain: "claude", reviewer: "codex" }, "claude"), "codex");
  assert.equal(pickReviewer({ brain: "claude", reviewer: "codex" }, "codex"), "claude");
  assert.equal(pickReviewer({ brain: "codex", reviewer: "codex" }, "codex"), "");
  assert.equal(pickReviewer({ brain: "claude", reviewer: "" }, "codex"), "");
});

test("工具函数", () => {
  assert.match(isoWithOffset(new Date()), /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d[+-]\d\d:\d\d$/);
  assert.equal(render("a{{x}}b{{y}}", { x: "1" }), "a1b");
  assert.equal(deepFind({ a: { b: [{ guid: "g1" }] } }, "guid"), "g1");
  assert.deepEqual(findItems({ data: { items: [{ guid: 1 }, { guid: 2 }] } }, "guid").length, 2);
  // 2026-11-19 10:00 北京时间 → 当天 23:59:59.999 北京时间
  const ms = Date.parse("2026-11-19T10:00:00+08:00");
  assert.equal(endOfLocalDay(ms, "Asia/Shanghai"), Date.parse("2026-11-19T23:59:59.999+08:00"));
});

test("审查结论：结构化 JSON 优先，兼容格式只认最后一行，解析不了是故障而不是打回", () => {
  const json = parseReview('看完了。\n```json\n{"verdict":"Changes","summary":"有 bug","issues":[{"severity":"high","location":"a.ts:3","problem":"空指针"}]}\n```');
  assert.equal(json?.verdict, "changes");
  assert.equal(json?.issues[0].location, "a.ts:3");
  assert.equal(parseReview('{"verdict":"approve","summary":"ok"}')?.verdict, "approve");
  // 多个 JSON 块：以最后一个为准
  assert.equal(parseReview('```json\n{"verdict":"approve"}\n```\n更正：\n```json\n{"verdict":"changes"}\n```')?.verdict, "changes");
  assert.equal(parseReview("很好\nVERDICT: APPROVE")?.verdict, "approve");
  assert.equal(parseReview("有问题\nVERDICT: CHANGES")?.verdict, "changes");
  // 正文里提到 APPROVE 字样，但最后一行是 CHANGES：不能误判为通过
  assert.equal(parseReview("如果修好了我会给 VERDICT: APPROVE\n但现在：\nVERDICT: CHANGES")?.verdict, "changes");
  assert.equal(parseReview("如果修好了我会给 VERDICT: APPROVE，现在还不行"), undefined);
  assert.equal(parseReview("忘了写结论"), undefined);
  assert.equal(parseReview('{"verdict":"maybe"}'), undefined);
});

test("验收关卡：故障≠打回，返工耗尽进人工，无校验按策略", () => {
  const c = (status: CheckResult["status"]): CheckResult => ({ kind: "review", name: "r", status, detail: "" });
  assert.deepEqual(decideRound(1, 2, [c("pass")], "needs_human"), { next: "accept", reason: "passed" });
  assert.deepEqual(decideRound(1, 2, [c("fail")], "needs_human"), { next: "rework", reason: "checks_failed" });
  assert.deepEqual(decideRound(2, 2, [c("fail")], "needs_human"), { next: "needs_human", reason: "rejected" });
  assert.deepEqual(decideRound(1, 2, [c("error")], "needs_human"), { next: "needs_human", reason: "verifier_error" });
  assert.deepEqual(decideRound(1, 2, [c("pass"), c("error")], "needs_human"), { next: "needs_human", reason: "verifier_error" });
  assert.deepEqual(decideRound(1, 1, [], "needs_human"), { next: "needs_human", reason: "unverified" });
  assert.deepEqual(decideRound(1, 1, [], "review"), { next: "unverified", reason: "unverified" });
});

test("对账计划：新卡片入队；再派与取消只给出候选，飞书没跟上时不误判", () => {
  const latest = new Map([
    ["running_ok", { id: "w1", terminal: false, pendingEffects: 0 }],
    ["moved_away", { id: "w2", terminal: false, pendingEffects: 0 }],
    ["redo", { id: "w3", terminal: true, pendingEffects: 0 }],
    ["finishing", { id: "w4", terminal: true, pendingEffects: 2 }],
    ["queued_not_moved_yet", { id: "w5", terminal: false, pendingEffects: 1 }],
  ]);
  const plan = planReconcile({
    cards: [
      { guid: "new", section: "dispatch" },
      { guid: "running_ok", section: "running" },
      { guid: "redo", section: "dispatch" },
      { guid: "finishing", section: "dispatch" },
      { guid: "queued_not_moved_yet", section: "dispatch" },
    ],
    latest,
  });
  assert.deepEqual(plan.enqueue, ["new"], "从没派过的新卡片直接入队");
  assert.deepEqual(plan.redo, ["redo"], "再派要先按 ID 核实");
  assert.deepEqual(plan.suspects, ["w2"], "两列都没看到只是候选，要按 ID 核实才取消");
});

test("lark authStatus 与 initApp：兼容新版裸 JSON（openId）和旧版信封格式，失败时报错", async () => {
  assert.equal(
    extractOwnerOpenId({ identities: { bot: { openId: "ou_bot" }, user: { openId: "ou_user_1", userName: "张三" } } }),
    "ou_user_1",
  );
  assert.equal(extractOwnerOpenId({ identity: "user", user: { open_id: "ou_old" } }), "ou_old");
  assert.equal(extractOwnerOpenId({ user_open_id: "ou_legacy" }), "ou_legacy");

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "pa-auth-"));
  try {
    const outFile = path.join(tmp, "out.json");
    const codeFile = path.join(tmp, "code.txt");
    const fakeLark = path.join(tmp, "fake-lark");
    fs.writeFileSync(
      fakeLark,
      `#!/usr/bin/env node\nconst fs = require("node:fs");\nprocess.stdout.write(fs.readFileSync(${JSON.stringify(outFile)}, "utf8"));\nprocess.exit(Number(fs.readFileSync(${JSON.stringify(codeFile)}, "utf8")));\n`,
      { mode: 0o755 },
    );
    const cfgFile = path.join(tmp, "config.yaml");
    fs.writeFileSync(
      cfgFile,
      JSON.stringify({
        data_dir: path.join(tmp, "data"),
        bins: { lark: fakeLark },
        harnesses: { cx: { type: "codex-exec", cmd: "codex" } },
        roles: { brain: "cx" },
        cards: { enabled: false },
        context: { enabled: false },
      }),
    );

    // 1. 新版 lark-cli：裸 JSON，无 ok/data 信封，字段为 identities.user.openId
    fs.writeFileSync(
      outFile,
      JSON.stringify({
        appId: "cli_test",
        identities: {
          bot: { status: "ready", available: true, message: "Bot identity: ready" },
          user: { status: "ready", available: true, openId: "ou_bare_123", userName: "李迎忠" },
        },
        identity: "user",
      }),
    );
    fs.writeFileSync(codeFile, "0");
    const app = createApp(loadConfig(cfgFile));
    app.board.init = async () => undefined;
    app.kb.init = async () => undefined;
    await initApp(app);
    assert.equal(app.cfg.owner.open_id, "ou_bare_123");
    assert.equal(app.store.get("owner.open_id"), "ou_bare_123");
    app.store.db.close();

    // 2. 旧版信封格式
    const lark = new Lark(loadConfig(cfgFile));
    fs.writeFileSync(outFile, JSON.stringify({ ok: true, data: { identity: "user", user: { open_id: "ou_env_456" } } }));
    assert.equal(extractOwnerOpenId(await lark.authStatus()), "ou_env_456");

    // 3. 失败返回（ok: false 或退出码非 0）
    fs.writeFileSync(outFile, JSON.stringify({ ok: false, error: { message: "未登录" } }));
    await assert.rejects(() => lark.authStatus(), /未登录/);
    fs.writeFileSync(outFile, JSON.stringify({ message: "token invalid" }));
    fs.writeFileSync(codeFile, "1");
    await assert.rejects(() => lark.authStatus(), /token invalid/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("KnowledgeBase.init：建空间无权限自动回退到我的文档库（建根节点并幂等）；支持 space_id 与 enabled=false", async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "pa-kb-"));
  const makeCfg = (kb: Record<string, unknown> = {}) => {
    const f = path.join(tmp, `cfg-${Math.random().toString(36).slice(2)}.yaml`);
    fs.writeFileSync(
      f,
      JSON.stringify({
        data_dir: path.join(tmp, `data-${Math.random().toString(36).slice(2)}`),
        harnesses: { cx: { type: "codex-exec", cmd: "codex" } },
        roles: { brain: "cx" },
        kb: { space_name: "个人知识库", nodes: ["00 Inbox", "项目"], ...kb },
      }),
    );
    return loadConfig(f);
  };
  try {
    // 1. +space-create 无权限 → 回退到 my_library，建根节点和子节点，二次运行幂等
    const cfg1 = makeCfg();
    const store1 = new Store(cfg1.dataDir);
    const calls1: string[][] = [];
    const createdNodes: { space: string; parent: string; title: string; token: string }[] = [];
    const fakeLark1 = {
      async run(args: string[]) {
        calls1.push(args);
        const cmd = `${args[0]} ${args[1]}`;
        const flag = (k: string) => (args.includes(k) ? args[args.indexOf(k) + 1] : "");
        if (cmd === "wiki +space-list") return { spaces: [] };
        if (cmd === "wiki +space-create") throw new LarkError("lark-cli wiki +space-create 失败：user lacks permission for the requested resource", 1);
        if (cmd === "wiki spaces") return { space: { space_id: "7319320097204846595", space_type: "my_library" } };
        if (cmd === "wiki +node-list") {
          const sp = flag("--space-id");
          const parent = flag("--parent-node-token");
          return { nodes: createdNodes.filter((n) => n.space === sp && n.parent === parent).map((n) => ({ node_token: n.token, title: n.title })) };
        }
        if (cmd === "wiki +node-create") {
          const title = flag("--title");
          const token = `nd_${createdNodes.length + 1}_${title}`;
          createdNodes.push({ space: flag("--space-id"), parent: flag("--parent-node-token"), title, token });
          return { node: { node_token: token, title } };
        }
        throw new Error(`unexpected: ${args.join(" ")}`);
      },
    } as unknown as Lark;

    const kb1 = new KnowledgeBase(cfg1, fakeLark1, store1);
    await kb1.init();
    assert.equal(store1.get("kb.space"), "7319320097204846595");
    assert.equal(store1.get("kb.space_mode"), "my_library");
    const root = store1.get("kb.root")!;
    assert.ok(root.startsWith("nd_1_个人知识库"));
    assert.equal(createdNodes.length, 3);
    assert.equal(createdNodes[1].parent, root);
    assert.equal(createdNodes[2].parent, root);
    assert.ok(calls1[0].includes("--page-all"), "+space-list 带 --page-all");

    const before = calls1.length;
    await kb1.init();
    assert.equal(createdNodes.length, 3, "幂等：不重复建根节点和子节点");
    assert.equal(calls1.slice(before).length, 1, "只做一次 +node-list 检查");
    store1.db.close();

    // 2. kb.space_id = "sp_custom"：直接用指定空间，不建额外根节点
    const cfg2 = makeCfg({ space_id: "sp_custom" });
    const store2 = new Store(cfg2.dataDir);
    const calls2: string[][] = [];
    const fakeLark2 = {
      async run(args: string[]) {
        calls2.push(args);
        if (args[1] === "+node-list") return { nodes: [] };
        if (args[1] === "+node-create") return { node: { node_token: `t_${args[args.indexOf("--title") + 1]}` } };
        throw new Error(`unexpected: ${args.join(" ")}`);
      },
    } as unknown as Lark;
    await new KnowledgeBase(cfg2, fakeLark2, store2).init();
    assert.equal(store2.get("kb.space"), "sp_custom");
    assert.equal(store2.get("kb.root"), "");
    assert.ok(calls2.every((c) => !c.includes("--parent-node-token")));
    store2.db.close();

    // 3. kb.enabled = false：跳过不调飞书
    const cfg3 = makeCfg({ enabled: false });
    const store3 = new Store(cfg3.dataDir);
    await new KnowledgeBase(cfg3, { async run() { throw new Error("should not call"); } } as unknown as Lark, store3).init();
    assert.equal(store3.get("kb.space"), undefined);
    store3.db.close();

    // 4. 非权限类错误（如网络故障）仍抛出，不静默回退
    const cfg4 = makeCfg();
    const store4 = new Store(cfg4.dataDir);
    const fakeLark4 = {
      async run(args: string[]) {
        if (args[1] === "+space-list") return { spaces: [] };
        throw new LarkError("lark-cli wiki +space-create 失败：network timeout", 1);
      },
    } as unknown as Lark;
    await assert.rejects(() => new KnowledgeBase(cfg4, fakeLark4, store4).init(), /network timeout/);
    store4.db.close();
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
