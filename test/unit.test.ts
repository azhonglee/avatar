import assert from "node:assert/strict";
import { test } from "node:test";
import { decide } from "../src/guard.ts";
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

test("对账计划：派单列的新卡片入队，进行中的卡片被拖走则取消，飞书没跟上时不误判", () => {
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
  assert.deepEqual(plan.enqueue.sort(), ["new", "redo"]);
  assert.deepEqual(plan.cancel, ["w2"]);
});
