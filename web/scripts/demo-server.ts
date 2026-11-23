/**
 * 本地演示控制台：创建临时配置和数据目录，写入多状态的示例派单、步骤、日志、审查轮次、副作用与审计记录，
 * 启动控制台服务并打印一次性登录链接，方便前端开发或 UI 验收。
 *
 * 用法：
 *   PORT=7878 npm run demo:web
 */
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createApp, VERSION, type App } from "../../src/app.ts";
import { loadConfig } from "../../src/config.ts";
import type { Effect } from "../../src/ledger.ts";
import { serverToken, startServer } from "../../src/server/index.ts";
import type { CheckResult, DispatchPayload } from "../../src/workflows/dispatch.ts";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "pa-demo-"));

function initDemoRepo(dir: string): { base: string } {
  fs.mkdirSync(path.join(dir, "src"), { recursive: true });
  const git = (args: string[]) =>
    execFileSync("git", ["-C", dir, ...args], {
      env: { ...process.env, GIT_AUTHOR_NAME: "Avatar Demo", GIT_AUTHOR_EMAIL: "demo@example.com", GIT_COMMITTER_NAME: "Avatar Demo", GIT_COMMITTER_EMAIL: "demo@example.com" },
      stdio: "ignore",
    });
  git(["init", "-q"]);
  fs.writeFileSync(
    path.join(dir, "src", "rate-limit.ts"),
    `export interface RateLimitConfig {\n  windowMs: number;\n  maxRequests: number;\n}\n\nexport function allowRequest(_ip: string): boolean {\n  return true;\n}\n`,
  );
  git(["add", "."]);
  git(["commit", "-q", "-m", "initial commit"]);
  const base = execFileSync("git", ["-C", dir, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  git(["checkout", "-q", "-b", "pa/demo-accepted"]);
  fs.writeFileSync(
    path.join(dir, "src", "rate-limit.ts"),
    `export interface RateLimitConfig {\n  windowMs: number;\n  maxRequests: number;\n}\n\nconst buckets = new Map<string, { count: number; resetAt: number }>();\n\nexport function allowRequest(ip: string, cfg: RateLimitConfig = { windowMs: 60_000, maxRequests: 60 }, now = Date.now()): boolean {\n  const cur = buckets.get(ip);\n  if (!cur || cur.resetAt <= now) {\n    buckets.set(ip, { count: 1, resetAt: now + cfg.windowMs });\n    return true;\n  }\n  if (cur.count >= cfg.maxRequests) return false;\n  cur.count++;\n  return true;\n}\n`,
  );
  fs.writeFileSync(
    path.join(dir, "src", "rate-limit.test.ts"),
    `import assert from "node:assert/strict";\nimport { allowRequest } from "./rate-limit.ts";\n\nassert.equal(allowRequest("127.0.0.1", { windowMs: 1000, maxRequests: 1 }, 100), true);\nassert.equal(allowRequest("127.0.0.1", { windowMs: 1000, maxRequests: 1 }, 200), false);\n`,
  );
  git(["add", "."]);
  git(["commit", "-q", "-m", "feat: implement sliding window rate limiter"]);
  return { base };
}

function writeLog(app: App, name: string, content: string): string {
  const file = path.join(app.cfg.dataDir, "runs", name);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content, "utf8");
  return file;
}

function seedDispatch(
  app: App,
  o: {
    id: string;
    guid: string;
    state: string;
    terminal: boolean;
    reason?: string;
    error?: string;
    attempts?: number;
    lease?: boolean;
    ageMs: number;
    payload: Partial<DispatchPayload>;
  },
): void {
  const now = Date.now();
  const created = now - o.ageMs;
  const updated = now - Math.min(o.ageMs, 30_000);
  const full: DispatchPayload = {
    guid: o.guid,
    summary: "",
    description: "",
    harness: "codex",
    reviewer: "claude",
    verify: "npm test",
    cwd: "",
    branch: "",
    base: "",
    round: 1,
    maxRounds: 2,
    checkpoints: {},
    report: "",
    feedback: "",
    history: [],
    ...o.payload,
  };
  app.ledger.enqueue({ id: o.id, kind: "dispatch", ref: o.guid, state: o.state, payload: full });
  app.ledger.db
    .prepare("UPDATE work SET terminal = ?, outcome = ?, reason = ?, error = ?, attempts = ?, lease_owner = ?, lease_until = ?, created = ?, updated = ? WHERE id = ?")
    .run(
      o.terminal ? 1 : 0,
      o.terminal ? o.state : "",
      o.reason ?? "",
      o.error ?? "",
      o.attempts ?? 1,
      o.lease ? app.ledger.owner : "",
      o.lease ? now + 60_000 : 0,
      created,
      updated,
      o.id,
    );
}

function seedStep(
  app: App,
  o: {
    work_id: string;
    name: string;
    harness: string;
    status: "running" | "ok" | "failed" | "interrupted";
    log?: string;
    summary: string;
    durationMs: number;
    tokensIn?: number;
    tokensOut?: number;
    costUsd?: number;
    agoMs: number;
  },
): number {
  const id = app.ledger.startStep({ work_id: o.work_id, name: o.name, harness: o.harness, log: o.log ?? "" });
  const started = Date.now() - o.agoMs;
  const ended = o.status === "running" ? null : started + o.durationMs;
  app.ledger.db
    .prepare("UPDATE steps SET status = ?, summary = ?, started = ?, ended = ?, duration_ms = ?, tokens_in = ?, tokens_out = ?, cost_usd = ? WHERE id = ?")
    .run(o.status, o.summary, started, ended, o.durationMs, o.tokensIn ?? 0, o.tokensOut ?? 0, o.costUsd ?? 0, id);
  return id;
}

function seedEffect(app: App, id: string, parent: string, effect: Effect, state: "done" | "pending" | "dead", error = ""): void {
  const now = Date.now();
  const terminal = state === "pending" ? 0 : 1;
  app.ledger.db
    .prepare("INSERT INTO work (id, kind, ref, state, terminal, outcome, attempts, payload, error, created, updated) VALUES (?, 'effect', ?, ?, ?, ?, ?, ?, ?, ?, ?)")
    .run(id, parent, state, terminal, state === "done" ? "done" : "", state === "dead" ? 10 : 1, JSON.stringify(effect), error, now - 60_000, now - 15_000);
}

function seedAll(app: App, demoRepo: string, baseSha: string): void {
  const now = Date.now();
  app.store.set("daemon.heartbeat", `${app.ledger.owner}|${now}`);

  // 1. executing（进行中，带实时日志）
  const execId = "dispatch:task_exec:demo1";
  seedDispatch(app, {
    id: execId,
    guid: "task_exec",
    state: "executing",
    terminal: false,
    lease: true,
    ageMs: 4 * 60_000,
    payload: {
      summary: "[codex] 优化 SSE 重连后的增量刷新逻辑",
      description: "repo: avatar\n断线重连后避免重复触发全量请求，补上单测。",
      harness: "codex",
      reviewer: "claude",
      cwd: demoRepo,
      branch: "pa/task_exec",
      base: baseSha,
      round: 1,
      maxRounds: 2,
    },
  });
  const execLog = writeLog(
    app,
    "exec-worker-1.log",
    [
      "[10:01:02] Reading web/src/lib/events.ts and web/src/lib/query.ts...",
      "[10:01:08] Found reconnect handler in useServerEvents().",
      "[10:01:19] Running vitest on web/src/lib/events.test.tsx...",
      "[10:01:24] Editing debounce scheduling to coalesce burst invalidations...",
    ].join("\n") + "\n",
  );
  seedStep(app, {
    work_id: execId,
    name: "worker#1",
    harness: "codex",
    status: "running",
    log: execLog,
    summary: "正在修改事件去抖逻辑并补充测试",
    durationMs: 95_000,
    tokensIn: 14_200,
    tokensOut: 3_100,
    costUsd: 0.038,
    agoMs: 95_000,
  });
  seedEffect(app, "fx:demo-exec-1", execId, { op: "task.move", args: { guid: "task_exec", section: "Agent进行中" } }, "done");

  // 2. accepted（待验收，带真实 git diff、验收轮次、日志、副作用、审计）
  const accId = "dispatch:task_acc:demo2";
  const accChecks: CheckResult[] = [
    { kind: "command", name: "npm test", status: "pass", detail: "✔ rate-limit tests passed (2/2)\nDuration: 42ms" },
    {
      kind: "review",
      name: "claude",
      status: "pass",
      detail: "### 审查结论：通过\n\n- 限流窗口边界判断正确（`cur.resetAt <= now`）。\n- 补充了单元测试覆盖放行与超限场景。\n- 没有引入额外外部依赖。",
    },
  ];
  seedDispatch(app, {
    id: accId,
    guid: "task_acc",
    state: "accepted",
    terminal: true,
    reason: "校验全部通过",
    ageMs: 25 * 60_000,
    payload: {
      summary: "[codex] 给登录接口加上按 IP 限流",
      description: "repo: avatar\n默认每分钟 60 次，超出返回 429，并补充单元测试。",
      harness: "codex",
      reviewer: "claude",
      cwd: demoRepo,
      branch: "pa/demo-accepted",
      base: baseSha,
      round: 1,
      maxRounds: 2,
      report: "## 完成说明\n\n- 新增 `src/rate-limit.ts` 实现固定时间窗限流。\n- 新增 `src/rate-limit.test.ts` 验证边界条件。\n- 本地 `npm test` 全部通过。",
      history: [{ round: 1, checks: accChecks }],
    },
  });
  const accWorkerLog = writeLog(
    app,
    "acc-worker-1.log",
    "[09:35:00] Creating src/rate-limit.ts\n[09:35:40] Adding unit tests in src/rate-limit.test.ts\n[09:36:05] All tests pass.\n",
  );
  const accVerifyLog = writeLog(app, "acc-verify-1.log", "> npm test\n✔ rate-limit tests passed (2/2)\n");
  seedStep(app, {
    work_id: accId,
    name: "worker#1",
    harness: "codex",
    status: "ok",
    log: accWorkerLog,
    summary: "实现按 IP 限流并补充单元测试",
    durationMs: 65_000,
    tokensIn: 24_800,
    tokensOut: 6_400,
    costUsd: 0.089,
    agoMs: 22 * 60_000,
  });
  seedStep(app, {
    work_id: accId,
    name: "verify#1",
    harness: "",
    status: "ok",
    log: accVerifyLog,
    summary: "npm test 通过（2/2）",
    durationMs: 3_400,
    agoMs: 20 * 60_000,
  });
  seedStep(app, {
    work_id: accId,
    name: "review#1",
    harness: "claude",
    status: "ok",
    summary: "APPROVE：逻辑清晰，单测覆盖完整",
    durationMs: 28_000,
    tokensIn: 11_500,
    tokensOut: 1_800,
    costUsd: 0.052,
    agoMs: 19 * 60_000,
  });
  seedEffect(app, "fx:demo-acc-1", accId, { op: "task.comment", args: { guid: "task_acc", content: "已完成限流实现并通过校验与审查，待验收。" } }, "done");
  seedEffect(app, "fx:demo-acc-2", accId, { op: "task.move", args: { guid: "task_acc", section: "待验收" } }, "done");
  app.ledger.audit({ source: "web", actor: "owner", command: "dispatch.create", target: accId, args: { summary: "给登录接口加上按 IP 限流", repo: "avatar" }, ok: true, message: "已创建派单" });

  // 3. needs_human（需介入，两轮验收失败）
  const nhId = "dispatch:task_nh:demo3";
  seedDispatch(app, {
    id: nhId,
    guid: "task_nh",
    state: "needs_human",
    terminal: true,
    reason: "返工轮次用完，校验仍未通过",
    ageMs: 90 * 60_000,
    payload: {
      summary: "[claude] 支持 GitLab 自建实例的 MR 合并前检查",
      description: "repo: avatar\n需要兼容 GitLab 15.x 与 16.x 的 pipeline status 字段。",
      harness: "claude",
      reviewer: "codex",
      cwd: demoRepo,
      branch: "pa/task_nh",
      base: baseSha,
      round: 2,
      maxRounds: 2,
      report: "已适配 16.x 字段，但 15.x 的旧字段缺少测试样例。",
      feedback: "请不要跳过对空 pipeline 列表的校验，并补充回归测试。",
      history: [
        {
          round: 1,
          checks: [
            { kind: "command", name: "npm test", status: "fail", detail: "AssertionError: expected 'pending' to equal 'running'\n  at test/gitlab.test.ts:44:12" },
          ],
        },
        {
          round: 2,
          checks: [
            { kind: "command", name: "npm test", status: "pass", detail: "✔ all unit tests passed" },
            {
              kind: "review",
              name: "codex",
              status: "fail",
              detail: "### 需要修改\n\n1. `src/delivery/gitlab.ts:88` 当 `head_pipeline` 为 `null` 时会直接放行，建议显式判定为未通过。\n2. 缺少对应单测。",
            },
          ],
        },
      ],
    },
  });
  const nhLog = writeLog(app, "nh-worker-2.log", "[08:40:12] Fixing GitLab 15.x status mapping...\n[08:41:09] Tests green locally.\n");
  seedStep(app, {
    work_id: nhId,
    name: "worker#1",
    harness: "claude",
    status: "ok",
    summary: "第 1 轮实现 GitLab MR 检查",
    durationMs: 74_000,
    tokensIn: 31_000,
    tokensOut: 7_200,
    costUsd: 0.145,
    agoMs: 85 * 60_000,
  });
  seedStep(app, {
    work_id: nhId,
    name: "verify#1",
    harness: "",
    status: "failed",
    summary: "test/gitlab.test.ts 1 项失败",
    durationMs: 4_200,
    agoMs: 83 * 60_000,
  });
  seedStep(app, {
    work_id: nhId,
    name: "worker#2",
    harness: "claude",
    status: "ok",
    log: nhLog,
    summary: "第 2 轮修复状态映射",
    durationMs: 52_000,
    tokensIn: 28_400,
    tokensOut: 5_100,
    costUsd: 0.118,
    agoMs: 80 * 60_000,
  });
  seedStep(app, {
    work_id: nhId,
    name: "review#2",
    harness: "codex",
    status: "failed",
    summary: "CHANGES：head_pipeline 为 null 时的兜底策略需确认",
    durationMs: 31_000,
    tokensIn: 16_000,
    tokensOut: 2_300,
    costUsd: 0.044,
    agoMs: 78 * 60_000,
  });
  seedEffect(app, "fx:demo-nh-1", nhId, { op: "task.move", args: { guid: "task_nh", section: "需人工介入" } }, "done");
  app.ledger.audit({ source: "card", actor: "owner", command: "dispatch.rework", target: nhId, args: { id: nhId, feedback: "请不要跳过对空 pipeline 列表的校验" }, ok: true, message: "已带着你的意见重新派单" });

  // 4. errored（执行出错）
  const errId = "dispatch:task_err:demo4";
  seedDispatch(app, {
    id: errId,
    guid: "task_err",
    state: "errored",
    terminal: true,
    reason: "执行反复失败",
    error: "acpx exited with code 1: ECONNRESET while connecting to upstream model endpoint",
    attempts: 2,
    ageMs: 35 * 60_000,
    payload: {
      summary: "[codex] 迁移旧版事件订阅重试配置",
      description: "repo: avatar\n把旧配置字段迁移到 engine.retry_base_ms。",
      harness: "codex",
      reviewer: "claude",
      round: 1,
      maxRounds: 2,
    },
  });
  const errLog = writeLog(
    app,
    "err-worker-1.log",
    "[07:05:10] Starting codex session...\n[07:05:42] ERROR: socket hang up (ECONNRESET)\n[07:05:42] Process exited with status 1\n",
  );
  seedStep(app, {
    work_id: errId,
    name: "worker#1",
    harness: "codex",
    status: "failed",
    log: errLog,
    summary: "上游模型连接中断（ECONNRESET）",
    durationMs: 32_000,
    tokensIn: 5_200,
    tokensOut: 400,
    costUsd: 0.011,
    agoMs: 35 * 60_000,
  });
  seedEffect(
    app,
    "fx:demo-err-1",
    errId,
    { op: "task.comment", args: { guid: "task_err", content: "执行出错：ECONNRESET" } },
    "dead",
    "lark-cli failed (code 1): feishu API rate limit exceeded after 10 attempts",
  );
  app.ledger.audit({ source: "web", actor: "owner", command: "dispatch.cancel", target: errId, args: { id: errId }, ok: false, message: "派单已经结束" });

  // 5. 定时作业运行记录与守卫日志
  app.ledger.db
    .prepare("INSERT INTO work (id, kind, ref, state, terminal, outcome, attempts, payload, error, created, updated) VALUES (?, 'job', ?, 'done', 1, 'done', 1, ?, '', ?, ?)")
    .run(
      "job:kb-tidy:demo1",
      "kb-tidy",
      JSON.stringify({ name: "kb-tidy", result: "已整理 4 条 Inbox 笔记，归档 2 篇会议纪要。" }),
      now - 2 * 3600_000,
      now - 2 * 3600_000 + 45_000,
    );

  const guardLog = path.join(app.cfg.dataDir, "logs", "guard.log");
  fs.writeFileSync(
    guardLog,
    [
      JSON.stringify({ t: new Date(now - 600_000).toISOString(), profile: "read-only", allow: true, reason: "", argv: ["lark-cli", "task", "list", "--json"] }),
      JSON.stringify({ t: new Date(now - 300_000).toISOString(), profile: "read-only", allow: false, reason: "只读配置禁止发送消息", argv: ["lark-cli", "im", "send", "--to", "ou_other"] }),
    ].join("\n") + "\n",
    "utf8",
  );
}

const demoRepo = path.join(tmp, "demo-repo");
const { base: baseSha } = initDemoRepo(demoRepo);

const configFile = path.join(tmp, "config.yaml");
fs.writeFileSync(
  configFile,
  JSON.stringify(
    {
      data_dir: path.join(tmp, "data"),
      bins: {
        lark: path.join(ROOT, "test/stubs/lark-cli"),
        acpx: path.join(ROOT, "test/stubs/acpx"),
      },
      owner: { open_id: "ou_demo_owner", timezone: "Asia/Shanghai" },
      harnesses: {
        claude: { agent: "claude", model: "claude-sonnet-4" },
        codex: { agent: "codex", model: "o4-mini" },
      },
      roles: { brain: "claude", reviewer: "claude" },
      dispatch: {
        default_harness: "codex",
        max_parallel: 2,
        repos: {
          avatar: { path: demoRepo, verify: "npm test", target_branch: "main" },
        },
      },
      budget: { daily_usd: 5, per_task_usd: 1.5 },
      jobs: {
        "kb-tidy": { cron: "0 21 * * 1-5", prompt: "整理知识库 Inbox 与今日会议纪要", harness: "claude", notify: true },
      },
    },
    null,
    2,
  ),
);

const app = createApp(loadConfig(configFile));
seedAll(app, demoRepo, baseSha);

const port = Number(process.env.PORT ?? 7878);
const srv = await startServer(app, { version: `${VERSION}-demo`, port });
const token = serverToken(app);

console.log(`Avatar demo server listening on ${srv.url}`);
console.log(`Login URL: ${srv.url}/login?token=${token}`);
console.log(`Bearer token: ${token}`);

const shutdown = async () => {
  await srv.close();
  app.store.db.close();
  fs.rmSync(tmp, { recursive: true, force: true });
  process.exit(0);
};
process.once("SIGINT", () => void shutdown());
process.once("SIGTERM", () => void shutdown());
