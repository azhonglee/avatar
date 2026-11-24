/**
 * M0 试跑：只读采集最近 N 天的工作信号，落到本机目录（不进 git，不写飞书 / Meego）。
 *
 *   node --experimental-strip-types scripts/m0/collect.ts [--days 7] [--out ~/.personal-agent/m0]
 *
 * 来源（全部是只读命令）：
 *   - Meego：我的待办（全部 / 逾期 / 本周）、最近已办
 *   - 飞书消息：@我、私聊、我发言过的群（每群最多 200 条）
 *   - 会议：我参加的妙记（摘要 + 待办）
 *   - 日历：前后 N 天日程
 *   - 飞书任务：分配给我的、与我相关的未完成任务
 *   - 文档评论 @我：经由私聊里的云文档助手通知覆盖
 */
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { parseArgs } from "node:util";

const { values } = parseArgs({ options: { days: { type: "string", default: "7" }, out: { type: "string" }, "max-groups": { type: "string", default: "40" } } });
const DAYS = Number(values.days);
const MAX_GROUPS = Number(values["max-groups"]);
const stamp = new Date().toISOString().slice(0, 10);
const OUT = path.resolve((values.out ?? path.join(os.homedir(), ".personal-agent", "m0")).replace(/^~(?=\/)/, os.homedir()), stamp);
fs.mkdirSync(OUT, { recursive: true, mode: 0o700 });

const iso = (d: Date) => {
  const off = -d.getTimezoneOffset();
  const pad = (n: number) => String(Math.floor(Math.abs(n))).padStart(2, "0");
  return `${new Date(d.getTime() + off * 60_000).toISOString().slice(0, 19)}${off >= 0 ? "+" : "-"}${pad(off / 60)}:${pad(off % 60)}`;
};
const now = new Date();
const START = iso(new Date(now.getTime() - DAYS * 86_400_000));
const END = iso(now);
const FUTURE = iso(new Date(now.getTime() + DAYS * 86_400_000));

function run(bin: string, args: string[], timeoutMs = 120_000): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const p = spawn(bin, args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    const t = setTimeout(() => p.kill("SIGTERM"), timeoutMs);
    p.stdout.on("data", (d) => (stdout += d));
    p.stderr.on("data", (d) => (stderr += d));
    p.on("close", (code) => {
      clearTimeout(t);
      resolve({ code: code ?? -1, stdout, stderr });
    });
  });
}

function parseJson(text: string): unknown {
  const t = text.trim();
  const i = t.indexOf("{");
  return i >= 0 ? JSON.parse(t.slice(i)) : undefined;
}

/** lark-cli 只读调用（user 身份），返回信封里的 data */
async function lark(args: string[], timeoutMs?: number): Promise<any> {
  const r = await run("lark-cli", [...args, "--as", "user", "--format", "json"], timeoutMs);
  const env = parseJson(r.stdout) as { ok?: boolean; data?: unknown; error?: { message?: string } } | undefined;
  if (r.code !== 0 || env?.ok === false) throw new Error(`lark-cli ${args.slice(0, 2).join(" ")} 失败：${env?.error?.message ?? r.stderr.trim().slice(0, 300)}`);
  return env?.data ?? env;
}

/** bytedcli meego 只读调用，返回 structuredContent */
async function meego(args: string[]): Promise<any> {
  const r = await run("bytedcli", ["meego", ...args, "--json"]);
  const j = parseJson(r.stdout) as any;
  if (r.code !== 0 || !j || j.status === "error") throw new Error(`bytedcli meego ${args.slice(0, 2).join(" ")} 失败：${r.stderr.trim().slice(0, 300) || JSON.stringify(j?.error)}`);
  return j.data?.result?.structuredContent ?? j.data;
}

const report: Record<string, string> = {};
function save(name: string, data: unknown, count: number): void {
  fs.writeFileSync(path.join(OUT, `${name}.json`), JSON.stringify(data, null, 2), { mode: 0o600 });
  report[name] = `${count} 条`;
  console.log(`✔ ${name}: ${count}`);
}
async function step(name: string, fn: () => Promise<void>): Promise<void> {
  try {
    await fn();
  } catch (e) {
    report[name] = `失败：${(e as Error).message}`;
    console.log(`✖ ${name}: ${(e as Error).message}`);
  }
}

const arr = (o: any, key: string): any[] => {
  if (Array.isArray(o)) return o;
  if (o && typeof o === "object") {
    if (Array.isArray(o[key])) return o[key];
    for (const v of Object.values(o)) {
      const r = arr(v, key);
      if (r.length) return r;
    }
  }
  return [];
};

/** 统一的消息观测格式 */
function normMsg(m: any) {
  const sender = m.sender ?? {};
  return {
    id: m.message_id,
    chat_id: m.chat_id,
    chat_name: m.chat_name ?? "",
    chat_type: m.chat_type ?? "",
    sender_id: sender.id ?? sender.open_id ?? "",
    sender_name: sender.name ?? "",
    sender_type: sender.sender_type ?? sender.type ?? "",
    time: m.create_time ?? "",
    thread_id: m.thread_id ?? "",
    parent_id: m.parent_id ?? m.root_id ?? "",
    msg_type: m.msg_type ?? m.message_type ?? "",
    text: typeof m.content === "string" ? m.content : JSON.stringify(m.content ?? ""),
  };
}

async function searchMessages(extra: string[]): Promise<any[]> {
  const data = await lark(["im", "+messages-search", "--start", START, "--end", END, "--page-all", "--page-limit", "40", "--page-size", "50", "--no-reactions", ...extra], 300_000);
  return arr(data, "messages").map(normMsg);
}

// ───────── 主人身份 ─────────
const auth = parseJson((await run("lark-cli", ["auth", "status", "--json"])).stdout) as any;
const ME = auth?.identities?.user?.openId as string;
const MY_NAME = auth?.identities?.user?.userName as string | undefined;
if (!ME) throw new Error("拿不到当前用户 open_id，请先 lark-cli auth login");
console.log(`时间窗：${START} ~ ${END}（日历到 ${FUTURE}）；输出：${OUT}`);

// ───────── Meego ─────────
await step("meego_todo", async () => {
  const all: any[] = [];
  for (let page = 1; page <= 10; page++) {
    const sc = await meego(["todo", "list", "--action", "todo", "--todo-scope", "all", "--page", String(page)]);
    const list = sc?.list ?? [];
    all.push(...list);
    if (!list.length || all.length >= (sc?.total ?? 0)) break;
  }
  save("meego_todo", all, all.length);
});
for (const action of ["overdue", "this_week", "done"]) {
  await step(`meego_${action}`, async () => {
    const args = ["todo", "list", "--action", action, "--page", "1"];
    if (action !== "done") args.push("--todo-scope", "all");
    const sc = await meego(args);
    save(`meego_${action}`, sc?.list ?? [], (sc?.list ?? []).length);
  });
}

// ───────── 飞书消息 ─────────
let mine: any[] = [];
await step("im_at_me", async () => {
  const msgs = await searchMessages(["--is-at-me"]);
  save("im_at_me", msgs, msgs.length);
});
await step("im_p2p", async () => {
  const msgs = await searchMessages(["--chat-type", "p2p"]);
  save("im_p2p", msgs, msgs.length);
});
await step("im_mine", async () => {
  mine = await searchMessages(["--sender", ME]);
  save("im_mine", mine, mine.length);
});
await step("im_groups", async () => {
  const counts = new Map<string, { name: string; n: number }>();
  for (const m of mine) {
    if (m.chat_type !== "group" && m.chat_type !== "topic_group") continue;
    const c = counts.get(m.chat_id) ?? { name: m.chat_name, n: 0 };
    c.n++;
    counts.set(m.chat_id, c);
  }
  const groups = [...counts.entries()].sort((a, b) => b[1].n - a[1].n).slice(0, MAX_GROUPS);
  const out: Record<string, { name: string; my_messages: number; messages: any[]; error?: string }> = {};
  let total = 0;
  for (const [chatId, { name, n }] of groups) {
    try {
      const data = await lark(["im", "+chat-messages-list", "--chat-id", chatId, "--start", START, "--end", END, "--order", "asc", "--page-all", "--page-limit", "4", "--no-reactions"], 180_000);
      const msgs = arr(data, "messages").map(normMsg);
      out[chatId] = { name, my_messages: n, messages: msgs };
      total += msgs.length;
      console.log(`  · ${name || chatId}: ${msgs.length}`);
    } catch (e) {
      out[chatId] = { name, my_messages: n, messages: [], error: (e as Error).message };
    }
  }
  save("im_groups", out, total);
});

// ───────── 会议 ─────────
await step("minutes", async () => {
  const items: any[] = [];
  let token: string | undefined;
  for (let i = 0; i < 5; i++) {
    const data = await lark(["minutes", "+search", "--participant-ids", "me", "--start", START, "--end", END, "--page-size", "30", ...(token ? ["--page-token", token] : [])]);
    items.push(...arr(data, "items"));
    token = data?.page_token;
    if (!data?.has_more || !token) break;
  }
  const tokens = items.map((x) => x.token ?? x.minute_token).filter(Boolean);
  const details: any[] = [];
  for (let i = 0; i < tokens.length; i += 10) {
    const d = await lark(["minutes", "+detail", "--minute-tokens", tokens.slice(i, i + 10).join(","), "--summary", "--todo"], 180_000);
    details.push(...(arr(d, "minutes").length ? arr(d, "minutes") : [d]));
  }
  save("minutes", { list: items, details }, items.length);
});

// ───────── 日历 ─────────
await step("calendar", async () => {
  const data = await lark(["calendar", "+agenda", "--start", START, "--end", FUTURE]);
  const events = arr(data, "items").length ? arr(data, "items") : arr(data, "events");
  save("calendar", events, events.length);
});

// ───────── 飞书任务 ─────────
await step("tasks_mine", async () => {
  const data = await lark(["task", "+get-my-tasks", "--complete=false", "--page-all"]);
  const items = arr(data, "items");
  save("tasks_mine", items, items.length);
});
await step("tasks_related", async () => {
  const data = await lark(["task", "+get-related-tasks", "--include-complete=false", "--page-all"]);
  const items = arr(data, "items");
  save("tasks_related", items, items.length);
});

fs.writeFileSync(
  path.join(OUT, "_report.json"),
  JSON.stringify({ me: ME, my_name: MY_NAME, window: { start: START, end: END, future: FUTURE }, report }, null, 2),
  { mode: 0o600 },
);
console.log("\n采集完成：", JSON.stringify(report, null, 1));
