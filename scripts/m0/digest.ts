/**
 * M0：把采集到的原始数据压缩成便于阅读和抽取的摘要文本（每个来源 / 会话一个文件）。
 *
 *   node --experimental-strip-types scripts/m0/digest.ts [数据目录]
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const DIR = path.resolve(process.argv[2] ?? path.join(os.homedir(), ".personal-agent", "m0", new Date().toISOString().slice(0, 10)));
const OUT = path.join(DIR, "digest");
fs.rmSync(OUT, { recursive: true, force: true });
fs.mkdirSync(OUT, { recursive: true, mode: 0o700 });
const load = (f: string) => (fs.existsSync(path.join(DIR, f)) ? JSON.parse(fs.readFileSync(path.join(DIR, f), "utf8")) : undefined);
const rep = load("_report.json") ?? {};
const ME: string = rep.me ?? "";
const TZ = "Asia/Shanghai";

const fmtTime = (v: unknown): string => {
  if (v === undefined || v === null || v === "") return "";
  const s = String(v);
  let ms = /^\d{10}$/.test(s) ? Number(s) * 1000 : /^\d{13}$/.test(s) ? Number(s) : Date.parse(s.replace(" ", "T"));
  if (Number.isNaN(ms)) return s.slice(0, 16);
  return new Intl.DateTimeFormat("zh-CN", { timeZone: TZ, month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false }).format(new Date(ms));
};

/** 从卡片 / 富文本 JSON 里提取可读文字 */
function textOf(raw: string): string {
  let t = raw;
  if (/^\s*[{[]/.test(raw)) {
    try {
      const out: string[] = [];
      const walk = (o: unknown) => {
        if (typeof o === "string") return;
        if (Array.isArray(o)) return o.forEach(walk);
        if (o && typeof o === "object") {
          for (const [k, v] of Object.entries(o)) {
            if (typeof v === "string" && ["text", "content", "title", "plain_text"].includes(k) && v.trim()) out.push(v.trim());
            else walk(v);
          }
        }
      };
      walk(JSON.parse(raw));
      if (out.length) t = out.join(" / ");
    } catch {
      // 不是 JSON
    }
  }
  return t
    .replace(/!\[Image\]\([^)]*\)/g, "[图]")
    .replace(/\s+/g, " ")
    .trim();
}
const cut = (s: string, n: number) => (s.length > n ? s.slice(0, n) + "…" : s);
const write = (name: string, lines: string[]) => fs.writeFileSync(path.join(OUT, name), lines.join("\n") + "\n", { mode: 0o600 });
const safe = (s: string) => s.replace(/[\/\\:*?"<>|\s]+/g, "_").slice(0, 40);

// ───────── Meego ─────────
{
  const todo = load("meego_todo.json") ?? [];
  const overdue = new Set((load("meego_overdue.json") ?? []).map((x: any) => x.work_item_info?.work_item_id));
  const done = load("meego_done.json") ?? [];
  const byProject = new Map<string, any[]>();
  for (const x of todo) {
    const k = x.project_name || x.project_key || "?";
    if (!byProject.has(k)) byProject.set(k, []);
    byProject.get(k)!.push(x);
  }
  const lines = [`# Meego 待办（${todo.length}，逾期 ${overdue.size}）`, ""];
  for (const [proj, items] of [...byProject.entries()].sort((a, b) => b[1].length - a[1].length)) {
    lines.push(`## ${proj}（${items.length}）`);
    for (const x of items) {
      const w = x.work_item_info ?? {};
      const end = x.schedule?.end_time ? ` 截止 ${fmtTime(x.schedule.end_time)}` : "";
      lines.push(
        `- [${w.work_item_type_key}#${w.work_item_id}]${overdue.has(w.work_item_id) ? " ⚠逾期" : ""} ${w.work_item_name} ｜节点:${x.node_info?.node_name ?? "-"} ｜状态:${x.state_info?.start_state_key_name ?? ""}→${x.state_info?.end_state_key_name ?? ""}${end}`,
      );
    }
    lines.push("");
  }
  lines.push(`# Meego 最近已办（${done.length}）`);
  for (const x of done) {
    const w = x.work_item_info ?? {};
    lines.push(`- [${w.work_item_type_key}#${w.work_item_id}] ${x.project_name} ｜ ${w.work_item_name} ｜节点:${x.node_info?.node_name ?? "-"}`);
  }
  write("00_meego.md", lines);
}

// ───────── 飞书任务 / 日历 / 妙记 ─────────
{
  const mine = load("tasks_mine.json") ?? [];
  const rel = load("tasks_related.json") ?? [];
  const lines = [`# 飞书任务：分配给我（未完成 ${mine.length}）`];
  for (const t of mine.sort((a: any, b: any) => Number(a.due_at || 9e15) - Number(b.due_at || 9e15)))
    lines.push(`- ${t.summary}${t.due_at && t.due_at !== "0" ? ` ｜截止 ${fmtTime(t.due_at)}` : ""} ｜创建 ${fmtTime(t.created_at)}`);
  lines.push("", `# 飞书任务：与我相关（${rel.length}）`);
  for (const t of rel) lines.push(`- ${t.summary}${t.due_at && t.due_at !== "0" ? ` ｜截止 ${fmtTime(t.due_at)}` : ""}`);
  write("01_tasks.md", lines);

  const cal = load("calendar.json") ?? [];
  const cl = [`# 日历（前后 7 天，${cal.length}）`];
  for (const e of cal) {
    const st = e.start_time?.timestamp ?? e.start_time?.date ?? e.start_time;
    cl.push(`- ${fmtTime(st)} ${e.summary ?? "(无标题)"} ｜rsvp:${e.self_rsvp_status ?? "-"}`);
  }
  write("02_calendar.md", cl);

  const mins = load("minutes.json") ?? { list: [], details: [] };
  const ml = [`# 妙记（${mins.list.length}）`];
  for (const d of mins.details) {
    const a = d.artifacts ?? {};
    ml.push(`## ${d.title ?? d.minute_token}`);
    if (a.summary) ml.push(`摘要：${cut(textOf(typeof a.summary === "string" ? a.summary : JSON.stringify(a.summary)), 1500)}`);
    const todos = a.todos ?? a.todo ?? [];
    for (const t of Array.isArray(todos) ? todos : []) ml.push(`- 待办：${textOf(typeof t === "string" ? t : JSON.stringify(t))}`);
    ml.push("");
  }
  write("03_minutes.md", ml);
}

// ───────── 消息 ─────────
type Msg = { id: string; chat_id: string; chat_name: string; chat_type: string; sender_id: string; sender_name: string; sender_type: string; time: string; msg_type: string; text: string };
const line = (m: Msg, n = 240) => `${fmtTime(m.time)} ${m.sender_id === ME ? "【我】" : m.sender_name || m.sender_id}: ${cut(textOf(m.text), n)}`;

{
  const at: Msg[] = load("im_at_me.json") ?? [];
  const l = [`# @我的消息（${at.length}）`];
  for (const m of [...at].sort((a, b) => a.time.localeCompare(b.time))) l.push(`- [${m.chat_name || m.chat_type}] ${line(m, 400)}`);
  write("10_at_me.md", l);

  // 私聊：按会话分组；人类会话一个文件，机器人通知合并去重
  const p2p: Msg[] = load("im_p2p.json") ?? [];
  const chats = new Map<string, Msg[]>();
  for (const m of p2p) {
    if (!chats.has(m.chat_id)) chats.set(m.chat_id, []);
    chats.get(m.chat_id)!.push(m);
  }
  const index: string[] = [`# 私聊索引（${chats.size} 个会话）`];
  const bots: string[] = [`# 机器人私聊通知（去重）`];
  for (const [id, ms] of [...chats.entries()].sort((a, b) => b[1].length - a[1].length)) {
    ms.sort((a, b) => a.time.localeCompare(b.time));
    const isBot = ms.some((m) => m.sender_type === "app") && !ms.some((m) => m.sender_type === "user" && m.sender_id !== ME);
    const other = ms.find((m) => m.sender_id !== ME)?.sender_name || id;
    if (isBot) {
      const seen = new Set<string>();
      bots.push(`## ${other}（${ms.length}）`);
      for (const m of ms) {
        const t = cut(textOf(m.text), 220);
        const key = t.slice(0, 60);
        if (seen.has(key)) continue;
        seen.add(key);
        bots.push(`- ${fmtTime(m.time)} ${t}`);
      }
      index.push(`- 🤖 ${other}: ${ms.length}`);
    } else {
      write(`20_p2p_${safe(other)}.md`, [`# 私聊：${other}（${ms.length}）`, ...ms.map((m) => `- ${line(m)}`)]);
      index.push(`- 👤 ${other}: ${ms.length}`);
    }
  }
  write("19_p2p_index.md", index);
  write("29_bots.md", bots);

  const groups = load("im_groups.json") ?? {};
  const gi = [`# 我发言过的群（${Object.keys(groups).length}）`];
  for (const [id, g] of Object.entries<any>(groups)) {
    const ms: Msg[] = g.messages;
    gi.push(`- ${g.name || id}: ${ms.length} 条，其中我 ${g.my_messages} 条${g.error ? ` ⚠${g.error}` : ""}`);
    write(`30_group_${safe(g.name || id)}.md`, [`# 群：${g.name || id}（${ms.length}，我发言 ${g.my_messages}）`, ...ms.map((m) => `- ${line(m, 200)}`)]);
  }
  write("29_groups_index.md", gi);
}

for (const f of fs.readdirSync(OUT).sort()) console.log(`${String(fs.statSync(path.join(OUT, f)).size).padStart(8)}  ${f}`);
