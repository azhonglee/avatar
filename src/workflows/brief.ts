import type { Board, BoardTask } from "../board.ts";
import { toBoardTask } from "../board.ts";
import type { Config } from "../config.ts";
import type { Lark } from "../lark.ts";
import type { Store } from "../store.ts";
import { findItems } from "../util.ts";

/**
 * 晨报 / 晚报：纯数据汇总，不调用模型——便宜、稳定、可预期。
 * 截止提醒本身交给飞书任务原生提醒；这里只做“全局视图”。
 */
export async function buildBrief(
  cfg: Config,
  lark: Lark,
  store: Store,
  board: Board,
  mode: "morning" | "evening",
): Promise<string> {
  const now = Date.now();
  const tz = cfg.owner.timezone;
  const dayEnd = endOfLocalDay(now, tz);
  const mine = findItems(
    await lark.run(["task", "+get-my-tasks", "--complete=false", "--page-all"], { as: "user" }),
    "guid",
  ).map(toBoardTask);

  const overdue = mine.filter((t) => t.dueMs !== null && t.dueMs < now);
  const today = mine.filter((t) => t.dueMs !== null && t.dueMs >= now && t.dueMs <= dayEnd);
  const tomorrow = mine.filter((t) => t.dueMs !== null && t.dueMs > dayEnd && t.dueMs <= dayEnd + 86_400_000);
  const pending = await board.listSection("pending");
  const review = await board.listSection("review");
  const since = now - 86_400_000;
  const runs = store.runsSince(since).filter((r) => r.role === "worker");
  const sig = store.countSignalsSince(since);

  const fmt = (t: BoardTask) => `- ${t.url ? `[${t.summary}](${t.url})` : t.summary}${t.dueMs ? `（${fmtTime(t.dueMs, tz)}）` : ""}`;
  const section = (title: string, list: BoardTask[]) => (list.length ? [`**${title}（${list.length}）**`, ...list.slice(0, 10).map(fmt)] : []);

  const lines = [
    mode === "morning" ? "☀️ **早上好，今日概览**" : "🌙 **今日收尾**",
    ...section("⚠️ 已逾期", overdue),
    ...section("📌 今天截止", today),
    ...(mode === "evening" ? section("⏭️ 明天截止", tomorrow) : []),
    ...section("❓ 待你确认（agent 识别出的候选任务，拖到 Inbox 即确认）", pending),
    ...section("🧪 待你验收（agent 已完成）", review),
    `**🤖 过去 24 小时**：识别信号 ${sig.total} 条，建任务 ${sig.tasks ?? 0} 个；派单 ${runs.length} 次（成功 ${runs.filter((r) => r.status === "ok").length}，失败 ${runs.filter((r) => r.status === "failed").length}，进行中 ${runs.filter((r) => r.status === "running").length}）`,
  ];
  if (lines.length === 2) lines.splice(1, 0, "今天没有逾期或到期的任务 🎉");
  return lines.join("\n");
}

function fmtTime(ms: number, tz: string): string {
  return new Date(ms).toLocaleString("zh-CN", { timeZone: tz, month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

/** 指定时区里“今天”结束时刻的毫秒时间戳。 */
export function endOfLocalDay(ms: number, tz: string): number {
  const parts = new Intl.DateTimeFormat("en-US", { timeZone: tz, hour: "numeric", minute: "numeric", second: "numeric", hourCycle: "h23" })
    .formatToParts(new Date(ms))
    .reduce<Record<string, number>>((acc, p) => (p.type === "literal" ? acc : { ...acc, [p.type]: Number(p.value) }), {});
  const elapsed = ((parts.hour * 60 + parts.minute) * 60 + parts.second) * 1000 + (ms % 1000);
  return ms - elapsed + 86_400_000 - 1;
}
