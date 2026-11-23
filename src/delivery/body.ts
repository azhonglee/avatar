import type { DeliveryStatus } from "../api/types.ts";
import { truncate } from "../util.ts";
import type { CheckResult, DispatchPayload } from "../workflows/dispatch.ts";

/** 交付的纯函数：标题、正文、前置条件判断（单元测试覆盖）。 */

export type DeliveryAction = "create_pr" | "merge_local" | "discard" | "restore";

/** 账本里 delivery 工作的 payload（约定见 src/ext.ts）。cleanup 是放弃后延迟清理的内部动作。 */
export interface DeliveryPayload {
  action: DeliveryAction | "cleanup";
  dispatch_id: string;
  /** 飞书任务 guid（评论用） */
  guid: string;
  /** create_pr */
  title?: string;
  draft?: boolean;
  provider?: string;
  number?: number;
  reused?: boolean;
  /** merge_local：目标分支（命令参数）；完成后记录实际合并的分支与提交范围 */
  target_branch?: string;
  from?: string;
  to?: string;
  /** discard：对应的清理工作；cleanup：对应的放弃工作 */
  cleanup_id?: string;
  discard_id?: string;
  /** 清理时间（discard 完成后写入） */
  cleanup_at?: number;
  /** 结果链接（PR/MR） */
  url?: string;
  /** 结果说明 / 失败原因（中文） */
  message?: string;
}

const DELIVERABLE = ["accepted", "unverified", "needs_human"];

/** 某个交付动作在当前状态下能不能做；不能做时返回原因（与 core-commands.ts 的 availableActions 保持一致）。 */
export function denyReason(action: DeliveryAction, dispatchState: string, status: DeliveryStatus): string | undefined {
  if (status === "pending") return "已有交付操作在进行中，请稍候";
  const deliverable = DELIVERABLE.includes(dispatchState);
  switch (action) {
    case "create_pr":
    case "merge_local":
      if (!deliverable) return "只有已通过 / 未验证 / 需人工介入的派单可以交付";
      if (status === "pr_open") return "已经创建过 PR，请在平台上继续处理";
      if (status === "merged_local") return "已经合并到本地分支";
      if (status === "discarded") return "已放弃，请先恢复";
      return undefined;
    case "discard":
      if (status === "discarded") return "已经放弃过了";
      if (status === "merged_local") return "已经合并到本地分支，无需放弃";
      if (status === "pr_open") return undefined;
      if (!deliverable) return "只有已通过 / 未验证 / 需人工介入的派单可以放弃";
      return undefined;
    case "restore":
      return status === "discarded" ? undefined : "只有已放弃的派单可以恢复";
  }
}

/** PR 标题：命令参数优先，否则用任务标题去掉 `[harness]` 前缀。 */
export function prTitle(summary: string, override?: string): string {
  const t = (override ?? "").trim() || summary.replace(/^\s*\[[\w-]+\]\s*/, "").trim();
  return truncate(t || "Avatar 交付", 250).split("\n")[0];
}

function statusText(s: CheckResult["status"]): string {
  return s === "pass" ? "✅ 通过" : s === "fail" ? "❌ 需修改" : "⚠️ 故障";
}

const quote = (s: string) =>
  s
    .trim()
    .split("\n")
    .map((l) => `> ${l}`)
    .join("\n");

/** PR 正文（中文 Markdown）：任务链接、执行者报告、每轮校验 / 审查结果、变更统计。 */
export function prBody(p: Pick<DispatchPayload, "summary" | "harness" | "reviewer" | "report" | "history" | "branch" | "base">, o: { taskUrl: string; dispatchId: string; diffStat: string }): string {
  const lines: string[] = ["## 任务", o.taskUrl ? `[${prTitle(p.summary)}](${o.taskUrl})` : prTitle(p.summary), ""];
  lines.push("## 执行者报告", "", p.report?.trim() ? quote(truncate(p.report, 6000)) : "（无）", "");
  lines.push("## 验收结果", "");
  const history = p.history ?? [];
  if (!history.length) lines.push("没有配置校验（无审查者、无校验命令），结果未经验证。", "");
  for (const h of history) {
    lines.push(`### 第 ${h.round} 轮`, "");
    if (!h.checks.length) lines.push("- 无校验");
    for (const c of h.checks) {
      lines.push(`- ${c.kind === "review" ? "🔍" : "🧪"} ${c.name}：${statusText(c.status)}`);
      if (c.detail && c.detail !== "通过") lines.push("", quote(truncate(c.detail, 1500)), "");
    }
    lines.push("");
  }
  if (o.diffStat) lines.push("## 变更统计", "", "```", truncate(o.diffStat, 4000), "```", "");
  const meta = [p.harness && `执行者：${p.harness}`, p.reviewer && `审查：${p.reviewer}`, `分支：${p.branch}`, `派单：${o.dispatchId}`].filter(Boolean).join(" · ");
  lines.push("---", `由 Avatar 生成（${meta}）`);
  return lines.join("\n");
}

/** 放弃后的保留截止时间文字（按本地时区）。 */
export function retentionText(at: number, tz: string): string {
  return new Intl.DateTimeFormat("zh-CN", { timeZone: tz, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hourCycle: "h23" }).format(new Date(at));
}
