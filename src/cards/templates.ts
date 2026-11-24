import type { CommandName, DeliveryStatus } from "../api/types.ts";
import { truncate } from "../util.ts";
import type { CheckResult } from "../workflows/dispatch.ts";

/**
 * 飞书交互卡片模板（JSON 2.0）。全部是纯函数：输入视图数据，输出完整卡片 JSON。
 * 按钮的回调值统一为 ActionValue（{ cmd, args, card }），表单字段在回调时合并进 args（见 actions.ts）。
 *
 * 版式约定：header 颜色表示状态（蓝=进行中、绿=成功、橙=需要你、红=失败、灰=已结束/次要）；
 * 一张卡片只有一个主按钮（primary_filled），危险操作用 danger 并带二次确认。
 */

export type Card = Record<string, unknown>;
type El = Record<string, unknown>;

/** 按钮回调值。card 是这张卡片的 key，操作后据此原地刷新。 */
export interface ActionValue {
  cmd: CommandName;
  args: Record<string, unknown>;
  card?: string;
}

export interface RenderCtx {
  harnesses: string[];
  /** 控制台地址（如 http://<局域网IP>:7878），没启用控制台时为空 */
  consoleBase: string;
  timezone: string;
  /** 刚执行的操作结果，显示在卡片底部 */
  notice?: string;
}

// ───────── 基础组件 ─────────

const pt = (content: string) => ({ tag: "plain_text", content });
const md = (content: string, extra: El = {}): El => ({ tag: "markdown", content, ...extra });
const grey = (s: string) => `<font color='grey'>${s}</font>`;
/** 卡片 markdown 里的用户文本：去掉会被当成标签/链接的字符，避免破坏版式 */
export const esc = (s: string) => s.replace(/[<>]/g, (c) => (c === "<" ? "＜" : "＞")).replace(/\[/g, "［").replace(/\]/g, "］");
/** 只把 http(s) 链接放进 markdown 链接里 */
const isUrl = (s: string) => /^https?:\/\/[^\s()]+$/.test(s);

function header(title: string, template: string, subtitle?: string, tag?: { text: string; color: string }): El {
  return {
    title: pt(truncate(title, 80)),
    ...(subtitle ? { subtitle: pt(truncate(subtitle, 80)) } : {}),
    template,
    ...(tag ? { text_tag_list: [{ tag: "text_tag", text: pt(tag.text), color: tag.color }] } : {}),
  };
}

function card(h: El, elements: El[], summary: string): Card {
  return {
    schema: "2.0",
    config: { update_multi: true, summary: { content: truncate(summary, 60) } },
    header: h,
    body: { direction: "vertical", padding: "12px 12px 16px 12px", vertical_spacing: "8px", elements },
  };
}

export interface Confirm {
  title: string;
  text: string;
}

type BtnType = "primary_filled" | "default" | "danger" | "primary";

export function button(text: string, value: ActionValue, o: { type?: BtnType; confirm?: Confirm } = {}): El {
  return {
    tag: "button",
    text: pt(text),
    type: o.type ?? "default",
    behaviors: [{ type: "callback", value }],
    ...(o.confirm ? { confirm: { title: pt(o.confirm.title), text: pt(o.confirm.text) } } : {}),
  };
}

function linkButton(text: string, url: string, type: BtnType = "default", fill = false): El {
  return { tag: "button", text: pt(text), type, ...(fill ? { width: "fill" } : {}), behaviors: [{ type: "open_url", default_url: url }] };
}

/** 一行按钮（自动换行）。第一个非危险按钮作为主按钮。 */
function buttonRow(buttons: El[]): El {
  let primarySet = false;
  const styled = buttons.map((b) => {
    if (!primarySet && b.type === "default" && (b.behaviors as { type: string }[])[0]?.type === "callback") {
      primarySet = true;
      return { ...b, type: "primary_filled" };
    }
    return b;
  });
  return {
    tag: "column_set",
    flex_mode: "flow",
    horizontal_spacing: "8px",
    columns: styled.map((b) => ({ tag: "column", width: "auto", elements: [b] })),
  };
}

function select(name: string, options: { label: string; value: string }[], o: { placeholder: string; initial?: string; required?: boolean }): El {
  return {
    tag: "select_static",
    name,
    placeholder: pt(o.placeholder),
    options: options.map((x) => ({ text: pt(x.label), value: x.value })),
    ...(o.initial && options.some((x) => x.value === o.initial) ? { initial_option: o.initial } : {}),
    ...(o.required ? { required: true } : {}),
    width: "fill",
  };
}

function input(name: string, o: { placeholder: string; label?: string; required?: boolean; multiline?: boolean; maxLength?: number; value?: string }): El {
  return {
    tag: "input",
    name,
    placeholder: pt(o.placeholder),
    ...(o.label ? { label: pt(o.label), label_position: "top" } : {}),
    ...(o.required ? { required: true } : {}),
    ...(o.multiline ? { input_type: "multiline_text", rows: 2, auto_resize: true, max_rows: 6 } : {}),
    ...(o.value ? { default_value: o.value } : {}),
    max_length: o.maxLength ?? 1000,
    width: "fill",
  };
}

/**
 * 表单：字段在回调的 form_value 里按 name 回传；提交按钮同时带回调值（cmd / args / card），
 * 没带回来时按提交按钮的 name 兜底识别（见 actions.ts 的 FORM_SUBMIT）。
 */
export const FORM_SUBMIT: Record<string, CommandName> = {
  btn_rework: "dispatch.rework",
  btn_switch: "dispatch.switch_harness",
  btn_cand_dispatch: "candidate.dispatch",
  btn_do: "dispatch.create",
};

function form(name: string, fields: El[], submit: { text: string; name: keyof typeof FORM_SUBMIT; value: ActionValue; type?: BtnType }): El {
  return {
    tag: "form",
    name,
    vertical_spacing: "8px",
    elements: [
      ...fields,
      {
        tag: "button",
        text: pt(submit.text),
        type: submit.type ?? "primary",
        name: submit.name,
        form_action_type: "submit",
        behaviors: [{ type: "callback", value: submit.value }],
      },
    ],
  };
}

function noticeEl(notice?: string): El[] {
  return notice ? [{ tag: "hr" }, md(grey(esc(notice)), { text_size: "notation" })] : [];
}

export function fmtDuration(ms: number): string {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return `${s} 秒`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} 分 ${s % 60} 秒`;
  const h = Math.floor(m / 60);
  return `${h} 小时 ${m % 60} 分`;
}

export function fmtUsd(n: number): string {
  return n > 0 ? `$${n < 0.01 ? n.toFixed(4) : n.toFixed(2)}` : "—";
}

function fmtTime(ms: number, tz: string): string {
  return new Date(ms).toLocaleString("zh-CN", { timeZone: tz, month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

// ───────── 派单卡片 ─────────

export interface DispatchCardView {
  id: string;
  guid: string;
  taskUrl: string;
  summary: string;
  state: string;
  terminal: boolean;
  reason: string;
  error: string;
  harness: string;
  reviewer: string;
  round: number;
  maxRounds: number;
  attempts: number;
  cancelRequested: boolean;
  elapsedMs: number;
  /** 这张任务所有派单的累计花费 */
  costUsd: number;
  /** 这张任务的第几次派单（返工 / 换执行者 / 重试都会新开一次） */
  dispatchNo: number;
  /** 最近一轮验收的结果 */
  checks: CheckResult[];
  checksRound: number;
  branch: string;
  delivery: DeliveryStatus;
  deliveryUrl: string;
  deliveryError: string;
  /** 当前可执行的命令（已按注册情况过滤） */
  actions: CommandName[];
}

const STATE: Record<string, { text: string; color: string }> = {
  queued: { text: "排队中", color: "blue" },
  executing: { text: "执行中", color: "blue" },
  verifying: { text: "验收中", color: "blue" },
  accepted: { text: "已通过验收", color: "green" },
  unverified: { text: "已完成 · 未验证", color: "turquoise" },
  needs_human: { text: "需要你介入", color: "orange" },
  errored: { text: "执行出错", color: "red" },
  cancelled: { text: "已取消", color: "grey" },
};

export const REASON_TEXT: Record<string, string> = {
  passed: "校验全部通过",
  checks_failed: "校验未通过，正在返工",
  rejected: "返工轮次用完，校验仍未通过",
  verifier_error: "校验器故障（审查超时 / 无输出 / 结论无法解析，或校验命令无法运行），无法判断是否达标",
  unverified: "没有配置任何校验（无审查者、无校验命令），结果未经验证",
  errored: "执行反复失败",
  cancelled: "已取消，已有改动保留在工作目录",
  budget: "超出用量预算，已暂停",
};

const DELIVERY_TEXT: Record<DeliveryStatus, string> = {
  none: "",
  pending: "⏳ 正在交付…",
  pr_open: "🔗 PR 已创建",
  merged_local: "✅ 已合并到本地分支",
  discarded: "🗑️ 已放弃（保留期内可恢复）",
  failed: "❌ 交付失败",
};

/** 阶段条：准备 → 执行 → 验收。 */
export function stageLine(v: Pick<DispatchCardView, "state" | "terminal" | "harness" | "checks">): string {
  const names = ["准备", "执行", "验收"];
  let at: number;
  let mark: string;
  if (!v.terminal) {
    at = { queued: 0, executing: 1, verifying: 2 }[v.state] ?? 0;
    mark = "🔄";
  } else if (["accepted", "unverified"].includes(v.state)) {
    at = 3;
    mark = "";
  } else if (v.state === "needs_human") {
    at = 2;
    mark = "⚠️";
  } else {
    // 出错 / 取消：按已有进度推断停在哪一步
    at = v.checks.length ? 2 : v.harness ? 1 : 0;
    mark = v.state === "cancelled" ? "⏹️" : "❌";
  }
  return names.map((n, i) => `${i < at ? "✅" : i === at ? mark : "⚪"} ${n}`).join("  →  ");
}

const CHECK_ICON = { pass: "✅", fail: "❌", error: "⚠️" } as const;
const CHECK_TEXT = { pass: "通过", fail: "需修改", error: "故障" } as const;

export function consoleUrl(base: string, dispatchId?: string): string {
  if (!base) return "";
  return dispatchId ? `${base}/dispatches/${encodeURIComponent(dispatchId)}` : `${base}/`;
}

export function dispatchCard(v: DispatchCardView, ctx: RenderCtx): Card {
  const key = `dispatch:${v.guid}`;
  const st = STATE[v.state] ?? { text: v.state, color: "grey" };
  const stateText = v.cancelRequested && !v.terminal ? "正在取消…" : st.text;
  const val = (cmd: CommandName, args: Record<string, unknown> = {}): ActionValue => ({ cmd, args: { id: v.id, ...args }, card: key });

  const facts = [
    `**进度**　${stageLine(v)}`,
    [
      v.maxRounds ? `**轮次**　${v.round || 1}/${v.maxRounds}` : "",
      v.harness ? `**执行者**　${esc(v.harness)}` : "",
      v.reviewer ? `**审查**　${esc(v.reviewer)}` : "",
    ]
      .filter(Boolean)
      .join("　　"),
    `**用时**　${fmtDuration(v.elapsedMs)}　　**费用**　${fmtUsd(v.costUsd)}${v.dispatchNo > 1 ? `（${v.dispatchNo} 次派单累计）` : ""}`,
  ].filter(Boolean);
  const elements: El[] = [md(facts.join("\n"))];

  if (!v.terminal && v.attempts > 1 && v.error) {
    elements.push(md(`<font color='orange'>第 ${v.attempts} 次尝试，上次失败：${esc(truncate(v.error, 200))}</font>`));
  }
  if (v.checks.length) {
    const lines = v.checks.map((c) => `${CHECK_ICON[c.status]} ${esc(c.name)}：${CHECK_TEXT[c.status]}`);
    elements.push(md(`**第 ${v.checksRound} 轮验收**\n${lines.join("\n")}`));
    const details = v.checks.filter((c) => c.status !== "pass" || c.kind === "review").filter((c) => c.detail && c.detail !== "通过");
    if (details.length) {
      elements.push({
        tag: "collapsible_panel",
        expanded: false,
        header: { title: md("**审查与校验详情**") },
        elements: details.map((c) => md(`**${esc(c.name)}**\n${esc(truncate(c.detail, 1200))}`)),
      });
    }
  }
  if (v.terminal) {
    const why = REASON_TEXT[v.reason] ?? v.reason;
    const lines = [why ? `**结论**　${why}` : ""];
    if (v.state === "errored" && v.error) lines.push(`**最后的错误**　${esc(truncate(v.error, 300))}`);
    if (v.branch) lines.push(`**分支**　${esc(v.branch)}`);
    if (v.delivery !== "none") {
      const d = DELIVERY_TEXT[v.delivery];
      lines.push(`**交付**　${isUrl(v.deliveryUrl) ? `[${d}](${v.deliveryUrl})` : d}${v.delivery === "failed" && v.deliveryError ? `：${esc(truncate(v.deliveryError, 200))}` : ""}`);
    }
    elements.push(md(lines.filter(Boolean).join("\n")));
  }

  // 操作：按钮一行；需要输入的（返工意见、换执行者）各一个表单
  const has = (c: CommandName) => v.actions.includes(c);
  const buttons: El[] = [];
  if (has("delivery.create_pr")) buttons.push(button("创建 PR", val("delivery.create_pr")));
  if (has("delivery.merge_local"))
    buttons.push(
      button("合并到本地分支", val("delivery.merge_local"), {
        confirm: { title: "合并到本地分支？", text: `会把 ${v.branch || "派单分支"} 合并进仓库的当前分支，这一步不能自动撤销。` },
      }),
    );
  if (has("dispatch.retry")) buttons.push(button("重试", val("dispatch.retry")));
  if (has("delivery.restore")) buttons.push(button("恢复", val("delivery.restore")));
  if (has("delivery.discard"))
    buttons.push(
      button("放弃", val("delivery.discard"), {
        type: "danger",
        confirm: { title: "放弃这次结果？", text: "worktree 与分支会保留一段时间，期间可以恢复；之后会被清理。" },
      }),
    );
  if (has("dispatch.cancel"))
    buttons.push(button("取消", val("dispatch.cancel"), { type: "danger", confirm: { title: "取消这次派单？", text: "正在运行的执行者会被结束，已有改动保留在工作目录。" } }));
  const url = consoleUrl(ctx.consoleBase, v.id);
  if (url) buttons.push(linkButton("在控制台查看", url));
  if (v.taskUrl) buttons.push(linkButton("打开任务", v.taskUrl));
  if (buttons.length) elements.push(buttonRow(buttons));

  if (has("dispatch.rework")) {
    elements.push(
      form("f_rework", [input("feedback", { placeholder: "写下返工意见，例如：补上单元测试、改用现有的工具函数", required: true, multiline: true, maxLength: 1000 })], {
        text: "带意见返工",
        name: "btn_rework",
        value: val("dispatch.rework"),
      }),
    );
  }
  const others = ctx.harnesses.filter((h) => h !== v.harness);
  if (has("dispatch.switch_harness") && others.length) {
    elements.push(
      form("f_switch", [select("harness", others.map((h) => ({ label: h, value: h })), { placeholder: "换一个执行者", required: true })], {
        text: "换执行者重试",
        name: "btn_switch",
        value: val("dispatch.switch_harness"),
        type: "default",
      }),
    );
  }
  elements.push(...noticeEl(ctx.notice));

  const subtitle = [stateText, v.dispatchNo > 1 ? `第 ${v.dispatchNo} 次派单` : ""].filter(Boolean).join(" · ");
  return card(header(v.summary || "派单", st.color, subtitle, { text: stateText, color: st.color }), elements, `派单 · ${stateText}：${v.summary}`);
}

// ───────── 候选任务卡片 ─────────

export interface CandidateCardView {
  signalId: string;
  taskGuid: string;
  taskUrl: string;
  summary: string;
  /** 分诊放进的列：pending（待确认）/ inbox（高置信度直接进 Inbox） */
  section: string;
  source: string;
  text: string;
  link: string;
  confidence: number | null;
  reason: string;
  dueMs: number | null;
  /** 你的反馈 */
  feedback: "" | "confirmed" | "rejected" | "dispatched";
  canConfirm: boolean;
  canReject: boolean;
  canDispatch: boolean;
  defaultHarness: string;
  repos: string[];
}

export function candidateCard(v: CandidateCardView, ctx: RenderCtx): Card {
  const key = `candidate:${v.signalId}`;
  const val = (cmd: CommandName, args: Record<string, unknown> = {}): ActionValue => ({ cmd, args: { signal_id: v.signalId, ...args }, card: key });
  const status = {
    "": v.section === "pending" ? { text: "待你确认", color: "wathet" } : { text: "已放进 Inbox", color: "turquoise" },
    confirmed: { text: "已确认是任务", color: "green" },
    rejected: { text: "已标记不是任务", color: "grey" },
    dispatched: { text: "已派给 Agent", color: "indigo" },
  }[v.feedback];

  const facts = [
    `**来源**　${esc(v.source || "未知")}${isUrl(v.link) ? `　[查看原文](${v.link})` : ""}`,
    v.reason ? `**判断依据**　${esc(truncate(v.reason, 300))}` : "",
    v.confidence !== null ? `**置信度**　${Math.round(v.confidence * 100)}%` : "",
    v.dueMs ? `**建议截止**　${fmtTime(v.dueMs, ctx.timezone)}` : "",
  ].filter(Boolean);
  const elements: El[] = [md(facts.join("\n"))];
  if (v.text) elements.push(md(`**原文摘录**\n${grey(esc(truncate(v.text, 300)))}`));

  const done = v.feedback === "rejected" || v.feedback === "dispatched";
  const buttons: El[] = [];
  if (v.canConfirm && !v.feedback && v.section === "pending") buttons.push(button("是任务", val("candidate.confirm")));
  if (v.canReject && !done) buttons.push(button("不是任务", val("candidate.reject"), { type: "danger" }));
  if (v.taskUrl) buttons.push(linkButton("打开任务", v.taskUrl));
  if (buttons.length) elements.push(buttonRow(buttons));
  if (v.canDispatch && !done && ctx.harnesses.length) {
    const fields = [select("harness", ctx.harnesses.map((h) => ({ label: h, value: h })), { placeholder: "执行者", initial: v.defaultHarness })];
    if (v.repos.length) fields.push(select("repo", v.repos.map((r) => ({ label: r, value: r })), { placeholder: "仓库（可不选）" }));
    elements.push(
      form("f_cand_dispatch", [{ tag: "column_set", flex_mode: "stretch", horizontal_spacing: "8px", columns: fields.map((f) => ({ tag: "column", width: "weighted", weight: 1, elements: [f] })) }], {
        text: "派给 Agent",
        name: "btn_cand_dispatch",
        value: val("candidate.dispatch"),
        type: "default",
      }),
    );
  }
  elements.push(...noticeEl(ctx.notice));
  return card(header(v.summary, status.color, "候选任务", { text: status.text, color: status.color }), elements, `候选任务：${v.summary}`);
}

// ───────── 失败告警卡片 ─────────

export interface FailureCardView {
  id: string;
  kind: string;
  state: string;
  terminal: boolean;
  acknowledged: boolean;
  /** 是什么失败了 */
  title: string;
  /** 补充说明（对象、影响） */
  detail: string;
  impact: string;
  error: string;
  attempts: number;
  updated: number;
  canRetry: boolean;
  canAcknowledge: boolean;
}

export function failureCard(v: FailureCardView, ctx: RenderCtx): Card {
  const key = `failure:${v.id}`;
  const failed = v.terminal && ["dead", "errored"].includes(v.state);
  const status = !failed
    ? v.terminal
      ? { text: "已恢复", color: "green" }
      : { text: "已重新排队", color: "blue" }
    : v.acknowledged
      ? { text: "已忽略", color: "grey" }
      : { text: "需要处理", color: "red" };
  const lines = [
    v.detail ? `**对象**　${esc(v.detail)}` : "",
    v.impact ? `**影响**　${v.impact}` : "",
    `**尝试次数**　${v.attempts}　　**时间**　${fmtTime(v.updated, ctx.timezone)}`,
  ].filter(Boolean);
  const elements: El[] = [md(lines.join("\n"))];
  if (v.error) elements.push(md(`**最后的错误**\n${grey(esc(truncate(v.error, 600)))}`));
  if (!failed) elements.push(md(v.terminal ? "✅ 重试已成功" : "🔁 已重新排队，正在重试"));
  const buttons: El[] = [];
  const val = (cmd: CommandName): ActionValue => ({ cmd, args: { id: v.id }, card: key });
  if (failed && !v.acknowledged) {
    if (v.canRetry) buttons.push(button("重试", val("work.retry")));
    if (v.canAcknowledge) buttons.push(button("忽略", val("work.acknowledge")));
  }
  if (ctx.consoleBase) buttons.push(linkButton("查看详情", `${ctx.consoleBase}/health`));
  if (buttons.length) elements.push(buttonRow(buttons));
  elements.push(...noticeEl(ctx.notice));
  return card(header(v.title, status.color, "失败告警", { text: status.text, color: status.color }), elements, `⚠️ ${v.title}`);
}

// ───────── 晨报 / 晚报 ─────────

/**
 * 把 buildBrief 的 Markdown 转成卡片：第一行是标题，以 **粗体** 开头的行开启一个分区。
 * 内容与私信版完全一致（同一份数据），只是分区成块、带“打开控制台”入口。
 */
export function briefCard(mode: "morning" | "evening", text: string, ctx: Pick<RenderCtx, "consoleBase">, date = new Date().toISOString().slice(0, 10)): Card {
  const [first = "", ...rest] = text.split("\n");
  const title = first.replace(/\*\*/g, "").trim() || (mode === "morning" ? "今日概览" : "今日收尾");
  const blocks: string[][] = [];
  for (const line of rest) {
    if (!blocks.length || line.startsWith("**")) blocks.push([line]);
    else blocks.at(-1)!.push(line);
  }
  const elements: El[] = blocks.map((b) => md(b.join("\n").trim())).filter((e) => e.content);
  if (ctx.consoleBase) elements.push(linkButton("打开控制台", consoleUrl(ctx.consoleBase), "primary_filled", true));
  return card(header(title, mode === "morning" ? "wathet" : "indigo", date), elements, title);
}

// ───────── /do 派单表单 ─────────

export interface DoFormView {
  key: string;
  harnesses: string[];
  defaultHarness: string;
  repos: string[];
  /** 提交成功后：显示结果，不再显示表单 */
  submitted?: { summary: string; message: string; dispatchId: string };
  /** 提交失败后重新显示表单时，保留已填的内容 */
  values?: { summary?: string; description?: string; harness?: string; repo?: string };
}

export function doFormCard(v: DoFormView, ctx: Pick<RenderCtx, "consoleBase" | "notice">): Card {
  if (v.submitted) {
    const url = v.submitted.dispatchId.startsWith("dispatch:") ? consoleUrl(ctx.consoleBase, v.submitted.dispatchId) : "";
    const elements: El[] = [md(`**任务**　${esc(v.submitted.summary)}\n${esc(v.submitted.message)}`)];
    if (url) elements.push(buttonRow([linkButton("在控制台查看", url)]));
    return card(header("已创建派单", "green", "进度会以单独的卡片实时更新"), elements, `已创建派单：${v.submitted.summary}`);
  }
  const val: ActionValue = { cmd: "dispatch.create", args: {}, card: v.key };
  const pre = v.values ?? {};
  const fields: El[] = [
    input("summary", { label: "要做什么", placeholder: "一句话描述任务，例如：修复登录页在 Safari 下的报错", required: true, maxLength: 200, value: pre.summary }),
    input("description", { label: "补充说明（可选）", placeholder: "背景、验收标准、注意事项", multiline: true, maxLength: 1000, value: pre.description }),
    select("harness", v.harnesses.map((h) => ({ label: h, value: h })), { placeholder: "执行者", initial: pre.harness || v.defaultHarness }),
  ];
  if (v.repos.length)
    fields.push(select("repo", v.repos.map((r) => ({ label: r, value: r })), { placeholder: "仓库（可不选，不选则在独立空目录里执行）", initial: pre.repo }));
  const elements: El[] = [form("f_do", fields, { text: "派单", name: "btn_do", value: val, type: "primary_filled" }), ...noticeEl(ctx.notice)];
  return card(header("新建派单", "blue", "填好后点「派单」，进度会实时更新"), elements, "新建派单");
}
