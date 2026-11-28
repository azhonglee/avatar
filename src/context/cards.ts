import type { CommandName, CtxConflictView, CtxDraftView, CtxItemDetail, CtxItemView, CtxMeeting, CtxToday, CtxUpdateView } from "../api/types.ts";
import { button, buttonRow, card, esc, form, grey, header, input, linkButton, md, noticeEl, type ActionValue, type Card } from "../cards/templates.ts";
import { consoleLinkUrl } from "../server/index.ts";
import { truncate } from "../util.ts";

/**
 * 工作上下文的飞书卡片（JSON 2.0）。纯函数：输入视图，输出卡片。
 *   - ctx-morning:<日期>  晨间卡：今天最该处理的事（每件带 完成 / 稍后 / 不对 / 起草）、待你判断的冲突、24 小时变化、今天的会
 *   - ctx-evening:<日期>  收尾卡：今天关掉的、还欠着别人的、明天先做什么
 *   - ctx-item:<事项 id>  实时提醒：新出现的高优先级请求 / 风险
 *   - ctx-draft:<草稿 id> 草稿：可编辑后一键确认发送（以你本人身份），或丢弃
 */

type El = Record<string, unknown>;

export interface CtxRenderCtx {
  consoleBase: string;
  consoleTicket?: string;
  timezone: string;
  notice?: string;
}

export const KIND_LABEL: Record<string, string> = {
  ask_me: "别人在等你",
  my_commitment: "你答应过",
  risk: "风险",
  meeting_action: "会议行动项",
  todo: "待办",
  waiting_on: "你在等别人",
};

const DRAFT_LABEL: Record<string, string> = { reply: "回复", followup: "跟进", meego_comment: "Meego 评论", weekly_report: "周报" };

const isUrl = (s: string) => /^https?:\/\/[^\s()]+$/.test(s);
const link = (text: string, url: string) => (isUrl(url) ? `[${esc(text)}](${url})` : esc(text));

export function fmtWhen(ms: number, tz: string, withDate = true): string {
  const o: Intl.DateTimeFormatOptions = withDate
    ? { timeZone: tz, month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: false }
    : { timeZone: tz, hour: "2-digit", minute: "2-digit", hour12: false };
  return new Date(ms).toLocaleString("zh-CN", o);
}

function dueText(due: number | null, tz: string, now = Date.now()): string {
  if (!due) return "";
  if (due < now) return `已逾期（${fmtWhen(due, tz)}）`;
  return `截止 ${fmtWhen(due, tz)}`;
}

function consoleLink(ctx: CtxRenderCtx, path: string): string {
  return consoleLinkUrl(ctx.consoleBase, path, ctx.consoleTicket);
}

/** 一件事的一行描述 + 操作按钮 */
function itemBlock(it: CtxItemView, cardKey: string, ctx: CtxRenderCtx, o: { draftable: boolean; index?: number }): El[] {
  const meta = [
    it.project_name ? esc(it.project_name) : "",
    it.counterpart ? `对方 ${esc(it.counterpart)}` : "",
    dueText(it.due, ctx.timezone),
    it.why.filter((w) => w !== KIND_LABEL[it.kind]).slice(0, 2).join(" · "),
  ].filter(Boolean);
  const title = `${o.index !== undefined ? `${o.index + 1}. ` : ""}**${link(truncate(it.title, 60), it.url)}**`;
  const next = it.next_step ? `\n${grey(`建议：${esc(truncate(it.next_step, 80))}`)}` : "";
  const lines = `<text_tag color='${tagColor(it.kind)}'>${KIND_LABEL[it.kind] ?? it.kind}</text_tag> ${title}\n${grey(meta.join(" ｜ "))}${next}`;
  const v = (cmd: CommandName, args: Record<string, unknown> = {}): ActionValue => ({ cmd, args: { id: it.id, ...args }, card: cardKey });
  const buttons: El[] = [button("完成", v("context.item_done")), button("稍后", v("context.item_snooze", { hours: 4 })), button("不对", v("context.feedback", { entity: "item", verdict: "wrong" }))];
  if (o.draftable) buttons.push(button("起草", { cmd: "context.draft_create", args: { item_id: it.id }, card: cardKey }));
  return [md(lines), buttonRow(buttons.map((b) => ({ ...b, size: "small" })))];
}

function tagColor(kind: string): string {
  return ({ ask_me: "orange", my_commitment: "violet", risk: "red", waiting_on: "neutral", meeting_action: "blue", todo: "wathet" } as Record<string, string>)[kind] ?? "neutral";
}

function conflictBlock(c: CtxConflictView, cardKey: string, ctx: CtxRenderCtx): El[] {
  const nums = ["①", "②", "③", "④", "⑤"];
  const lines = c.claims
    .slice(0, 5)
    .map((cl, i) => `${nums[i]} ${esc(truncate(cl.claim, 80))} ${grey(`${fmtWhen(cl.time, ctx.timezone)}「${esc(truncate(cl.quote, 40))}」`)}${isUrl(cl.url) ? ` [原文](${cl.url})` : ""}`);
  const buttons = c.claims.slice(0, 3).map((_, i) => button(`以${nums[i]}为准`, { cmd: "context.conflict_resolve", args: { id: c.id, choice: i }, card: cardKey }));
  return [md(`⚖️ **${esc(c.topic)}**${c.project_name ? ` ${grey(esc(c.project_name))}` : ""}\n${lines.join("\n")}`), buttonRow(buttons.map((b) => ({ ...b, size: "small" })))];
}

function meetingsMd(ms: CtxMeeting[], tz: string): string {
  return ms
    .slice(0, 8)
    .map((m) => `- ${fmtWhen(m.start, tz, false)}–${fmtWhen(m.end, tz, false)} ${link(truncate(m.summary, 40), m.url)}`)
    .join("\n");
}

function changesMd(us: CtxUpdateView[], tz: string): string {
  return us
    .slice(0, 6)
    .map((u) => `- ${grey(fmtWhen(u.time, tz))} ${u.project_name ? `**${esc(u.project_name)}**：` : ""}${esc(truncate(u.summary, 90))}`)
    .join("\n");
}

/** 晨间卡 */
export function morningCard(t: CtxToday, ctx: CtxRenderCtx, draftable: (it: CtxItemView) => boolean): Card {
  const key = `ctx-morning:${t.date}`;
  const elements: El[] = [];
  const focus = t.focus.slice(0, 5);
  const asks = t.asks.length;
  const overdue = t.focus.filter((i) => i.due && i.due < Date.now()).length;
  const summary = [asks ? `${asks} 件别人在等你` : "", t.commitments.length ? `${t.commitments.length} 件你答应过` : "", overdue ? `${overdue} 件已逾期` : "", t.conflicts.length ? `${t.conflicts.length} 处说法不一致` : ""]
    .filter(Boolean)
    .join("，");
  elements.push(md(summary ? `今天：${summary}。` : "今天没有特别紧急的事。"));
  if (focus.length) {
    elements.push(md("**🎯 先做这几件**"));
    focus.forEach((it, i) => elements.push(...itemBlock(it, key, ctx, { draftable: draftable(it), index: i })));
  }
  if (t.conflicts.length) {
    elements.push({ tag: "hr" }, md("**⚖️ 需要你判断**"));
    for (const c of t.conflicts.slice(0, 2)) elements.push(...conflictBlock(c, key, ctx));
  }
  if (t.drafts.length) {
    elements.push({ tag: "hr" }, md(`**✍️ ${t.drafts.length} 份草稿待你确认**\n${t.drafts.slice(0, 3).map((d) => `- ${DRAFT_LABEL[d.kind]}：${esc(d.target_label)}`).join("\n")}`));
  }
  if (t.meetings.length) elements.push({ tag: "hr" }, md(`**📅 今天的会**\n${meetingsMd(t.meetings, ctx.timezone)}`));
  if (t.changes.length) elements.push({ tag: "hr" }, md(`**🔄 过去 24 小时**\n${changesMd(t.changes, ctx.timezone)}`));
  if (t.needs_review.length) elements.push(md(grey(`另有 ${t.needs_review.length} 件识别把握不大，在控制台「事项 · 待确认」里`)));
  const url = consoleLink(ctx, "/today");
  if (url) elements.push(linkButton("打开今天", url, "primary_filled", true));
  elements.push(...noticeEl(ctx.notice));
  return card(header(`今天 · ${t.date.slice(5)}`, "wathet", summary || "工作上下文"), elements, `今天：${summary || "没有紧急的事"}`);
}

/** 收尾卡 */
export function eveningCard(
  v: { date: string; closed: CtxItemView[]; asks: CtxItemView[]; tomorrow: CtxItemView[]; changes: CtxUpdateView[] },
  ctx: CtxRenderCtx,
): Card {
  const key = `ctx-evening:${v.date}`;
  const elements: El[] = [];
  elements.push(md(v.closed.length ? `**✅ 今天关掉了 ${v.closed.length} 件**\n${v.closed.slice(0, 8).map((i) => `- ${esc(truncate(i.title, 60))}${i.close_reason ? grey(`（${esc(truncate(i.close_reason, 30))}）`) : ""}`).join("\n")}` : "今天没有关掉的事。"));
  if (v.asks.length) {
    elements.push({ tag: "hr" }, md(`**⏳ 还欠着别人 ${v.asks.length} 件**`));
    v.asks.slice(0, 3).forEach((it) => elements.push(...itemBlock(it, key, ctx, { draftable: true })));
  }
  if (v.tomorrow.length) elements.push({ tag: "hr" }, md(`**➡️ 明天先做**\n${v.tomorrow.slice(0, 3).map((i, n) => `${n + 1}. ${esc(truncate(i.title, 60))}`).join("\n")}`));
  if (v.changes.length) elements.push({ tag: "hr" }, md(`**🔄 今天的动态**\n${changesMd(v.changes, ctx.timezone)}`));
  const url = consoleLink(ctx, "/today");
  if (url) elements.push(linkButton("打开控制台", url, "default", true));
  elements.push(...noticeEl(ctx.notice));
  return card(header(`收尾 · ${v.date.slice(5)}`, "indigo", `关掉 ${v.closed.length} · 欠 ${v.asks.length}`), elements, `今日收尾：关掉 ${v.closed.length} 件`);
}

/** 实时提醒卡（一件事） */
export function itemCard(it: CtxItemDetail, ctx: CtxRenderCtx, draftable: boolean): Card {
  const key = `ctx-item:${it.id}`;
  const status =
    it.status === "done"
      ? { text: "已完成", color: "green" }
      : it.status === "dismissed"
        ? { text: "已忽略", color: "grey" }
        : it.status === "snoozed"
          ? { text: "稍后提醒", color: "grey" }
          : it.kind === "risk"
            ? { text: "风险", color: "red" }
            : { text: KIND_LABEL[it.kind] ?? "需要你", color: "orange" };
  const lines = [
    it.project_name ? `**项目**　${esc(it.project_name)}` : "",
    it.counterpart ? `**对方**　${esc(it.counterpart)}` : "",
    it.due ? `**时间**　${dueText(it.due, ctx.timezone)}` : "",
    it.next_step ? `**建议**　${esc(truncate(it.next_step, 120))}` : "",
    it.why.length ? grey(`为什么提醒你：${it.why.join(" · ")}`) : "",
  ].filter(Boolean);
  const elements: El[] = [md(lines.join("\n"))];
  const ev = it.evidence.slice(0, 3);
  if (ev.length) {
    elements.push(
      md(
        ev
          .map((e) => `> ${esc(e.actor_name || "")}${e.conv_name ? grey(` · ${esc(e.conv_name)}`) : ""} ${grey(fmtWhen(e.time, ctx.timezone))}\n> ${esc(truncate(e.quote, 120))}${isUrl(e.url) ? ` [原文](${e.url})` : ""}`)
          .join("\n\n"),
      ),
    );
  }
  if (it.status === "open") {
    const v = (cmd: CommandName, args: Record<string, unknown> = {}): ActionValue => ({ cmd, args: { id: it.id, ...args }, card: key });
    const buttons: El[] = [];
    if (draftable) buttons.push(button("起草回复", { cmd: "context.draft_create", args: { item_id: it.id }, card: key }));
    buttons.push(button("完成", v("context.item_done")), button("2 小时后", v("context.item_snooze", { hours: 2 })), button("明天", v("context.item_snooze", { hours: 16 })));
    buttons.push(button("不对", v("context.feedback", { entity: "item", verdict: "wrong" })), button("不重要", v("context.feedback", { entity: "item", verdict: "unimportant" })));
    if (isUrl(it.url)) buttons.push(linkButton("打开原文", it.url));
    elements.push(buttonRow(buttons));
  } else if (it.status === "done" || it.status === "dismissed" || it.status === "snoozed") {
    elements.push(buttonRow([button("重新打开", { cmd: "context.item_reopen", args: { id: it.id }, card: key })]));
  }
  elements.push(...noticeEl(ctx.notice));
  return card(header(truncate(it.title, 60), status.color, KIND_LABEL[it.kind] ?? "提醒", status), elements, `${KIND_LABEL[it.kind] ?? "提醒"}：${it.title}`);
}

/** 草稿卡：可编辑后确认发送 */
export function draftCard(d: CtxDraftView, ctx: CtxRenderCtx, itemTitle = ""): Card {
  const key = `ctx-draft:${d.id}`;
  const label = DRAFT_LABEL[d.kind] ?? "草稿";
  const status = (
    {
      proposed: { text: "待你确认", color: "orange" },
      approved: { text: "发送中", color: "blue" },
      sent: { text: "已发送", color: "green" },
      failed: { text: "发送失败", color: "red" },
      discarded: { text: "已丢弃", color: "grey" },
    } as const
  )[d.status];
  const elements: El[] = [md(`**发到**　${esc(d.target_label)}${isUrl(d.url) ? ` [打开](${d.url})` : ""}${itemTitle ? `\n**事项**　${esc(truncate(itemTitle, 60))}` : ""}`)];
  if (d.status === "proposed" || d.status === "failed") {
    if (d.error) elements.push(md(`⚠️ ${esc(truncate(d.error, 300))}`));
    elements.push(
      form("f_draft", [input("content", { placeholder: "草稿内容", multiline: true, maxLength: 4000, value: d.content, label: "确认前可以直接修改" })], {
        text: d.status === "failed" ? "重新发送" : `以我的身份发送${d.kind === "weekly_report" ? "（新建文档）" : ""}`,
        name: "btn_draft_send",
        value: { cmd: "context.draft_approve", args: { id: d.id }, card: key },
        type: "primary_filled",
      }),
      buttonRow([button("丢弃", { cmd: "context.draft_discard", args: { id: d.id }, card: key }, { type: "danger" })]),
    );
  } else {
    elements.push(md(grey(esc(truncate(d.content, 1500)))));
  }
  elements.push(...noticeEl(ctx.notice));
  return card(header(`${label}草稿`, status.color, truncate(d.target_label, 40), status), elements, `${label}草稿：${d.target_label}`);
}
