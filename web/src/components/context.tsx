import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import type { CtxConflictView, CtxDraftView, CtxEvidenceView, CtxItemKind, CtxItemView, CtxProjectSummary } from "../api/types.ts";
import { useCommand } from "../lib/command.ts";
import type { Tone } from "../lib/format.ts";
import { ConfirmDialog, Empty, ExternalLink, Pill, RelTime } from "./ui.tsx";

/** 工作上下文的共用组件：事项行、证据、草稿编辑、冲突、项目健康。 */

export const KIND_LABEL: Record<CtxItemKind, string> = {
  ask_me: "别人在等你",
  my_commitment: "你答应过",
  waiting_on: "你在等别人",
  risk: "风险",
  meeting_action: "会议行动项",
  todo: "待办",
};
const KIND_TONE: Record<CtxItemKind, Tone> = { ask_me: "warn", my_commitment: "info", waiting_on: "neutral", risk: "danger", meeting_action: "info", todo: "neutral" };
const SOURCE_LABEL: Record<string, string> = { meego: "Meego", im: "飞书消息", minutes: "妙记", task: "飞书任务", tasks: "飞书任务", calendar: "日历", doc: "文档评论", docs: "文档评论", manual: "手动" };
export const DRAFT_LABEL: Record<string, string> = { reply: "回复", followup: "跟进", meego_comment: "Meego 评论", weekly_report: "周报" };
export const HEALTH: Record<string, { label: string; tone: Tone }> = {
  ok: { label: "正常", tone: "success" },
  risk: { label: "有风险", tone: "warn" },
  blocked: { label: "受阻", tone: "danger" },
  unknown: { label: "未知", tone: "muted" },
};

export const itemHref = (id: string) => `/items/${encodeURIComponent(id)}`;
export const projectHref = (id: string) => `/projects/${encodeURIComponent(id)}`;

export function KindPill({ kind }: { kind: CtxItemKind }) {
  return <Pill tone={KIND_TONE[kind]}>{KIND_LABEL[kind]}</Pill>;
}

export function sourceLabel(s: string): string {
  return SOURCE_LABEL[s] ?? s;
}

function dueText(due: number | null): { text: string; tone: Tone } | null {
  if (!due) return null;
  const d = new Date(due);
  const p = (n: number) => String(n).padStart(2, "0");
  const s = `${d.getMonth() + 1}/${d.getDate()} ${p(d.getHours())}:${p(d.getMinutes())}`;
  if (due < Date.now()) return { text: `已逾期 ${s}`, tone: "danger" };
  if (due < Date.now() + 2 * 86_400_000) return { text: `截止 ${s}`, tone: "warn" };
  return { text: `截止 ${s}`, tone: "neutral" };
}

/** 事项的快捷操作（完成 / 稍后 / 不对 / 起草）。detail 页用更完整的操作栏。 */
export function ItemQuickActions({ it, compact }: { it: CtxItemView; compact?: boolean }) {
  const cmd = useCommand();
  const k = (n: string) => `${n}:${it.id}`;
  const busy = (n: string) => cmd.isPending(k(n));
  if (it.status !== "open") {
    return (
      <button className="btn btn-sm" disabled={busy("reopen")} onClick={() => void cmd.run("context.item_reopen", { id: it.id }, { key: k("reopen") })}>
        重新打开
      </button>
    );
  }
  return (
    <div className="row-gap">
      <button className="btn btn-sm btn-primary" disabled={busy("done")} onClick={() => void cmd.run("context.item_done", { id: it.id }, { key: k("done") })}>
        完成
      </button>
      <select
        className="input input-sm ctx-snooze"
        aria-label="稍后提醒"
        value=""
        disabled={busy("snooze")}
        onChange={(e) => {
          const hours = Number(e.target.value);
          if (hours) void cmd.run("context.item_snooze", { id: it.id, hours }, { key: k("snooze") });
        }}
      >
        <option value="">稍后…</option>
        <option value="2">2 小时后</option>
        <option value="16">明天</option>
        <option value="72">3 天后</option>
        <option value="168">下周</option>
      </select>
      {it.draft_kind && (
        <button className="btn btn-sm" disabled={busy("draft")} onClick={() => void cmd.run("context.draft_create", { item_id: it.id }, { key: k("draft") })}>
          起草{DRAFT_LABEL[it.draft_kind]}
        </button>
      )}
      <button
        className="btn btn-sm btn-ghost"
        title="识别错了：移除，并让之后的识别参考这次判断"
        disabled={busy("wrong")}
        onClick={() => void cmd.run("context.feedback", { entity: "item", id: it.id, verdict: "wrong" }, { key: k("wrong") })}
      >
        不对
      </button>
      {!compact && (
        <button className="btn btn-sm btn-ghost" disabled={busy("unimp")} onClick={() => void cmd.run("context.feedback", { entity: "item", id: it.id, verdict: "unimportant" }, { key: k("unimp") })}>
          不重要
        </button>
      )}
    </div>
  );
}

/** 一件事（列表行） */
export function ItemRow({ it, index, showProject = true, actions = true }: { it: CtxItemView; index?: number; showProject?: boolean; actions?: boolean }) {
  const due = dueText(it.due);
  return (
    <li className="attn-item ctx-item">
      <div className="attn-head">
        {index !== undefined && <span className="ctx-rank">{index + 1}</span>}
        <KindPill kind={it.kind} />
        <Link to={itemHref(it.id)} className="attn-title">
          {it.title}
        </Link>
        {it.needs_review && <Pill tone="warn">待确认</Pill>}
        {it.status !== "open" && <Pill tone="muted">{it.status === "done" ? "已完成" : it.status === "snoozed" ? "稍后" : "已忽略"}</Pill>}
      </div>
      <div className="attn-meta muted small">
        {showProject && it.project_name && <Link to={projectHref(it.project_id)}>{it.project_name}</Link>}
        {it.counterpart && <span>对方 {it.counterpart}</span>}
        {due && <Pill tone={due.tone}>{due.text}</Pill>}
        <span>{sourceLabel(it.source)}</span>
        <RelTime ts={it.last_seen} />
        {it.url && <ExternalLink href={it.url}>原文</ExternalLink>}
      </div>
      {it.next_step && <div className="attn-reason">建议：{it.next_step}</div>}
      {it.why.length > 0 && (
        <div className="ctx-why" aria-label="为什么排在这里">
          {it.why.map((w) => (
            <span key={w} className="chip">
              {w}
            </span>
          ))}
        </div>
      )}
      {actions && (
        <div className="attn-actions">
          <ItemQuickActions it={it} compact />
        </div>
      )}
    </li>
  );
}

export function ItemList({ items, empty, ranked, showProject }: { items: CtxItemView[]; empty: ReactNode; ranked?: boolean; showProject?: boolean }) {
  if (!items.length) return <>{empty}</>;
  return (
    <ul className="attn-list">
      {items.map((it, i) => (
        <ItemRow key={it.id} it={it} index={ranked ? i : undefined} showProject={showProject} />
      ))}
    </ul>
  );
}

export function EvidenceList({ ev, empty = "没有证据" }: { ev: CtxEvidenceView[]; empty?: string }) {
  if (!ev.length) return <p className="muted small">{empty}</p>;
  return (
    <ol className="ev-list">
      {ev.map((e) => (
        <li key={e.obs_id} className={`ev ${e.is_me ? "ev-me" : ""}`}>
          <div className="ev-head small">
            <strong>{e.actor_name || sourceLabel(e.source)}</strong>
            {e.conv_name && <span className="muted">{e.conv_name}</span>}
            <RelTime ts={e.time} />
            {e.url && <ExternalLink href={e.url}>打开</ExternalLink>}
          </div>
          <blockquote className="ev-quote">{e.quote}</blockquote>
        </li>
      ))}
    </ol>
  );
}

/** 草稿：可编辑，确认后以你本人身份发送（二次确认写明发到哪里）。 */
export function DraftEditor({ d }: { d: CtxDraftView }) {
  const cmd = useCommand();
  const [text, setText] = useState(d.content);
  const [confirm, setConfirm] = useState(false);
  const editable = d.status === "proposed" || d.status === "failed";
  const k = (n: string) => `${n}:${d.id}`;
  const status: Record<CtxDraftView["status"], { label: string; tone: Tone }> = {
    proposed: { label: "待你确认", tone: "warn" },
    approved: { label: "发送中", tone: "info" },
    sent: { label: "已发送", tone: "success" },
    failed: { label: "发送失败", tone: "danger" },
    discarded: { label: "已丢弃", tone: "muted" },
  };
  return (
    <div className="draft">
      <div className="draft-head">
        <Pill tone="neutral">{DRAFT_LABEL[d.kind]}</Pill>
        <span className="draft-target">{d.target_label}</span>
        <Pill tone={status[d.status].tone}>{status[d.status].label}</Pill>
        <span className="spacer" />
        {d.item_id && (
          <Link className="small" to={itemHref(d.item_id)}>
            查看事项
          </Link>
        )}
        {d.url && <ExternalLink href={d.url}>{d.status === "sent" && d.kind === "weekly_report" ? "打开文档" : "打开会话"}</ExternalLink>}
      </div>
      {d.error && <div className="inline-warn">{d.error}</div>}
      {editable ? (
        <>
          <textarea className="input textarea draft-text" aria-label="草稿内容" value={text} onChange={(e) => setText(e.target.value)} rows={Math.min(14, Math.max(3, text.split("\n").length + 1))} />
          <div className="row-gap">
            <button className="btn btn-sm btn-primary" disabled={!text.trim() || cmd.isPending(k("send"))} onClick={() => setConfirm(true)}>
              {d.status === "failed" ? "重新发送" : d.kind === "weekly_report" ? "新建文档" : "以我的身份发送"}
            </button>
            {text !== d.content && (
              <button className="btn btn-sm btn-ghost" onClick={() => setText(d.content)}>
                还原
              </button>
            )}
            <button className="btn btn-sm btn-danger-ghost" disabled={cmd.isPending(k("discard"))} onClick={() => void cmd.run("context.draft_discard", { id: d.id }, { key: k("discard") })}>
              丢弃
            </button>
            <span className="muted small">
              <RelTime ts={d.updated} prefix="起草于 " />
            </span>
          </div>
        </>
      ) : (
        <pre className="draft-sent wrap">{d.content}</pre>
      )}
      <ConfirmDialog
        open={confirm}
        title={d.kind === "weekly_report" ? "新建周报文档？" : "以你本人的身份发送？"}
        confirmLabel={d.kind === "weekly_report" ? "新建" : "发送"}
        danger={false}
        onClose={() => setConfirm(false)}
        onConfirm={() => {
          setConfirm(false);
          void cmd.run("context.draft_approve", { id: d.id, content: text }, { key: k("send") });
        }}
      >
        <p>
          {d.kind === "weekly_report" ? "将在「我的文档库」新建：" : "将发到："}
          <strong>{d.target_label}</strong>
        </p>
        <pre className="draft-sent wrap">{text}</pre>
      </ConfirmDialog>
    </div>
  );
}

export function DraftList({ drafts, empty }: { drafts: CtxDraftView[]; empty?: ReactNode }) {
  if (!drafts.length) return <>{empty ?? <Empty title="没有草稿" icon="✎" />}</>;
  return (
    <div className="draft-list">
      {drafts.map((d) => (
        <DraftEditor key={`${d.id}:${d.updated}`} d={d} />
      ))}
    </div>
  );
}

/** 冲突：几个说法并列，选一个为准（沉淀为决策知识），或写下最终结论。 */
export function ConflictBox({ c }: { c: CtxConflictView }) {
  const cmd = useCommand();
  const [custom, setCustom] = useState("");
  const k = `resolve:${c.id}`;
  return (
    <div className="conflict">
      <div className="conflict-head">
        <strong>{c.topic}</strong>
        {c.project_name && (
          <Link className="small" to={projectHref(c.project_id)}>
            {c.project_name}
          </Link>
        )}
        {c.status === "resolved" && <Pill tone="success">已确认：{c.resolution}</Pill>}
      </div>
      <ol className="claims">
        {c.claims.map((cl, i) => (
          <li key={`${i}-${cl.claim}`} className="claim">
            <div>
              <strong>{cl.claim}</strong>
              <div className="muted small">
                「{cl.quote}」 <RelTime ts={cl.time} /> {cl.url && <ExternalLink href={cl.url}>原文</ExternalLink>}
              </div>
            </div>
            {c.status === "open" && (
              <button className="btn btn-sm" disabled={cmd.isPending(k)} onClick={() => void cmd.run("context.conflict_resolve", { id: c.id, choice: i }, { key: k })}>
                以此为准
              </button>
            )}
          </li>
        ))}
      </ol>
      {c.status === "open" && (
        <form
          className="input-group"
          onSubmit={(e) => {
            e.preventDefault();
            if (custom.trim()) void cmd.run("context.conflict_resolve", { id: c.id, resolution: custom.trim() }, { key: k });
          }}
        >
          <input className="input input-sm" placeholder="都不对？写下最终结论" value={custom} onChange={(e) => setCustom(e.target.value)} aria-label="最终结论" />
          <button className="btn btn-sm" type="submit" disabled={!custom.trim() || cmd.isPending(k)}>
            确认
          </button>
        </form>
      )}
    </div>
  );
}

export function HealthPill({ p }: { p: Pick<CtxProjectSummary, "health" | "muted" | "status"> }) {
  if (p.muted) return <Pill tone="muted">已静音</Pill>;
  if (p.status !== "active") return <Pill tone="muted">{p.status === "legacy" ? "历史遗留" : "已归档"}</Pill>;
  const h = HEALTH[p.health] ?? HEALTH.unknown;
  return <Pill tone={h.tone}>{h.label}</Pill>;
}
