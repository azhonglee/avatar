import { useState } from "react";
import { Link } from "react-router-dom";
import type { CandidateList, CandidateView } from "../api/types.ts";
import { Dialog, Empty, ExternalLink, Field, PageHeader, Pill, QueryView, RelTime, Spinner, Stat, Tabs, Unavailable } from "../components/ui.tsx";
import { useCommand } from "../lib/command.ts";
import { pct } from "../lib/format.ts";
import { useMeta } from "../lib/meta.ts";
import { useQuery } from "../lib/query.ts";

type Fb = "" | "confirmed" | "rejected" | "all";
const FB_TABS: { key: "pending" | "confirmed" | "rejected" | "all"; label: string }[] = [
  { key: "pending", label: "待确认" },
  { key: "confirmed", label: "已确认" },
  { key: "rejected", label: "已驳回" },
  { key: "all", label: "全部" },
];

function Confidence({ v }: { v: number | null }) {
  if (v === null) return null;
  const tone = v >= 0.85 ? "success" : v >= 0.6 ? "info" : "warn";
  return (
    <span className="conf" title="分诊模型给出的置信度">
      <span className="conf-track" aria-hidden>
        <span className={`conf-fill bar-${tone}`} style={{ width: `${Math.round(v * 100)}%` }} />
      </span>
      置信度 {pct(v)}
    </span>
  );
}

function CandidateItem({ c }: { c: CandidateView }) {
  const meta = useMeta();
  const cmd = useCommand();
  const [dlg, setDlg] = useState<"reject" | "dispatch" | null>(null);
  const [reason, setReason] = useState("");
  const [harness, setHarness] = useState("");
  const [repo, setRepo] = useState("");
  const [expanded, setExpanded] = useState(false);
  const k = (n: string) => `${n}:${c.signal_id}`;
  const long = c.text.length > 280;
  return (
    <li className="cand">
      <div className="cand-head">
        <Pill tone="neutral">{c.source}</Pill>
        <RelTime ts={c.at} />
        {c.feedback === "confirmed" && <Pill tone="success">已确认是任务</Pill>}
        {c.feedback === "rejected" && <Pill tone="muted">已驳回</Pill>}
        <span className="spacer" />
        <Confidence v={c.confidence} />
      </div>
      {c.summary && <div className="cand-title">{c.summary}</div>}
      <blockquote className={`cand-text ${long && !expanded ? "clamp" : ""}`}>{c.text}</blockquote>
      {long && (
        <button className="btn btn-link small" onClick={() => setExpanded((v) => !v)} aria-expanded={expanded}>
          {expanded ? "收起" : "展开全文"}
        </button>
      )}
      {c.verdict && (
        <div className="cand-why">
          <span className="muted">判断依据：</span>
          {c.verdict}
        </div>
      )}
      <div className="cand-foot">
        <span className="row-gap small">
          {c.link && <ExternalLink href={c.link}>查看原文</ExternalLink>}
          {c.task_url && <ExternalLink href={c.task_url}>飞书任务</ExternalLink>}
        </span>
        {c.feedback === "" && (
          <span className="row-gap">
            <button className="btn btn-sm btn-primary" disabled={cmd.isPending(k("confirm"))} onClick={() => void cmd.run("candidate.confirm", { signal_id: c.signal_id }, { key: k("confirm") })}>
              {cmd.isPending(k("confirm")) && <Spinner />}是任务
            </button>
            <button className="btn btn-sm" onClick={() => (setReason(""), setDlg("reject"))}>
              不是任务
            </button>
            <button className="btn btn-sm" onClick={() => (setHarness(""), setRepo(""), setDlg("dispatch"))}>
              派给 Agent
            </button>
          </span>
        )}
      </div>
      <Dialog
        open={dlg === "reject"}
        title="不是任务"
        onClose={() => setDlg(null)}
        footer={
          <>
            <button className="btn" onClick={() => setDlg(null)}>
              取消
            </button>
            <button
              className="btn btn-primary"
              disabled={cmd.isPending(k("reject"))}
              onClick={async () => {
                const r = await cmd.run("candidate.reject", { signal_id: c.signal_id, reason: reason.trim() || undefined }, { key: k("reject") });
                if (r?.ok) setDlg(null);
              }}
            >
              {cmd.isPending(k("reject")) && <Spinner />}确认驳回
            </button>
          </>
        }
      >
        <p className="muted">驳回会作为反例交给分诊，类似的消息以后会更少被误判成任务。{c.task_url ? "已创建的飞书任务会被移除。" : ""}</p>
        <Field label="原因（可选）" htmlFor={`rj-${c.signal_id}`}>
          <input id={`rj-${c.signal_id}`} className="input" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="例如：只是通知，不需要我做什么" data-autofocus />
        </Field>
      </Dialog>
      <Dialog
        open={dlg === "dispatch"}
        title="派给 Agent"
        onClose={() => setDlg(null)}
        footer={
          <>
            <button className="btn" onClick={() => setDlg(null)}>
              取消
            </button>
            <button
              className="btn btn-primary"
              disabled={cmd.isPending(k("dispatch"))}
              onClick={async () => {
                const r = await cmd.run("candidate.dispatch", { signal_id: c.signal_id, harness: harness || undefined, repo: repo || undefined }, { key: k("dispatch") });
                if (r?.ok) setDlg(null);
              }}
            >
              {cmd.isPending(k("dispatch")) && <Spinner />}派出去
            </button>
          </>
        }
      >
        <p className="muted">会确认这是任务，并直接派给执行者。</p>
        <div className="form-row">
          <Field label="执行者" htmlFor={`cd-h-${c.signal_id}`}>
            <select id={`cd-h-${c.signal_id}`} className="input" value={harness} onChange={(e) => setHarness(e.target.value)} data-autofocus>
              <option value="">默认（{meta.roles.default_harness}）</option>
              {meta.harnesses.map((h) => (
                <option key={h}>{h}</option>
              ))}
            </select>
          </Field>
          <Field label="仓库" htmlFor={`cd-r-${c.signal_id}`}>
            <select id={`cd-r-${c.signal_id}`} className="input" value={repo} onChange={(e) => setRepo(e.target.value)}>
              <option value="">不指定</option>
              {meta.repos.map((r) => (
                <option key={r.alias}>{r.alias}</option>
              ))}
            </select>
          </Field>
        </div>
      </Dialog>
    </li>
  );
}

export function CandidatesPage() {
  const meta = useMeta();
  const [tab, setTab] = useState<(typeof FB_TABS)[number]["key"]>("pending");
  const [days, setDays] = useState(14);
  const fb: Fb = tab === "pending" ? "" : tab;
  const q = useQuery<CandidateList>(meta.features.candidates ? `/api/candidates?days=${days}&feedback=${fb}` : null, { tags: ["candidates"] });
  return (
    <div className="page">
      <PageHeader
        title="候选任务"
        subtitle="从消息、文档评论、会议妙记里识别出的可能要你做的事。确认或驳回会让识别越来越准。"
        actions={
          <label className="inline-select">
            <span className="muted small">时间范围</span>
            <select className="input input-sm" value={days} onChange={(e) => setDays(Number(e.target.value))}>
              <option value={7}>最近 7 天</option>
              <option value={14}>最近 14 天</option>
              <option value={30}>最近 30 天</option>
            </select>
          </label>
        }
      />
      {!meta.features.candidates ? (
        <Unavailable what="候选任务" />
      ) : (
      <QueryView q={q} what="候选任务">
        {(d) => (
          <>
            <div className="card">
              <div className="stats stats-5">
                <Stat label="识别准确率" value={pct(d.stats.precision)} tone={d.stats.precision !== null && d.stats.precision < 0.6 ? "warn" : "success"} sub="确认 ÷（确认 + 驳回）" />
                <Stat label="识别出" value={d.stats.created} />
                <Stat label="已确认" value={d.stats.confirmed} />
                <Stat label="已驳回" value={d.stats.rejected} />
                <Stat label="统计窗口" value={`${d.stats.window_days} 天`} />
              </div>
            </div>
            <Tabs label="按反馈筛选" value={tab} onChange={setTab} items={FB_TABS} />
            <div className="card">
              {d.items.length ? (
                <ul className="cand-list">
                  {d.items.map((c) => (
                    <CandidateItem key={c.signal_id} c={c} />
                  ))}
                </ul>
              ) : (
                <Empty title={tab === "pending" ? "没有待确认的候选任务" : "这个范围内没有记录"} icon="✓">
                  {tab === "pending" ? (
                    <>
                      新识别出的任务会实时出现在这里。也可以去 <Link to="/dispatches">派单</Link> 看看进展。
                    </>
                  ) : null}
                </Empty>
              )}
            </div>
          </>
        )}
      </QueryView>
      )}
    </div>
  );
}
