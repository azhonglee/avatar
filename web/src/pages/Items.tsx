import { useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import type { CtxItemDetail, CtxItemKind, CtxItemView } from "../api/types.ts";
import { DraftList, EvidenceList, ItemList, ItemQuickActions, KIND_LABEL, KindPill, projectHref, sourceLabel } from "../components/context.tsx";
import { Card, Dialog, Empty, ExternalLink, Field, PageHeader, Pill, QueryView, RelTime, Tabs } from "../components/ui.tsx";
import { useCommand } from "../lib/command.ts";
import { absTime, pct } from "../lib/format.ts";
import { useMeta } from "../lib/meta.ts";
import { useQuery } from "../lib/query.ts";

type Status = "open" | "review" | "snoozed" | "done" | "dismissed" | "all";
const STATUS_TABS: { key: Status; label: string }[] = [
  { key: "open", label: "未完成" },
  { key: "review", label: "待确认" },
  { key: "snoozed", label: "稍后" },
  { key: "done", label: "已完成" },
  { key: "dismissed", label: "已忽略" },
  { key: "all", label: "全部" },
];

export function ItemsPage() {
  const [sp, setSp] = useSearchParams();
  const status = (sp.get("status") as Status) || "open";
  const kind = sp.get("kind") ?? "";
  const [q, setQ] = useState(sp.get("q") ?? "");
  const set = (k: string, v: string) => {
    const n = new URLSearchParams(sp);
    if (v) n.set(k, v);
    else n.delete(k);
    setSp(n, { replace: true });
  };
  const qs = new URLSearchParams({ status, ...(kind ? { kind } : {}), ...(sp.get("q") ? { q: sp.get("q")! } : {}) });
  const list = useQuery<CtxItemView[]>(`/api/context/items?${qs}`, { tags: ["context"] });
  return (
    <div className="page">
      <PageHeader title="事项" subtitle="所有识别出来的待办、请求、承诺和风险。按重要程度排序，每件都能追溯到原始消息。" />
      <div className="toolbar">
        <Tabs label="状态" value={status} onChange={(v) => set("status", v === "open" ? "" : v)} items={STATUS_TABS} />
        <div className="row-gap">
          <select className="input input-sm" aria-label="类型" value={kind} onChange={(e) => set("kind", e.target.value)}>
            <option value="">全部类型</option>
            {(Object.keys(KIND_LABEL) as CtxItemKind[]).map((k) => (
              <option key={k} value={k}>
                {KIND_LABEL[k]}
              </option>
            ))}
          </select>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              set("q", q.trim());
            }}
          >
            <input className="input input-sm search" type="search" placeholder="搜索标题、对方、项目" value={q} onChange={(e) => setQ(e.target.value)} aria-label="搜索事项" />
          </form>
        </div>
      </div>
      <Card>
        <QueryView q={list} what="事项">
          {(items) => (
            <>
              <ItemList items={items} ranked={status === "open"} empty={<Empty title={status === "review" ? "没有需要确认的识别结果" : "没有符合条件的事项"} icon="✓" />} />
              {items.length >= 500 && <p className="muted small">只显示前 500 件，请用搜索或筛选缩小范围。</p>}
            </>
          )}
        </QueryView>
      </Card>
    </div>
  );
}

function DelegateDialog({ it, open, onClose }: { it: CtxItemDetail; open: boolean; onClose: () => void }) {
  const meta = useMeta();
  const cmd = useCommand();
  const [harness, setHarness] = useState(meta.roles.default_harness || "");
  const [repo, setRepo] = useState("");
  return (
    <Dialog
      open={open}
      title="交给 Agent 执行"
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            取消
          </button>
          <button
            className="btn btn-primary"
            disabled={cmd.isPending("delegate")}
            onClick={async () => {
              const r = await cmd.run("context.item_delegate", { id: it.id, harness: harness || undefined, repo: repo || undefined }, { key: "delegate" });
              if (r?.ok) onClose();
            }}
          >
            新建派单
          </button>
        </>
      }
    >
      <p className="small">会新建一个派单，标题是这件事，描述里附上来自工作上下文的背景和原文链接。执行结果在「派单」里验收。</p>
      <Field label="执行者" htmlFor="dl-h">
        <select id="dl-h" className="input" value={harness} onChange={(e) => setHarness(e.target.value)} data-autofocus>
          <option value="">默认</option>
          {meta.harnesses.map((h) => (
            <option key={h} value={h}>
              {h}
            </option>
          ))}
        </select>
      </Field>
      <Field label="仓库" htmlFor="dl-r" hint="代码类任务选择仓库；其他任务可不选">
        <select id="dl-r" className="input" value={repo} onChange={(e) => setRepo(e.target.value)}>
          <option value="">不指定</option>
          {meta.repos.map((r) => (
            <option key={r.alias} value={r.alias}>
              {r.alias}
            </option>
          ))}
        </select>
      </Field>
    </Dialog>
  );
}

export function ItemDetailPage() {
  const { id = "" } = useParams();
  const q = useQuery<CtxItemDetail>(`/api/context/items/${encodeURIComponent(id)}`, { tags: ["context"] });
  const [delegate, setDelegate] = useState(false);
  return (
    <div className="page page-detail">
      <div className="crumbs small">
        <Link to="/items">事项</Link> /
      </div>
      <QueryView q={q} what="事项">
        {(it) => (
          <>
            <PageHeader
              title={
                <span className="row-gap">
                  <KindPill kind={it.kind} /> {it.title}
                </span>
              }
              subtitle={it.next_step ? `建议下一步：${it.next_step}` : undefined}
            />
            <div className="grid-overview">
              <div className="col-main">
                <Card title="原始消息与依据">
                  <EvidenceList ev={it.evidence} />
                </Card>
                {(it.drafts.length > 0 || it.draft_kind) && (
                  <Card title="草稿">
                    <DraftList drafts={it.drafts} empty={<p className="muted small">还没有草稿。点「起草」让我按上下文帮你写一版，确认后才会发出。</p>} />
                  </Card>
                )}
              </div>
              <div className="col-side">
                <Card title="操作">
                  <ItemQuickActions it={it} />
                  {it.actions.includes("context.item_delegate") && (
                    <button className="btn btn-sm" onClick={() => setDelegate(true)}>
                      交给 Agent…
                    </button>
                  )}
                </Card>
                <Card title="信息">
                  <dl className="kv">
                    <dt>状态</dt>
                    <dd>
                      {{ open: "未完成", done: "已完成", dismissed: "已忽略", snoozed: "稍后" }[it.status]}
                      {it.status === "snoozed" && it.snooze_until && <RelTime ts={it.snooze_until} prefix=" · " />}
                      {it.close_reason && <div className="muted small">{it.close_reason}</div>}
                    </dd>
                    {it.project_name && (
                      <>
                        <dt>项目</dt>
                        <dd>
                          <Link to={projectHref(it.project_id)}>{it.project_name}</Link>
                        </dd>
                      </>
                    )}
                    {it.counterpart && (
                      <>
                        <dt>对方</dt>
                        <dd>{it.counterpart}</dd>
                      </>
                    )}
                    {it.due && (
                      <>
                        <dt>截止</dt>
                        <dd>{absTime(it.due).slice(0, 16)}</dd>
                      </>
                    )}
                    <dt>优先级</dt>
                    <dd>{{ high: "高", medium: "中", low: "低" }[it.priority]}</dd>
                    <dt>来源</dt>
                    <dd>
                      {sourceLabel(it.source)} {it.url && <ExternalLink href={it.url}>打开</ExternalLink>}
                    </dd>
                    <dt>首次出现</dt>
                    <dd>
                      <RelTime ts={it.first_seen} />
                    </dd>
                    <dt>识别把握</dt>
                    <dd>
                      {pct(it.confidence)} {it.needs_review && <Pill tone="warn">待确认</Pill>}
                    </dd>
                    <dt>排序依据</dt>
                    <dd>
                      {it.why.join(" · ")}（{it.score} 分）
                    </dd>
                  </dl>
                </Card>
              </div>
            </div>
            <DelegateDialog it={it} open={delegate} onClose={() => setDelegate(false)} />
          </>
        )}
      </QueryView>
    </div>
  );
}
