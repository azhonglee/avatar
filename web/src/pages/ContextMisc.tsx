import { useState } from "react";
import { Link } from "react-router-dom";
import type { CtxDraftView, CtxKnowledgeView, CtxPersonView, CtxUpdateView } from "../api/types.ts";
import { DraftList, EvidenceList, projectHref } from "../components/context.tsx";
import { Card, Collapsible, Empty, PageHeader, Pill, QueryView, RelTime, Tabs } from "../components/ui.tsx";
import { useCommand } from "../lib/command.ts";
import { useQuery } from "../lib/query.ts";
import { KNOW_KIND } from "./Projects.tsx";

export function KnowledgePage() {
  const [q, setQ] = useState("");
  const [term, setTerm] = useState("");
  const list = useQuery<CtxKnowledgeView[]>(`/api/context/knowledge${term ? `?q=${encodeURIComponent(term)}` : ""}`, { tags: ["context"] });
  const cmd = useCommand();
  return (
    <div className="page">
      <PageHeader
        title="知识"
        subtitle="从讨论和会议里沉淀的决策、结论、做法和关键文档。每条都能回到原文。"
        actions={
          <form
            onSubmit={(e) => {
              e.preventDefault();
              setTerm(q.trim());
            }}
          >
            <input className="input input-sm search" type="search" placeholder="搜索知识" value={q} onChange={(e) => setQ(e.target.value)} aria-label="搜索知识" />
          </form>
        }
      />
      <QueryView q={list} what="知识">
        {(ks) =>
          ks.length ? (
            <div className="know-grid">
              {ks.map((k) => (
                <Card key={k.id}>
                  <div className="row-gap">
                    <Pill tone={k.kind === "decision" ? "success" : "info"}>{KNOW_KIND[k.kind] ?? k.kind}</Pill>
                    <strong>{k.title}</strong>
                  </div>
                  <div className="wrap">{k.content}</div>
                  <div className="row-gap small muted">
                    {k.project_name && <Link to={projectHref(k.project_id)}>{k.project_name}</Link>}
                    <RelTime ts={k.updated} prefix="更新于 " />
                    <span className="spacer" />
                    <button className="btn btn-sm btn-ghost" disabled={cmd.isPending(`k:${k.id}`)} onClick={() => void cmd.run("context.feedback", { entity: "knowledge", id: k.id, verdict: "wrong" }, { key: `k:${k.id}` })}>
                      不对，删除
                    </button>
                  </div>
                  <Collapsible summary={`依据 ${k.evidence.length}`}>
                    <EvidenceList ev={k.evidence} />
                  </Collapsible>
                </Card>
              ))}
            </div>
          ) : (
            <Empty title={term ? "没有匹配的知识" : "还没有沉淀知识"} icon="❖" />
          )
        }
      </QueryView>
    </div>
  );
}

function dayKey(ts: number): string {
  const d = new Date(ts);
  return `${d.getMonth() + 1} 月 ${d.getDate()} 日`;
}

export function UpdatesPage() {
  const [days, setDays] = useState<"1" | "7" | "30">("7");
  const list = useQuery<CtxUpdateView[]>(`/api/context/updates?days=${days}`, { tags: ["context"] });
  return (
    <div className="page">
      <PageHeader
        title="动态"
        subtitle="项目层面的重要变化：上线、延期、方案变更、事故、状态流转。"
        actions={<Tabs label="时间范围" value={days} onChange={setDays} items={[{ key: "1", label: "24 小时" }, { key: "7", label: "7 天" }, { key: "30", label: "30 天" }]} />}
      />
      <QueryView q={list} what="动态">
        {(us) => {
          if (!us.length) return <Empty title="这段时间没有动态" icon="~" />;
          const groups = new Map<string, CtxUpdateView[]>();
          for (const u of us) {
            const k = dayKey(u.time);
            if (!groups.has(k)) groups.set(k, []);
            groups.get(k)!.push(u);
          }
          return (
            <>
              {[...groups.entries()].map(([day, items]) => (
                <Card key={day} title={day}>
                  <ul className="upd-list">
                    {items.map((u) => (
                      <li key={u.id}>
                        <div className="small muted">
                          <RelTime ts={u.time} /> {u.project_name && <Link to={projectHref(u.project_id)}>{u.project_name}</Link>}
                        </div>
                        <div>{u.summary}</div>
                        {u.evidence.length > 0 && (
                          <Collapsible summary="原文">
                            <EvidenceList ev={u.evidence} />
                          </Collapsible>
                        )}
                      </li>
                    ))}
                  </ul>
                </Card>
              ))}
            </>
          );
        }}
      </QueryView>
    </div>
  );
}

export function PeoplePage() {
  const list = useQuery<CtxPersonView[]>("/api/context/people", { tags: ["context"] });
  return (
    <div className="page">
      <PageHeader title="人" subtitle="和你一起工作的人：关系、共同的项目、还有几件事和他有关。" />
      <Card>
        <QueryView q={list} what="人">
          {(ps) =>
            ps.length ? (
              <table className="table">
                <thead>
                  <tr>
                    <th>姓名</th>
                    <th>关系</th>
                    <th>项目</th>
                    <th className="num">相关事项</th>
                    <th>最近</th>
                  </tr>
                </thead>
                <tbody>
                  {ps.map((p) => (
                    <tr key={p.id}>
                      <td>
                        <strong>{p.name}</strong>
                      </td>
                      <td>{p.relation || <span className="muted">—</span>}</td>
                      <td className="small">{p.projects.join("、") || <span className="muted">—</span>}</td>
                      <td className="num">{p.open_items ? <Link to={`/items?q=${encodeURIComponent(p.name)}`}>{p.open_items}</Link> : 0}</td>
                      <td>
                        <RelTime ts={p.last_seen} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <Empty title="还没有识别出相关的人" icon="☺" />
            )
          }
        </QueryView>
      </Card>
    </div>
  );
}

type DraftTab = "proposed,failed" | "approved,sent" | "discarded";

export function DraftsPage() {
  const [tab, setTab] = useState<DraftTab>("proposed,failed");
  const list = useQuery<CtxDraftView[]>(`/api/context/drafts?status=${tab}`, { tags: ["context"] });
  const cmd = useCommand();
  return (
    <div className="page">
      <PageHeader
        title="草稿"
        subtitle="我帮你起草的回复、跟进、Meego 评论和周报。只有你确认后，才会以你本人的身份发出。"
        actions={
          <button className="btn btn-sm" disabled={cmd.isPending("context.weekly_report")} onClick={() => void cmd.run("context.weekly_report", { days: 7 })}>
            起草本周周报
          </button>
        }
      />
      <Tabs
        label="草稿状态"
        value={tab}
        onChange={setTab}
        items={[
          { key: "proposed,failed", label: "待确认" },
          { key: "approved,sent", label: "已发送" },
          { key: "discarded", label: "已丢弃" },
        ]}
      />
      <QueryView q={list} what="草稿">
        {(ds) => <DraftList drafts={ds} empty={<Empty title={tab === "proposed,failed" ? "没有待确认的草稿" : "没有草稿"} icon="✎" />} />}
      </QueryView>
    </div>
  );
}
