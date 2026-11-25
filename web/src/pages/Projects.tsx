import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import type { CtxProjectDetail, CtxProjectSummary } from "../api/types.ts";
import { ConflictBox, EvidenceList, HealthPill, ItemList, projectHref } from "../components/context.tsx";
import { Card, Collapsible, Empty, PageHeader, Pill, QueryView, RelTime, Tabs } from "../components/ui.tsx";
import { useCommand } from "../lib/command.ts";
import { useQuery } from "../lib/query.ts";

function MuteButton({ p }: { p: Pick<CtxProjectSummary, "id" | "muted" | "status"> }) {
  const cmd = useCommand();
  const muted = p.muted || p.status !== "active";
  return (
    <button className="btn btn-sm btn-ghost" disabled={cmd.isPending(`mute:${p.id}`)} onClick={() => void cmd.run("context.project_mute", { id: p.id, muted: !muted }, { key: `mute:${p.id}` })}>
      {muted ? "恢复" : "静音"}
    </button>
  );
}

export function ProjectsPage() {
  const [legacy, setLegacy] = useState(false);
  const q = useQuery<CtxProjectSummary[]>(`/api/context/projects${legacy ? "?legacy=1" : ""}`, { tags: ["context"] });
  return (
    <div className="page">
      <PageHeader
        title="项目"
        subtitle="从 Meego、消息和会议里识别出的长期工作单元。静音的项目不会出现在「今天」。"
        actions={
          <label className="row-gap small">
            <input type="checkbox" checked={legacy} onChange={(e) => setLegacy(e.target.checked)} /> 显示已静音 / 历史遗留
          </label>
        }
      />
      <QueryView q={q} what="项目">
        {(list) => {
          if (!list.length)
            return (
              <Empty title="还没有识别出项目" icon="◇">
                采集并理解消息后，这里会列出你参与的项目。
              </Empty>
            );
          // 两层：顶层项目下面列出它的子项目
          const ids = new Set(list.map((p) => p.id));
          const tops = list.filter((p) => !p.parent_id || !ids.has(p.parent_id));
          return (
            <div className="proj-groups">
              {tops.map((t) => {
                const kids = list.filter((p) => p.parent_id === t.id);
                return (
                  <div key={t.id} className="proj-group">
                    <ProjectCard p={t} />
                    {kids.length > 0 && (
                      <div className="proj-grid proj-children">
                        {kids.map((c) => (
                          <ProjectCard key={c.id} p={c} />
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          );
        }}
      </QueryView>
    </div>
  );
}

function ProjectCard({ p }: { p: CtxProjectSummary }) {
  return (
    <section className={`card proj-card ${p.muted || p.status !== "active" ? "proj-dim" : ""} ${p.parent_id ? "proj-sub" : ""}`}>
      <div className="card-body">
        <div className="row-between">
          <Link to={projectHref(p.id)} className="proj-name">
            {p.name}
          </Link>
          <HealthPill p={p} />
        </div>
        {p.stage && <div className="small">{p.stage}</div>}
        {p.description && <div className="muted small clamp2">{p.description}</div>}
        <div className="row-gap small muted">
          {p.my_role && <span>我：{p.my_role}</span>}
          <span>{p.open_items} 件未完成</span>
          {p.children > 0 && <span>{p.children} 个子项目</span>}
          {p.high_items > 0 && <Pill tone="warn">{p.high_items} 件紧急 / 风险</Pill>}
          <RelTime ts={p.last_activity} prefix="活跃于 " />
          <span className="spacer" />
          <MuteButton p={p} />
        </div>
      </div>
    </section>
  );
}

function SplitButton({ id, hasChildren }: { id: string; hasChildren: boolean }) {
  const cmd = useCommand();
  return (
    <button
      className="btn btn-sm"
      title="让模型按工作线把这个项目下的事项、知识、动态归类成子项目；可以重复执行"
      disabled={cmd.isPending(`split:${id}`)}
      onClick={() => void cmd.run("context.project_split", { id }, { key: `split:${id}` })}
    >
      {hasChildren ? "重新整理子项目" : "拆分子项目"}
    </button>
  );
}

type Tab = "items" | "done" | "knowledge" | "updates" | "people" | "conflicts";

export function ProjectDetailPage() {
  const { id = "" } = useParams();
  const q = useQuery<CtxProjectDetail>(`/api/context/projects/${encodeURIComponent(id)}`, { tags: ["context"] });
  const [tab, setTab] = useState<Tab>("items");
  return (
    <div className="page page-detail">
      <QueryView q={q} what="项目">
        {(p) => {
          const open = p.items.filter((i) => i.status === "open" || i.status === "snoozed");
          const closed = p.items.filter((i) => i.status === "done" || i.status === "dismissed");
          const tabs: { key: Tab; label: string }[] = [
            { key: "items", label: `进行中 ${open.length}` },
            { key: "done", label: `已完成 ${closed.length}` },
            { key: "knowledge", label: `知识 ${p.knowledge.length}` },
            { key: "updates", label: `动态 ${p.updates.length}` },
            { key: "people", label: `人 ${p.people.length}` },
            { key: "conflicts", label: `冲突 ${p.conflicts.filter((c) => c.status === "open").length}` },
          ];
          return (
            <>
              <div className="crumbs small">
                <Link to="/projects">项目</Link> /{" "}
                {p.parent_id && (
                  <>
                    <Link to={projectHref(p.parent_id)}>{p.parent_name}</Link> /
                  </>
                )}
              </div>
              <PageHeader
                title={
                  <span className="row-gap">
                    {p.name} <HealthPill p={p} />
                  </span>
                }
                subtitle={[p.stage, p.my_role && `我：${p.my_role}`, p.description].filter(Boolean).join(" · ")}
                actions={
                  <div className="row-gap">
                    {!p.parent_id && <SplitButton id={p.id} hasChildren={p.subprojects.length > 0} />}
                    <MuteButton p={p} />
                  </div>
                }
              />
              {p.subprojects.length > 0 && (
                <div className="proj-grid">
                  {p.subprojects.map((c) => (
                    <ProjectCard key={c.id} p={c} />
                  ))}
                </div>
              )}
              {p.refs.length > 0 && (
                <div className="row-gap small muted">
                  关联：
                  {p.refs.slice(0, 10).map((r) => (
                    <code key={r}>{r}</code>
                  ))}
                </div>
              )}
              <Card actions={<Tabs label="项目内容" value={tab} onChange={setTab} items={tabs} />}>
                {tab === "items" && <ItemList items={open} showProject={p.subprojects.length > 0} empty={<Empty title="没有进行中的事项" icon="✓" />} />}
                {tab === "done" && <ItemList items={closed} showProject={p.subprojects.length > 0} empty={<Empty title="还没有完成的事项" />} />}
                {tab === "knowledge" &&
                  (p.knowledge.length ? (
                    <ul className="know-list">
                      {p.knowledge.map((k) => (
                        <li key={k.id}>
                          <div className="row-gap">
                            <Pill tone="info">{KNOW_KIND[k.kind] ?? k.kind}</Pill>
                            <strong>{k.title}</strong>
                          </div>
                          <div className="wrap">{k.content}</div>
                          <Collapsible summary={`依据 ${k.evidence.length}`}>
                            <EvidenceList ev={k.evidence} />
                          </Collapsible>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <Empty title="还没有沉淀知识" />
                  ))}
                {tab === "updates" &&
                  (p.updates.length ? (
                    <ul className="upd-list">
                      {p.updates.map((u) => (
                        <li key={u.id}>
                          <div className="small muted">
                            <RelTime ts={u.time} />
                          </div>
                          <div>{u.summary}</div>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <Empty title="没有动态" />
                  ))}
                {tab === "people" &&
                  (p.people.length ? (
                    <ul className="people-mini">
                      {p.people.map((x) => (
                        <li key={x.id}>
                          <strong>{x.name}</strong> <span className="muted small">{x.relation}</span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <Empty title="还没有识别出相关的人" />
                  ))}
                {tab === "conflicts" &&
                  (p.conflicts.length ? p.conflicts.map((c) => <ConflictBox key={c.id} c={c} />) : <Empty title="没有冲突" icon="✓" />)}
              </Card>
            </>
          );
        }}
      </QueryView>
    </div>
  );
}

export const KNOW_KIND: Record<string, string> = { decision: "决策", conclusion: "结论", doc: "文档", howto: "做法", fact: "事实" };
