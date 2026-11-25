import { useState } from "react";
import { Link } from "react-router-dom";
import type { CtxStatus, CtxToday } from "../api/types.ts";
import { ConflictBox, DraftList, HealthPill, ItemList, projectHref, sourceLabel } from "../components/context.tsx";
import { Card, Empty, ExternalLink, PageHeader, Pill, QueryView, RelTime, Spinner, Tabs } from "../components/ui.tsx";
import { useCommand } from "../lib/command.ts";
import { useQuery } from "../lib/query.ts";

const WEEK = ["日", "一", "二", "三", "四", "五", "六"];

function dateTitle(date: string): string {
  const d = new Date(`${date}T00:00:00`);
  return `${d.getMonth() + 1} 月 ${d.getDate()} 日 · 周${WEEK[d.getDay()]}`;
}

function hm(ts: number): string {
  const d = new Date(ts);
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
}

/** 刷新按钮 + 上次采集时间 */
export function RefreshControl({ s }: { s: CtxStatus }) {
  const cmd = useCommand();
  const running = s.running || cmd.isPending("context.refresh");
  return (
    <div className="row-gap">
      <span className="muted small">{s.last_cycle ? <RelTime ts={s.last_cycle} prefix="上次更新 " /> : "还没有采集过"}</span>
      <button className="btn btn-sm" disabled={running} onClick={() => void cmd.run("context.refresh", {})}>
        {running ? <Spinner label="采集中" /> : "↻"} {running ? "采集中…" : "立即刷新"}
      </button>
    </div>
  );
}

function summary(t: CtxToday): string {
  const parts = [
    t.asks.length ? `${t.asks.length} 件别人在等你` : "",
    t.commitments.length ? `${t.commitments.length} 件你答应过` : "",
    t.due_soon.filter((i) => i.due && i.due < Date.now()).length ? `${t.due_soon.filter((i) => i.due && i.due < Date.now()).length} 件已逾期` : "",
    t.conflicts.length ? `${t.conflicts.length} 处说法不一致` : "",
  ].filter(Boolean);
  return parts.length ? `今天：${parts.join("，")}。` : "今天没有特别紧急的事。";
}

type Lane = "asks" | "commitments" | "waiting" | "risks" | "review";

function Lanes({ t }: { t: CtxToday }) {
  const [lane, setLane] = useState<Lane>("asks");
  const map: Record<Lane, { label: string; items: CtxToday["asks"]; empty: string }> = {
    asks: { label: "别人在等你", items: t.asks, empty: "没有人在等你答复" },
    commitments: { label: "你答应过", items: t.commitments, empty: "没有未兑现的承诺" },
    waiting: { label: "你在等别人", items: t.waiting, empty: "没有在等别人的事" },
    risks: { label: "风险", items: t.risks, empty: "没有识别到风险" },
    review: { label: "待确认识别", items: t.needs_review, empty: "没有需要确认的识别结果" },
  };
  const cur = map[lane];
  return (
    <Card
      title="按类型看"
      actions={
        <Tabs
          label="事项类型"
          value={lane}
          onChange={setLane}
          items={(Object.keys(map) as Lane[]).map((k) => ({ key: k, label: `${map[k].label} ${map[k].items.length}` }))}
        />
      }
    >
      <ItemList items={cur.items} empty={<Empty title={cur.empty} icon="✓" />} />
      {lane === "review" && cur.items.length > 0 && <p className="muted small">识别把握不大的事项：点「不对」移除，点「完成」或保留即视为识别正确。你的每次判断都会用于校准之后的识别。</p>}
    </Card>
  );
}

function SourcesCard({ s }: { s: CtxStatus }) {
  return (
    <Card title="数据来源" actions={<Link to="/settings">设置</Link>}>
      <ul className="src-list">
        {s.sources.map((x) => (
          <li key={x.source}>
            <span className={`dot ${x.error ? "dot-danger" : x.last_pull ? "dot-success" : "dot-muted"}`} aria-hidden />
            <span className="src-name">{sourceLabel(x.source)}</span>
            <span className="muted small">{x.error ? <span title={x.error}>出错：{x.error.slice(0, 40)}</span> : x.last_pull ? <RelTime ts={x.last_pull} /> : "未采集"}</span>
          </li>
        ))}
      </ul>
      <div className="muted small">
        {s.understand_enabled ? `待理解的消息 ${s.pending_obs} 条` : "未开启消息理解（只采集 Meego 与飞书任务）"} · 项目 {s.totals.projects} · 知识 {s.totals.knowledge} · 人 {s.totals.people}
      </div>
      {s.last_error && <div className="inline-warn small">{s.last_error.split("\n")[0]}</div>}
    </Card>
  );
}

export function TodayPage() {
  const q = useQuery<CtxToday>("/api/context/today", { tags: ["context"] });
  return (
    <div className="page">
      <QueryView q={q} what="工作上下文">
        {(t) => (
          <>
            <PageHeader title={`今天 · ${dateTitle(t.date)}`} subtitle={summary(t)} actions={<RefreshControl s={t.status} />} />
            {!t.status.last_cycle && (
              <div className="banner banner-info" role="status">
                <span className="banner-icon" aria-hidden>
                  i
                </span>
                <div className="banner-text">
                  <strong>还没有采集过你的工作信息</strong>
                  <span>点「立即刷新」从 Meego、飞书消息、妙记、日历和飞书任务采集最近 7 天的信息；常驻进程运行时每 10 分钟自动更新。</span>
                </div>
              </div>
            )}
            <div className="grid-overview">
              <div className="col-main">
                <Card title={<>先做这几件{t.focus.length > 0 && <span className="count">{t.focus.length}</span>}</>} className="card-attn">
                  <ItemList ranked items={t.focus} empty={<Empty title="今天没有需要你优先处理的事" icon="✓" />} />
                </Card>
                {t.conflicts.length > 0 && (
                  <Card title={<>需要你判断<span className="count">{t.conflicts.length}</span></>}>
                    <p className="muted small">不同的人对同一件事说法不一致。选一个为准，会记成项目的决策知识。</p>
                    {t.conflicts.map((c) => (
                      <ConflictBox key={c.id} c={c} />
                    ))}
                  </Card>
                )}
                {t.drafts.length > 0 && (
                  <Card title={<>待你确认的草稿<span className="count">{t.drafts.length}</span></>} actions={<Link to="/drafts">全部草稿</Link>}>
                    <DraftList drafts={t.drafts} />
                  </Card>
                )}
                <Lanes t={t} />
              </div>
              <div className="col-side">
                <Card title="今天的会">
                  {t.meetings.length ? (
                    <ul className="meet-list">
                      {t.meetings.map((m) => (
                        <li key={`${m.start}-${m.summary}`} className={m.end < Date.now() ? "muted" : ""}>
                          <span className="meet-time">
                            {hm(m.start)}–{hm(m.end)}
                          </span>
                          {m.url ? <ExternalLink href={m.url}>{m.summary}</ExternalLink> : <span>{m.summary}</span>}
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="muted small">今天没有会</p>
                  )}
                </Card>
                <Card title="过去 24 小时" actions={<Link to="/updates">全部动态</Link>}>
                  {t.changes.length ? (
                    <ul className="upd-list">
                      {t.changes.slice(0, 8).map((u) => (
                        <li key={u.id}>
                          <div className="small muted">
                            <RelTime ts={u.time} /> {u.project_name && <Link to={projectHref(u.project_id)}>{u.project_name}</Link>}
                          </div>
                          <div>{u.summary}</div>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="muted small">没有新的项目动态</p>
                  )}
                </Card>
                <Card title="项目" actions={<Link to="/projects">全部</Link>}>
                  {t.projects.length ? (
                    <ul className="proj-mini">
                      {t.projects.slice(0, 8).map((p) => (
                        <li key={p.id}>
                          <Link to={projectHref(p.id)}>{p.name}</Link>
                          <span className="spacer" />
                          {p.open_items > 0 && <span className="muted small">{p.open_items} 件</span>}
                          <HealthPill p={p} />
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="muted small">还没有识别出项目</p>
                  )}
                </Card>
                <SourcesCard s={t.status} />
                {t.status.running && <Pill tone="info">正在采集与理解…</Pill>}
              </div>
            </div>
          </>
        )}
      </QueryView>
    </div>
  );
}
