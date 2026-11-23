import { Link } from "react-router-dom";
import type { DispatchDetail, DispatchSummary, DoctorReport, Overview } from "../api/types.ts";
import { ActionBar } from "../components/ActionBar.tsx";
import { DeliveryPill, DispatchRow, StatePill, dispatchHref } from "../components/dispatch.tsx";
import { Bar, Card, Empty, PageHeader, Pill, QueryView, RelTime, Stat } from "../components/ui.tsx";
import { useLiveState } from "../lib/events.ts";
import { STATE_EXPLAIN, usd } from "../lib/format.ts";
import { useMeta } from "../lib/meta.ts";
import { useQuery } from "../lib/query.ts";

function SetupBanner() {
  const q = useQuery<DoctorReport>("/api/doctor", { tags: ["doctor"] });
  if (!q.data || q.data.ready) return null;
  const bad = q.data.checks.filter((c) => c.status === "fail").length;
  return (
    <div className="banner banner-warn" role="status">
      <span className="banner-icon" aria-hidden>
        !
      </span>
      <div className="banner-text">
        <strong>初始化还没完成</strong>
        <span>{bad ? `${bad} 项检查没有通过，部分功能可能无法工作。` : "还有检查项需要处理。"}</span>
      </div>
      <Link className="btn btn-primary btn-sm" to="/setup">
        打开初始化向导
      </Link>
    </div>
  );
}

/** “需要你处理”里的一项：拉取详情拿到可执行操作，直接给出按钮。 */
function AttentionItem({ s, kind }: { s: DispatchSummary; kind: "needs" | "review" }) {
  const q = useQuery<DispatchDetail>(`/api/dispatches/${encodeURIComponent(s.id)}`, { tags: [`dispatch:${s.id}`] });
  const pick = kind === "needs" ? ["dispatch.rework", "dispatch.switch_harness", "dispatch.retry"] : ["delivery.create_pr", "delivery.merge_local", "delivery.discard", "delivery.restore"];
  const acts = q.data ? q.data.actions.filter((a) => pick.includes(a)) : [];
  return (
    <li className="attn-item">
      <div className="attn-head">
        <StatePill state={s.state} />
        <Link to={dispatchHref(s.id)} className="attn-title">
          {s.summary}
        </Link>
        <DeliveryPill d={s} />
      </div>
      <div className="attn-reason">{s.reason || STATE_EXPLAIN[s.state]}</div>
      <div className="attn-meta muted small">
        {s.harness && <span>{s.harness}</span>}
        {s.repo && (
          <span>
            仓库 <code>{s.repo}</code>
          </span>
        )}
        <RelTime ts={s.updated} />
      </div>
      <div className="attn-actions">
        {q.data && <ActionBar size="sm" d={{ ...q.data, actions: acts }} />}
        <Link className="btn btn-sm btn-ghost" to={dispatchHref(s.id)}>
          {kind === "review" ? "查看改动" : "查看详情"}
        </Link>
      </div>
    </li>
  );
}

function AttentionCard({ o }: { o: Overview }) {
  const meta = useMeta();
  const a = o.attention;
  const candidates = meta.features.candidates ? a.candidates : 0;
  const total = a.needs_human.length + a.to_review.length + candidates + a.failures;
  return (
    <Card title={<>需要你处理{total > 0 && <span className="count">{total}</span>}</>} className="card-attn">
      {total === 0 ? (
        <Empty title="没有需要你处理的事" icon="✓">
          派出去的活都在按计划进行。
        </Empty>
      ) : (
        <>
          {(candidates > 0 || a.failures > 0) && (
            <div className="attn-tiles">
              {candidates > 0 && (
                <Link to="/candidates" className="tile tile-info">
                  <span className="tile-num">{candidates}</span>
                  <span className="tile-label">个候选任务待确认</span>
                  <span className="tile-cta">去确认 →</span>
                </Link>
              )}
              {a.failures > 0 && (
                <Link to="/health" className="tile tile-danger">
                  <span className="tile-num">{a.failures}</span>
                  <span className="tile-label">项失败需要处理</span>
                  <span className="tile-cta">去处理 →</span>
                </Link>
              )}
            </div>
          )}
          {a.needs_human.length > 0 && (
            <div className="attn-group">
              <h3 className="group-title">需介入 · {a.needs_human.length}</h3>
              <ul className="attn-list">
                {a.needs_human.map((s) => (
                  <AttentionItem key={s.id} s={s} kind="needs" />
                ))}
              </ul>
            </div>
          )}
          {a.to_review.length > 0 && (
            <div className="attn-group">
              <h3 className="group-title">待验收 · {a.to_review.length}</h3>
              <ul className="attn-list">
                {a.to_review.map((s) => (
                  <AttentionItem key={s.id} s={s} kind="review" />
                ))}
              </ul>
            </div>
          )}
        </>
      )}
    </Card>
  );
}

function TodayCard({ o }: { o: Overview }) {
  const t = o.today;
  return (
    <Card title="今天">
      <div className="stats">
        <Stat label="派单" value={t.dispatched} />
        <Stat label="通过" value={t.accepted} tone="success" />
        <Stat label="需介入" value={t.needs_human} tone={t.needs_human ? "warn" : undefined} />
        <Stat label="出错" value={t.errored} tone={t.errored ? "danger" : undefined} />
      </div>
      <div className="budget">
        <div className="budget-row">
          <span>花费</span>
          <strong>{usd(t.cost_usd)}</strong>
          <span className="muted">{t.budget_usd > 0 ? `/ 每日预算 ${usd(t.budget_usd)}` : "· 未设每日预算"}</span>
        </div>
        {t.budget_usd > 0 && <Bar value={t.cost_usd} max={t.budget_usd} label="今日花费占每日预算" />}
        {t.budget_usd > 0 && t.cost_usd >= t.budget_usd && <div className="inline-warn">已达到每日预算，新的派单会暂停，直到明天或调高预算。</div>}
      </div>
    </Card>
  );
}

function HealthCard({ o }: { o: Overview }) {
  const h = o.health;
  const live = useLiveState();
  return (
    <Card title="系统健康" actions={<Link to="/health">详情 →</Link>}>
      <div className="health-line">
        <Pill tone={h.ok ? "success" : h.daemon_owner ? "warn" : "danger"}>{h.ok ? "正常" : h.daemon_owner ? "需要关注" : "常驻进程未运行"}</Pill>
        <span className="muted small">{h.daemon_owner ? `常驻进程 ${h.daemon_owner}` : "没有收到常驻进程的心跳"}</span>
      </div>
      {!h.daemon_owner && (
        <p className="small">
          事件不会被处理、派单不会推进。在开发机上运行 <code>pa run</code> 启动常驻进程。
        </p>
      )}
      <dl className="kv kv-compact">
        <dt>待处理事件</dt>
        <dd>{h.pending_events}</dd>
        <dt>待写回飞书</dt>
        <dd>{h.pending_effects}</dd>
        <dt>失败未处理</dt>
        <dd className={h.dead ? "text-danger" : ""}>{h.dead}</dd>
        <dt>实时更新</dt>
        <dd>{live === "open" ? "已连接" : live === "off" ? "不可用" : "重连中"}</dd>
      </dl>
    </Card>
  );
}

export function OverviewPage() {
  const meta = useMeta();
  const q = useQuery<Overview>("/api/overview", { tags: ["overview"] });
  return (
    <div className="page">
      <PageHeader
        title="概览"
        actions={
          <Link to="/dispatches?new=1" className="btn btn-primary">
            ＋ 新建派单
          </Link>
        }
      />
      {meta.features.doctor && <SetupBanner />}
      <QueryView q={q}>
        {(o) => (
          <div className="grid-overview">
            <div className="col-main">
              <AttentionCard o={o} />
              <Card title={<>进行中{o.running.length > 0 && <span className="count count-info">{o.running.length}</span>}</>} actions={<Link to="/dispatches?filter=active">全部 →</Link>}>
                {o.running.length ? (
                  <ul className="dlist">
                    {o.running.map((d) => (
                      <DispatchRow key={d.id} d={d} showStage />
                    ))}
                  </ul>
                ) : (
                  <Empty title="没有进行中的派单">
                    <Link to="/dispatches?new=1">新建一个派单</Link>，或在飞书看板把任务拖到「派给Agent」。
                  </Empty>
                )}
              </Card>
            </div>
            <div className="col-side">
              <TodayCard o={o} />
              <HealthCard o={o} />
            </div>
          </div>
        )}
      </QueryView>
    </div>
  );
}
