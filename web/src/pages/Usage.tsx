import { useState } from "react";
import { Link } from "react-router-dom";
import type { UsageSummary } from "../api/types.ts";
import { BarChart } from "../components/BarChart.tsx";
import { dispatchHref } from "../components/dispatch.tsx";
import { Bar, Card, Empty, PageHeader, QueryView, Stat, Unavailable } from "../components/ui.tsx";
import { duration, tokens, usd } from "../lib/format.ts";
import { useMeta } from "../lib/meta.ts";
import { useQuery } from "../lib/query.ts";

function Budget({ u }: { u: UsageSummary }) {
  const meta = useMeta();
  const b = u.budget;
  return (
    <Card title="预算" actions={meta.features.settings ? <Link to="/settings#budget">调整 →</Link> : undefined}>
      <div className="budget">
        <div className="budget-row">
          <span>今天</span>
          <strong>{usd(b.today_usd)}</strong>
          <span className="muted">{b.daily_usd > 0 ? `/ 每日 ${usd(b.daily_usd)}` : "· 每日不限"}</span>
        </div>
        {b.daily_usd > 0 && <Bar value={b.today_usd} max={b.daily_usd} label="今日花费占每日预算" />}
        <div className="budget-row">
          <span>单个派单上限</span>
          <strong>{b.per_task_usd > 0 ? usd(b.per_task_usd) : "不限"}</strong>
        </div>
        {b.exceeded && (
          <div className="inline-warn" role="alert">
            已超出预算：新的派单会暂停执行，直到预算恢复（明天或调高预算）。
          </div>
        )}
      </div>
    </Card>
  );
}

export function UsagePage() {
  const meta = useMeta();
  const [days, setDays] = useState(14);
  const q = useQuery<UsageSummary>(meta.features.usage ? `/api/usage?days=${days}` : null, { tags: ["usage"] });
  return (
    <div className="page">
      <PageHeader
        title="花费"
        subtitle="每次执行的耗时、token 与费用"
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
      {!meta.features.usage ? (
        <Unavailable what="用量统计" />
      ) : (
        <QueryView q={q} what="用量统计">
          {(u) => {
            const totalMs = u.by_day.reduce((a, d) => a + d.duration_ms, 0);
            const tin = u.by_day.reduce((a, d) => a + d.tokens_in, 0);
            const tout = u.by_day.reduce((a, d) => a + d.tokens_out, 0);
            return (
              <>
                {!u.metered && (
                  <div className="banner banner-info" role="note">
                    <span className="banner-icon" aria-hidden>
                      i
                    </span>
                    <div className="banner-text">
                      <strong>只有耗时</strong>
                      <span>当前的执行者没有上报 token 用量，所以只能统计耗时、无法计算费用。配置了单价且执行者支持上报后会自动计费。</span>
                    </div>
                  </div>
                )}
                <div className="grid-overview">
                  <div className="col-main">
                    <Card>
                      <div className="stats">
                        <Stat label={`${u.days} 天合计`} value={u.metered ? usd(u.total_usd) : "—"} />
                        <Stat label="总耗时" value={duration(totalMs)} />
                        <Stat label="输入 tokens" value={u.metered ? tokens(tin) : "—"} />
                        <Stat label="输出 tokens" value={u.metered ? tokens(tout) : "—"} />
                      </div>
                    </Card>
                    <Card title={u.metered ? "每天的费用" : "每天的执行耗时"}>
                      {u.by_day.length ? (
                        <BarChart
                          label={u.metered ? "每天的费用（美元）" : "每天的执行耗时"}
                          format={u.metered ? (v) => usd(v) : (v) => duration(v)}
                          data={u.by_day.map((d) => ({
                            label: d.day.slice(5),
                            value: u.metered ? d.usd : d.duration_ms,
                            title: `${d.day}：${usd(d.usd)} · ${duration(d.duration_ms)} · tokens ${tokens(d.tokens_in)}/${tokens(d.tokens_out)}`,
                          }))}
                        />
                      ) : (
                        <Empty title="这段时间没有执行记录" />
                      )}
                    </Card>
                    <Card title="按执行者">
                      {u.by_harness.length ? (
                        <div className="table-wrap">
                          <table className="table">
                            <thead>
                              <tr>
                                <th>执行者</th>
                                <th className="num">次数</th>
                                <th className="num">耗时</th>
                                <th className="num">tokens 入/出</th>
                                <th className="num">费用</th>
                              </tr>
                            </thead>
                            <tbody>
                              {u.by_harness.map((h) => (
                                <tr key={h.harness}>
                                  <td>{h.harness || "（校验命令）"}</td>
                                  <td className="num">{h.runs}</td>
                                  <td className="num">{duration(h.duration_ms)}</td>
                                  <td className="num">
                                    {tokens(h.tokens_in)} / {tokens(h.tokens_out)}
                                  </td>
                                  <td className="num">{u.metered ? usd(h.usd) : "—"}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      ) : (
                        <Empty title="没有数据" />
                      )}
                    </Card>
                  </div>
                  <div className="col-side">
                    <Budget u={u} />
                    <Card title="花费最多的派单">
                      {u.top_tasks.length ? (
                        <ol className="top-list">
                          {u.top_tasks.map((t) => (
                            <li key={t.dispatch_id}>
                              <Link to={dispatchHref(t.dispatch_id)}>{t.summary || t.dispatch_id}</Link>
                              <span className="num">{usd(t.usd)}</span>
                            </li>
                          ))}
                        </ol>
                      ) : (
                        <Empty title={u.metered ? "没有计费的派单" : "没有费用数据"} />
                      )}
                    </Card>
                  </div>
                </div>
              </>
            );
          }}
        </QueryView>
      )}
    </div>
  );
}
