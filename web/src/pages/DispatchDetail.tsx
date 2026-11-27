import { useEffect, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { ApiRequestError } from "../api/client.ts";
import type { AuditView, CheckView, DispatchDetail, StepView } from "../api/types.ts";
import { ActionBar } from "../components/ActionBar.tsx";
import { DiffViewer } from "../components/DiffViewer.tsx";
import { DeliveryPill, DispatchRow, StageBar, StatePill } from "../components/dispatch.tsx";
import { LogViewer } from "../components/LogViewer.tsx";
import { Markdown } from "../components/Markdown.tsx";
import { Card, Collapsible, Empty, ExternalLink, Loading, Pill, Pre, QueryView, RelTime, Tabs } from "../components/ui.tsx";
import { DELIVERY_LABEL, STATE_EXPLAIN, absTime, duration, tokens, usd, type Tone } from "../lib/format.ts";
import { useQuery } from "../lib/query.ts";

function Elapsed({ since }: { since: number }) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);
  return <>{duration(now - since)}</>;
}

const STEP_TONE: Record<StepView["status"], Tone> = { running: "info", ok: "success", failed: "danger", interrupted: "warn" };
const STEP_LABEL: Record<StepView["status"], string> = { running: "运行中", ok: "完成", failed: "失败", interrupted: "被中断" };

function stepTitle(name: string): string {
  const [base, n] = name.split("#");
  const map: Record<string, string> = { worker: "执行", verify: "校验命令", review: "交叉审查" };
  return `${map[base] ?? base}${n ? ` · 第 ${n} 轮` : ""}`;
}

function Steps({ steps }: { steps: StepView[] }) {
  const lastRunning = [...steps].reverse().find((s) => s.status === "running")?.id;
  const [open, setOpen] = useState<Set<number>>(() => new Set(lastRunning ? [lastRunning] : []));
  useEffect(() => {
    if (lastRunning) setOpen((o) => (o.has(lastRunning) ? o : new Set([...o, lastRunning])));
  }, [lastRunning]);
  if (!steps.length) return <Empty title="还没有执行步骤">派单开始执行后，每一步（执行、校验、审查）都会出现在这里。</Empty>;
  return (
    <ol className="timeline">
      {steps.map((s) => {
        const isOpen = open.has(s.id);
        return (
          <li key={s.id} className={`tl-item tl-${s.status}`}>
            <span className="tl-dot" aria-hidden />
            <div className="tl-body">
              <div className="tl-head">
                <strong>{stepTitle(s.name)}</strong>
                <Pill tone={STEP_TONE[s.status]}>{STEP_LABEL[s.status]}</Pill>
                {s.harness && <span className="muted small">{s.harness}</span>}
              </div>
              <div className="tl-meta muted small">
                <RelTime ts={s.started} prefix="开始于 " />
                <span>耗时 {s.status === "running" ? <Elapsed since={s.started} /> : duration(s.duration_ms)}</span>
                {(s.tokens_in > 0 || s.tokens_out > 0) && (
                  <span title={`输入 ${s.tokens_in} / 输出 ${s.tokens_out} tokens`}>
                    tokens {tokens(s.tokens_in)} / {tokens(s.tokens_out)}
                  </span>
                )}
                {s.cost_usd > 0 && <span>{usd(s.cost_usd)}</span>}
              </div>
              {s.summary && (s.summary.length > 240 ? <Collapsible summary={s.summary.slice(0, 120) + "…"}><Pre>{s.summary}</Pre></Collapsible> : <div className="tl-summary">{s.summary}</div>)}
              {s.has_log && (
                <button
                  className="btn btn-sm btn-ghost"
                  aria-expanded={isOpen}
                  onClick={() =>
                    setOpen((o) => {
                      const n = new Set(o);
                      if (n.has(s.id)) n.delete(s.id);
                      else n.add(s.id);
                      return n;
                    })
                  }
                >
                  {isOpen ? "收起日志" : s.status === "running" ? "查看实时日志" : "查看日志"}
                </button>
              )}
              {isOpen && s.has_log && <LogViewer stepId={s.id} />}
            </div>
          </li>
        );
      })}
    </ol>
  );
}

const CHECK_TONE: Record<CheckView["status"], Tone> = { pass: "success", fail: "danger", error: "warn" };
const CHECK_LABEL: Record<CheckView["status"], string> = { pass: "通过", fail: "未通过", error: "出错" };

function Rounds({ rounds }: { rounds: DispatchDetail["rounds"] }) {
  if (!rounds.length) return null;
  return (
    <div className="rounds">
      {rounds.map((r) => (
        <div key={r.round} className="round">
          <h3 className="group-title">第 {r.round} 轮验收</h3>
          {r.checks.length ? (
            <ul className="checks">
              {r.checks.map((c, i) => (
                <li key={i} className="check-item">
                  <div className="check-head">
                    <Pill tone={CHECK_TONE[c.status]}>{CHECK_LABEL[c.status]}</Pill>
                    <span className="muted small">{c.kind === "review" ? "审查" : "校验命令"}</span>
                    {c.kind === "command" ? <code>{c.name}</code> : <strong>{c.name}</strong>}
                  </div>
                  {c.detail && (
                    <Collapsible summary={c.status === "pass" ? "查看输出" : "查看原因"} defaultOpen={c.status !== "pass"}>
                      {c.kind === "review" ? <Markdown text={c.detail} /> : <Pre>{c.detail}</Pre>}
                    </Collapsible>
                  )}
                </li>
              ))}
            </ul>
          ) : (
            <p className="muted small">这一轮没有可运行的校验。</p>
          )}
        </div>
      ))}
    </div>
  );
}

const EFFECT_STATE: Record<string, { label: string; tone: Tone }> = {
  pending: { label: "待写入", tone: "neutral" },
  done: { label: "已写入", tone: "success" },
  dead: { label: "写入失败", tone: "danger" },
  errored: { label: "写入失败", tone: "danger" },
  skipped: { label: "已跳过", tone: "muted" },
};

function Effects({ effects }: { effects: DispatchDetail["effects"] }) {
  if (!effects.length) return <Empty title="还没有写回飞书的内容" />;
  return (
    <ul className="plain-list">
      {effects.map((e) => {
        const st = EFFECT_STATE[e.state] ?? { label: e.state, tone: "neutral" as Tone };
        return (
          <li key={e.id} className="plain-item">
            <div className="row-between">
              <span>{e.summary}</span>
              <span className="row-gap">
                <Pill tone={st.tone}>{st.label}</Pill>
                <RelTime ts={e.updated} />
              </span>
            </div>
            {e.error && <div className="small text-danger">{e.error}</div>}
          </li>
        );
      })}
    </ul>
  );
}

const SOURCE_LABEL: Record<string, string> = { web: "控制台", card: "飞书卡片", bot: "私聊", cli: "命令行" };

export function AuditTable({ audit }: { audit: AuditView[] }) {
  if (!audit.length) return <Empty title="还没有操作记录" />;
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <th>时间</th>
            <th>来源</th>
            <th>操作</th>
            <th>结果</th>
          </tr>
        </thead>
        <tbody>
          {audit.map((a) => (
            <tr key={a.id}>
              <td>
                <RelTime ts={a.at} />
              </td>
              <td>{SOURCE_LABEL[a.source] ?? a.source}</td>
              <td>
                <code>{a.command}</code>
              </td>
              <td>
                <Pill tone={a.ok ? "success" : "danger"}>{a.ok ? "成功" : "失败"}</Pill> <span className="small">{a.message}</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

type Tab = "process" | "diff" | "report" | "effects" | "history";

function Header({ d }: { d: DispatchDetail }) {
  return (
    <>
      <div className="crumbs">
        <Link to="/dispatches">← 派单</Link>
      </div>
      <header className="detail-head">
        <div className="detail-title-row">
          <h1>{d.summary}</h1>
          <div className="row-gap">
            <StatePill state={d.state} cancelRequested={d.cancel_requested} />
            <DeliveryPill d={d} />
            {d.active && <Pill tone="info">进程在线</Pill>}
          </div>
        </div>
        {!d.terminal && <StageBar state={d.state} />}
        <div className={`reason reason-${d.state}`}>
          <strong>{STATE_EXPLAIN[d.state]}</strong>
          {d.reason && <span>：{d.reason}</span>}
          {d.error && d.error !== d.reason && <Collapsible summary="错误详情" defaultOpen={d.state === "errored"}><Pre className="pre-danger">{d.error}</Pre></Collapsible>}
        </div>
        <ActionBar d={d} />
        <dl className="kv detail-kv">
          <dt>执行者</dt>
          <dd>{d.harness || "默认"}</dd>
          <dt>审查者</dt>
          <dd>{d.reviewer || <span className="muted">不审查</span>}</dd>
          <dt>轮次</dt>
          <dd>{d.max_rounds ? `第 ${d.round} / ${d.max_rounds} 轮` : "—"}{d.attempts > 1 ? `（第 ${d.attempts} 次尝试）` : ""}</dd>
          <dt>花费</dt>
          <dd>{d.cost_usd > 0 ? usd(d.cost_usd) : <span className="muted">未计费</span>}</dd>
          {d.repo && (
            <>
              <dt>仓库</dt>
              <dd>
                <code>{d.repo}</code>
              </dd>
            </>
          )}
          {d.branch && (
            <>
              <dt>分支</dt>
              <dd>
                <code>{d.branch}</code>
              </dd>
            </>
          )}
          <dt>创建</dt>
          <dd>
            <RelTime ts={d.created} />
          </dd>
          <dt>更新</dt>
          <dd>
            <RelTime ts={d.updated} />
          </dd>
          <dt>交付</dt>
          <dd>
            {DELIVERY_LABEL[d.delivery]}
            {d.delivery_url && (
              <>
                {" · "}
                <ExternalLink href={d.delivery_url}>{d.delivery === "pr_open" ? "打开 PR" : "打开"}</ExternalLink>
              </>
            )}
          </dd>
          {d.task_url && (
            <>
              <dt>飞书任务</dt>
              <dd>
                <ExternalLink href={d.task_url}>在飞书中打开</ExternalLink>
              </dd>
            </>
          )}
        </dl>
      </header>
    </>
  );
}

export function DispatchDetailPage() {
  const { id: raw = "" } = useParams();
  const id = decodeURIComponent(raw);
  const [sp, setSp] = useSearchParams();
  const [guid, setGuid] = useState("");
  // 同一张卡片的新派单出现时也刷新（“之前的派单”、可执行操作会变）
  const q = useQuery<DispatchDetail>(`/api/dispatches/${encodeURIComponent(id)}`, { tags: [`dispatch:${id}`, ...(guid ? [`card:${guid}`] : [])] });
  const loadedGuid = q.data?.task_guid ?? "";
  useEffect(() => {
    if (loadedGuid) setGuid(loadedGuid);
  }, [loadedGuid]);
  const rawTab = sp.get("tab") as Tab | null;
  const tab: Tab = rawTab && (["process", "diff", "report", "effects", "history"] as const).includes(rawTab) ? rawTab : "process";
  const setTab = (t: Tab) => {
    const n = new URLSearchParams(sp);
    n.set("tab", t);
    setSp(n, { replace: true });
  };

  if (q.error instanceof ApiRequestError && q.error.status === 404)
    return (
      <div className="page">
        <Empty title="没有这项派单" icon="?">
          可能已被清理。<Link to="/dispatches">回到派单列表</Link>
        </Empty>
      </div>
    );

  return (
    <div className="page page-detail">
      <QueryView q={q} loading={<Loading label="加载派单…" />}>
        {(d) => (
          <>
            <Header d={d} />
            <Tabs<Tab>
              label="派单详情"
              value={tab}
              onChange={setTab}
              items={[
                { key: "process", label: `过程${d.steps.length ? ` · ${d.steps.length}` : ""}` },
                { key: "diff", label: "改动" },
                { key: "report", label: "报告" },
                { key: "effects", label: `飞书写入${d.effects.length ? ` · ${d.effects.length}` : ""}` },
                { key: "history", label: "历史与审计" },
              ]}
            />
            <div className="tab-panel" role="tabpanel">
              {tab === "process" && (
                <>
                  {d.rounds.length > 0 && (
                    <Card title="验收结果">
                      <Rounds rounds={d.rounds} />
                    </Card>
                  )}
                  <Card title="时间线">
                    <Steps steps={d.steps} />
                  </Card>
                </>
              )}
              {tab === "diff" && (
                <Card title="改动">
                  {d.diff_stat && (
                    <Collapsible summary="改动统计（git diff --stat）">
                      <Pre>{d.diff_stat}</Pre>
                    </Collapsible>
                  )}
                  {d.base || d.branch ? <DiffViewer id={d.id} /> : <Empty title="没有可显示的改动">这次派单没有指定仓库，不在 git worktree 中执行。</Empty>}
                </Card>
              )}
              {tab === "report" && (
                <>
                  <Card title="执行者报告">{d.report ? <Markdown text={d.report} /> : <Empty title="还没有报告" />}</Card>
                  {d.feedback && (
                    <Card title="返工意见">
                      <Markdown text={d.feedback} />
                    </Card>
                  )}
                  <Card title="任务说明">{d.description ? <Pre>{d.description}</Pre> : <p className="muted">没有补充说明。</p>}</Card>
                  {(d.cwd || d.verify) && (
                    <Card title="执行环境">
                      <dl className="kv">
                        {d.cwd && (
                          <>
                            <dt>工作目录</dt>
                            <dd>
                              <code>{d.cwd}</code>
                            </dd>
                          </>
                        )}
                        {d.base && (
                          <>
                            <dt>基线</dt>
                            <dd>
                              <code>{d.base}</code>
                            </dd>
                          </>
                        )}
                        {d.verify && (
                          <>
                            <dt>校验命令</dt>
                            <dd>
                              <code>{d.verify}</code>
                            </dd>
                          </>
                        )}
                      </dl>
                    </Card>
                  )}
                </>
              )}
              {tab === "effects" && (
                <Card title="写回飞书">
                  <Effects effects={d.effects} />
                </Card>
              )}
              {tab === "history" && (
                <>
                  <Card title="这张卡片之前的派单">
                    {d.previous.length ? (
                      <ul className="dlist">
                        {d.previous.map((p) => (
                          <DispatchRow key={p.id} d={p} />
                        ))}
                      </ul>
                    ) : (
                      <Empty title="这是第一次派单" />
                    )}
                  </Card>
                  <Card title="操作记录">
                    <AuditTable audit={d.audit} />
                  </Card>
                  <p className="muted small">
                    派单 ID <code>{d.id}</code> · 创建于 {absTime(d.created)}
                  </p>
                </>
              )}
            </div>
          </>
        )}
      </QueryView>
    </div>
  );
}
