import { Link } from "react-router-dom";
import type { DispatchState, DispatchSummary } from "../api/types.ts";
import { DELIVERY_LABEL, DELIVERY_TONE, STATE_EXPLAIN, STATE_LABEL, STATE_TONE, stageIndex, usd } from "../lib/format.ts";
import { Pill, RelTime } from "./ui.tsx";

export function StatePill({ state, cancelRequested }: { state: DispatchState; cancelRequested?: boolean }) {
  if (cancelRequested && state !== "cancelled") return <Pill tone="warn">取消中</Pill>;
  return (
    <Pill tone={STATE_TONE[state] ?? "neutral"} title={STATE_EXPLAIN[state]}>
      {STATE_LABEL[state] ?? state}
    </Pill>
  );
}

export function DeliveryPill({ d }: { d: Pick<DispatchSummary, "delivery" | "delivery_url"> }) {
  if (d.delivery === "none") return null;
  const pill = <Pill tone={DELIVERY_TONE[d.delivery]}>{DELIVERY_LABEL[d.delivery]}</Pill>;
  return d.delivery_url ? (
    <a href={d.delivery_url} target="_blank" rel="noreferrer noopener" className="pill-link">
      {pill}
    </a>
  ) : (
    pill
  );
}

const STAGES = ["准备", "执行", "验收"];

/** 阶段条：准备 → 执行 → 验收（当前阶段高亮）。 */
export function StageBar({ state }: { state: DispatchState }) {
  const cur = stageIndex(state);
  return (
    <ol className="stagebar" aria-label={`阶段：${STAGES[Math.min(cur, 2)]}${cur > 2 ? "（已结束）" : ""}`}>
      {STAGES.map((s, i) => (
        <li key={s} className={i < cur ? "stage-done" : i === cur ? "stage-current" : "stage-todo"} aria-current={i === cur ? "step" : undefined}>
          <span className="stage-dot" aria-hidden />
          {s}
        </li>
      ))}
    </ol>
  );
}

export function dispatchHref(id: string): string {
  return `/dispatches/${encodeURIComponent(id)}`;
}

/** 列表里的一行派单。 */
export function DispatchRow({ d, showStage }: { d: DispatchSummary; showStage?: boolean }) {
  return (
    <li className="drow">
      <div className="drow-state">
        <StatePill state={d.state} cancelRequested={d.cancel_requested} />
      </div>
      <div className="drow-main">
        <Link to={dispatchHref(d.id)} className="drow-title">
          {d.summary || d.task_guid}
        </Link>
        <div className="drow-meta">
          {d.harness && <span>{d.harness}</span>}
          {d.repo && (
            <span>
              仓库 <code>{d.repo}</code>
            </span>
          )}
          {d.max_rounds > 0 && (
            <span>
              第 {d.round}/{d.max_rounds} 轮
            </span>
          )}
          {d.cost_usd > 0 && <span>{usd(d.cost_usd)}</span>}
          <DeliveryPill d={d} />
        </div>
        {d.reason && d.terminal && <div className="drow-reason">{d.reason}</div>}
        {showStage && !d.terminal && <StageBar state={d.state} />}
      </div>
      <div className="drow-time">
        <RelTime ts={d.updated} />
      </div>
    </li>
  );
}
