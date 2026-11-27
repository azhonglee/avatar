import { useEffect, useState } from "react";
import type { DeliveryStatus, DispatchState } from "../api/types.ts";

const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

/** “3 分钟前” / “2 小时后”。 */
export function relTime(ts: number, now = Date.now()): string {
  const d = ts - now;
  const a = Math.abs(d);
  const suffix = d < 0 ? "前" : "后";
  if (a < 45_000) return d < 0 ? "刚刚" : "马上";
  if (a < HOUR) return `${Math.round(a / MIN)} 分钟${suffix}`;
  if (a < DAY) return `${Math.round(a / HOUR)} 小时${suffix}`;
  if (a < 30 * DAY) return `${Math.round(a / DAY)} 天${suffix}`;
  return absTime(ts, false);
}

export function absTime(ts: number, withTime = true): string {
  const d = new Date(ts);
  const p = (n: number) => String(n).padStart(2, "0");
  const date = `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
  return withTime ? `${date} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}` : date;
}

/** 共享时钟：让相对时间每 30 秒刷新一次。 */
let tick = Date.now();
const listeners = new Set<(n: number) => void>();
let timer: ReturnType<typeof setInterval> | undefined;
export function useNow(intervalMs = 30_000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    listeners.add(setNow);
    if (!timer)
      timer = setInterval(() => {
        tick = Date.now();
        listeners.forEach((f) => f(tick));
      }, intervalMs);
    return () => {
      listeners.delete(setNow);
      if (!listeners.size && timer) {
        clearInterval(timer);
        timer = undefined;
      }
    };
  }, [intervalMs]);
  return now;
}

export function duration(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return "—";
  if (ms < 1000) return `${Math.round(ms)} 毫秒`;
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s} 秒`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} 分 ${s % 60} 秒`;
  const h = Math.floor(m / 60);
  return `${h} 小时 ${m % 60} 分`;
}

export function usd(v: number, digits?: number): string {
  if (!v) return "$0";
  const d = digits ?? (v < 0.1 ? 4 : v < 10 ? 3 : 2);
  return `$${v.toFixed(d).replace(/\.?0+$/, "")}`;
}

export function tokens(n: number): string {
  if (!n) return "0";
  if (n < 1000) return String(n);
  if (n < 1_000_000) return `${(n / 1000).toFixed(1).replace(/\.0$/, "")}k`;
  return `${(n / 1_000_000).toFixed(2).replace(/\.?0+$/, "")}M`;
}

export function pct(v: number | null | undefined): string {
  return v === null || v === undefined ? "—" : `${Math.round(v * 100)}%`;
}

export const STATE_LABEL: Record<DispatchState, string> = {
  queued: "排队中",
  executing: "执行中",
  verifying: "验收中",
  accepted: "已通过",
  unverified: "未验证",
  needs_human: "需介入",
  errored: "出错",
  cancelled: "已取消",
};

export type Tone = "neutral" | "info" | "success" | "warn" | "danger" | "muted";

export const STATE_TONE: Record<DispatchState, Tone> = {
  queued: "neutral",
  executing: "info",
  verifying: "info",
  accepted: "success",
  unverified: "warn",
  needs_human: "warn",
  errored: "danger",
  cancelled: "muted",
};

/** 给人看的状态说明（拼在 reason 前面）。 */
export const STATE_EXPLAIN: Record<DispatchState, string> = {
  queued: "等待空闲的执行槽位",
  executing: "执行者正在改代码",
  verifying: "正在跑校验命令和交叉审查",
  accepted: "校验与审查都通过了，等你验收",
  unverified: "没有可用的校验手段，结果未经验证，请人工检查",
  needs_human: "自动流程没法继续，需要你做决定",
  errored: "执行过程中出错了",
  cancelled: "已取消",
};

export const DELIVERY_LABEL: Record<DeliveryStatus, string> = {
  none: "未交付",
  pending: "交付中",
  pr_open: "已创建 PR",
  merged_local: "已合并到本地",
  discarded: "已放弃",
  failed: "交付失败",
};

export const DELIVERY_TONE: Record<DeliveryStatus, Tone> = {
  none: "muted",
  pending: "info",
  pr_open: "success",
  merged_local: "success",
  discarded: "muted",
  failed: "danger",
};

/** 派单阶段：准备 → 执行 → 验收 */
export function stageIndex(s: DispatchState): number {
  if (s === "queued") return 0;
  if (s === "executing") return 1;
  if (s === "verifying") return 2;
  return 3;
}

export function plural(n: number, unit: string): string {
  return `${n} ${unit}`;
}
