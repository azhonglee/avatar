import type { App } from "./app.ts";
import type { Config } from "./config.ts";
import type { EffectHooks } from "./effects.ts";
import type { Effect, NotifyKind } from "./ledger.ts";

/**
 * 通知偏好：在 outbox 投递私信/卡片前决定“现在发、延后发、还是不发”。
 *
 *   - 按类型开关（notify.types）：关闭的类型直接跳过；failure（失败告警）不能关闭，也不受免打扰影响
 *   - 免打扰（notify.quiet_start / quiet_end，按 owner.timezone，可跨午夜，留空即关闭）：
 *     期间的非紧急私信、新卡片延后到时段结束时发送（引擎按 next_at 重新领取，不计入重试次数）
 *   - 已经发出的卡片（kv 里有 card.msg.<key>）的原地更新不会再提醒，所以照常立即更新
 *   - 没有标注类型的私信（旧代码路径，如事件重试耗尽的告警）照常发送：无法判断是否紧急，宁可打扰
 *
 * 每次都读 app.cfg.notify，设置页热更新后立即生效。
 */

/** 解析 "HH:MM"（也接受 "H:MM"），返回当天第几分钟；格式不对返回 undefined。 */
export function parseHHMM(s: string): number | undefined {
  const m = /^(\d{1,2}):(\d{2})$/.exec(s.trim());
  if (!m) return undefined;
  const h = Number(m[1]);
  const mi = Number(m[2]);
  if (h > 23 || mi > 59) return undefined;
  return h * 60 + mi;
}

const formatters = new Map<string, Intl.DateTimeFormat>();

/** 某时刻在指定时区里是当天第几分钟。时区无效时抛 RangeError。 */
export function localMinutes(ts: number, timeZone: string): number {
  let f = formatters.get(timeZone);
  if (!f) {
    f = new Intl.DateTimeFormat("en-US", { timeZone, hour12: false, hour: "2-digit", minute: "2-digit" });
    formatters.set(timeZone, f);
  }
  const parts = f.formatToParts(new Date(ts));
  const h = Number(parts.find((p) => p.type === "hour")?.value ?? 0) % 24; // 部分实现把午夜写成 24
  const mi = Number(parts.find((p) => p.type === "minute")?.value ?? 0);
  return h * 60 + mi;
}

/**
 * 当前处于免打扰时段时，返回时段结束的时间戳；否则 undefined。
 * 按“距离结束还有几分钟”推算（夏令时切换恰好落在时段内时可能差一小时，可接受）。
 */
export function quietUntil(now: number, n: Pick<Config["notify"], "quiet_start" | "quiet_end">, timeZone: string): number | undefined {
  const s = parseHHMM(n.quiet_start);
  const e = parseHHMM(n.quiet_end);
  if (s === undefined || e === undefined || s === e) return undefined;
  const m = localMinutes(now, timeZone);
  const inside = s < e ? m >= s && m < e : m >= s || m < e;
  if (!inside) return undefined;
  const delta = (e - m + 1440) % 1440;
  return now - (now % 60_000) + delta * 60_000;
}

/** 没有显式类型时，从卡片 key 的约定前缀推断（见 src/ext.ts）。 */
function inferKind(e: Effect): NotifyKind | undefined {
  if (e.op !== "card.upsert") return undefined;
  const prefix = e.args.key.split(":")[0];
  if (prefix === "failure" || prefix === "brief" || prefix === "candidate") return prefix;
  return undefined;
}

export function notifyGate(app: Pick<App, "cfg" | "store">, now: () => number = () => Date.now()): NonNullable<EffectHooks["gate"]> {
  return (kind, e) => {
    const k = kind ?? inferKind(e);
    if (k === "failure") return undefined; // 失败告警：总是立即发送
    // 已发出的卡片：原地更新不提醒，保持卡片最新（即使该类型后来被关闭）
    if (e.op === "card.upsert" && app.store.get(`card.msg.${e.args.key}`)) return undefined;
    const n = app.cfg.notify;
    if (k && n.types[k] === false) return false;
    if (!k && e.op === "notify") return undefined;
    try {
      return quietUntil(now(), n, app.cfg.owner.timezone);
    } catch {
      return undefined; // 时区无效等：不拦截，照常发送
    }
  };
}

export function registerNotifyPrefs(app: App): void {
  const prev = app.effectHooks.gate;
  const gate = notifyGate(app);
  // 已有其他模块设置的 gate：先问它，它放行再按偏好判断
  app.effectHooks.gate = prev
    ? (kind, e) => {
        const g = prev(kind, e);
        return g === undefined ? gate(kind, e) : g;
      }
    : gate;
}
