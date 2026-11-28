import type { App } from "./app.ts";
import type { UsageSummary } from "./api/types.ts";
import { setUsageRecorder } from "./harness.ts";
import type { WorkItem } from "./ledger.ts";
import { log } from "./util.ts";
import type { DispatchPayload } from "./workflows/dispatch.ts";

/**
 * 用量与预算（P5 成本与质量）：
 *   - 每次 harness 结束后从 acpx 输出里解析 token 数（和适配器上报的费用），写进对应步骤；
 *   - 汇总：按天（owner.timezone）、按 harness、花费最多的任务；
 *   - 预算守卫：派单每次运行 harness 之前检查今日花费与这张卡片累计花费，超出就暂停为“需人工介入”。
 *
 * acpx 的 quiet 模式（我们用的就是 --format quiet）在适配器于 prompt 结果里带了用量时，往 stderr 写：
 *   [acpx] tokens: input=17030 output=4 cache_read=12 cache_write=3 total=17049
 *   [acpx] cost: 0.051276 USD
 * 见 openclaw/acpx 的 docs/output-formats.md 与 src/cli/output/output.ts（QuietOutputFormatter.flushMetadata）。
 * 适配器不上报时什么都不写——这时只记耗时（endStep 已记录），汇总里 metered = false。
 */

const DAY = 86_400_000;

export interface ParsedUsage {
  /** 未命中缓存的输入 token */
  input: number;
  output: number;
  cache_read: number;
  cache_write: number;
  /** 适配器上报的费用（美元）；没有或币种不是美元时为 undefined */
  cost_usd?: number;
}

const num = (s: string | undefined): number => {
  const n = Number(s);
  return Number.isFinite(n) && n >= 0 ? n : 0;
};

/** 取最后一次出现的数值（同一输出里多次出现时以最终汇总为准）。 */
function lastNumber(text: string, keys: string[]): number | undefined {
  const re = new RegExp(`\\b"?(?:${keys.join("|")})"?\\s*[:=]\\s*(\\d+(?:\\.\\d+)?)`, "g");
  let v: number | undefined;
  for (const m of text.matchAll(re)) v = num(m[1]);
  return v;
}

/**
 * 从 harness 输出里解析用量。只看 stderr：stdout 是 agent 的回复正文，里面出现 "input_tokens" 之类的字样不能当真。
 * 先认 acpx quiet 模式的格式，再退回通用的 JSON 字段（input_tokens / prompt_tokens / inputTokens …）。
 * 什么都没找到返回 undefined。
 */
export function parseUsage(stderr: string): ParsedUsage | undefined {
  if (!stderr) return undefined;
  let u: ParsedUsage | undefined;
  const tokenLines = [...stderr.matchAll(/^\[acpx\] tokens:(.*)$/gm)];
  if (tokenLines.length) {
    const line = tokenLines.at(-1)![1];
    const field = (k: string) => num(line.match(new RegExp(`\\b${k}=(\\d+(?:\\.\\d+)?)`))?.[1]);
    u = { input: field("input"), output: field("output"), cache_read: field("cache_read"), cache_write: field("cache_write") };
    // 只有 total 没有分项时，全部算作输入（宁可多算，预算守卫偏保守）
    if (!u.input && !u.output && !u.cache_read && !u.cache_write) u.input = field("total");
  } else {
    const input = lastNumber(stderr, ["input_tokens", "inputTokens", "prompt_tokens", "promptTokens"]);
    const output = lastNumber(stderr, ["output_tokens", "outputTokens", "completion_tokens", "completionTokens"]);
    if (input !== undefined || output !== undefined) {
      u = {
        input: input ?? 0,
        output: output ?? 0,
        cache_read: lastNumber(stderr, ["cache_read_input_tokens", "cachedReadTokens", "cacheReadInputTokens"]) ?? 0,
        cache_write: lastNumber(stderr, ["cache_creation_input_tokens", "cachedWriteTokens", "cacheCreationInputTokens"]) ?? 0,
      };
    }
  }
  const costLine = [...stderr.matchAll(/^\[acpx\] cost:\s*\$?\s*(\d+(?:\.\d+)?)\s*([A-Za-z]*)\s*$/gm)].at(-1);
  let cost: number | undefined;
  if (costLine) {
    if (!costLine[2] || costLine[2].toUpperCase() === "USD") cost = num(costLine[1]);
  } else {
    cost = lastNumber(stderr, ["total_cost_usd", "cost_usd"]);
  }
  if (cost !== undefined) {
    u ??= { input: 0, output: 0, cache_read: 0, cache_write: 0 };
    u.cost_usd = cost;
  }
  return u;
}

/** 缓存读取按输入单价的 10% 计（主流模型的缓存命中折扣），缓存写入按输入单价计。 */
const CACHE_READ_FACTOR = 0.1;

/**
 * 一次运行的费用：适配器上报了美元费用就用它；否则按 budget.pricing[harness]（每百万 token 美元）估算；
 * 都没有返回 0（只记 token 不计费）。
 */
export function costOf(u: ParsedUsage, pricing: { input: number; output: number } | undefined): number {
  if (u.cost_usd !== undefined) return u.cost_usd;
  if (!pricing) return 0;
  const input = u.input + u.cache_write + u.cache_read * CACHE_READ_FACTOR;
  return (input * pricing.input + u.output * pricing.output) / 1e6;
}

// ───────── 本地日期 ─────────

/** 某时刻在给定时区里的日期 YYYY-MM-DD。 */
export function localDay(ms: number, tz: string): string {
  return new Intl.DateTimeFormat("en-CA", { timeZone: tz, year: "numeric", month: "2-digit", day: "2-digit" }).format(new Date(ms));
}

/** 某时刻所在本地日的零点（毫秒）。与 api/queries.ts 的“今日”口径一致。 */
export function startOfLocalDay(tz: string, now = Date.now()): number {
  const parts = new Intl.DateTimeFormat("en-US", { timeZone: tz, hour: "numeric", minute: "numeric", second: "numeric", hourCycle: "h23" })
    .formatToParts(new Date(now))
    .reduce<Record<string, number>>((acc, p) => (p.type === "literal" ? acc : { ...acc, [p.type]: Number(p.value) }), {});
  return now - ((parts.hour * 60 + parts.minute) * 60 + parts.second) * 1000 - (now % 1000);
}

const usd = (n: number) => `$${n >= 1 ? n.toFixed(2) : n.toFixed(4)}`;

// ───────── 汇总 ─────────

interface StepRow {
  work_id: string;
  harness: string;
  started: number;
  tokens_in: number;
  tokens_out: number;
  cost_usd: number;
  duration_ms: number;
  kind: string | null;
  ref: string | null;
}

export function usageSummary(app: Pick<App, "cfg" | "ledger">, daysIn: number, now = Date.now()): UsageSummary {
  const { cfg, ledger } = app;
  const tz = cfg.owner.timezone;
  const days = Math.min(Math.max(Math.floor(daysIn) || 1, 1), 90);
  const since = startOfLocalDay(tz, now - (days - 1) * DAY);
  // 只统计 harness 运行（校验命令的步骤没有 harness，也不花钱）
  const rows = ledger.db
    .prepare(
      `SELECT s.work_id, s.harness, s.started, s.tokens_in, s.tokens_out, s.cost_usd, s.duration_ms, w.kind, w.ref
         FROM steps s LEFT JOIN work w ON w.id = s.work_id
        WHERE s.started >= ? AND s.harness != ''`,
    )
    .all(since) as unknown as StepRow[];

  const byDay = new Map<string, UsageSummary["by_day"][number]>();
  for (let i = days - 1; i >= 0; i--) {
    const day = localDay(startOfLocalDay(tz, now - i * DAY), tz);
    byDay.set(day, { day, usd: 0, tokens_in: 0, tokens_out: 0, duration_ms: 0 });
  }
  const byHarness = new Map<string, UsageSummary["by_harness"][number]>();
  const byCard = new Map<string, number>();
  let metered = false;
  for (const r of rows) {
    if (r.tokens_in > 0 || r.tokens_out > 0 || r.cost_usd > 0) metered = true;
    const day = localDay(r.started, tz);
    const d = byDay.get(day) ?? { day, usd: 0, tokens_in: 0, tokens_out: 0, duration_ms: 0 };
    d.usd += r.cost_usd;
    d.tokens_in += r.tokens_in;
    d.tokens_out += r.tokens_out;
    d.duration_ms += r.duration_ms;
    byDay.set(day, d);
    const h = byHarness.get(r.harness) ?? { harness: r.harness, usd: 0, tokens_in: 0, tokens_out: 0, runs: 0, duration_ms: 0 };
    h.usd += r.cost_usd;
    h.tokens_in += r.tokens_in;
    h.tokens_out += r.tokens_out;
    h.runs += 1;
    h.duration_ms += r.duration_ms;
    byHarness.set(r.harness, h);
    if (r.kind === "dispatch" && r.ref) byCard.set(r.ref, (byCard.get(r.ref) ?? 0) + r.cost_usd);
  }
  // 花费最多的任务：同一张卡片的所有派单合计，链接到最新一次派单
  const top = [...byCard.entries()]
    .filter(([, c]) => c > 0)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([ref, c]) => {
      const w = ledger.latest<DispatchPayload>("dispatch", ref);
      return { dispatch_id: w?.id ?? ref, summary: (w?.payload.summary ?? "").replace(/^\s*\[[\w-]+\]\s*/, "") || ref, usd: round(c) };
    });
  const by_day = [...byDay.values()].sort((a, b) => a.day.localeCompare(b.day)).map((d) => ({ ...d, usd: round(d.usd) }));
  const b = cfg.budget;
  const today = ledger.costSince(startOfLocalDay(tz, now));
  return {
    days,
    total_usd: round(by_day.reduce((s, d) => s + d.usd, 0)),
    budget: { daily_usd: b.daily_usd, per_task_usd: b.per_task_usd, today_usd: round(today), exceeded: reached(today, b.daily_usd) },
    by_day,
    by_harness: [...byHarness.values()].sort((a, b2) => b2.usd - a.usd || b2.runs - a.runs).map((h) => ({ ...h, usd: round(h.usd) })),
    top_tasks: top,
    metered,
  };
}

const round = (n: number) => Math.round(n * 1e6) / 1e6;
/** 浮点累加有误差（0.6 + 0.3 = 0.8999…），比较预算时留一点余量 */
const reached = (spent: number, limit: number) => limit > 0 && spent >= limit - 1e-9;

// ───────── 预算守卫 ─────────

/**
 * 派单运行 harness 之前的预算检查。返回非空字符串表示暂停（派单收尾为 needs_human / budget）。
 * 每次都读 cfg.budget（设置热更新会原地修改 cfg）。
 */
export function budgetGuard(app: Pick<App, "cfg" | "ledger">, it: WorkItem<DispatchPayload>, now = Date.now()): string | undefined {
  const { cfg, ledger } = app;
  const b = cfg.budget;
  if (b.daily_usd > 0) {
    const today = ledger.costSince(startOfLocalDay(cfg.owner.timezone, now));
    if (reached(today, b.daily_usd)) return `今日花费 ${usd(today)} 已达每日预算 ${usd(b.daily_usd)}`;
  }
  if (b.per_task_usd > 0 && it.ref) {
    const ids = ledger.list({ kinds: ["dispatch"], ref: it.ref, limit: 1000 }).map((w) => w.id);
    const spent = ledger.costOf(ids.includes(it.id) ? ids : [...ids, it.id]);
    if (reached(spent, b.per_task_usd)) return `这张卡片累计花费 ${usd(spent)} 已达单任务预算 ${usd(b.per_task_usd)}`;
  }
  return undefined;
}

/** 记录一次 harness 运行的用量。解析不到就什么都不写（只有耗时）。 */
export function recordUsage(app: Pick<App, "cfg" | "ledger">, run: { harness: string; stepId?: number }, out: { stderr: string }): ParsedUsage | undefined {
  if (run.stepId === undefined) return undefined;
  const u = parseUsage(out.stderr);
  if (!u) return undefined;
  const pricing = app.cfg.budget.pricing[run.harness];
  app.ledger.setStepUsage(run.stepId, {
    tokens_in: Math.round(u.input + u.cache_read + u.cache_write),
    tokens_out: Math.round(u.output),
    cost_usd: costOf(u, pricing),
  });
  return u;
}

export function registerUsage(app: App): void {
  setUsageRecorder((run, out) => {
    try {
      recordUsage(app, run, out);
    } catch (e) {
      log("warn", "记录用量失败（不影响执行）", { err: String(e) });
    }
  });
  app.dispatcher.guard = (it) => budgetGuard(app, it);
  app.ext.usage = { summary: (days) => usageSummary(app, days) };
}
