import path from "node:path";
import { z } from "zod";
import type { Config } from "../config.ts";
import { loadPrompt, runHarness } from "../harness.ts";
import { render, truncate } from "../util.ts";

export interface Signal {
  id: string;
  source: string;
  text: string;
  link: string;
}

const Verdict = z.object({
  signal_id: z.string(),
  is_task: z.boolean(),
  summary: z.string().default(""),
  due: z.string().nullable().default(null),
  confidence: z.number().min(0).max(1).default(0),
  reason: z.string().default(""),
});
export type Verdict = z.infer<typeof Verdict>;

/** 从模型回复里取出 JSON 数组并校验。容忍 ```json 代码块和前后说明文字。 */
export function parseVerdicts(text: string): Verdict[] {
  const start = text.indexOf("[");
  const end = text.lastIndexOf("]");
  if (start < 0 || end <= start) throw new Error(`分诊结果里没有 JSON 数组：${truncate(text, 300)}`);
  return z.array(Verdict).parse(JSON.parse(text.slice(start, end + 1)));
}

/**
 * 分诊：判断每条信号是不是“需要我做的事”。
 * 这一步只要文本输出——不给任何工具、不给飞书权限，信号内容再怎么注入也做不了事。
 */
export async function triage(cfg: Config, signals: Signal[], existingSummaries: string[]): Promise<Verdict[]> {
  if (signals.length === 0) return [];
  const body = signals
    .map((s) => `<signal id="${s.id}" source="${s.source}">\n${truncate(s.text, 4000)}\n</signal>`)
    .join("\n");
  const prompt = render(loadPrompt("triage.md"), {
    now: new Date().toLocaleString("zh-CN", { timeZone: cfg.owner.timezone }),
    timezone: cfg.owner.timezone,
    owner: cfg.owner.open_id,
    existing: existingSummaries.map((s) => `- ${s}`).join("\n") || "（无）",
    signals: body,
  });
  const r = await runHarness(cfg, {
    harness: cfg.roles.brain,
    prompt,
    cwd: path.join(cfg.dataDir, "workspace", "triage"),
    tools: "none",
    lark: "none",
    timeoutSec: 600,
    logFile: path.join(cfg.dataDir, "runs", `triage-${Date.now()}.log`),
  });
  // 拒绝了工具调用时 acpx 会以退出码 5 结束，只要文本可解析就照常使用
  if (!r.text) throw new Error(`分诊 harness 无输出（exit ${r.exitCode}${r.timedOut ? "，超时" : ""}）`);
  const ids = new Set(signals.map((s) => s.id));
  return parseVerdicts(r.text).filter((v) => ids.has(v.signal_id));
}
