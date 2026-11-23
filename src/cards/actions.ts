import { createHash } from "node:crypto";
import { z } from "zod";
import { FORM_SUBMIT } from "./templates.ts";

/**
 * 解析 card.action.trigger 事件（不可信输入）。
 *
 * lark-cli 1.0.100 的事件是扁平的：operator_id、action_tag、action_name、action_value（JSON 字符串）、
 * form_value（JSON 字符串，表单提交时）、option（独立下拉框）、input_value、message_id、event_id、token。
 * 也兼容原始回调结构（event.operator.open_id / event.action.value …），以防输出格式变化。
 */

const Event = z.object({
  event_id: z.string().default(""),
  token: z.string().default(""),
  operator_id: z.string().default(""),
  message_id: z.string().default(""),
  action_tag: z.string().default(""),
  action_name: z.string().default(""),
  action_value: z.unknown().optional(),
  form_value: z.unknown().optional(),
  option: z.string().optional(),
  input_value: z.string().optional(),
});

/** 按钮回调值：我们自己写进卡片的，但经过客户端回传，同样按不可信处理。 */
const Value = z.object({
  cmd: z.string().regex(/^[a-z]+\.[a-z_]+$/),
  args: z.record(z.string(), z.unknown()).default({}),
  card: z.string().max(200).optional(),
  /** 独立下拉框（不在表单里）选中的值填进哪个参数 */
  option_arg: z.string().regex(/^[a-z_]+$/).optional(),
});

export type ParsedAction =
  | {
      ok: true;
      /** 去重键：event_id，退而求其次 token，再不行用内容哈希 */
      eventKey: string;
      actor: string;
      cmd: string;
      args: Record<string, unknown>;
      /** 卡片 key（回调值里带的）；没有时调用方按 message_id 反查 */
      card?: string;
      messageId: string;
      /** 回调值缺失、按表单提交按钮的 name 兜底识别的：目标参数（id / signal_id）需要按卡片补上 */
      inferred: boolean;
    }
  | { ok: false; reason: string; actor: string };

function obj(v: unknown): Record<string, unknown> {
  if (typeof v === "string") {
    if (!v.trim()) return {};
    try {
      return obj(JSON.parse(v));
    } catch {
      return {};
    }
  }
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
}

/** 原始回调结构 → 扁平结构。 */
export function normalizeEvent(ev: Record<string, unknown>): Record<string, unknown> {
  if (ev.operator_id || ev.action_value !== undefined || ev.form_value !== undefined) return ev;
  const inner = obj(ev.event);
  if (!Object.keys(inner).length) return ev;
  const action = obj(inner.action);
  const header = obj(ev.header);
  return {
    event_id: String(header.event_id ?? ev.event_id ?? ""),
    token: String(inner.token ?? ""),
    operator_id: String(obj(inner.operator).open_id ?? ""),
    message_id: String(obj(inner.context).open_message_id ?? ""),
    action_tag: String(action.tag ?? ""),
    action_name: String(action.name ?? ""),
    action_value: action.value,
    form_value: action.form_value,
    option: typeof action.option === "string" ? action.option : undefined,
    input_value: typeof action.input_value === "string" ? action.input_value : undefined,
  };
}

/** 表单字段：只取标量，空串视为没填。 */
export function formFields(v: unknown): Record<string, string | number | boolean> {
  const out: Record<string, string | number | boolean> = {};
  for (const [k, x] of Object.entries(obj(v))) {
    if (!/^[a-z_]{1,32}$/.test(k)) continue;
    if (typeof x === "string" ? x.trim() !== "" : typeof x === "number" || typeof x === "boolean") out[k] = x as string | number | boolean;
  }
  return out;
}

export function parseAction(raw: Record<string, unknown>, owner: string): ParsedAction {
  const parsed = Event.safeParse(normalizeEvent(raw));
  if (!parsed.success) return { ok: false, reason: "事件格式不对", actor: "" };
  const ev = parsed.data;
  const actor = ev.operator_id;
  if (!owner || actor !== owner) return { ok: false, reason: "操作者不是主人", actor };
  const eventKey = ev.event_id || ev.token || createHash("sha256").update(JSON.stringify(raw)).digest("hex").slice(0, 32);
  const form = formFields(ev.form_value);

  const value = Value.safeParse(obj(ev.action_value));
  if (value.success) {
    const v = value.data;
    const extra: Record<string, unknown> = { ...form };
    if (v.option_arg && ev.option) extra[v.option_arg] = ev.option;
    // 回调值里的目标参数（id / signal_id 等）优先：表单字段不能改操作对象
    return { ok: true, eventKey, actor, cmd: v.cmd, args: { ...extra, ...v.args }, card: v.card, messageId: ev.message_id, inferred: false };
  }
  const cmd = FORM_SUBMIT[ev.action_name];
  if (cmd) return { ok: true, eventKey, actor, cmd, args: form, messageId: ev.message_id, inferred: true };
  return { ok: false, reason: "无法识别的卡片操作", actor };
}
