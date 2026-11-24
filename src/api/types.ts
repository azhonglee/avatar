/**
 * 控制台 API 契约（后端与 web/ 共用，只放类型）。
 *
 * 约定：
 *   - 所有接口在 /api 下，JSON；鉴权见 src/server/index.ts（令牌 → HttpOnly Cookie，或 Authorization: Bearer）
 *   - 写操作统一走 POST /api/commands/:name，body 为 { args }，返回 CommandResult
 *   - 实时更新：GET /api/events（SSE），事件见 ServerEvent；收到后按需重新拉取对应资源
 *   - 错误：非 2xx，body 为 ApiError
 */

export interface ApiError {
  error: { code: "unauthorized" | "not_found" | "invalid" | "conflict" | "forbidden" | "unavailable" | "internal"; message: string };
}

// ───────── 通用 ─────────

export type DispatchState = "queued" | "executing" | "verifying" | "accepted" | "unverified" | "needs_human" | "errored" | "cancelled";
export type DeliveryStatus = "none" | "pending" | "pr_open" | "merged_local" | "discarded" | "failed";

export interface Meta {
  version: string;
  owner: { open_id: string; timezone: string };
  harnesses: string[];
  roles: { brain: string; reviewer: string; default_harness: string };
  repos: { alias: string; path: string; verify?: string; provider?: string }[];
  providers: { name: string; type: "github" | "gitlab" | "codebase" }[];
  features: { cards: boolean; delivery: boolean; usage: boolean; settings: boolean; doctor: boolean; candidates: boolean; context: boolean };
  /** 飞书网页域名，拼任务链接用 */
  lark_web: string;
}

// ───────── 概览 ─────────

export interface Overview {
  /** 需要你处理的事 */
  attention: {
    needs_human: DispatchSummary[];
    to_review: DispatchSummary[];
    candidates: number;
    failures: number;
  };
  running: DispatchSummary[];
  today: { dispatched: number; accepted: number; needs_human: number; errored: number; cost_usd: number; budget_usd: number };
  health: { ok: boolean; pending_events: number; pending_effects: number; dead: number; daemon_owner: string | null };
}

// ───────── 派单 ─────────

export interface DispatchSummary {
  id: string;
  task_guid: string;
  task_url: string;
  summary: string;
  state: DispatchState;
  terminal: boolean;
  reason: string;
  harness: string;
  reviewer: string;
  repo: string;
  round: number;
  max_rounds: number;
  attempts: number;
  /** 正在被某个进程执行 */
  active: boolean;
  cancel_requested: boolean;
  created: number;
  updated: number;
  cost_usd: number;
  delivery: DeliveryStatus;
  delivery_url: string;
}

export interface StepView {
  id: number;
  name: string;
  harness: string;
  status: "running" | "ok" | "failed" | "interrupted";
  started: number;
  ended: number | null;
  duration_ms: number;
  summary: string;
  has_log: boolean;
  tokens_in: number;
  tokens_out: number;
  cost_usd: number;
}

export interface CheckView {
  kind: "command" | "review";
  name: string;
  status: "pass" | "fail" | "error";
  detail: string;
}

export interface DispatchDetail extends DispatchSummary {
  description: string;
  cwd: string;
  branch: string;
  base: string;
  verify: string;
  report: string;
  feedback: string;
  error: string;
  rounds: { round: number; checks: CheckView[] }[];
  steps: StepView[];
  /** 这次派单写回飞书的评论/移动/卡片（含投递状态） */
  effects: { id: string; op: string; state: string; summary: string; error: string; updated: number }[];
  /** 同一张卡片之前的派单（最近在前） */
  previous: DispatchSummary[];
  diff_stat: string;
  /** 当前状态下可执行的命令（按钮据此显示/禁用） */
  actions: CommandName[];
  audit: AuditView[];
}

export interface DiffView {
  base: string;
  head: string;
  stat: string;
  /** unified diff；过大时截断 */
  patch: string;
  truncated: boolean;
}

export interface LogChunk {
  step_id: number;
  offset: number;
  next_offset: number;
  text: string;
  eof: boolean;
  /** 步骤仍在运行，可以继续拉 */
  running: boolean;
}

// ───────── 候选任务（分诊） ─────────

export interface CandidateView {
  signal_id: string;
  source: string;
  text: string;
  link: string;
  at: number;
  verdict: string;
  task_guid: string;
  task_url: string;
  summary: string;
  confidence: number | null;
  /** 用户反馈：confirmed / rejected / 空 */
  feedback: "" | "confirmed" | "rejected";
}

export interface CandidateList {
  items: CandidateView[];
  stats: { window_days: number; created: number; confirmed: number; rejected: number; precision: number | null };
}

// ───────── 作业 ─────────

export interface JobView {
  name: string;
  cron: string;
  prompt: string;
  harness: string;
  notify: boolean;
  next_run: number | null;
  last: { id: string; state: string; updated: number; result: string; error: string } | null;
}

// ───────── 健康 ─────────

export interface HealthItem {
  id: string;
  kind: "event" | "effect" | "job" | "delivery";
  ref: string;
  state: string;
  terminal: boolean;
  attempts: number;
  next_at: number;
  error: string;
  summary: string;
  updated: number;
  acknowledged: boolean;
}

export interface Health {
  daemon: { owner: string | null; last_heartbeat: number | null };
  retrying: HealthItem[];
  failed: HealthItem[];
  guard: { at: string; profile: string; allow: boolean; reason: string; argv: string[] }[];
}

// ───────── 用量 ─────────

export interface UsageSummary {
  days: number;
  total_usd: number;
  budget: { daily_usd: number; per_task_usd: number; today_usd: number; exceeded: boolean };
  by_day: { day: string; usd: number; tokens_in: number; tokens_out: number; duration_ms: number }[];
  by_harness: { harness: string; usd: number; tokens_in: number; tokens_out: number; runs: number; duration_ms: number }[];
  top_tasks: { dispatch_id: string; summary: string; usd: number }[];
  /** 是否有任何步骤拿到了 token 数（否则只有耗时） */
  metered: boolean;
}

// ───────── 设置与体检 ─────────

export interface SettingsView {
  /** 当前生效的配置（敏感值已隐藏） */
  config: Record<string, unknown>;
  /** 每个顶层字段是否保存即生效（false 表示需要重启常驻进程） */
  hot_reload: Record<string, boolean>;
  file: string;
  restart_required: boolean;
}

export interface SettingsUpdateResult {
  ok: boolean;
  errors: { path: string; message: string }[];
  restart_required: boolean;
}

export interface DoctorCheck {
  id: string;
  title: string;
  status: "ok" | "warn" | "fail" | "skip";
  detail: string;
  /** 修复指引（Markdown） */
  fix: string;
}

export interface DoctorReport {
  checks: DoctorCheck[];
  ready: boolean;
}

// ───────── 审计 ─────────

export interface AuditView {
  id: number;
  at: number;
  source: string;
  command: string;
  target: string;
  ok: boolean;
  message: string;
}

// ───────── 命令 ─────────

export type CommandName =
  | "dispatch.create"
  | "dispatch.cancel"
  | "dispatch.retry"
  | "dispatch.rework"
  | "dispatch.switch_harness"
  | "delivery.create_pr"
  | "delivery.merge_local"
  | "delivery.discard"
  | "delivery.restore"
  | "candidate.confirm"
  | "candidate.reject"
  | "candidate.dispatch"
  | "work.retry"
  | "work.acknowledge"
  | "job.run"
  | "context.refresh"
  | "context.item_done"
  | "context.item_reopen"
  | "context.item_snooze"
  | "context.item_delegate"
  | "context.feedback"
  | "context.project_mute"
  | "context.conv_mute"
  | "context.conflict_resolve"
  | "context.draft_create"
  | "context.draft_approve"
  | "context.draft_discard"
  | "context.weekly_report";

export interface CommandArgs {
  "dispatch.create": { summary: string; description?: string; harness?: string; repo?: string };
  "dispatch.cancel": { id: string };
  "dispatch.retry": { id: string };
  "dispatch.rework": { id: string; feedback: string };
  "dispatch.switch_harness": { id: string; harness: string };
  "delivery.create_pr": { id: string; title?: string; draft?: boolean };
  "delivery.merge_local": { id: string; target_branch?: string };
  "delivery.discard": { id: string };
  "delivery.restore": { id: string };
  "candidate.confirm": { signal_id: string };
  "candidate.reject": { signal_id: string; reason?: string };
  "candidate.dispatch": { signal_id: string; harness?: string; repo?: string };
  "work.retry": { id: string };
  "work.acknowledge": { id: string };
  "job.run": { name: string };
  "context.refresh": Record<string, never>;
  "context.item_done": { id: string; note?: string };
  "context.item_reopen": { id: string };
  "context.item_snooze": { id: string; hours?: number; until?: string };
  "context.item_delegate": { id: string; harness?: string; repo?: string };
  "context.feedback": { entity: "item" | "project" | "knowledge" | "update" | "person"; id: string; verdict: "right" | "wrong" | "unimportant"; note?: string };
  "context.project_mute": { id: string; muted: boolean };
  "context.conv_mute": { conv: string; muted: boolean; name?: string };
  "context.conflict_resolve": { id: string; choice?: number; resolution?: string };
  "context.draft_create": { item_id: string; kind?: CtxDraftKind };
  "context.draft_approve": { id: string; content?: string };
  "context.draft_discard": { id: string };
  "context.weekly_report": { days?: number };
}

export interface CommandResult {
  ok: boolean;
  message: string;
  /** 受影响的对象 id（如新派单 id、PR 链接） */
  target?: string;
  url?: string;
}

// ───────── 实时事件 ─────────

export type ServerEvent =
  | { type: "work"; id: string; kind: string; ref: string; state: string; terminal: boolean }
  | { type: "candidate"; signal_id: string }
  | { type: "command"; name: string; ok: boolean; target: string }
  /** 跨进程变化（命令行等）被轮询发现：整体刷新 */
  | { type: "refresh" }
  | { type: "ping"; at: number };

// ═════════ Working Context（工作上下文） ═════════

export type CtxItemKind = "todo" | "ask_me" | "my_commitment" | "waiting_on" | "meeting_action" | "risk";
export type CtxItemStatus = "open" | "done" | "dismissed" | "snoozed";
export type CtxPriority = "high" | "medium" | "low";
export type CtxSource = "meego" | "im" | "minutes" | "task" | "calendar" | "manual";

export interface CtxEvidenceView {
  obs_id: string;
  source: CtxSource;
  quote: string;
  time: number;
  conv_name: string;
  actor_name: string;
  is_me: boolean;
  /** 打开原文（飞书会话 / Meego 工作项 / 妙记）的链接 */
  url: string;
}

export interface CtxProjectSummary {
  id: string;
  name: string;
  description: string;
  my_role: string;
  stage: string;
  status: "active" | "legacy" | "archived";
  muted: boolean;
  health: "ok" | "risk" | "blocked" | "unknown";
  open_items: number;
  high_items: number;
  last_activity: number;
  refs: string[];
}

export interface CtxItemView {
  id: string;
  title: string;
  kind: CtxItemKind;
  status: CtxItemStatus;
  priority: CtxPriority;
  project_id: string;
  project_name: string;
  due: number | null;
  counterpart: string;
  next_step: string;
  confidence: number;
  source: CtxSource;
  strong_key: string;
  first_seen: number;
  last_seen: number;
  closed_at: number | null;
  close_reason: string;
  snooze_until: number | null;
  /** 排序分（越高越该先处理）与原因 */
  score: number;
  why: string[];
  /** 识别把握不大，需要你确认 */
  needs_review: boolean;
  feedback: "" | "right" | "wrong" | "unimportant";
  url: string;
}

export interface CtxItemDetail extends CtxItemView {
  evidence: CtxEvidenceView[];
  drafts: CtxDraftView[];
  actions: string[];
}

export interface CtxKnowledgeView {
  id: string;
  project_id: string;
  project_name: string;
  kind: "decision" | "conclusion" | "doc" | "howto" | "fact";
  title: string;
  content: string;
  confidence: number;
  updated: number;
  evidence: CtxEvidenceView[];
}

export interface CtxUpdateView {
  id: string;
  project_id: string;
  project_name: string;
  time: number;
  summary: string;
  evidence: CtxEvidenceView[];
}

export interface CtxPersonView {
  id: string;
  name: string;
  relation: string;
  projects: string[];
  open_items: number;
  last_seen: number;
}

export interface CtxConflictView {
  id: string;
  project_id: string;
  project_name: string;
  topic: string;
  claims: { claim: string; quote: string; time: number; url: string }[];
  status: "open" | "resolved";
  resolution: string;
  created: number;
}

export type CtxDraftKind = "reply" | "followup" | "meego_comment" | "weekly_report";

export interface CtxDraftView {
  id: string;
  item_id: string;
  project_id: string;
  kind: CtxDraftKind;
  /** 发给谁 / 写到哪（人类可读） */
  target_label: string;
  content: string;
  status: "proposed" | "approved" | "sent" | "discarded" | "failed";
  error: string;
  created: number;
  updated: number;
  url: string;
}

export interface CtxProjectDetail extends CtxProjectSummary {
  items: CtxItemView[];
  knowledge: CtxKnowledgeView[];
  updates: CtxUpdateView[];
  people: CtxPersonView[];
  conflicts: CtxConflictView[];
}

export interface CtxMeeting {
  start: number;
  end: number;
  summary: string;
  url: string;
}

export interface CtxToday {
  date: string;
  /** 今天最该处理的事（已排序） */
  focus: CtxItemView[];
  asks: CtxItemView[];
  commitments: CtxItemView[];
  waiting: CtxItemView[];
  risks: CtxItemView[];
  due_soon: CtxItemView[];
  needs_review: CtxItemView[];
  conflicts: CtxConflictView[];
  drafts: CtxDraftView[];
  meetings: CtxMeeting[];
  changes: CtxUpdateView[];
  projects: CtxProjectSummary[];
  status: CtxStatus;
}

export interface CtxStatus {
  last_cycle: number | null;
  last_error: string;
  running: boolean;
  sources: { source: string; last_pull: number | null; last_count: number; error: string }[];
  pending_obs: number;
  totals: { projects: number; open_items: number; knowledge: number; people: number };
  understand_enabled: boolean;
}

/** 一轮采集 + 理解的结果 */
export interface CtxCycleReport {
  skipped: boolean;
  sources: { source: string; count: number; error: string }[];
  convs: number;
  created: number;
  closed: number;
  knowledge: number;
  updates: number;
  conflicts: number;
  rejected: number;
  nudged: number;
  errors: string[];
}
