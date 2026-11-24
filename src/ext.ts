import type {
  CandidateList,
  CtxConflictView,
  CtxCycleReport,
  CtxDraftView,
  CtxItemDetail,
  CtxItemView,
  CtxKnowledgeView,
  CtxPersonView,
  CtxProjectDetail,
  CtxProjectSummary,
  CtxStatus,
  CtxToday,
  CtxUpdateView,
  DoctorReport,
  SettingsUpdateResult,
  SettingsView,
  UsageSummary,
} from "./api/types.ts";
import type { Ctx } from "./engine.ts";

/**
 * 可选模块的扩展点。每个模块在 src/modules.ts 里注册自己，填充对应字段；
 * 控制台 API 和其他模块只通过这里访问它们，没有注册时相应功能显示为未启用。
 *
 * 约定（模块之间共享的数据形状）：
 *   - 交付（delivery）：账本里 kind = "delivery" 的工作，ref = 派单 id，
 *     payload = { action: "create_pr" | "merge_local" | "discard" | "restore", dispatch_id, url?, ... }；
 *     成功落定 state = "done"，失败 state = "errored"。派单的交付状态由最新一项 delivery 工作推导（见 api/queries.ts）。
 *   - 卡片（cards）：通过 outbox 的 card.upsert 发送/原地更新，key 约定为
 *     "dispatch:<任务 guid>"（一张卡片跟随这张任务的所有派单）、"candidate:<signal id>"、"failure:<work id>"、"brief:<日期>-<mode>"。
 *   - 分诊反馈（candidates）：signals 表的 feedback 列（"" | "confirmed" | "rejected"），由该模块迁移添加。
 */
export interface Extensions {
  candidates?: {
    list(o: { days: number; feedback?: "" | "confirmed" | "rejected" | "all" }): CandidateList;
    /** 待你确认的候选任务数（概览用） */
    pendingCount(): number;
  };
  usage?: {
    summary(days: number): UsageSummary;
  };
  settings?: {
    get(): SettingsView;
    put(patch: Record<string, unknown>): Promise<SettingsUpdateResult>;
  };
  doctor?: {
    run(): Promise<DoctorReport>;
  };
  cards?: {
    /** 处理 card.action.trigger 事件（经 inbox 投递，可重试；需幂等） */
    onAction(ev: Record<string, unknown>, ctx: Ctx): Promise<void>;
    /** 把晨报 / 晚报的 Markdown 渲染成卡片 JSON（schema 2.0）；未提供时按私信发送 */
    brief?(mode: "morning" | "evening", text: string): Record<string, unknown>;
    /** 注册其他模块的卡片类型：按钮操作后用 render 原地刷新；表单兜底时用 target 补操作对象 */
    register?(type: string, render: (id: string, notice: string, cmd: string, args: Record<string, unknown>, res: { ok: boolean; message: string; target: string }) => void, target?: (id: string) => Record<string, unknown>): void;
  };
  /**
   * 工作上下文（src/context）：项目 / 事项 / 知识 / 动态 / 人。
   * 存在 ctx_* 表里；账本里 kind = "context" 的工作是采集理解周期（context:cycle:*）、起草（context:draft:*）、周报（context:weekly:*）。
   */
  context?: {
    today(): CtxToday;
    projects(o: { legacy?: boolean }): CtxProjectSummary[];
    project(id: string): CtxProjectDetail | undefined;
    items(f: { status?: string; kind?: string; project?: string; q?: string }): CtxItemView[];
    item(id: string): CtxItemDetail | undefined;
    knowledge(f: { q?: string; project?: string }): CtxKnowledgeView[];
    updates(f: { days?: number; project?: string }): CtxUpdateView[];
    people(): CtxPersonView[];
    conflicts(status?: "open" | "resolved"): CtxConflictView[];
    drafts(status?: string): CtxDraftView[];
    status(): CtxStatus;
    /** 常驻进程里启动定时采集、晨间 / 收尾卡、周报草稿 */
    start(): { stop(): void };
    /** 立即跑一轮采集 + 理解（命令行用） */
    runOnce(): Promise<CtxCycleReport>;
    /** 发晨间 / 收尾卡（命令行、定时任务用） */
    sendDigest(mode: "morning" | "evening"): void;
  };
}
