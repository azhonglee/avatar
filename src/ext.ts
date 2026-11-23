import type { CandidateList, DoctorReport, SettingsUpdateResult, SettingsView, UsageSummary } from "./api/types.ts";
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
  };
}
