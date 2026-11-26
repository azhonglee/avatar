import fs from "node:fs";
import path from "node:path";
import { z } from "zod";
import { isContextDerivedDispatchBlocked, isWorkBlockedByOwner } from "./api/queries.ts";
import type { CommandName, DeliveryStatus } from "./api/types.ts";
import { CommandError, S, type Commands } from "./commands.ts";
import type { Config } from "./config.ts";
import type { Board } from "./board.ts";
import { loadPrompt } from "./harness.ts";
import type { Ledger, WorkItem } from "./ledger.ts";
import type { Store } from "./store.ts";
import { expandHome } from "./util.ts";
import { enqueueJob } from "./workflows/agent.ts";
import type { Dispatcher, DispatchPayload } from "./workflows/dispatch.ts";

/** 派单当前可执行的命令（控制台按钮、卡片按钮据此显示）。 */
export function availableActions(
  w: WorkItem<DispatchPayload>,
  o: { delivery: DeliveryStatus; providers: number; deliveryEnabled: boolean; isLatest: boolean },
): CommandName[] {
  if (!w.terminal) return w.cancel ? [] : ["dispatch.cancel"];
  if (!o.isLatest) return []; // 只能操作这张卡片最新的一次派单
  const acts: CommandName[] = ["dispatch.retry", "dispatch.rework", "dispatch.switch_harness"];
  const hasBranch = !!w.payload.branch;
  const deliverable = ["accepted", "unverified", "needs_human"].includes(w.state);
  if (o.deliveryEnabled && hasBranch) {
    if (o.delivery === "discarded") acts.push("delivery.restore");
    else if (deliverable && (o.delivery === "none" || o.delivery === "failed")) {
      if (o.providers > 0) acts.push("delivery.create_pr");
      acts.push("delivery.merge_local", "delivery.discard");
    } else if (o.delivery === "pr_open") acts.push("delivery.discard");
  }
  return acts;
}

export interface CoreDeps {
  cfg: Config;
  store: Store;
  ledger: Ledger;
  board: Board;
  dispatcher: Dispatcher;
}

function assertDispatchOwnerAllowed(d: Pick<CoreDeps, "cfg" | "store" | "ledger">, id: string): void {
  if (isContextDerivedDispatchBlocked(d, id)) {
    throw new CommandError("conflict", "该派单源自旧工作区主人的工作上下文，已按主人隔离阻断操作");
  }
}

function terminalDispatch(d: Pick<CoreDeps, "cfg" | "store" | "ledger">, id: string): WorkItem<DispatchPayload> {
  assertDispatchOwnerAllowed(d, id);
  const w = d.ledger.get<DispatchPayload>(id);
  if (!w || w.kind !== "dispatch") throw new CommandError("not_found", `没有这项派单：${id}`);
  if (!w.terminal) throw new CommandError("conflict", "派单还在进行中，请先取消");
  const latest = d.ledger.latest("dispatch", w.ref);
  if (latest && latest.id !== w.id) throw new CommandError("conflict", "这张卡片已经有更新的派单，请操作最新的一次");
  return w;
}

/** 注册不依赖可选模块的核心命令。 */
export function registerCoreCommands(commands: Commands, d: CoreDeps): void {
  const { cfg, store, ledger, board, dispatcher } = d;
  const harnessName = z.string().refine((h) => !!cfg.harnesses[h], { message: "未定义的执行者" });

  commands.register({
    name: "dispatch.create",
    title: "新建派单",
    schema: z.object({
      summary: z.string().trim().min(1, "请填写任务描述").max(200),
      description: z.string().max(5000).optional(),
      harness: harnessName.optional(),
      repo: z
        .string()
        .refine((r) => !!cfg.dispatch.repos[r] || fs.existsSync(path.resolve(expandHome(r))), { message: "未配置的仓库别名，且路径不存在" })
        .optional(),
    }),
    target: (a) => a.summary,
    run: async (a, ctx) => {
      const summary = `${a.harness ? `[${a.harness}] ` : ""}${a.summary}`;
      const description = [a.description ?? "", a.repo ? `repo: ${a.repo}` : ""].filter(Boolean).join("\n");
      const guid = await board.createTask({ summary, description, section: "dispatch" });
      // 在对账前立即持久化 GUID 归属：即使后续 board 读取/对账失败，远端已建任务也已绑定原主人
      const contextOwner = ctx.contextOwner?.trim();
      if (contextOwner) {
        store.set(`ctx.dispatch_ref_owner.${guid}`, contextOwner);
      }
      await dispatcher.reconcile();
      const w = ledger.latest("dispatch", guid);
      if (contextOwner && w?.id) {
        store.set(`ctx.dispatch_owner.${w.id}`, contextOwner);
      }
      return { ok: true, message: "已创建派单，进度会实时更新", target: w?.id ?? guid };
    },
  });

  commands.register({
    name: "dispatch.cancel",
    title: "取消派单",
    schema: S.id,
    target: (a) => a.id,
    run: async (a) => {
      assertDispatchOwnerAllowed(d, a.id);
      const w = ledger.get(a.id);
      if (!w || w.kind !== "dispatch") throw new CommandError("not_found", `没有这项派单：${a.id}`);
      if (w.terminal) throw new CommandError("conflict", "派单已经结束");
      ledger.requestCancel(a.id);
      return { ok: true, message: "已请求取消，正在结束执行中的进程", target: a.id };
    },
  });

  commands.register({
    name: "dispatch.retry",
    title: "重试（同一执行者）",
    schema: S.id,
    target: (a) => a.id,
    run: async (a) => {
      const w = terminalDispatch(d, a.id);
      const id = dispatcher.redispatch(w.ref, { reason: "手动重试", harness: w.payload.harness || undefined, from: w.id });
      return { ok: true, message: "已重新派单", target: id };
    },
  });

  commands.register({
    name: "dispatch.rework",
    title: "带意见返工",
    schema: z.object({ id: z.string().min(1), feedback: z.string().trim().min(1, "请写下返工意见").max(5000) }),
    target: (a) => a.id,
    run: async (a) => {
      const w = terminalDispatch(d, a.id);
      const id = dispatcher.redispatch(w.ref, { reason: "带意见返工", feedback: a.feedback, harness: w.payload.harness || undefined, from: w.id });
      return { ok: true, message: "已带着你的意见重新派单", target: id };
    },
  });

  commands.register({
    name: "dispatch.switch_harness",
    title: "换执行者重试",
    schema: z.object({ id: z.string().min(1), harness: harnessName }),
    target: (a) => a.id,
    run: async (a) => {
      const w = terminalDispatch(d, a.id);
      const id = dispatcher.redispatch(w.ref, { reason: `换执行者为 ${a.harness}`, harness: a.harness, from: w.id });
      return { ok: true, message: `已改由 ${a.harness} 重新执行`, target: id };
    },
  });

  commands.register({
    name: "work.retry",
    title: "重试失败的事件 / 飞书写入 / 作业",
    schema: S.id,
    target: (a) => a.id,
    run: async (a) => {
      const w = ledger.get(a.id);
      if (!w) throw new CommandError("not_found", `没有这项工作：${a.id}`);
      if (isWorkBlockedByOwner(d, w)) throw new CommandError("conflict", "该工作项源自旧工作区主人的工作上下文，已按主人隔离阻断操作");
      if (w.kind === "dispatch") throw new CommandError("invalid", "派单请用“重试”或“返工”");
      if (!ledger.revive(a.id)) throw new CommandError("conflict", "只有失败落定的工作可以重试");
      return { ok: true, message: "已重新排队", target: a.id };
    },
  });

  commands.register({
    name: "work.acknowledge",
    title: "忽略这条失败",
    schema: S.id,
    target: (a) => a.id,
    run: async (a) => {
      if (!ledger.acknowledge(a.id)) throw new CommandError("conflict", "只有失败落定的工作可以忽略");
      return { ok: true, message: "已忽略", target: a.id };
    },
  });

  commands.register({
    name: "job.run",
    title: "立即运行作业",
    schema: z.object({ name: z.string().refine((n) => !!cfg.jobs[n], { message: "未定义的作业" }) }),
    target: (a) => a.name,
    run: async (a) => {
      const j = cfg.jobs[a.name];
      const id = `${a.name}:manual-${Date.now()}`;
      enqueueJob(ledger, id, { name: a.name, task: loadPrompt(j.prompt), harness: j.harness, notify: j.notify });
      return { ok: true, message: "作业已排队", target: `job:${id}` };
    },
  });
}
