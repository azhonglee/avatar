import { z } from "zod";
import type { ApiError, CommandArgs, CommandName, CommandResult } from "./api/types.ts";
import type { Bus } from "./bus.ts";
import type { Ledger } from "./ledger.ts";
import { errMsg, log } from "./util.ts";

/**
 * 统一命令层：飞书卡片按钮、控制台按钮、私聊指令、命令行都走这里。
 * 负责参数校验、前置条件检查、审计；命令本身只做“把意图写进账本”，具体执行交给引擎。
 */

export type CommandSource = "web" | "card" | "bot" | "cli";

export interface CommandCtx {
  source: CommandSource;
  /** 操作者（飞书 open_id；控制台/命令行为 "owner"） */
  actor: string;
  /** 可选：来自工作上下文委派的内部调用归属主人，用于即使内部命令失败也保留审计主人隔离 */
  contextOwner?: string;
}

export class CommandError extends Error {
  code: ApiError["error"]["code"];
  constructor(code: ApiError["error"]["code"], message: string) {
    super(message);
    this.code = code;
  }
}

export interface CommandDef<N extends CommandName = CommandName> {
  name: N;
  /** 一句话说明（控制台提示、/help 用） */
  title: string;
  schema: z.ZodType<CommandArgs[N]>;
  /** 审计里的目标对象（如派单 id） */
  target: (args: CommandArgs[N]) => string;
  run: (args: CommandArgs[N], ctx: CommandCtx) => Promise<CommandResult>;
}

export class Commands {
  private defs = new Map<string, CommandDef>();
  ledger: Ledger;
  bus?: Bus;
  /** 命令写入账本后调用，让引擎尽快领取 */
  kick: () => void = () => undefined;

  constructor(ledger: Ledger, bus?: Bus) {
    this.ledger = ledger;
    this.bus = bus;
  }

  register<N extends CommandName>(def: CommandDef<N>): void {
    this.defs.set(def.name, def as unknown as CommandDef);
  }

  has(name: string): boolean {
    return this.defs.has(name);
  }

  names(): CommandName[] {
    return [...this.defs.keys()] as CommandName[];
  }

  async exec<N extends CommandName>(name: N | string, rawArgs: unknown, ctx: CommandCtx): Promise<CommandResult> {
    const def = this.defs.get(name);
    if (!def) throw new CommandError("not_found", `未知的命令：${name}（该功能可能未启用）`);
    const parsed = def.schema.safeParse(rawArgs ?? {});
    if (!parsed.success) throw new CommandError("invalid", `参数有误：${z.prettifyError(parsed.error)}`);
    const args = parsed.data;
    const target = def.target(args as never);
    const auditArgs =
      ctx.contextOwner !== undefined
        ? typeof args === "object" && args !== null && !Array.isArray(args)
          ? { ...(args as Record<string, unknown>), __context_owner: ctx.contextOwner }
          : { value: args, __context_owner: ctx.contextOwner }
        : args;
    try {
      const r = await def.run(args as never, ctx);
      this.ledger.audit({ source: ctx.source, actor: ctx.actor, command: name, target: r.target ?? target, args: auditArgs, ok: r.ok, message: r.message });
      this.bus?.emit("command.executed", { name, source: ctx.source, ok: r.ok, target: r.target ?? target });
      this.kick();
      return r;
    } catch (e) {
      const msg = errMsg(e);
      this.ledger.audit({ source: ctx.source, actor: ctx.actor, command: name, target, args: auditArgs, ok: false, message: msg });
      this.bus?.emit("command.executed", { name, source: ctx.source, ok: false, target });
      log("warn", "命令失败", { command: name, source: ctx.source, err: msg });
      throw e instanceof CommandError ? e : new CommandError("internal", msg);
    }
  }
}

/** 常用参数 schema */
export const S = {
  id: z.object({ id: z.string().min(1) }),
};
